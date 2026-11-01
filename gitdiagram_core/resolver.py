"""Cross-module import and symbol resolution with explicit confidence levels."""

from __future__ import annotations

import builtins
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable

from .ast_index import CallRec, DefRec, FileIndex, ImportRec

BUILTIN_NAMES = set(dir(builtins))


@dataclass(slots=True)
class Binding:
    kind: str  # module | namespace | symbol | external | unknown
    value: str
    confidence: float = 1.0


@dataclass(slots=True)
class Resolution:
    kind: str  # module | namespace | symbol | external
    target: str
    confidence: float
    method: str  # exact | import | inferred | name-only | dynamic
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ImportTarget:
    kind: str
    target: str
    names: list[str]
    line: int
    confidence: float
    star: bool = False


@dataclass(slots=True)
class Assignment:
    value_callee: str | None
    value_type: str | None


class Resolver:
    def __init__(self, indexes: dict[str, FileIndex]) -> None:
        self.indexes = indexes
        self.module_map: dict[str, str] = {}
        self.index_by_module: dict[str, FileIndex] = {}
        self.duplicate_modules: dict[str, list[str]] = {}
        self.symbols: dict[str, tuple[str, DefRec]] = {}
        self.module_bindings: dict[str, dict[str, Binding]] = {}
        self.child_defs: dict[str, dict[str, str]] = {}
        self.class_members: dict[str, dict[str, str]] = {}
        self.class_bases: dict[str, list[str]] = {}
        self.assignments: dict[str, dict[str, Assignment]] = {}
        self.short_index: dict[str, list[str]] = {}
        self.star_imports: dict[str, list[str]] = {}
        self.unresolved: list[dict[str, object]] = []
        self._build_modules()
        self._build_symbols()
        self._build_bindings()

    # ------------------------------------------------------------------ build
    def _build_modules(self) -> None:
        for path in sorted(self.indexes):
            module = self.indexes[path].module
            if module in self.module_map:
                self.duplicate_modules.setdefault(module, [self.module_map[module]]).append(path)
                continue
            self.module_map[module] = path
            self.index_by_module[module] = self.indexes[path]
        self.local_tops = {name.split(".")[0] for name in self.module_map if name}

    def _build_symbols(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            for definition in index.defs:
                self.symbols.setdefault(definition.qualname, (path, definition))
                if definition.parent:
                    self.child_defs.setdefault(definition.parent, {}).setdefault(
                        definition.name, definition.qualname
                    )
                if definition.kind == "class":
                    self.class_bases[definition.qualname] = list(definition.bases)
                elif definition.parent and self._is_class(definition.parent):
                    self.class_members.setdefault(definition.parent, {}).setdefault(
                        definition.name, definition.qualname
                    )
                if definition.parent == index.module:
                    self.short_index.setdefault(definition.name, []).append(definition.qualname)
        for name in self.short_index:
            self.short_index[name] = sorted(set(self.short_index[name]))

    def _is_class(self, qualname: str) -> bool:
        entry = self.symbols.get(qualname)
        return bool(entry and entry[1].kind == "class")

    def _build_bindings(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            bindings: dict[str, Binding] = {}
            for imp in index.imports:
                for name, binding in self._import_bindings(index, imp):
                    bindings.setdefault(name, binding)
            for definition in index.defs:
                if definition.parent == index.module:
                    bindings[definition.name] = Binding("symbol", definition.qualname, 1.0)
            self.module_bindings[index.module] = bindings
            self.assignments.setdefault(index.module, {})
            for definition in index.defs:
                self.assignments.setdefault(definition.qualname, {})
            for assign in index.assigns:
                for target in (item.strip() for item in assign.target.split(",")):
                    if target:
                        self.assignments.setdefault(assign.scope, {})[target] = Assignment(
                            assign.value_callee, assign.value_type
                        )

    def _absolute_module(self, index: FileIndex, imp: ImportRec) -> str:
        if not imp.level:
            return imp.module or ""
        base = index.module
        if not index.is_package:
            base = base.rsplit(".", 1)[0] if "." in base else ""
        for _ in range(max(0, imp.level - 1)):
            base = base.rsplit(".", 1)[0] if "." in base else ""
        if imp.module:
            return f"{base}.{imp.module}" if base else imp.module
        return base

    def module_status(self, name: str) -> Binding:
        if not name:
            return Binding("unknown", name)
        if name in self.module_map:
            return Binding("module", name, 1.0)
        if any(module.startswith(name + ".") for module in self.module_map):
            return Binding("namespace", name, 0.9)
        top = name.split(".")[0]
        if top in self.local_tops:
            return Binding("unknown", name, 0.0)
        return Binding("external", top, 0.9)

    def _import_bindings(self, index: FileIndex, imp: ImportRec) -> list[tuple[str, Binding]]:
        out: list[tuple[str, Binding]] = []
        if not imp.is_from:
            for name, asname in imp.names:
                status = self.module_status(name)
                if asname:
                    out.append((asname, Binding(status.kind, name if status.kind != "external" else name, status.confidence)))
                else:
                    first = name.split(".")[0]
                    first_status = self.module_status(first)
                    out.append((first, Binding(first_status.kind, first, first_status.confidence)))
            return out

        base = self._absolute_module(index, imp)
        status = self.module_status(base)
        if imp.star:
            self.star_imports.setdefault(index.module, []).append(base)
            return out
        for name, asname in imp.names:
            alias = asname or name
            candidate = f"{base}.{name}" if base else name
            if status.kind == "external":
                out.append((alias, Binding("external", candidate, 0.85)))
                continue
            if status.kind == "unknown":
                out.append((alias, Binding("unknown", candidate, 0.0)))
                continue
            candidate_status = self.module_status(candidate)
            if candidate_status.kind in {"module", "namespace"}:
                out.append((alias, Binding(candidate_status.kind, candidate, candidate_status.confidence)))
            elif candidate in self.symbols:
                out.append((alias, Binding("symbol", candidate, 1.0)))
            else:
                existing = self.module_bindings.get(base, {}).get(name)
                if existing is not None:
                    out.append((alias, existing))
                else:
                    out.append((alias, Binding("unknown", candidate, 0.0)))
        return out

    # --------------------------------------------------------------- imports
    def import_targets(self, index: FileIndex) -> list[ImportTarget]:
        targets: list[ImportTarget] = []
        for imp in index.imports:
            if not imp.is_from:
                for name, _asname in imp.names:
                    status = self.module_status(name)
                    target = name if status.kind in {"module", "namespace"} else status.value
                    targets.append(
                        ImportTarget(status.kind, target, [name], imp.line, status.confidence)
                    )
                continue
            base = self._absolute_module(index, imp)
            status = self.module_status(base)
            target = base if status.kind in {"module", "namespace"} else status.value
            names = [name for name, _ in imp.names if name != "*"]
            targets.append(
                ImportTarget(
                    status.kind,
                    target,
                    names,
                    imp.line,
                    status.confidence,
                    star=imp.star,
                )
            )
        return targets

    # ------------------------------------------------------------ resolution
    def resolve_callee(self, index: FileIndex, call: CallRec) -> list[Resolution]:
        callee = call.callee
        if not callee or any(ch in callee for ch in "()[]{} "):
            if callee.startswith("super()."):
                method = callee[len("super().") :]
                return self._resolve_super(index, call.scope, method, call.line)
            return []
        return self.resolve_dotted(index, callee, call.scope, call.line)

    def resolve_dotted(
        self,
        index: FileIndex,
        dotted: str,
        scope: str,
        line: int = 0,
        depth: int = 0,
    ) -> list[Resolution]:
        dotted = dotted.strip()
        if not dotted or depth > 4:
            return []
        parts = [part for part in dotted.split(".") if part]
        if not parts or not parts[0].isidentifier():
            return []
        first = parts[0]

        exact = self._exact(dotted, line)
        if exact:
            return exact

        if first in {"self", "cls"}:
            return self._resolve_self(index, scope, parts, line)

        scope_res = self._resolve_scope_child(index, scope, parts)
        if scope_res:
            return scope_res

        bindings = self.module_bindings.get(index.module, {})
        binding = bindings.get(first)
        if binding is not None:
            resolved = self._resolve_binding(index, binding, parts, line)
            if resolved:
                return resolved

        for star_base in self.star_imports.get(index.module, []):
            star_binding = self.module_bindings.get(star_base, {}).get(first)
            if star_binding is not None:
                resolved = self._resolve_binding(index, star_binding, parts, line)
                if resolved:
                    return resolved
            star_qual = f"{star_base}.{first}"
            if star_qual in self.symbols:
                if len(parts) == 1:
                    return self._symbol_result(star_qual, 0.9, "import")
                full = f"{star_qual}." + ".".join(parts[1:])
                if full in self.symbols:
                    return self._symbol_result(full, 0.9, "import")
                member = self.class_members.get(star_qual, {}).get(parts[1])
                if member:
                    return self._symbol_result(member, 0.85, "inferred")

        inferred = self._resolve_assignment(index, scope, parts, line, depth)
        if inferred:
            return inferred

        typed = self._resolve_parameter_type(index, scope, parts, line, depth)
        if typed:
            return typed

        if first in BUILTIN_NAMES:
            return []

        candidates = self.short_index.get(first, [])
        if len(candidates) == 1:
            return self._symbol_result(candidates[0], 0.5, "name-only")
        same_module = [qual for qual in candidates if self.symbols[qual][1].path == index.path]
        if len(same_module) == 1:
            return self._symbol_result(same_module[0], 0.6, "name-only")
        return []

    def _exact(self, dotted: str, line: int, confidence: float = 1.0, method: str = "exact") -> list[Resolution]:
        if dotted in self.symbols:
            return self._symbol_result(dotted, confidence, method)
        if dotted in self.module_map:
            return [Resolution("module", dotted, confidence, method)]
        return []

    def _symbol_result(self, qualname: str, confidence: float, method: str) -> list[Resolution]:
        return [Resolution("symbol", qualname, confidence, method)]

    def _resolve_scope_child(self, index: FileIndex, scope: str, parts: list[str]) -> list[Resolution]:
        for ancestor in self._scope_chain(scope):
            children = self.child_defs.get(ancestor, {})
            qual = children.get(parts[0])
            if not qual:
                continue
            if len(parts) == 1:
                return self._symbol_result(qual, 1.0, "exact")
            full = f"{qual}." + ".".join(parts[1:])
            if full in self.symbols:
                return self._symbol_result(full, 0.95, "exact")
            member = self.class_members.get(qual, {}).get(parts[1])
            if member:
                return self._symbol_result(member, 0.9, "inferred")
        return []

    def _resolve_self(self, index: FileIndex, scope: str, parts: list[str], line: int) -> list[Resolution]:
        if len(parts) < 2:
            return []
        cls = self._enclosing_class(scope)
        if not cls:
            return []
        if len(parts) >= 3:
            for scope_name, assigns in self.assignments.items():
                if scope_name != cls and not scope_name.startswith(cls + "."):
                    continue
                assignment = assigns.get(f"self.{parts[1]}")
                if not assignment:
                    continue
                source = assignment.value_callee or assignment.value_type
                if not source:
                    continue
                for base in self.resolve_dotted(index, source, scope_name, line, depth=1):
                    if base.kind == "symbol":
                        member = self._member(base.target, parts[2], set())
                        if member:
                            return self._symbol_result(member, 0.7, "inferred")
                    elif base.kind == "external":
                        symbol = base.attrs.get("symbol", base.target)
                        full = symbol + "." + ".".join(parts[2:])
                        return [
                            Resolution(
                                "external",
                                base.target,
                                base.confidence * 0.75,
                                "inferred",
                                {"symbol": full},
                            )
                        ]
        member = self._member(cls, parts[1], set())
        if member:
            confidence = 0.9 if parts[1] in self.class_members.get(cls, {}) else 0.7
            return self._symbol_result(member, confidence, "inferred")
        return []

    def _resolve_super(self, index: FileIndex, scope: str, method: str, line: int) -> list[Resolution]:
        cls = self._enclosing_class(scope)
        if not cls:
            return []
        for base in self.class_bases.get(cls, []):
            for resolution in self.resolve_dotted(index, base, cls, line, depth=1):
                if resolution.kind == "symbol":
                    member = self._member(resolution.target, method, set())
                    if member:
                        return self._symbol_result(member, 0.7, "inferred")
        return []

    def _enclosing_class(self, scope: str) -> str | None:
        for ancestor in self._scope_chain(scope):
            if self._is_class(ancestor):
                return ancestor
        return None

    def _member(self, cls: str, name: str, seen: set[str]) -> str | None:
        if cls in seen:
            return None
        seen.add(cls)
        direct = self.class_members.get(cls, {}).get(name)
        if direct:
            return direct
        for base in self.class_bases.get(cls, []):
            for resolution in self.resolve_dotted(self._index_for_qualname(cls), base, cls, depth=1):
                if resolution.kind == "symbol":
                    found = self._member(resolution.target, name, seen)
                    if found:
                        return found
        return None

    def _index_for_qualname(self, qualname: str) -> FileIndex:
        entry = self.symbols.get(qualname)
        if entry:
            return self.indexes[entry[0]]
        return FileIndex(path="", module="", is_package=False)

    def _resolve_binding(self, index: FileIndex, binding: Binding, parts: list[str], line: int) -> list[Resolution]:
        rest = parts[1:]
        if binding.kind == "external":
            full = binding.value + ("." + ".".join(rest) if rest else "")
            top = binding.value.split(".")[0]
            return [Resolution("external", top, binding.confidence, "import", {"symbol": full})]
        if binding.kind == "symbol":
            if not rest:
                return self._symbol_result(binding.value, binding.confidence, "import")
            full = f"{binding.value}." + ".".join(rest)
            if full in self.symbols:
                return self._symbol_result(full, 0.95, "import")
            member = self.class_members.get(binding.value, {}).get(rest[0])
            if member:
                return self._symbol_result(member, 0.9, "inferred")
            inherited = self._member(binding.value, rest[0], set())
            if inherited:
                return self._symbol_result(inherited, 0.85, "inferred")
            return []
        if binding.kind in {"module", "namespace"}:
            if not rest:
                status = self.module_status(binding.value)
                return [Resolution(status.kind, binding.value, status.confidence, "import")]
            sub_binding = self.module_bindings.get(binding.value, {}).get(rest[0])
            if sub_binding is not None:
                return self._resolve_binding(index, sub_binding, rest, line)
            full = f"{binding.value}." + ".".join(rest)
            if full in self.symbols:
                return self._symbol_result(full, 0.95, "import")
            status = self.module_status(full)
            if status.kind in {"module", "namespace"}:
                return [Resolution(status.kind, full, status.confidence, "import")]
            member = self.class_members.get(binding.value, {}).get(rest[0])
            if member:
                return self._symbol_result(member, 0.85, "inferred")
            return []
        return []

    def _resolve_assignment(
        self, index: FileIndex, scope: str, parts: list[str], line: int, depth: int
    ) -> list[Resolution]:
        if len(parts) < 2:
            return []
        assignment = None
        for ancestor in self._scope_chain(scope):
            assignment = self.assignments.get(ancestor, {}).get(parts[0])
            if assignment:
                break
        if not assignment:
            return []
        source = assignment.value_callee or assignment.value_type
        if not source or source.split(".")[0] == parts[0]:
            return []
        base_results = self.resolve_dotted(index, source, scope, line, depth + 1)
        out: list[Resolution] = []
        for base in base_results:
            if base.kind == "symbol":
                member = self._member(base.target, parts[1], set())
                if member:
                    out.append(Resolution("symbol", member, base.confidence * 0.85, "inferred"))
                elif len(parts) == 2:
                    full = f"{base.target}.{parts[1]}"
                    if full in self.symbols:
                        out.append(Resolution("symbol", full, base.confidence * 0.8, "inferred"))
                entry = self.symbols.get(base.target)
                definition = entry[1] if entry else None
                if definition is not None and definition.return_type:
                    for returned in self._resolve_type(
                        index, definition.return_type, scope, line, depth + 1
                    ):
                        if returned.kind == "symbol":
                            member = self._member(returned.target, parts[1], set())
                            if member:
                                out.append(
                                    Resolution("symbol", member, base.confidence * 0.7, "inferred")
                                )
                        elif returned.kind == "external":
                            symbol = returned.attrs.get("symbol", returned.target)
                            full = symbol + "." + ".".join(parts[1:])
                            out.append(
                                Resolution(
                                    "external",
                                    returned.target,
                                    returned.confidence * 0.75,
                                    "inferred",
                                    {"symbol": full},
                                )
                            )
            elif base.kind == "external":
                symbol = base.attrs.get("symbol", base.target)
                full = f"{symbol}." + ".".join(parts[1:])
                out.append(Resolution("external", base.target, base.confidence * 0.8, "inferred", {"symbol": full}))
            elif base.kind in {"module", "namespace"}:
                full = f"{base.target}." + ".".join(parts[1:])
                if full in self.symbols:
                    out.append(Resolution("symbol", full, base.confidence * 0.85, "inferred"))
                else:
                    status = self.module_status(full)
                    if status.kind in {"module", "namespace"}:
                        out.append(Resolution(status.kind, full, status.confidence * 0.85, "inferred"))
        return out

    def _def_for_scope(self, scope: str) -> DefRec | None:
        for ancestor in self._scope_chain(scope):
            entry = self.symbols.get(ancestor)
            if entry and entry[1].kind in {"function", "method", "endpoint", "task", "cli"}:
                return entry[1]
        return None

    def _type_candidates(self, annotation: str) -> list[str]:
        text = annotation.strip().strip("'\"")
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_.]*", text)
        wrappers = {
            "typing", "Optional", "Union", "List", "list", "Dict", "dict", "Set", "set",
            "Sequence", "Iterable", "Mapping", "Annotated", "Type", "ClassVar", "None",
            "Any", "Callable", "tuple", "Tuple",
        }
        candidates: list[str] = []
        for token in tokens:
            if token.split(".")[-1] in wrappers:
                continue
            if token not in candidates:
                candidates.append(token)
        known = [
            token
            for token in candidates
            if token in self.symbols
            or token in self.module_map
            or token.split(".")[0] in self.local_tops
        ]
        return known + [token for token in candidates if token not in known]

    def _resolve_type(
        self, index: FileIndex, annotation: str, scope: str, line: int, depth: int
    ) -> list[Resolution]:
        for candidate in self._type_candidates(annotation):
            results = self.resolve_dotted(index, candidate, scope, line, depth)
            if results:
                return results
        return []

    def _resolve_parameter_type(
        self, index: FileIndex, scope: str, parts: list[str], line: int, depth: int
    ) -> list[Resolution]:
        definition = self._def_for_scope(scope)
        if definition is None:
            return []
        annotation = definition.arg_types.get(parts[0])
        if not annotation:
            return []
        rest = parts[1:]
        if not rest:
            return []
        for base in self._resolve_type(index, annotation, scope, line, depth + 1):
            if base.kind == "symbol":
                member = self._member(base.target, rest[0], set())
                if member:
                    return [Resolution("symbol", member, base.confidence * 0.75, "inferred")]
                full = base.target + "." + ".".join(rest)
                if full in self.symbols:
                    return [Resolution("symbol", full, base.confidence * 0.75, "inferred")]
            elif base.kind == "external":
                symbol = base.attrs.get("symbol", base.target)
                return [
                    Resolution(
                        "external",
                        base.target,
                        base.confidence * 0.75,
                        "inferred",
                        {"symbol": symbol + "." + ".".join(rest)},
                    )
                ]
            elif base.kind in {"module", "namespace"}:
                full = base.target + "." + ".".join(rest)
                if full in self.symbols:
                    return [Resolution("symbol", full, base.confidence * 0.75, "inferred")]
                return [Resolution(base.kind, full, base.confidence * 0.75, "inferred")]
        return []

    def _scope_chain(self, scope: str) -> Iterable[str]:
        parts = [part for part in scope.split(".") if part]
        for end in range(len(parts), 0, -1):
            yield ".".join(parts[:end])
