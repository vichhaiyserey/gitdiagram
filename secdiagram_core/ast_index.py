"""Per-file Python AST extraction: definitions, imports, calls, and assignments."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cache import IndexCache, file_digest, resolve_jobs

MAX_TEXT = 240
MAX_SOURCE_BYTES = 5 * 1024 * 1024


def _text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        rendered = ast.unparse(node)
    except Exception:  # pragma: no cover - defensive for exotic nodes
        rendered = node.__class__.__name__
    rendered = " ".join(rendered.split())
    if len(rendered) > MAX_TEXT:
        rendered = rendered[: MAX_TEXT - 3] + "..."
    return rendered


@dataclass(slots=True)
class ImportRec:
    module: str | None
    names: list[tuple[str, str | None]]
    level: int
    line: int
    is_from: bool
    star: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "names": [[name, alias] for name, alias in self.names],
            "level": self.level,
            "line": self.line,
            "is_from": self.is_from,
            "star": self.star,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> ImportRec:
        return cls(
            module=data.get("module"),
            names=[(str(pair[0]), pair[1]) for pair in data.get("names", [])],
            level=int(data.get("level", 0)),
            line=int(data.get("line", 0)),
            is_from=bool(data.get("is_from", False)),
            star=bool(data.get("star", False)),
        )


@dataclass(slots=True)
class DefRec:
    kind: str
    name: str
    qualname: str
    path: str
    line: int
    col: int
    end_line: int
    doc: str | None
    decorators: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    parent: str | None = None
    args: list[str] = field(default_factory=list)
    positional_args: list[str] = field(default_factory=list)
    arg_types: dict[str, str] = field(default_factory=dict)
    return_type: str | None = None
    is_async: bool = False
    routes: list[dict[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "doc": self.doc,
            "decorators": self.decorators,
            "bases": self.bases,
            "parent": self.parent,
            "args": self.args,
            "positional_args": self.positional_args,
            "arg_types": self.arg_types,
            "return_type": self.return_type,
            "is_async": self.is_async,
            "routes": self.routes,
            "tags": self.tags,
            "attrs": self.attrs,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> DefRec:
        return cls(
            kind=str(data["kind"]),
            name=str(data["name"]),
            qualname=str(data["qualname"]),
            path=str(data["path"]),
            line=int(data["line"]),
            col=int(data.get("col", 0)),
            end_line=int(data.get("end_line", 0)),
            doc=data.get("doc"),
            decorators=list(data.get("decorators", [])),
            bases=list(data.get("bases", [])),
            parent=data.get("parent"),
            args=list(data.get("args", [])),
            positional_args=list(data.get("positional_args", [])),
            arg_types=dict(data.get("arg_types", {})),
            return_type=data.get("return_type"),
            is_async=bool(data.get("is_async", False)),
            routes=list(data.get("routes", [])),
            tags=list(data.get("tags", [])),
            attrs=dict(data.get("attrs", {})),
        )


@dataclass(slots=True)
class CallRec:
    scope: str
    scope_kind: str
    callee: str
    line: int
    col: int
    arg_texts: list[str] = field(default_factory=list)
    arg_names: list[str] = field(default_factory=list)
    arg_names_by_position: list[list[str]] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)
    assigned_to: list[str] = field(default_factory=list)
    has_star: bool = False
    has_fstring: bool = False
    is_await: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "scope_kind": self.scope_kind,
            "callee": self.callee,
            "line": self.line,
            "col": self.col,
            "arg_texts": self.arg_texts,
            "arg_names": self.arg_names,
            "arg_names_by_position": self.arg_names_by_position,
            "keywords": self.keywords,
            "assigned_to": self.assigned_to,
            "has_star": self.has_star,
            "has_fstring": self.has_fstring,
            "is_await": self.is_await,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> CallRec:
        return cls(
            scope=str(data["scope"]),
            scope_kind=str(data["scope_kind"]),
            callee=str(data["callee"]),
            line=int(data["line"]),
            col=int(data.get("col", 0)),
            arg_texts=list(data.get("arg_texts", [])),
            arg_names=list(data.get("arg_names", [])),
            arg_names_by_position=[list(item) for item in data.get("arg_names_by_position", [])],
            keywords=dict(data.get("keywords", {})),
            assigned_to=list(data.get("assigned_to", [])),
            has_star=bool(data.get("has_star", False)),
            has_fstring=bool(data.get("has_fstring", False)),
            is_await=bool(data.get("is_await", False)),
        )


@dataclass(slots=True)
class AssignRec:
    scope: str
    target: str
    value_text: str
    value_names: list[str] = field(default_factory=list)
    value_callee: str | None = None
    value_type: str | None = None
    line: int = 0

    def to_payload(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "target": self.target,
            "value_text": self.value_text,
            "value_names": self.value_names,
            "value_callee": self.value_callee,
            "value_type": self.value_type,
            "line": self.line,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> AssignRec:
        return cls(
            scope=str(data["scope"]),
            target=str(data.get("target", "")),
            value_text=str(data.get("value_text", "")),
            value_names=list(data.get("value_names", [])),
            value_callee=data.get("value_callee"),
            value_type=data.get("value_type"),
            line=int(data.get("line", 0)),
        )


@dataclass(slots=True)
class FileIndex:
    path: str
    module: str
    is_package: bool
    doc: str | None = None
    imports: list[ImportRec] = field(default_factory=list)
    defs: list[DefRec] = field(default_factory=list)
    calls: list[CallRec] = field(default_factory=list)
    assigns: list[AssignRec] = field(default_factory=list)
    strings: list[tuple[str, int]] = field(default_factory=list)
    error: str | None = None
    text: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "module": self.module,
            "is_package": self.is_package,
            "doc": self.doc,
            "imports": [item.to_payload() for item in self.imports],
            "defs": [item.to_payload() for item in self.defs],
            "calls": [item.to_payload() for item in self.calls],
            "assigns": [item.to_payload() for item in self.assigns],
            "strings": [[text, line] for text, line in self.strings],
            "error": self.error,
            "text": self.text,
        }

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> FileIndex:
        return cls(
            path=str(data["path"]),
            module=str(data["module"]),
            is_package=bool(data.get("is_package", False)),
            doc=data.get("doc"),
            imports=[ImportRec.from_payload(item) for item in data.get("imports", [])],
            defs=[DefRec.from_payload(item) for item in data.get("defs", [])],
            calls=[CallRec.from_payload(item) for item in data.get("calls", [])],
            assigns=[AssignRec.from_payload(item) for item in data.get("assigns", [])],
            strings=[(str(item[0]), int(item[1])) for item in data.get("strings", [])],
            error=data.get("error"),
            text=str(data.get("text", "")),
        )


def _expr_names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.add(child.id)
        elif isinstance(child, ast.Attribute):
            names.add(_text(child))
    return sorted(names)


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[str] = []
        for element in node.elts:
            out.extend(_target_names(element))
        return out
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return [_text(node)]
    return []


def _has_fstring(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            return True
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "format":
            return True
    return False


class _Indexer(ast.NodeVisitor):
    def __init__(self, path: str, module: str, is_package: bool) -> None:
        self.index = FileIndex(path=path, module=module, is_package=is_package)
        self.scope: list[tuple[str, str]] = [(module, "module")]

    @property
    def current_scope(self) -> tuple[str, str]:
        return self.scope[-1]

    def visit_Module(self, node: ast.Module) -> None:
        self.index.doc = ast.get_docstring(node, clean=True)
        for child in node.body:
            self.visit(child)

    def _decorators(self, node: ast.AST) -> list[str]:
        out = []
        for dec in getattr(node, "decorator_list", []):
            out.append(_text(dec))
        return out

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str | None = None) -> None:
        parent, parent_kind = self.current_scope
        qualname = f"{parent}.{node.name}" if parent else node.name
        actual_kind = kind or ("method" if parent_kind == "class" else "function")
        positional = [arg.arg for arg in node.args.posonlyargs + node.args.args]
        all_args = (
            positional
            + ([node.args.vararg.arg] if node.args.vararg else [])
            + [arg.arg for arg in node.args.kwonlyargs]
            + ([node.args.kwarg.arg] if node.args.kwarg else [])
        )
        arg_types = {}
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            if arg.annotation is not None:
                arg_types[arg.arg] = _text(arg.annotation)
        for maybe_arg in (node.args.vararg, node.args.kwarg):
            if maybe_arg is not None and maybe_arg.annotation is not None:
                arg_types[maybe_arg.arg] = _text(maybe_arg.annotation)
        record = DefRec(
            kind=actual_kind,
            name=node.name,
            qualname=qualname,
            path=self.index.path,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            doc=ast.get_docstring(node, clean=True),
            decorators=self._decorators(node),
            parent=parent,
            args=all_args,
            positional_args=positional,
            arg_types=arg_types,
            return_type=_text(node.returns) if node.returns is not None else None,
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )
        self.index.defs.append(record)

        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            self.visit(default)

        self.scope.append((qualname, "function"))
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        parent, _ = self.current_scope
        qualname = f"{parent}.{node.name}" if parent else node.name
        record = DefRec(
            kind="class",
            name=node.name,
            qualname=qualname,
            path=self.index.path,
            line=node.lineno,
            col=node.col_offset,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            doc=ast.get_docstring(node, clean=True),
            decorators=self._decorators(node),
            bases=[_text(base) for base in node.bases],
            parent=parent,
        )
        self.index.defs.append(record)
        self.scope.append((qualname, "class"))
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        names = [(alias.name, alias.asname) for alias in node.names]
        self.index.imports.append(
            ImportRec(module=None, names=names, level=0, line=node.lineno, is_from=False)
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        names = [(alias.name, alias.asname) for alias in node.names]
        star = any(name == "*" for name, _ in names)
        self.index.imports.append(
            ImportRec(
                module=node.module,
                names=names,
                level=node.level or 0,
                line=node.lineno,
                is_from=True,
                star=star,
            )
        )

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) <= 2000:
            self.index.strings.append((node.value, node.lineno))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets: list[str] = []
        for target in node.targets:
            targets.extend(_target_names(target))
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        else:
            self.visit(node.value)
        for target in node.targets:
            if not isinstance(target, (ast.Name, ast.Tuple, ast.List)):
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        targets = _target_names(node.target)
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                value_type=_text(node.annotation),
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        elif node.value is not None:
            self.visit(node.value)
        self.visit(node.annotation)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        targets = _target_names(node.target)
        value_callee = _text(node.value.func) if isinstance(node.value, ast.Call) else None
        self.index.assigns.append(
            AssignRec(
                scope=self.current_scope[0],
                target=", ".join(targets),
                value_text=_text(node.value),
                value_names=_expr_names(node.value),
                value_callee=value_callee,
                line=node.lineno,
            )
        )
        if isinstance(node.value, ast.Call):
            self._record_call(node.value, assigned_to=targets)
        else:
            self.visit(node.value)
        self.visit(node.target)

    def _with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            targets = _target_names(item.optional_vars) if item.optional_vars is not None else []
            value_callee = _text(item.context_expr.func) if isinstance(item.context_expr, ast.Call) else None
            self.index.assigns.append(
                AssignRec(
                    scope=self.current_scope[0],
                    target=", ".join(targets),
                    value_text=_text(item.context_expr),
                    value_names=_expr_names(item.context_expr),
                    value_callee=value_callee,
                    line=getattr(item.context_expr, "lineno", node.lineno),
                )
            )
            if isinstance(item.context_expr, ast.Call):
                self._record_call(item.context_expr, assigned_to=targets)
            else:
                self.visit(item.context_expr)
        for child in node.body:
            self.visit(child)

    def visit_With(self, node: ast.With) -> None:
        self._with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._with(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._record_call(node)

    def _record_call(self, node: ast.Call, assigned_to: Iterable[str] | None = None) -> None:
        scope, scope_kind = self.current_scope
        args = list(node.args)
        self.index.calls.append(
            CallRec(
                scope=scope,
                scope_kind=scope_kind,
                callee=_text(node.func),
                line=node.lineno,
                col=node.col_offset,
                arg_texts=[_text(arg) for arg in args],
                arg_names=sorted({name for arg in args for name in _expr_names(arg)}),
                arg_names_by_position=[_expr_names(arg) for arg in args],
                keywords={kw.arg or "**": _text(kw.value) for kw in node.keywords},
                assigned_to=list(assigned_to or []),
                has_star=any(isinstance(arg, ast.Starred) for arg in args),
                has_fstring=any(_has_fstring(arg) for arg in args),
                is_await=isinstance(getattr(node, "parent", None), ast.Await),
            )
        )
        self.visit(node.func)
        for arg in args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)


def module_name_for_path(path: str) -> tuple[str, bool]:
    """Derive a dotted module name from a repo-relative path."""
    parts = path.replace("\\", "/").split("/")
    is_package = parts[-1] == "__init__.py"
    if is_package:
        parts = parts[:-1]
    else:
        parts = parts[:-1] + [parts[-1][:-3]]
    if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
        parts = parts[1:]
    if not parts:
        return "__init__", True
    return ".".join(parts), is_package


def index_file(root: Path, rel_path: str) -> FileIndex:
    module, is_package = module_name_for_path(rel_path)
    absolute = root / rel_path
    try:
        resolved = absolute.resolve()
        if not resolved.is_relative_to(root.resolve()):
            return FileIndex(path=rel_path, module=module, is_package=is_package, error="path escapes repository root")
    except (ValueError, OSError) as exc:
        return FileIndex(path=rel_path, module=module, is_package=is_package, error=f"path resolution error: {exc}")
    try:
        if absolute.stat().st_size > MAX_SOURCE_BYTES:
            return FileIndex(
                path=rel_path,
                module=module,
                is_package=is_package,
                error=f"file exceeds {MAX_SOURCE_BYTES} byte index limit",
            )
        text = absolute.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        return FileIndex(path=rel_path, module=module, is_package=is_package, error=f"read error: {exc}")
    index = FileIndex(path=rel_path, module=module, is_package=is_package, text=text)
    try:
        tree = ast.parse(text, filename=rel_path)
    except (SyntaxError, ValueError) as exc:
        if isinstance(exc, SyntaxError):
            index.error = f"SyntaxError: {exc.msg} (line {exc.lineno})"
        else:
            index.error = f"{type(exc).__name__}: {exc}"
        return index
    visitor = _Indexer(rel_path, module, is_package)
    visitor.visit(tree)
    result = visitor.index
    result.text = text
    result.doc = ast.get_docstring(tree, clean=True)
    return result


def _index_task(root: str, rel_path: str) -> FileIndex:
    return index_file(Path(root), rel_path)


def index_repo(
    root: Path,
    rel_paths: list[str],
    *,
    jobs: int = 1,
    cache: IndexCache | None = None,
) -> dict[str, FileIndex]:
    """Index Python files, optionally reusing cached payloads in parallel.

    Results are assembled in sorted repository order regardless of worker
    completion order, keeping every downstream graph deterministic.
    """
    ordered = sorted(set(rel_paths))
    results: dict[str, FileIndex] = {}
    misses: list[tuple[str, str]] = []

    for rel_path in ordered:
        digest = file_digest(root / rel_path) if cache is not None and cache.enabled else None
        if digest is not None and cache is not None:
            payload = cache.load(rel_path, digest)
            if payload is not None:
                try:
                    results[rel_path] = FileIndex.from_payload(payload)
                    continue
                except (KeyError, TypeError, ValueError, IndexError):
                    cache.errors += 1
        if digest is not None:
            misses.append((rel_path, digest))
        else:
            misses.append((rel_path, ""))

    workers = resolve_jobs(jobs, len(misses))
    if workers <= 1 or len(misses) < 2:
        for rel_path, digest in misses:
            index = index_file(root, rel_path)
            results[rel_path] = index
            if cache is not None and digest:
                cache.save(rel_path, digest, index.to_payload())
    else:
        try:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(_index_task, str(root), rel_path): (rel_path, digest)
                    for rel_path, digest in misses
                }
                for future in as_completed(futures):
                    rel_path, digest = futures[future]
                    try:
                        index = future.result()
                    except Exception:  # pragma: no cover - worker crash fallback
                        index = index_file(root, rel_path)
                    results[rel_path] = index
                    if cache is not None and digest:
                        cache.save(rel_path, digest, index.to_payload())
        except Exception:  # pragma: no cover - pool startup/runtime fallback
            for rel_path, digest in misses:
                if rel_path in results:
                    continue
                index = index_file(root, rel_path)
                results[rel_path] = index
                if cache is not None and digest:
                    cache.save(rel_path, digest, index.to_payload())

    return {rel_path: results[rel_path] for rel_path in ordered if rel_path in results}
