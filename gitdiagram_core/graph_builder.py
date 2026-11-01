"""Assemble the code graph from AST indexes and resolver output."""

from __future__ import annotations

import builtins
import re
import sys
from dataclasses import dataclass, field

from .ast_index import FileIndex
from .model import Graph, Loc, Node, stable_id
from .resolver import Resolution, Resolver

BASE_SPLIT_RE = re.compile(r"[\[\(]")


@dataclass(slots=True)
class BuildStats:
    unresolved: list[dict[str, object]] = field(default_factory=list)
    duplicate_modules: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    dropped_nodes: int = 0


def _module_node(index: FileIndex) -> Node:
    attrs: dict[str, object] = {
        "is_package": index.is_package,
        "parse_error": index.error,
    }
    return Node(
        id=stable_id("module", index.module),
        kind="module",
        name=index.module,
        qualname=index.module,
        path=index.path,
        line=1,
        doc=index.doc,
        attrs=attrs,
    )


def _def_node(index: FileIndex, definition) -> Node:
    attrs: dict[str, object] = {}
    if definition.decorators:
        attrs["decorators"] = definition.decorators
    if definition.bases:
        attrs["bases"] = definition.bases
    if definition.routes:
        attrs["routes"] = definition.routes
    if definition.tags:
        attrs["tags"] = definition.tags
    if definition.is_async:
        attrs["async"] = True
    if definition.args:
        attrs["args"] = definition.args
    return Node(
        id=stable_id("symbol", definition.path, definition.qualname),
        kind=definition.kind,
        name=definition.name,
        qualname=definition.qualname,
        path=definition.path,
        line=definition.line,
        doc=definition.doc,
        attrs=attrs,
    )


class GraphBuilder:
    def __init__(self, indexes: dict[str, FileIndex], resolver: Resolver, max_nodes: int = 2000) -> None:
        self.indexes = indexes
        self.resolver = resolver
        self.graph = Graph()
        self.stats = BuildStats(duplicate_modules={k: sorted(v) for k, v in resolver.duplicate_modules.items()})
        self.module_ids: dict[str, str] = {}
        self.symbol_ids: dict[str, str] = {}
        self.external_ids: dict[str, str] = {}
        self.namespace_ids: dict[str, str] = {}
        self.scope_ids: dict[str, str] = {}
        self.max_nodes = max_nodes

    # ------------------------------------------------------------------ nodes
    def _ensure_external(self, top: str, symbol: str | None = None, module: str | None = None) -> str | None:
        if not top or not top.isidentifier() or top in sys.stdlib_module_names or top == "__future__":
            return None
        node_id = self.external_ids.get(top)
        if node_id is None:
            node = Node(
                id=stable_id("external", top),
                kind="external",
                name=top,
                qualname=top,
                attrs={"modules": [], "symbols": []},
            )
            self.graph.add_node(node)
            self.external_ids[top] = node.id
            node_id = node.id
        node = self.graph.nodes[node_id]
        if module and module not in node.attrs["modules"]:
            node.attrs["modules"].append(module)
            node.attrs["modules"].sort()
        if symbol and symbol not in node.attrs["symbols"]:
            node.attrs["symbols"].append(symbol)
            node.attrs["symbols"].sort()
        return node_id

    def _ensure_namespace(self, name: str) -> str:
        if name in self.module_ids:
            return self.module_ids[name]
        existing = self.namespace_ids.get(name)
        if existing:
            return existing
        node = Node(
            id=stable_id("package", name),
            kind="package",
            name=name,
            qualname=name,
            attrs={"namespace": True},
        )
        self.graph.add_node(node)
        self.namespace_ids[name] = node.id
        return node.id

    def _ensure_module_or_namespace(self, name: str) -> str | None:
        if name in self.module_ids:
            return self.module_ids[name]
        status = self.resolver.module_status(name)
        if status.kind in {"module", "namespace"}:
            return self._ensure_namespace(name)
        if status.kind == "external":
            external = self._ensure_external(status.value, module=name)
            return external or None
        return None

    def _resolve_dst(self, resolution: Resolution) -> str | None:
        if resolution.kind == "symbol":
            return self.symbol_ids.get(resolution.target)
        if resolution.kind in {"module", "namespace"}:
            return self._ensure_module_or_namespace(resolution.target)
        if resolution.kind == "external":
            return self._ensure_external(
                resolution.target,
                symbol=resolution.attrs.get("symbol"),
                module=resolution.attrs.get("module"),
            )
        return None

    # ------------------------------------------------------------------ build
    def build(self) -> Graph:
        self._build_module_and_symbol_nodes()
        self._build_containment()
        self._build_imports()
        self._build_calls()
        self._build_inheritance()
        self.graph.dedupe_edges()
        self._prune()
        self.graph.dedupe_edges()
        meta = self.graph.meta
        meta["duplicate_modules"] = self.stats.duplicate_modules
        meta["unresolved_count"] = len(self.stats.unresolved)
        meta["unresolved_samples"] = self.stats.unresolved[:50]
        meta["truncated"] = self.stats.truncated
        meta["dropped_nodes"] = self.stats.dropped_nodes
        return self.graph

    def _build_module_and_symbol_nodes(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            module_node = _module_node(index)
            self.graph.add_node(module_node)
            self.module_ids[index.module] = module_node.id
            self.scope_ids[index.module] = module_node.id
        for path in sorted(self.indexes):
            index = self.indexes[path]
            for definition in index.defs:
                node = _def_node(index, definition)
                self.graph.add_node(node)
                self.symbol_ids[definition.qualname] = node.id
                self.scope_ids[definition.qualname] = node.id

    def _build_containment(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            module_id = self.module_ids[index.module]
            parent_name = index.module.rsplit(".", 1)[0] if "." in index.module else ""
            if parent_name:
                parent_id = self._ensure_module_or_namespace(parent_name)
                if parent_id and parent_id != module_id:
                    self.graph.add_edge(
                        parent_id,
                        module_id,
                        "contains",
                        confidence=1.0,
                        resolution="exact",
                        evidence=[Loc(index.path, 1)],
                    )
            for definition in index.defs:
                parent_scope = definition.parent or index.module
                parent_id = self.scope_ids.get(parent_scope)
                child_id = self.symbol_ids.get(definition.qualname)
                if parent_id and child_id:
                    self.graph.add_edge(
                        parent_id,
                        child_id,
                        "contains",
                        confidence=1.0,
                        resolution="exact",
                        evidence=[Loc(definition.path, definition.line)],
                    )

    def _build_imports(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            src = self.module_ids[index.module]
            for target in self.resolver.import_targets(index):
                if target.kind == "external":
                    dst = self._ensure_external(target.target, module=target.target)
                elif target.kind in {"module", "namespace"}:
                    if target.target == index.module:
                        continue
                    dst = self._ensure_module_or_namespace(target.target)
                else:
                    self.stats.unresolved.append(
                        {
                            "path": index.path,
                            "line": target.line,
                            "kind": "import",
                            "name": target.target,
                        }
                    )
                    continue
                if not dst or dst == src:
                    continue
                self.graph.add_edge(
                    src,
                    dst,
                    "imports",
                    confidence=target.confidence,
                    resolution="import",
                    evidence=[Loc(index.path, target.line)],
                    attrs={"names": sorted(target.names), "star": target.star},
                )

    def _build_calls(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            for call in sorted(index.calls, key=lambda c: (c.line, c.col, c.callee)):
                src = self.scope_ids.get(call.scope) or self.module_ids.get(index.module)
                if not src:
                    continue
                resolutions = self.resolver.resolve_callee(index, call)
                for resolution in resolutions:
                    dst = self._resolve_dst(resolution)
                    if not dst or dst == src:
                        continue
                    kind = "calls"
                    if resolution.kind == "symbol":
                        entry = self.resolver.symbols.get(resolution.target)
                        if entry and entry[1].kind == "class":
                            kind = "instantiates"
                    attrs = {"callee": call.callee}
                    if resolution.attrs.get("symbol"):
                        attrs["symbol"] = resolution.attrs["symbol"]
                    self.graph.add_edge(
                        src,
                        dst,
                        kind,
                        confidence=resolution.confidence,
                        resolution=resolution.method,
                        evidence=[Loc(index.path, call.line, call.col)],
                        attrs=attrs,
                    )
                if not resolutions:
                    first = call.callee.split(".")[0]
                    if first and first not in dir(builtins) and not any(
                        ch in call.callee for ch in "()[]{} "
                    ):
                        self.stats.unresolved.append(
                            {
                                "path": index.path,
                                "line": call.line,
                                "kind": "call",
                                "name": call.callee,
                                "scope": call.scope,
                            }
                        )

    def _build_inheritance(self) -> None:
        for path in sorted(self.indexes):
            index = self.indexes[path]
            for definition in index.defs:
                if definition.kind != "class":
                    continue
                src = self.symbol_ids.get(definition.qualname)
                if not src:
                    continue
                for base in definition.bases:
                    cleaned = BASE_SPLIT_RE.split(base, 1)[0].strip()
                    if not cleaned or cleaned in {"object", "ABC"}:
                        continue
                    for resolution in self.resolver.resolve_dotted(
                        index, cleaned, definition.qualname, definition.line
                    ):
                        dst = self._resolve_dst(resolution)
                        if not dst or dst == src:
                            continue
                        self.graph.add_edge(
                            src,
                            dst,
                            "inherits",
                            confidence=min(1.0, resolution.confidence),
                            resolution=resolution.method,
                            evidence=[Loc(definition.path, definition.line)],
                            attrs={"base": cleaned},
                        )

    # ------------------------------------------------------------------ prune
    def _prune(self) -> None:
        if self.max_nodes <= 0 or len(self.graph.nodes) <= self.max_nodes:
            return
        degree: dict[str, int] = {}
        for edge in self.graph.edges:
            degree[edge.src] = degree.get(edge.src, 0) + 1
            degree[edge.dst] = degree.get(edge.dst, 0) + 1

        priority = {
            "endpoint": 0,
            "task": 0,
            "cli": 0,
            "workflow": 1,
            "infra": 1,
            "service": 1,
            "module": 2,
            "package": 3,
            "class": 4,
            "function": 5,
            "method": 6,
            "external": 7,
        }
        ranked = sorted(
            self.graph.nodes.values(),
            key=lambda n: (priority.get(n.kind, 9), -degree.get(n.id, 0), n.qualname),
        )
        keep = {node.id for node in ranked[: self.max_nodes]}
        dropped = len(self.graph.nodes) - len(keep)
        self.graph.nodes = {node_id: node for node_id, node in self.graph.nodes.items() if node_id in keep}
        self.graph.edges = [
            edge for edge in self.graph.edges if edge.src in keep and edge.dst in keep
        ]
        self.stats.truncated = True
        self.stats.dropped_nodes = dropped
