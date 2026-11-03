"""Stable, serialisable graph model shared by every analyzer and renderer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import SCHEMA_VERSION, __version__

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def stable_id(*parts: str) -> str:
    """Return a deterministic, collision-resistant identifier."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:12]


@dataclass(slots=True)
class Loc:
    """A source location used as evidence for a node, edge, or finding."""

    path: str
    line: int
    col: int = 0

    @property
    def ref(self) -> str:
        return f"{self.path}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "col": self.col}


@dataclass(slots=True)
class Node:
    id: str
    kind: str
    name: str
    qualname: str
    path: str | None = None
    line: int | None = None
    feature: str | None = None
    doc: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def evidence(self) -> Loc | None:
        if self.path and self.line:
            return Loc(self.path, self.line)
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "qualname": self.qualname,
            "path": self.path,
            "line": self.line,
            "feature": self.feature,
            "doc": self.doc,
        }
        if self.attrs:
            out["attrs"] = self.attrs
        return out


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    kind: str
    confidence: float = 1.0
    resolution: str = "exact"
    evidence: list[Loc] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "confidence": round(float(self.confidence), 2),
            "resolution": self.resolution,
            "evidence": [loc.to_dict() for loc in self.evidence],
        }
        if self.attrs:
            out["attrs"] = self.attrs
        return out


@dataclass(slots=True)
class Feature:
    id: str
    name: str
    description: str = ""
    nodes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "nodes": sorted(self.nodes),
            "files": sorted(self.files),
        }


@dataclass(slots=True)
class Finding:
    id: str
    category: str
    severity: str
    title: str
    message: str
    node_id: str | None = None
    cwe: str | None = None
    confidence: float = 0.8
    evidence: list[Loc] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "node_id": self.node_id,
            "cwe": self.cwe,
            "confidence": round(float(self.confidence), 2),
            "evidence": [loc.to_dict() for loc in self.evidence],
            "recommendation": self.recommendation,
        }
        return out


@dataclass(slots=True)
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    features: list[Feature] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        if existing.feature is None and node.feature is not None:
            existing.feature = node.feature
        if existing.doc is None and node.doc is not None:
            existing.doc = node.doc
        for key, value in node.attrs.items():
            existing.attrs.setdefault(key, value)
        return existing

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: str,
        *,
        confidence: float = 1.0,
        resolution: str = "exact",
        evidence: Iterable[Loc] = (),
        attrs: dict[str, Any] | None = None,
    ) -> Edge | None:
        if src not in self.nodes or dst not in self.nodes:
            return None
        edge = Edge(
            src=src,
            dst=dst,
            kind=kind,
            confidence=confidence,
            resolution=resolution,
            evidence=list(evidence),
            attrs=dict(attrs or {}),
        )
        self.edges.append(edge)
        return edge

    def find_node_by_qualname(self, qualname: str) -> Node | None:
        for node in self.nodes.values():
            if node.qualname == qualname:
                return node
        return None

    def sorted_nodes(self) -> list[Node]:
        return sorted(self.nodes.values(), key=lambda n: (n.feature or "", n.kind, n.qualname, n.path or ""))

    def sorted_edges(self) -> list[Edge]:
        return sorted(self.edges, key=lambda e: (e.kind, e.src, e.dst, e.resolution))

    def sorted_findings(self) -> list[Finding]:
        def key(f: Finding) -> tuple[Any, ...]:
            first = f.evidence[0] if f.evidence else None
            return (
                -SEVERITY_RANK.get(f.severity, 0),
                f.category,
                first.path if first else "",
                first.line if first else 0,
                f.id,
            )

        return sorted(self.findings, key=key)

    def dedupe_edges(self) -> None:
        merged: dict[tuple[str, str, str], Edge] = {}
        for edge in self.edges:
            key = (edge.src, edge.dst, edge.kind)
            current = merged.get(key)
            if current is None:
                merged[key] = edge
                continue
            current.confidence = max(current.confidence, edge.confidence)
            if edge.resolution == "exact":
                current.resolution = "exact"
            for loc in edge.evidence:
                if all(loc.ref != seen.ref for seen in current.evidence):
                    current.evidence.append(loc)
            for attr_key, value in edge.attrs.items():
                current.attrs.setdefault(attr_key, value)
        self.edges = sorted(merged.values(), key=lambda e: (e.kind, e.src, e.dst))

    def to_dict(self) -> dict[str, Any]:
        self.dedupe_edges()
        self.findings = self.sorted_findings()
        return {
            "schema_version": SCHEMA_VERSION,
            "meta": {
                **self.meta,
                "tool": "secdiagram",
                "tool_version": __version__,
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "feature_count": len(self.features),
                "finding_count": len(self.findings),
            },
            "features": [feature.to_dict() for feature in sorted(self.features, key=lambda f: f.name)],
            "nodes": [node.to_dict() for node in self.sorted_nodes()],
            "edges": [edge.to_dict() for edge in self.sorted_edges()],
            "findings": [finding.to_dict() for finding in self.findings],
        }
