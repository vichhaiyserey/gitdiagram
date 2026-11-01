"""End-to-end analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .ast_index import index_repo
from .discover import RepoInfo, discover
from .features import assign_features
from .frameworks import annotate
from .graph_builder import BuildStats, GraphBuilder
from .iac import analyze_iac
from .model import Graph
from .resolver import Resolver
from .security import analyze as analyze_security


@dataclass(slots=True)
class AnalysisConfig:
    root: Path
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    min_confidence: float = 0.5
    max_nodes: int = 2000
    security: bool = True


@dataclass(slots=True)
class AnalysisResult:
    repo: RepoInfo
    graph: Graph
    stats: BuildStats
    python_files: int
    parse_errors: list[str] = field(default_factory=list)


def run_analysis(config: AnalysisConfig) -> AnalysisResult:
    repo = discover(config.root, config.include, config.exclude)
    indexes = index_repo(repo.root, repo.python_files)
    annotate(indexes)

    resolver = Resolver(indexes)
    builder = GraphBuilder(indexes, resolver, max_nodes=config.max_nodes)
    graph = builder.build()

    findings = []
    if config.security:
        findings.extend(analyze_iac(graph, repo))
        findings.extend(analyze_security(graph, indexes, resolver, repo.root, repo.rel_files))
    merged: dict[str, object] = {}
    for finding in findings:
        merged.setdefault(finding.id, finding)
    graph.findings = list(merged.values())
    graph.edges = [
        edge
        for edge in graph.edges
        if edge.confidence >= config.min_confidence or edge.kind in {"contains", "imports"}
    ]
    assign_features(graph)

    parse_errors = sorted(path for path, index in indexes.items() if index.error)
    graph.meta.update(
        {
            "name": repo.name,
            "commit": repo.commit,
            "branch": repo.branch,
            "dirty": repo.dirty,
            "is_git": repo.is_git,
            "python_files": len(indexes),
            "iac_files": len(repo.iac_files),
            "include": sorted(config.include),
            "exclude": sorted(config.exclude),
            "min_confidence": config.min_confidence,
            "analysis": {
                "unresolved_count": graph.meta.get("unresolved_count", 0),
                "truncated": graph.meta.get("truncated", False),
                "dropped_nodes": graph.meta.get("dropped_nodes", 0),
                "parse_errors": parse_errors,
            },
        }
    )
    return AnalysisResult(
        repo=repo,
        graph=graph,
        stats=builder.stats,
        python_files=len(indexes),
        parse_errors=parse_errors,
    )
