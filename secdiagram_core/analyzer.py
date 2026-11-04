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
from .java_index import analyze_java_security, build_java_graph, index_java
from .model import Finding, Graph, stable_id
from .resolver import Resolver
from .security import analyze as analyze_security

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".groovy": "groovy",
    ".scala": "scala",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
}

SECURITY_LANGUAGES = ("java", "python")


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
    java_files: int = 0


def run_analysis(config: AnalysisConfig) -> AnalysisResult:
    repo = discover(config.root, config.include, config.exclude)
    indexes = index_repo(repo.root, repo.python_files)
    annotate(indexes)

    resolver = Resolver(indexes)
    builder = GraphBuilder(indexes, resolver, max_nodes=config.max_nodes)
    graph = builder.build()

    java_index = index_java(repo.root, repo.rel_files)
    if java_index.files:
        build_java_graph(graph, java_index)

    findings: list[Finding] = []
    if config.security:
        findings.extend(analyze_iac(graph, repo))
        findings.extend(analyze_security(graph, indexes, resolver, repo.root, repo.rel_files))
        if java_index.files:
            findings.extend(analyze_java_security(graph, java_index, repo.root, repo.name))
    merged: dict[str, Finding] = {}
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
    languages: dict[str, int] = {}
    for rel in repo.rel_files:
        name = rel.rsplit("/", 1)[-1]
        if "." not in name:
            continue
        suffix = "." + name.rsplit(".", 1)[-1].lower()
        language = LANGUAGE_BY_SUFFIX.get(suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
    languages = dict(sorted(languages.items()))
    unsupported_languages = sorted(
        language for language in languages if language not in SECURITY_LANGUAGES
    )
    config_hash = stable_id(
        "config",
        ",".join(sorted(config.include)),
        ",".join(sorted(config.exclude)),
        str(config.min_confidence),
        str(config.max_nodes),
        str(config.security),
    )
    graph.meta.update(
        {
            "name": repo.name,
            "commit": repo.commit,
            "branch": repo.branch,
            "dirty": repo.dirty,
            "is_git": repo.is_git,
            "python_files": len(indexes),
            "java_files": len(java_index.files),
            "iac_files": len(repo.iac_files),
            "files_discovered": len(repo.rel_files),
            "files_skipped": len(repo.skipped),
            "skipped_samples": sorted(repo.skipped)[:20],
            "languages": languages,
            "security_languages": list(SECURITY_LANGUAGES),
            "unsupported_security_languages": unsupported_languages,
            "config_hash": config_hash,
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
        java_files=len(java_index.files),
    )
