"""Security baseline: suppress known findings so CI fails only on regressions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Finding, Graph

BASELINE_SCHEMA_VERSION = "1"


def finding_fingerprint(finding: Finding) -> str:
    """Return the stable, deterministic fingerprint of a finding.

    Fingerprints are the finding id, itself derived from rule category,
    source path, line number, and title. A finding wiped or shifted in
    the source therefore regenerates and is reported as new, which is
    the expected baseline drift behaviour.
    """
    return finding.id


def load_baseline(path: Path) -> set[str]:
    """Load baseline fingerprints from ``path``; raise on malformed content."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")
    if payload.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema_version: {payload.get('schema_version')!r}")
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("baseline 'findings' must be a list")
    entries = set()
    for item in findings:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("baseline findings entries must have a non-empty 'id'")
        entries.add(item["id"])
    return entries


def write_baseline(graph: Graph, path: Path) -> int:
    """Write a deterministic baseline file with the current findings; return its count."""
    records: list[dict[str, Any]] = []
    for finding in graph.sorted_findings():
        first = finding.evidence[0] if finding.evidence else None
        records.append(
            {
                "id": finding.id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "path": first.path if first else "",
                "line": first.line if first else 0,
            }
        )
    records.sort(key=lambda record: record["id"])
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "tool": "secdiagram",
        "usage": (
            "pass --baseline with this file so CI fails only on findings that are not listed here; "
            "regenerate with --create-baseline after triaging new findings"
        ),
        "findings": records,
    }
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return len(records)


def apply_baseline(graph: Graph, entries: set[str], file_label: str) -> tuple[int, int]:
    """Mark findings listed in the baseline and annotate graph meta.

    Returns ``(known, new)`` where ``known`` is how many findings were
    suppressed and ``new`` how many are not covered by the baseline.
    """
    known = 0
    for finding in graph.findings:
        if finding.id in entries:
            finding.baseline = True
            known += 1
    total = len(graph.findings)
    graph.meta["security_baseline"] = {
        "file": file_label,
        "known": known,
        "new": total - known,
        "total": total,
    }
    return known, total - known


def ignore_baseline(graph: Graph, file_label: str) -> None:
    """Record a baseline-mode run where no findings could be suppressed."""
    graph.meta["security_baseline"] = {
        "file": file_label,
        "known": 0,
        "new": len(graph.findings),
        "total": len(graph.findings),
    }
