"""Minimal SARIF 2.1.0 export for CI security ingestion."""

from __future__ import annotations

import json

from . import __version__
from .model import Graph

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_sarif(graph: Graph) -> str:
    rules: list[dict[str, object]] = []
    rule_index: dict[str, int] = {}
    for finding in graph.sorted_findings():
        key = f"{finding.category}:{finding.cwe or ''}"
        if key not in rule_index:
            rule_index[key] = len(rules)
            rules.append(
                {
                    "id": key,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[1]}.html"
                    if finding.cwe and "-" in finding.cwe
                    else "",
                    "properties": {"category": finding.category, "cwe": finding.cwe},
                }
            )
    results = []
    for finding in graph.sorted_findings():
        key = f"{finding.category}:{finding.cwe or ''}"
        result = {
            "ruleId": key,
            "ruleIndex": rule_index[key],
            "level": LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "recommendation": finding.recommendation,
            },
        }
        if finding.evidence:
            loc = finding.evidence[0]
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc.path.replace("\\", "/")},
                        "region": {"startLine": max(1, loc.line)},
                    }
                }
            ]
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitdiagram",
                        "version": __version__,
                        "informationUri": "https://github.com/ahmedkhaleel2004/gitdiagram",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
