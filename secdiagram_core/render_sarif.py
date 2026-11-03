"""SARIF 2.1.0 export with fingerprints, suppressions, and taint code flows."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .model import SEVERITY_RANK, Finding, Graph, Loc

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}
INFORMATION_URI = "https://github.com/vichhaiyserey/secdiagram"

CATEGORY_DESCRIPTIONS = {
    "command": "Request-derived input reaches a process execution sink, which can allow arbitrary command execution.",
    "code": "Request-derived input or dynamic strings reach eval/exec/compile, allowing arbitrary code execution.",
    "deserialization": "Untrusted data is passed to an unsafe deserializer, which can lead to remote code execution.",
    "sql": "Request-derived input reaches a SQL execution sink without parameterization.",
    "path": "Request-derived input is used to construct a filesystem path, allowing traversal outside an intended directory.",
    "network": "Request-derived input controls an outbound destination, enabling server-side request forgery.",
    "crypto": "A weak or insecure cryptographic primitive is used in a security-sensitive context.",
    "template": "Request-derived input is rendered as template source, enabling server-side template injection.",
    "secret": "A credential-shaped value is committed to source or configuration and may be exposed to anyone with repository access.",
    "container": "Container configuration weakens isolation and increases the impact of a compromise.",
    "supply-chain": "A dependency or build artifact is not pinned, allowing unexpected upstream changes.",
    "ci": "A CI workflow grants excessive permissions or executes untrusted actions.",
    "cloud": "Cloud infrastructure configuration exposes resources beyond the intended trust boundary.",
}


def _precision(confidence: float) -> str:
    if confidence >= 0.9:
        return "very-high"
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.65:
        return "medium"
    return "low"


def _cwe_uri(cwe: str | None) -> str:
    if cwe and "-" in cwe:
        return f"https://cwe.mitre.org/data/definitions/{cwe.split('-', 1)[1]}.html"
    return INFORMATION_URI


def _physical(loc: Loc) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": loc.path.replace("\\", "/")},
            "region": {"startLine": max(1, loc.line), "startColumn": max(1, loc.col)},
        }
    }


def _dedupe_locations(locs: list[Loc]) -> list[Loc]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Loc] = []
    for loc in locs:
        key = (loc.path, loc.line, loc.col)
        if key in seen:
            continue
        seen.add(key)
        out.append(loc)
    return out


def _thread_flow(trace: list[Loc]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    last = len(trace) - 1
    for position, loc in enumerate(trace):
        if position == 0:
            label = "taint source"
        elif position == last:
            label = "sink"
        else:
            label = "taint propagation"
        steps.append(
            {
                "location": {
                    "message": {"text": label},
                    "physicalLocation": _physical(loc)["physicalLocation"],
                },
                "nestingLevel": 0,
            }
        )
    return steps


def _rule_properties(finding: Finding, severity: str, confidence: float) -> dict[str, Any]:
    tags = ["security"]
    if finding.cwe and "-" in finding.cwe:
        tags.append(f"external/cwe/cwe-{finding.cwe.split('-', 1)[1]}")
    return {
        "tags": tags,
        "precision": _precision(confidence),
        "problem.severity": severity,
        "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
        "category": finding.category,
        "cwe": finding.cwe,
    }


def render_sarif(graph: Graph, skip_baseline: bool = False) -> str:
    findings = graph.sorted_findings()
    if skip_baseline:
        findings = [finding for finding in findings if not finding.baseline]

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    rule_state: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = f"{finding.category}:{finding.cwe or ''}"
        state = rule_state.get(key)
        if state is None:
            state = {
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "recommendation": finding.recommendation,
            }
            rule_state[key] = state
        else:
            if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(state["severity"], 0):
                state["severity"] = finding.severity
            state["confidence"] = max(state["confidence"], finding.confidence)
        if key not in rule_index:
            rule_index[key] = len(rules)
            description = CATEGORY_DESCRIPTIONS.get(finding.category, finding.title)
            rules.append(
                {
                    "id": key,
                    "name": f"secdiagram/{finding.category}",
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": description},
                    "help": {
                        "text": finding.recommendation,
                        "markdown": (
                            f"**{finding.title}**\n\n{description}\n\n"
                            f"**Remediation:** {finding.recommendation}"
                        ),
                    },
                    "helpUri": _cwe_uri(finding.cwe),
                    "defaultConfiguration": {"level": LEVEL.get(finding.severity, "warning")},
                    "properties": _rule_properties(finding, finding.severity, finding.confidence),
                }
            )

    for key, state in rule_state.items():
        rule = rules[rule_index[key]]
        rule["properties"] = _rule_properties(
            next(f for f in findings if f"{f.category}:{f.cwe or ''}" == key),
            state["severity"],
            state["confidence"],
        )
        rule["defaultConfiguration"] = {"level": LEVEL.get(state["severity"], "warning")}

    baseline = graph.meta.get("security_baseline") or {}
    baseline_file = baseline.get("file", "security.baseline.json")
    results: list[dict[str, Any]] = []
    for finding in findings:
        key = f"{finding.category}:{finding.cwe or ''}"
        result: dict[str, Any] = {
            "ruleId": key,
            "ruleIndex": rule_index[key],
            "level": LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "partialFingerprints": {"secdiagramFindingId/v1": finding.id},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "precision": _precision(finding.confidence),
                "recommendation": finding.recommendation,
            },
        }
        locations = _dedupe_locations(finding.evidence)
        if not locations and finding.trace:
            locations = [finding.trace[-1]]
        if locations:
            result["locations"] = [_physical(loc) for loc in locations]
        trace = _dedupe_locations(finding.trace)
        if trace:
            result["relatedLocations"] = [
                {
                    "id": index + 1,
                    "message": {
                        "text": "taint source"
                        if index == 0
                        else ("sink" if index == len(trace) - 1 else "taint propagation")
                    },
                    "physicalLocation": _physical(loc)["physicalLocation"],
                }
                for index, loc in enumerate(trace)
            ]
            result["codeFlows"] = [
                {
                    "message": {"text": "Request-derived input reaches the reported sink."},
                    "threadFlows": [{"locations": _thread_flow(trace)}],
                }
            ]
        if finding.baseline:
            result["baselineState"] = "unchanged"
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": f"Known finding suppressed by baseline {baseline_file}.",
                }
            ]
        elif baseline:
            result["baselineState"] = "new"
        results.append(result)

    analysis = graph.meta.get("analysis") or {}
    unsupported = list(graph.meta.get("unsupported_security_languages") or [])
    notifications: list[dict[str, Any]] = []
    for path in analysis.get("parse_errors", []):
        notifications.append(
            {"level": "warning", "message": {"text": f"Parse error; file skipped: {path}"}}
        )
    for path in graph.meta.get("skipped_samples", []):
        notifications.append(
            {"level": "note", "message": {"text": f"Discovery skip: {path}"}}
        )
    if unsupported:
        notifications.append(
            {
                "level": "note",
                "message": {
                    "text": "Security analysis is not implemented for: " + ", ".join(unsupported)
                },
            }
        )
    coverage: dict[str, Any] = {
        "toolVersion": __version__,
        "commit": graph.meta.get("commit"),
        "branch": graph.meta.get("branch"),
        "dirty": graph.meta.get("dirty"),
        "configHash": graph.meta.get("config_hash"),
        "filesDiscovered": graph.meta.get("files_discovered"),
        "filesAnalyzed": {
            "python": graph.meta.get("python_files"),
            "java": graph.meta.get("java_files"),
            "iac": graph.meta.get("iac_files"),
        },
        "filesSkipped": graph.meta.get("files_skipped"),
        "languages": graph.meta.get("languages", {}),
        "securityLanguages": graph.meta.get("security_languages", []),
        "unsupportedSecurityLanguages": unsupported,
        "unresolvedCount": analysis.get("unresolved_count", 0),
        "truncated": bool(analysis.get("truncated", False)),
        "droppedNodes": analysis.get("dropped_nodes", 0),
    }
    invocation: dict[str, Any] = {"executionSuccessful": True, "properties": coverage}
    if notifications:
        invocation["notifications"] = notifications

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secdiagram",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "coverage": coverage,
                    "baseline": baseline or None,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
