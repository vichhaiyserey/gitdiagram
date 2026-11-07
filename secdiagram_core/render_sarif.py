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

SEVERITY_RANK_VALUE = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 0,
}

CATEGORY_OWASP = {
    "command": ("A05:2025", "A03:2021"),
    "code": ("A05:2025", "A03:2021"),
    "deserialization": ("A08:2025", "A08:2021"),
    "sql": ("A05:2025", "A03:2021"),
    "path": ("A01:2025", "A01:2021"),
    "network": ("A01:2025", "A10:2021"),
    "crypto": ("A04:2025", "A02:2021"),
    "template": ("A05:2025", "A03:2021"),
    "xss": ("A05:2025", "A03:2021"),
    "xxe": ("A05:2025", "A05:2021"),
    "redirect": ("A01:2025", "A01:2021"),
    "auth": ("A07:2025", "A07:2021"),
    "misconfig": ("A02:2025", "A05:2021"),
    "secret": ("A02:2025", "A07:2021"),
    "container": ("A02:2025", "A05:2021"),
    "cloud": ("A02:2025", "A05:2021"),
    "ci": ("A03:2025", "A08:2021"),
    "supply_chain": ("A03:2025", "A06:2021"),
    "supply-chain": ("A03:2025", "A06:2021"),
}

CATEGORY_DESCRIPTIONS = {
    "command": "Request-derived input reaches a process execution sink, which can allow arbitrary command execution.",
    "code": "Request-derived input or dynamic strings reach eval/exec/compile, allowing arbitrary code execution.",
    "deserialization": "Untrusted data is passed to an unsafe deserializer, which can lead to remote code execution.",
    "sql": "Request-derived input reaches a SQL execution sink without parameterization.",
    "path": "Request-derived input is used to construct a filesystem path, allowing traversal outside an intended directory.",
    "network": "Request-derived input controls an outbound destination, enabling server-side request forgery.",
    "crypto": "A weak or insecure cryptographic primitive is used in a security-sensitive context.",
    "template": "Request-derived input is rendered as template source, enabling server-side template injection.",
    "xss": "Request-derived input reaches an HTML output sink without escaping, enabling cross-site scripting.",
    "xxe": "An XML parser processes untrusted documents with external entities enabled, enabling file disclosure or SSRF.",
    "redirect": "Request-derived input controls a redirect target, enabling open redirects and credential theft.",
    "auth": "Authentication or authorization controls are disabled or weakened.",
    "misconfig": "A framework or runtime setting weakens the security posture of the application.",
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


def _rule_key(finding: Finding) -> str:
    prefix = "" if finding.source == "secdiagram" else f"{finding.source}:"
    return f"{prefix}{finding.category}:{finding.cwe or ''}"


def _rule_properties(finding: Finding, severity: str, confidence: float) -> dict[str, Any]:
    tags = ["security"]
    if finding.cwe and "-" in finding.cwe:
        tags.append(f"external/cwe/cwe-{finding.cwe.split('-', 1)[1]}")
    for owasp in CATEGORY_OWASP.get(finding.category, ()):
        tags.append(f"external/owasp/owasp-{owasp.lower()}")
    properties: dict[str, Any] = {
        "tags": tags,
        "precision": _precision(confidence),
        "problem.severity": severity,
        "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
        "rank": SEVERITY_RANK_VALUE.get(severity, 50),
        "category": finding.category,
        "cwe": finding.cwe,
        "source": finding.source,
    }
    if finding.metadata.get("validation"):
        properties["validation"] = finding.metadata["validation"]
    return properties


def render_sarif(graph: Graph, skip_baseline: bool = False) -> str:
    findings = graph.sorted_findings()
    if skip_baseline:
        findings = [finding for finding in findings if not finding.baseline]

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    rule_state: dict[str, dict[str, Any]] = {}
    for finding in findings:
        key = _rule_key(finding)
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
                    "name": f"secdiagram/{finding.source}/{finding.category}",
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
            next(f for f in findings if _rule_key(f) == key),
            state["severity"],
            state["confidence"],
        )
        rule["defaultConfiguration"] = {"level": LEVEL.get(state["severity"], "warning")}

    baseline = graph.meta.get("security_baseline") or {}
    baseline_file = baseline.get("file", "security.baseline.json")
    results: list[dict[str, Any]] = []
    for finding in findings:
        key = _rule_key(finding)
        result: dict[str, Any] = {
            "ruleId": key,
            "ruleIndex": rule_index[key],
            "level": LEVEL.get(finding.severity, "warning"),
            "rank": SEVERITY_RANK_VALUE.get(finding.severity, 50),
            "message": {"text": finding.message},
            "partialFingerprints": {"secdiagramFindingId/v1": finding.id},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "precision": _precision(finding.confidence),
                "recommendation": finding.recommendation,
                "source": finding.source,
            },
        }
        if finding.external_id:
            result["properties"]["external_id"] = finding.external_id
        if finding.metadata.get("validation"):
            result["properties"]["validation"] = finding.metadata["validation"]
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
