"""Deterministic, evidence-first security report model.

The report is deliberately separate from the architecture report: it is built
from the same graph, but prioritizes new findings, provenance, attack surface,
coverage, and explicit limitations. Nothing here executes analyzed code.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .model import SEVERITY_RANK, Finding, Graph, Node, stable_id

SEVERITIES = ("critical", "high", "medium", "low", "info")
RISK_WEIGHTS = {"critical": 20, "high": 8, "medium": 3, "low": 1, "info": 0}
RISK_FORMULA = (
    "min(100, 20*critical + 8*high + 3*medium + 1*low); new findings only; "
    "label floors at High for any critical and Moderate for any high"
)
CONFIG_CATEGORIES = {"container", "ci", "cloud", "supply-chain", "supply_chain", "iac"}
SECRET_CATEGORIES = {"secret"}
PRIORITY_LIMIT = 10


@dataclass(slots=True)
class Gate:
    threshold: str | None
    verdict: str
    reason: str


@dataclass(slots=True)
class Risk:
    index: int
    label: str
    weighted: float
    formula: str
    by_severity: dict[str, int]
    by_category: dict[str, int]
    new_count: int
    baselined_count: int
    highest: Finding | None


@dataclass(slots=True)
class SurfaceEndpoint:
    qualname: str
    path: str | None
    line: int | None
    routes: list[str]
    authenticated: bool
    methods: list[str]


@dataclass(slots=True)
class Surface:
    endpoints: list[SurfaceEndpoint]
    authenticated: int
    unauthenticated: int
    route_count: int
    external_dependencies: list[str]
    infrastructure: list[str]
    risky_infrastructure: list[str]


@dataclass(slots=True)
class RemediationGroup:
    timeframe: str
    title: str
    action: str
    finding_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SecurityReport:
    name: str
    commit: str | None
    branch: str | None
    dirty: bool
    tool_version: str
    report_id: str
    config_hash: str | None
    security_enabled: bool
    finding_confidence_floor: float
    gate: Gate
    risk: Risk
    priorities: list[Finding]
    new_findings: list[Finding]
    baselined_findings: list[Finding]
    all_findings: list[Finding]
    dependency_findings: list[Finding]
    configuration_findings: list[Finding]
    secret_findings: list[Finding]
    surface: Surface
    remediation: list[RemediationGroup]
    coverage: dict[str, Any]
    external_reports: list[dict[str, Any]]
    advisory_sources: list[dict[str, Any]]
    advisory_validated: int
    baseline: dict[str, Any]
    limitations: list[str]
    reproduce: str
    narrative: str | None = None


def _is_known_exploited(finding: Finding) -> bool:
    validation = finding.metadata.get("validation") or {}
    return bool(validation.get("known_exploited"))


def _is_validated(finding: Finding) -> bool:
    return bool(finding.metadata.get("validation"))


def _sort_key(finding: Finding) -> tuple[Any, ...]:
    location = finding.evidence[0] if finding.evidence else None
    return (
        -SEVERITY_RANK.get(finding.severity, 0),
        0 if _is_known_exploited(finding) else 1,
        0 if finding.trace else 1,
        -round(float(finding.confidence), 4),
        location.path if location else "",
        location.line if location else 0,
        finding.title,
        finding.id,
    )


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=_sort_key)


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def _risk(findings: list[Finding], baselined: int) -> Risk:
    new = [finding for finding in findings if not finding.baseline]
    weighted = sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in new)
    index = min(100, int(round(weighted)))
    if index == 0:
        label = "None"
    elif index < 20:
        label = "Low"
    elif index < 50:
        label = "Moderate"
    elif index < 80:
        label = "High"
    else:
        label = "Critical"
    categories = Counter(finding.category for finding in new)
    highest = _sorted(new)[0] if new else None
    order = {"None": 0, "Low": 1, "Moderate": 2, "High": 3, "Critical": 4}
    if highest is not None:
        floor = "High" if highest.severity == "critical" else "Moderate" if highest.severity == "high" else None
        if floor is not None and order[label] < order[floor]:
            label = floor
    return Risk(
        index=index,
        label=label,
        weighted=float(weighted),
        formula=RISK_FORMULA,
        by_severity=_counts(new),
        by_category={key: value for key, value in sorted(categories.items())},
        new_count=len(new),
        baselined_count=baselined,
        highest=highest,
    )


def _gate(findings: list[Finding], threshold: str | None, enabled: bool) -> Gate:
    if not enabled:
        return Gate(threshold, "N/A", "Security analysis was disabled for this run.")
    if not threshold or threshold == "none":
        return Gate(
            None,
            "INFORMATIONAL",
            "No CI severity gate was configured; review the new findings below.",
        )
    rank = SEVERITY_RANK.get(threshold, 0)
    hits = [
        finding
        for finding in findings
        if not finding.baseline and SEVERITY_RANK.get(finding.severity, 0) >= rank
    ]
    if hits:
        return Gate(
            threshold,
            "FAIL",
            f"{len(hits)} new finding(s) meet or exceed the '{threshold}' gate.",
        )
    return Gate(
        threshold,
        "PASS",
        f"No new findings meet or exceed the '{threshold}' gate.",
    )


def _route_text(routes: Any) -> list[str]:
    result: list[str] = []
    if not isinstance(routes, list):
        return result
    for route in routes:
        if not isinstance(route, dict):
            continue
        method = str(route.get("method") or "").strip()
        path = str(route.get("path") or "").strip()
        text = f"{method} {path}".strip()
        if text:
            result.append(text)
    return result


def _surface(graph: Graph) -> Surface:
    nodes = graph.sorted_nodes()
    endpoints: list[SurfaceEndpoint] = []
    route_count = 0
    for node in nodes:
        if node.kind != "endpoint":
            continue
        routes = _route_text(node.attrs.get("routes"))
        methods: list[str] = []
        for route in node.attrs.get("routes") or []:
            if isinstance(route, dict):
                methods.extend(
                    part.strip()
                    for part in str(route.get("method") or "").split(",")
                    if part.strip()
                )
        tags = {str(tag) for tag in node.attrs.get("tags") or []}
        authenticated = bool(node.attrs.get("auth")) or "auth" in tags or "auth_dependency" in tags
        route_count += len(routes)
        endpoints.append(
            SurfaceEndpoint(
                qualname=node.qualname,
                path=node.path,
                line=node.line,
                routes=routes,
                authenticated=authenticated,
                methods=sorted(set(methods)),
            )
        )
    endpoints.sort(key=lambda item: (item.path or "", item.line or 0, item.qualname))
    external = sorted(
        {node.name for node in nodes if node.kind == "external" and node.name}
    )
    infrastructure = sorted(
        node.name for node in nodes if node.kind in {"infra", "workflow", "service"}
    )
    risky: list[str] = []
    for node in nodes:
        if node.kind not in {"infra", "workflow", "service"}:
            continue
        attrs = node.attrs
        reasons: list[str] = []
        if attrs.get("privileged") is True:
            reasons.append("privileged")
        if attrs.get("docker_socket"):
            reasons.append("docker socket")
        if attrs.get("host_network") or attrs.get("network_mode") == "host":
            reasons.append("host network")
        if attrs.get("dangerous_capability"):
            reasons.append("dangerous capability")
        if attrs.get("unconfined_profile"):
            reasons.append("unconfined profile")
        if str(attrs.get("user") or "").lower() == "root":
            reasons.append("root user")
        if reasons:
            risky.append(f"{node.name} ({', '.join(reasons)})")
    authenticated_count = sum(1 for item in endpoints if item.authenticated)
    return Surface(
        endpoints=endpoints,
        authenticated=authenticated_count,
        unauthenticated=len(endpoints) - authenticated_count,
        route_count=route_count,
        external_dependencies=external,
        infrastructure=infrastructure,
        risky_infrastructure=sorted(set(risky)),
    )


def _is_dependency(finding: Finding) -> bool:
    if finding.source == "xray":
        return True
    return bool(finding.metadata.get("cves") or finding.metadata.get("package"))


def _is_configuration(finding: Finding) -> bool:
    return finding.category in CONFIG_CATEGORIES or finding.category == "misconfig"


def _is_secret(finding: Finding) -> bool:
    return finding.category in SECRET_CATEGORIES


def _remediation(
    new: list[Finding], dependency: list[Finding]
) -> list[RemediationGroup]:
    immediate = [
        finding for finding in new if finding.severity in {"critical", "high"}
    ][:8]
    medium = [finding for finding in new if finding.severity == "medium"][:8]
    categories = Counter(finding.category for finding in new)
    recurring = {
        category
        for category, count in categories.items()
        if count >= 2 and category not in {"secret"}
    }
    systemic = [
        finding
        for finding in new
        if finding.category in recurring or _is_secret(finding) or _is_dependency(finding)
    ][:10]
    groups: list[RemediationGroup] = []
    if immediate:
        groups.append(
            RemediationGroup(
                timeframe="Immediate (0-7 days)",
                title="Contain critical and high findings",
                action=(
                    "Validate the highest-severity findings, apply the cited remediation, "
                    "and add a regression test or configuration check before release."
                ),
                finding_ids=[finding.id for finding in immediate],
            )
        )
    if medium:
        groups.append(
            RemediationGroup(
                timeframe="Short term (7-30 days)",
                title="Resolve medium findings with clear fixes",
                action=(
                    "Fix the medium-severity review items or document a time-bounded "
                    "accepted risk with an owner."
                ),
                finding_ids=[finding.id for finding in medium],
            )
        )
    if dependency:
        groups.append(
            RemediationGroup(
                timeframe="Supply chain",
                title="Upgrade or replace vulnerable dependencies",
                action=(
                    "Prefer a fixed version from the scanner report; if none exists, "
                    "pin, isolate, or replace the affected component and monitor advisories."
                ),
                finding_ids=[finding.id for finding in dependency[:10]],
            )
        )
    if systemic:
        groups.append(
            RemediationGroup(
                timeframe="Systemic",
                title="Remove recurring security patterns",
                action=(
                    "Address repeat categories at the framework or configuration layer "
                    "rather than fixing individual findings one by one."
                ),
                finding_ids=[finding.id for finding in systemic],
            )
        )
    if not groups:
        groups.append(
            RemediationGroup(
                timeframe="No action",
                title="No new findings require remediation",
                action=(
                    "Keep the current gate and baseline process in place; revisit after "
                    "the next dependency or infrastructure change."
                ),
            )
        )
    return groups


def _coverage(meta: dict[str, Any], enabled: bool) -> dict[str, Any]:
    analysis = meta.get("analysis") or {}
    languages = meta.get("languages") or {}
    if isinstance(languages, dict):
        language_rows = [
            {"name": str(name), "files": int(count)}
            for name, count in sorted(languages.items())
        ]
    else:
        language_rows = [{"name": str(name), "files": 0} for name in sorted(languages)]
    language_rows.sort(key=lambda item: (item["name"], item["files"]))
    unsupported = sorted(
        str(name) for name in (meta.get("unsupported_security_languages") or [])
    )
    parse_errors = sorted(str(path) for path in (analysis.get("parse_errors") or []))
    return {
        "security_enabled": enabled,
        "files_discovered": int(meta.get("files_discovered") or 0),
        "files_skipped": int(meta.get("files_skipped") or 0),
        "python_files": int(meta.get("python_files") or 0),
        "java_files": int(meta.get("java_files") or 0),
        "iac_files": int(meta.get("iac_files") or 0),
        "languages": language_rows,
        "unsupported_security_languages": unsupported,
        "parse_errors": parse_errors,
        "unresolved_count": int(analysis.get("unresolved_count") or 0),
        "truncated": bool(analysis.get("truncated")),
        "dropped_nodes": int(analysis.get("dropped_nodes") or 0),
        "finding_confidence_floor": float(meta.get("finding_confidence_floor") or 0.0),
    }


def _limitations(coverage: dict[str, Any]) -> list[str]:
    unsupported = coverage["unsupported_security_languages"]
    limitations = [
        "This report is based on static analysis. Analyzed code is never executed, "
        "so runtime behavior, feature flags, and deployed configuration are not proven.",
        "secdiagram findings are evidence-backed heuristics with confidence scores; "
        "they are review prompts, not proof of exploitability or a substitute for manual testing.",
        "Security rules cover Python and Java sources. Unsupported languages are listed in the "
        "coverage section and were not assessed.",
        "Dynamic imports, reflection, metaprogramming, monkey patching, and runtime registries "
        "cannot be fully resolved and are counted rather than guessed.",
        "Imported SonarQube and JFrog Xray reports are accepted as supplied. Advisory validation "
        "corroborates CVE metadata but does not re-scan the affected component.",
        "Findings suppressed by the security baseline are excluded from the risk index but remain "
        "visible in the evidence appendix.",
    ]
    if unsupported:
        limitations.append(
            "No security checks ran for: " + ", ".join(unsupported) + "."
        )
    if coverage["parse_errors"]:
        limitations.append(
            f"{len(coverage['parse_errors'])} source file(s) could not be parsed and were skipped."
        )
    if coverage["truncated"]:
        limitations.append(
            f"The graph was capped and {coverage['dropped_nodes']} node(s) were dropped; "
            "coverage is partial."
        )
    if not coverage["security_enabled"]:
        limitations.append("Security analysis was disabled for this run; no findings were produced.")
    return limitations


def build_security_report(
    graph: Graph,
    meta: dict[str, Any] | None = None,
    *,
    fail_on: str | None = None,
    reproduce: str | None = None,
    narrative: str | None = None,
) -> SecurityReport:
    """Build a deterministic security report from an analyzed graph."""
    merged_meta = dict(graph.meta)
    merged_meta.update(meta or {})
    meta = merged_meta
    enabled = bool(meta.get("security_enabled", True))
    findings = _sorted(list(graph.findings))
    new_findings = [finding for finding in findings if not finding.baseline]
    baselined = [finding for finding in findings if finding.baseline]
    risk = _risk(findings, len(baselined))
    dependency = [finding for finding in new_findings if _is_dependency(finding)]
    configuration = [
        finding
        for finding in new_findings
        if _is_configuration(finding) and not _is_secret(finding)
    ]
    secrets = [finding for finding in new_findings if _is_secret(finding)]
    surface = _surface(graph)
    coverage = _coverage(meta, enabled)
    external_reports = sorted(
        (dict(item) for item in (meta.get("external_reports") or []) if isinstance(item, dict)),
        key=lambda item: (str(item.get("source") or ""), str(item.get("file") or "")),
    )
    advisory_sources = sorted(
        (dict(item) for item in (meta.get("advisory_sources") or []) if isinstance(item, dict)),
        key=lambda item: (str(item.get("file") or ""), str(item.get("source") or "")),
    )
    report_id = stable_id(
        "security-report",
        __version__,
        str(meta.get("name") or "repository"),
        str(meta.get("commit") or ""),
        str(meta.get("config_hash") or ""),
        str(fail_on or "none"),
        *[
            json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=True, default=str)
            for finding in findings
        ],
        *[
            f"{item.get('source')}:{item.get('file')}:{item.get('findings')}"
            for item in external_reports
        ],
        *[
            f"{item.get('source')}:{item.get('file')}:{item.get('entries')}"
            for item in advisory_sources
        ],
    )
    baseline = dict(meta.get("security_baseline") or {})
    return SecurityReport(
        name=str(meta.get("name") or "repository"),
        commit=str(meta["commit"]) if meta.get("commit") else None,
        branch=str(meta["branch"]) if meta.get("branch") else None,
        dirty=bool(meta.get("dirty")),
        tool_version=__version__,
        report_id=report_id,
        config_hash=str(meta["config_hash"]) if meta.get("config_hash") else None,
        security_enabled=enabled,
        finding_confidence_floor=float(meta.get("finding_confidence_floor") or 0.0),
        gate=_gate(findings, fail_on, enabled),
        risk=risk,
        priorities=new_findings[:PRIORITY_LIMIT],
        new_findings=new_findings,
        baselined_findings=baselined,
        all_findings=findings,
        dependency_findings=dependency,
        configuration_findings=configuration,
        secret_findings=secrets,
        surface=surface,
        remediation=_remediation(new_findings, dependency),
        coverage=coverage,
        external_reports=external_reports,
        advisory_sources=advisory_sources,
        advisory_validated=int(meta.get("advisory_validated_findings") or 0),
        baseline=baseline,
        limitations=_limitations(coverage),
        reproduce=reproduce
        or "secdiagram --dir . --security-report both --format sarif",
        narrative=narrative,
    )


def is_known_exploited(finding: Finding) -> bool:
    return _is_known_exploited(finding)


def is_validated(finding: Finding) -> bool:
    return _is_validated(finding)


def node_ref(node: Node) -> str:
    if node.path and node.line:
        return f"{node.path}:{node.line}"
    return node.qualname
