"""Print-first security report renderers (Markdown and static HTML)."""

from __future__ import annotations

import html
from typing import Any

from .model import Finding
from .render_sarif import CATEGORY_DESCRIPTIONS, CATEGORY_OWASP
from .security_report import (
    SecurityReport,
    is_known_exploited,
    is_validated,
)

_SOURCE_LABEL = {
    "secdiagram": "secdiagram SAST",
    "sonarqube": "SonarQube",
    "xray": "JFrog Xray",
}

_EXTERNAL_WHY = (
    "An external scanner reports this component or issue as security-relevant. "
    "Treat the scanner evidence as the source of truth and verify the affected version."
)


def _md(text: Any) -> str:
    return " ".join(str(text or "").split()).replace("|", "\\|")


def _h(text: Any) -> str:
    return html.escape(str(text or ""), quote=True)


def _source(finding: Finding) -> str:
    return _SOURCE_LABEL.get(finding.source, finding.source)


def _confidence(finding: Finding) -> str:
    score = float(finding.confidence)
    if score >= 0.9:
        label = "very high"
    elif score >= 0.8:
        label = "high"
    elif score >= 0.65:
        label = "moderate"
    else:
        label = "low"
    return f"{score:.2f} ({label})"


def _badges(finding: Finding) -> list[str]:
    if is_known_exploited(finding):
        return ["Known exploited", "Advisory validated"]
    if is_validated(finding):
        return ["Advisory validated"]
    if finding.trace:
        return ["Taint-confirmed"]
    if finding.source != "secdiagram":
        return ["Scanner-reported"]
    return ["Heuristic"]


def _why(finding: Finding) -> str:
    if finding.source != "secdiagram" and finding.category == "external":
        return _EXTERNAL_WHY
    return CATEGORY_DESCRIPTIONS.get(
        finding.category,
        "Review this finding at the cited location and apply the recommended remediation.",
    )


def _owasp(finding: Finding) -> str:
    tags = CATEGORY_OWASP.get(finding.category, ())
    return ", ".join(tags) if tags else "-"


def _ref(finding: Finding) -> str:
    if not finding.evidence:
        return "-"
    return finding.evidence[0].ref


def _provenance(finding: Finding) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if finding.external_id:
        items.append(("External ID", finding.external_id))
    metadata = finding.metadata or {}
    for key, label in (
        ("package", "Package"),
        ("version", "Version"),
        ("ecosystem", "Ecosystem"),
        ("rule", "Rule"),
        ("policy", "Policy / watch"),
        ("cvss", "CVSS"),
        ("fixed_versions", "Fixed versions"),
        ("cves", "CVEs"),
        ("provider", "Provider"),
    ):
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value)
        else:
            text = str(value)
        items.append((label, text))
    validation = metadata.get("validation") or {}
    if validation:
        sources = ", ".join(str(source) for source in validation.get("sources") or [])
        exploited = "yes" if validation.get("known_exploited") else "no"
        items.append(("Validation", f"{sources or 'local advisory'}; known exploited: {exploited}"))
    advisories = metadata.get("advisories") or []
    if isinstance(advisories, list):
        for advisory in advisories[:3]:
            if not isinstance(advisory, dict):
                continue
            label = str(advisory.get("source") or "advisory")
            name = str(advisory.get("name") or "")
            cve = str(advisory.get("cve") or "")
            items.append(("Advisory", f"{label} {cve} {name}".strip()))
    return items


def _counts_line(report: SecurityReport) -> str:
    counts = report.risk.by_severity
    parts = [f"{counts[severity]} {severity}" for severity in ("critical", "high", "medium", "low", "info") if counts[severity]]
    return ", ".join(parts) if parts else "none"


def _summary_sentence(report: SecurityReport) -> str:
    if not report.security_enabled:
        return (
            "Security analysis was disabled for this run. This report records the scan scope "
            "and must not be interpreted as a clean security assessment."
        )
    if not report.new_findings:
        return (
            "No new findings were identified in the analyzed scope. This is a coverage statement, "
            "not proof that the application is free of vulnerabilities."
        )
    highest = report.risk.highest
    highest_text = ""
    if highest is not None:
        highest_text = (
            f" The highest-severity finding is **{highest.severity.upper()}** "
            f"({_md(highest.title)} at `{_ref(highest)}`)."
        )
    return (
        f"This review identified **{len(report.new_findings)} new finding(s)**: "
        f"{_counts_line(report)}.{highest_text} "
        f"{report.risk.baselined_count} additional finding(s) are suppressed by the committed baseline."
    )


def _external_summary(report: SecurityReport) -> str:
    bits: list[str] = []
    if report.external_reports:
        for item in report.external_reports:
            bits.append(
                f"{item.get('source', 'external')} ({item.get('findings', 0)} finding(s))"
            )
    if report.advisory_sources:
        bits.append(f"{len(report.advisory_sources)} advisory source file(s)")
    if report.advisory_validated:
        bits.append(f"{report.advisory_validated} validated finding(s)")
    return ", ".join(bits) if bits else "No external scanner reports or advisory databases imported."


def render_security_markdown(report: SecurityReport) -> str:
    """Render a deterministic Markdown security review."""
    lines: list[str] = []
    lines.append(f"# Security Review: {_md(report.name)}")
    lines.append("")
    lines.append(
        f"> Generated by **secdiagram {report.tool_version}** | report `{report.report_id}`"
        + (f" | commit `{report.commit}`" if report.commit else "")
        + (f" | branch `{report.branch}`" if report.branch else "")
        + (" | working tree dirty" if report.dirty else "")
    )
    lines.append("")
    lines.append(f"**Verdict: {report.gate.verdict}** - {_md(report.gate.reason)}")
    lines.append("")
    lines.append("| Risk index | New findings | Critical / High | Baseline-suppressed |")
    lines.append("|---|---:|---:|---:|")
    critical_high = report.risk.by_severity["critical"] + report.risk.by_severity["high"]
    lines.append(
        f"| {report.risk.index}/100 ({report.risk.label}) | {report.risk.new_count} | "
        f"{critical_high} | {report.risk.baselined_count} |"
    )
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    lines.append(_summary_sentence(report))
    lines.append("")
    lines.append(f"Risk index formula: `{report.risk.formula}`.")
    lines.append("")
    lines.append(f"Detection sources: {_external_summary(report)}")
    lines.append("")
    lines.append("| Severity | New findings |")
    lines.append("|---|---:|")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.title()} | {report.risk.by_severity[severity]} |")
    lines.append("")
    if report.risk.by_category:
        lines.append("| Category | New findings |")
        lines.append("|---|---:|")
        for category, count in sorted(report.risk.by_category.items()):
            lines.append(f"| {_md(category)} | {count} |")
        lines.append("")
    if report.gate.threshold:
        lines.append(
            f"CI gate: new findings at or above **{report.gate.threshold}** must be resolved "
            "or explicitly baselined before release."
        )
        lines.append("")
    if report.priorities:
        lines.append("### Top priorities")
        lines.append("")
        for index, finding in enumerate(report.priorities, 1):
            badges = ", ".join(_badges(finding))
            lines.append(
                f"{index}. **{finding.severity.upper()}** - {_md(finding.title)} "
                f"(`{finding.id}`) at `{_ref(finding)}`; confidence {_confidence(finding)}; {badges}."
            )
        lines.append("")
    lines.append("## Attack surface")
    lines.append("")
    surface = report.surface
    lines.append(
        f"- **{len(surface.endpoints)}** endpoint(s), **{surface.route_count}** route(s); "
        f"**{surface.unauthenticated}** without an authentication marker and "
        f"**{surface.authenticated}** with one."
    )
    lines.append(
        f"- **{len(surface.external_dependencies)}** external dependency name(s) and "
        f"**{len(surface.infrastructure)}** infrastructure artifact(s) observed."
    )
    if surface.risky_infrastructure:
        lines.append(
            "- Risky infrastructure markers: " + ", ".join(_md(item) for item in surface.risky_infrastructure) + "."
        )
    lines.append("")
    lines.append(
        "> \"Without an authentication marker\" means no supported decorator or annotation was "
        "detected. It is not proof that the endpoint is publicly reachable."
    )
    lines.append("")
    if surface.endpoints:
        lines.append("| Endpoint | Routes | Auth marker | Source |")
        lines.append("|---|---|---|---|")
        for endpoint in surface.endpoints[:40]:
            route_text = ", ".join(_md(route) for route in endpoint.routes) or "-"
            auth = "yes" if endpoint.authenticated else "not detected"
            ref = f"`{endpoint.path}:{endpoint.line}`" if endpoint.path and endpoint.line else "-"
            lines.append(f"| `{_md(endpoint.qualname)}` | {route_text} | {auth} | {ref} |")
        if len(surface.endpoints) > 40:
            lines.append(f"| ... | {len(surface.endpoints) - 40} more endpoint(s) | | |")
        lines.append("")
    if surface.external_dependencies:
        shown = ", ".join(f"`{_md(name)}`" for name in surface.external_dependencies[:24])
        suffix = (
            f" (+{len(surface.external_dependencies) - 24} more)"
            if len(surface.external_dependencies) > 24
            else ""
        )
        lines.append("External dependencies: " + shown + suffix)
        lines.append("")
    if surface.infrastructure:
        shown = ", ".join(f"`{_md(name)}`" for name in surface.infrastructure[:24])
        suffix = (
            f" (+{len(surface.infrastructure) - 24} more)"
            if len(surface.infrastructure) > 24
            else ""
        )
        lines.append("Infrastructure artifacts: " + shown + suffix)
        lines.append("")

    lines.append("## Priority findings")
    lines.append("")
    if not report.priorities:
        lines.append("No new findings require prioritization.")
        lines.append("")
    for finding in report.priorities:
        lines.append(f"### {finding.severity.upper()} - {_md(finding.title)}")
        lines.append("")
        lines.append(
            f"- **ID:** `{finding.id}` | **Source:** {_source(finding)} | "
            f"**Confidence:** {_confidence(finding)} | **Badges:** {', '.join(_badges(finding))}"
        )
        lines.append(f"- **Location:** `{_ref(finding)}`")
        lines.append(
            f"- **Classification:** {_md(finding.category)} | **CWE:** {_md(finding.cwe or '-')} | "
            f"**OWASP:** {_owasp(finding)}"
        )
        lines.append("")
        lines.append(f"**Why it matters:** {_why(finding)}")
        lines.append("")
        lines.append(f"**Finding:** {_md(finding.message)}")
        lines.append("")
        if finding.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            for loc in finding.evidence:
                lines.append(f"- `{loc.ref}`")
            lines.append("")
        if finding.trace:
            trace = " -> ".join(f"`{loc.ref}`" for loc in finding.trace)
            lines.append(f"**Taint path:** {trace}")
            lines.append("")
        if finding.recommendation:
            lines.append(f"**Remediation:** {_md(finding.recommendation)}")
            lines.append("")
        provenance = _provenance(finding)
        if provenance:
            lines.append("**Provenance:**")
            lines.append("")
            for label, value in provenance:
                lines.append(f"- {label}: {_md(value)}")
            lines.append("")

    lines.append("## Dependency and CVE findings")
    lines.append("")
    if not report.dependency_findings:
        lines.append("No new dependency or CVE findings.")
        lines.append("")
    else:
        lines.append("| Severity | Package | Version | CVEs | Fixed version | Evidence |")
        lines.append("|---|---|---|---|---|---|")
        for finding in report.dependency_findings:
            metadata = finding.metadata or {}
            package = _md(metadata.get("package") or "-")
            version = _md(metadata.get("version") or "-")
            cves = ", ".join(str(cve) for cve in metadata.get("cves") or []) or "-"
            fixed = ", ".join(str(v) for v in metadata.get("fixed_versions") or []) or "-"
            lines.append(
                f"| {finding.severity.title()} | `{package}` | {version} | {_md(cves)} | "
                f"{_md(fixed)} | `{_ref(finding)}` |"
            )
        lines.append("")

    lines.append("## Configuration, infrastructure, and secrets")
    lines.append("")
    config_findings = report.configuration_findings + report.secret_findings
    if not config_findings:
        lines.append("No new configuration, infrastructure, or secret findings.")
        lines.append("")
    else:
        lines.append("| Severity | Category | Finding | Confidence | Evidence | Recommendation |")
        lines.append("|---|---|---|---|---|---|")
        for finding in config_findings:
            lines.append(
                f"| {finding.severity.title()} | {_md(finding.category)} | {_md(finding.title)} | "
                f"{_confidence(finding)} | `{_ref(finding)}` | {_md(finding.recommendation)} |"
            )
        lines.append("")

    lines.append("## Remediation roadmap")
    lines.append("")
    for group in report.remediation:
        lines.append(f"### {group.timeframe} - {_md(group.title)}")
        lines.append("")
        lines.append(group.action)
        lines.append("")
        if group.finding_ids:
            lines.append("Findings: " + ", ".join(f"`{finding_id}`" for finding_id in group.finding_ids))
            lines.append("")

    lines.append("## Coverage and limitations")
    lines.append("")
    coverage = report.coverage
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Security analysis | {'enabled' if coverage['security_enabled'] else 'disabled'} |")
    lines.append(f"| Files discovered / skipped | {coverage['files_discovered']} / {coverage['files_skipped']} |")
    lines.append(
        f"| Python / Java / IaC files | {coverage['python_files']} / "
        f"{coverage['java_files']} / {coverage['iac_files']} |"
    )
    lines.append(f"| Unresolved dynamic references | {coverage['unresolved_count']} |")
    lines.append(f"| Parse errors | {len(coverage['parse_errors'])} |")
    lines.append(f"| Confidence floor | {coverage['finding_confidence_floor']:.2f} |")
    if coverage["languages"]:
        language_text = ", ".join(
            f"{row['name']} ({row['files']})" for row in coverage["languages"]
        )
        lines.append(f"| Languages | {_md(language_text)} |")
    if coverage["unsupported_security_languages"]:
        lines.append(
            "| Unsupported security languages | "
            + _md(", ".join(coverage["unsupported_security_languages"]))
            + " |"
        )
    lines.append("")
    if coverage["parse_errors"]:
        lines.append("Files that could not be parsed:")
        lines.append("")
        for path in coverage["parse_errors"][:20]:
            lines.append(f"- `{_md(path)}`")
        if len(coverage["parse_errors"]) > 20:
            lines.append(f"- ... {len(coverage['parse_errors']) - 20} more")
        lines.append("")
    lines.append("### Known limitations")
    lines.append("")
    for limitation in report.limitations:
        lines.append(f"- {limitation}")
    lines.append("")
    if report.external_reports:
        lines.append("### Imported scanner reports")
        lines.append("")
        lines.append("| Source | File | Findings |")
        lines.append("|---|---|---:|")
        for item in report.external_reports:
            lines.append(
                f"| {_md(item.get('source', ''))} | `{_md(item.get('file', ''))}` | "
                f"{item.get('findings', 0)} |"
            )
        lines.append("")
    if report.advisory_sources:
        lines.append("### Advisory validation sources")
        lines.append("")
        lines.append("| File | Entries |")
        lines.append("|---|---:|")
        for item in report.advisory_sources:
            lines.append(
                f"| `{_md(item.get('file', ''))}` | {item.get('entries', 0)} |"
            )
        lines.append("")

    lines.append("## Evidence appendix")
    lines.append("")
    lines.append("### New findings")
    lines.append("")
    if not report.new_findings:
        lines.append("No new findings.")
        lines.append("")
    else:
        lines.append("| ID | Severity | Source | Title | Evidence | Confidence |")
        lines.append("|---|---|---|---|---|---|")
        for finding in report.new_findings:
            lines.append(
                f"| `{finding.id}` | {finding.severity.title()} | {_source(finding)} | "
                f"{_md(finding.title)} | `{_ref(finding)}` | {finding.confidence:.2f} |"
            )
        lines.append("")
    if report.baselined_findings:
        lines.append("### Baseline-suppressed findings")
        lines.append("")
        lines.append("| ID | Severity | Source | Title | Evidence |")
        lines.append("|---|---|---|---|---|")
        for finding in report.baselined_findings:
            lines.append(
                f"| `{finding.id}` | {finding.severity.title()} | {_source(finding)} | "
                f"{_md(finding.title)} | `{_ref(finding)}` |"
            )
        lines.append("")

    if report.narrative:
        lines.append("## Appendix: AI-assisted narrative (optional)")
        lines.append("")
        lines.append(
            "> Machine-generated from the deterministic evidence pack. This is a drafting aid, "
            "not an authoritative finding. Verify every citation before use."
        )
        lines.append("")
        lines.append(report.narrative.strip())
        lines.append("")

    lines.append("## Reproducibility")
    lines.append("")
    lines.append("```bash")
    lines.append(report.reproduce)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _html_badge(label: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{_h(label)}</span>'


def _html_finding(finding: Finding) -> str:
    badges = "".join(
        _html_badge(label, "exploited" if label == "Known exploited" else "info")
        for label in _badges(finding)
    )
    severity = _h(finding.severity)
    parts: list[str] = []
    parts.append(f'<article class="finding sev-{severity}">')
    parts.append('<div class="finding-head">')
    parts.append(f'<span class="sev sev-{severity}">{severity.upper()}</span>')
    parts.append(f'<h3>{_h(finding.title)}</h3>')
    parts.append(badges)
    parts.append("</div>")
    parts.append('<div class="meta-grid">')
    parts.append(f"<div><span>ID</span><code>{_h(finding.id)}</code></div>")
    parts.append(f"<div><span>Source</span>{_h(_source(finding))}</div>")
    parts.append(f"<div><span>Confidence</span>{_h(_confidence(finding))}</div>")
    parts.append(f"<div><span>Location</span><code>{_h(_ref(finding))}</code></div>")
    cwe = _h(finding.cwe or "-")
    if finding.cwe and finding.cwe.startswith("CWE-"):
        number = finding.cwe.split("-", 1)[1]
        cwe = (
            f'<a href="https://cwe.mitre.org/data/definitions/{_h(number)}.html">'
            f"{_h(finding.cwe)}</a>"
        )
    parts.append(f"<div><span>CWE</span>{cwe}</div>")
    parts.append(f"<div><span>OWASP</span>{_h(_owasp(finding))}</div>")
    parts.append("</div>")
    parts.append(f'<p class="why"><strong>Why it matters.</strong> {_h(_why(finding))}</p>')
    parts.append(f"<p>{_h(finding.message)}</p>")
    if finding.evidence:
        parts.append('<div class="kv"><span>Evidence</span><ul>')
        for loc in finding.evidence:
            parts.append(f"<li><code>{_h(loc.ref)}</code></li>")
        parts.append("</ul></div>")
    if finding.trace:
        parts.append('<div class="kv"><span>Taint path</span><p class="trace">')
        parts.append(
            " &rarr; ".join(f"<code>{_h(loc.ref)}</code>" for loc in finding.trace)
        )
        parts.append("</p></div>")
    if finding.recommendation:
        parts.append(f'<p><strong>Remediation.</strong> {_h(finding.recommendation)}</p>')
    provenance = _provenance(finding)
    if provenance:
        parts.append('<table class="compact"><tbody>')
        for label, value in provenance:
            parts.append(f"<tr><th>{_h(label)}</th><td>{_h(value)}</td></tr>")
        parts.append("</tbody></table>")
    parts.append("</article>")
    return "\n".join(parts)


def _html_table(headers: list[str], rows: list[list[str]], *, compact: bool = False) -> str:
    classes = "data compact" if compact else "data"
    parts = [f'<table class="{classes}"><thead><tr>']
    parts.extend(f"<th>{_h(header)}</th>" for header in headers)
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append(f"<td>{cell}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


_CSS = """
:root{--ink:#111827;--muted:#6b7280;--line:#d1d5db;--bg:#ffffff;--soft:#f8fafc;
--critical:#991b1b;--high:#c2410c;--medium:#a16207;--low:#1d4ed8;--info:#475569}
*{box-sizing:border-box}
html{background:#e5e7eb}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.page{max-width:1080px;margin:0 auto;background:var(--bg);padding:32px 44px 60px}
h1,h2,h3{line-height:1.2;margin:0 0 10px}
h1{font-size:32px;letter-spacing:-.02em}
h2{font-size:22px;border-bottom:2px solid var(--ink);padding-bottom:8px;margin-top:34px}
h3{font-size:16px}
p{margin:8px 0}
a{color:#1d4ed8}
code{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px;background:var(--soft);padding:1px 4px;border-radius:4px}
.cover{min-height:640px;display:flex;flex-direction:column;justify-content:space-between;border:1px solid var(--line);padding:36px;margin-bottom:28px;page-break-after:always}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:700;color:var(--muted)}
.subtitle{color:var(--muted);font-size:15px}
.verdict{border:2px solid;padding:12px 16px;margin:22px 0;font-size:20px;font-weight:800;letter-spacing:.04em}
.verdict small{display:block;font-size:12px;font-weight:500;letter-spacing:0;color:var(--muted);margin-top:4px}
.v-pass{color:#166534;border-color:#166534;background:#f0fdf4}
.v-fail{color:var(--critical);border-color:var(--critical);background:#fef2f2}
.v-info{color:#1d4ed8;border-color:#1d4ed8;background:#eff6ff}
.cover-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.metric{border:1px solid var(--line);padding:12px;background:var(--soft)}
.metric b{display:block;font-size:24px;line-height:1.1}
.metric span{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.toc{columns:2;column-gap:32px;padding-left:18px}
.toc li{margin:4px 0}
.lead{font-size:15px}
table.data{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:12.5px}
table.data th,table.data td{border:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}
table.data th{background:var(--soft);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
table.data tr{page-break-inside:avoid}
table.compact{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px}
table.compact th,table.compact td{border-top:1px solid var(--line);padding:5px 6px;text-align:left;vertical-align:top}
table.compact th{width:150px;color:var(--muted);font-weight:600}
.sev,.badge{display:inline-block;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;margin-right:6px}
.sev{color:#fff}
.sev-critical{background:var(--critical)}
.sev-high{background:var(--high)}
.sev-medium{background:var(--medium)}
.sev-low{background:var(--low)}
.sev-info{background:var(--info)}
.badge-info{background:#e0e7ff;color:#3730a3}
.badge-exploited{background:#fee2e2;color:var(--critical)}
.finding{border:1px solid var(--line);border-left:5px solid var(--info);padding:16px 18px;margin:16px 0;page-break-inside:avoid;background:#fff}
.finding.sev-critical{border-left-color:var(--critical)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--medium)}
.finding.sev-low{border-left-color:var(--low)}
.finding-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.finding-head h3{margin:0;flex:1;min-width:240px}
.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 18px;margin:12px 0;padding:10px;background:var(--soft);border:1px solid var(--line)}
.meta-grid div{font-size:12px}
.meta-grid span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.why{background:#fffbeb;border-left:3px solid var(--medium);padding:8px 10px}
.kv{margin:10px 0}
.kv>span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:3px}
.kv ul,.kv ol{margin:4px 0 0 18px;padding:0}
.trace{font-size:12px}
.callout{border:1px solid var(--line);background:var(--soft);padding:10px 12px;margin:12px 0;font-size:13px}
.limits li{margin:5px 0}
.roadmap{border-left:3px solid var(--ink);padding-left:14px;margin:16px 0}
.ids{font-size:12px;color:var(--muted)}
.narrative{border:1px dashed var(--line);padding:14px;background:var(--soft)}
footer{margin-top:40px;border-top:1px solid var(--line);padding-top:12px;font-size:11px;color:var(--muted)}
@media (max-width:760px){.page{padding:20px}.cover{padding:22px}.cover-grid{grid-template-columns:repeat(2,1fr)}.meta-grid{grid-template-columns:1fr}.toc{columns:1}}
@media print{html,body{background:#fff}body{font-size:11.5px}.page{max-width:none;padding:0}.cover{min-height:auto;border:0;padding:0 0 24px}.toc,.no-print{display:none}a{color:inherit;text-decoration:none}.finding,table.data tr{page-break-inside:avoid}h2{page-break-after:avoid}}
"""


def render_security_html(report: SecurityReport) -> str:
    """Render a static, print-first HTML security review."""
    gate_class = {
        "PASS": "v-pass",
        "FAIL": "v-fail",
    }.get(report.gate.verdict, "v-info")
    critical_high = report.risk.by_severity["critical"] + report.risk.by_severity["high"]
    known_exploited = sum(1 for finding in report.new_findings if is_known_exploited(finding))
    validated = sum(1 for finding in report.new_findings if is_validated(finding))

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>Security Review - {_h(report.name)}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><main class=\"page\">")

    parts.append('<header class="cover">')
    parts.append('<div>')
    parts.append('<div class="eyebrow">Security Review | Static Analysis</div>')
    parts.append(f"<h1>{_h(report.name)}</h1>")
    bits = [
        f"Generated by secdiagram {_h(report.tool_version)}",
        f"report <code>{_h(report.report_id)}</code>",
    ]
    if report.commit:
        bits.append(f"commit <code>{_h(report.commit)}</code>")
    if report.branch:
        bits.append(f"branch <code>{_h(report.branch)}</code>")
    if report.dirty:
        bits.append("working tree dirty")
    parts.append(f'<p class="subtitle">{" | ".join(bits)}</p>')
    parts.append(
        f'<div class="verdict {gate_class}">{_h(report.gate.verdict)}'
        f"<small>{_h(report.gate.reason)}</small></div>"
    )
    parts.append("</div>")
    parts.append('<div class="cover-grid">')
    for value, label in (
        (f"{report.risk.index}/100", f"Risk index ({report.risk.label})"),
        (str(report.risk.new_count), "New findings"),
        (str(critical_high), "Critical / high"),
        (str(report.risk.baselined_count), "Baseline-suppressed"),
    ):
        parts.append(f'<div class="metric"><b>{_h(value)}</b><span>{_h(label)}</span></div>')
    parts.append("</div>")
    parts.append("</header>")

    parts.append('<section id="summary">')
    parts.append("<h2>Executive summary</h2>")
    summary_text = _summary_sentence(report).replace("**", "").replace("`", "")
    parts.append(f'<p class="lead">{_h(summary_text)}</p>')
    parts.append(
        f'<p class="callout">Advisory validation: <strong>{validated}</strong> finding(s) '
        f"corroborated; <strong>{known_exploited}</strong> known-exploited match(es). "
        f"Risk index formula: <code>{_h(report.risk.formula)}</code>. "
                 "This is a prioritization aid, not a CVSS score or exploitability proof.</p>")
    parts.append(f"<p><strong>Detection sources.</strong> {_h(_external_summary(report))}</p>")
    severity_rows = [
        [_h(label), str(report.risk.by_severity[key])]
        for key, label in (
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        )
    ]
    parts.append(_html_table(["Severity", "New findings"], severity_rows, compact=True))
    if report.risk.by_category:
        category_rows = [
            [f"<code>{_h(category)}</code>", str(count)]
            for category, count in sorted(report.risk.by_category.items())
        ]
        parts.append(_html_table(["Category", "New findings"], category_rows, compact=True))
    if report.gate.threshold:
        parts.append(
            f'<p class="callout">CI gate: new findings at or above '
            f"<strong>{_h(report.gate.threshold)}</strong> must be fixed or explicitly baselined.</p>"
        )
    parts.append("</section>")

    parts.append('<section id="priorities">')
    parts.append("<h2>Top priorities</h2>")
    if not report.priorities:
        parts.append("<p>No new findings require prioritization.</p>")
    else:
        parts.append("<ol>")
        for finding in report.priorities:
            badges = "".join(_html_badge(label, "info") for label in _badges(finding))
            parts.append(
                f'<li><span class="sev sev-{_h(finding.severity)}">{_h(finding.severity.upper())}</span>'
                f"<strong>{_h(finding.title)}</strong> "
                f'<code>{_h(finding.id)}</code> at <code>{_h(_ref(finding))}</code> '
                f"({_h(_confidence(finding))}) {badges}</li>"
            )
        parts.append("</ol>")
    parts.append("</section>")

    parts.append('<section id="surface">')
    parts.append("<h2>Attack surface</h2>")
    surface = report.surface
    parts.append(
        f"<p><strong>{len(surface.endpoints)}</strong> endpoint(s), "
        f"<strong>{surface.route_count}</strong> route(s), "
        f"<strong>{surface.unauthenticated}</strong> without an authentication marker, "
        f"<strong>{surface.authenticated}</strong> with one. "
        f"<strong>{len(surface.external_dependencies)}</strong> external dependency name(s), "
        f"<strong>{len(surface.infrastructure)}</strong> infrastructure artifact(s).</p>"
    )
    if surface.risky_infrastructure:
        parts.append(
            '<p class="callout"><strong>Risky infrastructure markers.</strong> '
            + _h(", ".join(surface.risky_infrastructure))
            + ".</p>"
        )
    parts.append(
        '<p class="callout">"Without an authentication marker" means no supported decorator '
        "or annotation was detected. It is not proof that the endpoint is publicly reachable.</p>"
    )
    if surface.endpoints:
        rows = []
        for endpoint in surface.endpoints[:40]:
            ref = (
                f"<code>{_h(endpoint.path)}:{_h(endpoint.line)}</code>"
                if endpoint.path and endpoint.line
                else "-"
            )
            rows.append(
                [
                    f"<code>{_h(endpoint.qualname)}</code>",
                    _h(", ".join(endpoint.routes) or "-"),
                    "yes" if endpoint.authenticated else "not detected",
                    ref,
                ]
            )
        if len(surface.endpoints) > 40:
            rows.append([f"... {len(surface.endpoints) - 40} more", "", "", ""])
        parts.append(_html_table(["Endpoint", "Routes", "Auth marker", "Source"], rows))
    if surface.external_dependencies:
        shown = ", ".join(f"<code>{_h(name)}</code>" for name in surface.external_dependencies[:24])
        suffix = (
            f" (+{len(surface.external_dependencies) - 24} more)"
            if len(surface.external_dependencies) > 24
            else ""
        )
        parts.append(f"<p><strong>External dependencies.</strong> {shown}{suffix}</p>")
    if surface.infrastructure:
        shown = ", ".join(f"<code>{_h(name)}</code>" for name in surface.infrastructure[:24])
        suffix = (
            f" (+{len(surface.infrastructure) - 24} more)"
            if len(surface.infrastructure) > 24
            else ""
        )
        parts.append(f"<p><strong>Infrastructure artifacts.</strong> {shown}{suffix}</p>")
    parts.append("</section>")

    parts.append('<section id="findings">')
    parts.append("<h2>Priority findings</h2>")
    if not report.priorities:
        parts.append("<p>No new findings require prioritization.</p>")
    for finding in report.priorities:
        parts.append(_html_finding(finding))
    parts.append("</section>")

    parts.append('<section id="dependencies">')
    parts.append("<h2>Dependency and CVE findings</h2>")
    if not report.dependency_findings:
        parts.append("<p>No new dependency or CVE findings.</p>")
    else:
        rows = []
        for finding in report.dependency_findings:
            metadata = finding.metadata or {}
            package = _h(metadata.get("package") or "-")
            version = _h(metadata.get("version") or "-")
            cves = ", ".join(str(cve) for cve in metadata.get("cves") or []) or "-"
            fixed = ", ".join(str(v) for v in metadata.get("fixed_versions") or []) or "-"
            rows.append(
                [
                    f'<span class="sev sev-{_h(finding.severity)}">{_h(finding.severity.upper())}</span>',
                    f"<code>{package}</code>",
                    version,
                    _h(cves),
                    _h(fixed),
                    f"<code>{_h(_ref(finding))}</code>",
                ]
            )
        parts.append(
            _html_table(
                ["Severity", "Package", "Version", "CVEs", "Fixed version", "Evidence"],
                rows,
            )
        )
    parts.append("</section>")

    parts.append('<section id="configuration">')
    parts.append("<h2>Configuration, infrastructure, and secrets</h2>")
    config_findings = report.configuration_findings + report.secret_findings
    if not config_findings:
        parts.append("<p>No new configuration, infrastructure, or secret findings.</p>")
    else:
        rows = []
        for finding in config_findings:
            rows.append(
                [
                    f'<span class="sev sev-{_h(finding.severity)}">{_h(finding.severity.upper())}</span>',
                    _h(finding.category),
                    _h(finding.title),
                    _h(_confidence(finding)),
                    f"<code>{_h(_ref(finding))}</code>",
                    _h(finding.recommendation),
                ]
            )
        parts.append(
            _html_table(
                ["Severity", "Category", "Finding", "Confidence", "Evidence", "Remediation"],
                rows,
            )
        )
    parts.append("</section>")

    parts.append('<section id="roadmap">')
    parts.append("<h2>Remediation roadmap</h2>")
    for group in report.remediation:
        parts.append('<div class="roadmap">')
        parts.append(f"<h3>{_h(group.timeframe)} - {_h(group.title)}</h3>")
        parts.append(f"<p>{_h(group.action)}</p>")
        if group.finding_ids:
            parts.append(
                '<p class="ids">Findings: '
                + ", ".join(f"<code>{_h(finding_id)}</code>" for finding_id in group.finding_ids)
                + "</p>"
            )
        parts.append("</div>")
    parts.append("</section>")

    parts.append('<section id="coverage">')
    parts.append("<h2>Coverage and limitations</h2>")
    coverage = report.coverage
    rows = [
        ["Security analysis", "enabled" if coverage["security_enabled"] else "disabled"],
        ["Files discovered / skipped", f"{coverage['files_discovered']} / {coverage['files_skipped']}"],
        [
            "Python / Java / IaC files",
            f"{coverage['python_files']} / {coverage['java_files']} / {coverage['iac_files']}",
        ],
        ["Unresolved dynamic references", str(coverage["unresolved_count"])],
        ["Parse errors", str(len(coverage["parse_errors"]))],
        ["Confidence floor", f"{coverage['finding_confidence_floor']:.2f}"],
    ]
    if coverage["languages"]:
        rows.append(
            [
                "Languages",
                ", ".join(f"{row['name']} ({row['files']})" for row in coverage["languages"]),
            ]
        )
    if coverage["unsupported_security_languages"]:
        rows.append(
            ["Unsupported security languages", ", ".join(coverage["unsupported_security_languages"])]
        )
    parts.append(_html_table(["Metric", "Value"], [[_h(a), _h(b)] for a, b in rows], compact=True))
    if coverage["parse_errors"]:
        parts.append("<h3>Files that could not be parsed</h3><ul>")
        for path in coverage["parse_errors"][:20]:
            parts.append(f"<li><code>{_h(path)}</code></li>")
        if len(coverage["parse_errors"]) > 20:
            parts.append(f"<li>... {len(coverage['parse_errors']) - 20} more</li>")
        parts.append("</ul>")
    parts.append('<h3>Known limitations</h3><ul class="limits">')
    for limitation in report.limitations:
        parts.append(f"<li>{_h(limitation)}</li>")
    parts.append("</ul>")

    if report.external_reports:
        parts.append("<h3>Imported scanner reports</h3>")
        parts.append(
            _html_table(
                ["Source", "File", "Findings"],
                [
                    [
                        _h(item.get("source", "")),
                        f"<code>{_h(item.get('file', ''))}</code>",
                        str(item.get("findings", 0)),
                    ]
                    for item in report.external_reports
                ],
                compact=True,
            )
        )
    if report.advisory_sources:
        parts.append("<h3>Advisory validation sources</h3>")
        parts.append(
            _html_table(
                ["File", "Entries"],
                [
                    [f"<code>{_h(item.get('file', ''))}</code>", str(item.get("entries", 0))]
                    for item in report.advisory_sources
                ],
                compact=True,
            )
        )
    parts.append("</section>")

    parts.append('<section id="appendix">')
    parts.append("<h2>Evidence appendix</h2>")
    parts.append("<h3>New findings</h3>")
    if not report.new_findings:
        parts.append("<p>No new findings.</p>")
    else:
        rows = []
        for finding in report.new_findings:
            rows.append(
                [
                    f"<code>{_h(finding.id)}</code>",
                    f'<span class="sev sev-{_h(finding.severity)}">{_h(finding.severity.upper())}</span>',
                    _h(_source(finding)),
                    _h(finding.title),
                    f"<code>{_h(_ref(finding))}</code>",
                    f"{finding.confidence:.2f}",
                ]
            )
        parts.append(
            _html_table(
                ["ID", "Severity", "Source", "Title", "Evidence", "Confidence"],
                rows,
                compact=True,
            )
        )
    if report.baselined_findings:
        parts.append("<h3>Baseline-suppressed findings</h3>")
        rows = []
        for finding in report.baselined_findings:
            rows.append(
                [
                    f"<code>{_h(finding.id)}</code>",
                    f'<span class="sev sev-{_h(finding.severity)}">{_h(finding.severity.upper())}</span>',
                    _h(_source(finding)),
                    _h(finding.title),
                    f"<code>{_h(_ref(finding))}</code>",
                ]
            )
        parts.append(
            _html_table(
                ["ID", "Severity", "Source", "Title", "Evidence"],
                rows,
                compact=True,
            )
        )
    parts.append("</section>")

    if report.narrative:
        parts.append('<section id="narrative">')
        parts.append("<h2>Appendix: AI-assisted narrative (optional)</h2>")
        parts.append(
            '<div class="narrative callout"><strong>Machine-generated drafting aid.</strong> '
            "This is not an authoritative finding. Verify every citation before use.</div>"
        )
        parts.append(f"<pre>{_h(report.narrative.strip())}</pre>")
        parts.append("</section>")

    parts.append('<section id="reproduce">')
    parts.append("<h2>Reproducibility</h2>")
    parts.append(f"<pre><code>{_h(report.reproduce)}</code></pre>")
    if report.commit:
        parts.append(f"<p>Source commit: <code>{_h(report.commit)}</code>.")
        if report.dirty:
            parts.append(" The working tree was dirty at scan time; results may not match the commit.")
        parts.append("</p>")
    parts.append("</section>")

    parts.append(
        f'<footer>secdiagram {_h(report.tool_version)} | report <code>{_h(report.report_id)}</code> | '
        "Deterministic static analysis. Findings are evidence-backed review prompts, not proof "
        "of exploitability.</footer>"
    )
    parts.append("</main></body></html>")
    return "\n".join(parts)
