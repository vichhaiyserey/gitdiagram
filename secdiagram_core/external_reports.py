"""Import SonarQube and JFrog Xray reports as evidence-backed findings.

Reports are treated as untrusted data: only local JSON files are read, no code is
executed, and every external claim is anchored to a repository path where possible.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .model import SEVERITY_RANK, Finding, Loc, stable_id

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ISSUES = 5000
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,4})\b", re.IGNORECASE)

_SEVERITY_MAP = {
    "blocker": "critical",
    "critical": "critical",
    "high": "high",
    "major": "high",
    "medium": "medium",
    "minor": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "low",
}

_MANIFEST_BY_ECOSYSTEM = {
    "npm": ("package-lock.json", "package.json", "yarn.lock", "pnpm-lock.yaml"),
    "maven": ("pom.xml",),
    "gradle": ("build.gradle", "build.gradle.kts"),
    "pypi": ("requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock"),
    "go": ("go.mod", "go.sum"),
    "nuget": ("packages.lock.json",),
    "rubygems": ("Gemfile.lock",),
    "gem": ("Gemfile.lock",),
    "cargo": ("Cargo.lock", "Cargo.toml"),
}


class ExternalReportError(ValueError):
    """Raised when a supplied external report cannot be normalized."""


def _read_json(path: Path) -> Any:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"external report not found: {path}")
    try:
        if resolved.stat().st_size > MAX_REPORT_BYTES:
            raise ExternalReportError(
                f"external report is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB: {path}"
            )
        text = resolved.read_text(encoding="utf-8", errors="replace")
        return json.loads(text)
    except ExternalReportError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise ExternalReportError(f"could not read JSON report {path}: {exc}") from exc


def _severity(value: Any) -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), "medium")


def _max_severity(*values: Any) -> str:
    result = "info"
    for value in values:
        if value is None or value == "":
            continue
        candidate = _severity(value)
        if SEVERITY_RANK[candidate] > SEVERITY_RANK[result]:
            result = candidate
    return result if result != "info" else "medium"


def _line(value: Any) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


def _rel_path(raw: Any, root: Path, *, project_component: bool = False) -> str | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.startswith("file://"):
        text = text[7:]
    text = text.replace("\\", "/")
    if project_component and ":" in text:
        prefix, rest = text.split(":", 1)
        if len(prefix) != 1 and "/" not in prefix and rest and not rest.startswith("/"):
            text = rest
    while text.startswith("./"):
        text = text[2:]
    if Path(text).is_absolute():
        try:
            text = Path(text).resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return None
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _text(value: Any, limit: int = 240) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _cwe(*values: Any) -> str | None:
    for value in values:
        if not value:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            match = CWE_RE.search(str(item))
            if match:
                number = int(match.group(1))
                if 1 <= number <= 2000:
                    return f"CWE-{number}"
    return None


def collect_cves(value: Any) -> list[str]:
    """Collect unique CVE IDs from arbitrary JSON-ish report fields."""
    found: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, str):
            found.update(match.upper() for match in CVE_RE.findall(item))
            return
        if isinstance(item, dict):
            for key in ("cve", "cveID", "id", "name", "summary", "description"):
                if key in item:
                    walk(item[key])
            for key in ("cves", "references", "aliases", "identifiers"):
                if key in item:
                    walk(item[key])
            return
        if isinstance(item, list):
            for entry in item:
                walk(entry)

    walk(value)
    return sorted(found)


def _max_cvss(*values: Any) -> float | None:
    best: float | None = None
    for value in values:
        if isinstance(value, dict):
            for key in ("cvss_v3_score", "cvss_v2_score", "score"):
                score = _max_cvss(value.get(key))
                if score is not None and (best is None or score > best):
                    best = score
        elif isinstance(value, list):
            for entry in value:
                score = _max_cvss(entry)
                if score is not None and (best is None or score > best):
                    best = score
        elif value not in (None, ""):
            try:
                score = float(value)
            except (TypeError, ValueError):
                continue
            if 0.0 <= score <= 10.0 and (best is None or score > best):
                best = score
    return best


def _guess_manifest(rel_files: list[str], ecosystem: str) -> str | None:
    hints = _MANIFEST_BY_ECOSYSTEM.get(ecosystem)
    if not hints:
        return None
    present = set(rel_files)
    for hint in hints:
        if hint in present:
            return hint
    for rel in sorted(present):
        if rel.rsplit("/", 1)[-1] in hints:
            return rel
    return None


def _component_info(component: Any, issue: dict[str, Any]) -> dict[str, Any]:
    raw = component if isinstance(component, str) else ""
    if not raw and isinstance(component, dict):
        raw = str(
            component.get("component") or component.get("id") or component.get("name") or ""
        )
    package = _text(issue.get("component_name") or issue.get("package_name"), 160)
    version = _text(issue.get("component_version") or issue.get("version"), 80)
    ecosystem = ""
    if "://" in raw:
        ecosystem, rest = raw.split("://", 1)
        ecosystem = ecosystem.lower()
        rest = rest.split("?", 1)[0]
        if ":" in rest:
            name, parsed_version = rest.rsplit(":", 1)
            package = package or name
            version = version or parsed_version
        elif not package:
            package = rest
    elif raw:
        if ":" in raw:
            name, parsed_version = raw.rsplit(":", 1)
            package = package or name
            version = version or parsed_version
        else:
            package = package or raw
    if not package and isinstance(component, dict):
        package = _text(component.get("name"), 160)
        version = version or _text(component.get("version"), 80)
        ecosystem = ecosystem or str(component.get("type") or "").lower()
    return {"package": package, "version": version, "ecosystem": ecosystem}


def _sonar_findings(data: Any, root: Path) -> list[Finding]:
    issues = data.get("issues") if isinstance(data, dict) else data
    if not isinstance(issues, list):
        raise ExternalReportError("SonarQube report must contain an 'issues' list")
    findings: list[Finding] = []
    for issue in issues[:MAX_ISSUES]:
        if not isinstance(issue, dict):
            continue
        status = str(issue.get("status") or "").upper()
        if status in {"CLOSED", "FALSE_POSITIVE", "ACCEPTED", "WONTFIX", "RESOLVED"}:
            continue
        issue_type = str(issue.get("type") or issue.get("issueType") or "").upper()
        if issue_type == "CODE_SMELL":
            continue
        component = issue.get("component") or issue.get("path") or issue.get("filePath")
        rel_path = _rel_path(component, root, project_component=True)
        if rel_path is None:
            rel_path = _rel_path(issue.get("path"), root)
        if rel_path is None:
            continue
        line = _line(issue.get("line") or (issue.get("textRange") or {}).get("startLine"))
        rule = _text(issue.get("rule"), 120)
        tags = [str(tag) for tag in issue.get("tags", []) if isinstance(tag, str)][:12]
        impacts = issue.get("impacts") or []
        impact_severities = [
            impact.get("severity")
            for impact in impacts
            if isinstance(impact, dict)
            and str(impact.get("softwareQuality") or "").upper() == "SECURITY"
        ]
        severity = _max_severity(issue.get("severity"), *impact_severities)
        message = _text(issue.get("message") or rule or "SonarQube security issue", 220)
        metadata: dict[str, Any] = {
            "tool": "sonarqube",
            "rule": rule,
            "type": issue_type,
            "status": status,
            "project": _text(issue.get("project"), 120),
            "tags": tags,
            "effort": _text(issue.get("effort"), 40),
            "flows": len(issue.get("flows") or []),
        }
        metadata = {key: value for key, value in metadata.items() if value not in ("", None, [])}
        findings.append(
            Finding(
                id=stable_id("external", "sonarqube", rule, rel_path, str(line), message),
                category="external",
                severity=severity,
                title=f"SonarQube: {message}",
                message=f"SonarQube {rule or 'issue'} at {rel_path}:{line}: {message}",
                cwe=_cwe(issue.get("cwe"), tags, message),
                confidence=0.9 if issue_type == "VULNERABILITY" else 0.85,
                evidence=[Loc(rel_path, line)],
                recommendation=(
                    f"Review SonarQube rule {rule} in the SonarQube UI and apply its remediation."
                    if rule
                    else "Review this SonarQube security issue and apply the recommended remediation."
                ),
                source="sonarqube",
                external_id=_text(issue.get("key"), 120) or None,
                metadata=metadata,
            )
        )
    return findings


def _xray_records(data: Any) -> list[tuple[Any, Any, dict[str, Any]]]:
    records: list[tuple[Any, Any, dict[str, Any]]] = []

    def add_violations(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict):
                records.append(
                    (
                        item.get("component") or item.get("component_name"),
                        item.get("path") or item.get("artifact"),
                        item,
                    )
                )

    if isinstance(data, list):
        add_violations(data)
    elif isinstance(data, dict):
        add_violations(data.get("violations"))
        nested = data.get("data")
        if isinstance(nested, dict):
            add_violations(nested.get("violations"))
        components = data.get("components")
        if isinstance(components, dict):
            for key in sorted(components):
                component = components[key]
                if not isinstance(component, dict):
                    continue
                issues = (
                    component.get("issues")
                    or component.get("violations")
                    or component.get("vulnerabilities")
                    or []
                )
                for issue in issues:
                    if isinstance(issue, dict):
                        records.append(
                            (key, component.get("path") or component.get("artifact"), issue)
                        )
        for key in ("artifacts", "results"):
            items = data.get(key)
            if not isinstance(items, list):
                continue
            for artifact in items:
                if not isinstance(artifact, dict):
                    continue
                artifact_path = artifact.get("path") or artifact.get("artifact")
                for issue in artifact.get("issues") or []:
                    if isinstance(issue, dict):
                        records.append((artifact_path, artifact_path, issue))
    return records


def _xray_findings(
    data: Any, root: Path, rel_files: list[str], report_name: str
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for component, artifact, issue in _xray_records(data)[:MAX_ISSUES]:
        info = _component_info(component, issue)
        package = info["package"] or "unknown component"
        version = info["version"]
        cves = collect_cves(
            [
                issue.get("cves"),
                issue.get("cve"),
                issue.get("references"),
                issue.get("summary"),
                issue.get("description"),
            ]
        )
        summary = _text(
            issue.get("summary") or issue.get("description") or issue.get("id"), 220
        )
        issue_id = _text(issue.get("id") or issue.get("issue_id"), 120)
        if not summary and not cves and not issue_id:
            continue
        rel_path = _rel_path(artifact or issue.get("path"), root)
        if rel_path is None:
            rel_path = _guess_manifest(rel_files, info["ecosystem"]) or report_name
        line = _line(issue.get("line"))
        fixed_versions = [
            _text(version_value, 80)
            for version_value in (issue.get("fixed_versions") or [])
            if str(version_value).strip()
        ][:10]
        references = [
            _text(reference, 200)
            for reference in (issue.get("references") or [])
            if str(reference).strip()
        ][:8]
        cvss = _max_cvss(
            issue.get("cvss_v3_score"),
            issue.get("cvss_v2_score"),
            issue.get("cvss"),
            issue.get("cves"),
        )
        severity = _max_severity(issue.get("severity"))
        if not issue.get("severity") and cvss is not None:
            severity = (
                "critical"
                if cvss >= 9
                else "high"
                if cvss >= 7
                else "medium"
                if cvss >= 4
                else "low"
            )
        title = f"Xray: {summary or issue_id or (cves[0] if cves else package)}"
        identity = issue_id or (cves[0] if cves else summary)
        finding_id = stable_id("external", "xray", identity, rel_path, str(line), title)
        if finding_id in seen:
            continue
        seen.add(finding_id)
        metadata: dict[str, Any] = {
            "tool": "xray",
            "package": package,
            "version": version,
            "ecosystem": info["ecosystem"],
            "cves": cves,
            "cvss": cvss,
            "fixed_versions": fixed_versions,
            "provider": _text(issue.get("provider"), 120),
            "references": references,
            "policy": _text(issue.get("policy_name") or issue.get("watch_name"), 120),
        }
        metadata = {key: value for key, value in metadata.items() if value not in ("", None, [])}
        recommendation = (
            f"Upgrade {package} to {fixed_versions[0]} or later, or remove the affected dependency."
            if fixed_versions
            else f"Upgrade or replace {package}; no fixed version is listed in the report."
        )
        findings.append(
            Finding(
                id=finding_id,
                category="external",
                severity=severity,
                title=_text(title, 200),
                message=(
                    f"Xray reports {package} {version or ''} affected by "
                    f"{', '.join(cves) if cves else 'a vulnerable component'}: {summary}"
                )
                .replace("  ", " ")
                .strip(),
                cwe=_cwe(issue.get("cwe"), issue.get("cwes"), summary),
                confidence=0.95 if cves else 0.85,
                evidence=[Loc(rel_path, line)],
                recommendation=recommendation,
                source="xray",
                external_id=issue_id or None,
                metadata=metadata,
            )
        )
    return findings


def load_external_reports(
    root: Path,
    rel_files: list[str],
    sonarqube_report: Path | None = None,
    xray_report: Path | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Load all configured external reports and return findings plus provenance."""
    findings: list[Finding] = []
    summaries: list[dict[str, Any]] = []
    if sonarqube_report is not None:
        data = _read_json(sonarqube_report)
        items = _sonar_findings(data, root)
        findings.extend(items)
        summaries.append(
            {"source": "sonarqube", "file": sonarqube_report.name, "findings": len(items)}
        )
    if xray_report is not None:
        data = _read_json(xray_report)
        items = _xray_findings(data, root, rel_files, xray_report.name)
        findings.extend(items)
        summaries.append({"source": "xray", "file": xray_report.name, "findings": len(items)})
    summaries.sort(key=lambda item: (item["source"], item["file"]))
    return findings, summaries
