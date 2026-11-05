"""Offline advisory validation for imported dependency findings.

Supports local CISA KEV, NVD, OSV, and generic CVE-to-advisory JSON files so
external scanner results can be corroborated without mandatory network access.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .external_reports import collect_cves
from .model import SEVERITY_RANK, Finding

MAX_ADVISORY_BYTES = 128 * 1024 * 1024
_KEV_SOURCE = "cisa-kev"


@dataclass(frozen=True, slots=True)
class Advisory:
    source: str
    name: str
    summary: str = ""
    vendor: str = ""
    product: str = ""
    severity: str | None = None
    known_exploited: bool = False
    ransomware: str = ""
    published: str = ""
    url: str = ""


def _read_json(path: Path) -> Any:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"advisory database not found: {path}")
    try:
        if resolved.stat().st_size > MAX_ADVISORY_BYTES:
            raise ValueError(
                f"advisory database is larger than {MAX_ADVISORY_BYTES // (1024 * 1024)} MiB: {path}"
            )
        return json.loads(resolved.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read advisory database {path}: {exc}") from exc


def _severity(value: Any) -> str | None:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(str(value or "").strip().lower())


def _nvd_entry(entry: dict[str, Any]) -> tuple[list[str], Advisory] | None:
    cve = entry.get("cve")
    if not isinstance(cve, dict):
        return None
    identifiers = collect_cves(cve.get("id"))
    if not identifiers:
        return None
    descriptions = cve.get("descriptions") or []
    summary = ""
    if isinstance(descriptions, list):
        for description in descriptions:
            if isinstance(description, dict) and description.get("lang") == "en":
                summary = str(description.get("value") or "")
                break
    metrics = cve.get("metrics") or {}
    severity = None
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if not isinstance(entries, list):
                continue
            for metric in entries:
                if not isinstance(metric, dict):
                    continue
                data = metric.get("cvssData") or {}
                if isinstance(data, dict):
                    severity = severity or _severity(
                        data.get("baseSeverity") or metric.get("baseSeverity")
                    )
    return identifiers, Advisory(
        source="nvd",
        name=str(cve.get("id") or identifiers[0]),
        summary=summary[:280],
        severity=severity,
        published=str(cve.get("published") or ""),
        url=f"https://nvd.nist.gov/vuln/detail/{identifiers[0]}",
    )


def _kev_entry(entry: dict[str, Any]) -> tuple[list[str], Advisory] | None:
    identifiers = collect_cves(entry.get("cveID") or entry.get("cve"))
    if not identifiers:
        return None
    return identifiers, Advisory(
        source=_KEV_SOURCE,
        name=str(entry.get("vulnerabilityName") or identifiers[0]),
        summary=str(entry.get("shortDescription") or "")[:280],
        vendor=str(entry.get("vendorProject") or ""),
        product=str(entry.get("product") or ""),
        known_exploited=True,
        ransomware=str(entry.get("knownRansomwareCampaignUse") or ""),
        published=str(entry.get("dateAdded") or ""),
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )


def _osv_entry(entry: dict[str, Any]) -> tuple[list[str], Advisory] | None:
    identifiers = collect_cves([entry.get("id"), entry.get("aliases")])
    if not identifiers:
        return None
    severity = None
    severities = entry.get("severity")
    if isinstance(severities, list) and severities:
        first = severities[0]
        if isinstance(first, dict):
            score = str(first.get("score") or "")
            severity = "high" if "CVSS:3" in score else None
    return identifiers, Advisory(
        source="osv",
        name=str(entry.get("id") or identifiers[0]),
        summary=str(entry.get("summary") or entry.get("details") or "")[:280],
        severity=severity,
        published=str(entry.get("published") or ""),
        url=f"https://osv.dev/vulnerability/{entry.get('id') or identifiers[0]}",
    )


def _iter_entries(data: Any) -> list[tuple[list[str], Advisory]]:
    entries: list[tuple[list[str], Advisory]] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                parsed = _entry_from_dict(item)
                if parsed:
                    entries.append(parsed)
        return entries
    if not isinstance(data, dict):
        return entries
    if "cveID" in data:
        parsed = _kev_entry(data)
        return [parsed] if parsed else entries
    if "cve" in data and isinstance(data.get("cve"), dict):
        parsed = _nvd_entry(data)
        return [parsed] if parsed else entries
    if "id" in data and ("aliases" in data or "affected" in data):
        parsed = _osv_entry(data)
        return [parsed] if parsed else entries
    if isinstance(data.get("vulnerabilities"), list):
        for item in data["vulnerabilities"]:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("cve"), dict):
                parsed = _nvd_entry(item)
            else:
                parsed = _kev_entry(item)
            if parsed:
                entries.append(parsed)
    if isinstance(data.get("vulns"), list):
        for item in data["vulns"]:
            if isinstance(item, dict):
                parsed = _osv_entry(item)
                if parsed:
                    entries.append(parsed)
    for key, value in data.items():
        if not isinstance(value, dict) or not isinstance(key, str):
            continue
        identifiers = collect_cves(key)
        if not identifiers:
            continue
        entries.append(
            (
                identifiers,
                Advisory(
                    source="advisory",
                    name=str(value.get("name") or key),
                    summary=str(value.get("summary") or value.get("description") or "")[:280],
                    severity=_severity(value.get("severity")),
                    known_exploited=bool(value.get("known_exploited")),
                    published=str(value.get("published") or ""),
                    url=str(value.get("url") or ""),
                ),
            )
        )
    return entries


def _entry_from_dict(item: dict[str, Any]) -> tuple[list[str], Advisory] | None:
    if "cveID" in item:
        return _kev_entry(item)
    if "id" in item and ("aliases" in item or "summary" in item):
        return _osv_entry(item)
    identifiers = collect_cves(item.get("cve") or item.get("id") or item.get("name"))
    if not identifiers:
        return None
    return identifiers, Advisory(
        source="advisory",
        name=str(item.get("name") or identifiers[0]),
        summary=str(item.get("summary") or item.get("description") or "")[:280],
        severity=_severity(item.get("severity")),
        known_exploited=bool(item.get("known_exploited")),
        published=str(item.get("published") or ""),
        url=str(item.get("url") or ""),
    )


def load_advisories(
    paths: list[Path],
) -> tuple[dict[str, list[Advisory]], list[dict[str, Any]]]:
    """Load advisory files or directories into a deterministic CVE index."""
    index: dict[str, list[Advisory]] = {}
    summaries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for supplied in paths:
        path = Path(supplied)
        files = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for file_path in files:
            data = _read_json(file_path)
            count = 0
            for identifiers, advisory in _iter_entries(data):
                identity = (advisory.source, advisory.name, advisory.summary)
                if identity in seen:
                    continue
                seen.add(identity)
                count += 1
                for cve in identifiers:
                    index.setdefault(cve, []).append(advisory)
            summaries.append(
                {"file": file_path.name, "entries": count, "source": "advisory-db"}
            )
    for cve in index:
        index[cve].sort(key=lambda item: (item.source, item.name))
    summaries.sort(key=lambda item: (item["file"], item["source"]))
    return index, summaries


def apply_advisories(findings: list[Finding], index: dict[str, list[Advisory]]) -> int:
    """Corroborate CVE-bearing findings and raise confidence/severity where justified."""
    updated = 0
    for finding in findings:
        cves = collect_cves([finding.metadata.get("cves"), finding.message])
        if not cves:
            continue
        matches: list[dict[str, Any]] = []
        for cve in cves:
            for advisory in index.get(cve, []):
                matches.append(
                    {
                        "cve": cve,
                        "source": advisory.source,
                        "name": advisory.name,
                        "severity": advisory.severity,
                        "known_exploited": advisory.known_exploited,
                        "ransomware": advisory.ransomware,
                        "published": advisory.published,
                        "url": advisory.url,
                    }
                )
        if not matches:
            continue
        sources = sorted({str(match["source"]) for match in matches})
        known_exploited = any(bool(match["known_exploited"]) for match in matches)
        severity_values = [match["severity"] for match in matches if match["severity"]]
        advisory_severity = max(
            severity_values, key=lambda value: SEVERITY_RANK.get(str(value), 0)
        ) if severity_values else None
        finding.metadata["advisories"] = matches[:8]
        finding.metadata["validation"] = {
            "sources": sources,
            "known_exploited": known_exploited,
            "advisory_severity": advisory_severity,
        }
        if advisory_severity and SEVERITY_RANK.get(
            str(advisory_severity), 0
        ) > SEVERITY_RANK.get(finding.severity, 0):
            finding.severity = str(advisory_severity)
        if known_exploited:
            finding.severity = "critical"
            finding.confidence = max(finding.confidence, 0.98)
            note = "CISA KEV lists this CVE as known exploited."
        elif len(sources) >= 2:
            finding.confidence = max(finding.confidence, 0.97)
            note = f"Corroborated by {len(sources)} advisory sources."
        else:
            finding.confidence = max(finding.confidence, 0.9)
            note = f"Validated against {sources[0]}."
        if note not in finding.message:
            finding.message = f"{finding.message} {note}".strip()
        updated += 1
    return updated
