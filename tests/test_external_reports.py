from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.advisories import apply_advisories, load_advisories
from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.external_reports import (
    ExternalReportError,
    collect_cves,
    load_external_reports,
)
from secdiagram_core.llm import _compact
from secdiagram_core.render_sarif import render_sarif

SONAR = {
    "issues": [
        {
            "key": "AZ1",
            "rule": "python:S3649",
            "severity": "CRITICAL",
            "component": "demo:app.py",
            "line": 7,
            "message": "Make sure using a dynamically formatted SQL query is safe.",
            "type": "VULNERABILITY",
            "cwe": "cwe: CWE-89",
            "status": "OPEN",
            "tags": ["owasp-a03", "sql"],
            "textRange": {"startLine": 7},
        },
        {
            "key": "AZ2",
            "rule": "python:S1481",
            "severity": "MAJOR",
            "component": "demo:app.py",
            "line": 1,
            "message": "Unused variable",
            "type": "CODE_SMELL",
        },
        {
            "key": "AZ3",
            "rule": "python:S1",
            "severity": "MAJOR",
            "component": "demo:app.py",
            "line": 2,
            "message": "Already fixed",
            "type": "VULNERABILITY",
            "status": "CLOSED",
        },
        {
            "key": "AZ4",
            "rule": "python:S2",
            "severity": "HIGH",
            "component": "../../etc/passwd",
            "line": 1,
            "message": "Escaped path",
            "type": "VULNERABILITY",
        },
    ]
}

XRAY = {
    "data": {
        "violations": [
            {
                "id": "XRAY-1",
                "component": "npm://lodash:4.17.20",
                "severity": "High",
                "summary": "Prototype pollution in lodash",
                "cves": ["CVE-2021-23337"],
                "fixed_versions": ["4.17.21"],
                "references": ["https://example.invalid/CVE-2021-23337"],
            }
        ]
    }
}

KEV = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-23337",
            "vulnerabilityName": "Lodash command injection",
            "shortDescription": "Lodash before 4.17.21 is vulnerable.",
            "dateAdded": "2021-02-18",
            "knownRansomwareCampaignUse": "Unknown",
        }
    ]
}

OSV = {
    "vulns": [
        {
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command injection in lodash",
            "published": "2021-02-15T00:00:00Z",
        }
    ]
}


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _workspace() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    (root / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    _write(root / "package-lock.json", {"name": "demo", "lockfileVersion": 3})
    return tmp, root


class ExternalReportTests(unittest.TestCase):
    def test_sonarqube_normalization_skips_noise_and_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            report = _write(root / "sonar.json", SONAR)
            findings, summaries = load_external_reports(
                root, ["app.py"], sonarqube_report=report
            )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.source, "sonarqube")
        self.assertEqual(finding.external_id, "AZ1")
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.evidence[0].path, "app.py")
        self.assertEqual(finding.evidence[0].line, 7)
        self.assertEqual(summaries[0]["findings"], 1)

    def test_xray_normalization_maps_vulnerable_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "package-lock.json", {"name": "demo"})
            report = _write(root / "xray.json", XRAY)
            findings, _ = load_external_reports(
                root, ["package-lock.json"], xray_report=report
            )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.source, "xray")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.metadata["package"], "lodash")
        self.assertEqual(finding.metadata["version"], "4.17.20")
        self.assertEqual(finding.metadata["cves"], ["CVE-2021-23337"])
        self.assertEqual(finding.evidence[0].path, "package-lock.json")

    def test_advisory_validation_promotes_known_exploited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "package-lock.json", {"name": "demo"})
            kev = _write(root / "kev.json", KEV)
            osv = _write(root / "osv.json", OSV)
            report = _write(root / "xray.json", XRAY)
            findings, _ = load_external_reports(
                root, ["package-lock.json"], xray_report=report
            )
            index, summaries = load_advisories([kev, osv])
        updated = apply_advisories(findings, index)
        self.assertEqual(updated, 1)
        finding = findings[0]
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.confidence, 0.98)
        self.assertTrue(finding.metadata["validation"]["known_exploited"])
        self.assertIn("cisa-kev", finding.metadata["validation"]["sources"])
        self.assertEqual(len(summaries), 2)

    def test_single_osv_record_is_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            osv = _write(
                root / "osv-single.json",
                {
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "aliases": ["CVE-2021-23337"],
                    "summary": "Command injection in lodash",
                    "published": "2021-02-15T00:00:00Z",
                },
            )
            index, summaries = load_advisories([osv])
        self.assertIn("CVE-2021-23337", index)
        self.assertEqual(index["CVE-2021-23337"][0].source, "osv")
        self.assertEqual(summaries[0]["entries"], 1)

    def test_run_analysis_merges_reports_and_annotates_meta(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        sonar = _write(root / "sonar.json", SONAR)
        xray = _write(root / "xray.json", XRAY)
        kev = _write(root / "kev.json", KEV)
        result = run_analysis(
            AnalysisConfig(
                root=root,
                sonarqube_report=sonar,
                xray_report=xray,
                advisory_dbs=[kev],
            )
        )
        findings = [f for f in result.graph.findings if f.source != "secdiagram"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(result.graph.meta["advisory_validated_findings"], 1)
        self.assertEqual(result.graph.meta["external_reports"][0]["source"], "sonarqube")
        sarif = json.loads(render_sarif(result.graph))
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("sonarqube:external:CWE-89", rule_ids)
        self.assertIn("xray:external:", " ".join(rule_ids))
        validation = [
            rule["properties"]["validation"]
            for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
            if rule["id"].startswith("xray:")
        ]
        self.assertTrue(validation and validation[0]["known_exploited"])

    def test_compact_includes_provenance(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        xray = _write(root / "xray.json", XRAY)
        result = run_analysis(AnalysisConfig(root=root, xray_report=xray))
        compact = _compact(result.graph)
        rows = [row for row in compact["findings"] if row.get("source") == "xray"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["provenance"]["package"], "lodash")
        self.assertIn("external_reports", compact["meta"])

    def test_cli_imports_external_reports(self) -> None:
        tmp, root = _workspace()
        self.addCleanup(tmp.cleanup)
        out = root / "out"
        sonar = _write(root / "sonar.json", SONAR)
        xray = _write(root / "xray.json", XRAY)
        kev = _write(root / "kev.json", KEV)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(
                [
                    "--dir",
                    str(root),
                    "--out",
                    str(out),
                    "--format",
                    "json,sarif",
                    "--sonarqube-report",
                    str(sonar),
                    "--xray-report",
                    str(xray),
                    "--advisory-db",
                    str(kev),
                    "--quiet",
                ]
            )
        self.assertEqual(code, 0, stderr.getvalue())
        payload = json.loads((out / "graph.json").read_text(encoding="utf-8"))
        sources = sorted(
            finding.get("source", "secdiagram") for finding in payload["findings"]
        )
        self.assertIn("sonarqube", sources)
        self.assertIn("xray", sources)
        self.assertEqual(payload["meta"]["advisory_validated_findings"], 1)
        sarif = json.loads((out / "security.sarif").read_text(encoding="utf-8"))
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        self.assertIn("sonarqube:external:CWE-89", rule_ids)

    def test_cve_collection_is_sorted_and_deduplicated(self) -> None:
        self.assertEqual(
            collect_cves(
                {
                    "cves": ["cve-2021-23337", "CVE-2021-23337"],
                    "references": ["https://example.invalid/CVE-2020-8203"],
                }
            ),
            ["CVE-2020-8203", "CVE-2021-23337"],
        )

    def test_invalid_report_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ExternalReportError):
                load_external_reports(Path(tmp), [], sonarqube_report=path)
            with self.assertRaises(ExternalReportError):
                load_external_reports(Path(tmp), [], xray_report=path)


if __name__ == "__main__":
    unittest.main()
