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

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.model import Finding, Graph, Loc
from secdiagram_core.render_security import (
    render_security_html,
    render_security_markdown,
)
from secdiagram_core.security_report import build_security_report

try:
    from .support import FIXTURE, fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE, fixture_result
    except (ImportError, ValueError):
        from support import FIXTURE, fixture_result


def _meta(result) -> dict:
    graph = result.graph
    return {
        "name": result.repo.name,
        "commit": result.repo.commit,
        "branch": result.repo.branch,
        "dirty": result.repo.dirty,
        "python_files": result.python_files,
        "java_files": result.java_files,
        "iac_files": graph.meta.get("iac_files", 0),
        "files_discovered": graph.meta.get("files_discovered", 0),
        "files_skipped": graph.meta.get("files_skipped", 0),
        "languages": graph.meta.get("languages", {}),
        "unsupported_security_languages": graph.meta.get(
            "unsupported_security_languages", []
        ),
        "analysis": graph.meta.get("analysis", {}),
        "config_hash": graph.meta.get("config_hash"),
        "security_enabled": True,
        "finding_confidence_floor": 0.0,
    }


class SecurityReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = fixture_result()
        cls.meta = _meta(cls.result)

    def test_markdown_and_html_are_deterministic_and_ascii(self) -> None:
        first = build_security_report(
            self.result.graph, self.meta, fail_on="high", reproduce="secdiagram --dir ."
        )
        second = build_security_report(
            self.result.graph, self.meta, fail_on="high", reproduce="secdiagram --dir ."
        )
        markdown = render_security_markdown(first)
        html = render_security_html(first)
        self.assertEqual(markdown, render_security_markdown(second))
        self.assertEqual(html, render_security_html(second))
        self.assertTrue(markdown.isascii())
        self.assertTrue(html.isascii())
        self.assertIn("## Executive summary", markdown)
        self.assertIn("## Attack surface", markdown)
        self.assertIn("## Evidence appendix", markdown)
        self.assertIn("## Reproducibility", markdown)
        self.assertIn("Possible command injection", markdown)
        self.assertIn("app/service.py:16", markdown)
        self.assertNotIn("<script", html.lower())
        self.assertIn("Known limitations", html)

    def test_gate_and_risk_are_explainable(self) -> None:
        report = build_security_report(self.result.graph, self.meta, fail_on="critical")
        self.assertEqual(report.gate.verdict, "FAIL")
        self.assertEqual(report.risk.new_count, len(report.new_findings))
        self.assertGreater(report.risk.index, 0)
        self.assertIn("20*critical", report.risk.formula)
        self.assertEqual(
            report.risk.by_severity["critical"] + report.risk.by_severity["high"],
            sum(
                1
                for finding in report.new_findings
                if finding.severity in {"critical", "high"}
            ),
        )
        text = render_security_markdown(report)
        self.assertIn("Risk index formula:", text)
        self.assertIn("FAIL", text)

    def test_risk_weights_are_transparent(self) -> None:
        graph = Graph()
        graph.findings = [
            Finding(
                id="a",
                category="sql",
                severity="critical",
                title="critical",
                message="critical",
                evidence=[Loc("app.py", 1)],
                confidence=0.9,
            ),
            Finding(
                id="b",
                category="crypto",
                severity="high",
                title="high",
                message="high",
                evidence=[Loc("app.py", 2)],
                confidence=0.9,
            ),
            Finding(
                id="c",
                category="secret",
                severity="medium",
                title="medium",
                message="medium",
                evidence=[Loc("app.py", 3)],
                confidence=0.9,
            ),
        ]
        report = build_security_report(graph, {"name": "demo", "security_enabled": True})
        self.assertEqual(report.risk.weighted, 31.0)
        self.assertEqual(report.risk.index, 31)
        self.assertEqual(report.risk.label, "High")
        self.assertEqual(report.remediation[0].finding_ids, ["a", "b"])
        self.assertEqual(report.remediation[-1].finding_ids, ["c"])

    def test_baseline_findings_are_excluded_from_risk_but_listed(self) -> None:
        graph = Graph()
        known = Finding(
            id="known",
            category="sql",
            severity="critical",
            title="known",
            message="known",
            evidence=[Loc("app.py", 10)],
        )
        new = Finding(
            id="new",
            category="command",
            severity="high",
            title="new",
            message="new",
            evidence=[Loc("app.py", 11)],
        )
        known.baseline = True
        graph.findings = [known, new]
        meta = {
            "name": "demo",
            "security_enabled": True,
            "security_baseline": {"file": "security.baseline.json", "known": 1, "new": 1},
        }
        report = build_security_report(graph, meta)
        self.assertEqual(report.risk.new_count, 1)
        self.assertEqual(report.risk.baselined_count, 1)
        self.assertEqual(report.risk.by_severity["critical"], 0)
        self.assertEqual(report.risk.by_severity["high"], 1)
        text = render_security_markdown(report)
        self.assertIn("Baseline-suppressed findings", text)
        self.assertIn("`known`", text)

    def test_empty_repository_is_honest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# empty\n", encoding="utf-8")
            result = run_analysis(AnalysisConfig(root=root))
            report = build_security_report(result.graph, _meta(result), fail_on="high")
        self.assertEqual(report.risk.index, 0)
        self.assertEqual(report.gate.verdict, "PASS")
        text = render_security_markdown(report)
        self.assertIn("No new findings were identified", text)
        self.assertIn("not proof", text)

    def test_disabled_security_is_not_reported_as_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "import subprocess\nsubprocess.call('id', shell=True)\n",
                encoding="utf-8",
            )
            result = run_analysis(AnalysisConfig(root=root, security=False))
            report = build_security_report(
                result.graph,
                {**_meta(result), "security_enabled": False},
                fail_on="high",
            )
        self.assertEqual(report.gate.verdict, "N/A")
        self.assertEqual(report.risk.index, 0)
        text = render_security_markdown(report)
        self.assertIn("Security analysis was disabled", text)
        self.assertIn("must not be interpreted as a clean security assessment", text)

    def test_html_escapes_untrusted_repository_name(self) -> None:
        meta = dict(self.meta)
        meta["name"] = '<script>alert("x")</script>'
        report = build_security_report(self.result.graph, meta)
        html = render_security_html(report)
        self.assertNotIn('<script>alert("x")</script>', html)
        self.assertIn("&lt;script&gt;", html)

    def test_external_provenance_and_validation_are_rendered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")
            (root / "package-lock.json").write_text(
                json.dumps({"name": "demo", "lockfileVersion": 3}), encoding="utf-8"
            )
            xray = root / "xray.json"
            xray.write_text(
                json.dumps(
                    {
                        "violations": [
                            {
                                "id": "XRAY-1",
                                "component": "npm://lodash:4.17.20",
                                "severity": "High",
                                "summary": "Prototype pollution",
                                "cves": ["CVE-2021-23337"],
                                "fixed_versions": ["4.17.21"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            kev = root / "kev.json"
            kev.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2021-23337",
                                "vulnerabilityName": "Lodash issue",
                                "knownRansomwareCampaignUse": "Unknown",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = run_analysis(
                AnalysisConfig(root=root, xray_report=xray, advisory_dbs=[kev])
            )
            report = build_security_report(
                result.graph, {**_meta(result), "security_enabled": True}
            )
        text = render_security_markdown(report)
        html = render_security_html(report)
        self.assertIn("CVE-2021-23337", text)
        self.assertIn("4.17.21", text)
        self.assertIn("cisa-kev", text)
        self.assertIn("Known exploited", text)
        self.assertIn("JFrog Xray", text)
        self.assertIn("xray.json", text)
        self.assertIn("kev.json", html)

    def test_cli_writes_security_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "--dir",
                        str(FIXTURE),
                        "--out",
                        str(out),
                        "--format",
                        "sarif",
                        "--security-report",
                        "both",
                        "--quiet",
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            md_path = out / "SECURITY_REVIEW.md"
            html_path = out / "security-report.html"
            self.assertTrue(md_path.exists())
            self.assertTrue(html_path.exists())
            self.assertTrue((out / "security.sarif").exists())
            self.assertTrue(md_path.read_text(encoding="utf-8").isascii())
            self.assertFalse("<script" in html_path.read_text(encoding="utf-8").lower())

    def test_cli_security_report_requires_selection(self) -> None:
        parser_error = 2
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                main(["--dir", str(FIXTURE), "--security-report", "pdf"])
        self.assertEqual(caught.exception.code, parser_error)


if __name__ == "__main__":
    unittest.main()
