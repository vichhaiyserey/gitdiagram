from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import secdiagram_core.cli as cli
from secdiagram_core.high_level import build_high_level_architecture, render_mermaid_highlevel
from secdiagram_core.model import Finding, Graph, Loc, Node
from secdiagram_core.render_html import MERMAID_CDN, MERMAID_STUB_FALLBACK, render_html
from secdiagram_core.render_mermaid import render_mermaid

try:
    from .support import FIXTURE, fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE, fixture_result
    except (ImportError, ValueError):
        from support import FIXTURE, fixture_result


DATA_MARKER = re.compile(
    r'<script id="gd-data" type="application/json">(.*?)</script>', re.DOTALL
)


def _payload(html_text: str) -> dict:
    match = DATA_MARKER.search(html_text)
    if not match:
        raise AssertionError("embedded report payload not found")
    return json.loads(match.group(1))


class HtmlReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = fixture_result()
        cls.graph = cls.result.graph
        cls.meta = {
            "name": cls.result.repo.name,
            "commit": cls.result.repo.commit,
            "branch": cls.result.repo.branch,
            "dirty": cls.result.repo.dirty,
            "analysis": cls.graph.meta.get("analysis", {}),
        }
        cls.hla = build_high_level_architecture(FIXTURE, cls.graph)
        cls.hlm = render_mermaid_highlevel(cls.hla)
        cls.dlm = render_mermaid(cls.graph)
        cls.html_text = render_html(
            cls.graph,
            cls.meta,
            hla=cls.hla,
            highlevel_mermaid=cls.hlm,
            detail_mermaid=cls.dlm,
            root=FIXTURE,
        )

    def test_is_complete_self_contained_document(self) -> None:
        self.assertTrue(self.html_text.startswith("<!DOCTYPE html>"))
        self.assertTrue(self.html_text.rstrip().endswith("</html>"))
        # No external asset references: css is inline, only the mermaid script may be remote.
        self.assertNotIn("<link rel", self.html_text)
        self.assertNotIn("fonts.googleapis", self.html_text)

    def test_deterministic_output(self) -> None:
        second = render_html(
            self.graph,
            self.meta,
            hla=self.hla,
            highlevel_mermaid=self.hlm,
            detail_mermaid=self.dlm,
            root=FIXTURE,
        )
        self.assertEqual(self.html_text, second)

    def test_embedded_payload_matches_analysis(self) -> None:
        payload = _payload(self.html_text)
        self.assertEqual(payload["meta"]["name"], "sample_app")
        self.assertEqual(payload["summary"]["node_count"], len(self.graph.nodes))
        self.assertEqual(payload["summary"]["edge_count"], len(self.graph.edges))
        self.assertEqual(len(payload["nodes"]), len(self.graph.nodes))
        self.assertEqual(len(payload["edges"]), len(self.graph.edges))
        self.assertEqual(len(payload["findings"]), len(self.graph.findings))
        self.assertEqual(len(payload["features"]), len(self.graph.features))
        self.assertTrue(payload["subsystems"])
        self.assertTrue(payload["diagram"]["highlevel"].startswith("%% High-Level"))
        severities = payload["summary"]["severities"]
        self.assertEqual(sum(severities.values()), len(self.graph.findings))

    def test_finding_snippets_and_ui_sections(self) -> None:
        payload = _payload(self.html_text)
        self.assertEqual(payload["meta"]["tool"], "secdiagram")
        for section in (
            "Security and IaC findings",
            "Security posture",
            "Subsystem architecture",
            "Data quality and methodology",
            "Edge resolution distribution",
        ):
            self.assertIn(section, self.html_text)
        self.assertIn(MERMAID_STUB_FALLBACK[:32], self.html_text)
        snippet_rows = [f for f in payload["findings"] if f.get("snippet")]
        self.assertTrue(snippet_rows)
        first = snippet_rows[0]["snippet"]["lines"]
        self.assertTrue(all(isinstance(row[0], int) for row in first))

    def test_offline_mode_omits_cdn(self) -> None:
        html_text = render_html(self.graph, self.meta, offline=True)
        self.assertNotIn(MERMAID_CDN, html_text)

    def test_default_uses_pinned_cdn(self) -> None:
        self.assertIn(MERMAID_CDN, self.html_text)

    def test_inline_mermaid_bundle(self) -> None:
        html_text = render_html(self.graph, self.meta, mermaid_js="window.__stub=1;")
        self.assertIn("<script>window.__stub=1;</script>", html_text)

    def test_snippet_redacts_secrets(self) -> None:
        secret = "mock-secret-value-1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
            graph = Graph()
            graph.add_node(Node(id="n1", kind="module", name="app", qualname="app", path="app.py", line=1))
            graph.findings.append(
                Finding(
                    id="f1",
                    category="secret",
                    severity="high",
                    title="Possible hardcoded secret: api_key",
                    message="Credential-like assignment found at app.py:1.",
                    node_id="n1",
                    evidence=[Loc("app.py", 1)],
                )
            )
            html_text = render_html(graph, {"name": "secret_app"}, root=root)
            payload = _payload(html_text)
            snippet = payload["findings"][0]["snippet"]["lines"]
            rendered = json.dumps(snippet)
            self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED]", rendered)

    def test_payload_is_injection_safe(self) -> None:
        tricky = Graph()
        tricky.add_node(
            Node(id="n_bad", kind="module", name="<script>alert(1)</script>", qualname='mod."</svg>"')
        )
        tricky.add_edge(
            "n_bad",
            "n_bad",
            "calls",
            evidence=[Loc('<img src=x onerror="p">', 1)],
        )
        tricky.findings.append(
            Finding(
                id="f_bad",
                category="exploit",
                severity="critical",
                title='Bad "</script>"',
                message="<script>document.write(1)</script>",
                node_id="n_bad",
                recommendation="<b>patch</b>",
                evidence=[Loc("x.py", 1)],
            )
        )
        html_text = render_html(tricky, {"name": "<b>evil</b>"})
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertNotIn("</script>alert", html_text)
        self.assertNotIn("<img src=x onerror", html_text)
        payload = _payload(html_text)
        self.assertEqual(payload["nodes"][0]["name"], "<script>alert(1)</script>")
        self.assertEqual(payload["meta"]["name"], "<b>evil</b>")


class HtmlCliTests(unittest.TestCase):
    def _run_main(self, args: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_writes_report_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, _, _ = self._run_main(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "html", "--quiet"]
            )
            self.assertEqual(code, 0)
            report = out / "report.html"
            self.assertTrue(report.exists())
            text = report.read_text(encoding="utf-8")
            self.assertIn('id="gd-data"', text)
            self.assertIn("sample_app", text)
            payload = _payload(text)
            self.assertEqual(payload["meta"]["name"], "sample_app")

    def test_cli_html_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, _, _ = self._run_main(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "report", "--quiet"]
            )
            self.assertEqual(code, 0)
            self.assertTrue((out / "report.html").exists())

    def test_cli_mermaid_bundle_inline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            bundle = Path(tmp) / "mermaid.min.js"
            bundle.write_text("window.__gdBundle=1;", encoding="utf-8")
            code, _, _ = self._run_main(
                [
                    "--dir",
                    str(FIXTURE),
                    "--out",
                    str(out),
                    "--format",
                    "html",
                    "--quiet",
                    "--offline",
                    "--mermaid-js",
                    str(bundle),
                ]
            )
            self.assertEqual(code, 0)
            text = (out / "report.html").read_text(encoding="utf-8")
            self.assertIn("<script>window.__gdBundle=1;</script>", text)
            self.assertNotIn("cdn.jsdelivr.net", text)


if __name__ == "__main__":
    unittest.main()
