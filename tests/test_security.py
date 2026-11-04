from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from .support import fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import fixture_result
    except (ImportError, ValueError):
        from support import fixture_result


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = fixture_result()
        cls.graph = cls.result.graph
        cls.findings = cls.graph.findings
        cls.indexes = None

    def _find(self, category: str, title_contains: str = ""):
        return [
            finding
            for finding in self.findings
            if finding.category == category and title_contains.lower() in finding.title.lower()
        ]

    def test_tainted_findings_carry_source_to_sink_trace(self) -> None:
        command = self._find("command", "command injection")
        self.assertTrue(command)
        for finding in command:
            self.assertGreaterEqual(len(finding.trace), 2)
            self.assertEqual(finding.trace[-1].path, finding.evidence[0].path)
            self.assertEqual(finding.trace[-1].line, finding.evidence[0].line)

    def test_tainted_command_and_sql_are_critical(self) -> None:
        command = self._find("command", "command injection")
        self.assertTrue(command)
        self.assertTrue(all(item.severity == "critical" for item in command))
        sql = self._find("sql")
        self.assertTrue(sql)
        self.assertTrue(all(item.severity == "critical" for item in sql))

    def test_path_and_deserialization(self) -> None:
        self.assertTrue(self._find("path"))
        self.assertTrue(self._find("deserialization"))
        self.assertTrue(self._find("crypto"))

    def test_weak_hash_ignores_id_generation(self) -> None:
        result = fixture_result()
        weak = [
            finding
            for finding in result.graph.findings
            if finding.title == "Weak cryptographic hash"
            and finding.evidence[0].path == "app/service.py"
        ]
        self.assertTrue(weak)
        make_id = next(
            node for node in result.graph.nodes.values() if node.qualname == "app.service.make_id"
        )
        self.assertFalse(any(finding.evidence[0].line == make_id.line for finding in weak))

    def test_safe_yaml_is_not_flagged(self) -> None:
        from secdiagram_core.ast_index import index_repo
        from secdiagram_core.discover import discover

        repo = discover(self.result.repo.root)
        indexes = index_repo(repo.root, repo.python_files)
        safe_call = next(
            call
            for call in indexes["app/service.py"].calls
            if call.callee == "yaml.safe_load"
        )
        unsafe_call = next(
            call
            for call in indexes["app/service.py"].calls
            if call.callee == "yaml.load"
        )
        deserialization = self._find("deserialization")
        lines = {item.evidence[0].line for item in deserialization}
        self.assertNotIn(safe_call.line, lines)
        self.assertIn(unsafe_call.line, lines)

    def test_secrets(self) -> None:
        secrets = self._find("secret")
        titles = " | ".join(item.title for item in secrets)
        self.assertIn("API_KEY", titles)
        self.assertIn("PASSWORD", titles)
        self.assertTrue(any("env" in item.title.lower() for item in secrets))

    def test_iac_findings(self) -> None:
        categories = {finding.category for finding in self.findings}
        self.assertTrue({"container", "ci", "cloud", "supply-chain"} <= categories)
        titles = " | ".join(finding.title for finding in self.findings)
        self.assertIn("Container runs as root", titles)
        self.assertIn("Privileged container", titles)
        self.assertIn("Workflow grants write-all permissions", titles)
        self.assertIn("Unpinned GitHub Action", titles)
        self.assertIn("Security group open to the internet", titles)

    def test_env_is_not_treated_as_ssrf_source(self) -> None:
        self.assertFalse(self._find("network"))

    def test_findings_have_evidence_and_ids(self) -> None:
        ids = [finding.id for finding in self.findings]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(finding.evidence for finding in self.findings))
        self.assertTrue(all(finding.recommendation for finding in self.findings))

    def test_env_example_and_placeholders_ignored(self) -> None:
        import tempfile

        from secdiagram_core.analyzer import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / ".env.example").write_text("API_KEY=mock_secret_should_be_ignored\n", encoding="utf-8")
            (tmp_root / ".env").write_text("API_KEY=your_secret_here\nPASSWORD=changeme\n", encoding="utf-8")
            (tmp_root / "dummy.py").write_text("x = 1\n", encoding="utf-8")
            res = run_analysis(AnalysisConfig(root=tmp_root))
            secret_findings = [f for f in res.graph.findings if f.category == "secret"]
            self.assertEqual(len(secret_findings), 0)

    def test_tls_verification_disabled(self) -> None:
        import tempfile

        from secdiagram_core.analyzer import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "client.py").write_text(
                "import requests\ndef fetch():\n    return requests.get('https://example.com', verify=False)\n",
                encoding="utf-8",
            )
            res = run_analysis(AnalysisConfig(root=tmp_root))
            tls_findings = [f for f in res.graph.findings if "TLS verification disabled" in f.title]
            self.assertEqual(len(tls_findings), 1)
            self.assertEqual(tls_findings[0].severity, "high")
            self.assertEqual(tls_findings[0].cwe, "CWE-295")

    def test_secret_token_patterns(self) -> None:
        import tempfile

        from secdiagram_core.analyzer import AnalysisConfig, run_analysis
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            aws_prefix = "AK" + "IA"
            (tmp_root / "config.py").write_text(
                f"AWS_KEY = '{aws_prefix}1234567890ABCDEF'\nGH_TOKEN = 'ghp_' + 'a'*20\n",
                encoding="utf-8",
            )
            res = run_analysis(AnalysisConfig(root=tmp_root))
            token_findings = [f for f in res.graph.findings if f.category == "secret"]
            self.assertGreaterEqual(len(token_findings), 1)


if __name__ == "__main__":
    unittest.main()
