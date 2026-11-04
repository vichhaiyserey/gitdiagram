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

from secdiagram_core.baseline import (
    apply_baseline,
    finding_fingerprint,
    ignore_baseline,
    load_baseline,
    write_baseline,
)
from secdiagram_core.model import SEVERITY_RANK, Finding, Graph, Loc

try:
    from .support import fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import fixture_result
    except (ImportError, ValueError):
        from support import fixture_result


def _finding(fid: str, *, severity: str = "high", path: str = "a.py", line: int = 1) -> Finding:
    return Finding(
        id=fid,
        category="sql",
        severity=severity,
        title="Tainted query",
        message="demo",
        evidence=[Loc(path, line)],
    )


class BaselineUnitTests(unittest.TestCase):
    def _graph(self, *findings: Finding) -> Graph:
        graph = Graph()
        graph.findings = list(findings)
        return graph

    def test_fingerprint_is_stable_id(self) -> None:
        finding = _finding("abc123")
        self.assertEqual(finding_fingerprint(finding), "abc123")
        other = fixture_result().graph.sorted_findings()[0]
        self.assertEqual(finding_fingerprint(other), other.id)
        self.assertEqual(finding_fingerprint(other), finding_fingerprint(other))

    def test_write_baseline_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            g = fixture_result().graph
            first = root / "first.json"
            second = root / "second.json"
            count = write_baseline(g, first)
            count2 = write_baseline(g, second)
            self.assertEqual(count, count2)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            payload = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "1")
            self.assertEqual(payload["tool"], "secdiagram")
            ids = [record["id"] for record in payload["findings"]]
            self.assertEqual(ids, sorted(finding.id for finding in g.sorted_findings()))
            self.assertTrue(ids)
            for record in payload["findings"]:
                self.assertIn(record["severity"], SEVERITY_RANK)
                self.assertIn("path", record)
                self.assertIn("line", record)

    def test_load_baseline_round_trip_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security.baseline.json"
            graph = self._graph(_finding("f1", line=3), _finding("f2", line=9))
            self.assertEqual(write_baseline(graph, path), 2)
            ids = load_baseline(path)
            self.assertEqual(ids, {"f1", "f2"})

            missing = Path(tmp) / "nope.json"
            with self.assertRaises(FileNotFoundError):
                load_baseline(missing)

            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(bad)

            stale = Path(tmp) / "stale.json"
            stale.write_text(json.dumps({"schema_version": "999"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(stale)

    def test_apply_baseline_marks_known_findings(self) -> None:
        graph = self._graph(_finding("known", line=2), _finding("fresh", line=7))
        known, new = apply_baseline(graph, {"known"}, "baseline.json")
        self.assertEqual((known, new), (1, 1))
        flagged = {finding.id: finding.baseline for finding in graph.findings}
        self.assertEqual(flagged, {"known": True, "fresh": False})
        info = graph.meta["security_baseline"]
        self.assertEqual(info, {"file": "baseline.json", "known": 1, "new": 1, "total": 2})

    def test_ignore_baseline(self) -> None:
        graph = self._graph(_finding("f1"), _finding("f2"))
        ignore_baseline(graph, "baseline.json")
        self.assertFalse(any(finding.baseline for finding in graph.findings))
        self.assertEqual(
            graph.meta["security_baseline"], {"file": "baseline.json", "known": 0, "new": 2, "total": 2}
        )


class BaselineCliTests(unittest.TestCase):
    def _run(self, args: list[str]) -> tuple[int, str, str]:
        from secdiagram_core.cli import main

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    FLAG_ARGS = ["--format", "json,md,sarif", "--fail-on", "medium"]

    def test_create_then_baseline_passes_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            run_args = ["--dir", str(Path(__file__).resolve().parent / "fixtures" / "sample_app"), "--out", str(out)] + self.FLAG_ARGS

            code, _, _ = self._run(run_args + ["--quiet"])
            self.assertEqual(code, 2, "medium findings exist without a baseline")

            code, _, stderr = self._run(run_args + ["--create-baseline", "--quiet"])
            self.assertEqual(code, 0, "creating the baseline clears the gate")
            self.assertIn("created baseline", stderr)
            baseline_path = out / "security.baseline.json"
            self.assertTrue(baseline_path.exists())

            code, _, stderr = self._run(run_args + ["--baseline", str(baseline_path), "--quiet"])
            self.assertEqual(code, 0, "known findings are suppressed by the baseline")
            self.assertIn("suppresses", stderr)

            sarif = json.loads((out / "security.sarif").read_text(encoding="utf-8"))
            results = sarif["runs"][0]["results"]
            self.assertTrue(results)
            self.assertTrue(all(result.get("baselineState") == "unchanged" for result in results))
            self.assertTrue(all(result.get("suppressions") for result in results))
            self.assertIn("baselineState", sarif["runs"][0]["results"][0])
            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertTrue(graph["findings"])
            self.assertTrue(all(finding.get("baseline") is True for finding in graph["findings"]))
            self.assertIn("security_baseline", graph["meta"])

            md = (out / "ARCHITECTURE.md").read_text(encoding="utf-8")
            self.assertIn("security.baseline.json", md)
            self.assertIn("nothing new to review", md)

    def test_baseline_filters_only_known_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            run_args = ["--dir", str(Path(__file__).resolve().parent / "fixtures" / "sample_app"), "--out", str(out)]
            self._run(run_args + ["--create-baseline", "--quiet"])
            baseline_path = out / "security.baseline.json"

            payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            total = len(payload["findings"])
            critical = [record for record in payload["findings"] if record["severity"] == "critical"]
            self.assertTrue(critical)
            keep = [record for record in payload["findings"] if record["id"] != critical[0]["id"]]
            baseline_path.write_text(
                json.dumps({"schema_version": "1", "tool": "secdiagram", "findings": keep}),
                encoding="utf-8",
            )

            gate_args = run_args + ["--fail-on", "critical"]
            code, _, stderr = self._run(gate_args + ["--baseline", str(baseline_path), "--quiet"])
            self.assertEqual(code, 2, "the critical finding left out of the baseline must fail the gate")
            self.assertIn("1 new", stderr)

            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            info = graph["meta"]["security_baseline"]
            self.assertEqual(info["known"], total - 1)
            self.assertEqual(info["new"], 1)
            new_ids = [finding["id"] for finding in graph["findings"] if not finding.get("baseline")]
            self.assertEqual(new_ids, [critical[0]["id"]])
            md = (out / "ARCHITECTURE.md").read_text(encoding="utf-8")
            self.assertIn(f"**{total - 1}** known", md)
            self.assertIn("**1** new", md)

    def test_missing_and_malformed_baseline_warn_without_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            run_args = [
                "--dir",
                str(Path(__file__).resolve().parent / "fixtures" / "sample_app"),
                "--out",
                str(out),
                "--fail-on",
                "critical",
            ]
            code, _, stderr = self._run(run_args + ["--baseline", "missing.json", "--quiet"])
            self.assertEqual(code, 2)
            self.assertIn("not found", stderr)

            bad = root / "bad.json"
            bad.write_text("[]", encoding="utf-8")
            code, _, stderr = self._run(run_args + ["--baseline", str(bad), "--quiet"])
            self.assertEqual(code, 2)
            self.assertIn("malformed", stderr)
            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertFalse(any(finding.get("baseline") for finding in graph["findings"]))

    def test_baseline_off_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, stdout, _ = self._run(
                [
                    "--dir",
                    str(Path(__file__).resolve().parent / "fixtures" / "sample_app"),
                    "--out",
                    str(out),
                    "--format",
                    "json",
                    "--quiet",
                ]
            )
            self.assertEqual(code, 0)
            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertNotIn("security_baseline", graph["meta"])
            self.assertFalse(any(finding.get("baseline") for finding in graph["findings"]))
            self.assertNotIn("in baseline, 0 known", stdout)


if __name__ == "__main__":
    unittest.main()
