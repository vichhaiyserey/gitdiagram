from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.ast_index import index_file, index_repo
from secdiagram_core.cli import main
from secdiagram_core.discover import discover


def _write(root: Path, rel_path: str, text: str) -> None:
    target = root / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _sample_repo(root: Path) -> None:
    _write(root, "app/__init__.py", "")
    _write(
        root,
        "app/main.py",
        "from app.service import load\n\n\ndef handler(name: str) -> str:\n    return load(name)\n",
    )
    _write(
        root,
        "app/service.py",
        "def load(name: str) -> str:\n    return name.strip()\n",
    )
    _write(root, "app/models.py", "class User:\n    def __init__(self, name: str) -> None:\n        self.name = name\n")
    _write(root, "src/util.py", "def helper(value: int) -> int:\n    return value + 1\n")
    _write(
        root,
        "java/src/main/java/demo/Greeter.java",
        "package demo;\n\npublic class Greeter {\n    public String greet(String name) {\n        return name;\n    }\n}\n",
    )
    _write(
        root,
        "java/src/main/java/demo/Service.java",
        "package demo;\n\npublic class Service {\n    private Greeter greeter;\n    public String run() {\n        return greeter.greet(\"x\");\n    }\n}\n",
    )


class ScaleTests(unittest.TestCase):
    def test_parallel_matches_serial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _sample_repo(root)
            serial = run_analysis(AnalysisConfig(root=root, jobs=1))
            parallel = run_analysis(AnalysisConfig(root=root, jobs=2))
            self.assertEqual(serial.graph.to_dict(), parallel.graph.to_dict())
            self.assertEqual(serial.parse_errors, parallel.parse_errors)

    def test_cache_hits_second_run_and_reuses_across_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            cache = Path(tmp) / "cache"
            _sample_repo(root)
            config = AnalysisConfig(root=root, jobs=1, cache_dir=cache)
            first = run_analysis(config)
            second = run_analysis(config)
            self.assertEqual(first.graph.to_dict(), second.graph.to_dict())
            self.assertGreater(first.cache_stats["python"]["misses"], 0)
            self.assertGreater(second.cache_stats["python"]["hits"], 0)
            self.assertGreater(second.cache_stats["java"]["hits"], 0)
            self.assertTrue(any(cache.rglob("*.json")))

            _write(root, "app/extra.py", "def added(value: int) -> int:\n    return value * 2\n")
            third = run_analysis(config)
            self.assertEqual(third.cache_stats["python"]["misses"], 1)
            self.assertEqual(third.cache_stats["python"]["hits"], first.cache_stats["python"]["misses"])
            self.assertNotEqual(first.graph.to_dict(), third.graph.to_dict())

    def test_identical_content_at_different_paths_gets_independent_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            cache = Path(tmp) / "cache"
            _write(root, "a/twin_one.py", "def twin() -> int:\n    return 1\n")
            _write(root, "a/twin_two.py", "def twin() -> int:\n    return 1\n")
            config = AnalysisConfig(root=root, jobs=1, cache_dir=cache)
            first = run_analysis(config)
            second = run_analysis(config)
            self.assertEqual(first.cache_stats["python"]["misses"], 2)
            self.assertEqual(second.cache_stats["python"]["hits"], 2)
            self.assertEqual(second.cache_stats["python"]["misses"], 0)

    def test_cache_inside_repository_is_not_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _sample_repo(root)
            cache = root / "cacheout"
            config = AnalysisConfig(root=root, jobs=1, cache_dir=cache)
            first = run_analysis(config)
            second = run_analysis(config)
            self.assertEqual(first.repo.rel_files, second.repo.rel_files)
            self.assertEqual(first.graph.to_dict(), second.graph.to_dict())
            self.assertTrue(any(cache.rglob("*.json")))

    def test_corrupt_cache_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            cache = Path(tmp) / "cache"
            _sample_repo(root)
            config = AnalysisConfig(root=root, jobs=1, cache_dir=cache)
            baseline = run_analysis(config)
            for entry in cache.rglob("*.json"):
                entry.write_text("{not-json", encoding="utf-8")
            recovered = run_analysis(config)
            self.assertEqual(baseline.graph.to_dict(), recovered.graph.to_dict())

    def test_parallel_index_repo_has_stable_order_and_payload_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _sample_repo(root)
            files = discover(root).python_files
            serial = index_repo(root, list(reversed(files)), jobs=1)
            parallel = index_repo(root, files, jobs=2)
            self.assertEqual(list(serial), sorted(files))
            self.assertEqual(list(parallel), sorted(files))
            for path in sorted(files):
                self.assertEqual(serial[path].to_payload(), parallel[path].to_payload())
                for imported in serial[path].imports:
                    for name, alias in imported.names:
                        self.assertIsInstance(name, str)
                        self.assertTrue(alias is None or isinstance(alias, str))

    def test_vendored_and_generated_code_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, "app/main.py", "x = 1\n")
            _write(root, "vendor/lib.py", "x = 1\n")
            _write(root, "Vendor/Other.py", "x = 1\n")
            _write(root, "third_party/dep.py", "x = 1\n")
            _write(root, "third-party/dep.py", "x = 1\n")
            _write(root, "generated/model.py", "x = 1\n")
            _write(root, "coverage/html/app.js", "x = 1\n")
            _write(root, "pkg/models_pb2.py", "x = 1\n")
            _write(root, "pkg/code_generated.py", "x = 1\n")
            _write(root, "pkg/normal.py", "x = 1\n")
            _write(root, "web/app.min.js", "x = 1\n")
            discovered = discover(root)
            self.assertIn("app/main.py", discovered.rel_files)
            self.assertIn("pkg/normal.py", discovered.rel_files)
            for excluded in (
                "vendor/lib.py",
                "Vendor/Other.py",
                "third_party/dep.py",
                "third-party/dep.py",
                "generated/model.py",
                "coverage/html/app.js",
                "pkg/models_pb2.py",
                "pkg/code_generated.py",
                "web/app.min.js",
            ):
                self.assertNotIn(excluded, discovered.rel_files)

    def test_oversized_source_is_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.py"
            path.write_text("x = 1\n", encoding="utf-8")
            with mock.patch("secdiagram_core.ast_index.MAX_SOURCE_BYTES", 4):
                index = index_file(Path(tmp), "big.py")
            self.assertIsNotNone(index.error)
            self.assertIn("exceeds", index.error or "")

    def test_cli_cache_and_jobs_flags_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _sample_repo(root)
            out = Path(tmp) / "out"
            cache = Path(tmp) / "cache"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "--dir",
                        str(root),
                        "--out",
                        str(out),
                        "--format",
                        "json",
                        "--jobs",
                        "2",
                        "--cache-dir",
                        str(cache),
                        "--quiet",
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            payload = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertGreater(payload["meta"]["files_discovered"], 0)
            self.assertTrue(any(cache.rglob("*.json")))


if __name__ == "__main__":
    unittest.main()
