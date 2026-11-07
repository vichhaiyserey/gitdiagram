from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.discover import discover

try:
    from .support import FIXTURE
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE
    except (ImportError, ValueError):
        from support import FIXTURE


class DiscoverTests(unittest.TestCase):
    def test_fixture_files_and_metadata(self) -> None:
        repo = discover(FIXTURE)
        self.assertFalse(repo.is_git)
        self.assertEqual(repo.name, "sample_app")
        self.assertIn("app/main.py", repo.rel_files)
        self.assertIn("Dockerfile", repo.rel_files)
        self.assertIn(".github/workflows/ci.yml", repo.rel_files)
        self.assertIn("k8s/deployment.yaml", repo.rel_files)
        self.assertNotIn("not_python.txt", repo.python_files)
        self.assertEqual(len(repo.python_files), 8)

    def test_dotenv_files_are_discovered(self) -> None:
        # Fixtures cannot commit .env (gitignored), so exercise discovery in a temp tree.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sample_app"
            (root / "app").mkdir(parents=True)
            (root / ".env").write_text("SAFE_SETTING=hello\n", encoding="utf-8")
            (root / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
            repo = discover(root)
            self.assertIn(".env", repo.rel_files)
            self.assertEqual(repo.name, "sample_app")

    def test_iac_classification(self) -> None:
        repo = discover(FIXTURE)
        iac = set(repo.iac_files)
        self.assertIn("Dockerfile", iac)
        self.assertIn("docker-compose.yml", iac)
        self.assertIn(".github/workflows/ci.yml", iac)
        self.assertIn("k8s/deployment.yaml", iac)
        self.assertIn("terraform/main.tf", iac)

    def test_include_and_exclude(self) -> None:
        included = discover(FIXTURE, include=["app/*.py"])
        self.assertTrue(included.rel_files)
        self.assertTrue(all(path.startswith("app/") for path in included.rel_files))
        excluded = discover(FIXTURE, exclude=["app/service.py", "app/broken.py"])
        self.assertNotIn("app/service.py", excluded.rel_files)
        self.assertNotIn("app/broken.py", excluded.rel_files)
        self.assertIn("app/main.py", excluded.rel_files)

    def test_cross_platform_backslash_globs(self) -> None:
        included = discover(FIXTURE, include=["app\\*.py"])
        self.assertTrue(included.rel_files)
        self.assertTrue(all(path.startswith("app/") for path in included.rel_files))

    def test_git_discovery_respects_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "tracked.py").write_text("x = 1\n", encoding="utf-8")
            (root / "untracked.py").write_text("y = 2\n", encoding="utf-8")
            (root / "ignored.py").write_text("z = 3\n", encoding="utf-8")
            (root / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
            repo = discover(root)
            self.assertTrue(repo.is_git)
            self.assertIn("tracked.py", repo.rel_files)
            self.assertIn("untracked.py", repo.rel_files)
            self.assertNotIn("ignored.py", repo.rel_files)

    def test_missing_directory_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            discover(FIXTURE / "does-not-exist")

    def test_symlink_outside_root_skipped(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as external_dir, tempfile.TemporaryDirectory() as repo_dir:
            secret = Path(external_dir) / "secret.txt"
            secret.write_text("classified", encoding="utf-8")
            repo = Path(repo_dir)
            symlink_py = repo / "symlinked.py"
            try:
                os.symlink(secret, symlink_py)
            except OSError:
                return  # OS does not support symlinks without elevated privileges

            info = discover(repo)
            self.assertNotIn("symlinked.py", info.rel_files)
            self.assertTrue(any("symlink outside root" in s for s in info.skipped))

    def test_git_symlink_outside_root_skipped(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as external_dir, tempfile.TemporaryDirectory() as repo_dir:
            secret = Path(external_dir) / "secret.txt"
            secret.write_text("classified", encoding="utf-8")
            repo = Path(repo_dir)
            try:
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
            except (OSError, subprocess.SubprocessError):
                return
            symlink_py = repo / "symlinked.py"
            try:
                os.symlink(secret, symlink_py)
            except OSError:
                return  # OS does not support symlinks without elevated privileges

            info = discover(repo)
            self.assertTrue(info.is_git)
            self.assertNotIn("symlinked.py", info.rel_files)
            self.assertTrue(any("symlink outside root" in s for s in info.skipped))


if __name__ == "__main__":
    unittest.main()
