from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXACT_PIN = re.compile(r"[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[0-9][^\s]*")
SHA_PIN = re.compile(r"[^@\s]+@[0-9a-f]{40}")
DIGEST_PIN = re.compile(r"[^@\s]+:[\w.-]+@sha256:[0-9a-f]{64}")


class SupplyChainPinTests(unittest.TestCase):
    def test_python_dependencies_are_exact_pins(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        build = re.search(r"\[build-system\](.*?)(?:\n\[|\Z)", text, re.S)
        self.assertIsNotNone(build)
        requires_block = re.search(r"requires\s*=\s*\[(.*?)\]", build.group(1), re.S)
        self.assertIsNotNone(requires_block)
        build_requires = re.findall(r'"([^"]+)"', requires_block.group(1))
        self.assertTrue(build_requires)
        for requirement in build_requires:
            self.assertRegex(requirement.split(";", 1)[0].strip(), EXACT_PIN)

        dev = re.search(r"dev\s*=\s*\[(.*?)\n\]", text, re.S)
        self.assertIsNotNone(dev)
        dev_requires = re.findall(r'"([^"]+)"', dev.group(1))
        self.assertTrue(dev_requires)
        for requirement in dev_requires:
            self.assertRegex(requirement.split(";", 1)[0].strip(), EXACT_PIN)

    def test_github_actions_are_commit_pinned(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for workflow in workflows:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                if "uses:" not in line:
                    continue
                reference = line.split("uses:", 1)[1].split("#", 1)[0].strip()
                self.assertRegex(reference, SHA_PIN, f"{workflow.name}: {line.strip()}")

    def test_container_images_are_digest_pinned(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        self.assertTrue(from_lines)
        for line in from_lines:
            self.assertRegex(line.split()[1], DIGEST_PIN, line)

        for name in ("docker-compose.yml", "docker-compose.ollama.yml"):
            text = (ROOT / name).read_text(encoding="utf-8")
            images = re.findall(r"^\s*image:\s*(\S+)", text, re.M)
            for image in images:
                if image.startswith("secdiagram:"):
                    continue
                self.assertRegex(image, DIGEST_PIN, f"{name}: {image}")

    def test_mermaid_cli_uses_committed_lockfile(self) -> None:
        lock_path = ROOT / "docker" / "mermaid" / "package-lock.json"
        self.assertTrue(lock_path.exists())
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        self.assertEqual(lock["packages"][""]["dependencies"]["@mermaid-js/mermaid-cli"], "12.2.0")
        for name, package in lock["packages"].items():
            if not name:
                continue
            self.assertTrue(package.get("integrity"), name)
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("npm ci --omit=dev", dockerfile)
        self.assertNotIn("npm install -g", dockerfile)


if __name__ == "__main__":
    unittest.main()
