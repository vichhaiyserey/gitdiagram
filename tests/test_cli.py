from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gitdiagram_core.cli import main

try:
    from .support import FIXTURE
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE
    except (ImportError, ValueError):
        from support import FIXTURE


class CliTests(unittest.TestCase):
    def _run(self, args: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_full_run_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, stdout, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "json,md,mermaid,sarif"]
            )
            self.assertEqual(code, 0)
            for name in ("graph.json", "ARCHITECTURE.md", "diagram.mmd", "security.sarif"):
                self.assertTrue((out / name).exists(), name)
            self.assertIn("wrote", stdout)
            payload = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertGreater(payload["meta"]["finding_count"], 0)

    def test_fail_on_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(Path(tmp) / "out"), "--quiet", "--fail-on", "critical"]
            )
            self.assertEqual(code, 2)

    def test_no_security(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, _, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "json", "--no-security", "--quiet"]
            )
            self.assertEqual(code, 0)
            payload = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["findings"], [])
            self.assertFalse((out / "security.sarif").exists())

    def test_missing_directory(self) -> None:
        code, _, stderr = self._run(["--dir", str(FIXTURE / "nope")])
        self.assertEqual(code, 1)
        self.assertIn("does not exist", stderr)

    def test_llm_without_key_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = {key: value for key, value in os.environ.items() if key not in {"OPENAI_API_KEY", "GITDIAGRAM_LLM_API_KEY"}}
            with mock.patch.dict(os.environ, env, clear=True):
                code, _, stderr = self._run(
                    [
                        "--dir",
                        str(FIXTURE),
                        "--out",
                        str(Path(tmp) / "out"),
                        "--format",
                        "json",
                        "--llm",
                        "--quiet",
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("no LLM key", stderr)

    def test_ollama_flag_writes_narrative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            fake_narrative = "# Qwen Architecture\nAnalyzed with Qwen 2.5."
            with mock.patch("gitdiagram_core.cli.generate_narrative", return_value=fake_narrative) as mock_gen:
                code, _, _ = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--ollama", "qwen2.5-coder", "--quiet"]
                )
            self.assertEqual(code, 0)
            self.assertTrue((out / "NARRATIVE.md").exists())
            self.assertEqual((out / "NARRATIVE.md").read_text(encoding="utf-8"), fake_narrative)
            mock_gen.assert_called_once()
            self.assertEqual(mock_gen.call_args[1]["model"], "qwen2.5-coder")
            self.assertEqual(mock_gen.call_args[1]["provider"], "ollama")

    def test_entrypoint_subprocess_and_determinism(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out1 = Path(tmp) / "one"
            out2 = Path(tmp) / "two"
            for out in (out1, out2):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "gitdiagram.py"),
                        "--dir",
                        str(FIXTURE),
                        "--out",
                        str(out),
                        "--format",
                        "json,md,mermaid",
                        "--quiet",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
            for name in ("graph.json", "ARCHITECTURE.md", "diagram.mmd"):
                self.assertEqual(
                    (out1 / name).read_bytes(),
                    (out2 / name).read_bytes(),
                    f"{name} is not deterministic",
                )


    def test_fail_on_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(Path(tmp) / "out"), "--quiet", "--fail-on", "CRITICAL"]
            )
            self.assertEqual(code, 2)

    def test_format_alias_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, _, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "markdown", "--quiet"]
            )
            self.assertEqual(code, 0)
            self.assertTrue((out / "ARCHITECTURE.md").exists())
            self.assertFalse((out / "graph.json").exists())

    def test_invalid_format_raises(self) -> None:
        with self.assertRaises(SystemExit):
            self._run(["--format", "invalid_format"])

    def test_quiet_suppresses_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code, stdout, _ = self._run(
                ["--dir", str(FIXTURE), "--out", str(out), "--format", "json", "--quiet"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(stdout.strip(), "")

    def test_image_flag_generates_diagram_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            dummy_png = b"\x89PNGdummy"

            def fake_render_image(mermaid_source, output_path, image_format="png", **kwargs):
                output_path.write_bytes(dummy_png)
                return output_path

            with mock.patch("gitdiagram_core.cli.render_image", side_effect=fake_render_image):
                code, stdout, _ = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--image"]
                )
            self.assertEqual(code, 0)
            self.assertTrue((out / "diagram.png").exists())
            self.assertTrue((out / "diagram.mmd").exists())
            self.assertEqual((out / "diagram.png").read_bytes(), dummy_png)
            self.assertIn("diagram.png", stdout)

    def test_image_svg_generates_diagram_svg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            dummy_svg = b"<svg>dummy</svg>"

            def fake_render_image(mermaid_source, output_path, image_format="svg", **kwargs):
                output_path.write_bytes(dummy_svg)
                return output_path

            with mock.patch("gitdiagram_core.cli.render_image", side_effect=fake_render_image):
                code, stdout, _ = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--image", "svg", "--quiet"]
                )
            self.assertEqual(code, 0)
            self.assertTrue((out / "diagram.svg").exists())
            self.assertEqual((out / "diagram.svg").read_bytes(), dummy_svg)

    def test_format_png_writes_diagram_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            dummy_png = b"\x89PNGpngformat"

            def fake_render_image(mermaid_source, output_path, image_format="png", **kwargs):
                output_path.write_bytes(dummy_png)
                return output_path

            with mock.patch("gitdiagram_core.cli.render_image", side_effect=fake_render_image):
                code, _, _ = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--format", "png", "--quiet"]
                )
            self.assertEqual(code, 0)
            self.assertTrue((out / "diagram.png").exists())
            self.assertFalse((out / "graph.json").exists())

    def test_image_render_error_returns_exit_1(self) -> None:
        from gitdiagram_core.render_image import ImageRenderError

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch(
                "gitdiagram_core.cli.render_image",
                side_effect=ImageRenderError("Network unreachable"),
            ):
                code, _, stderr = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--image", "--quiet"]
                )
            self.assertEqual(code, 1)
            self.assertIn("could not write output: Network unreachable", stderr)

    def test_normalize_cli_path_git_bash(self) -> None:
        from gitdiagram_core.cli import _normalize_cli_path

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with mock.patch("os.name", "posix"):
                fake_git_bash_path = f"C:/Program Files/Git/{tmp_path.name}"
                with mock.patch.object(Path, "exists", autospec=True) as mock_exists:
                    def fake_exists(p):
                        return str(p).endswith(tmp_path.name)
                    mock_exists.side_effect = fake_exists
                    resolved = _normalize_cli_path(fake_git_bash_path)
                    self.assertTrue(str(resolved).endswith(tmp_path.name))

    def test_llm_timeout_cli_arg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch("gitdiagram_core.cli.generate_narrative", return_value="# Mock Narrative") as mock_gen:
                code, _, _ = self._run(
                    ["--dir", str(FIXTURE), "--out", str(out), "--llm", "--llm-timeout", "450", "--quiet"]
                )
                self.assertEqual(code, 0)
                mock_gen.assert_called_once()
                self.assertEqual(mock_gen.call_args.kwargs.get("timeout"), 450.0)


if __name__ == "__main__":
    unittest.main()
