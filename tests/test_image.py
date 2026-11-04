from __future__ import annotations

import io
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.render_image import (
    ImageRenderError,
    render_image,
    render_kroki,
    render_local_mmdc,
    render_mermaid_ink,
    sanitize_mermaid,
)
from secdiagram_core.render_image import (
    main as image_cli_main,
)


class ImageRenderTests(unittest.TestCase):
    def test_sanitize_mermaid_fixes_class_keyword(self) -> None:
        raw = "flowchart LR\n  n_1:::class\n  classDef class fill:#f00;"
        cleaned = sanitize_mermaid(raw)
        self.assertIn("n_1:::cls", cleaned)
        self.assertIn("classDef cls fill:#f00;", cleaned)
        self.assertNotIn(":::class", cleaned)
        self.assertNotIn("classDef class ", cleaned)

    def test_invalid_image_format_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.bmp"
            with self.assertRaises(ValueError) as ctx:
                render_image("flowchart LR\n A --> B", out_file, image_format="bmp")
            self.assertIn("Unsupported image format: bmp", str(ctx.exception))

    def test_unknown_provider_raises_value_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            with self.assertRaises(ValueError) as ctx:
                render_image("flowchart LR\n A --> B", out_file, provider="unknown_provider")
            self.assertIn("Unknown image provider", str(ctx.exception))

    def test_local_mmdc_missing_raises_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            with mock.patch("shutil.which", return_value=None):
                with self.assertRaises(ImageRenderError) as ctx:
                    render_local_mmdc("flowchart LR\n A --> B", out_file)
                self.assertIn("Local Mermaid CLI ('mmdc') was not found on PATH", str(ctx.exception))

    def test_local_mmdc_mocked_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"

            def fake_run(cmd, **kwargs):
                out_file.write_bytes(b"\x89PNGfake")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch("shutil.which", return_value="/usr/local/bin/mmdc"):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    render_local_mmdc("flowchart LR\n A --> B", out_file)
            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.read_bytes(), b"\x89PNGfake")

    def test_local_mmdc_mocked_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"

            def fake_run(cmd, **kwargs):
                return mock.Mock(returncode=1, stdout="", stderr="Syntax error in diagram")

            with mock.patch("shutil.which", return_value="/usr/local/bin/mmdc"):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    with self.assertRaises(ImageRenderError) as ctx:
                        render_local_mmdc("flowchart LR\n A --> B", out_file)
                    self.assertIn("Syntax error in diagram", str(ctx.exception))

    def test_local_mmdc_detects_rendered_error_box(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.svg"

            def fake_run(cmd, **kwargs):
                out_file.write_text("<svg><p>Maximum text size in diagram exceeded</p></svg>", encoding="utf-8")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch("shutil.which", return_value="/usr/local/bin/mmdc"):
                with mock.patch("subprocess.run", side_effect=fake_run):
                    with self.assertRaises(ImageRenderError) as ctx:
                        render_local_mmdc("A" * 60000, out_file, image_format="svg")
                    self.assertIn("exceeded renderer limit", str(ctx.exception))

    def test_kroki_render_mocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            dummy_png = b"\x89PNG\r\n\x1a\n\x00\x00fake_image_data"

            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = dummy_png
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = False

            with mock.patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                render_kroki("flowchart LR\n A --> B", out_file, image_format="png")
                self.assertTrue(out_file.exists())
                self.assertEqual(out_file.read_bytes(), dummy_png)

                # Verify Request was made to Kroki endpoint
                req = mock_urlopen.call_args[0][0]
                self.assertIn("kroki.io/mermaid/png", req.full_url)
                self.assertEqual(req.get_method(), "POST")

    def test_kroki_http_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            err = urllib.error.HTTPError(
                "http://kroki.io", 400, "Bad Request", {}, io.BytesIO(b"Syntax Error in Mermaid")
            )
            with mock.patch("urllib.request.urlopen", side_effect=err):
                with self.assertRaises(ImageRenderError) as ctx:
                    render_kroki("flowchart LR\n A --> B", out_file, image_format="png")
                self.assertIn("HTTP error 400: Syntax Error in Mermaid", str(ctx.exception))

    def test_kroki_connection_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            err = urllib.error.URLError("Connection refused")
            with mock.patch("urllib.request.urlopen", side_effect=err):
                with self.assertRaises(ImageRenderError) as ctx:
                    render_kroki("flowchart LR\n A --> B", out_file, image_format="png")
                self.assertIn("connection failed: Connection refused", str(ctx.exception))

    def test_endpoint_scheme_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            with self.assertRaises(ImageRenderError) as ctx:
                render_kroki("flowchart LR\n A --> B", out_file, endpoint="file:///etc/passwd")
            self.assertIn("Invalid image endpoint scheme: 'file'", str(ctx.exception))

            with self.assertRaises(ImageRenderError) as ctx2:
                render_mermaid_ink("flowchart LR\n A --> B", out_file, endpoint="ftp://malicious.com")
            self.assertIn("Invalid image endpoint scheme: 'ftp'", str(ctx2.exception))

    def test_mermaid_ink_render_mocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.svg"
            dummy_svg = b"<svg>fake</svg>"

            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = dummy_svg
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = False

            with mock.patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                render_mermaid_ink("flowchart LR\n A --> B", out_file, image_format="svg")
                self.assertTrue(out_file.exists())
                self.assertEqual(out_file.read_bytes(), dummy_svg)

                req = mock_urlopen.call_args[0][0]
                self.assertIn("mermaid.ink/svg/pako:", req.full_url)

    def test_mermaid_ink_unsupported_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.pdf"
            with self.assertRaises(ImageRenderError) as ctx:
                render_mermaid_ink("flowchart LR\n A --> B", out_file, image_format="pdf")
            self.assertIn("mermaid.ink only supports 'png' and 'svg'", str(ctx.exception))

    def test_auto_provider_pdf_requires_mmdc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.pdf"
            with mock.patch("shutil.which", return_value=None):
                with self.assertRaises(ImageRenderError) as ctx:
                    render_image("flowchart LR\n A --> B", out_file, image_format="pdf", provider="auto")
                self.assertIn("PDF output requires local mermaid-cli", str(ctx.exception))

    def test_auto_provider_fallback_to_mermaid_ink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "diagram.png"
            dummy_png = b"\x89PNGfallback"

            def mock_urlopen_fn(req, **kwargs):
                raw_url = req.full_url if hasattr(req, "full_url") else str(req)
                hostname = urllib.parse.urlsplit(raw_url).hostname or ""
                if hostname == "kroki.io" or hostname.endswith(".kroki.io"):
                    raise urllib.error.URLError("Kroki down")
                if hostname == "mermaid.ink" or hostname.endswith(".mermaid.ink"):
                    mock_resp = mock.MagicMock()
                    mock_resp.read.return_value = dummy_png
                    mock_resp.__enter__.return_value = mock_resp
                    mock_resp.__exit__.return_value = False
                    return mock_resp
                raise urllib.error.URLError("Unexpected url")

            with mock.patch("shutil.which", return_value=None):
                with mock.patch("urllib.request.urlopen", side_effect=mock_urlopen_fn):
                    render_image("flowchart LR\n A --> B", out_file, image_format="png", provider="auto")
            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.read_bytes(), dummy_png)

    def test_image_cli_main(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            input_mmd = Path(tmp) / "diagram.mmd"
            input_mmd.write_text("flowchart LR\n  A --> B\n", encoding="utf-8")
            output_png = Path(tmp) / "diagram.png"

            dummy_png = b"\x89PNGclipng"
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = dummy_png
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = False

            with mock.patch("shutil.which", return_value=None):
                with mock.patch("urllib.request.urlopen", return_value=mock_resp):
                    code = image_cli_main([str(input_mmd), str(output_png)])
            self.assertEqual(code, 0)
            self.assertTrue(output_png.exists())
            self.assertEqual(output_png.read_bytes(), dummy_png)

    def test_image_cli_missing_input(self) -> None:
        code = image_cli_main(["non_existent_file.mmd"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
