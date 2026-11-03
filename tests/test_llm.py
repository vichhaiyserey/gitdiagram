from __future__ import annotations

import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.llm import NarrativeError, _compact, generate_narrative

try:
    from .support import fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import fixture_result
    except (ImportError, ValueError):
        from support import fixture_result


class DummyHTTPResponse:
    def __init__(self, data: bytes, status: int = 200) -> None:
        self.data = data
        self.status = status

    def read(self) -> bytes:
        return self.data

    def __enter__(self) -> DummyHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class LLMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.graph = fixture_result().graph

    def test_compact_graph_structure(self) -> None:
        compact = _compact(self.graph)
        self.assertIn("meta", compact)
        self.assertIn("features", compact)
        self.assertIn("entrypoints", compact)
        self.assertIn("external", compact)
        self.assertIn("findings", compact)
        self.assertGreater(len(compact["entrypoints"]), 0)
        self.assertGreater(len(compact["findings"]), 0)

    def test_generate_narrative_success(self) -> None:
        fake_response = {
            "choices": [
                {
                    "message": {
                        "content": "# Architecture Narrative\n\nThis is a generated narrative citing app/main.py:12."
                    }
                }
            ]
        }
        response_bytes = json.dumps(fake_response).encode("utf-8")

        with mock.patch.dict(os.environ, {"GITDIAGRAM_LLM_API_KEY": "test-key"}):
            with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(response_bytes)) as mock_urlopen:
                narrative = generate_narrative(self.graph)
                self.assertIn("# Architecture Narrative", narrative)
                self.assertIn("app/main.py:12", narrative)
                self.assertTrue(narrative.endswith("\n"))
                mock_urlopen.assert_called_once()
                req = mock_urlopen.call_args[0][0]
                self.assertEqual(req.headers.get("Authorization"), "Bearer test-key")

    def test_generate_narrative_missing_key(self) -> None:
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITDIAGRAM_LLM_API_KEY", "OPENAI_API_KEY")}
        with mock.patch.dict(os.environ, clean_env, clear=True):
            with self.assertRaises(NarrativeError) as ctx:
                generate_narrative(self.graph)
            self.assertIn("no LLM key found", str(ctx.exception))

    def test_generate_narrative_http_error(self) -> None:
        with mock.patch.dict(os.environ, {"GITDIAGRAM_LLM_API_KEY": "test-key"}):
            with mock.patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(
                    url="https://api.openai.com/v1/chat/completions",
                    code=401,
                    msg="Unauthorized",
                    hdrs={},  # type: ignore
                    fp=io.BytesIO(b'{"error": "invalid_api_key"}'),
                ),
            ):
                with self.assertRaises(NarrativeError) as ctx:
                    generate_narrative(self.graph)
                self.assertIn("LLM request failed", str(ctx.exception))

    def test_generate_narrative_malformed_json(self) -> None:
        with mock.patch.dict(os.environ, {"GITDIAGRAM_LLM_API_KEY": "test-key"}):
            with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(b"not json")):
                with self.assertRaises(NarrativeError) as ctx:
                    generate_narrative(self.graph)
                self.assertIn("LLM request failed", str(ctx.exception))

    def test_generate_narrative_missing_choices(self) -> None:
        empty_payload = json.dumps({"choices": []}).encode("utf-8")
        with mock.patch.dict(os.environ, {"GITDIAGRAM_LLM_API_KEY": "test-key"}):
            with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(empty_payload)):
                with self.assertRaises(NarrativeError) as ctx:
                    generate_narrative(self.graph)
                self.assertIn("did not contain message content", str(ctx.exception))

    def test_ollama_no_key_required_success(self) -> None:
        fake_response = {
            "choices": [{"message": {"content": "# Qwen Narrative\nArchitecture summary."}}]
        }
        response_bytes = json.dumps(fake_response).encode("utf-8")
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITDIAGRAM_LLM_API_KEY", "OPENAI_API_KEY")}

        with mock.patch.dict(os.environ, clean_env, clear=True):
            with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(response_bytes)) as mock_urlopen:
                narrative = generate_narrative(self.graph, provider="ollama")
                self.assertIn("# Qwen Narrative", narrative)
                req = mock_urlopen.call_args[0][0]
                self.assertIn("localhost:11434/v1", req.full_url)
                body = json.loads(req.data.decode("utf-8"))
                self.assertEqual(body["model"], "qwen2.5-coder")

    def test_ollama_custom_qwen_model(self) -> None:
        fake_response = {
            "choices": [{"message": {"content": "# Qwen 7B Narrative"}}]
        }
        response_bytes = json.dumps(fake_response).encode("utf-8")
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITDIAGRAM_LLM_API_KEY", "OPENAI_API_KEY")}

        with mock.patch.dict(os.environ, clean_env, clear=True):
            with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(response_bytes)) as mock_urlopen:
                narrative = generate_narrative(self.graph, provider="ollama", model="qwen2.5:7b")
                self.assertIn("# Qwen 7B Narrative", narrative)
                req = mock_urlopen.call_args[0][0]
                body = json.loads(req.data.decode("utf-8"))
                self.assertEqual(body["model"], "qwen2.5:7b")

    def test_ollama_connection_error_has_docker_help(self) -> None:
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITDIAGRAM_LLM_API_KEY", "OPENAI_API_KEY")}
        with mock.patch.dict(os.environ, clean_env, clear=True):
            with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
                with self.assertRaises(NarrativeError) as ctx:
                    generate_narrative(self.graph, provider="ollama")
                self.assertIn("docker run -d -p 11434:11434", str(ctx.exception))

    def test_ollama_404_has_pull_help(self) -> None:
        clean_env = {k: v for k, v in os.environ.items() if k not in ("GITDIAGRAM_LLM_API_KEY", "OPENAI_API_KEY")}
        with mock.patch.dict(os.environ, clean_env, clear=True):
            with mock.patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(
                    url="http://localhost:11434/v1/chat/completions",
                    code=404,
                    msg="Not Found",
                    hdrs={},  # type: ignore
                    fp=io.BytesIO(b'{"error": "model not found"}'),
                ),
            ):
                with self.assertRaises(NarrativeError) as ctx:
                    generate_narrative(self.graph, provider="ollama", model="qwen2.5-coder")
                self.assertIn("ollama pull qwen2.5-coder", str(ctx.exception))

    def test_templates_sent_in_prompt(self) -> None:
        for tpl in ("threat-model", "remediation", "compliance", "comprehensive"):
            fake_response = {"choices": [{"message": {"content": f"# {tpl} Review" }}]}
            response_bytes = json.dumps(fake_response).encode("utf-8")
            with mock.patch.dict(os.environ, {"GITDIAGRAM_LLM_API_KEY": "test-key"}):
                with mock.patch("urllib.request.urlopen", return_value=DummyHTTPResponse(response_bytes)) as mock_urlopen:
                    narrative = generate_narrative(self.graph, template=tpl)
                    self.assertIn(f"# {tpl} Review", narrative)
                    req = mock_urlopen.call_args[0][0]
                    body = json.loads(req.data.decode("utf-8"))
                    user_prompt = body["messages"][1]["content"]
                    if tpl == "threat-model":
                        self.assertIn("STRIDE", user_prompt)
                    elif tpl == "remediation":
                        self.assertIn("Remediation Playbook", user_prompt)
                    elif tpl == "compliance":
                        self.assertIn("OWASP Top 10", user_prompt)
                    elif tpl == "comprehensive":
                        self.assertIn("Security Architecture Review", user_prompt)


if __name__ == "__main__":
    unittest.main()
