from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from secdiagram_core.config import SecdiagramConfig
from secdiagram_core.server import (
    BasicAuthenticator,
    NoOpAuthenticator,
    RateLimiter,
    ScanManager,
    create_server,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_app"


class AuthenticatorTests(unittest.TestCase):
    def test_noop_authenticator(self) -> None:
        auth = NoOpAuthenticator()
        ok, user = auth.authenticate({})
        self.assertTrue(ok)
        self.assertEqual(user, "anonymous")
        self.assertIsNone(auth.challenge_header())

    def test_basic_authenticator(self) -> None:
        auth = BasicAuthenticator(username="admin", password="secretpassword")
        self.assertIn("Basic realm=", auth.challenge_header() or "")

        # Missing header
        ok, _ = auth.authenticate({})
        self.assertFalse(ok)

        # Non-basic header
        ok, _ = auth.authenticate({"Authorization": "Bearer token123"})
        self.assertFalse(ok)

        # Invalid base64
        ok, _ = auth.authenticate({"Authorization": "Basic ???notb64???"})
        self.assertFalse(ok)

        # Wrong credentials
        bad_b64 = base64.b64encode(b"admin:wrongpass").decode("ascii")
        ok, _ = auth.authenticate({"Authorization": f"Basic {bad_b64}"})
        self.assertFalse(ok)

        # Correct credentials
        good_b64 = base64.b64encode(b"admin:secretpassword").decode("ascii")
        ok, user = auth.authenticate({"Authorization": f"Basic {good_b64}"})
        self.assertTrue(ok)
        self.assertEqual(user, "admin")


class LimitPrimitiveTests(unittest.TestCase):
    def test_rate_limiter_allows_up_to_limit(self) -> None:
        limiter = RateLimiter(limit_per_minute=2, window_seconds=60)
        self.assertTrue(limiter.check("client")[0])
        self.assertTrue(limiter.check("client")[0])
        allowed, retry_after = limiter.check("client")
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)
        self.assertTrue(limiter.check("other-client")[0])

    def test_rate_limiter_zero_disables(self) -> None:
        limiter = RateLimiter(limit_per_minute=0)
        for _ in range(100):
            self.assertTrue(limiter.check("client")[0])

    def test_scan_manager_bounds_concurrency(self) -> None:
        manager = ScanManager(max_concurrent=1)
        self.assertTrue(manager.try_acquire())
        self.assertFalse(manager.try_acquire())
        manager.release()
        self.assertTrue(manager.try_acquire())
        manager.release()

    def test_scan_manager_release_without_acquire_is_safe(self) -> None:
        manager = ScanManager(max_concurrent=1)
        manager.release()  # must not raise ValueError


class ServerConstructionTests(unittest.TestCase):
    def test_requires_auth_by_default(self) -> None:
        cfg = SecdiagramConfig()
        cfg.server.port = 0
        with self.assertRaises(ValueError) as ctx:
            create_server(FIXTURE, cfg)
        self.assertIn("Authentication is required", str(ctx.exception))

    def test_insecure_flag_only_allows_loopback(self) -> None:
        cfg = SecdiagramConfig()
        cfg.server.port = 0
        cfg.server.insecure_no_auth = True
        cfg.server.host = "0.0.0.0"
        with self.assertRaises(ValueError) as ctx:
            create_server(FIXTURE, cfg)
        self.assertIn("non-loopback", str(ctx.exception))

    def test_scan_root_allowlist_must_contain_served_root(self) -> None:
        cfg = SecdiagramConfig()
        cfg.server.port = 0
        cfg.server.insecure_no_auth = True
        cfg.server.scan_roots = [str(FIXTURE.parent / "elsewhere")]
        with self.assertRaises(ValueError):
            create_server(FIXTURE, cfg)


class ServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = SecdiagramConfig()
        cls.config.server.host = "127.0.0.1"
        cls.config.server.port = 0  # Ephemeral port assigned by OS
        cls.config.server.insecure_no_auth = True
        cls.server = create_server(FIXTURE, cls.config)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_endpoint(self) -> None:
        url = f"{self.base_url}/api/v1/health"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
            self.assertIn("default-src", resp.headers.get("Content-Security-Policy", ""))
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["repo"], "sample_app")

    def test_summary_and_graph_endpoints(self) -> None:
        url = f"{self.base_url}/api/v1/summary"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertGreater(data["nodes_count"], 0)
            self.assertGreater(data["edges_count"], 0)

        graph_url = f"{self.base_url}/api/v1/graph"
        with urllib.request.urlopen(graph_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            raw = resp.read().decode("utf-8")
            graph_data = json.loads(raw)
            self.assertIn("nodes", graph_data)
            self.assertIn("edges", graph_data)
            self.assertNotIn(str(FIXTURE), raw)

    def test_findings_endpoint_and_filtering(self) -> None:
        url = f"{self.base_url}/api/v1/findings"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("findings", data)
            total = data["total"]
            self.assertGreaterEqual(total, 1)

        # Filter by severity
        crit_url = f"{self.base_url}/api/v1/findings?severity=critical"
        with urllib.request.urlopen(crit_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            crit_data = json.loads(resp.read().decode("utf-8"))
            for f in crit_data["findings"]:
                self.assertEqual(f["severity"].lower(), "critical")

    def test_sarif_and_diagram_endpoints(self) -> None:
        sarif_url = f"{self.base_url}/api/v1/sarif"
        with urllib.request.urlopen(sarif_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            sarif_data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(sarif_data["version"], "2.1.0")

        diag_url = f"{self.base_url}/api/v1/diagram"
        with urllib.request.urlopen(diag_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            text = resp.read().decode("utf-8")
            self.assertIn("flowchart", text)

    def test_config_endpoint_is_safe(self) -> None:
        cfg_url = f"{self.base_url}/api/v1/config"
        with urllib.request.urlopen(cfg_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("server", data)
            self.assertIn("analysis", data)
            self.assertNotIn(str(FIXTURE), json.dumps(data))

    def test_post_scan_endpoint(self) -> None:
        scan_url = f"{self.base_url}/api/v1/scan"
        req = urllib.request.Request(scan_url, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "success")

    def test_scan_endpoint_accepts_allowlisted_path(self) -> None:
        scan_url = f"{self.base_url}/api/v1/scan"
        body = json.dumps({"path": str(FIXTURE)}).encode("utf-8")
        req = urllib.request.Request(
            scan_url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_scan_endpoint_rejects_non_allowlisted_path(self) -> None:
        scan_url = f"{self.base_url}/api/v1/scan"
        body = json.dumps({"path": str(FIXTURE.parent)}).encode("utf-8")
        req = urllib.request.Request(
            scan_url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

    def test_ui_root_serves_html(self) -> None:
        ui_url = f"{self.base_url}/"
        with urllib.request.urlopen(ui_url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            html = resp.read().decode("utf-8")
            self.assertIn("<!DOCTYPE html>", html)
            self.assertIn("secdiagram report", html)
            self.assertNotIn(str(FIXTURE), html)

    def test_unknown_route_returns_404(self) -> None:
        bad_url = f"{self.base_url}/api/v1/non_existent_route"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(bad_url, timeout=5)
        self.assertEqual(ctx.exception.code, 404)


class ServerAuthAndReadOnlyTests(unittest.TestCase):
    def test_basic_auth_enforcement(self) -> None:
        cfg = SecdiagramConfig()
        cfg.server.host = "127.0.0.1"
        cfg.server.port = 0
        cfg.server.auth_mode = "basic"
        cfg.server.auth_username = "alice"
        cfg.server.auth_password = "password123"

        server = create_server(FIXTURE, cfg)
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            # 1. Unauthenticated request should fail with 401 and WWW-Authenticate
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5)
            self.assertEqual(ctx.exception.code, 401)
            self.assertIn("Basic", ctx.exception.headers.get("WWW-Authenticate", ""))

            # 2. Authenticated request succeeds
            creds = base64.b64encode(b"alice:password123").decode("ascii")
            req = urllib.request.Request(
                f"{base_url}/api/v1/health",
                headers={"Authorization": f"Basic {creds}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["auth_mode"], "basic")
        finally:
            server.shutdown()
            server.server_close()

    def test_read_only_mode_forbids_post_scan(self) -> None:
        cfg = SecdiagramConfig()
        cfg.server.host = "127.0.0.1"
        cfg.server.port = 0
        cfg.server.read_only = True
        cfg.server.insecure_no_auth = True

        server = create_server(FIXTURE, cfg)
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            req = urllib.request.Request(f"{base_url}/api/v1/scan", data=b"", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()


class ServerHardeningTests(unittest.TestCase):
    def _serve(self, cfg: SecdiagramConfig):
        server = create_server(FIXTURE, cfg)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{port}"

    def _base_config(self) -> SecdiagramConfig:
        cfg = SecdiagramConfig()
        cfg.server.host = "127.0.0.1"
        cfg.server.port = 0
        cfg.server.insecure_no_auth = True
        return cfg

    def test_rate_limit_returns_429(self) -> None:
        cfg = self._base_config()
        cfg.server.rate_limit_per_minute = 2
        server, base_url = self._serve(cfg)
        try:
            for _ in range(2):
                with urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5)
            self.assertEqual(ctx.exception.code, 429)
            self.assertIsNotNone(ctx.exception.headers.get("Retry-After"))
        finally:
            server.shutdown()
            server.server_close()

    def test_request_size_limit_returns_413(self) -> None:
        cfg = self._base_config()
        cfg.server.max_request_bytes = 16
        server, base_url = self._serve(cfg)
        try:
            req = urllib.request.Request(
                f"{base_url}/api/v1/scan",
                data=b"x" * 64,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 413)
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_log_records_events_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.jsonl"
            cfg = SecdiagramConfig()
            cfg.server.host = "127.0.0.1"
            cfg.server.port = 0
            cfg.server.auth_mode = "basic"
            cfg.server.auth_username = "alice"
            cfg.server.auth_password = "mock_password_12345"
            cfg.server.audit_log = str(audit_path)
            server, base_url = self._serve(cfg)
            try:
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(f"{base_url}/api/v1/sarif", timeout=5)
                creds = base64.b64encode(b"alice:mock_password_12345").decode("ascii")
                req = urllib.request.Request(
                    f"{base_url}/api/v1/sarif",
                    headers={"Authorization": f"Basic {creds}"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
            finally:
                server.shutdown()
                server.server_close()

            text = audit_path.read_text(encoding="utf-8")
            self.assertIn('"event": "auth_failure"', text)
            self.assertIn('"event": "sarif_download"', text)
            self.assertNotIn("mock_password_12345", text)
            self.assertNotIn(str(FIXTURE), text)
            for line in text.splitlines():
                json.loads(line)


if __name__ == "__main__":
    unittest.main()
