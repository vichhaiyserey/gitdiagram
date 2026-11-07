from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secdiagram_core.config import find_config_file, load_config


class ConfigTests(unittest.TestCase):
    def test_default_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = load_config(root)
            self.assertEqual(cfg.server.host, "127.0.0.1")
            self.assertEqual(cfg.server.port, 8080)
            self.assertEqual(cfg.server.auth_mode, "none")
            self.assertFalse(cfg.server.read_only)
            self.assertFalse(cfg.server.is_auth_enabled())
            self.assertFalse(cfg.server.insecure_no_auth)
            self.assertEqual(cfg.server.max_request_bytes, 1_048_576)
            self.assertEqual(cfg.server.rate_limit_per_minute, 240)
            self.assertEqual(cfg.server.max_concurrent_scans, 1)
            self.assertEqual(cfg.server.scan_roots, [])
            self.assertIsNone(cfg.server.audit_log)

    def test_load_from_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_file = root / "secdiagram.config.json"
            config_file.write_text(
                json.dumps(
                    {
                        "server": {
                            "host": "0.0.0.0",
                            "port": 9090,
                            "auth_mode": "basic",
                            "auth_username": "admin",
                            "auth_password": "supersecretpassword",
                            "read_only": True,
                            "cors_origins": ["http://localhost:3000"],
                            "insecure_no_auth": False,
                            "max_request_bytes": 2048,
                            "rate_limit_per_minute": 60,
                            "max_concurrent_scans": 2,
                            "scan_roots": ["/srv/repos/one"],
                            "audit_log": "/var/log/secdiagram/audit.jsonl",
                        },
                        "analysis": {
                            "include": ["app/**/*.py"],
                            "exclude": ["tests/**"],
                            "min_confidence": 0.8,
                            "min_finding_confidence": 0.7,
                            "max_nodes": 500,
                            "security": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(find_config_file(root), config_file)
            cfg = load_config(root)
            self.assertEqual(cfg.server.host, "0.0.0.0")
            self.assertEqual(cfg.server.port, 9090)
            self.assertTrue(cfg.server.is_auth_enabled())
            self.assertEqual(cfg.server.auth_username, "admin")
            self.assertEqual(cfg.server.auth_password, "supersecretpassword")
            self.assertTrue(cfg.server.read_only)
            self.assertEqual(cfg.server.max_request_bytes, 2048)
            self.assertEqual(cfg.server.rate_limit_per_minute, 60)
            self.assertEqual(cfg.server.max_concurrent_scans, 2)
            self.assertEqual(cfg.server.scan_roots, ["/srv/repos/one"])
            self.assertEqual(cfg.server.audit_log, "/var/log/secdiagram/audit.jsonl")
            self.assertEqual(cfg.analysis.include, ["app/**/*.py"])
            self.assertEqual(cfg.analysis.min_confidence, 0.8)

            # Test safe_dict redacts secret and absolute host paths
            safe = cfg.safe_dict()
            self.assertEqual(safe["server"]["auth_password"], "******")
            self.assertEqual(safe["server"]["auth_username"], "admin")
            self.assertEqual(safe["server"]["scan_roots"], ["one"])
            self.assertEqual(safe["server"]["audit_log"], "audit.jsonl")
            self.assertNotIn("/srv/repos/one", json.dumps(safe))
            self.assertNotIn("/var/log/secdiagram", json.dumps(safe))

    def test_env_var_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {
                "SECDIAGRAM_SERVER_HOST": "10.0.0.1",
                "SECDIAGRAM_SERVER_PORT": "8888",
                "SECDIAGRAM_AUTH_USER": "ci-agent",
                "SECDIAGRAM_AUTH_PASS": "ci-token-xyz",
                "SECDIAGRAM_READ_ONLY": "true",
                "SECDIAGRAM_INSECURE_NO_AUTH": "true",
                "SECDIAGRAM_MAX_REQUEST_BYTES": "8192",
                "SECDIAGRAM_RATE_LIMIT_PER_MINUTE": "30",
                "SECDIAGRAM_MAX_CONCURRENT_SCANS": "3",
                "SECDIAGRAM_AUDIT_LOG": "audit.jsonl",
            }
            with mock.patch.dict(os.environ, env):
                cfg = load_config(root)
                self.assertEqual(cfg.server.host, "10.0.0.1")
                self.assertEqual(cfg.server.port, 8888)
                self.assertEqual(cfg.server.auth_mode, "basic")
                self.assertEqual(cfg.server.auth_username, "ci-agent")
                self.assertEqual(cfg.server.auth_password, "ci-token-xyz")
                self.assertTrue(cfg.server.read_only)
                self.assertTrue(cfg.server.is_auth_enabled())
                self.assertTrue(cfg.server.insecure_no_auth)
                self.assertEqual(cfg.server.max_request_bytes, 8192)
                self.assertEqual(cfg.server.rate_limit_per_minute, 30)
                self.assertEqual(cfg.server.max_concurrent_scans, 3)
                self.assertEqual(cfg.server.audit_log, "audit.jsonl")


if __name__ == "__main__":
    unittest.main()
