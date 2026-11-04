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
            self.assertEqual(cfg.analysis.include, ["app/**/*.py"])
            self.assertEqual(cfg.analysis.min_confidence, 0.8)

            # Test safe_dict redacts secret
            safe = cfg.safe_dict()
            self.assertEqual(safe["server"]["auth_password"], "******")
            self.assertEqual(safe["server"]["auth_username"], "admin")

    def test_env_var_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {
                "SECDIAGRAM_SERVER_HOST": "10.0.0.1",
                "SECDIAGRAM_SERVER_PORT": "8888",
                "SECDIAGRAM_AUTH_USER": "ci-agent",
                "SECDIAGRAM_AUTH_PASS": "ci-token-xyz",
                "SECDIAGRAM_READ_ONLY": "true",
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


if __name__ == "__main__":
    unittest.main()
