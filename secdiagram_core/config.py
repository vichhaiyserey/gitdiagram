"""Configuration management for secdiagram platform and CLI."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

CONFIG_FILENAMES = ("secdiagram.config.json", ".secdiagram.json", ".secdiagramrc.json")


@dataclass(slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    auth_mode: str = "none"  # "none" or "basic"
    auth_username: str | None = None
    auth_password: str | None = None
    read_only: bool = False
    cors_origins: list[str] = field(default_factory=list)

    def is_auth_enabled(self) -> bool:
        return self.auth_mode == "basic" and bool(self.auth_username and self.auth_password)

    def safe_dict(self) -> dict[str, Any]:
        """Return config with credentials safely redacted."""
        data = asdict(self)
        if data.get("auth_password"):
            data["auth_password"] = "******"
        return data


@dataclass(slots=True)
class AnalysisSettings:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    min_confidence: float = 0.5
    min_finding_confidence: float = 0.0
    max_nodes: int = 2000
    security: bool = True
    diagram_detail: str = "architecture"
    diagram_theme: str = "modern"
    diagram_direction: str = "LR"


@dataclass(slots=True)
class SecdiagramConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    analysis: AnalysisSettings = field(default_factory=AnalysisSettings)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "server": self.server.safe_dict(),
            "analysis": asdict(self.analysis),
        }


def find_config_file(root: Path) -> Path | None:
    """Search for a standard config file in root directory."""
    for filename in CONFIG_FILENAMES:
        candidate = root / filename
        if candidate.is_file():
            return candidate
    return None


def load_config(root: Path, config_path: Path | None = None) -> SecdiagramConfig:
    """Load configuration from file, environment variables, and defaults."""
    cfg = SecdiagramConfig()
    target_path = config_path or find_config_file(root)

    if target_path and target_path.is_file():
        try:
            content = json.loads(target_path.read_text(encoding="utf-8"))
            if isinstance(content, dict):
                # Server section
                srv = content.get("server", {})
                if isinstance(srv, dict):
                    if "host" in srv:
                        cfg.server.host = str(srv["host"])
                    if "port" in srv:
                        cfg.server.port = int(srv["port"])
                    if "auth_mode" in srv:
                        cfg.server.auth_mode = str(srv["auth_mode"]).lower()
                    if "auth_username" in srv:
                        cfg.server.auth_username = str(srv["auth_username"])
                    if "auth_password" in srv:
                        cfg.server.auth_password = str(srv["auth_password"])
                    if "read_only" in srv:
                        cfg.server.read_only = bool(srv["read_only"])
                    if "cors_origins" in srv and isinstance(srv["cors_origins"], list):
                        cfg.server.cors_origins = [str(o) for o in srv["cors_origins"]]

                # Analysis section
                ana = content.get("analysis", {})
                if isinstance(ana, dict):
                    if "include" in ana and isinstance(ana["include"], list):
                        cfg.analysis.include = [str(x) for x in ana["include"]]
                    if "exclude" in ana and isinstance(ana["exclude"], list):
                        cfg.analysis.exclude = [str(x) for x in ana["exclude"]]
                    if "min_confidence" in ana:
                        cfg.analysis.min_confidence = float(ana["min_confidence"])
                    if "min_finding_confidence" in ana:
                        cfg.analysis.min_finding_confidence = float(ana["min_finding_confidence"])
                    if "max_nodes" in ana:
                        cfg.analysis.max_nodes = int(ana["max_nodes"])
                    if "security" in ana:
                        cfg.analysis.security = bool(ana["security"])
                    if "diagram_detail" in ana:
                        cfg.analysis.diagram_detail = str(ana["diagram_detail"])
                    if "diagram_theme" in ana:
                        cfg.analysis.diagram_theme = str(ana["diagram_theme"])
                    if "diagram_direction" in ana:
                        cfg.analysis.diagram_direction = str(ana["diagram_direction"])
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    # Environment variable overrides
    env_host = os.environ.get("SECDIAGRAM_SERVER_HOST")
    if env_host:
        cfg.server.host = env_host

    env_port = os.environ.get("SECDIAGRAM_SERVER_PORT")
    if env_port:
        try:
            cfg.server.port = int(env_port)
        except ValueError:
            pass

    env_auth_mode = os.environ.get("SECDIAGRAM_AUTH_MODE")
    if env_auth_mode:
        cfg.server.auth_mode = env_auth_mode.lower()

    env_user = os.environ.get("SECDIAGRAM_AUTH_USER")
    if env_user:
        cfg.server.auth_username = env_user

    env_pass = os.environ.get("SECDIAGRAM_AUTH_PASS")
    if env_pass:
        cfg.server.auth_password = env_pass

    env_ro = os.environ.get("SECDIAGRAM_READ_ONLY")
    if env_ro:
        cfg.server.read_only = env_ro.lower() in {"1", "true", "yes"}

    # If credentials are provided but auth_mode was left as "none", promote to basic
    if cfg.server.auth_username and cfg.server.auth_password and cfg.server.auth_mode == "none":
        cfg.server.auth_mode = "basic"

    return cfg
