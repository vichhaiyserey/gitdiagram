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
    insecure_no_auth: bool = False
    max_request_bytes: int = 1_048_576
    rate_limit_per_minute: int = 240
    max_concurrent_scans: int = 1
    scan_roots: list[str] = field(default_factory=list)
    audit_log: str | None = None

    def is_auth_enabled(self) -> bool:
        return self.auth_mode == "basic" and bool(self.auth_username and self.auth_password)

    def safe_dict(self) -> dict[str, Any]:
        """Return config with credentials and host paths safely redacted."""
        data = asdict(self)
        if data.get("auth_password"):
            data["auth_password"] = "******"
        if data.get("scan_roots"):
            data["scan_roots"] = [Path(entry).name or "configured-root" for entry in data["scan_roots"]]
        if data.get("audit_log"):
            data["audit_log"] = Path(data["audit_log"]).name
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
                    if "insecure_no_auth" in srv:
                        cfg.server.insecure_no_auth = bool(srv["insecure_no_auth"])
                    if "max_request_bytes" in srv:
                        cfg.server.max_request_bytes = int(srv["max_request_bytes"])
                    if "rate_limit_per_minute" in srv:
                        cfg.server.rate_limit_per_minute = int(srv["rate_limit_per_minute"])
                    if "max_concurrent_scans" in srv:
                        cfg.server.max_concurrent_scans = int(srv["max_concurrent_scans"])
                    if "scan_roots" in srv and isinstance(srv["scan_roots"], list):
                        cfg.server.scan_roots = [str(p) for p in srv["scan_roots"]]
                    if "audit_log" in srv and srv["audit_log"]:
                        cfg.server.audit_log = str(srv["audit_log"])

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

    env_insecure = os.environ.get("SECDIAGRAM_INSECURE_NO_AUTH")
    if env_insecure:
        cfg.server.insecure_no_auth = env_insecure.lower() in {"1", "true", "yes"}

    env_max_body = os.environ.get("SECDIAGRAM_MAX_REQUEST_BYTES")
    if env_max_body:
        try:
            cfg.server.max_request_bytes = int(env_max_body)
        except ValueError:
            pass

    env_rate = os.environ.get("SECDIAGRAM_RATE_LIMIT_PER_MINUTE")
    if env_rate:
        try:
            cfg.server.rate_limit_per_minute = int(env_rate)
        except ValueError:
            pass

    env_scans = os.environ.get("SECDIAGRAM_MAX_CONCURRENT_SCANS")
    if env_scans:
        try:
            cfg.server.max_concurrent_scans = int(env_scans)
        except ValueError:
            pass

    env_roots = os.environ.get("SECDIAGRAM_SCAN_ROOTS")
    if env_roots:
        cfg.server.scan_roots = [p for p in env_roots.split(os.pathsep) if p]

    env_audit = os.environ.get("SECDIAGRAM_AUDIT_LOG")
    if env_audit:
        cfg.server.audit_log = env_audit

    # If credentials are provided but auth_mode was left as "none", promote to basic
    if cfg.server.auth_username and cfg.server.auth_password and cfg.server.auth_mode == "none":
        cfg.server.auth_mode = "basic"

    return cfg
