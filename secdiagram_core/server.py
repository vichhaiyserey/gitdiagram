"""Deterministic, secure, stdlib-only platform HTTP server and REST API for secdiagram."""

from __future__ import annotations

import abc
import base64
import json
import secrets
import sys
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .analyzer import AnalysisConfig, AnalysisResult, run_analysis
from .config import SecdiagramConfig, load_config
from .high_level import build_high_level_architecture, render_mermaid_highlevel
from .model import SEVERITY_RANK, Finding, Graph
from .render_html import render_html
from .render_json import render_json
from .render_mermaid import render_mermaid
from .render_sarif import render_sarif


def _sev_counts(graph: Graph) -> dict[str, int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for finding in graph.findings:
        severity = finding.severity.lower()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1
    return counts


# Standard security headers applied to all HTTP responses
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store, no-cache, must-revalidate",
}


# ------------------------------------------------------------------- Authentication
class Authenticator(abc.ABC):
    """Abstract authentication backend interface.

    Allows adding future authentication methods (Bearer token, OAuth2, API key)
    without modifying core server request dispatching.
    """

    @abc.abstractmethod
    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        """Verify request headers; return (is_authenticated, identity_identifier)."""

    @abc.abstractmethod
    def challenge_header(self) -> str | None:
        """Return WWW-Authenticate header challenge string, if applicable."""


class NoOpAuthenticator(Authenticator):
    """Permissive authenticator when authentication is disabled."""

    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        return True, "anonymous"

    def challenge_header(self) -> str | None:
        return None


class BasicAuthenticator(Authenticator):
    """Timing-attack-safe HTTP Basic Authenticator using secrets.compare_digest."""

    def __init__(self, username: str, password: str, realm: str = "secdiagram") -> None:
        self.username = username
        self.password = password
        self.realm = realm

    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        auth_header = headers.get("authorization") or headers.get("Authorization") or ""
        if not auth_header.startswith("Basic "):
            return False, None
        try:
            raw_b64 = auth_header[6:].strip()
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            if ":" not in decoded:
                return False, None
            user, pwd = decoded.split(":", 1)
            user_ok = secrets.compare_digest(user, self.username)
            pwd_ok = secrets.compare_digest(pwd, self.password)
            if user_ok and pwd_ok:
                return True, user
            return False, None
        except Exception:
            return False, None

    def challenge_header(self) -> str | None:
        return f'Basic realm="{self.realm}", charset="UTF-8"'


# ------------------------------------------------------------------- Platform State
class PlatformState:
    """Thread-safe state holding the latest analysis result, cache, and settings."""

    def __init__(self, root: Path, config: SecdiagramConfig) -> None:
        self.root = root.resolve()
        self.config = config
        self.lock = threading.Lock()
        self.last_analysis: AnalysisResult | None = None
        self.last_scan_timestamp: float = 0.0
        self.html_cache: str | None = None

    def rescan(self) -> AnalysisResult:
        with self.lock:
            ana_cfg = self.config.analysis
            result = run_analysis(
                AnalysisConfig(
                    root=self.root,
                    include=ana_cfg.include,
                    exclude=ana_cfg.exclude,
                    min_confidence=ana_cfg.min_confidence,
                    max_nodes=ana_cfg.max_nodes,
                    security=ana_cfg.security,
                )
            )
            if ana_cfg.min_finding_confidence > 0:
                result.graph.findings = [
                    f for f in result.graph.findings
                    if f.confidence >= ana_cfg.min_finding_confidence
                ]
            self.last_analysis = result
            self.last_scan_timestamp = time.time()
            self.html_cache = None  # invalidate cache
            return result

    def get_analysis(self) -> AnalysisResult:
        if self.last_analysis is None:
            return self.rescan()
        return self.last_analysis

    def get_html_report(self) -> str:
        with self.lock:
            if self.html_cache is not None:
                return self.html_cache
        result = self.get_analysis()
        with self.lock:
            hla = build_high_level_architecture(self.root, result.graph)
            highlevel_mermaid = render_mermaid_highlevel(
                hla,
                direction=self.config.analysis.diagram_direction,
                theme=self.config.analysis.diagram_theme,
            )
            detail_mermaid = render_mermaid(
                result.graph,
                detail=self.config.analysis.diagram_detail,
                direction=self.config.analysis.diagram_direction,
                theme=self.config.analysis.diagram_theme,
            )
            html = render_html(
                result.graph,
                meta=dict(result.graph.meta),
                hla=hla,
                highlevel_mermaid=highlevel_mermaid,
                detail_mermaid=detail_mermaid,
                root=self.root,
                offline=False,
            )
            self.html_cache = html
            return html


# ------------------------------------------------------------------- Request Handler
class PlatformHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer with strongly typed platform state and authenticator."""

    platform_state: PlatformState
    authenticator: Authenticator


class SecdiagramRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing REST API endpoints and modular UI hosting."""

    server_version = f"secdiagram-platform/{__version__}"

    @property
    def platform_server(self) -> PlatformHTTPServer:
        return cast(PlatformHTTPServer, self.server)

    def send_security_headers(self) -> None:
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)

    def _send_json(self, status_code: int, data: Any) -> None:
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status_code: int, content: str, content_type: str = "text/plain; charset=utf-8") -> None:
        payload = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _check_auth(self) -> bool:
        authenticator: Authenticator = self.platform_server.authenticator
        ok, _ = authenticator.authenticate(dict(self.headers))
        if not ok:
            challenge = authenticator.challenge_header()
            self.send_response(401)
            if challenge:
                self.send_header("WWW-Authenticate", challenge)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_security_headers()
            err_body = json.dumps({"error": "Unauthorized", "message": "Authentication required."}).encode("utf-8")
            self.send_header("Content-Length", str(len(err_body)))
            self.end_headers()
            self.wfile.write(err_body)
            return False
        return True

    def do_GET(self) -> None:
        if not self._check_auth():
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        state: PlatformState = self.platform_server.platform_state

        # 1. UI Root
        if path in {"/", "/app"}:
            try:
                html = state.get_html_report()
                self._send_text(200, html, "text/html; charset=utf-8")
            except Exception as exc:
                self._send_json(500, {"error": "InternalServerError", "message": str(exc)})
            return

        # 2. REST API v1
        if path == "/api/v1/health":
            last_dt = (
                datetime.fromtimestamp(state.last_scan_timestamp, tz=timezone.utc).isoformat()
                if state.last_scan_timestamp else None
            )
            self._send_json(200, {
                "status": "ok",
                "version": __version__,
                "repo": state.root.name,
                "read_only": state.config.server.read_only,
                "auth_mode": state.config.server.auth_mode,
                "last_scan": last_dt,
            })
            return

        if path == "/api/v1/config":
            self._send_json(200, state.config.safe_dict())
            return

        if path == "/api/v1/summary":
            analysis = state.get_analysis()
            graph = analysis.graph
            self._send_json(200, {
                "name": analysis.repo.name,
                "commit": analysis.repo.commit,
                "branch": analysis.repo.branch,
                "nodes_count": len(graph.nodes),
                "edges_count": len(graph.edges),
                "findings_count": len(graph.findings),
                "features_count": len(graph.features),
                "severities": _sev_counts(graph),
                "languages": graph.meta.get("languages", {}),
            })
            return

        if path == "/api/v1/graph":
            analysis = state.get_analysis()
            self._send_text(200, render_json(analysis.graph), "application/json; charset=utf-8")
            return

        if path == "/api/v1/sarif":
            analysis = state.get_analysis()
            self._send_text(200, render_sarif(analysis.graph), "application/json; charset=utf-8")
            return

        if path == "/api/v1/findings":
            analysis = state.get_analysis()
            findings: list[Finding] = list(analysis.graph.findings)

            # Filtering query parameters
            sev_filter = query.get("severity")
            if sev_filter:
                allowed_sevs = {s.lower() for s in sev_filter}
                findings = [f for f in findings if f.severity.lower() in allowed_sevs]

            cat_filter = query.get("category")
            if cat_filter:
                allowed_cats = {c.lower() for c in cat_filter}
                findings = [f for f in findings if f.category.lower() in allowed_cats]

            min_conf = query.get("min_confidence")
            if min_conf:
                try:
                    conf_floor = float(min_conf[0])
                    findings = [f for f in findings if f.confidence >= conf_floor]
                except ValueError:
                    pass

            findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.id))
            self._send_json(200, {
                "total": len(findings),
                "findings": [f.to_dict() for f in findings],
            })
            return

        if path == "/api/v1/diagram":
            analysis = state.get_analysis()
            detail = query.get("detail", ["architecture"])[0]
            if detail in {"high-level", "overview"}:
                hla = build_high_level_architecture(state.root, analysis.graph)
                diagram_text = render_mermaid_highlevel(
                    hla,
                    direction=state.config.analysis.diagram_direction,
                    theme=state.config.analysis.diagram_theme,
                )
            else:
                diagram_text = render_mermaid(
                    analysis.graph,
                    detail=detail,
                    direction=state.config.analysis.diagram_direction,
                    theme=state.config.analysis.diagram_theme,
                )
            self._send_text(200, diagram_text, "text/plain; charset=utf-8")
            return

        # 404 Not Found
        self._send_json(404, {"error": "NotFound", "message": f"Endpoint '{path}' does not exist."})

    def do_POST(self) -> None:
        if not self._check_auth():
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        state: PlatformState = self.platform_server.platform_state

        if path == "/api/v1/scan":
            if state.config.server.read_only:
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; scans cannot be triggered via API.",
                })
                return

            try:
                result = state.rescan()
                self._send_json(200, {
                    "status": "success",
                    "message": "Repository re-scanned successfully.",
                    "nodes_count": len(result.graph.nodes),
                    "edges_count": len(result.graph.edges),
                    "findings_count": len(result.graph.findings),
                })
            except Exception as exc:
                self._send_json(500, {"error": "ScanFailed", "message": str(exc)})
            return

        self._send_json(404, {"error": "NotFound", "message": f"Endpoint '{path}' does not exist."})

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs to keep CLI/daemon stdout clean
        pass


# ------------------------------------------------------------------- Server Construction
def create_server(root: Path, config: SecdiagramConfig | None = None) -> PlatformHTTPServer:
    """Create and configure a PlatformHTTPServer instance."""
    resolved_root = root.resolve()
    cfg = config or load_config(resolved_root)
    state = PlatformState(resolved_root, cfg)

    # Initialize authenticator
    if cfg.server.is_auth_enabled():
        assert cfg.server.auth_username is not None
        assert cfg.server.auth_password is not None
        authenticator: Authenticator = BasicAuthenticator(
            username=cfg.server.auth_username,
            password=cfg.server.auth_password,
        )
    else:
        authenticator = NoOpAuthenticator()

    server_address = (cfg.server.host, cfg.server.port)
    server = PlatformHTTPServer(server_address, SecdiagramRequestHandler)
    server.platform_state = state
    server.authenticator = authenticator
    return server


def serve(
    root: Path,
    host: str | None = None,
    port: int | None = None,
    auth_username: str | None = None,
    auth_password: str | None = None,
    read_only: bool = False,
    config_path: Path | None = None,
) -> int:
    """Run the platform server daemon."""
    cfg = load_config(root, config_path)
    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port
    if auth_username:
        cfg.server.auth_username = auth_username
    if auth_password:
        cfg.server.auth_password = auth_password
    if read_only:
        cfg.server.read_only = True

    if cfg.server.auth_username and cfg.server.auth_password:
        cfg.server.auth_mode = "basic"

    server = create_server(root, cfg)
    addr = server.server_address
    bind_host = addr[0].decode("ascii") if isinstance(addr[0], bytes) else str(addr[0])
    bind_port = int(addr[1])
    auth_status = "Basic Auth (active)" if cfg.server.is_auth_enabled() else "None (public local)"

    print(f"secdiagram platform listening on http://{bind_host}:{bind_port}", file=sys.stderr)
    print(f"  Repository: {root.resolve()}", file=sys.stderr)
    print(f"  Authentication: {auth_status}", file=sys.stderr)
    print(f"  REST API: http://{bind_host}:{bind_port}/api/v1/health", file=sys.stderr)
    print(f"  Web UI: http://{bind_host}:{bind_port}/", file=sys.stderr)
    print("Press Ctrl+C to terminate.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down secdiagram platform...", file=sys.stderr)
        server.server_close()
    return 0
