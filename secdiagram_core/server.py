"""Deterministic, secure, stdlib-only platform HTTP server and REST API for secdiagram."""

from __future__ import annotations

import abc
import base64
import ipaddress
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
from .redaction import redact_secrets, sanitize_path_text
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


def _is_loopback_host(host: str) -> bool:
    """Return True only for literal loopback bind addresses or ``localhost``."""
    value = (host or "").strip().strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_within(path: Path, parent: Path) -> bool:
    """Return True when *path* is *parent* or lives underneath it."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


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
    """Permissive authenticator for explicit, loopback-only development mode."""

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


# ------------------------------------------------------------------- Audit Logging
class AuditLogger:
    """Append-only structured audit log for security-relevant events.

    Secrets are redacted and repository paths are normalised before writing.
    Logging failures are swallowed so auditing can never take down the server.
    """

    def __init__(self, destination: str | None, root: Path) -> None:
        self.root = root.resolve()
        self._lock = threading.Lock()
        self._path: Path | None = None
        self._stderr = destination is None or destination == "-"
        if destination and destination != "-":
            candidate = Path(destination).expanduser()
            if not candidate.is_absolute():
                candidate = self.root / candidate
            self._path = candidate
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                self._path = None

    def log(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
        }
        for key, value in fields.items():
            text = sanitize_path_text(redact_secrets(str(value)), self.root)
            record[key] = text[:512]
        line = json.dumps(record, sort_keys=True, ensure_ascii=True)
        with self._lock:
            try:
                if self._path is not None:
                    with self._path.open("a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                elif self._stderr:
                    print(line, file=sys.stderr, flush=True)
            except OSError:
                pass


# ------------------------------------------------------------------- Rate Limiting
class RateLimiter:
    """Thread-safe sliding-window request rate limiter keyed by client identity."""

    def __init__(self, limit_per_minute: int, window_seconds: float = 60.0) -> None:
        self.limit = max(0, int(limit_per_minute))
        self.window = max(1.0, float(window_seconds))
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def check(self, key: str) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds). A non-positive limit disables limiting."""
        if self.limit <= 0:
            return True, 0.0
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            events = [stamp for stamp in self._events.get(key, ()) if stamp > cutoff]
            if len(events) >= self.limit:
                retry_after = max(0.0, self.window - (now - events[0]))
                self._events[key] = events
                return False, retry_after
            events.append(now)
            self._events[key] = events
            if now - self._last_prune > self.window:
                for stale_key in list(self._events):
                    kept = [stamp for stamp in self._events[stale_key] if stamp > cutoff]
                    if kept:
                        self._events[stale_key] = kept
                    else:
                        del self._events[stale_key]
                self._last_prune = now
            return True, 0.0


class ScanManager:
    """Bounded concurrent-scan gate for API-triggered rescans."""

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)

    def try_acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        try:
            self._semaphore.release()
        except ValueError:
            pass


# ------------------------------------------------------------------- Platform State
class PlatformState:
    """Thread-safe state holding the latest analysis result, cache, and settings."""

    def __init__(self, root: Path, config: SecdiagramConfig, allowed_scan_roots: list[Path]) -> None:
        self.root = root.resolve()
        self.config = config
        self.allowed_scan_roots = allowed_scan_roots
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
    audit: AuditLogger
    rate_limiter: RateLimiter
    scan_manager: ScanManager


class SecdiagramRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing REST API endpoints and modular UI hosting."""

    server_version = f"secdiagram-platform/{__version__}"

    @property
    def platform_server(self) -> PlatformHTTPServer:
        return cast(PlatformHTTPServer, self.server)

    def send_security_headers(self) -> None:
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)

    def _send_json(
        self,
        status_code: int,
        data: Any,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for header, value in extra_headers.items():
                self.send_header(header, value)
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

    def _client_key(self) -> str:
        address = self.client_address
        if isinstance(address, tuple) and address:
            return str(address[0])
        return "unknown"

    def _request_path(self) -> str:
        return urlsplit(self.path).path or "/"

    def _check_rate_limit(self) -> bool:
        allowed, retry_after = self.platform_server.rate_limiter.check(self._client_key())
        if allowed:
            return True
        self.platform_server.audit.log(
            "rate_limited",
            remote=self._client_key(),
            path=self._request_path(),
        )
        self._send_json(
            429,
            {"error": "TooManyRequests", "message": "Rate limit exceeded. Retry later."},
            extra_headers={"Retry-After": str(max(1, int(retry_after + 0.5)))},
        )
        return False

    def _auth_username(self) -> str:
        raw = self.headers.get("authorization") or self.headers.get("Authorization") or ""
        if not raw.startswith("Basic "):
            return ""
        try:
            decoded = base64.b64decode(raw[6:].strip()).decode("utf-8")
            return decoded.split(":", 1)[0] if ":" in decoded else ""
        except Exception:
            return ""

    def _check_auth(self) -> bool:
        authenticator: Authenticator = self.platform_server.authenticator
        ok, identity = authenticator.authenticate(dict(self.headers))
        if ok:
            return True
        self.platform_server.audit.log(
            "auth_failure",
            remote=self._client_key(),
            path=self._request_path(),
            user=self._auth_username(),
            credential_present=bool(self.headers.get("Authorization")),
        )
        challenge = authenticator.challenge_header()
        body = json.dumps({"error": "Unauthorized", "message": "Authentication required."})
        err_body = body.encode("utf-8")
        self.send_response(401)
        if challenge:
            self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(err_body)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(err_body)
        return False

    def _read_json_body(self) -> tuple[bool, dict[str, Any]]:
        """Read a bounded JSON object request body.

        Returns ``(ok, payload)``; on failure a response has already been sent.
        """
        max_bytes = self.platform_server.platform_state.config.server.max_request_bytes
        if self.headers.get("Transfer-Encoding"):
            self.platform_server.audit.log(
                "request_rejected", remote=self._client_key(), path=self._request_path(), reason="chunked_body"
            )
            self._send_json(411, {"error": "LengthRequired", "message": "Chunked request bodies are not supported."})
            return False, {}
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return True, {}
        try:
            length = int(raw_length)
        except ValueError:
            self._send_json(400, {"error": "BadRequest", "message": "Invalid Content-Length header."})
            return False, {}
        if length < 0 or length > max_bytes:
            self.platform_server.audit.log(
                "request_rejected", remote=self._client_key(), path=self._request_path(), reason="body_too_large"
            )
            self._send_json(
                413,
                {"error": "PayloadTooLarge", "message": "Request body exceeds the configured limit."},
            )
            return False, {}
        if length == 0:
            return True, {}
        raw = self.rfile.read(length)
        if not raw.strip():
            return True, {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "BadRequest", "message": "Request body must be valid JSON."})
            return False, {}
        if not isinstance(data, dict):
            self._send_json(400, {"error": "BadRequest", "message": "Request body must be a JSON object."})
            return False, {}
        return True, data

    def do_GET(self) -> None:
        if not self._check_rate_limit():
            return
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
                self.platform_server.audit.log("report_failed", remote=self._client_key(), error=type(exc).__name__)
                self._send_json(500, {"error": "InternalServerError", "message": "The report could not be generated."})
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
            self.platform_server.audit.log("sarif_download", remote=self._client_key(), user=self._auth_username() or "anonymous")
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
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        state: PlatformState = self.platform_server.platform_state

        if path == "/api/v1/scan":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return

            requested = body.get("path") or body.get("root") or body.get("dir")
            if requested is not None:
                if not isinstance(requested, str) or not requested.strip():
                    self._send_json(400, {"error": "BadRequest", "message": "Scan path must be a non-empty string."})
                    return

                root_text = str(state.root.resolve())
                requested_expanded = str(Path(requested).expanduser())
                requested_normalized = str(Path(requested_expanded))

                if requested_normalized != root_text:
                    self.platform_server.audit.log(
                        "scan_rejected",
                        remote=self._client_key(),
                        path=requested,
                        reason="path_not_allowlisted",
                    )
                    self._send_json(
                        403,
                        {
                            "error": "Forbidden",
                            "message": "The requested scan path is not allowlisted.",
                        },
                    )
                    return

                try:
                    candidate = Path(requested_normalized).resolve()
                except (OSError, ValueError):
                    candidate = None
                allowlisted = (
                    candidate is not None
                    and candidate == state.root
                    and any(_is_within(candidate, allowed) for allowed in state.allowed_scan_roots)
                )
                if not allowlisted:
                    self.platform_server.audit.log(
                        "scan_rejected",
                        remote=self._client_key(),
                        path=requested,
                        reason="path_not_allowlisted",
                    )
                    self._send_json(
                        403,
                        {
                            "error": "Forbidden",
                            "message": "The requested scan path is not allowlisted.",
                        },
                    )
                    return

            if state.config.server.read_only:
                self.platform_server.audit.log(
                    "scan_rejected", remote=self._client_key(), user=self._auth_username() or "anonymous",
                    reason="read_only",
                )
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; scans cannot be triggered via API.",
                })
                return

            self.platform_server.audit.log(
                "scan_requested", remote=self._client_key(), user=self._auth_username() or "anonymous"
            )
            if not self.platform_server.scan_manager.try_acquire():
                self.platform_server.audit.log(
                    "scan_rejected", remote=self._client_key(), reason="concurrency_limit"
                )
                self._send_json(
                    429,
                    {"error": "TooManyRequests", "message": "Another scan is already running. Retry later."},
                    extra_headers={"Retry-After": "5"},
                )
                return
            try:
                result = state.rescan()
                self.platform_server.audit.log(
                    "scan_succeeded",
                    remote=self._client_key(),
                    nodes=len(result.graph.nodes),
                    edges=len(result.graph.edges),
                    findings=len(result.graph.findings),
                )
                self._send_json(200, {
                    "status": "success",
                    "message": "Repository re-scanned successfully.",
                    "nodes_count": len(result.graph.nodes),
                    "edges_count": len(result.graph.edges),
                    "findings_count": len(result.graph.findings),
                })
            except Exception as exc:
                self.platform_server.audit.log(
                    "scan_failed", remote=self._client_key(), error=type(exc).__name__
                )
                self._send_json(500, {"error": "ScanFailed", "message": "The scan could not be completed."})
            finally:
                self.platform_server.scan_manager.release()
            return

        self._send_json(404, {"error": "NotFound", "message": f"Endpoint '{path}' does not exist."})

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs to keep CLI/daemon stdout clean
        pass


# ------------------------------------------------------------------- Server Construction
def _resolve_scan_roots(root: Path, configured: list[str]) -> list[Path]:
    """Resolve the configured scan allowlist and require the served root to be inside it."""
    entries = configured or [str(root)]
    resolved: list[Path] = []
    for entry in entries:
        candidate = Path(entry).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved.append(candidate.resolve())
        except OSError:
            continue
    if not resolved:
        resolved = [root.resolve()]
    if not any(_is_within(root.resolve(), allowed) for allowed in resolved):
        raise ValueError("Served repository is not inside the configured scan allowlist.")
    return resolved


def create_server(root: Path, config: SecdiagramConfig | None = None) -> PlatformHTTPServer:
    """Create and configure a PlatformHTTPServer instance."""
    resolved_root = root.resolve()
    cfg = config or load_config(resolved_root)

    if not cfg.server.is_auth_enabled():
        if not cfg.server.insecure_no_auth:
            raise ValueError(
                "Authentication is required. Configure HTTP Basic Auth credentials "
                "(--server-user/--server-pass or SECDIAGRAM_AUTH_USER/SECDIAGRAM_AUTH_PASS), "
                "or pass --insecure-no-auth for loopback-only development."
            )
        if not _is_loopback_host(cfg.server.host):
            raise ValueError(
                "Refusing to bind a non-loopback host without authentication. "
                "Configure credentials or bind to 127.0.0.1."
            )

    allowed_scan_roots = _resolve_scan_roots(resolved_root, cfg.server.scan_roots)
    state = PlatformState(resolved_root, cfg, allowed_scan_roots)
    audit = AuditLogger(cfg.server.audit_log, resolved_root)

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
    server.audit = audit
    server.rate_limiter = RateLimiter(cfg.server.rate_limit_per_minute)
    server.scan_manager = ScanManager(cfg.server.max_concurrent_scans)
    return server


def serve(
    root: Path,
    host: str | None = None,
    port: int | None = None,
    auth_username: str | None = None,
    auth_password: str | None = None,
    read_only: bool = False,
    config_path: Path | None = None,
    insecure_no_auth: bool = False,
    max_request_bytes: int | None = None,
    rate_limit_per_minute: int | None = None,
    max_concurrent_scans: int | None = None,
    scan_roots: list[str] | None = None,
    audit_log: str | None = None,
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
    if insecure_no_auth:
        cfg.server.insecure_no_auth = True
    if max_request_bytes is not None:
        cfg.server.max_request_bytes = max_request_bytes
    if rate_limit_per_minute is not None:
        cfg.server.rate_limit_per_minute = rate_limit_per_minute
    if max_concurrent_scans is not None:
        cfg.server.max_concurrent_scans = max_concurrent_scans
    if scan_roots is not None:
        cfg.server.scan_roots = list(scan_roots)
    if audit_log is not None:
        cfg.server.audit_log = audit_log

    if cfg.server.auth_username and cfg.server.auth_password:
        cfg.server.auth_mode = "basic"

    server = create_server(root, cfg)
    addr = server.server_address
    bind_host = addr[0].decode("ascii") if isinstance(addr[0], bytes) else str(addr[0])
    bind_port = int(addr[1])
    auth_status = "Basic Auth (active)" if cfg.server.is_auth_enabled() else "None (insecure loopback development mode)"

    server.audit.log(
        "server_started",
        host=bind_host,
        port=bind_port,
        auth_mode=cfg.server.auth_mode,
        read_only=cfg.server.read_only,
        root=str(root.resolve()),
    )
    if not _is_loopback_host(bind_host):
        print(
            "WARNING: secdiagram platform is bound to a non-loopback interface; "
            "ensure a trusted reverse proxy, TLS, and authentication are in place.",
            file=sys.stderr,
        )

    print(f"secdiagram platform listening on http://{bind_host}:{bind_port}", file=sys.stderr)
    print(f"  Repository: {root.name}", file=sys.stderr)
    print(f"  Authentication: {auth_status}", file=sys.stderr)
    print(f"  REST API: http://{bind_host}:{bind_port}/api/v1/health", file=sys.stderr)
    print(f"  Web UI: http://{bind_host}:{bind_port}/", file=sys.stderr)
    print("Press Ctrl+C to terminate.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down secdiagram platform...", file=sys.stderr)
    finally:
        server.audit.log("server_stopped", host=bind_host, port=bind_port)
        server.server_close()
    return 0
