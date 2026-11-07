"""Deterministic, content-addressed cache for per-file index payloads.

Cache entries are keyed by the SHA-256 digest of the source bytes, so an
unchanged file is reused even when the repository commit changes. The commit
and tool version are recorded in each envelope for traceability, and the cache
path is namespaced by schema/tool version to invalidate old payload shapes.

Only plain JSON is read or written: caches are never unpickled, so a cache
directory cannot execute code or smuggle objects into the analyzer.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from . import __version__

CACHE_SCHEMA = 1
MAX_CACHE_BYTES = 96 * 1024 * 1024
HASH_CHUNK = 1024 * 1024
AUTO_PARALLEL_THRESHOLD = 128
MAX_WORKERS = 32


def resolve_jobs(requested: int, task_count: int) -> int:
    """Resolve a CLI jobs value into a safe worker count.

    ``0`` means auto: stay serial on small repositories and use a bounded
    fraction of the CPU otherwise. ``1`` forces serial execution.
    """
    if task_count <= 1 or requested == 1:
        return 1
    if requested <= 0:
        if task_count < AUTO_PARALLEL_THRESHOLD:
            return 1
        requested = min(8, os.cpu_count() or 1)
    return max(1, min(requested, MAX_WORKERS, task_count))


def file_digest(path: Path) -> str | None:
    """Return the SHA-256 of a file, or ``None`` when it cannot be read."""
    digest = hashlib.sha256(usedforsecurity=False)
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(HASH_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


class IndexCache:
    """Small cache facade with deterministic, atomic writes and soft failures."""

    def __init__(self, directory: Path | None, namespace: str, commit: str | None = None) -> None:
        safe_namespace = "".join(ch for ch in namespace if ch.isalnum() or ch in "-_") or "index"
        self.namespace = safe_namespace
        self.commit = commit or "nogit"
        self.directory = (
            directory / f"{self.namespace}-v{CACHE_SCHEMA}-{__version__}"
            if directory is not None
            else None
        )
        self.hits = 0
        self.misses = 0
        self.writes = 0
        self.errors = 0

    @property
    def enabled(self) -> bool:
        return self.directory is not None

    def entry_path(self, rel_path: str, digest: str) -> Path | None:
        if self.directory is None:
            return None
        key = hashlib.sha256(
            f"{self.namespace}\0{rel_path}\0{digest}".encode(),
            usedforsecurity=False,
        ).hexdigest()
        return self.directory / key[:2] / f"{key}.json"

    def load(self, rel_path: str, digest: str) -> dict[str, Any] | None:
        if self.directory is None:
            return None
        path = self.entry_path(rel_path, digest)
        if path is None:
            return None
        try:
            if path.stat().st_size > MAX_CACHE_BYTES:
                self.misses += 1
                return None
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            self.misses += 1
            return None
        if not isinstance(envelope, dict):
            self.misses += 1
            return None
        if (
            envelope.get("schema") != CACHE_SCHEMA
            or envelope.get("tool") != __version__
            or envelope.get("namespace") != self.namespace
            or envelope.get("path") != rel_path
            or envelope.get("digest") != digest
        ):
            self.misses += 1
            return None
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            self.misses += 1
            return None
        self.hits += 1
        return payload

    def save(self, rel_path: str, digest: str, payload: dict[str, Any]) -> None:
        if self.directory is None:
            return
        path = self.entry_path(rel_path, digest)
        if path is None:
            return
        envelope = {
            "schema": CACHE_SCHEMA,
            "tool": __version__,
            "namespace": self.namespace,
            "path": rel_path,
            "digest": digest,
            "commit": self.commit,
            "payload": payload,
        }
        try:
            rendered = json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        except (TypeError, ValueError):
            self.errors += 1
            return
        if len(rendered.encode("utf-8")) > MAX_CACHE_BYTES:
            self.errors += 1
            return
        tmp = path.with_name(f".{digest}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(rendered, encoding="utf-8", newline="\n")
            os.replace(tmp, path)
        except OSError:
            self.errors += 1
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            return
        self.writes += 1

    def summary(self) -> dict[str, int | bool | str]:
        """Return run-local stats for stderr/telemetry (never serialized to output)."""
        return {
            "enabled": self.enabled,
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "errors": self.errors,
            "namespace": self.namespace,
        }
