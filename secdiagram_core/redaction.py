"""Best-effort redaction helpers for secrets and host paths.

These helpers are applied to text that leaves the process through audit logs,
API error responses, and embedded HTML source snippets. They are intentionally
conservative: they target well-known credential shapes and sensitive
key/value assignments rather than every token-like string.
"""

from __future__ import annotations

import re
from pathlib import Path

REDACTED = "[REDACTED]"

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"]?)"
    r"([^\s'\";,]{6,})"
)
_BEARER_RE = re.compile(r"(?i)(\bauthorization\b\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{16,})")


def redact_secrets(text: str) -> str:
    """Return *text* with recognized credentials replaced by a marker."""
    if not text:
        return text
    cleaned = _PRIVATE_KEY_RE.sub(REDACTED, text)
    for pattern in _TOKEN_PATTERNS:
        cleaned = pattern.sub(REDACTED, cleaned)
    cleaned = _BEARER_RE.sub(lambda m: m.group(1) + REDACTED, cleaned)
    cleaned = _ASSIGNMENT_RE.sub(lambda m: m.group(1) + REDACTED, cleaned)
    return cleaned


def sanitize_path_text(text: str, root: Path | None = None) -> str:
    """Remove a repository root prefix from *text* and hide other absolute paths."""
    if not text:
        return text
    cleaned = text
    if root is not None:
        try:
            cleaned = cleaned.replace(str(root.resolve()), ".")
        except OSError:
            pass
    if len(cleaned) >= 3 and cleaned[1:3] in {":\\", ":/"} and cleaned[0].isalpha():
        return "[external-path]"
    if cleaned.startswith("\\\\"):
        return "[external-path]"
    return cleaned


def redact_snippet_line(line: str) -> str:
    """Redact secrets from a single source line before embedding it in a report."""
    return redact_secrets(line)
