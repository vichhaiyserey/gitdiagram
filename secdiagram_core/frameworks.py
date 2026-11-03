"""Framework-aware annotation of Python callables (routes, tasks, CLI, auth)."""

from __future__ import annotations

import re

from .ast_index import FileIndex

ROUTE_RE = re.compile(
    r"^(?P<obj>[\w.]+)\.(?P<method>get|post|put|patch|delete|head|options|websocket|route|api_route)\s*\((?P<args>.*)\)$",
    re.S,
)
STRING_RE = re.compile(r"""(['"])(.*?)\1""", re.S)
METHODS_RE = re.compile(r"methods\s*=\s*[\[(](?P<body>[^\])]*)[\])]", re.S)
AUTH_WORDS = (
    "login_required",
    "requires_auth",
    "permission_required",
    "jwt_required",
    "authenticated",
    "auth_required",
    "requires_permission",
    "security",
)
CLI_WORDS = ("click.command", "click.group", "typer", ".command(", "argparse")


def _first_string(text: str) -> str | None:
    match = STRING_RE.search(text)
    return match.group(2) if match else None


def _methods(text: str, default: str) -> list[str]:
    match = METHODS_RE.search(text)
    if not match:
        return [default]
    found = [item.upper() for _quote, item in STRING_RE.findall(match.group("body"))]
    return found or [default]


def annotate(indexes: dict[str, FileIndex]) -> None:
    for index in indexes.values():
        for definition in index.defs:
            if definition.kind not in {"function", "method"}:
                continue
            routes: list[dict[str, str]] = []
            tags: list[str] = []
            role: str | None = None
            for decorator in definition.decorators:
                lowered = decorator.lower()
                if any(word in lowered for word in AUTH_WORDS):
                    tags.append("auth")
                if "depends(" in lowered and any(word in lowered for word in ("auth", "user", "token", "security")):
                    tags.append("auth_dependency")
                if lowered == "shared_task" or lowered.endswith(".task") or lowered.startswith("shared_task("):
                    role = role or "task"
                if any(word in lowered for word in CLI_WORDS):
                    role = role or "cli"
                match = ROUTE_RE.match(decorator)
                if not match:
                    if "api_view(" in lowered:
                        methods = _methods(decorator, "GET")
                        routes.append({"method": ",".join(methods), "path": ""})
                        role = "endpoint"
                    continue
                method = match.group("method")
                args = match.group("args")
                path = _first_string(args) or ""
                if method == "websocket":
                    routes.append({"method": "WS", "path": path})
                    role = "endpoint"
                elif method in {"route", "api_route"}:
                    for detected in _methods(args, "GET"):
                        routes.append({"method": detected, "path": path})
                    role = "endpoint"
                else:
                    routes.append({"method": method.upper(), "path": path})
                    role = "endpoint"
            if routes:
                definition.routes = routes
                definition.kind = "endpoint"
            elif role:
                definition.kind = role
            if tags:
                definition.tags = sorted(set(definition.tags + tags))
