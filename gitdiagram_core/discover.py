"""Repository discovery that respects git's ignored-file rules when possible."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".gitdiagram",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    ".eggs",
    ".idea",
    ".vscode",
    ".next",
    ".cache",
    "target",
}

SKIP_FILE_SUFFIXES = (
    ".pyc",
    ".pyo",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".lock",
    ".min.js",
)

IAC_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}
IAC_SUFFIXES = (".tf", ".yaml", ".yml")


@dataclass(slots=True)
class RepoInfo:
    root: Path
    name: str
    rel_files: list[str] = field(default_factory=list)
    is_git: bool = False
    commit: str | None = None
    branch: str | None = None
    dirty: bool = False
    skipped: list[str] = field(default_factory=list)

    @property
    def python_files(self) -> list[str]:
        return [path for path in self.rel_files if path.endswith(".py")]

    @property
    def iac_files(self) -> list[str]:
        out = []
        for path in self.rel_files:
            lower = path.lower()
            name = lower.rsplit("/", 1)[-1]
            if name.startswith("dockerfile") or name in IAC_NAMES:
                out.append(path)
            elif lower.endswith(IAC_SUFFIXES) and (
                "/.github/workflows/" in f"/{lower}"
                or "/k8s/" in f"/{lower}"
                or "/kubernetes/" in f"/{lower}"
                or "/manifests/" in f"/{lower}"
                or "/deploy/" in f"/{lower}"
                or lower.endswith(".tf")
            ):
                out.append(path)
        return out


def _git(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def _is_git_root(root: Path) -> bool:
    return (root / ".git").exists()


def _matches(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel.rsplit("/", 1)[-1], pattern) for pattern in patterns)


def _keep(rel: str, include: list[str], exclude: list[str]) -> bool:
    if include and not _matches(rel, include):
        return False
    if exclude and _matches(rel, exclude):
        return False
    return True


def _git_files(root: Path) -> list[str] | None:
    raw = _git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if raw is None:
        return None
    files = [item.replace("\\", "/") for item in raw.split("\0") if item]
    return sorted(set(files))


def _walk_files(root: Path) -> tuple[list[str], list[str]]:
    files: list[str] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in SKIP_DIRS and name != ".git"
        )
        for name in sorted(filenames):
            if name.endswith(SKIP_FILE_SUFFIXES):
                continue
            absolute = Path(dirpath) / name
            if absolute.is_symlink():
                try:
                    resolved = absolute.resolve()
                    if not resolved.is_relative_to(root.resolve()):
                        skipped.append(f"symlink outside root: {name}")
                        continue
                except (ValueError, OSError):
                    skipped.append(f"unresolvable symlink: {name}")
                    continue
            try:
                rel = absolute.relative_to(root).as_posix()
            except ValueError:
                continue
            files.append(rel)
    return sorted(set(files)), skipped


def discover(root: str | Path, include: list[str] | None = None, exclude: list[str] | None = None) -> RepoInfo:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"directory does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")

    include = [item.replace("\\", "/") for item in (include or [])]
    exclude = [item.replace("\\", "/") for item in (exclude or [])]
    is_git = _is_git_root(root_path)
    skipped: list[str] = []

    if is_git:
        found = _git_files(root_path)
        if found is None:
            found, skipped = _walk_files(root_path)
            is_git = False
    else:
        found, skipped = _walk_files(root_path)

    rel_files = []
    for rel in found:
        if rel.endswith(SKIP_FILE_SUFFIXES):
            continue
        if any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
            continue
        if _keep(rel, include, exclude):
            rel_files.append(rel)

    commit = branch = None
    dirty = False
    if is_git:
        commit = (_git(root_path, "rev-parse", "--short=12", "HEAD") or "").strip() or None
        branch = (_git(root_path, "rev-parse", "--abbrev-ref", "HEAD") or "").strip() or None
        dirty = bool((_git(root_path, "status", "--porcelain") or "").strip())

    return RepoInfo(
        root=root_path,
        name=root_path.name,
        rel_files=sorted(set(rel_files)),
        is_git=is_git,
        commit=commit,
        branch=branch,
        dirty=dirty,
        skipped=skipped,
    )
