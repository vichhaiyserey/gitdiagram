"""Best-effort infrastructure-as-code inspection (Docker, Compose, CI, K8s, Terraform)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .discover import RepoInfo
from .model import Finding, Graph, Loc, Node, stable_id

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class IacFinding:
    category: str
    severity: str
    title: str
    message: str
    path: str
    line: int
    cwe: str | None
    recommendation: str
    confidence: float = 0.7


@dataclass
class IacResult:
    nodes: list[Node] = field(default_factory=list)
    findings: list[IacFinding] = field(default_factory=list)


def _node(path: str, name: str, kind: str, line: int, attrs: dict) -> Node:
    return Node(
        id=stable_id("infra", path, name),
        kind=kind,
        name=name,
        qualname=f"infra:{path}#{name}",
        path=path,
        line=line,
        feature="infrastructure",
        doc=None,
        attrs=attrs,
    )


def _safe_read_text(root: Path, path: str, max_size: int = 5 * 1024 * 1024) -> str | None:
    target = root / path
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > max_size:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None


def _dockerfile(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    base_images: list[str] = []
    user: str | None = None
    exposed: list[str] = []
    node = _node(path, path.rsplit("/", 1)[-1], "infra", 1, {"type": "container_image"})
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        upper = line.upper()
        if upper.startswith("FROM "):
            image = line.split(None, 1)[1].split(" AS ")[0].strip()
            base_images.append(image)
            if image.endswith(":latest") or ":" not in image.split("@")[0]:
                result.findings.append(
                    IacFinding(
                        "supply-chain",
                        "low",
                        "Unpinned container base image",
                        f"`{image}` is not pinned to a digest or version at {path}:{number}.",
                        path,
                        number,
                        "CWE-1357",
                        "Pin base images to a version and digest; rebuild on a schedule.",
                    )
                )
        elif upper.startswith("USER "):
            user = line.split(None, 1)[1].strip()
        elif upper.startswith("EXPOSE "):
            exposed.extend(line.split(None, 1)[1].split())
        elif upper.startswith("ADD ") and ("http://" in line or "https://" in line):
            result.findings.append(
                IacFinding(
                    "supply-chain",
                    "medium",
                    "Remote ADD instruction",
                    f"Remote fetch via ADD at {path}:{number}.",
                    path,
                    number,
                    "CWE-829",
                    "Use COPY with verified artifacts and checksums.",
                )
            )
        if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", line):
            result.findings.append(
                IacFinding(
                    "supply-chain",
                    "high",
                    "Remote script piped to shell",
                    f"Unverified remote script execution at {path}:{number}.",
                    path,
                    number,
                    "CWE-829",
                    "Download, verify a checksum/signature, then execute.",
                )
            )
        env_match = re.match(r"(?i)ENV\s+([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(.+)", line)
        if env_match and re.search(r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)", env_match.group(1)):
            value = env_match.group(2).strip().strip('"')
            if value and value.lower() not in {"changeme", "example", "none", "null"}:
                result.findings.append(
                    IacFinding(
                        "secret",
                        "high",
                        "Secret in container image environment",
                        f"`{env_match.group(1)}` is baked into the image at {path}:{number}.",
                        path,
                        number,
                        "CWE-798",
                        "Inject secrets at runtime from a secret manager.",
                    )
                )
    if user is None or user.lower() in {"root", "0"}:
        result.findings.append(
            IacFinding(
                "container",
                "medium",
                "Container runs as root",
                f"No non-root USER is set in {path}.",
                path,
                1,
                "CWE-250",
                "Create an unprivileged user and set `USER <name>`.",
            )
        )
    node.attrs.update({"base_images": base_images, "user": user or "root", "exposed_ports": exposed})
    result.nodes.append(node)
    return result


def _compose(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    service: str | None = None
    service_attrs: dict[str, dict] = {}
    service_nodes: dict[str, Node] = {}
    in_services = False
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent == 0:
            in_services = stripped == "services:"
            service = None
            continue
        if not in_services:
            continue
        if indent == 2 and stripped.endswith(":"):
            service = stripped[:-1]
            service_attrs[service] = {}
            service_nodes[service] = _node(path, service, "service", number, {"type": "compose_service"})
            result.nodes.append(service_nodes[service])
            continue
        if service is None:
            continue
        attrs = service_attrs[service]
        if stripped.startswith("image:"):
            attrs["image"] = stripped.split(":", 1)[1].strip().strip("'\"")
            if ":" not in attrs["image"] or attrs["image"].endswith(":latest"):
                result.findings.append(
                    IacFinding(
                        "supply-chain",
                        "low",
                        "Unpinned container image",
                        f"Service `{service}` uses an unpinned image at {path}:{number}.",
                        path,
                        number,
                        "CWE-1357",
                        "Pin the image tag/digest.",
                    )
                )
        for key, expected, severity, cwe, title in (
            ("privileged", "true", "critical", "CWE-250", "Privileged container"),
            ("network_mode", "host", "high", "CWE-284", "Host network mode"),
            ("pid", "host", "high", "CWE-250", "Host PID namespace"),
        ):
            if not stripped.startswith(key + ":"):
                continue
            value_text = stripped.split(":", 1)[1].strip().strip("'\"").lower()
            if value_text != expected:
                continue
            attrs[key] = value_text
            result.findings.append(
                IacFinding(
                    "container",
                    severity,
                    title,
                    f"Service `{service}` enables {key} at {path}:{number}.",
                    path,
                    number,
                    cwe,
                    "Remove the elevated setting or isolate the workload.",
                )
            )
        if "/var/run/docker.sock" in stripped:
            attrs["docker_socket"] = True
            result.findings.append(
                IacFinding(
                    "container",
                    "high",
                    "Docker socket mounted",
                    f"Service `{service}` mounts the Docker socket at {path}:{number}.",
                    path,
                    number,
                    "CWE-250",
                    "Avoid mounting the Docker socket; use a scoped API proxy.",
                )
            )
    for name, attrs in service_attrs.items():
        if name in service_nodes:
            service_nodes[name].attrs.update(attrs)
    return result


def _workflow(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    name = path.rsplit("/", 1)[-1]
    node = _node(path, name, "workflow", 1, {"type": "ci_workflow"})
    actions: list[str] = []
    secrets: list[str] = []
    triggers: list[str] = []
    in_on = False
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("on:"):
            in_on = True
            rest = stripped[3:].strip()
            if rest:
                triggers.append(rest)
            continue
        if in_on:
            if raw.startswith(" ") or raw.startswith("\t"):
                key = stripped.split(":", 1)[0]
                if key and not key.startswith("-"):
                    triggers.append(key)
            else:
                in_on = False
        if stripped.startswith("permissions:") and "write-all" in stripped:
            result.findings.append(
                IacFinding(
                    "ci",
                    "high",
                    "Workflow grants write-all permissions",
                    f"Overly broad permissions at {path}:{number}.",
                    path,
                    number,
                    "CWE-732",
                    "Grant least-privilege permissions per job.",
                )
            )
        uses_line = stripped[2:].lstrip() if stripped.startswith("- ") else stripped
        if uses_line.startswith("uses:"):
            action = uses_line.split(":", 1)[1].strip().strip("'\"")
            actions.append(action)
            if not action.startswith("./") and "@" in action:
                ref = action.rsplit("@", 1)[1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    result.findings.append(
                        IacFinding(
                            "supply-chain",
                            "low",
                            "Unpinned GitHub Action",
                            f"`{action}` is not pinned to a commit SHA at {path}:{number}.",
                            path,
                            number,
                            "CWE-1357",
                            "Pin third-party actions to a full commit SHA.",
                        )
                    )
        if "secrets." in stripped:
            for found in re.findall(r"secrets\.([A-Za-z0-9_]+)", stripped):
                secrets.append(found)
        if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", stripped):
            result.findings.append(
                IacFinding(
                    "supply-chain",
                    "high",
                    "Remote script piped to shell in CI",
                    f"Unverified remote script execution at {path}:{number}.",
                    path,
                    number,
                    "CWE-829",
                    "Pin and verify downloaded tooling.",
                )
            )
        if "pull_request_target" in stripped:
            result.findings.append(
                IacFinding(
                    "ci",
                    "medium",
                    "pull_request_target trigger",
                    f"Review checkout and secret exposure at {path}:{number}.",
                    path,
                    number,
                    "CWE-829",
                    "Avoid checking out untrusted PR code in privileged workflows.",
                )
            )
    node.attrs.update({"actions": sorted(set(actions)), "secrets": sorted(set(secrets)), "triggers": sorted(set(triggers))})
    result.nodes.append(node)
    return result


K8S_KINDS = {"deployment", "statefulset", "daemonset", "pod", "job", "cronjob", "replicaset"}


def _kubernetes(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    kind = None
    name = path.rsplit("/", 1)[-1]
    node = None
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if stripped.startswith("kind:"):
            kind = stripped.split(":", 1)[1].strip()
            if kind.lower() not in K8S_KINDS:
                node = None
                continue
            node = _node(path, f"{kind}/{name}", "infra", number, {"type": f"k8s_{kind.lower()}"})
            result.nodes.append(node)
        elif stripped.startswith("name:") and node is not None and "name" not in node.attrs:
            node.attrs["name"] = stripped.split(":", 1)[1].strip().strip("'\"")
        checks = (
            ("privileged:", "true", "critical", "CWE-250", "Privileged container"),
            ("hostNetwork:", "true", "high", "CWE-284", "Host network namespace"),
            ("hostPID:", "true", "high", "CWE-250", "Host PID namespace"),
            ("runAsUser:", "0", "high", "CWE-250", "Container runs as UID 0"),
            ("allowPrivilegeEscalation:", "true", "medium", "CWE-250", "Privilege escalation allowed"),
        )
        for key, value, severity, cwe, title in checks:
            if key in stripped and value in stripped.replace(" ", "").lower():
                result.findings.append(
                    IacFinding(
                        "container",
                        severity,
                        title,
                        f"Kubernetes manifest sets {key} at {path}:{number}.",
                        path,
                        number,
                        cwe,
                        "Apply least privilege and a restricted pod security profile.",
                    )
                )
    return result


def _terraform(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    node = _node(path, path.rsplit("/", 1)[-1], "infra", 1, {"type": "terraform"})
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if re.search(r"cidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0/0", stripped):
            result.findings.append(
                IacFinding(
                    "cloud",
                    "high",
                    "Security group open to the internet",
                    f"0.0.0.0/0 ingress at {path}:{number}.",
                    path,
                    number,
                    "CWE-284",
                    "Restrict CIDR ranges to known networks.",
                )
            )
        if re.search(r"acl\s*=\s*\"public", stripped):
            result.findings.append(
                IacFinding(
                    "cloud",
                    "high",
                    "Public storage ACL",
                    f"Public ACL at {path}:{number}.",
                    path,
                    number,
                    "CWE-284",
                    "Use private ACLs and explicit access policies.",
                )
            )
        if re.search(r"encrypted\s*=\s*false", stripped):
            result.findings.append(
                IacFinding(
                    "cloud",
                    "medium",
                    "Encryption disabled",
                    f"Encryption disabled at {path}:{number}.",
                    path,
                    number,
                    "CWE-311",
                    "Enable encryption at rest and in transit.",
                )
            )
    result.nodes.append(node)
    return result


def analyze_iac(graph: Graph, repo: RepoInfo) -> list[Finding]:
    results: list[IacResult] = []
    for path in repo.iac_files:
        lower = path.lower()
        name = lower.rsplit("/", 1)[-1]
        if name.startswith("dockerfile"):
            results.append(_dockerfile(repo.root, path))
        elif name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            results.append(_compose(repo.root, path))
        elif "/.github/workflows/" in f"/{lower}" and lower.endswith((".yml", ".yaml")):
            results.append(_workflow(repo.root, path))
        elif lower.endswith(".tf"):
            results.append(_terraform(repo.root, path))
        elif lower.endswith((".yml", ".yaml")):
            results.append(_kubernetes(repo.root, path))

    findings: list[Finding] = []
    seen: set[str] = set()
    for result in results:
        for node in result.nodes:
            graph.add_node(node)
        for item in result.findings:
            key = f"{item.category}:{item.path}:{item.line}:{item.title}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=stable_id("iac", item.category, item.path, str(item.line), item.title),
                    category=item.category,
                    severity=item.severity,
                    title=item.title,
                    message=item.message,
                    cwe=item.cwe,
                    confidence=item.confidence,
                    evidence=[Loc(item.path, item.line)],
                    recommendation=item.recommendation,
                )
            )
    return findings
