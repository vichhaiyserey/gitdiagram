"""Deterministic, directory-anchored feature grouping."""

from __future__ import annotations

from collections import defaultdict

from .model import Feature, Graph, Node, stable_id

INFRA_FEATURE = "infrastructure"
EXTERNAL_FEATURE = "external"
ROOT_FEATURE = "root"


def feature_for_path(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    name = parts[-1].lower() if parts else ""
    if name.startswith("dockerfile") or name in {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        ".env",
    } or name.startswith(".env."):
        return INFRA_FEATURE
    if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
        parts = parts[1:]
    if parts and parts[0] in {
        ".github",
        "deploy",
        "deployment",
        "k8s",
        "kubernetes",
        "manifests",
        "terraform",
        "infra",
    }:
        return INFRA_FEATURE
    if len(parts) >= 2:
        return parts[0]
    return ROOT_FEATURE


def feature_for_node(node: Node) -> str:
    if node.kind in {"external", "external_package"}:
        return EXTERNAL_FEATURE
    if node.kind in {"infra", "workflow", "container", "service", "module_infra"}:
        return INFRA_FEATURE
    if not node.path:
        if node.kind in {"module", "package"} and node.qualname:
            parts = node.qualname.split(".")
            if parts and parts[0] in {"src", "lib"} and len(parts) > 1:
                parts = parts[1:]
            return parts[0] if parts else ROOT_FEATURE
        return ROOT_FEATURE
    return feature_for_path(node.path)


def assign_features(graph: Graph) -> list[Feature]:
    grouped: dict[str, list[Node]] = defaultdict(list)
    for node in graph.nodes.values():
        name = feature_for_node(node)
        node.feature = name
        grouped[name].append(node)

    features: list[Feature] = []
    for name in sorted(grouped):
        nodes = grouped[name]
        files = sorted({node.path for node in nodes if node.path})
        counts: dict[str, int] = defaultdict(int)
        for node in nodes:
            counts[node.kind] += 1
        pieces = [f"{counts['module']} module(s)"] if counts["module"] else []
        if counts["class"]:
            pieces.append(f"{counts['class']} class(es)")
        funcs = counts["function"] + counts["method"]
        if funcs:
            pieces.append(f"{funcs} function(s)")
        if counts["endpoint"]:
            pieces.append(f"{counts['endpoint']} endpoint(s)")
        if counts["task"]:
            pieces.append(f"{counts['task']} task(s)")
        if counts["external"]:
            pieces.append(f"{counts['external']} external package(s)")
        if counts["infra"]:
            pieces.append(f"{counts['infra']} infra artifact(s)")
        description = "Feature `{}` groups {}.".format(name, ", ".join(pieces) or "no symbols")
        features.append(
            Feature(
                id=stable_id("feature", name),
                name=name,
                description=description,
                nodes=sorted(node.id for node in nodes),
                files=files,
            )
        )

    graph.features = features
    return features
