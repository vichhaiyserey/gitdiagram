"""Compile the validated graph into safe, deterministic, human-friendly Mermaid source."""

from __future__ import annotations

from collections import defaultdict

from .model import Graph, Node, SEVERITY_RANK

SHAPES = {
    "module": '["{label}"]',
    "package": '["{label}"]',
    "class": '{{"{label}"}}',
    "function": '("{label}")',
    "method": '("{label}")',
    "endpoint": '[["{label}"]]',
    "task": '(["{label}"])',
    "cli": '(["{label}"])',
    "external": '>"{label}"]',
    "infra": '{{"{label}"}}',
    "workflow": '{{"{label}"}}',
    "service": '["{label}"]',
}

MODERN_INIT = """%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#f8fafc',
    'primaryTextColor': '#0f172a',
    'primaryBorderColor': '#94a3b8',
    'lineColor': '#64748b',
    'secondaryColor': '#f1f5f9',
    'tertiaryColor': '#e2e8f0',
    'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
    'fontSize': '12px'
  }
}}%%"""

CLASS_DEFS_MODERN = """
  classDef endpoint fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e40af;
  classDef module fill:#f8fafc,stroke:#64748b,stroke-width:1.5px,color:#0f172a;
  classDef package fill:#f1f5f9,stroke:#64748b,stroke-width:1.5px,color:#0f172a;
  classDef cls fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#581c87;
  classDef function fill:#f0fdf4,stroke:#16a34a,stroke-width:1.5px,color:#14532d;
  classDef method fill:#f0fdf4,stroke:#16a34a,stroke-width:1.5px,color:#14532d;
  classDef external fill:#fffbeb,stroke:#d97706,stroke-width:2px,color:#78350f;
  classDef infra fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#075985;
  classDef workflow fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#075985;
  classDef service fill:#ecfdf5,stroke:#059669,stroke-width:2px,color:#064e3b;
  classDef critical fill:#fef2f2,stroke:#dc2626,stroke-width:2.5px,color:#991b1b;
  classDef high fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#9a3412;
  classDef medium fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12;
  classDef low fill:#f8fafc,stroke:#475569,stroke-width:1.5px,color:#1e293b;
"""

CLASS_DEFS_CLASSIC = """
  classDef endpoint fill:#e8f2ff,stroke:#1f6feb,stroke-width:2px,color:#0b1f33;
  classDef module fill:#f5f7fb,stroke:#7a869a,color:#1b2733;
  classDef package fill:#eef1f6,stroke:#7a869a,color:#1b2733;
  classDef cls fill:#f3ecff,stroke:#7d4cdb,color:#241b3a;
  classDef function fill:#eefaf1,stroke:#2da44e,color:#10281a;
  classDef method fill:#f0fbf4,stroke:#2da44e,color:#10281a;
  classDef external fill:#faf3e6,stroke:#bf8700,color:#33260a;
  classDef infra fill:#eaf7f8,stroke:#0f7b8a,color:#0a2a2e;
  classDef workflow fill:#eaf7f8,stroke:#0f7b8a,color:#0a2a2e;
  classDef service fill:#eaf7f8,stroke:#0f7b8a,color:#0a2a2e;
  classDef critical fill:#ffdce0,stroke:#cf222e,stroke-width:2px,color:#4c0d12;
  classDef high fill:#ffe9cc,stroke:#bc4c00,color:#3d1a00;
  classDef medium fill:#fff5cc,stroke:#9a6700,color:#33260a;
  classDef low fill:#eef4ff,stroke:#57606a,color:#24292f;
"""


def _escape(text: str) -> str:
    cleaned = " ".join(str(text).split())
    cleaned = (
        cleaned.replace('"', "'")
        .replace("|", "/")
        .replace("<", "")
        .replace(">", "")
        .replace("`", "")
        .replace("#", "")
        .replace(";", ",")
        .replace("{", "(")
        .replace("}", ")")
        .replace("[", "(")
        .replace("]", ")")
    )
    if len(cleaned) > 75:
        cleaned = cleaned[:72] + "..."
    return cleaned or "unnamed"


def _label(node: Node) -> str:
    if node.kind == "endpoint" and node.attrs.get("routes"):
        routes = node.attrs["routes"]
        if routes:
            route = routes[0]
            method = route.get("method", "").upper()
            path = route.get("path", "")
            return _escape(f"🌐 {method} {path} ({node.name})".strip())
    if node.kind == "class":
        return _escape(f"🏛️ {node.name}")
    if node.kind == "service":
        return _escape(f"⚙️ {node.name}")
    if node.kind in {"module", "package"}:
        return _escape(f"📁 {node.name}")
    if node.kind == "task":
        return _escape(f"⚡ {node.name} (Task)")
    if node.kind == "cli":
        return _escape(f"💻 {node.name} (CLI)")
    if node.kind == "method":
        parts = node.qualname.split(".")
        if len(parts) >= 2:
            parent = parts[-2]
            return _escape(f"λ {parent}.{node.name}()")
        return _escape(f"λ {node.name}()")
    if node.kind == "function":
        return _escape(f"λ {node.name}()")
    if node.kind == "external":
        return _escape(f"📦 {node.name}")
    if node.kind in {"infra", "workflow"}:
        name_lower = node.name.lower()
        if "dockerfile" in name_lower:
            return _escape(f"🐳 {node.name}")
        if "compose" in name_lower:
            return _escape(f"🐙 {node.name}")
        if name_lower.endswith(".tf"):
            return _escape(f"🏗️ {node.name}")
        if "k8s" in name_lower or "deployment" in name_lower:
            return _escape(f"☸️ {node.name}")
        if name_lower.endswith((".yml", ".yaml")) or "ci" in name_lower:
            return _escape(f"🔄 {node.name}")
        if ".env" in name_lower:
            return _escape(f"🔑 {node.name}")
        return _escape(f"☁️ {node.name}")
    return _escape(node.name)


def _shape(node: Node) -> str:
    template = SHAPES.get(node.kind, '["{label}"]')
    return template.format(label=_label(node))


def _severity_for(graph: Graph) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in graph.findings:
        if not finding.node_id:
            continue
        current = out.get(finding.node_id)
        if current is None or SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(current, 0):
            out[finding.node_id] = finding.severity
    return out


def render_mermaid(
    graph: Graph,
    link_base: str | None = None,
    detail: str = "architecture",
    direction: str = "LR",
    theme: str = "modern",
    max_diagram_nodes: int = 150,
) -> str:
    """Compile graph into clear, structured, human-friendly Mermaid diagram."""
    graph.dedupe_edges()
    all_nodes = graph.sorted_nodes()
    severity = _severity_for(graph)

    # In architecture detail mode:
    # 1. Collapse class methods to their parent class
    # 2. Omit private helper functions and redundant container modules
    # 3. Cap nodes and edges to ensure diagrams are human-readable and within Mermaid limits
    remap: dict[str, str] = {}
    if detail == "architecture":
        classes_by_name = {n.name: n.id for n in all_nodes if n.kind == "class"}
        classes_by_qual = {n.qualname: n.id for n in all_nodes if n.kind == "class"}

        for n in all_nodes:
            if n.kind == "method":
                parts = n.qualname.split(".")
                parent_id = None
                if len(parts) >= 2:
                    parent_id = classes_by_name.get(parts[-2]) or classes_by_qual.get(".".join(parts[:-1]))
                if parent_id:
                    remap[n.id] = parent_id

        candidates: list[Node] = []
        for n in all_nodes:
            if n.kind == "method":
                continue
            # Skip private functions without security findings
            if n.kind == "function" and n.name.startswith("_") and n.id not in severity:
                continue
            # Skip container modules without security findings
            if n.kind in {"module", "package"} and n.id not in severity:
                continue
            candidates.append(n)

        # Prioritize top architectural nodes if repository exceeds max_diagram_nodes
        if max_diagram_nodes and len(candidates) > max_diagram_nodes:
            def _arch_rank(node: Node) -> tuple[int, int]:
                if node.id in severity:
                    return (0, -SEVERITY_RANK.get(severity[node.id], 0))
                if node.kind in {"endpoint", "cli", "task"}:
                    return (1, 0)
                if node.kind in {"external", "infra", "workflow"}:
                    return (2, 0)
                if node.kind in {"service", "class"}:
                    return (3, 0)
                return (4, 0)

            candidates.sort(key=lambda n: (_arch_rank(n), n.qualname))
            nodes = candidates[:max_diagram_nodes]
        else:
            nodes = candidates
    else:
        nodes = all_nodes

    displayed_ids = {node.id for node in nodes}

    by_feature: dict[str, list[Node]] = defaultdict(list)
    for node in nodes:
        by_feature[node.feature or "root"].append(node)

    lines = [
        "%% Architecture graph generated by gitdiagram (deterministic static analysis).",
        f"%% nodes={len(nodes)} edges={len(graph.edges)} findings={len(graph.findings)}",
    ]
    if theme == "modern":
        lines.append(MODERN_INIT)
    lines.append(f"flowchart {direction}")

    if not nodes:
        lines.append('  empty["No Python nodes were discovered"]')
        return "\n".join(lines) + "\n"

    for feature in sorted(by_feature):
        feature_id = "F_" + "".join(ch if ch.isalnum() else "_" for ch in feature)[:40]
        feature_nodes = by_feature[feature]

        if feature == "external":
            lines.append(f'  subgraph {feature_id}["📦 External Dependencies"]')
            lines.append("    direction TB")
            for node in sorted(feature_nodes, key=lambda n: n.name):
                style = f":::{severity[node.id]}" if node.id in severity else ":::external"
                lines.append(f"    n_{node.id}{_shape(node)}{style}")
            lines.append("  end")
        elif feature in {"infra", "infrastructure"}:
            lines.append(f'  subgraph {feature_id}["☁️ Infrastructure & Deployment"]')
            lines.append("    direction TB")
            for node in sorted(feature_nodes, key=lambda n: n.name):
                style = f":::{severity[node.id]}" if node.id in severity else ":::infra"
                lines.append(f"    n_{node.id}{_shape(node)}{style}")
            lines.append("  end")
        else:
            feature_title = "📁 " + feature.replace("_", " ").title()
            lines.append(f'  subgraph {feature_id}["{feature_title}"]')
            lines.append("    direction TB")

            # Logical architectural tiering within feature
            endpoints = [n for n in feature_nodes if n.kind in {"endpoint", "cli", "task"}]
            models = [n for n in feature_nodes if n.kind == "class"]
            core = [n for n in feature_nodes if n not in endpoints and n not in models]

            tiers = []
            if endpoints:
                tiers.append((f"{feature_id}_api", "🌐 API & Entrypoints", endpoints))
            if core:
                tiers.append((f"{feature_id}_core", "⚙️ Services & Logic", core))
            if models:
                tiers.append((f"{feature_id}_models", "🏛️ Models & Data", models))

            if len(tiers) > 1:
                for sub_id, sub_title, tier_nodes in tiers:
                    lines.append(f'    subgraph {sub_id}["{sub_title}"]')
                    lines.append("      direction TB")
                    for node in sorted(tier_nodes, key=lambda n: (n.kind, n.qualname)):
                        shape = _shape(node)
                        style = ""
                        if node.id in severity:
                            style = f":::{severity[node.id]}"
                        else:
                            kind_style = "cls" if node.kind == "class" else node.kind
                            style = f":::{kind_style}"
                        lines.append(f"      n_{node.id}{shape}{style}")
                    lines.append("    end")
            else:
                for node in sorted(feature_nodes, key=lambda n: (n.kind, n.qualname)):
                    shape = _shape(node)
                    style = ""
                    if node.id in severity:
                        style = f":::{severity[node.id]}"
                    else:
                        kind_style = "cls" if node.kind == "class" else node.kind
                        style = f":::{kind_style}"
                    lines.append(f"    n_{node.id}{shape}{style}")

            lines.append("  end")

    defs = CLASS_DEFS_MODERN if theme == "modern" else CLASS_DEFS_CLASSIC
    lines.append(defs.rstrip())

    seen_edges: set[tuple[str, str, str]] = set()
    node_by_id = {n.id: n for n in nodes}
    edge_lines: list[str] = []

    for edge in graph.sorted_edges():
        if edge.kind == "contains":
            continue

        src = remap.get(edge.src, edge.src)
        dst = remap.get(edge.dst, edge.dst)

        if src == dst:
            continue
        if src not in displayed_ids or dst not in displayed_ids:
            continue

        src_node = node_by_id.get(src)
        dst_node = node_by_id.get(dst)

        # In architecture mode, suppress intra-feature imports to prevent visual noise
        if detail == "architecture" and edge.kind == "imports":
            if dst_node and dst_node.kind != "external":
                if src_node and dst_node and (src_node.feature == dst_node.feature):
                    continue

        edge_key = (src, dst, edge.kind)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        if edge.kind == "imports":
            arrow = "-.->|imports|"
        elif edge.kind == "inherits":
            arrow = "-->|inherits|"
        elif edge.kind == "instantiates":
            arrow = "==>|new|"
        else:
            arrow = "-->"
        edge_lines.append(f"  n_{src} {arrow} n_{dst}")

    # In architecture mode, cap rendered edges to prevent exceeding Mermaid layout limits (500 maxEdges)
    if detail == "architecture" and len(edge_lines) > 350:
        edge_lines = edge_lines[:350]

    lines.extend(edge_lines)

    if link_base:
        base = link_base.rstrip("/")
        # Validate link_base protocol to prevent XSS / malicious schemes (e.g. javascript:, data:)
        if base.lower().startswith(("http://", "https://")):
            for node in nodes:
                if node.path:
                    normalized_path = node.path.replace("\\", "/")
                    target = f"{base}/{normalized_path}"
                    lines.append(f'  click n_{node.id} "{_escape(target)}" "Open {_escape(normalized_path)}"')

    return "\n".join(lines) + "\n"
