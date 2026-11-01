"""High-Level Architecture and multi-language system diagram generation (inspired by gitdiagram.com).

Extracts and synthesizes polyglot systems (.NET, Node.js, Python, Infrastructure)
into a crisp C4-style tier diagram showing how clients, API gateways, core services,
data persistence, external integrations, and container platforms interconnect.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import SEVERITY_RANK, Graph, Node

MODERN_HIGHLEVEL_INIT = """%%{init: {
  'theme': 'base',
  'themeVariables': {
    'primaryColor': '#f8fafc',
    'primaryTextColor': '#0f172a',
    'primaryBorderColor': '#94a3b8',
    'lineColor': '#475569',
    'secondaryColor': '#f1f5f9',
    'tertiaryColor': '#e2e8f0',
    'fontFamily': 'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif',
    'fontSize': '12px'
  }
}}%%"""

CLASS_DEFS_HIGHLEVEL = """
  classDef ingress fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d;
  classDef gateway fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e40af;
  classDef service fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#581c87;
  classDef data fill:#fffbeb,stroke:#d97706,stroke-width:2px,color:#78350f;
  classDef external fill:#f8fafc,stroke:#475569,stroke-width:2px,color:#0f172a;
  classDef platform fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#075985;
  classDef critical fill:#fef2f2,stroke:#dc2626,stroke-width:2.5px,color:#991b1b;
  classDef high fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#9a3412;
  classDef medium fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12;
"""


@dataclass
class Subsystem:
    id: str
    name: str
    tier: str  # "ingress", "gateway", "services", "data", "external", "platform"
    kind: str  # "client", "api", "service", "database", "cache", "queue", "worker", "external", "platform"
    technology: str
    description: str = ""
    details: list[str] = field(default_factory=list)
    path: str | None = None
    findings_count: int = 0
    max_severity: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SubsystemConnection:
    src: str
    dst: str
    label: str
    style: str = "solid"  # "thick" (==>), "solid" (-->), "dotted" (-.->)


@dataclass
class HighLevelArchitecture:
    subsystems: list[Subsystem] = field(default_factory=list)
    connections: list[SubsystemConnection] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)


def _clean_id(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", raw).strip("_")
    return cleaned or "subsystem"


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
    if len(cleaned) > 80:
        cleaned = cleaned[:77] + "..."
    return cleaned or "unnamed"


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Lightweight stdlib parser for common compose/yaml configs without external dependencies."""
    result: dict[str, Any] = {}
    current_key = None
    sub_key = None

    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and ":" in trimmed:
            key = trimmed.split(":", 1)[0].strip()
            current_key = key
            result[current_key] = {}
            sub_key = None
        elif indent in (2, 4) and current_key and ":" in trimmed:
            parts = trimmed.split(":", 1)
            sub_key = parts[0].strip()
            val = parts[1].strip()
            if not isinstance(result[current_key], dict):
                result[current_key] = {}
            result[current_key][sub_key] = val or {}
        elif indent >= 4 and current_key and sub_key:
            if isinstance(result[current_key], dict) and isinstance(result[current_key].get(sub_key), dict):
                if ":" in trimmed:
                    p = trimmed.split(":", 1)
                    prop_k = p[0].strip("- ").strip()
                    prop_v = p[1].strip()
                    result[current_key][sub_key][prop_k] = prop_v
                elif trimmed.startswith("- "):
                    item = trimmed[2:].strip().strip('"\'')
                    if not isinstance(result[current_key][sub_key], list):
                        result[current_key][sub_key] = []
                    result[current_key][sub_key].append(item)
    return result


def _scan_compose_and_docker(root: Path) -> tuple[list[Subsystem], list[SubsystemConnection]]:
    subsystems: list[Subsystem] = []
    connections: list[SubsystemConnection] = []

    compose_files = [
        root / "docker-compose.yml",
        root / "docker-compose.yaml",
        root / "compose.yml",
        root / "compose.yaml",
    ]
    compose_path = next((f for f in compose_files if f.is_file()), None)

    services_dict: dict[str, Any] = {}
    if compose_path:
        try:
            content = compose_path.read_text(encoding="utf-8", errors="replace")
            parsed = _parse_simple_yaml(content)
            services_dict = parsed.get("services", {})
        except OSError:
            pass

    has_dockerfile = (root / "Dockerfile").is_file()
    if has_dockerfile or compose_path:
        subsystems.append(
            Subsystem(
                id="platform_docker",
                name="Docker Platform",
                tier="platform",
                kind="platform",
                technology="Docker / Compose",
                description="Containerized execution runtime",
                path=str(compose_path.relative_to(root)) if compose_path else "Dockerfile",
            )
        )

    for svc_name, svc_info in services_dict.items():
        if not isinstance(svc_info, dict):
            continue
        image = str(svc_info.get("image", "")).lower()
        ports = svc_info.get("ports", [])
        port_str = f"Port {ports[0]}" if isinstance(ports, list) and ports else ""

        # Identify database / storage services from image names
        if "postgres" in image or "postgres" in svc_name.lower():
            sub_id = _clean_id(f"db_{svc_name}")
            subsystems.append(
                Subsystem(
                    id=sub_id,
                    name=f"PostgreSQL ({svc_name})",
                    tier="data",
                    kind="database",
                    technology=f"PostgreSQL {port_str}".strip(),
                    description="Relational database store",
                )
            )
        elif "mysql" in image or "mariadb" in image or "mysql" in svc_name.lower():
            sub_id = _clean_id(f"db_{svc_name}")
            subsystems.append(
                Subsystem(
                    id=sub_id,
                    name=f"MySQL ({svc_name})",
                    tier="data",
                    kind="database",
                    technology=f"MySQL {port_str}".strip(),
                    description="Relational database store",
                )
            )
        elif "redis" in image or "redis" in svc_name.lower():
            sub_id = _clean_id(f"cache_{svc_name}")
            subsystems.append(
                Subsystem(
                    id=sub_id,
                    name=f"Redis ({svc_name})",
                    tier="data",
                    kind="cache",
                    technology=f"Redis In-Memory Cache {port_str}".strip(),
                    description="Caching and key-value store",
                )
            )
        elif "mongo" in image or "mongo" in svc_name.lower():
            sub_id = _clean_id(f"db_{svc_name}")
            subsystems.append(
                Subsystem(
                    id=sub_id,
                    name=f"MongoDB ({svc_name})",
                    tier="data",
                    kind="database",
                    technology=f"MongoDB NoSQL {port_str}".strip(),
                    description="Document database store",
                )
            )
        elif "rabbit" in image or "kafka" in image or "queue" in svc_name.lower():
            sub_id = _clean_id(f"queue_{svc_name}")
            tech = "RabbitMQ" if "rabbit" in image or "rabbit" in svc_name.lower() else "Kafka"
            subsystems.append(
                Subsystem(
                    id=sub_id,
                    name=f"{tech} ({svc_name})",
                    tier="data",
                    kind="queue",
                    technology=f"{tech} Message Broker {port_str}".strip(),
                    description="Message queue and event bus",
                )
            )

    return subsystems, connections


def _find_or_create_subsystem(
    subsystems: list[Subsystem],
    sub_id: str,
    name: str,
    tier: str,
    kind: str,
    technology: str,
    description: str = "",
) -> Subsystem:
    for s in subsystems:
        if s.id == sub_id:
            return s
        if s.tier == tier and s.kind == kind and (name.lower() in s.name.lower() or s.name.lower() in name.lower()):
            return s
    created = Subsystem(
        id=sub_id,
        name=name,
        tier=tier,
        kind=kind,
        technology=technology,
        description=description,
    )
    subsystems.append(created)
    return created


def _scan_dotnet(
    root: Path,
    existing_subsystems: list[Subsystem],
) -> tuple[list[Subsystem], list[SubsystemConnection]]:
    subsystems: list[Subsystem] = []
    connections: list[SubsystemConnection] = []

    proj_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in {".git", ".gitdiagram", "bin", "obj", "node_modules", ".vs"}
        ]
        for f in filenames:
            if f.endswith((".csproj", ".fsproj")):
                proj_files.append(Path(dirpath) / f)

    if not proj_files:
        return subsystems, connections

    proj_map: dict[str, str] = {}
    proj_data: dict[str, dict[str, Any]] = {}

    for proj in proj_files:
        stem = proj.stem
        sub_id = _clean_id(f"dotnet_{stem}")
        proj_map[stem.lower()] = sub_id

        packages: list[str] = []
        references: list[str] = []
        is_web = False

        try:
            tree = ET.parse(proj)
            xml_root = tree.getroot()
            sdk = xml_root.get("Sdk", "")
            if "Microsoft.NET.Sdk.Web" in sdk:
                is_web = True

            for pkg in xml_root.findall(".//PackageReference"):
                inc = pkg.get("Include") or ""
                if inc:
                    packages.append(inc)

            for pref in xml_root.findall(".//ProjectReference"):
                inc = pref.get("Include") or ""
                if inc:
                    target_name = Path(inc).stem
                    references.append(target_name)
        except (ET.ParseError, OSError):
            continue

        endpoint_count = 0
        dbcontext_count = 0
        mediatr_count = 0
        class_count = 0

        for dp, dns, fns in os.walk(proj.parent):
            dns[:] = [d for d in dns if d not in {"bin", "obj", ".vs"}]
            for fn in fns:
                if fn.endswith((".cs", ".fs")):
                    try:
                        code = (Path(dp) / fn).read_text(encoding="utf-8", errors="replace")
                        if "ControllerBase" in code or "[ApiController]" in code or "Controller" in fn:
                            endpoint_count += len(re.findall(r"\[Http(Get|Post|Put|Delete|Patch)", code)) or 1
                        if "app.Map" in code:
                            endpoint_count += len(re.findall(r"app\.Map(Get|Post|Put|Delete)", code))
                        if ": DbContext" in code or ": IdentityDbContext" in code:
                            dbcontext_count += 1
                        if "IRequestHandler<" in code or "INotificationHandler<" in code:
                            mediatr_count += 1
                        class_count += len(re.findall(r"\bclass\s+[A-Za-z0-9_]+", code))
                    except OSError:
                        pass

        proj_data[stem] = {
            "sub_id": sub_id,
            "path": str(proj.relative_to(root)),
            "packages": packages,
            "references": references,
            "is_web": is_web,
            "endpoint_count": endpoint_count,
            "dbcontext_count": dbcontext_count,
            "mediatr_count": mediatr_count,
            "class_count": class_count,
        }

    for stem, data in proj_data.items():
        sub_id = data["sub_id"]
        packages = data["packages"]
        name_lower = stem.lower()

        tier = "services"
        kind = "service"
        tech = ".NET"

        if data["is_web"] or "api" in name_lower or "web" in name_lower or "gateway" in name_lower:
            tier = "gateway"
            kind = "api"
            tech = "ASP.NET Core Web API"
        elif "domain" in name_lower or "core" in name_lower:
            tier = "services"
            kind = "service"
            tech = ".NET Domain Layer"
        elif "infra" in name_lower or "data" in name_lower or "persistence" in name_lower:
            tier = "services"
            kind = "service"
            tech = ".NET Infrastructure"

        details = []
        if data["endpoint_count"] > 0:
            details.append(f"{data['endpoint_count']} Endpoints")
        if data["mediatr_count"] > 0:
            details.append(f"{data['mediatr_count']} CQRS Handlers")
        if data["dbcontext_count"] > 0:
            details.append(f"{data['dbcontext_count']} DbContexts")
        if data["class_count"] > 0:
            details.append(f"{data['class_count']} Classes")

        # Persistence detection
        db_sub = None
        if any("SqlServer" in p or "SqlClient" in p for p in packages):
            tech += " • EF Core (SQL Server)"
            db_sub = _find_or_create_subsystem(
                existing_subsystems, "db_sqlserver", "SQL Server Database", "data", "database", "SQL Server / EF Core"
            )
        elif any("Npgsql" in p or "PostgreSQL" in p for p in packages):
            tech += " • EF Core (Postgres)"
            db_sub = _find_or_create_subsystem(
                existing_subsystems, "db_postgres", "PostgreSQL Database", "data", "database", "PostgreSQL (Port 5432)"
            )
        elif any("Sqlite" in p for p in packages):
            tech += " • EF Core (SQLite)"
            db_sub = _find_or_create_subsystem(
                existing_subsystems, "db_sqlite", "SQLite Database", "data", "database", "SQLite Embedded"
            )

        if any("MediatR" in p for p in packages):
            tech += " • MediatR"
        if any("MassTransit" in p for p in packages):
            tech += " • MassTransit"

        subsystems.append(
            Subsystem(
                id=sub_id,
                name=stem,
                tier=tier,
                kind=kind,
                technology=tech,
                details=details,
                path=data["path"],
            )
        )

        if db_sub:
            connections.append(SubsystemConnection(src=sub_id, dst=db_sub.id, label="Queries / EF Core", style="solid"))

        # Wire <ProjectReference> dependencies
        for ref in data["references"]:
            target_id = proj_map.get(ref.lower())
            if target_id and target_id != sub_id:
                connections.append(
                    SubsystemConnection(
                        src=sub_id,
                        dst=target_id,
                        label="Depends On",
                        style="solid",
                    )
                )

        # Wire Redis / Cache
        if any("StackExchange.Redis" in p or "Redis" in p for p in packages):
            redis_sub = _find_or_create_subsystem(
                existing_subsystems, "cache_redis", "Redis Cache", "data", "cache", "Redis / StackExchange.Redis"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=redis_sub.id, label="Caches / Reads", style="dotted"))

        # Wire Message Broker
        if any("MassTransit" in p or "RabbitMQ" in p for p in packages):
            rabbit_sub = _find_or_create_subsystem(
                existing_subsystems, "queue_rabbitmq", "RabbitMQ Broker", "data", "queue", "RabbitMQ / MassTransit"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=rabbit_sub.id, label="Pub/Sub Events", style="dotted"))

        # Wire Stripe
        if any("Stripe" in p for p in packages):
            stripe_sub = _find_or_create_subsystem(
                existing_subsystems, "ext_stripe_payments", "Stripe Payments", "external", "external", "Stripe.net SDK"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=stripe_sub.id, label="Charges API", style="dotted"))

        # Wire SendGrid
        if any("SendGrid" in p for p in packages):
            sendgrid_sub = _find_or_create_subsystem(
                existing_subsystems, "ext_sendgrid_email", "SendGrid Email", "external", "external", "SendGrid SDK"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=sendgrid_sub.id, label="Send Emails", style="dotted"))

    return subsystems, connections


def _scan_nodejs(
    root: Path,
    existing_subsystems: list[Subsystem],
) -> tuple[list[Subsystem], list[SubsystemConnection]]:
    subsystems: list[Subsystem] = []
    connections: list[SubsystemConnection] = []

    pkg_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", ".gitdiagram", "node_modules", "dist", ".next"}]
        for f in filenames:
            if f == "package.json":
                pkg_files.append(Path(dirpath) / f)

    if not pkg_files:
        return subsystems, connections

    for pkg_path in pkg_files:
        try:
            content = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue

        raw_name = content.get("name") or pkg_path.parent.name or "node_app"
        name = raw_name.split("/")[-1]
        sub_id = _clean_id(f"node_{name}")

        deps = content.get("dependencies", {})
        dev_deps = content.get("devDependencies", {})
        all_deps = {**dev_deps, **deps}

        tech_list = []
        tier = "services"
        kind = "service"

        if "next" in all_deps:
            tier = "ingress"
            kind = "api"
            tech_list.append("Next.js Fullstack")
        elif "@nestjs/core" in all_deps:
            tier = "gateway"
            kind = "api"
            tech_list.append("NestJS API")
        elif "express" in all_deps:
            tier = "gateway"
            kind = "api"
            tech_list.append("Express.js API")
        elif "fastify" in all_deps:
            tier = "gateway"
            kind = "api"
            tech_list.append("Fastify API")
        elif "hono" in all_deps:
            tier = "gateway"
            kind = "api"
            tech_list.append("Hono API")
        elif "react" in all_deps or "vue" in all_deps:
            tier = "ingress"
            kind = "client"
            tech_list.append("Frontend Web App")

        has_prisma = "prisma" in all_deps or "@prisma/client" in all_deps
        has_pg = "pg" in all_deps
        has_mongoose = "mongoose" in all_deps
        has_typeorm = "typeorm" in all_deps

        if has_prisma:
            tech_list.append("Prisma ORM")
        if has_typeorm:
            tech_list.append("TypeORM")
        if has_mongoose:
            tech_list.append("Mongoose")

        endpoint_count = 0
        model_count = 0
        for dp, dns, fns in os.walk(pkg_path.parent):
            dns[:] = [d for d in dns if d not in {"node_modules", "dist", ".next"}]
            for fn in fns:
                if fn.endswith((".js", ".ts", ".jsx", ".tsx")):
                    try:
                        code = (Path(dp) / fn).read_text(encoding="utf-8", errors="replace")
                        endpoint_count += len(
                            re.findall(r"\b(router|app)\.(get|post|put|delete|patch)\s*\(", code)
                        )
                        endpoint_count += len(re.findall(r"@Controller\b", code))
                        model_count += len(re.findall(r"\b(model|Schema|Entity)\b", code))
                    except OSError:
                        pass
                elif fn == "schema.prisma":
                    try:
                        prisma_code = (Path(dp) / fn).read_text(encoding="utf-8", errors="replace")
                        model_count += len(re.findall(r"\bmodel\s+[A-Za-z0-9_]+\s*\{", prisma_code))
                    except OSError:
                        pass

        details = []
        if endpoint_count > 0:
            details.append(f"{endpoint_count} Routes")
        if model_count > 0:
            details.append(f"{model_count} Models")

        subsystems.append(
            Subsystem(
                id=sub_id,
                name=name,
                tier=tier,
                kind=kind,
                technology=" • ".join(tech_list) if tech_list else "Node.js / TypeScript",
                details=details,
                path=str(pkg_path.relative_to(root)),
            )
        )

        if has_prisma or has_pg:
            db_sub = _find_or_create_subsystem(
                existing_subsystems, "db_postgres", "PostgreSQL Database", "data", "database", "PostgreSQL (Port 5432)"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=db_sub.id, label="Queries / Persists", style="solid"))

        if has_mongoose:
            mongo_sub = _find_or_create_subsystem(
                existing_subsystems, "db_mongo", "MongoDB Database", "data", "database", "MongoDB NoSQL"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=mongo_sub.id, label="Persists Documents", style="solid"))

        if "redis" in all_deps or "ioredis" in all_deps or "bullmq" in all_deps:
            redis_sub = _find_or_create_subsystem(
                existing_subsystems, "cache_redis", "Redis Cache & Queue", "data", "cache", "Redis / BullMQ"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=redis_sub.id, label="Cache & Jobs", style="dotted"))

        if "stripe" in all_deps:
            stripe_sub = _find_or_create_subsystem(
                existing_subsystems, "ext_stripe_payments", "Stripe Payments", "external", "external", "Stripe Node SDK"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=stripe_sub.id, label="Payment API", style="dotted"))

        if "openai" in all_deps or "@anthropic-ai/sdk" in all_deps:
            ai_sub = _find_or_create_subsystem(
                existing_subsystems, "ext_ai_provider", "AI LLM Provider", "external", "external", "OpenAI / Anthropic API"
            )
            connections.append(SubsystemConnection(src=sub_id, dst=ai_sub.id, label="Inference API", style="dotted"))

    return subsystems, connections


def _scan_python_graph(
    root: Path,
    graph: Graph | None,
    existing_subsystems: list[Subsystem],
) -> tuple[list[Subsystem], list[SubsystemConnection]]:
    subsystems: list[Subsystem] = []
    connections: list[SubsystemConnection] = []

    if graph is None or not graph.nodes:
        return subsystems, connections

    nodes = graph.sorted_nodes()
    node_by_id = {n.id: n for n in nodes}

    # Group nodes by feature; ignore test suites for production architecture
    features: dict[str, list[Node]] = {}
    for n in nodes:
        f = n.feature or "core"
        if f.lower() in {"tests", "test", "testing"}:
            continue
        if f not in features:
            features[f] = []
        features[f].append(n)

    # Compute findings severity per feature
    findings_by_feature: dict[str, list[str]] = {}
    for finding in graph.findings:
        f_name = None
        if finding.node_id and finding.node_id in node_by_id:
            f_name = node_by_id[finding.node_id].feature
        elif finding.evidence:
            f_name = finding.evidence[0].path.split("/")[0]
        if f_name and f_name.lower() not in {"tests", "test", "testing"}:
            if f_name not in findings_by_feature:
                findings_by_feature[f_name] = []
            findings_by_feature[f_name].append(finding.severity)

    # External dependencies mapping
    ext_nodes = [n for n in nodes if n.kind == "external"]
    ext_sub_map: dict[str, str] = {}  # ext_node_id -> subsystem_id

    for ext in ext_nodes:
        name_lower = ext.name.lower()
        if "stripe" in name_lower:
            sub = _find_or_create_subsystem(
                existing_subsystems, "ext_stripe_payments", "Stripe Payments", "external", "external", "Stripe Python SDK"
            )
            ext_sub_map[ext.id] = sub.id
        elif "openai" in name_lower or "anthropic" in name_lower:
            sub = _find_or_create_subsystem(
                existing_subsystems, "ext_ai_provider", "AI LLM Provider", "external", "external", "OpenAI / Anthropic API"
            )
            ext_sub_map[ext.id] = sub.id
        elif "redis" in name_lower:
            sub = _find_or_create_subsystem(
                existing_subsystems, "cache_redis", "Redis Cache", "data", "cache", "Redis Store"
            )
            ext_sub_map[ext.id] = sub.id
        elif "celery" in name_lower:
            sub = _find_or_create_subsystem(
                existing_subsystems, "queue_celery", "Celery Worker & Queue", "data", "queue", "Celery / Broker"
            )
            ext_sub_map[ext.id] = sub.id

    feature_subsystems: dict[str, str] = {}
    for feature_name, feature_nodes in features.items():
        if feature_name in {"external", "infrastructure", "infra"}:
            continue

        sub_id = _clean_id(f"py_{feature_name}")
        feature_subsystems[feature_name] = sub_id

        endpoints = [n for n in feature_nodes if n.kind in {"endpoint", "cli", "task"}]
        classes = [n for n in feature_nodes if n.kind == "class"]
        functions = [n for n in feature_nodes if n.kind in {"function", "method"}]

        tier = "services"
        kind = "service"
        tech = "Python"

        if endpoints:
            tier = "gateway"
            kind = "api"
            tech = "Python REST API"
        elif "domain" in feature_name.lower() or "service" in feature_name.lower():
            tier = "services"
        elif "model" in feature_name.lower() or "db" in feature_name.lower():
            tier = "data"
            kind = "database"

        details = []
        if endpoints:
            details.append(f"{len(endpoints)} Endpoints")
        if classes:
            details.append(f"{len(classes)} Classes")
        if functions:
            details.append(f"{len(functions)} Functions")

        f_severities = findings_by_feature.get(feature_name, [])
        max_sev = None
        if f_severities:
            f_severities.sort(key=lambda s: -SEVERITY_RANK.get(s, 0))
            max_sev = f_severities[0]

        subsystems.append(
            Subsystem(
                id=sub_id,
                name=feature_name.replace("_", " ").title(),
                tier=tier,
                kind=kind,
                technology=tech,
                details=details,
                findings_count=len(f_severities),
                max_severity=max_sev,
            )
        )

    # Connect feature-to-feature call edges & feature-to-external edges
    seen_conn: set[tuple[str, str]] = set()
    for edge in graph.edges:
        if edge.confidence < 0.5 and edge.kind not in {"imports", "contains"}:
            continue
        src_node = node_by_id.get(edge.src)
        dst_node = node_by_id.get(edge.dst)
        if not src_node or not dst_node:
            continue

        src_sub = feature_subsystems.get(src_node.feature or "")
        if not src_sub:
            continue

        # Check if dst is an external integration
        if dst_node.id in ext_sub_map:
            target_sub = ext_sub_map[dst_node.id]
            pair = (src_sub, target_sub)
            if pair not in seen_conn:
                seen_conn.add(pair)
                connections.append(
                    SubsystemConnection(
                        src=src_sub,
                        dst=target_sub,
                        label="Uses / Calls",
                        style="dotted",
                    )
                )
            continue

        if src_node.feature == dst_node.feature:
            continue

        dst_sub = feature_subsystems.get(dst_node.feature or "")
        if dst_sub and src_sub != dst_sub:
            pair = (src_sub, dst_sub)
            if pair not in seen_conn:
                seen_conn.add(pair)
                connections.append(
                    SubsystemConnection(
                        src=src_sub,
                        dst=dst_sub,
                        label="Invokes" if edge.kind == "calls" else "Uses",
                        style="solid",
                    )
                )

    return subsystems, connections


def build_high_level_architecture(root: Path, graph: Graph | None = None) -> HighLevelArchitecture:
    """Build a consolidated high-level system architecture across .NET, Node.js, Python, and IaC."""
    root = root.resolve()
    all_subsystems: list[Subsystem] = []
    all_connections: list[SubsystemConnection] = []
    languages: set[str] = set()
    frameworks: set[str] = set()

    # 1. Inspect Docker and Compose
    iac_subs, iac_conns = _scan_compose_and_docker(root)
    all_subsystems.extend(iac_subs)
    all_connections.extend(iac_conns)
    if iac_subs:
        frameworks.add("Docker")

    # 2. Inspect .NET Projects
    dotnet_subs, dotnet_conns = _scan_dotnet(root, all_subsystems)
    if dotnet_subs:
        languages.add("C# / .NET")
        all_subsystems.extend(dotnet_subs)
        all_connections.extend(dotnet_conns)
        for s in dotnet_subs:
            frameworks.add(s.technology.split(" • ")[0])

    # 3. Inspect Node.js Projects
    node_subs, node_conns = _scan_nodejs(root, all_subsystems)
    if node_subs:
        languages.add("JavaScript / TypeScript")
        all_subsystems.extend(node_subs)
        all_connections.extend(node_conns)
        for s in node_subs:
            frameworks.add(s.technology.split(" • ")[0])

    # 4. Inspect Python
    py_subs, py_conns = _scan_python_graph(root, graph, all_subsystems)
    if py_subs:
        languages.add("Python")
        all_subsystems.extend(py_subs)
        all_connections.extend(py_conns)

    # Fallback if no specific subprojects detected
    if not any(s.tier in {"gateway", "services"} for s in all_subsystems):
        all_subsystems.append(
            Subsystem(
                id="core_app",
                name=root.name.replace("_", " ").title(),
                tier="services",
                kind="service",
                technology="Core Application",
                description="Primary application codebase",
            )
        )

    # 5. Connect Ingress / Client tier to Presentation / API Gateways
    gateways = [s for s in all_subsystems if s.tier == "gateway"]
    fullstack = [s for s in all_subsystems if s.tier == "ingress" and s.kind == "api"]

    client_id = "client_ingress"
    all_subsystems.insert(
        0,
        Subsystem(
            id=client_id,
            name="Clients / Frontends",
            tier="ingress",
            kind="client",
            technology="Web, Mobile & CLI",
            description="User client applications",
        ),
    )
    if gateways or fullstack:
        target = fullstack[0] if fullstack else gateways[0]
        all_connections.insert(
            0,
            SubsystemConnection(
                src=client_id,
                dst=target.id,
                label="HTTPS / REST",
                style="thick",
            ),
        )
    else:
        services = [s for s in all_subsystems if s.tier == "services"]
        if services:
            all_connections.insert(
                0,
                SubsystemConnection(
                    src=client_id,
                    dst=services[0].id,
                    label="Interacts With",
                    style="thick",
                ),
            )

    # Connect Gateway to Core Services if not already connected
    services = [s for s in all_subsystems if s.tier == "services"]
    if gateways and services:
        for gw in gateways:
            if not any(c.src == gw.id and c.dst in {s.id for s in services} for c in all_connections):
                for svc in services[:2]:
                    all_connections.append(
                        SubsystemConnection(
                            src=gw.id,
                            dst=svc.id,
                            label="Dispatches / Invokes",
                            style="solid",
                        )
                    )

    # Connect Docker Platform to Gateways or Services
    docker_platform = next((s for s in all_subsystems if s.id == "platform_docker"), None)
    if docker_platform:
        primary_targets = gateways if gateways else services
        if primary_targets:
            all_connections.append(
                SubsystemConnection(
                    src=docker_platform.id,
                    dst=primary_targets[0].id,
                    label="Runs & Hosts",
                    style="dotted",
                )
            )

    # Deduplicate subsystems by ID
    unique_subs: dict[str, Subsystem] = {}
    for sub in all_subsystems:
        if sub.id not in unique_subs:
            unique_subs[sub.id] = sub
        else:
            for d in sub.details:
                if d not in unique_subs[sub.id].details:
                    unique_subs[sub.id].details.append(d)

    # Filter invalid connection endpoints
    valid_ids = set(unique_subs.keys())
    valid_conns: list[SubsystemConnection] = []
    seen_conns: set[tuple[str, str]] = set()

    for conn in all_connections:
        if conn.src in valid_ids and conn.dst in valid_ids and conn.src != conn.dst:
            pair = (conn.src, conn.dst)
            if pair not in seen_conns:
                seen_conns.add(pair)
                valid_conns.append(conn)

    return HighLevelArchitecture(
        subsystems=list(unique_subs.values()),
        connections=valid_conns,
        languages=languages,
        frameworks=frameworks,
    )


def _render_node_shape(sub: Subsystem) -> str:
    escaped_name = _escape(sub.name)
    tech = _escape(sub.technology) if sub.technology else ""
    details_str = " • ".join(_escape(d) for d in sub.details) if sub.details else ""

    content_lines = [f"<b>{escaped_name}</b>"]
    if tech:
        content_lines.append(f"<i>{tech}</i>")
    if details_str:
        content_lines.append(f"<small>{details_str}</small>")
    if sub.findings_count > 0:
        sev_label = sub.max_severity.upper() if sub.max_severity else "ALERT"
        content_lines.append(f"<b>⚠️ {sub.findings_count} {sev_label}</b>")

    label = "<br/>".join(content_lines)

    if sub.kind == "client":
        return f'(["{label}"])'
    elif sub.kind in {"database", "cache"}:
        return f'[("{label}")]'
    elif sub.kind in {"queue", "api"}:
        return f'[["{label}"]]'
    elif sub.kind == "external":
        return f'[/"{label}"/]'
    return f'["{label}"]'


def render_mermaid_highlevel(
    hla: HighLevelArchitecture,
    direction: str = "TB",
    theme: str = "modern",
) -> str:
    """Render the HighLevelArchitecture into a clean, professional, human-friendly Mermaid diagram."""
    lines = [
        "%% High-Level System Architecture Diagram generated by gitdiagram",
        "%% Deterministic C4-inspired tier overview",
    ]
    if theme == "modern":
        lines.append(MODERN_HIGHLEVEL_INIT)
    lines.append(f"flowchart {direction}")

    tier_order = [
        ("ingress", "🌐 Clients & Ingress"),
        ("gateway", "🚪 Presentation & API Gateway"),
        ("services", "⚙️ Domain & Core Services"),
        ("data", "🗄️ Persistence & Data Stores"),
        ("external", "📦 External Services & Integrations"),
        ("platform", "☁️ Runtime Platform & Containers"),
    ]

    tier_map: dict[str, list[Subsystem]] = {key: [] for key, _ in tier_order}
    for sub in hla.subsystems:
        target_tier = sub.tier if sub.tier in tier_map else "services"
        tier_map[target_tier].append(sub)

    for tier_key, tier_title in tier_order:
        subs = tier_map.get(tier_key, [])
        if not subs:
            continue

        subgraph_id = f"Tier_{tier_key.capitalize()}"
        lines.append(f'  subgraph {subgraph_id}["{tier_title}"]')
        lines.append("    direction LR")
        for sub in subs:
            shape = _render_node_shape(sub)
            if sub.max_severity:
                style = f":::{sub.max_severity}"
            else:
                style = f":::{sub.tier}"
            lines.append(f"    {sub.id}{shape}{style}")
        lines.append("  end")

    lines.append(CLASS_DEFS_HIGHLEVEL.rstrip())

    for conn in hla.connections:
        label_part = f"|{_escape(conn.label)}|" if conn.label else ""
        if conn.style == "thick":
            arrow = f"=={label_part}==>"
        elif conn.style == "dotted":
            arrow = f"-.{label_part}.->"
        else:
            arrow = f"--{label_part}-->"
        lines.append(f"  {conn.src} {arrow} {conn.dst}")

    return "\n".join(lines) + "\n"
