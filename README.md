<div align="center">

# ⚡ gitdiagram

### *Small but Gold* — Deterministic Architecture, Polyglot System Diagrams, and Security Intelligence for Repositories.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-success.svg?style=flat-square)](pyproject.toml)
[![Tests](https://img.shields.io/badge/Tests-97%2F97%20Passing-brightgreen.svg?style=flat-square)](tests/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Cross Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Ubuntu%20%7C%20RHEL%20%7C%20Windows-blueviolet.svg?style=flat-square)](#-100-cross-platform-matrix)

<p align="center">
  <b>Transform codebases into clear, human-friendly system architecture diagrams (gitdiagram.com style), publication-quality images, security threat models, and AI reviews.</b><br>
  <i>100% offline-first. Zero external Python dependencies. Polyglot support across <b>.NET (C#)</b>, <b>Node.js / TypeScript</b>, <b>Python</b>, and <b>Docker / Kubernetes / Terraform</b>.</i>
</p>

---

[Key Highlights](#-key-highlights) •
[High-Level Architecture Diagrams](#-high-level-system-architecture-diagrams-gitdiagramcom-style) •
[Polyglot Ecosystem Support](#-polyglot-ecosystem-support) •
[Quick Start](#-quick-start) •
[Containerized Run](#-containerized-execution-docker--podman) •
[Visual Diagrams & Images](#-visual-diagrams--image-generation) •
[Security & IaC SAST](#-security--iac-static-analysis) •
[AI Architectural Reviews](#-ai-architectural-reviews-ollama--qwen) •
[CLI Reference](#-cli-reference)

---

</div>

## 🌟 Key Highlights

- **Pure Python Standard Library (`zero dependencies`)**: Runs instantly without downloading hundreds of megabytes of third-party wheels. Zero supply chain attack surface.
- **High-Level System Overview Diagrams (`gitdiagram.com` style)**: Automatically produces high-level C4-style tier diagrams (`diagram-highlevel.mmd` & `diagram-highlevel.png`) explaining how Clients, API Gateways, Microservices, Databases, Caches, Message Brokers, and Runtime Platforms connect.
- **Polyglot & Multi-Project Flexibility**: First-class detection and architectural relationship mapping for **.NET (C#/F#)** solutions (`*.csproj`, `<ProjectReference>`, ASP.NET Core, EF Core, MediatR), **Node.js / TypeScript** (`package.json`, Express, NestJS, Next.js, Prisma, TypeORM), and **Python** (FastAPI, Flask, Django, Celery, SQLAlchemy).
- **Multi-Format Image Rendering**: Export directly to **PNG**, **SVG**, or **PDF**. Uses pre-bundled offline Mermaid CLI (`mmdc`) + headless Chromium or zero-dependency HTTP fallbacks (Kroki, mermaid.ink).
- **Security & IaC SAST Overlay**: Discovers entrypoints, traces taint dataflows to dangerous sinks, catches hardcoded secrets, and audits Dockerfile, Kubernetes, Terraform, and GitHub Actions configurations with exact `path:line` citations.
- **SARIF Code-Scanning Export**: Generates industry-standard `security.sarif` for seamless integration into GitHub Advanced Security, GitLab SAST, or DefectDojo.
- **AI Architectural & Threat Modeling Reviews**: Integrates with local/containerized **Ollama (Qwen, LLaMA, DeepSeek)** or OpenAI endpoints. The LLM receives the deterministic graph and produces evidence-grounded reviews citing exact `path:line` with zero hallucinations.
- **Hardened Multi-Stage Container**: Runs securely as an unprivileged non-root user (`gitdiagram`, UID `10001`), compatible with Docker, Docker Compose, and rootless Podman on SELinux.
- **100% Deterministic & CI-Ready**: Same codebase produces byte-for-byte identical graphs. Exit codes signal analysis success (`0`), errors (`1`), or security threshold violations (`2`).

---

## 🏛️ High-Level System Architecture Diagrams (`gitdiagram.com` Style)

When explaining system design to engineers, architects, managers, or stakeholders, raw function call graphs create noise. `gitdiagram` automatically compiles a clean **C4 Container / Tier System Overview Diagram** into:
- `diagram-highlevel.mmd` (Mermaid code)
- `diagram-highlevel.png` / `.svg` (Rendered image)
- Embedded at the top of `ARCHITECTURE.md`

### Visual Architecture Tiering:

```mermaid
flowchart TB
  subgraph Tier_Ingress["🌐 Clients & Ingress"]
    direction LR
    client_ingress(["<b>Clients / Frontends</b><br/><i>Web, Mobile & CLI</i>"]):::ingress
  end

  subgraph Tier_Gateway["🚪 Presentation & API Gateway"]
    direction LR
    web_api[["<b>Web API Subsystem</b><br/><i>ASP.NET Core • Express.js • FastAPI</i><br/><small>14 Endpoints • JWT Auth</small>"]]:::gateway
  end

  subgraph Tier_Services["⚙️ Domain & Core Services"]
    direction LR
    order_svc["<b>Order Service</b><br/><i>MediatR / CQRS • Domain Logic</i><br/><small>8 Handlers • 4 Events</small>"]:::services
    billing_svc["<b>Billing Service</b><br/><i>Subscription & Invoicing</i><br/><small><b>⚠️ 1 HIGH</b></small>"]:::high
  end

  subgraph Tier_Data["🗄️ Persistence & Data Stores"]
    direction LR
    db_store[("<b>PostgreSQL / SQL Server</b><br/><i>Entity Framework • Prisma • SQLAlchemy</i><br/><small>Port 5432</small>")]:::data
    cache_store[("<b>Redis Cache</b><br/><i>StackExchange.Redis • ioredis</i><br/><small>Port 6379</small>")]:::data
    queue_broker[["<b>RabbitMQ Broker</b><br/><i>MassTransit • Celery • AMQP</i><br/><small>Port 5672</small>"]]:::data
  end

  subgraph Tier_External["📦 External Services & Integrations"]
    direction LR
    stripe_ext[/"<b>Stripe Payments</b><br/><i>Stripe SDK (Charges & Webhooks)</i>"/]:::external
    ai_ext[/"<b>AI LLM Provider</b><br/><i>OpenAI / Anthropic API</i>"/]:::external
  end

  subgraph Tier_Platform["☁️ Runtime Platform & Containers"]
    direction LR
    docker_platform["<b>Docker Platform</b><br/><i>Multi-Stage Containers • Compose</i>"]:::platform
  end

  classDef ingress fill:#f0fdf4,stroke:#16a34a,stroke-width:2px,color:#14532d;
  classDef gateway fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e40af;
  classDef service fill:#faf5ff,stroke:#9333ea,stroke-width:2px,color:#581c87;
  classDef data fill:#fffbeb,stroke:#d97706,stroke-width:2px,color:#78350f;
  classDef external fill:#f8fafc,stroke:#475569,stroke-width:2px,color:#0f172a;
  classDef platform fill:#f0f9ff,stroke:#0284c7,stroke-width:2px,color:#075985;
  classDef high fill:#fff7ed,stroke:#ea580c,stroke-width:2px,color:#9a3412;

  client_ingress ==|HTTPS / REST|==> web_api
  web_api ==|Invokes / Dispatches|==> order_svc
  web_api ==|Invokes|==> billing_svc
  order_svc --|Queries / Persists|--> db_store
  order_svc -.|Publishes Events|.-> queue_broker
  order_svc -.|Caches State|.-> cache_store
  billing_svc -.|Process Payments|.-> stripe_ext
  billing_svc -.|Generate Summaries|.-> ai_ext
  docker_platform -.|Runs & Hosts|.-> web_api
```

---

## 🔀 Polyglot Ecosystem Support

`gitdiagram` automatically identifies project manifests and code patterns across multiple ecosystems:

| Ecosystem | Manifests Inspected | Architectural Elements Detected |
| :--- | :--- | :--- |
| **.NET (C# / F#)** | `*.sln`, `*.csproj`, `*.fsproj` | • Direct project dependency arrows via `<ProjectReference>`<br>• ASP.NET Core Web API, Controllers (`[ApiController]`, `[HttpGet]`), Minimal APIs (`app.MapGet`)<br>• Entity Framework Core (SQL Server, PostgreSQL/Npgsql, SQLite, Cosmos DB) & DbContexts<br>• MediatR CQRS handlers (`IRequestHandler<T>`), MassTransit / RabbitMQ brokers<br>• StackExchange.Redis cache, Stripe.net, SendGrid, AWS/Azure SDKs |
| **Node.js / TypeScript** | `package.json`, workspaces, `schema.prisma` | • Frameworks: Express.js, Fastify, NestJS, Next.js, Hono, Koa, React/Vue frontends<br>• ORMs: Prisma (auto-counts models & datasource provider), TypeORM, Mongoose (MongoDB), Sequelize<br>• Caching & Queues: Redis (`ioredis`, `redis`), BullMQ (`bullmq`), RabbitMQ (`amqplib`), Kafka<br>• Integrations: Stripe, OpenAI, Anthropic, AWS SDK, SendGrid |
| **Python** | `pyproject.toml`, `requirements.txt`, `*.py` AST | • Frameworks: FastAPI, Flask, Django, Starlette, Tornado, Celery, Click, Typer<br>• ORMs & DBs: SQLAlchemy, Django ORM, Tortoise-ORM, asyncpg, psycopg2, pymongo<br>• Taint tracking: sources to dangerous execution/injection sinks (CWE-78, CWE-89, CWE-502) |
| **Infrastructure & IaC** | `docker-compose.yml`, `Dockerfile`, K8s, Terraform | • Docker Compose service images, published ports, and `depends_on` relationships<br>• Dockerfile unpinned tags, non-root users, exposed ports<br>• Kubernetes manifests & Terraform cloud security rules |

---

## 🚀 Quick Start

### 1. Instant Run (No Installation Required)

Because `gitdiagram` requires **only the Python standard library**, you can run it immediately on any machine with Python 3.10+:

```bash
# Analyze any repository:
python gitdiagram.py --dir="."

# Generate both detailed architecture diagram and high-level system diagram with PNG images:
python gitdiagram.py --dir="." --image

# Generate high-level system overview as primary diagram:
python gitdiagram.py --dir="." --high-level --image
```

Default outputs are written directly to `<repo>/.gitdiagram/`:
- `diagram-highlevel.mmd` — High-level C4 system overview diagram (`gitdiagram.com` style).
- `diagram-highlevel.png` — High-res rendered system architecture image (when `--image` is specified).
- `diagram.mmd` — Detailed architecture flowchart.
- `diagram.png` — Rendered detailed architecture image (when `--image` is specified).
- `ARCHITECTURE.md` — Complete architecture report with the high-level diagram embedded at the top.
- `graph.json` — Machine-readable graph schema (nodes, edges, confidence, features, findings).
- `security.sarif` — SARIF code-scanning findings.

---

### 2. Native CLI Installation

```bash
# Clone the repository:
git clone https://github.com/vichhaiyserey/gitgendiagram.git
cd gitgendiagram

# Install in editable mode:
pip install -e .

# Run on any project:
gitdiagram --dir /path/to/project --image svg
```

---

## 🐳 Containerized Execution (Docker & Podman)

`gitdiagram` provides an enterprise-ready, multi-stage Docker image built on `python:3.12-slim` and `node:20-slim`. It executes as an unprivileged non-root user (`uid=10001`) and comes pre-bundled with `@mermaid-js/mermaid-cli` and Chromium for **100% offline diagram image rendering**.

### Standalone Docker Execution

Mount your target project to `/repo` (the container's default `WORKDIR`):

```bash
# Linux / macOS:
docker run --rm -v "$(pwd):/repo" gitdiagram:latest --image

# Windows PowerShell:
docker run --rm -v "${PWD}:/repo" gitdiagram:latest --image

# Windows Command Prompt (CMD):
docker run --rm -v "%cd%:/repo" gitdiagram:latest --image

# RHEL / Fedora / CentOS (SELinux mode with :z flag):
docker run --rm -v "$(pwd):/repo:z" gitdiagram:latest --image
```

> [!TIP]
> **Windows Git Bash Users**: Git Bash on Windows automatically translates POSIX paths (e.g. `/repo` to `C:/Program Files/Git/repo`). `gitdiagram` includes built-in MSYS auto-recovery. You can also simply omit `--dir` entirely (the container defaults to the mounted repository) or use double slashes `--dir //repo`.

---

### Multi-Service Docker Compose with Local Ollama (Qwen)

Run `gitdiagram` alongside a companion Ollama container over an isolated internal bridge network:

```bash
# 1. Start Ollama:
docker compose up -d ollama

# 2. Pull Qwen (or any Ollama model):
docker compose exec ollama ollama pull qwen2.5-coder

# 3. Run gitdiagram with AI-powered architectural review:
docker compose run --rm gitdiagram --ollama qwen2.5-coder --llm-template comprehensive --image
```

---

## 🗺️ Visual Diagrams & Image Generation

### Detail Level Modes (`--diagram-detail`):

1. **`high-level` (or `--high-level`)**:
   Produces the clean, executive-ready C4 system diagram (`gitdiagram.com` style) showing Subsystems, Ingress, Gateways, Core Services, Databases, Caches, Brokers, and External APIs.
2. **`architecture` (default for `diagram.mmd`)**:
   Grounded functional architecture with classes, routes, models, and external dependencies. Class methods are collapsed into parent classes and intra-feature import noise is suppressed.
3. **`full`**:
   Exhaustive raw symbol graph including individual helper functions, private methods, and modules.

### Multi-Format Diagram Images

Generate publication-ready architecture diagrams in **PNG**, **SVG**, or **PDF**:

```bash
# Default PNG output (diagram.png and diagram-highlevel.png):
gitdiagram --image

# Crisp vector SVG output:
gitdiagram --image svg

# High-resolution PDF document:
gitdiagram --image pdf

# Export all diagram formats simultaneously:
gitdiagram --format json,md,mermaid,png,svg,pdf
```

#### Rendering Providers (`--image-provider`):
1. **`auto` (default)**: Uses local offline Mermaid CLI (`mmdc`) if available. Otherwise, falls back seamlessly to open-source Kroki / mermaid.ink HTTP endpoints via standard library `urllib` (zero pip packages required).
2. **`local`**: Offline rendering via bundled Mermaid CLI (`mmdc`) + headless Chromium.
3. **`kroki`**: Uses public `https://kroki.io` or your private on-premise Kroki container (`--image-endpoint`).
4. **`mermaid.ink`**: Uses the public mermaid.ink image service.

---

## 🛡️ Security & IaC Static Analysis

`gitdiagram` performs static security analysis across application code and infrastructure files:

### Application Security Rules (SAST)

| Category | CWE | Patterns Detected | Severity |
| :--- | :--- | :--- | :--- |
| **Command Injection** | CWE-78 | `subprocess` with `shell=True`, `os.system`, `os.popen`, `eval`, `exec` with tainted variables | Critical / High |
| **SQL Injection** | CWE-89 | Raw SQL string interpolation, f-strings, `%` formatting in DB executions | High |
| **Unsafe Deserialization** | CWE-502 | `pickle.loads`, `yaml.load` without `SafeLoader` | Critical / High |
| **Path Traversal** | CWE-22 | Unsanitized file path joins with user inputs | High |
| **Weak Cryptography** | CWE-327 | Use of `MD5`, `SHA1` for security contexts, hardcoded AES ECB mode | Medium |
| **Hardcoded Secrets** | CWE-798 | Embedded API keys, AWS tokens, private keys, populated `.env` files | High / Medium |

### Infrastructure-as-Code (IaC) Rules

- **Dockerfile**: Root user execution (`USER root` or missing non-root user), unpinned base tags (`:latest`), exposed privileged ports.
- **Kubernetes**: Missing `runAsNonRoot`, `privileged: true`, dangerous capabilities (`SYS_ADMIN`), missing resource limits.
- **Terraform**: S3 buckets with public read/write ACLs, unrestricted security group ingress (`0.0.0.0/0`).
- **GitHub Actions**: Workflows using `pull_request_target` with explicit checkouts, untrusted script execution.

---

## 🤖 AI Architectural Reviews (Ollama & Qwen)

Turn raw graphs into executive-ready security architecture reviews using **local offline models** (Qwen, LLaMA, DeepSeek) or OpenAI:

```bash
# Run with local Ollama using Qwen:
python gitdiagram.py --ollama qwen2.5-coder

# Choose a specialized architectural review template:
python gitdiagram.py --ollama qwen2.5-coder --llm-template comprehensive
```

### 4 Specialized Review Profiles (`--llm-template`):

1. **`comprehensive` (default)**:
   - 1. Executive Summary & Security Posture Scorecard.
   - 2. Attack Surface Catalog & Ingress Points (`path:line`).
   - 3. Trust Boundaries & Component Data Flow Analysis.
   - 4. Deep-Dive Threat Modeling (STRIDE / CWE).
   - 5. Infrastructure, Supply Chain & IaC Posture.
   - 6. Prioritized Remediation Roadmap (P0 / P1 / P2).

2. **`threat-model`**:
   - Formal STRIDE threat matrix (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege).
   - Component trust boundary crossings and attack trees.

3. **`remediation`**:
   - Developer-centric vulnerability-by-vulnerability fix guide.
   - Exact vulnerable patterns vs. secure drop-in code replacements.

4. **`compliance`**:
   - Formal audit mapping against **OWASP Top 10 (2021)** and **CIS Software Benchmarks**.

> [!NOTE]
> **Strict Anti-Hallucination Guardrails**: The LLM prompt enforces that every finding, component, and flow must cite an exact `path:line` present in the deterministic graph. The model cannot invent phantom files or hallucinate non-existent vulnerabilities.

---

## 🌐 100% Cross-Platform Matrix

`gitdiagram` runs seamlessly across all major operating systems, shells, and enterprise server environments:

| Operating System | Environments Supported | Primary Commands |
| :--- | :--- | :--- |
| **macOS** | Apple Silicon (`arm64`), Intel (`x86_64`) | `docker run -v "${PWD}:/repo" gitdiagram:latest --image`<br>`python gitdiagram.py --image` |
| **Ubuntu / Debian** | Ubuntu 20.04+, Debian 11+ (`x86_64`, `arm64`) | `docker run -v "$(pwd):/repo" gitdiagram:latest --image`<br>`python3 gitdiagram.py --image` |
| **RHEL / Rocky / Alma** | RHEL 8/9, CentOS, Fedora, Podman, SELinux | `podman run -v "$(pwd):/repo:z" gitdiagram:latest --image`<br>`docker run -v "$(pwd):/repo:z" gitdiagram:latest --image` |
| **Windows** | PowerShell 5.1/7+, CMD, Git Bash, WSL2 | `docker run -v "${PWD}:/repo" gitdiagram:latest --image`<br>`python gitdiagram.py --image` |

---

## 📖 CLI Reference

```text
usage: gitdiagram [-h] [--dir DIR] [--out OUT] [--format FORMAT]
                  [--include GLOB] [--exclude GLOB]
                  [--min-confidence MIN_CONFIDENCE] [--max-nodes MAX_NODES]
                  [--security] [--no-security] [--link-base LINK_BASE]
                  [--image [FORMAT]] [--image-format {png,svg,pdf}]
                  [--image-provider {auto,local,kroki,mermaid.ink}]
                  [--image-endpoint IMAGE_ENDPOINT] [--offline]
                  [--diagram-detail {architecture,full,high-level,overview}]
                  [--high-level]
                  [--max-diagram-nodes MAX_DIAGRAM_NODES]
                  [--diagram-direction {LR,TB}]
                  [--diagram-theme {modern,classic}]
                  [--ollama [MODEL]] [--llm] [--llm-model LLM_MODEL]
                  [--llm-base-url LLM_BASE_URL] [--llm-api-key LLM_API_KEY]
                  [--llm-template {comprehensive,threat-model,remediation,compliance}]
                  [--llm-timeout LLM_TIMEOUT] [--llm-max-tokens LLM_MAX_TOKENS]
                  [--fail-on {critical,high,medium,low,info,none}]
                  [--quiet] [--version]
```

### Options Breakdown

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--dir DIR` | `.` | Target repository directory to inspect |
| `--out OUT` | `<dir>/.gitdiagram` | Output directory for all generated artifacts |
| `--format FORMAT` | `json,md,mermaid` | Comma-separated outputs: `json`, `md`, `mermaid`, `sarif`, `png`, `svg`, `pdf` |
| `--high-level` | `false` | Generate high-level system overview diagram (`gitdiagram.com` style) as primary diagram |
| `--diagram-detail` | `architecture` | Visual detail level: `architecture`, `full`, `high-level`, `overview` |
| `--image [FORMAT]` | `png` | Render visual diagrams to image (`png`, `svg`, `pdf`) |
| `--image-provider` | `auto` | Image renderer: `auto`, `local` (`mmdc`), `kroki`, `mermaid.ink` |
| `--offline` | `false` | Enforce strictly offline execution; forbids external HTTP calls |
| `--max-diagram-nodes` | `150` | Max components displayed in architecture diagram; 0 for unlimited |
| `--diagram-direction`| `LR` | Diagram orientation: `LR` (horizontal) or `TB` (top-to-bottom) |
| `--diagram-theme` | `modern` | Visual theme palette: `modern` (Tailwind) or `classic` |
| `--link-base URL` | `None` | Prefix for clickable source links (e.g. `https://github.com/org/repo/blob/main`) |
| `--security / --no-security` | enabled | Toggle SAST security rules and IaC configuration checks |
| `--fail-on SEVERITY` | `none` | Return exit code `2` if findings meet or exceed severity threshold |
| `--ollama [MODEL]` | `qwen2.5-coder` | Generate AI review using local Ollama (`qwen2.5-coder`, `qwen2.5:7b`, etc.) |
| `--llm-template` | `comprehensive` | Prompt profile: `comprehensive`, `threat-model`, `remediation`, `compliance` |
| `--llm-timeout` | `300s` (Ollama) | Network timeout in seconds for LLM generation |
| `--llm-max-tokens` | `1500` | Maximum completion tokens generated by the model |
| `--quiet` | `false` | Suppress console summary output |
| `--version` | — | Display program version (`gitdiagram 0.1.0`) |

---

## 🧪 Comprehensive Test Suite

`gitdiagram` includes 97 unit tests covering AST discovery, call resolution, polyglot .NET and Node.js manifests, high-level C4 diagram rendering, security heuristics, image renderers, and deterministic CLI behaviors:

```bash
# Run all unit tests:
python -m unittest
```

```text
Ran 97 tests in 6.933s
OK
```

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.
