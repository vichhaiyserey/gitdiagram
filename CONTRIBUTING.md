# Contributing to gitdiagram

Thank you for your interest in contributing to **gitdiagram**! We welcome contributions from developers, security researchers, and software architects of all backgrounds.

This guide outlines our development workflow, architectural principles, coding standards, and security policies to help you contribute effectively and safely.

---

## Table of Contents

- [Architectural Principles](#-architectural-principles)
- [Code of Conduct](#-code-of-conduct)
- [Development Setup](#-development-setup)
- [Development Workflow](#-development-workflow)
  - [Running Unit Tests](#running-unit-tests)
  - [Linting and Formatting](#linting-and-formatting)
  - [Type Checking](#type-checking)
  - [Security and SAST Scans](#security-and-sast-scans)
- [Codebase Architecture](#-codebase-architecture)
- [Coding Guidelines](#-coding-guidelines)
  - [Zero Runtime Dependencies](#1-zero-runtime-dependencies)
  - [Strict Determinism](#2-strict-determinism)
  - [Cross-Platform File Handling](#3-cross-platform-file-handling)
  - [Modern Python Typing (3.10+)](#4-modern-python-typing-310)
  - [Security Best Practices](#5-security-best-practices)
- [Pull Request Process](#-pull-request-process)
- [Commit Message Conventions](#-commit-message-conventions)
- [Reporting Security Vulnerabilities](#-reporting-security-vulnerabilities)

---

## 🏛️ Architectural Principles

Before writing code, please keep the four core tenets of `gitdiagram` in mind:

1. **Zero External Runtime Dependencies**: The core CLI, AST analyzer, graph builder, and renderers must run on the **Python standard library only**. We do not add third-party runtime wheels to `dependencies = []` in `pyproject.toml`. This eliminates supply chain risk and ensures instant installation.
2. **Deterministic Output**: Analyzing the same repository state must always yield identical outputs (`diagram.mmd`, `graph.json`, `security.sarif`, etc.). IDs are computed via deterministic hashing (`stable_id`). Never iterate over unordered sets or dict keys when writing outputs.
3. **100% Offline-First**: All core analysis, diagram generation, and security checks must run without internet access. Any remote feature (e.g. Kroki, mermaid.ink, OpenAI API) must be strictly optional with graceful local fallbacks.
4. **Security by Design**: `gitdiagram` inspects untrusted repositories. It must never execute (`eval`, `exec`, `importlib`) analyzed code. All file reading, path resolutions, and YAML/JSON parses must be hardened against path traversal and deserialization attacks.

---

## 📜 Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors. Please treat others with respect, empathy, and professional courtesy in all project interactions, including issues, pull requests, and discussions.

---

## 🚀 Development Setup

### Prerequisites

- **Python**: Version **3.10** or higher (tested on 3.10, 3.11, 3.12, 3.13, and 3.14).
- **Git**: Installed and configured.
- *(Optional)* **Docker**: For testing containerized execution and local Ollama reviews.
- *(Optional)* **Node.js & Mermaid CLI (`@mermaid-js/mermaid-cli`)**: For testing local offline PNG/SVG/PDF image rendering.

### Step-by-Step Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/vserey/gitdiagram.git
   cd clone-gitdiagram
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows (PowerShell)
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

3. **Install the package in editable mode with development dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

   Development dependencies installed via `.[dev]` include:
   - `ruff`: High-speed linter and import formatter.
   - `mypy`: Static type checker.
   - `coverage`: Test coverage suite.
   - `bandit`: Static application security testing (SAST) for Python.
   - `pip-audit`: Known CVE dependency auditor.

---

## 🔄 Development Workflow

### Running Unit Tests

Run the full test suite using Python's built-in `unittest` runner:

```bash
# Run all unit tests
python -m unittest discover -s tests -v

# Run a specific test module
python -m unittest tests/test_security.py -v

# Run with test coverage
python -m coverage run -m unittest discover -s tests
python -m coverage report
```

> **Note**: Test suite must achieve **≥ 80% coverage** across `gitdiagram_core`. All existing 97+ tests must pass without regressions.

### Linting and Formatting

We use `ruff` for linting and import sorting:

```bash
# Check code style and imports
ruff check .

# Automatically apply safe fixes
ruff check . --fix
```

### Type Checking

We use `mypy` with Python 3.10+ strict typing rules:

```bash
mypy
```

### Security and SAST Scans

Run automated security gates before pushing commits:

```bash
# Run Bandit SAST gate (high severity)
python -m bandit -r gitdiagram_core -lll

# Generate full Bandit JSON report
python -m bandit -r gitdiagram_core -f json -o bandit.json

# Check installed dev dependencies for vulnerabilities
python -m pip_audit --strict --skip-editable
```

---

## 📂 Codebase Architecture

```text
gitdiagram/
├── gitdiagram_core/             # Core library (Zero external runtime dependencies)
│   ├── __init__.py              # Version, schema, and public exports
│   ├── analyzer.py              # Orchestrates repo discovery, AST indexing, and analysis
│   ├── ast_index.py             # Python AST parser (classes, functions, calls, imports)
│   ├── cli.py                   # Command-line entrypoint and argument parser
│   ├── discover.py              # File walking, gitignore parsing, polyglot manifest detection
│   ├── features.py              # Feature grouping and subsystem association
│   ├── frameworks.py            # Framework detection (FastAPI, Flask, Django, etc.)
│   ├── graph_builder.py         # Builds dependency graph, pruning, edge weighting
│   ├── high_level.py            # Compiles C4 high-level tier overview diagrams
│   ├── iac.py                   # Infrastructure-as-Code audits (Dockerfile, Compose, K8s, TF)
│   ├── llm.py                   # Citation-preserving LLM narrative review generator
│   ├── model.py                 # Graph, Node, Edge, Finding, and stable_id data models
│   ├── render_image.py          # PNG, SVG, PDF image generation (local mmdc / Kroki / ink)
│   ├── render_json.py           # Structured JSON output serializer
│   ├── render_markdown.py       # Architecture document generator (ARCHITECTURE.md)
│   ├── render_mermaid.py        # Mermaid flowchart code generator (diagram.mmd)
│   ├── render_sarif.py          # OASIS SARIF v2.1.0 security report serializer
│   ├── resolver.py              # Qualified symbol resolution and call attribution
│   └── security.py              # SAST security rules (taint flow, hardcoded secrets, injection)
├── tests/                       # Test suite
│   ├── fixtures/                # Sample applications (Python, .NET, Node.js)
│   ├── test_cli.py              # CLI integration tests
│   ├── test_discover.py         # Discovery & gitignore tests
│   ├── test_graph.py            # Graph construction & pruning tests
│   ├── test_high_level.py       # High-level C4 diagram tests
│   ├── test_image.py            # Image rendering and provider tests
│   ├── test_llm.py              # Ollama and LLM narrative tests
│   ├── test_python_index.py     # AST indexing & resolver tests
│   ├── test_render.py           # Renderers verification
│   └── test_security.py         # SAST heuristics & secret scanner tests
├── .github/
│   ├── dependabot.yml           # Automated dependency updates
│   └── workflows/
│       ├── ci.yml               # Multi-version Python CI, lint, SAST, Trivy
│       ├── codeql.yml           # GitHub CodeQL static analysis
│       ├── docker.yml           # Container build & security scan
│       └── release.yml          # Automated release and Docker Hub delivery
├── Dockerfile                   # Hardened multi-stage unprivileged container
├── docker-compose.yml           # Container run orchestration
└── pyproject.toml               # Package build metadata & tool configurations
```

---

## 📐 Coding Guidelines

### 1. Zero Runtime Dependencies
- **Strict Rule**: Do not add packages to `dependencies = []` in `pyproject.toml`.
- Use Python's standard library modules (`ast`, `urllib`, `dataclasses`, `hashlib`, `json`, `pathlib`, `re`, `shutil`, `tempfile`, `subprocess`).
- If a feature requires external tooling (like rendering images via Mermaid or executing local LLMs), interact with the CLI binary or standard HTTP protocols with robust error handling and offline fallbacks.

### 2. Strict Determinism
- Stable IDs must be created using `stable_id(*parts)`.
- Never iterate over unordered `set` or `dict.keys()` where order influences output files.
- Always sort collections before generating Markdown, JSON, Mermaid code, or SARIF findings.

### 3. Cross-Platform File Handling
- Always use `pathlib.Path` for filesystem operations.
- Internally normalize graph node and file paths to forward slashes (`/`) so diagrams and SARIF reports remain byte-for-byte identical across Linux, macOS, and Windows.

### 4. Modern Python Typing (3.10+)
- Use Python 3.10+ type union syntax: `str | None` instead of `Optional[str]`.
- Use built-in generic collections: `list[str]`, `dict[str, Any]`, `set[int]`.
- Import abstract collection types from `collections.abc` (e.g. `from collections.abc import Iterable, Sequence`), **not** from `typing`.
- Provide complete type hints for function signatures and data models.

### 5. Security Best Practices
- **No Code Execution**: Never call `eval()`, `exec()`, or dynamically `__import__()` untrusted user code.
- **Hashing**: When computing non-cryptographic hashes for IDs (e.g., `hashlib.sha1`), always pass `usedforsecurity=False` to comply with FIPS and Bandit security gates:
  ```python
  digest = hashlib.sha1(data.encode("utf-8"), usedforsecurity=False).hexdigest()
  ```
- **Subprocess Safety**: Pass commands as argument lists (`['mmdc', '-i', ...]`): never use `shell=True`. Set explicit execution timeouts.
- **Network Calls**: Always set explicit `timeout` on `urllib.request.urlopen`.

---

## 🤝 Pull Request Process

1. **Fork and branch**: Create a branch with a descriptive name:
   ```bash
   git checkout -b feat/add-go-manifest-detection
   # or
   git checkout -b fix/sanitize-mermaid-subgraph-ids
   ```

2. **Develop and test**:
   - Write clean, commented code conforming to the guidelines above.
   - Add comprehensive unit tests under `tests/` covering new functionality and edge cases.
   - Ensure all tests pass: `python -m unittest discover -s tests -v`.
   - Ensure linter passes: `ruff check .`.
   - Ensure type check passes: `mypy`.
   - Ensure security scan passes: `python -m bandit -r gitdiagram_core -lll`.

3. **Verify Git Hygiene**:
   - Verify no secrets, `.env` files, temporary screenshots, or dump files are staged:
     ```bash
     git status
     git diff --cached
     ```

4. **Submit PR**: Open a Pull Request targeting the `main` branch. Provide a clear description of:
   - What the PR accomplishes.
   - Why the change is needed.
   - Relevant issue numbers.
   - Test results.

---

## 💬 Commit Message Conventions

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` A new feature or capability.
- `fix:` A bug fix.
- `docs:` Documentation updates.
- `test:` Adding or updating tests.
- `refactor:` Code changes that neither fix a bug nor add a feature.
- `ci:` Changes to CI/CD workflows, build scripts, or release automation.
- `perf:` Performance improvements.

**Example**:
```text
feat: add detection for Go modules and Gin route endpoints

- Parse go.mod for module identity and direct dependencies
- Map Gin engine HTTP route bindings to presentation tier
- Add unit tests covering go.mod parsing
```

---

## 🛡️ Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in `gitdiagram`, **please do not disclose it publicly in an issue or forum**.

Instead, please report it privately:

1. **GitHub Security Advisory**: Submit a report via [GitHub Private Vulnerability Reporting](https://github.com/vserey/gitdiagram/security/advisories/new).
2. **Email**: If you are unable to use GitHub Security Advisories, send an encrypted email to the maintainer at `vichhaiyserey@gmail.com`.

Include:
- A description of the vulnerability and its potential impact.
- Step-by-step reproduction steps or a minimal proof-of-concept repository.
- Recommended remediation steps, if known.

We will acknowledge receipt within 48 hours and work with you on a coordinated fix and disclosure schedule.
