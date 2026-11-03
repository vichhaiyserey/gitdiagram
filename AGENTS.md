# AGENTS.md — AI Agent Operating Manual & Safety Guardrails

This document establishes the mandatory operational boundaries, architectural constraints, and verification protocols for autonomous AI coding assistants (such as Antigravity, Claude, Copilot, Cursor, and Windsurf) working within the `secdiagram` repository.

All AI agents operating on this codebase **MUST** read, understand, and adhere to these guidelines.

---

## 🎯 1. Core Mission & Philosophy

`secdiagram` is a lightweight, high-performance, deterministic static analysis engine that generates:
- **Human-friendly system architecture diagrams** (`secdiagram.com` and C4 style) in Mermaid, PNG, SVG, and PDF.
- **Detailed architectural relationship graphs** (modules, classes, methods, endpoints, database schemas, queues).
- **SAST security overlays & threat models** citing exact `path:line` references, exportable to OASIS SARIF v2.1.0.
- **Evidence-grounded AI architectural narratives** via local Ollama or OpenAI endpoints without hallucinations.

The guiding motto is: ***Small but Gold*** — minimal footprint, zero runtime bloat, maximum reliability.

---

## ⛔ 2. Absolute Non-Negotiable Constraints

Agents must **NEVER** violate these 6 cardinal rules:

### Rule 1: Zero External Runtime Dependencies
- **Constraint**: `secdiagram`'s core package **must remain 100% standard library**.
- **Action**: Never add any third-party package to `dependencies = []` in `pyproject.toml`.
- **Allowed Exception**: Tooling required purely for developer workflows (such as `ruff`, `mypy`, `bandit`, `pip-audit`, `coverage`) belongs exclusively in `[project.optional-dependencies] dev`.
- **Runtime implementation**: Use standard library modules (`ast`, `urllib`, `dataclasses`, `hashlib`, `json`, `pathlib`, `re`, `shutil`, `tempfile`, `subprocess`).
- **Supply-chain pinning**: All non-runtime tooling must be exact-pinned (`==`) in `pyproject.toml`; CI must pin pip/build tool versions; GitHub Actions must use full commit SHAs with version comments; container and Compose images must use exact tags plus `@sha256:` digests; npm dependencies must be installed from the committed `docker/mermaid/package-lock.json` via `npm ci`. Never use `latest`, version ranges, or floating action tags.

### Rule 2: Strict Determinism
- **Constraint**: The exact same codebase analyzed multiple times must produce byte-for-byte identical output (`diagram.mmd`, `diagram-highlevel.mmd`, `graph.json`, `security.sarif`, `ARCHITECTURE.md`).
- **Action**:
  - Never iterate over unordered `set` or dictionary keys when writing diagram elements, markdown, or JSON.
  - Always use `stable_id(*parts)` from `secdiagram_core.model` to generate IDs.
  - Sort lists and keys deterministically before output serialization.

### Rule 3: Zero Code Execution on Analyzed Repositories
- **Constraint**: `secdiagram` is designed to analyze potentially untrusted third-party repositories.
- **Action**:
  - **NEVER** use `eval()`, `exec()`, `compile()`, or `importlib.import_module()` to inspect code.
  - All source analysis must be performed strictly via AST parsing (`ast.parse`) and static regex/manifest parsing.
  - Treat all inspected code as untrusted data.

### Rule 4: 100% Offline-First Architecture
- **Constraint**: The CLI and analysis pipeline must execute seamlessly on air-gapped systems without internet access.
- **Action**:
  - Never make hardcoded, mandatory network requests during core analysis.
  - Image rendering fallbacks (Kroki, mermaid.ink) and LLM narratives must be strictly optional opt-in features with graceful local error handling.
  - Respect the `--offline` flag everywhere.

### Rule 5: Zero Secret Leaks & Rigorous Pre-Commit Hygiene
- **Constraint**: Never introduce or commit real API keys, credentials, tokens, passwords, private keys, or `.env` files into source code, test fixtures, documentation, or commit messages.
- **Action**:
  - In unit tests and fixtures, use obvious mock placeholders (e.g. `mock_token_12345`, `dummy-api-key`).
  - Never edit or bypass `.gitignore` or `.dockerignore` to force-track ignored or sensitive files.
  - Run a secret pattern scan before committing.

### Rule 6: Strictly No Direct Push to `main` — Always Use Feature Branches
- **Constraint**: Autonomous AI agents must **NEVER** push commits directly to the `main` (or `master`) branch.
- **Action**:
  - Never run `git push origin main` or attempt to push directly to `main`.
  - Always check out a dedicated, descriptively named feature or bugfix branch (e.g. `feature/...`, `feat/...`, `fix/...`, `ci/...`) before committing or pushing.
  - Push changes exclusively to the feature branch: `git push -u origin <branch-name>`.
  - Open a Pull Request (PR) against `main` for CI validation and human review.

---

## 🗺️ 3. Repository Architecture Map

When implementing fixes or enhancements, modify only the relevant modules:

| Module | Responsibility | Key Interfaces / Functions |
|---|---|---|
| [`secdiagram_core/discover.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/discover.py) | Repository enumeration, `.gitignore` parsing, polyglot manifest detection | `discover_repo()`, `RepoContext` |
| [`secdiagram_core/ast_index.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/ast_index.py) | Python AST parsing for definitions, routes, calls, tasks, type annotations | `index_repo()`, `FileIndex`, `DefRec`, `CallRec` |
| [`secdiagram_core/java_index.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/java_index.py) | Stdlib-only Java/Spring lexical indexer, DI/call graph edges, and Java SAST heuristics | `index_java()`, `build_java_graph()`, `analyze_java_security()` |
| [`secdiagram_core/resolver.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/resolver.py) | Qualified symbol resolution, star-import handling, re-exports | `Resolver`, `Resolution` |
| [`secdiagram_core/graph_builder.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/graph_builder.py) | Assembly of dependency graph, node pruning, edge deduplication | `GraphBuilder`, `BuildStats` |
| [`secdiagram_core/high_level.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/high_level.py) | C4 subsystem compiler, tiering (Ingress, Gateway, Services, Data, External) | `build_high_level_architecture()`, `render_mermaid_highlevel()` |
| [`secdiagram_core/security.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/security.py) | SAST heuristics: taint tracking, SQLi, command injection, secret patterns | `analyze()`, `Finding` |
| [`secdiagram_core/iac.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/iac.py) | Infrastructure-as-Code audits: Dockerfile, Compose, K8s, Terraform | `analyze_iac()`, `IacResult` |
| [`secdiagram_core/render_mermaid.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/render_mermaid.py) | Detailed Mermaid diagram generation, node shape styling | `render_mermaid()` |
| [`secdiagram_core/render_image.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/render_image.py) | PNG/SVG/PDF rendering via local `mmdc`, Kroki, or mermaid.ink | `render_image()`, `ImageRenderError` |
| [`secdiagram_core/render_sarif.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/render_sarif.py) | OASIS SARIF v2.1.0 security report generation | `render_sarif()` |
| [`secdiagram_core/baseline.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/baseline.py) | Security baseline: load/write/deterministically suppress known findings | `load_baseline()`, `write_baseline()`, `apply_baseline()` |
| [`secdiagram_core/render_markdown.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/render_markdown.py) | Markdown architecture report with citations | `render_markdown()` |
| [`secdiagram_core/render_json.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/render_json.py) | Full structured graph JSON serializer | `render_json()` |
| [`secdiagram_core/llm.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/llm.py) | Structured prompt templates & streaming/request handling for Ollama/OpenAI | `generate_narrative()`, `NarrativeError` |
| [`secdiagram_core/cli.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/cli.py) | CLI argument parser, pipeline orchestration, exit codes | `main()`, `build_parser()` |
| [`secdiagram_core/model.py`](file:///C:/Users/Lenovo/projects/clone-secdiagram/secdiagram_core/model.py) | Data models: `Graph`, `Node`, `Edge`, `Finding`, `Loc`, `stable_id` | `stable_id()`, `SEVERITY_RANK` |

---

## 🧪 4. Required Agent Verification Steps

Before declaring any coding task complete or committing changes, AI agents **MUST** execute the following verification steps in sequence:

### Step 1: Run Full Unit Test Suite
```bash
python -m unittest discover -s tests -v
```
- **Requirement**: All 97+ tests must pass with exit code `0`.
- If new functionality was added, corresponding unit tests must be added in `tests/test_*.py`.

### Step 2: Verify Code Quality & Type Safety
```bash
# Lint checks
ruff check .

# Static type analysis
mypy
```
- **Requirement**: Zero lint errors and zero type errors.

### Step 3: Run Static Application Security Testing (SAST)
```bash
python -m bandit -r secdiagram_core -lll
```
- **Requirement**: Zero high/critical severity findings.

### Step 4: Verify Git Working Tree
```bash
git status
git diff
```
- **Requirement**: Ensure no unintended files (such as `.coverage`, cache directories, test image dumps, or `.env` files) were modified or staged.

---

## 🔒 5. Security & Secure Coding Rules for Agents

1. **Non-Cryptographic Hashing**:
   Whenever calling `hashlib.sha1` or `hashlib.md5` for deterministic identifier generation (e.g. in `stable_id`), you must pass `usedforsecurity=False` to prevent Bandit `B324` / FIPS alerts:
   ```python
   digest = hashlib.sha1(data.encode("utf-8"), usedforsecurity=False).hexdigest()
   ```

2. **Safe Path Normalization & Traversal Prevention**:
   - Always resolve paths safely against the repo root:
     ```python
     target = (root / rel_path).resolve()
     if not str(target).startswith(str(root.resolve())):
         # Path escapes root directory - skip safely!
     ```
   - Never allow absolute paths from untrusted user configurations to escape root.

3. **Subprocess Execution**:
   - Never use `shell=True` in `subprocess.run` or `subprocess.Popen`.
   - Pass arguments strictly as a `list[str]`.
   - Always specify a reasonable `timeout` (e.g. `timeout=30`).

4. **Network Requests**:
   - All HTTP requests via `urllib.request.urlopen` must set an explicit `timeout`.
   - Catch specific exceptions (`urllib.error.HTTPError`, `urllib.error.URLError`, `TimeoutError`).
   - Do not leak authorization tokens or credentials in exception error messages.

5. **Python Typing Conventions (PEP 585 & PEP 604)**:
   - Target Python 3.10+.
   - Use `|` for unions: `str | None` instead of `Optional[str]`.
   - Use built-in generic collections: `list[T]`, `dict[K, V]`, `set[T]`.
   - Import abstract collection types from `collections.abc` (`Iterable`, `Mapping`, `Sequence`), **never** from `typing`.

---

## 📝 6. Branching, Commit & Pull Request Conventions for Agents

When creating branches, committing changes, or pushing on behalf of the user, AI agents must:

1. **Branching Protocol (Strictly No Direct Push to `main`)**:
   - **NEVER** run `git push origin main` or attempt to push directly to `main` (or `master`).
   - Check the active branch with `git branch --show-current`. If currently on `main`, immediately check out a dedicated feature branch before committing or pushing:
     ```bash
     git checkout -b <prefix>/<descriptive-name>
     ```
   - Standard branch naming prefixes:
     - `feat/<feature-name>` for new capabilities or analyzers.
     - `fix/<bug-or-alert-name>` for bug fixes or security remediations.
     - `ci/<workflow-name>` for CI/CD workflow updates.
     - `docs/<doc-update>` for documentation updates.
     - `refactor/<module-name>` for refactoring without functional changes.
   - Always push strictly to the feature branch:
     ```bash
     git push -u origin <branch-name>
     ```
   - Notify the user of the pushed branch name so they can review and open a Pull Request.

2. **Follow Conventional Commits**:
   - `feat:` for new capabilities or analyzers.
   - `fix:` for bug fixes.
   - `ci:` for CI/CD workflow updates.
   - `docs:` for documentation updates.
   - `test:` for test additions or refactoring.
   - `refactor:` for code restructuring without behavioral change.
3. **Provide a Meaningful Multi-Line Description**:
   Summarize the specific technical changes, impacted modules, and test results.
4. **Never include AI internal metadata or conversational artifacts** inside commit messages.
