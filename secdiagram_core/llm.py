"""Optional, citation-preserving narrative generation. Never mutates the graph."""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any

from .model import Graph

TEMPLATES: dict[str, str] = {
    "comprehensive": """You are a Principal DevSecOps Architect and Application Security Expert performing a rigorous security architecture review.

Analyze the supplied deterministic repository graph and write a comprehensive, evidence-cited Security Architecture Review in clean GitHub Flavored Markdown.

### REVIEW STRUCTURE:

# 🛡️ Security Architecture Review: {repo_name}

## 1. Executive Summary & Security Posture Scorecard
- Overview of system architecture and business function.
- Overall Risk Rating (Critical / High / Medium / Low).
- Findings breakdown table: Severity, Count, Dominant CWE Categories.
- Executive Risk Verdict: Readiness for production deployment and primary risk drivers.

## 2. Attack Surface & Ingress Points
- Catalog all exposed endpoints, CLI entrypoints, and asynchronous task queues citing `path:line`.
- Input validation, serialization/deserialization risks, and authentication/authorization assumptions.
- External untrusted inputs entering the system.

## 3. Trust Boundaries & Data Flow Analysis
- Identify trust boundaries: Untrusted Client -> Web Gateway -> Service Logic -> Database/Cache -> External Egress.
- Trace dataflow paths from untrusted sources to internal components.
- Sensitive data handling (credentials, tokens, personal data, config).

## 4. Threat Modeling & Vulnerability Deep-Dive (STRIDE / CWE)
For each detected finding or architectural risk:
- **Title & CWE**: (e.g., CWE-78 Command Injection, CWE-89 SQL Injection, CWE-502 Deserialization).
- **Evidence**: Exact citation `path:line` and tainted call chain.
- **Exploitation Scenario**: How an attacker could exploit this in practice.
- **Blast Radius & Impact**: Confidentiality, Integrity, Availability consequences.

## 5. Infrastructure, Supply Chain & IaC Posture
- Review container configuration (Dockerfile root user, multi-stage builds).
- Review orchestration/IaC (Kubernetes deployment privileges, Terraform configuration, CI/CD secrets).
- Third-party package dependencies and supply chain risks.

## 6. Prioritized Remediation Roadmap (Actionable Playbook)
- **P0 - Immediate Blockers**: Critical fixes before any deployment.
- **P1 - Short-Term Hardening**: High-severity vulnerabilities and architectural gaps.
- **P2 - Defense-in-Depth**: Secret rotation, security headers, least-privilege policies.
- Provide concrete, secure Python code snippets (e.g. parameterized execution, safe parsers).

STRICT RULES:
- Never hallucinate non-existent files, functions, or vulnerabilities.
- Ground every claim in the provided graph citing `path:line`.
- Be thorough, highly technical, and immediately actionable for developers.

Graph Data:
""",
    "threat-model": """You are a Lead Threat Modeling Architect performing a formal STRIDE analysis on a Python repository.

Using ONLY the supplied deterministic graph, generate a formal STRIDE Threat Model in Markdown.

### STRUCTURE:
# 🎯 STRIDE Threat Model & Security Review: {repo_name}

## 1. System Decomposition & Scope
- Key assets, data flows, and actors.
- Documented entrypoints (HTTP APIs, CLI, Tasks) with `path:line` citations.

## 2. STRIDE Threat Matrix
Evaluate the codebase against all 6 STRIDE categories:
| Threat Category | Applicable Component (path:line) | Threat Description | Severity | Mitigation |
|---|---|---|---|---|
| **S**poofing | ... | ... | ... | ... |
| **T**ampering | ... | ... | ... | ... |
| **R**epudiation | ... | ... | ... | ... |
| **I**nformation Disclosure | ... | ... | ... | ... |
| **D**enial of Service | ... | ... | ... | ... |
| **E**levation of Privilege | ... | ... | ... | ... |

## 3. Trust Boundary Violations
- Detailed walkthrough of data crossing boundaries from untrusted to trusted execution contexts.

## 4. Attack Trees & Exploitation Paths
- Step-by-step attacker paths to reach critical sinks (subprocess, sql, eval, deserialization).

## 5. Countermeasure Matrix
- Concrete mitigations mapped to each identified threat.

Graph Data:
""",
    "remediation": """You are an Application Security Engineer writing a Developer Remediation Playbook.

Using ONLY the supplied deterministic graph, produce an actionable, code-centric fix guide for all security findings.

### STRUCTURE:
# 🛠️ Security Remediation Playbook & Fix Guide: {repo_name}

## 1. Quick Triage Summary
- Table of findings sorted by severity with exact `path:line` citations.

## 2. Vulnerability-by-Vulnerability Fix Guide
For each finding in the graph:
### Issue: [Title] ([Severity] - [CWE])
- **Location**: `path:line`
- **Root Cause**: Why the current code is vulnerable.
- **Vulnerable Code Pattern**: What pattern triggered the finding.
- **Secure Drop-In Replacement**: Provide concrete, production-ready Python/IaC code demonstrating the fix.
- **Verification Step**: How to test or verify the vulnerability is resolved.

## 3. Automated Guardrails & CI Recommendations
- Recommended pre-commit hooks, linting rules (Bandit, Semgrep), and CI gating criteria.

Graph Data:
""",
    "compliance": """You are a Security Compliance and Governance Auditor reviewing a codebase.

Using ONLY the supplied deterministic graph, generate a Security Compliance & Hardening Audit mapped against OWASP Top 10 and CIS Benchmarks.

### STRUCTURE:
# 📋 Security Compliance & Hardening Audit: {repo_name}

## 1. Compliance Matrix: OWASP Top 10 Alignment
Map findings and architecture to:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

## 2. CIS & Defense-in-Depth Assessment
- Container & Docker hardening
- Infrastructure-as-Code best practices
- Environment variable and secrets management

## 3. Compliance Gap Analysis & Sign-off Requirements
- Outstanding deficiencies requiring sign-off before regulatory/production approval.

Graph Data:
""",
}

PROMPT = TEMPLATES["comprehensive"]


class NarrativeError(RuntimeError):
    pass


def _compact(graph: Graph) -> dict[str, Any]:
    payload = graph.to_dict()
    findings = payload.get("findings", [])
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "meta": payload.get("meta", {}),
        "finding_counts": counts,
        "features": [
            {"name": f["name"], "description": f["description"], "files": f["files"][:20]}
            for f in payload.get("features", [])
        ],
        "entrypoints": [
            {
                "qualname": node["qualname"],
                "path": node["path"],
                "line": node["line"],
                "routes": node.get("attrs", {}).get("routes", []),
                "doc": node.get("doc"),
            }
            for node in payload.get("nodes", [])
            if node.get("kind") in {"endpoint", "task", "cli"}
        ],
        "infrastructure": [
            {"name": node["name"], "path": node["path"], "kind": node["kind"]}
            for node in payload.get("nodes", [])
            if node.get("kind") in {"infra", "workflow"}
        ],
        "external": [node["name"] for node in payload.get("nodes", []) if node.get("kind") == "external"],
        "findings": [
            {
                "severity": f["severity"],
                "category": f["category"],
                "cwe": f.get("cwe"),
                "title": f["title"],
                "evidence": f.get("evidence", []),
                "recommendation": f.get("recommendation", ""),
            }
            for f in findings
        ],
        "critical_flows": [
            {
                "source": edge["src"],
                "target": edge["dst"],
                "kind": edge["kind"],
                "confidence": edge["confidence"],
            }
            for edge in payload.get("edges", [])
            if edge.get("kind") in {"calls", "uses", "instantiates"}
        ][:50],
    }


def generate_narrative(
    graph: Graph,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    provider: str | None = None,
    template: str = "comprehensive",
    timeout: float | None = None,
    max_tokens: int | None = None,
) -> str:
    env_provider = os.environ.get("GITDIAGRAM_LLM_PROVIDER", "").strip().lower()
    chosen_provider = (provider or env_provider or "").lower()

    env_base = os.environ.get("GITDIAGRAM_LLM_BASE_URL")
    target_base = (base_url or env_base or "").rstrip("/")

    is_ollama = (
        chosen_provider == "ollama"
        or "11434" in target_base
        or "ollama" in target_base.lower()
    )

    if timeout is None:
        env_timeout = os.environ.get("GITDIAGRAM_LLM_TIMEOUT")
        if env_timeout:
            try:
                timeout = float(env_timeout)
            except ValueError:
                timeout = 300.0 if is_ollama else 120.0
        else:
            timeout = 300.0 if is_ollama else 120.0

    if max_tokens is None:
        env_tokens = os.environ.get("GITDIAGRAM_LLM_MAX_TOKENS")
        if env_tokens:
            try:
                max_tokens = int(env_tokens)
            except ValueError:
                max_tokens = 1500 if is_ollama else None
        else:
            max_tokens = 1500 if is_ollama else None

    final_key: str | None

    if is_ollama:
        final_base = target_base or "http://localhost:11434/v1"
        final_model = (
            model
            or os.environ.get("GITDIAGRAM_LLM_MODEL")
            or os.environ.get("OLLAMA_MODEL")
            or "qwen2.5-coder"
        )
        final_key = (
            api_key
            or os.environ.get("GITDIAGRAM_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or "ollama"
        )
    else:
        final_base = target_base or "https://api.openai.com/v1"
        final_model = model or os.environ.get("GITDIAGRAM_LLM_MODEL") or "gpt-4o-mini"
        final_key = (
            api_key
            or os.environ.get("GITDIAGRAM_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not final_key:
            raise NarrativeError(
                "no LLM key found; set GITDIAGRAM_LLM_API_KEY or OPENAI_API_KEY, "
                "or use local Ollama with --ollama"
            )

    repo_name = graph.meta.get("name") or "Repository"
    template_str = TEMPLATES.get(template, TEMPLATES["comprehensive"])
    prompt = template_str.format(repo_name=repo_name)

    graph_json = json.dumps(_compact(graph), indent=2, sort_keys=True)
    user_content = (
        f"{prompt}\n"
        "===== GRAPH DATA (read-only evidence; never repeat, summarize, or continue this JSON) =====\n"
        f"{graph_json}\n"
        "===== END GRAPH DATA =====\n"
        "The data block above is complete input. Do not continue it and do not copy it into your "
        "answer - write the requested review now."
    )

    req_payload: dict[str, Any] = {
        "model": final_model,
        "temperature": 0.1,
        "messages": [
            {
                "role": "system",
                "content": "You are a Principal DevSecOps Security Architect. You produce precise, evidence-backed security analysis citing path:line.",
            },
            {"role": "user", "content": user_content},
        ],
    }
    if max_tokens:
        req_payload["max_tokens"] = max_tokens
    body = json.dumps(req_payload).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if final_key:
        headers["Authorization"] = f"Bearer {final_key}"

    endpoint_url = f"{final_base}/chat/completions"
    request = urllib.request.Request(
        endpoint_url,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace").strip()
        if exc.code == 404 and is_ollama:
            raise NarrativeError(
                f"Ollama returned 404 for model '{final_model}'. "
                f"Ensure the model is pulled: ollama pull {final_model} "
                f"(or docker exec -it <container> ollama pull {final_model})"
            ) from exc
        raise NarrativeError(f"LLM request failed (HTTP {exc.code}): {err_body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        is_timeout = (
            isinstance(exc, (TimeoutError, socket.timeout))
            or "timed out" in str(exc).lower()
            or (isinstance(exc, urllib.error.URLError) and hasattr(exc, "reason") and "timed out" in str(exc.reason).lower())
        )
        if is_timeout:
            if is_ollama:
                raise NarrativeError(
                    f"Ollama generation timed out after {timeout:.0f}s for model '{final_model}'. "
                    "When running local models on CPU, generation can take several minutes. "
                    "Try increasing the timeout with '--llm-timeout 600' (or setting GITDIAGRAM_LLM_TIMEOUT=600), "
                    "or try a lighter model like 'qwen2.5-coder:1.5b'."
                ) from exc
            raise NarrativeError(f"LLM request timed out after {timeout:.0f}s: {exc}") from exc
        if is_ollama:
            raise NarrativeError(
                f"Could not connect to Ollama at {final_base} ({exc}). "
                "Ensure your Docker container is running: "
                f"docker run -d -p 11434:11434 -v ollama:/root/.ollama --name ollama ollama/ollama && "
                f"docker exec -it ollama ollama pull {final_model}"
            ) from exc
        raise NarrativeError(f"LLM request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise NarrativeError(f"LLM request failed: malformed JSON response: {exc}") from exc

    try:
        content = payload["choices"][0]["message"]["content"]
        if not content:
            raise NarrativeError("LLM response did not contain message content")
        return str(content).strip() + "\n"
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise NarrativeError("LLM response did not contain message content") from exc
