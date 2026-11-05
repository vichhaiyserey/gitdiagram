"""Command-line interface for secdiagram."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import AnalysisConfig, run_analysis
from .baseline import apply_baseline, ignore_baseline, load_baseline, write_baseline
from .high_level import build_high_level_architecture, render_mermaid_highlevel
from .llm import NarrativeError, generate_narrative
from .model import SEVERITY_RANK
from .render_html import render_html
from .render_image import ImageRenderError, render_image
from .render_json import write_json
from .render_markdown import render_markdown
from .render_mermaid import render_mermaid
from .render_sarif import render_sarif
from .render_security import render_security_html, render_security_markdown
from .security_report import build_security_report

FORMATS = {"json", "md", "mermaid", "sarif", "png", "svg", "pdf", "image", "html"}


def _parse_formats(value: str) -> list[str]:
    formats = []
    for item in value.split(","):
        item = item.strip().lower()
        if item == "markdown":
            item = "md"
        elif item in {"img", "picture"}:
            item = "image"
        elif item in {"web", "report"}:
            item = "html"
        if item and item not in FORMATS:
            raise argparse.ArgumentTypeError(f"unknown format: {item}")
        if item and item not in formats:
            formats.append(item)
    if not formats:
        raise argparse.ArgumentTypeError("at least one format is required")
    return formats


def _security_reproduce_command(args: argparse.Namespace) -> str:
    def quote(value: str) -> str:
        return f'"{value}"' if " " in value else value

    parts = [
        "secdiagram",
        "--dir",
        quote(args.dir),
        "--security-report",
        args.security_report,
    ]
    if args.sonarqube_report:
        parts.extend(["--sonarqube-report", quote(args.sonarqube_report)])
    if args.xray_report:
        parts.extend(["--xray-report", quote(args.xray_report)])
    for advisory in args.advisory_db:
        parts.extend(["--advisory-db", quote(advisory)])
    if args.baseline:
        parts.extend(["--baseline", quote(args.baseline)])
    if args.fail_on != "none":
        parts.extend(["--fail-on", args.fail_on])
    return " ".join(parts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secdiagram",
        description="Build deterministic architecture, relationship, and security diagrams for a Python repository.",
    )
    parser.add_argument("--dir", default=".", help="repository directory to analyze (default: .)")
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: <dir>/.secdiagram)",
    )
    parser.add_argument(
        "--format",
        default="json,md,mermaid",
        type=_parse_formats,
        help="comma-separated outputs: json, md, mermaid, sarif, html, png, svg, pdf (default: json,md,mermaid)",
    )
    parser.add_argument("--include", action="append", default=[], metavar="GLOB", help="include path glob")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude path glob")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="drop call/inheritance edges below this confidence (default: 0.5)",
    )
    parser.add_argument(
        "--min-finding-confidence",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="drop security findings below this confidence (0.0-1.0; default: 0.0)",
    )
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=2000,
        help="cap the graph node count; 0 disables the cap (default: 2000)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        metavar="N",
        help="parallel indexer processes; 0 = auto, 1 = serial (default: 0)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        metavar="PATH",
        help="incremental index cache directory (default: <out>/cache)",
    )
    parser.add_argument(
        "--no-cache",
        dest="cache",
        action="store_false",
        default=True,
        help="disable the incremental index cache",
    )
    parser.add_argument(
        "--security",
        dest="security",
        action="store_true",
        default=True,
        help="enable the security and IaC overlay (default)",
    )
    parser.add_argument(
        "--no-security",
        dest="security",
        action="store_false",
        help="disable security findings and IaC analysis",
    )
    parser.add_argument(
        "--security-report",
        choices=("html", "md", "both"),
        default=None,
        help="write a standalone security review (security-report.html and/or SECURITY_REVIEW.md)",
    )
    parser.add_argument(
        "--sonarqube-report",
        default=None,
        metavar="PATH",
        help="import a SonarQube issues JSON export as security findings",
    )
    parser.add_argument(
        "--xray-report",
        default=None,
        metavar="PATH",
        help="import a JFrog Xray violations JSON export as dependency findings",
    )
    parser.add_argument(
        "--advisory-db",
        action="append",
        default=[],
        metavar="PATH",
        help="validate imported CVEs against a local CISA KEV/NVD/OSV JSON file or directory (repeatable)",
    )
    parser.add_argument(
        "--link-base",
        default=None,
        help="base URL for Mermaid node clicks, e.g. https://github.com/org/repo/blob/main",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="write NARRATIVE.md using an optional OpenAI-compatible endpoint",
    )
    parser.add_argument(
        "--ollama",
        nargs="?",
        const="qwen2.5-coder",
        default=None,
        metavar="MODEL",
        help="generate NARRATIVE.md using local/docker Ollama (default model: qwen2.5-coder)",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help="LLM model name (e.g. qwen2.5-coder, qwen2.5:7b, gpt-4o-mini)",
    )
    parser.add_argument(
        "--llm-base-url",
        default=None,
        help="LLM API base URL (default: http://localhost:11434 for Ollama native API, https://api.openai.com/v1 for OpenAI)",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="LLM API key (optional for Ollama)",
    )
    parser.add_argument(
        "--llm-template",
        choices=["comprehensive", "threat-model", "remediation", "compliance"],
        default="comprehensive",
        help="security review prompt template: comprehensive (default), threat-model, remediation, compliance",
    )
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=None,
        help="LLM API request timeout in seconds (default: 300s for Ollama, 120s for cloud endpoints)",
    )
    parser.add_argument(
        "--llm-max-tokens",
        type=int,
        default=None,
        help="maximum completion tokens generated by the LLM (default: 1500 for Ollama)",
    )
    parser.add_argument(
        "--llm-context-chars",
        type=int,
        default=None,
        help="maximum graph evidence characters sent to the LLM (default: auto-sized to the model context)",
    )
    parser.add_argument(
        "--image",
        nargs="?",
        const="png",
        default=None,
        metavar="FORMAT",
        choices=["png", "svg", "pdf"],
        help="generate diagram image from diagram.mmd (formats: png, svg, pdf; default: png)",
    )
    parser.add_argument(
        "--to-image",
        dest="image",
        nargs="?",
        const="png",
        metavar="FORMAT",
        choices=["png", "svg", "pdf"],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--image-format",
        choices=["png", "svg", "pdf"],
        default="png",
        help="default diagram image format when generating images (default: png)",
    )
    parser.add_argument(
        "--image-provider",
        choices=["auto", "local", "kroki", "mermaid.ink"],
        default="auto",
        help="renderer for diagram image: auto, local (mmdc), kroki, mermaid.ink (default: auto)",
    )
    parser.add_argument(
        "--image-endpoint",
        default=None,
        help="custom HTTP rendering endpoint URL for kroki or mermaid.ink",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="strictly offline mode: forbids external HTTP diagram rendering and requires local tools",
    )
    parser.add_argument(
        "--mermaid-js",
        default=None,
        metavar="PATH",
        help="inline a local mermaid.min.js bundle into the HTML report for fully offline diagram rendering",
    )
    parser.add_argument(
        "--diagram-detail",
        choices=["architecture", "full", "high-level", "overview"],
        default="architecture",
        help="diagram detail level: architecture (clean, human-friendly), full (every symbol), high-level (subsystem C4 overview) (default: architecture)",
    )
    parser.add_argument(
        "--high-level",
        action="store_true",
        help="generate high-level system overview diagram (subsystems, tiers & connections) as primary diagram",
    )
    parser.add_argument(
        "--max-diagram-nodes",
        type=int,
        default=150,
        help="maximum components displayed in Mermaid architecture diagrams; 0 for unlimited (default: 150)",
    )
    parser.add_argument(
        "--diagram-direction",
        choices=["LR", "TB"],
        default="LR",
        help="diagram layout direction: LR (horizontal), TB (vertical) (default: LR)",
    )
    parser.add_argument(
        "--diagram-theme",
        choices=["modern", "classic"],
        default="modern",
        help="diagram visual theme: modern, classic (default: modern)",
    )
    parser.add_argument(
        "--fail-on",
        type=str.lower,
        choices=["critical", "high", "medium", "low", "info", "none"],
        default="none",
        help="exit with code 2 when a finding at or above this severity exists",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="suppress findings listed in this baseline file so CI fails only on new findings",
    )
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="write security.baseline.json from the current scan (path from --baseline, default <out>/security.baseline.json)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="launch the interactive platform HTTP server and REST API daemon",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=None,
        metavar="PORT",
        help="port for the platform HTTP server (default: 8080)",
    )
    parser.add_argument(
        "--server-host",
        default=None,
        metavar="HOST",
        help="host binding for the platform server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--server-user",
        default=None,
        metavar="USER",
        help="username for platform HTTP Basic Authentication",
    )
    parser.add_argument(
        "--server-pass",
        default=None,
        metavar="PASS",
        help="password for platform HTTP Basic Authentication",
    )
    parser.add_argument(
        "--server-read-only",
        action="store_true",
        default=False,
        help="disallow re-scans via the platform REST API",
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="path to secdiagram configuration JSON file",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the summary")
    parser.add_argument("--version", action="version", version=f"secdiagram {__version__}")
    return parser


def _normalize_cli_path(path_str: str) -> Path:
    p = Path(path_str).expanduser()
    if p.exists() or os.name == "nt":
        return p
    # Detect MSYS2 / Git Bash automatic POSIX-to-Windows path conversion inside Linux environments:
    # Git Bash automatically converts "/repo" -> "C:/Program Files/Git/repo" or "C:\Program Files\Git\repo"
    import re

    m = re.match(
        r"^[a-zA-Z]:[/\\](?:Program Files[/\\]Git[/\\]|msys\d*[/\\]|cygwin\d*[/\\])?(.*)$",
        path_str,
        re.IGNORECASE,
    )
    if m:
        subpath = m.group(1).replace("\\", "/").strip("/")
        if subpath:
            candidate_abs = Path("/" + subpath)
            if candidate_abs.exists() or candidate_abs.parent.exists():
                return candidate_abs
            candidate_rel = Path(subpath)
            if candidate_rel.exists() or candidate_rel.parent.exists():
                return candidate_rel

    parts = Path(path_str.replace("\\", "/")).parts
    for i in range(1, len(parts)):
        cand = Path("/" + "/".join(parts[i:]))
        if cand.exists() or cand.parent.exists():
            return cand
    return p


def server_main(argv: list[str] | None = None) -> int:
    """Dedicated entrypoint for secdiagram-server."""
    parser = argparse.ArgumentParser(
        prog="secdiagram-server",
        description="Run the secdiagram platform HTTP server and REST API daemon.",
    )
    parser.add_argument("--dir", default=".", help="repository directory to serve (default: .)")
    parser.add_argument("--host", default=None, help="host binding (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="port (default: 8080)")
    parser.add_argument("--user", default=None, help="HTTP Basic Auth username")
    parser.add_argument("--password", default=None, help="HTTP Basic Auth password")
    parser.add_argument("--read-only", action="store_true", default=False, help="disallow API-triggered scans")
    parser.add_argument("--config", default=None, help="configuration file path")
    args = parser.parse_args(argv)
    from .server import serve
    root = _normalize_cli_path(args.dir)
    cfg_path = _normalize_cli_path(args.config) if args.config else None
    return serve(
        root=root,
        host=args.host,
        port=args.port,
        auth_username=args.user,
        auth_password=args.password,
        read_only=args.read_only,
        config_path=cfg_path,
    )


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "serve":
        return server_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.jobs < 0:
        parser.error("--jobs must be zero (auto) or a positive integer")
    root = _normalize_cli_path(args.dir)

    if args.serve:
        from .server import serve
        cfg_path = _normalize_cli_path(args.config) if args.config else None
        return serve(
            root=root,
            host=args.server_host,
            port=args.server_port,
            auth_username=args.server_user,
            auth_password=args.server_pass,
            read_only=args.server_read_only,
            config_path=cfg_path,
        )

    out = _normalize_cli_path(args.out) if args.out else root / ".secdiagram"
    cache_dir = None
    if args.cache:
        cache_dir = _normalize_cli_path(args.cache_dir) if args.cache_dir else out / "cache"

    try:
        result = run_analysis(
            AnalysisConfig(
                root=root,
                include=args.include,
                exclude=args.exclude,
                min_confidence=args.min_confidence,
                max_nodes=args.max_nodes,
                security=args.security,
                jobs=args.jobs,
                cache_dir=cache_dir,
                sonarqube_report=(
                    _normalize_cli_path(args.sonarqube_report)
                    if args.sonarqube_report
                    else None
                ),
                xray_report=(
                    _normalize_cli_path(args.xray_report) if args.xray_report else None
                ),
                advisory_dbs=[
                    _normalize_cli_path(path) for path in args.advisory_db
                ],
            )
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"secdiagram: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"secdiagram: analysis failed: {exc}", file=sys.stderr)
        return 1

    graph = result.graph
    if args.min_finding_confidence > 0:
        graph.findings = [
            finding
            for finding in graph.findings
            if finding.confidence >= args.min_finding_confidence
        ]
    graph.meta["finding_confidence_floor"] = args.min_finding_confidence
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    baseline_mode = args.create_baseline or args.baseline is not None
    baseline_path = (
        _normalize_cli_path(args.baseline)
        if args.baseline
        else out / "security.baseline.json"
    )
    baseline_label = args.baseline if args.baseline else baseline_path.name
    if baseline_mode:
        if args.create_baseline:
            count = write_baseline(graph, baseline_path)
            apply_baseline(graph, {finding.id for finding in graph.findings}, baseline_label)
            print(f"secdiagram: created baseline with {count} finding(s): {baseline_path}", file=sys.stderr)
            written.append(baseline_path)
        else:
            baseline_ids: set[str] = set()
            try:
                baseline_ids = load_baseline(baseline_path)
            except FileNotFoundError:
                print(
                    f"secdiagram: baseline file not found: {baseline_path} "
                    f"(no findings suppressed; create one with --create-baseline)",
                    file=sys.stderr,
                )
                ignore_baseline(graph, baseline_label)
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                print(
                    f"secdiagram: ignoring malformed baseline ({exc}); "
                    "regenerate it with --create-baseline",
                    file=sys.stderr,
                )
                ignore_baseline(graph, baseline_label)
            else:
                known, new = apply_baseline(graph, baseline_ids, baseline_label)
                print(
                    f"secdiagram: baseline {baseline_label} suppresses {known} known finding(s); "
                    f"{new} new finding(s) remain",
                    file=sys.stderr,
                )

    meta = dict(graph.meta)
    meta.update(
        {
            "name": result.repo.name,
            "commit": result.repo.commit,
            "branch": result.repo.branch,
            "dirty": result.repo.dirty,
            "analysis": graph.meta.get("analysis", {}),
            "finding_confidence_floor": args.min_finding_confidence,
        }
    )
    if "security_baseline" in graph.meta:
        meta["security_baseline"] = graph.meta["security_baseline"]

    if args.high_level:
        args.diagram_detail = "high-level"

    hla = build_high_level_architecture(root, graph)
    highlevel_mermaid = render_mermaid_highlevel(
        hla,
        direction=args.diagram_direction if args.diagram_direction == "LR" else "TB",
        theme=args.diagram_theme,
    )

    mermaid_text: str | None = None
    narrative_text: str | None = None

    try:
        if "json" in args.format:
            path = out / "graph.json"
            write_json(graph, path)
            written.append(path)
        if "md" in args.format:
            path = out / "ARCHITECTURE.md"
            path.write_text(
                render_markdown(graph, meta, high_level_mermaid=highlevel_mermaid),
                encoding="utf-8",
                newline="\n",
            )
            written.append(path)
        if "mermaid" in args.format:
            if args.diagram_detail in {"high-level", "overview"}:
                mermaid_text = highlevel_mermaid
            else:
                mermaid_text = render_mermaid(
                    graph,
                    link_base=args.link_base,
                    detail=args.diagram_detail,
                    direction=args.diagram_direction,
                    theme=args.diagram_theme,
                    max_diagram_nodes=args.max_diagram_nodes,
                )
            path = out / "diagram.mmd"
            path.write_text(mermaid_text, encoding="utf-8", newline="\n")
            written.append(path)

            hl_path = out / "diagram-highlevel.mmd"
            hl_path.write_text(highlevel_mermaid, encoding="utf-8", newline="\n")
            written.append(hl_path)
        if "sarif" in args.format:
            path = out / "security.sarif"
            path.write_text(render_sarif(graph), encoding="utf-8", newline="\n")
            written.append(path)

        image_formats: list[str] = []
        if args.image:
            image_formats.append(args.image.lower())
        if "image" in args.format:
            fmt = (args.image or args.image_format or "png").lower()
            if fmt not in image_formats:
                image_formats.append(fmt)
        for fmt in ("png", "svg", "pdf"):
            if fmt in args.format and fmt not in image_formats:
                image_formats.append(fmt)

        if image_formats:
            if mermaid_text is None:
                if args.diagram_detail in {"high-level", "overview"}:
                    mermaid_text = highlevel_mermaid
                else:
                    mermaid_text = render_mermaid(
                        graph,
                        link_base=args.link_base,
                        detail=args.diagram_detail,
                        direction=args.diagram_direction,
                        theme=args.diagram_theme,
                        max_diagram_nodes=args.max_diagram_nodes,
                    )
            for fmt in image_formats:
                img_path = out / f"diagram.{fmt}"
                render_image(
                    mermaid_source=mermaid_text,
                    output_path=img_path,
                    image_format=fmt,
                    provider=args.image_provider,
                    endpoint=args.image_endpoint,
                    offline=args.offline,
                )
                written.append(img_path)

                hl_img_path = out / f"diagram-highlevel.{fmt}"
                render_image(
                    mermaid_source=highlevel_mermaid,
                    output_path=hl_img_path,
                    image_format=fmt,
                    provider=args.image_provider,
                    endpoint=args.image_endpoint,
                    offline=args.offline,
                )
                written.append(hl_img_path)

        if args.ollama:
            args.llm = True
            llm_provider = "ollama"
            llm_model = args.llm_model or args.ollama
        else:
            llm_provider = None
            llm_model = args.llm_model

        if args.llm:
            try:
                narrative_text = generate_narrative(
                    graph,
                    model=llm_model,
                    base_url=args.llm_base_url,
                    api_key=args.llm_api_key,
                    provider=llm_provider,
                    template=args.llm_template,
                    timeout=args.llm_timeout,
                    max_tokens=args.llm_max_tokens,
                    context_chars=args.llm_context_chars,
                )
            except NarrativeError as exc:
                print(f"secdiagram: {exc}", file=sys.stderr)
                return 1
            path = out / "NARRATIVE.md"
            path.write_text(narrative_text, encoding="utf-8", newline="\n")
            written.append(path)

        if args.security_report:
            report = build_security_report(
                graph,
                meta,
                fail_on=args.fail_on,
                reproduce=_security_reproduce_command(args),
                narrative=narrative_text,
            )
            if args.security_report in {"md", "both"}:
                path = out / "SECURITY_REVIEW.md"
                path.write_text(
                    render_security_markdown(report),
                    encoding="utf-8",
                    newline="\n",
                )
                written.append(path)
            if args.security_report in {"html", "both"}:
                path = out / "security-report.html"
                path.write_text(
                    render_security_html(report),
                    encoding="utf-8",
                    newline="\n",
                )
                written.append(path)

        if "html" in args.format:
            mermaid_js_text: str | None = None
            if args.mermaid_js:
                bundle = _normalize_cli_path(args.mermaid_js)
                try:
                    mermaid_js_text = bundle.read_text(encoding="utf-8")
                except OSError as exc:
                    print(f"secdiagram: could not read mermaid bundle: {exc}", file=sys.stderr)
                    return 1
            if args.diagram_detail in {"high-level", "overview"}:
                report_detail = highlevel_mermaid
            else:
                if mermaid_text is None:
                    mermaid_text = render_mermaid(
                        graph,
                        link_base=args.link_base,
                        detail=args.diagram_detail,
                        direction=args.diagram_direction,
                        theme=args.diagram_theme,
                        max_diagram_nodes=args.max_diagram_nodes,
                    )
                report_detail = mermaid_text
            path = out / "report.html"
            path.write_text(
                render_html(
                    graph,
                    meta=meta,
                    hla=hla,
                    highlevel_mermaid=highlevel_mermaid,
                    detail_mermaid=report_detail,
                    narrative=narrative_text,
                    root=root,
                    mermaid_js=mermaid_js_text,
                    offline=args.offline,
                ),
                encoding="utf-8",
                newline="\n",
            )
            written.append(path)
    except (OSError, ImageRenderError) as exc:
        print(f"secdiagram: could not write output: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        counts: dict[str, int] = {}
        for finding in graph.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        severity_text = ", ".join(f"{key}={counts[key]}" for key in ("critical", "high", "medium", "low", "info") if key in counts)
        baseline_info = ""
        if baseline_mode:
            info = graph.meta.get("security_baseline") or {}
            baseline_info = f", {info.get('known', 0)} known in baseline, {info.get('new', 0)} new"
        polyglot_bits = []
        if hla.languages:
            polyglot_bits.append(f"languages: {', '.join(sorted(hla.languages))}")
        if hla.frameworks:
            polyglot_bits.append(f"frameworks: {', '.join(sorted(hla.frameworks))}")
        polyglot_info = f" [{'; '.join(polyglot_bits)}]" if polyglot_bits else ""
        print(
            f"secdiagram: {result.python_files} Python files, {len(graph.nodes)} nodes, "
            f"{len(graph.edges)} edges, {len(graph.features)} features, {len(hla.subsystems)} subsystems, "
            f"{len(graph.findings)} findings"
            + (f" ({severity_text})" if severity_text else "")
            + (baseline_info if baseline_info else "")
            + polyglot_info
        )
        if result.cache_stats:
            parts = [
                f"{name} {stats['hits']} hit(s)/{stats['misses']} miss(es)"
                for name, stats in sorted(result.cache_stats.items())
            ]
            print("secdiagram: index cache " + ", ".join(parts), file=sys.stderr)
        if result.parse_errors:
            print(f"secdiagram: skipped {len(result.parse_errors)} file(s) with parse errors", file=sys.stderr)
        for path in written:
            print(f"  wrote {path}")

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(
            SEVERITY_RANK.get(finding.severity, 0) >= threshold and not finding.baseline
            for finding in graph.findings
        ):
            return 2
    return 0
