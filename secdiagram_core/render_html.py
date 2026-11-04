"""Self-contained interactive HTML report: every analysis result in one offline file.

The report embeds the full graph payload (nodes, edges, features, findings),
source snippets for each security finding, subsystem architecture, diagram
sources, and analysis-quality metadata inside a single HTML document. The UI
is vanilla JavaScript and CSS with zero project-external assets, so the file
renders correctly on air-gapped machines. Diagram rendering degrades
gracefully: if a local ``mermaid.min.js`` bundle is supplied (``--mermaid-js``)
it is inlined; otherwise a pinned CDN copy is referenced client-side; when
fully offline the raw Mermaid source is always shown and copyable.
"""

from __future__ import annotations

import dataclasses
import html as html_module
import json
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION, __version__
from .high_level import HighLevelArchitecture
from .model import Finding, Graph

MERMAID_CDN = "https://cdn.jsdelivr.net/npm/mermaid@11.12.0/dist/mermaid.min.js"
MERMAID_STUB_FALLBACK = (
    "Mermaid could not be loaded, so the diagram is shown as annotated source. "
    "Supply a local bundle with --mermaid-js <path/to/mermaid.min.js> for a fully "
    "offline report; the source below stays copyable either way."
)

SEVERITIES = ("critical", "high", "medium", "low", "info")

_RESOLUTION_HELP = {
    "exact": "Resolved to a concrete symbol via AST scope analysis (highest confidence).",
    "import": "Resolved through the import table of the referring module.",
    "inferred": "Resolved by heuristic class/type inference; confidence is discounted.",
    "name-only": "Only a bare name matched; weaker evidence - verify manually.",
    "dynamic": "Call looks dynamic (getattr/duck typing); counted, not guessed.",
}

_METHOD_NOTE = (
    "secdiagram performs 100% static analysis: Python sources are parsed with the "
    "ast module and are never executed, manifests are scanned with lightweight regex "
    "parsers, and every claim carries a path:line citation. Security findings are "
    "SAST heuristics: they highlight suspicious constructs with a confidence score "
    "and remediation guidance, not a proof of exploitability. Confirmed issues "
    "should be verified at the cited locations."
)

_LIMITATION_NOTE = (
    "Known limitations: dynamic imports, getattr reflection, metaprogramming, monkey "
    "patching and runtime configuration cannot be resolved statically; such behaviour "
    "is reported as unresolved/dynamic counts instead of guessed edges. Files that "
    "fail to parse are skipped and listed on this page. Low-severity findings may "
    "represent intentional design choices; use --fail-on to gate CI on this report."
)


def _esc(text: Any) -> str:
    return html_module.escape(str(text), quote=True)


def _netjson(payload: dict[str, Any]) -> str:
    """Serialise embedded JSON so it cannot terminate the script tag."""
    text = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _sev_counts(graph: Graph) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in graph.findings:
        severity = finding.severity if finding.severity in counts else "info"
        counts[severity] += 1
    return counts


def _snippet_maps(root: Path, findings: list[Finding]) -> dict[str, dict[str, Any]]:
    """Collect a small source window around the first evidence line of each finding."""
    windows: dict[str, set[int]] = {}
    for finding in findings:
        if not finding.evidence:
            continue
        loc = finding.evidence[0]
        lines = windows.setdefault(loc.path, set())
        for offset in (-2, -1, 0, 1, 2):
            if loc.line + offset > 0:
                lines.add(loc.line + offset)
    snippets: dict[str, dict[str, Any]] = {}
    root_dir = root.resolve()
    for path in sorted(windows):
        target = (root / path).resolve()
        try:
            if not target.is_relative_to(root_dir) or not target.is_file():
                continue
            if target.stat().st_size > 5 * 1024 * 1024:
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue
        file_lines = text.splitlines()
        collected: list[list[Any]] = []
        for number in sorted(windows[path]):
            if number <= len(file_lines):
                collected.append([number, file_lines[number - 1][:400]])
        if collected:
            snippets[path] = {"lines": collected}
    return snippets


def _subtitle(meta: dict[str, Any]) -> str:
    bits = []
    if meta.get("branch"):
        bits.append(f"branch {meta['branch']}")
    if meta.get("commit"):
        bits.append(f"commit {str(meta['commit'])[:12]}")
    if meta.get("dirty"):
        bits.append("working tree dirty")
    return " | ".join(bits)


def render_html(
    graph: Graph,
    meta: dict[str, Any] | None = None,
    hla: HighLevelArchitecture | None = None,
    highlevel_mermaid: str | None = None,
    detail_mermaid: str | None = None,
    narrative: str | None = None,
    root: Path | None = None,
    mermaid_js: str | None = None,
    offline: bool = False,
) -> str:
    """Build the complete, self-contained interactive HTML report."""
    graph.dedupe_edges()
    graph.findings = graph.sorted_findings()
    meta = dict(meta or {})

    if hla is not None:
        subsystems = [dataclasses.asdict(sub) for sub in hla.subsystems]
        connections = [dataclasses.asdict(conn) for conn in hla.connections]
        languages = sorted(hla.languages)
        frameworks = sorted(hla.frameworks)
    else:
        subsystems, connections, languages, frameworks = [], [], [], []

    edge_kinds: dict[str, int] = {}
    edge_resolutions: dict[str, int] = {}
    node_kinds: dict[str, int] = {}
    for edge in graph.edges:
        edge_kinds[edge.kind] = edge_kinds.get(edge.kind, 0) + 1
        edge_resolutions[edge.resolution] = edge_resolutions.get(edge.resolution, 0) + 1
    for node in graph.nodes.values():
        node_kinds[node.kind] = node_kinds.get(node.kind, 0) + 1

    findings_payload: list[dict[str, Any]] = []
    snippet_maps = _snippet_maps(root, graph.findings) if root is not None else {}
    for finding in graph.findings:
        entry = finding.to_dict()
        if finding.evidence:
            loc = finding.evidence[0]
            entry["loc"] = loc.to_dict()
            window = snippet_maps.get(loc.path)
            if window:
                entry["snippet"] = window
        findings_payload.append(entry)

    analysis = meta.get("analysis") or {}
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            **meta,
            "tool": "secdiagram",
            "tool_version": __version__,
            "analysis": analysis,
        },
        "summary": {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "feature_count": len(graph.features),
            "finding_count": len(graph.findings),
            "subsystem_count": len(subsystems),
            "python_files": meta.get("python_files"),
            "iac_files": meta.get("iac_files"),
            "severities": _sev_counts(graph),
            "node_kinds": dict(sorted(node_kinds.items())),
            "edge_kinds": dict(sorted(edge_kinds.items())),
            "edge_resolutions": dict(sorted(edge_resolutions.items())),
            "languages": languages,
            "frameworks": frameworks,
            "unresolved_count": analysis.get("unresolved_count", 0),
            "truncated": bool(analysis.get("truncated", False)),
            "dropped_nodes": analysis.get("dropped_nodes", 0),
            "parse_errors": sorted(analysis.get("parse_errors", [])),
            "min_confidence": meta.get("min_confidence"),
            "include": sorted(meta.get("include", []) or []),
            "exclude": sorted(meta.get("exclude", []) or []),
        },
        "features": [feature.to_dict() for feature in sorted(graph.features, key=lambda f: f.name)],
        "nodes": [node.to_dict() for node in graph.sorted_nodes()],
        "edges": [edge.to_dict() for edge in graph.sorted_edges()],
        "findings": findings_payload,
        "subsystems": sorted(subsystems, key=lambda s: (s["tier"], s["name"])),
        "connections": connections,
        "diagram": {"highlevel": highlevel_mermaid, "detailed": detail_mermaid},
        "narrative": narrative,
        "notes": {
            "methodology": _METHOD_NOTE,
            "limitations": _LIMITATION_NOTE,
            "resolutions": _RESOLUTION_HELP,
        },
        "ui": {"offline": bool(offline)},
    }

    if mermaid_js:
        script = "<script>" + mermaid_js + "</script>"
    elif offline:
        script = ""
    else:
        script = f'<script src="{MERMAID_CDN}" crossorigin="anonymous"></script>'

    name = str(meta.get("name") or "repository")
    return (
        _TEMPLATE.replace("__TITLE__", _esc(name))
        .replace("__HEADING__", _esc(name))
        .replace("__SUBTITLE__", _esc(_subtitle(meta)))
        .replace("__MERMAID_SCRIPT__", script)
        .replace("__MERMAID_FALLBACK__", _esc(MERMAID_STUB_FALLBACK))
        .replace("__REPORT_DATA__", _netjson(payload))
    )


_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ - secdiagram report</title>
<style>
:root{--bg:#f8fafc;--bg2:#ffffff;--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#2563eb;--accent2:#1e40af;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--chip:#f1f5f9;--code-bg:#0f172a;--code-fg:#e2e8f0;--shadow:0 1px 3px rgba(15,23,42,.08)}
[data-theme="dark"]{--bg:#0b1120;--bg2:#11182c;--fg:#e2e8f0;--muted:#94a3b8;--line:#233047;--accent:#60a5fa;--accent2:#93c5fd;--chip:#1a233a;--code-bg:#060a14;--shadow:none}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);font-size:14px;line-height:1.5}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header.app{position:sticky;top:0;z-index:40;background:var(--bg2);border-bottom:1px solid var(--line);padding:10px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;box-shadow:var(--shadow)}
.brand{display:flex;align-items:baseline;gap:10px}.brand b{font-size:17px}.brand .brand-tag{color:var(--muted);font-size:12px}
.sub{color:var(--muted);font-size:12px}.spacer{flex:1}
button.btn{cursor:pointer;border:1px solid var(--line);background:var(--bg2);color:var(--fg);border-radius:8px;padding:5px 11px;font-size:12.5px}
button.btn:hover{border-color:var(--accent);color:var(--accent)}
button.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}button.btn.primary:hover{color:#fff}
nav.tabs{position:sticky;top:52px;z-index:35;display:flex;gap:2px;overflow-x:auto;background:var(--bg2);border-bottom:1px solid var(--line);padding:0 12px}
nav.tabs button{background:none;border:none;border-bottom:2.5px solid transparent;color:var(--muted);padding:10px 13px;font-size:13.5px;cursor:pointer;white-space:nowrap}
nav.tabs button.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
nav.tabs button:hover{color:var(--fg)}
main{max-width:1280px;margin:0 auto;padding:18px 16px 60px}
section.view{display:none}section.view.active{display:block}
h2.vt{font-size:19px;margin:4px 0 12px}h3{margin:0 0 8px}
.grid.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:16px}
.kpi .card{padding:12px 14px}.kpi b{font-size:22px;display:block}.kpi span{color:var(--muted);font-size:12px}
.card{background:var(--bg2);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow)}
.pad{padding:14px}.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:900px){.row2{grid-template-columns:1fr}}
.chip{display:inline-block;background:var(--chip);border-radius:999px;padding:1px 9px;font-size:11.5px;margin:1px 3px 1px 0;border:1px solid var(--line)}
.sev-chip{color:#fff;font-weight:700;font-size:11.5px;border:none}
.s-critical{background:#dc2626}.s-high{background:#ea580c}.s-medium{background:#ca8a04}.s-low{background:#0891b2}.s-info{background:#64748b}
.k-chip{display:inline-block;font-size:11px;border:1px solid var(--line);border-radius:6px;padding:0 6px;color:var(--muted);background:var(--chip)}
table.tbl{width:100%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-top:6px}
.tbl th,.tbl td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
.tbl th{background:var(--chip);color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;user-select:none}
.tbl tr:last-child td{border-bottom:none}
.tbl tr.clickable{cursor:pointer}.tbl tr.clickable:hover td{background:rgba(37,99,235,.07)}
.tbl tr.flash>td{animation:flash 2s ease-out}
@keyframes flash{0%{background:rgba(37,99,235,.4)}100%{background:transparent}}
tr.detail>td{background:var(--chip)}
.loc{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:var(--accent);background:none;border:none;cursor:pointer;padding:0;text-align:left}
.loc:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.muted{color:var(--muted)}
pre.src{background:var(--code-bg);color:var(--code-fg);border-radius:8px;padding:12px;overflow:auto;font-size:12px;line-height:1.5;margin:6px 0}
pre.src .ln{display:inline-block;width:4.5em;color:#64748b;user-select:none;white-space:pre}
pre.src .hitline{background:rgba(220,38,38,.35);color:#fff}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0 6px}
.toolbar input,.toolbar select{background:var(--bg2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:6px 10px;font-size:13px}
.toolbar input[type="search"]{min-width:240px;flex:1}
.sevfilter{display:flex;gap:6px;flex-wrap:wrap}
.sevfilter button{border:1px solid var(--line);border-radius:999px;background:var(--bg2);color:var(--fg);padding:4px 12px;font-size:12px;cursor:pointer}
.sevfilter button.on{color:#fff;border-color:transparent;font-weight:700}
.confbar{display:inline-block;width:52px;height:6px;border-radius:4px;background:var(--chip);vertical-align:middle;overflow:hidden;margin-right:5px}
.confbar i{display:block;height:100%;background:var(--accent)}
.mini{font-size:12px}.note{border-left:3px solid var(--accent);background:var(--chip);padding:9px 12px;border-radius:0 8px 8px 0;font-size:12.5px;margin:10px 0}
.note.warn{border-left-color:var(--warn)}
.diagram-head{display:flex;align-items:center;gap:10px;margin:8px 0;flex-wrap:wrap}
.diagram-wrap{position:relative;overflow:auto;background:var(--bg2);border:1px solid var(--line);border-radius:10px;min-height:260px;cursor:grab}
.diagram-wrap svg{transform-origin:0 0;max-width:100%}
.sub-arrow{font-weight:700}
footer.app{max-width:1280px;margin:0 auto;padding:14px 16px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--code-bg);color:var(--code-fg);padding:8px 16px;border-radius:8px;font-size:12.5px;opacity:0;transition:opacity .25s;z-index:99}
.toast.show{opacity:1;pointer-events:none}
.bar-row{display:grid;grid-template-columns:130px 1fr 46px;gap:8px;align-items:center;margin:3px 0;font-size:12.5px}
.bar-track{height:10px;background:var(--chip);border-radius:5px;overflow:hidden}
.bar-track i{display:block;height:100%}
dl.meta{display:grid;grid-template-columns:220px 1fr;gap:4px 12px;margin:0}
dl.meta dt{color:var(--muted);font-size:12.5px}dl.meta dd{margin:0;word-break:break-all}
</style>
</head>
<body>
<header class="app">
  <div class="brand"><b>__HEADING__</b><span class="brand-tag">secdiagram report</span></div>
  <div class="sub">__SUBTITLE__</div>
  <div class="spacer"></div>
  <button class="btn" id="btn-export-json" title="Download all embedded data as JSON">Export JSON</button>
  <button class="btn" id="btn-theme" title="Toggle dark mode">Dark</button>
</header>
<nav class="tabs" id="gd-nav"></nav>
<main id="gd-main">
  <section class="view" id="view-overview"></section>
  <section class="view" id="view-systems"></section>
  <section class="view" id="view-diagram"></section>
  <section class="view" id="view-findings"></section>
  <section class="view" id="view-components"></section>
  <section class="view" id="view-dependencies"></section>
  <section class="view" id="view-features"></section>
  <section class="view" id="view-quality"></section>
  <section class="view" id="view-narrative"></section>
</main>
<footer class="app">Generated by secdiagram static analysis. Every claim cites a path:line reference from the analyzed source tree; no code was executed during analysis.</footer>
<div class="toast" id="gd-toast"></div>
<script id="gd-data" type="application/json">__REPORT_DATA__</script>
__MERMAID_SCRIPT__
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("gd-data").textContent);
  var S = DATA.summary || {};
  var M = DATA.meta || {};
  var NOT = DATA.notes || {};
  var SEVS = ["critical", "high", "medium", "low", "info"];
  var SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  var SEV_RGB = { critical: "220,38,38", high: "234,88,12", medium: "202,138,4", low: "8,145,178", info: "100,116,139" };
  var RES_HELP = NOT.resolutions || {};
  var TABS = ["overview", "systems", "diagram", "findings", "components", "dependencies", "features", "quality"];
  if (DATA.narrative) TABS.push("narrative");
  var TAB_LABEL = { overview: "Overview", systems: "Systems", diagram: "Diagram", findings: "Findings", components: "Components", dependencies: "Dependencies", features: "Features", quality: "Data quality", narrative: "Narrative" };
  var mmCounter = 0;

  var nodesById = {}, findingsById = {}, findingsByNode = {};
  var edgesOut = {}, edgesIn = {};
  DATA.nodes.forEach(function (n) { nodesById[n.id] = n; });
  DATA.edges.forEach(function (e) {
    (edgesOut[e.src] = edgesOut[e.src] || []).push(e);
    (edgesIn[e.dst] = edgesIn[e.dst] || []).push(e);
  });
  DATA.findings.forEach(function (f) {
    findingsById[f.id] = f;
    if (f.node_id && nodesById[f.node_id]) {
      (findingsByNode[f.node_id] = findingsByNode[f.node_id] || []).push(f);
    }
  });

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.setAttribute("class", cls);
    if (text !== undefined && text !== null) e.textContent = text !== "" ? text : " ";
    return e;
  }

  var toastTimer = null;
  function toast(msg) {
    var t = document.getElementById("gd-toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.remove("show"); }, 1500);
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast("Copied: " + shorten(text)); }, fallbackCopy(text));
    } else { fallbackCopy(text); }
  }
  function shorten(text) {
    return String(text).length > 48 ? String(text).slice(0, 45) + "..." : String(text);
  }
  function fallbackCopy(text) {
    return function () {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); toast("Copied: " + shorten(text)); } catch (err) { toast("Copy failed"); }
      document.body.removeChild(ta);
    };
  }

  function locBtn(path, line, col) {
    var label = path + (line ? ":" + line : "");
    var b = el("button", "loc", label);
    b.type = "button";
    b.title = label + " - click to copy";
    if (col) b.title += " (col " + col + ")";
    b.addEventListener("click", function (ev) { ev.stopPropagation(); copyText(label); });
    return b;
  }
  function sevChip(sev) { return el("span", "chip sev-chip s-" + sev, sev); }
  function kindChip(kind) { return el("span", "k-chip", kind); }
  function confConf(conf) {
    var cell = el("td");
    var bar = el("span", "confbar");
    var fill = el("i");
    fill.style.width = Math.round((conf || 0) * 100) + "%";
    bar.appendChild(fill);
    cell.appendChild(bar);
    cell.appendChild(el("span", "mini", (conf || 0).toFixed(2)));
    return cell;
  }
  function nodeLink(id) {
    var n = nodesById[id];
    if (!n) return el("span", null, id);
    var a = el("a", null, n.qualname);
    a.href = "#node/" + id;
    a.title = n.kind + (n.path ? (" | " + n.path + ":" + n.line) : "");
    a.addEventListener("click", function (ev) { ev.stopPropagation(); });
    return a;
  }
  function findingLink(id) {
    var f = findingsById[id];
    if (!f) return null;
    var a = el("a", null, f.title);
    a.href = "#finding/" + id;
    a.title = f.severity + " " + f.category + " - " + f.message;
    return a;
  }

  function bar(block, map, colorFn, orderList) {
    var keys = Object.keys(map);
    if (orderList) keys = orderList.filter(function (k) { return map[k]; });
    else keys = keys.sort(function (a, b) { return map[b] - map[a]; });
    var total = keys.reduce(function (acc, k) { return acc + map[k]; }, 0);
    if (!total) { block.appendChild(el("div", "muted mini", "none")); return; }
    keys.forEach(function (k) {
      var row = el("div", "bar-row");
      row.appendChild(el("div", null, k));
      var track = el("div", "bar-track");
      var fill = el("i");
      fill.style.width = Math.max(2, Math.round(map[k] * 100 / total)) + "%";
      fill.style.background = colorFn ? colorFn(k) : "var(--accent)";
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el("span", "mini", String(map[k])));
      block.appendChild(row);
    });
  }

  function codePre(code) {
    var pre = el("pre", "src");
    String(code).split("\\n").forEach(function (lineText, idx) {
      pre.appendChild(el("span", "ln", String(idx + 1) + ":"));
      pre.appendChild(document.createTextNode(lineText + "\\n"));
    });
    return pre;
  }

  var VIEWS = {};

  VIEWS.overview = function (root) {
    var grid = el("div", "grid kpi");
    [[ "Nodes", S.node_count], ["Edges", S.edge_count], ["Features", S.feature_count], ["Findings", S.finding_count],
     ["Subsystems", S.subsystem_count], ["Python files", S.python_files], ["IaC files", S.iac_files], ["Unresolved calls", S.unresolved_count]]
      .forEach(function (item) {
        var card = el("div", "card");
        card.appendChild(el("b", null, item[1] === null || item[1] === undefined ? "-" : String(item[1])));
        card.appendChild(el("span", null, item[0]));
        grid.appendChild(card);
      });
    root.appendChild(grid);

    var row = el("div", "row2");
    var sec = el("div", "card pad");
    sec.appendChild(el("h3", null, "Security posture"));
    var sevMap = S.severities || {};
    var total = SEVS.reduce(function (acc, s) { return acc + (sevMap[s] || 0); }, 0);
    if (!total) {
      sec.appendChild(el("div", "mini muted", "No security or IaC findings were reported for this repository."));
    } else {
      bar(sec, sevMap, function (s) { return "rgb(" + SEV_RGB[s] + ")"; }, SEVS);
      if (M.security_baseline) {
        var bl = M.security_baseline;
        var blNote = el("div", "mini muted", bl.known + " finding(s) suppressed by baseline '" + (bl.file || "security.baseline.json") + "'; " + bl.new + " new.");
        blNote.style.marginTop = "10px";
        sec.appendChild(blNote);
      }
      var cats = {};
      DATA.findings.forEach(function (f) { cats[f.category] = (cats[f.category] || 0) + 1; });
      var lead = el("div", "mini muted", "findings by category (top 8)");
      lead.style.marginTop = "10px";
      sec.appendChild(lead);
      bar(sec, cats);
    }
    var repo = el("div", "card pad");
    repo.appendChild(el("h3", null, "Repository"));
    var dl = el("dl", "meta");
    function metaRow(dt, dd) {
      dl.appendChild(el("dt", null, dt));
      dl.appendChild(el("dd", null, dd));
    }
    metaRow("Name", M.name || "unknown");
    metaRow("Commit", (M.commit ? String(M.commit).slice(0, 12) : "none") + (M.branch ? " on " + M.branch : ""));
    metaRow("Git repository", M.is_git ? "yes" : "no");
    metaRow("Working tree", M.dirty ? "dirty" : "clean");
    metaRow("Languages", S.languages && S.languages.length ? S.languages.join(", ") : "Python");
    metaRow("Frameworks", S.frameworks && S.frameworks.length ? S.frameworks.join(", ") : "none detected");
    repo.appendChild(dl);
    row.appendChild(sec); row.appendChild(repo);
    root.appendChild(row);

    var worst = DATA.findings.filter(function (f) { return f.severity === "critical" || f.severity === "high"; }).slice(0, 5);
    if (worst.length) {
      var top = el("div", "card pad");
      top.style.marginTop = "12px";
      top.appendChild(el("h3", null, "Top priorities"));
      var list = el("ul");
      worst.forEach(function (f) {
        var li = el("li", null);
        li.appendChild(sevChip(f.severity));
        li.appendChild(document.createTextNode(" "));
        var a = findingLink(f.id);
        if (a) li.appendChild(a);
        if (f.loc) {
          li.appendChild(document.createTextNode(" @ "));
          li.appendChild(locBtn(f.loc.path, f.loc.line, f.loc.col));
        }
        list.appendChild(li);
      });
      top.appendChild(list);
      root.appendChild(top);
    }
  };

  function subName(id) {
    var sub = (DATA.subsystems || []).filter(function (s) { return s.id === id; })[0];
    return sub ? sub.name : id;
  }

  VIEWS.systems = function (root) {
    root.appendChild(el("h2", "vt", "Subsystem architecture"));
    if (!(DATA.subsystems && DATA.subsystems.length)) {
      root.appendChild(el("div", "note", "No subsystems detected."));
    } else {
      var tbl = el("table", "tbl");
      var thead = el("thead");
      var hr = el("tr");
      ["Tier", "Subsystem", "Kind", "Technology", "Description", "Details", "Findings"].forEach(function (h) {
        hr.appendChild(el("th", null, h));
      });
      thead.appendChild(hr); tbl.appendChild(thead);
      var tbody = el("tbody");
      (DATA.subsystems || []).forEach(function (sub) {
        var r = el("tr");
        var tierCell = el("td"); tierCell.appendChild(kindChip(sub.tier)); r.appendChild(tierCell);
        var nameCell = el("td");
        nameCell.appendChild(el("b", null, sub.name));
        if (sub.path) nameCell.appendChild(el("div", "mini muted", sub.path));
        r.appendChild(nameCell);
        var kindCell = el("td"); kindCell.appendChild(kindChip(sub.kind)); r.appendChild(kindCell);
        r.appendChild(el("td", "mini", sub.technology || ""));
        r.appendChild(el("td", "mini muted", sub.description || ""));
        var det = el("td", "mini");
        (sub.details || []).forEach(function (d) { det.appendChild(kindChip(d)); });
        r.appendChild(det);
        var fcell = el("td");
        if (sub.findings_count) {
          fcell.appendChild(sevChip(sub.max_severity || "low"));
          fcell.appendChild(el("span", "mini muted", " x" + sub.findings_count));
        }
        r.appendChild(fcell);
        tbody.appendChild(r);
      });
      tbl.appendChild(tbody);
      root.appendChild(tbl);
    }
    var cons = el("div", "card pad");
    cons.style.marginTop = "12px";
    cons.appendChild(el("h3", null, "Subsystem connections"));
    (DATA.connections || []).forEach(function (conn) {
      var line = el("div");
      line.style.margin = "3px 0";
      line.appendChild(el("span", "mono", subName(conn.src)));
      var arrow = conn.style === "thick" ? "===>" : (conn.style === "dotted" ? "-.->" : "--->");
      line.appendChild(el("span", "mini muted", " " + arrow + (conn.label ? " [" + conn.label + "]" : "") + " "));
      line.appendChild(el("span", "mono", subName(conn.dst)));
      cons.appendChild(line);
    });
    root.appendChild(cons);
  };

  var diagramState = { mode: "highlevel", source: false };

  VIEWS.diagram = function (root) {
    root.appendChild(el("h2", "vt", "Architecture diagram"));
    var head = el("div", "diagram-head");
    var highBtn = el("button", "btn", "High-level");
    var detBtn = el("button", "btn", "Detailed");
    var srcBtn = el("button", "btn", "View source");
    var copyBtn = el("button", "btn", "Copy Mermaid");
    head.appendChild(highBtn); head.appendChild(detBtn); head.appendChild(srcBtn); head.appendChild(copyBtn);
    root.appendChild(head);
    root.appendChild(el("div", "note mini muted", "Pan: drag - Zoom: mouse wheel - Reset: double click. Configure diagram flags with --diagram-direction, --diagram-theme and --max-diagram-nodes."));
    var wrap = el("div", "diagram-wrap pad");
    root.appendChild(wrap);
    attachPanZoom(wrap);

    function activeSource() {
      if (diagramState.mode === "highlevel") return (DATA.diagram && DATA.diagram.highlevel) || "";
      return (DATA.diagram && DATA.diagram.detailed) || "";
    }
    function redraw() {
      highBtn.className = diagramState.mode === "highlevel" ? "btn primary" : "btn";
      detBtn.className = diagramState.mode !== "highlevel" ? "btn primary" : "btn";
      srcBtn.className = diagramState.source ? "btn primary" : "btn";
      var code = activeSource();
      wrap.textContent = "";
      if (!code) {
        wrap.appendChild(el("div", "muted", "No diagram source available."));
        return;
      }
      if (diagramState.source) {
        var pre = codePre(code);
        pre.style.maxHeight = "70vh";
        wrap.appendChild(pre);
        return;
      }
      renderMermaid(wrap, code);
    }
    highBtn.addEventListener("click", function () { diagramState.mode = "highlevel"; redraw(); });
    detBtn.addEventListener("click", function () { diagramState.mode = "detailed"; redraw(); });
    srcBtn.addEventListener("click", function () { diagramState.source = !diagramState.source; redraw(); });
    copyBtn.addEventListener("click", function () { copyText(activeSource()); });
    redraw();
  };

  function attachPanZoom(wrap) {
    if (wrap.__gdReset) return;
    var scale = 1, tx = 0, ty = 0, drag = null;
    function apply() {
      var svg = wrap.querySelector("svg");
      if (svg) svg.style.transform = "translate(" + tx + "px," + ty + "px) scale(" + scale + ")";
    }
    wrap.addEventListener("wheel", function (e) {
      if (!wrap.querySelector("svg")) return;
      e.preventDefault();
      var factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
      scale = Math.min(8, Math.max(0.2, scale * factor));
      apply();
    }, { passive: false });
    wrap.addEventListener("pointerdown", function (e) {
      if (!wrap.querySelector("svg")) return;
      drag = { x: e.clientX, y: e.clientY, tx: tx, ty: ty };
      wrap.style.cursor = "grabbing";
    });
    wrap.addEventListener("pointermove", function (e) {
      if (!drag) return;
      tx = drag.tx + (e.clientX - drag.x);
      ty = drag.ty + (e.clientY - drag.y);
      apply();
    });
    wrap.addEventListener("pointerup", function () { drag = null; wrap.style.cursor = "grab"; });
    wrap.addEventListener("pointerleave", function () { drag = null; wrap.style.cursor = "grab"; });
    wrap.addEventListener("dblclick", function () { scale = 1; tx = 0; ty = 0; apply(); });
    wrap.__gdReset = function () { scale = 1; tx = 0; ty = 0; apply(); };
  }

  function renderMermaid(container, code) {
    container.textContent = "";
    if (typeof mermaid === "undefined") {
      container.appendChild(el("div", "note warn", "__MERMAID_FALLBACK__"));
      container.appendChild(codePre(code));
      return;
    }
    if (!mermaid.__gdInit) {
      mermaid.__gdInit = true;
      mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        theme: "default",
        maxTextSize: Math.max(400000, code.length * 4),
        maxEdges: 20000,
        useMaxWidth: false
      });
    }
    mermaid.render("gd-svg-" + (++mmCounter), code).then(function (out) {
      container.innerHTML = out.svg;
    }, function (err) {
      container.textContent = "";
      container.appendChild(el("div", "note warn", "Mermaid failed to render this diagram: " + (err && err.message ? err.message : String(err))));
      container.appendChild(codePre(code));
    });
  }

  var findingView = { q: "", severities: {}, category: "all", minConf: 0, sort: "severity" };

  VIEWS.findings = function (root) {
    root.appendChild(el("h2", "vt", "Security and IaC findings"));
    var toolbar = el("div", "toolbar");
    var tableWrap = el("div");
    var counter = el("div", "mini muted");
    var tbl = el("table", "tbl");
    var thead = el("thead");
    var hr = el("tr");
    ["Severity", "Finding", "Category / CWE", "Confidence", "Location", "Taint path", ""].forEach(function (h) {
      hr.appendChild(el("th", null, h));
    });
    thead.appendChild(hr);
    tbl.appendChild(thead);
    var tbody = el("tbody");
    tbl.appendChild(tbody);

    var search = el("input");
    search.type = "search";
    search.placeholder = "Search title, message, CWE, category, recommendation...";
    search.value = findingView.q;
    search.addEventListener("input", function () { findingView.q = search.value; draw(); });
    toolbar.appendChild(search);

    var sevWrap = el("div", "sevfilter");
    var sevMap = S.severities || {};
    var allBtn = el("button", null, "all (" + DATA.findings.length + ")");
    allBtn.type = "button";
    allBtn.addEventListener("click", function () {
      findingView.severities = {};
      Array.prototype.forEach.call(sevWrap.querySelectorAll("button"), function (b2) {
        if (b2 !== allBtn) { b2.className = ""; }
      });
      allBtn.className = "on";
      draw();
    });
    sevWrap.appendChild(allBtn);
    SEVS.forEach(function (s) {
      var b = el("button", findingView.severities[s] ? "on" : "", s + " (" + (sevMap[s] || 0) + ")");
      b.type = "button";
      if (findingView.severities[s]) b.style.background = "rgb(" + SEV_RGB[s] + ")";
      b.addEventListener("click", function () {
        findingView.severities[s] = !findingView.severities[s];
        allBtn.className = "";
        var on = findingView.severities[s];
        b.className = on ? "on" : "";
        b.style.background = on ? "rgb(" + SEV_RGB[s] + ")" : "";
        draw();
      });
      sevWrap.appendChild(b);
    });
    toolbar.appendChild(sevWrap);

    var catSel = el("select");
    var cats = {};
    DATA.findings.forEach(function (f) { cats[f.category] = 1; });
    [["all", "category: all"]].concat(Object.keys(cats).sort().map(function (c) { return [c, "category: " + c]; }))
      .forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; catSel.appendChild(o); });
    catSel.value = findingView.category;
    catSel.addEventListener("change", function () { findingView.category = catSel.value; draw(); });
    toolbar.appendChild(catSel);

    var newBtn = el("button", "", "new only");
    newBtn.type = "button";
    newBtn.title = "Hide findings already covered by the security baseline";
    if (findingView.newOnly) newBtn.className = "on";
    newBtn.addEventListener("click", function () {
      findingView.newOnly = !findingView.newOnly;
      newBtn.className = findingView.newOnly ? "on" : "";
      draw();
    });
    toolbar.appendChild(newBtn);

    var minConf = el("input");
    minConf.type = "number"; minConf.step = "0.05"; minConf.min = "0"; minConf.max = "1";
    minConf.style.width = "76px";
    minConf.title = "Minimum confidence";
    minConf.value = String(findingView.minConf);
    minConf.addEventListener("input", function () { findingView.minConf = parseFloat(minConf.value) || 0; draw(); });
    toolbar.appendChild(minConf);

    var sortSel = el("select");
    [["severity", "sort: severity"], ["confidence", "sort: confidence"], ["path", "sort: location"], ["category", "sort: category"]]
      .forEach(function (pair) { var o = el("option", null, pair[1]); o.value = pair[0]; sortSel.appendChild(o); });
    sortSel.value = findingView.sort;
    sortSel.addEventListener("change", function () { findingView.sort = sortSel.value; draw(); });
    toolbar.appendChild(sortSel);

    var csvBtn = el("button", "btn", "Export CSV");
    csvBtn.addEventListener("click", function () {
      download((M.name || "findings") + ".security.findings.csv", findingsCsv(), "text/csv");
    });
    toolbar.appendChild(csvBtn);

    root.appendChild(toolbar);
    root.appendChild(counter);
    root.appendChild(tbl);

    function firstLoc(f) { return f.loc || (f.evidence && f.evidence[0]) || null; }
    function locKey(f) {
      var loc = firstLoc(f);
      return loc ? loc.path + ":" + String(loc.line).padStart(6, "0") : "zzz-";
    }
    function draw() {
      tbody.textContent = "";
      var hasBaseline = DATA.findings.some(function (f) { return f.baseline; });
      newBtn.style.display = hasBaseline ? "" : "none";
      var rows = DATA.findings.filter(function (f) {
        var anySev = !Object.keys(findingView.severities).some(function (k) { return findingView.severities[k]; });
        var okSev = anySev || findingView.severities[f.severity];
        var okCat = findingView.category === "all" || f.category === findingView.category;
        var okConf = (f.confidence || 0) >= findingView.minConf;
        var okNew = !findingView.newOnly || !f.baseline;
        var okQ = !findingView.q || (f.title + " " + f.message + " " + f.id + " " + (f.cwe || "") + " " + f.category + " " + f.recommendation)
          .toLowerCase().indexOf(findingView.q.toLowerCase()) >= 0;
        return okSev && okCat && okConf && okNew && okQ;
      });
      if (findingView.sort === "severity") {
        rows.sort(function (a, b) {
          return (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || (b.confidence - a.confidence) || locKey(a).localeCompare(locKey(b));
        });
      } else if (findingView.sort === "confidence") {
        rows.sort(function (a, b) { return b.confidence - a.confidence || locKey(a).localeCompare(locKey(b)); });
      } else if (findingView.sort === "path") {
        rows.sort(function (a, b) { return locKey(a).localeCompare(locKey(b)); });
      } else {
        rows.sort(function (a, b) { return a.category.localeCompare(b.category) || locKey(a).localeCompare(locKey(b)); });
      }
      var tableBody = el("tbody");
      rows.forEach(function (f) {
        var tr = el("tr", "clickable hitrow");
        tr.id = "row-finding-" + f.id;
        var tdSev = el("td"); tdSev.appendChild(sevChip(f.severity)); tr.appendChild(tdSev);
        var tdTitle = el("td");
        tdTitle.appendChild(el("b", null, f.title));
        if (f.baseline) {
          var knownBadge = el("span", "mini muted", " in baseline");
          knownBadge.style.border = "1px solid var(--border)";
          knownBadge.style.borderRadius = "6px";
          knownBadge.style.padding = "0 4px";
          knownBadge.style.marginLeft = "5px";
          tdTitle.appendChild(knownBadge);
        }
        tdTitle.appendChild(el("div", "mini muted", f.message));
        tr.appendChild(tdTitle);
        var tdCat = el("td", "mini");
        tdCat.appendChild(kindChip(f.category));
        if (f.cwe) {
          tdCat.appendChild(document.createTextNode(" "));
          var cwe = el("a", "mini", f.cwe);
          cwe.href = "https://cwe.mitre.org/data/definitions/" + f.cwe.replace("CWE-", "") + ".html";
          cwe.target = "_blank"; cwe.rel = "noopener";
          cwe.addEventListener("click", function (ev) { ev.stopPropagation(); });
          tdCat.appendChild(cwe);
        }
        tr.appendChild(tdCat);
        tr.appendChild(confConf(f.confidence));
        var tdLoc = el("td");
        var loc = firstLoc(f);
        if (loc) tdLoc.appendChild(locBtn(loc.path, loc.line, loc.col));
        if ((f.evidence || []).length > 1) tdLoc.appendChild(el("div", "mini muted", "+" + (f.evidence.length - 1) + " more evidence"));
        tr.appendChild(tdLoc);
        var tdTrace = el("td", "mini");
        var trace = f.trace || [];
        if (trace.length) {
          tdTrace.appendChild(el("div", null, trace.map(function (l) { return l.path + ":" + l.line; }).join(" -> ")));
        } else {
          tdTrace.textContent = "-";
        }
        tr.appendChild(tdTrace);
        var tdExp = el("td", "mini muted", "detail");
        tr.appendChild(tdExp);
        tableBody.appendChild(tr);
        var det = el("tr", "detail");
        det.id = "detail-finding-" + f.id;
        det.style.display = "none";
        var dt = el("td"); dt.setAttribute("colspan", "7");
        det.appendChild(dt);
        tableBody.appendChild(det);
        tr.addEventListener("click", function () {
          var open = det.style.display !== "none";
          if (open) {
            det.style.display = "none";
            tdExp.textContent = "detail";
          } else {
            if (!dt.childElementCount) fillDetail(dt, f);
            det.style.display = "";
            tdExp.textContent = "close x";
          }
        });
      });
      tbl.appendChild(tableBody);
      counter.textContent
        = "Showing " + rows.length + " of " + DATA.findings.length + " findings"
        + (hasBaseline ? " (" + DATA.findings.filter(function (f) { return f.baseline; }).length + " in baseline)" : "");
    }
    draw();
  };

  function fillDetail(dt, f) {
    dt.appendChild(el("div", "mini muted", "Message"));
    dt.appendChild(document.createTextNode(f.message));
    if (f.recommendation) {
      dt.appendChild(el("div", "mini muted", "Remediation"));
      dt.appendChild(document.createTextNode(f.recommendation));
    }
    dt.appendChild(el("div", "mini muted", "Evidence (path:line - all claim locations)"));
    var evList = el("ul", "mini");
    (f.evidence || []).forEach(function (loc) {
      var li = el("li", null);
      li.appendChild(locBtn(loc.path, loc.line, loc.col));
      evList.appendChild(li);
    });
    dt.appendChild(evList);
    if ((f.trace || []).length) {
      dt.appendChild(el("div", "mini muted", "Taint path (source -> sink)"));
      var traceList = el("ol", "mini");
      f.trace.forEach(function (loc) {
        var li = el("li", null);
        li.appendChild(locBtn(loc.path, loc.line, loc.col));
        traceList.appendChild(li);
      });
      dt.appendChild(traceList);
    }
    if (f.snippet && f.snippet.lines && f.snippet.lines.length && f.loc) {
      dt.appendChild(el("div", "mini muted", "Source context from " + f.loc.path));
      var pre = el("pre", "src");
      f.snippet.lines.forEach(function (pair) {
        pre.appendChild(el("span", "ln", String(pair[0]) + ":"));
        var isHit = f.loc && pair[0] === f.loc.line;
        if (isHit) {
          pre.appendChild(el("span", "hitline", pair[1] === "" ? " " : pair[1]));
          pre.appendChild(document.createTextNode("\\n"));
        } else {
          pre.appendChild(document.createTextNode((pair[1] === "" ? " " : pair[1]) + "\\n"));
        }
      });
      dt.appendChild(pre);
    }
    if (f.node_id && nodesById[f.node_id]) {
      var n = nodesById[f.node_id];
      dt.appendChild(el("div", "mini muted", "Related component"));
      var rel = el("div", "mini");
      rel.appendChild(nodeLink(f.node_id));
      rel.appendChild(document.createTextNode(" - " + n.kind + (n.path ? (" at " + n.path + ":" + n.line) : "")));
      dt.appendChild(rel);
    }
  }

  function findingsCsv() {
    var rows = [["id", "severity", "category", "cwe", "confidence", "file", "line", "title", "message", "taint_path", "recommendation", "in_baseline"]];
    DATA.findings.forEach(function (f) {
      var loc = f.loc || (f.evidence && f.evidence[0]) || {};
      var taint = (f.trace || []).map(function (l) { return l.path + ":" + l.line; }).join(" -> ");
      rows.push([f.id, f.severity, f.category, f.cwe || "", f.confidence, loc.path || "", loc.line || "", f.title, f.message, taint, f.recommendation, f.baseline ? "known" : "new"]);
    });
    return rows.map(function (r) {
      return r.map(function (cell) {
        var s = String(cell === undefined || cell === null ? "" : cell);
        return /[",\\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }).join(",");
    }).join("\\n");
  }

  function download(name, text, type) {
    var blob = new Blob([text], { type: type || "text/plain" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    toast("Downloaded " + name);
  }

  var compView = { q: "", kind: "all", feature: "all", findingsOnly: false };

  VIEWS.components = function (root) {
    root.appendChild(el("h2", "vt", "Components"));
    var toolbar = el("div", "toolbar");
    var search = el("input");
    search.type = "search";
    search.placeholder = "Search qualname, file path, docstring...";
    search.value = compView.q;
    search.addEventListener("input", function () { compView.q = search.value; draw(); });
    toolbar.appendChild(search);
    var kindSel = el("select");
    var kinds = {};
    DATA.nodes.forEach(function (n) { kinds[n.kind] = 1; });
    [["all", "kind: all"]].concat(Object.keys(kinds).sort().map(function (k) { return [k, "kind: " + k]; }))
      .forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; kindSel.appendChild(o); });
    kindSel.value = compView.kind;
    kindSel.addEventListener("change", function () { compView.kind = kindSel.value; draw(); });
    toolbar.appendChild(kindSel);
    var featSel = el("select");
    [["all", "feature: all"]].concat(DATA.features.map(function (f) { return [f.name, "feature: " + f.name]; }))
      .forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; featSel.appendChild(o); });
    featSel.value = compView.feature;
    featSel.addEventListener("change", function () { compView.feature = featSel.value; draw(); });
    toolbar.appendChild(featSel);
    var onlyF = el("input"); onlyF.type = "checkbox"; onlyF.id = "c-onlyf";
    onlyF.checked = compView.findingsOnly;
    onlyF.addEventListener("change", function () { compView.findingsOnly = onlyF.checked; draw(); });
    var onlyFL = el("label", "mini muted", "with findings");
    onlyFL.setAttribute("for", "c-onlyf");
    toolbar.appendChild(onlyF); toolbar.appendChild(onlyFL);
    root.appendChild(toolbar);

    var counter = el("div", "mini muted");
    root.appendChild(counter);
    var tableWrap = el("div");
    root.appendChild(tableWrap);
    var CAP = 600;

    function draw() {
      var q = compView.q.toLowerCase();
      var match = DATA.nodes.filter(function (n) {
        var okK = compView.kind === "all" || n.kind === compView.kind;
        var okF = compView.feature === "all" || n.feature === compView.feature;
        var okFo = !compView.findingsOnly || (findingsByNode[n.id] && findingsByNode[n.id].length);
        var hay = (n.qualname + " " + (n.path || "") + " " + (n.doc || "")).toLowerCase();
        return okK && okF && okFo && (!q || hay.indexOf(q) >= 0);
      });
      counter.textContent = "Showing " + Math.min(match.length, CAP) + " of " + match.length + " components" +
        (match.length > CAP ? " - refine filters or search" : "");
      tableWrap.textContent = "";
      var tbl = el("table", "tbl");
      var thead = el("thead");
      var hr = el("tr");
      ["Component", "Kind", "Feature", "Location", "Edges out", "Edges in", "Findings"].forEach(function (h) {
        hr.appendChild(el("th", null, h));
      });
      thead.appendChild(hr); tbl.appendChild(thead);
      var tbody = el("tbody");
      match.slice(0, CAP).forEach(function (n) {
        var outE = edgesOut[n.id] || [], inE = edgesIn[n.id] || [], fs = findingsByNode[n.id] || [];
        var tr = el("tr", "clickable");
        tr.id = "row-node-" + n.id;
        var tdN = el("td");
        tdN.appendChild(el("div", "mono", n.name));
        tdN.appendChild(el("div", "mini muted", n.qualname));
        tr.appendChild(tdN);
        var tdK = el("td"); tdK.appendChild(kindChip(n.kind)); tr.appendChild(tdK);
        tr.appendChild(el("td", "mini", n.feature || ""));
        var tdL = el("td");
        if (n.path) tdL.appendChild(locBtn(n.path, n.line || 0, 0));
        tr.appendChild(tdL);
        tr.appendChild(el("td", "mini", String(outE.length)));
        tr.appendChild(el("td", "mini", String(inE.length)));
        tr.appendChild(el("td", "mini", fs.length ? String(fs.length) : ""));
        tbody.appendChild(tr);
        var det = el("tr", "detail");
        det.style.display = "none";
        var dt = el("td"); dt.setAttribute("colspan", "7");
        det.appendChild(dt);
        tbody.appendChild(det);
        tr.addEventListener("click", function () {
          var open = det.style.display !== "none";
          if (open) { det.style.display = "none"; return; }
          if (!dt.childElementCount) fillNodeDetail(dt, n);
          det.style.display = "";
        });
      });
      tbl.appendChild(tbody);
      tableWrap.appendChild(tbl);
    }
    draw();
  };

  function fillNodeDetail(dt, n) {
    dt.appendChild(el("div", "mini muted", "Qualified name"));
    dt.appendChild(el("div", "mono", n.qualname));
    if (n.doc) {
      dt.appendChild(el("div", "mini muted", "Docstring"));
      var pre = el("pre", "src");
      pre.textContent = n.doc;
      dt.appendChild(pre);
    }
    if (n.attrs) {
      var keys = Object.keys(n.attrs);
      if (keys.length) {
        dt.appendChild(el("div", "mini muted", "Analyzed attributes"));
        var at = el("table", "tbl mini");
        keys.sort().forEach(function (k) {
          var tr = el("tr");
          tr.appendChild(el("td", "mini mono", k));
          var td = el("td", "mini mono");
          td.textContent = typeof n.attrs[k] === "object" ? JSON.stringify(n.attrs[k]) : String(n.attrs[k]);
          tr.appendChild(td);
          at.appendChild(tr);
        });
        dt.appendChild(at);
      }
    }
    dt.appendChild(el("div", "mini muted", "Incoming edges (" + (edgesIn[n.id] || []).length + ")"));
    edgeTable(dt, edgesIn[n.id] || [], true);
    dt.appendChild(el("div", "mini muted", "Outgoing edges (" + (edgesOut[n.id] || []).length + ")"));
    edgeTable(dt, edgesOut[n.id] || [], false);
    var fs = findingsByNode[n.id] || [];
    if (fs.length) {
      dt.appendChild(el("div", "mini muted", "Findings (" + fs.length + ")"));
      var ul = el("ul", "mini");
      fs.forEach(function (f) {
        var li = el("li", null);
        li.appendChild(sevChip(f.severity));
        li.appendChild(document.createTextNode(" "));
        var a = findingLink(f.id);
        if (a) li.appendChild(a);
        li.appendChild(document.createTextNode(f.loc ? (" @ " + f.loc.path + ":" + f.loc.line) : ""));
        ul.appendChild(li);
      });
      dt.appendChild(ul);
    }
  }
  function edgeTable(dt, list, incoming) {
    if (!list.length) { dt.appendChild(el("div", "mini muted", "none")); return; }
    list = list.slice().sort(function (a, b) { return b.confidence - a.confidence; });
    var tbl = el("table", "tbl mini");
    list.slice(0, 60).forEach(function (e) {
      var tr = el("tr");
      var tdA = el("td");
      tdA.appendChild(nodeLink(incoming ? e.src : e.dst));
      tr.appendChild(tdA);
      tr.appendChild(el("td", "mini muted", relationGlyph(e.kind) + " " + e.kind));
      tr.appendChild(confConf(e.confidence));
      var tdR = el("td", "mini muted", e.resolution);
      tdR.title = RES_HELP[e.resolution] || "";
      tr.appendChild(tdR);
      var tdE = el("td", "mini");
      (e.evidence || []).slice(0, 3).forEach(function (loc, k) {
        if (k) tdE.appendChild(document.createTextNode(", "));
        tdE.appendChild(locBtn(loc.path, loc.line, 0));
      });
      tr.appendChild(tdE);
      tbl.appendChild(tr);
    });
    if (list.length > 60) {
      var more = el("div", "mini muted", "+" + (list.length - 60) + " more (edge count truncated in detail view)");
      tbl.appendChild(more);
    }
    dt.appendChild(tbl);
  }
  function relationGlyph(kind) {
    return { calls: "->", contains: "owns", imports: "uses", inherits: "extends" }[kind] || "->";
  }

  var depView = { kind: "all", resolution: "all", q: "" };

  VIEWS.dependencies = function (root) {
    root.appendChild(el("h2", "vt", "Dependency and call graph"));
    var toolbar = el("div", "toolbar");
    var kindSel = el("select");
    [["all", "kind: all"]].concat(Object.keys(S.edge_kinds || {}).sort().map(function (k) { return [k, "kind: " + k]; }))
      .forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; kindSel.appendChild(o); });
    kindSel.value = depView.kind;
    kindSel.addEventListener("change", function () { depView.kind = kindSel.value; draw(); });
    toolbar.appendChild(kindSel);
    var resSel = el("select");
    [["all", "resolution: all"]].concat(Object.keys(S.edge_resolutions || {}).sort().map(function (k) { return [k, "resolution: " + k]; }))
      .forEach(function (p) { var o = el("option", null, p[1]); o.value = p[0]; resSel.appendChild(o); });
    resSel.value = depView.resolution;
    resSel.addEventListener("change", function () { depView.resolution = resSel.value; draw(); });
    toolbar.appendChild(resSel);
    var search = el("input");
    search.type = "search";
    search.placeholder = "Search source/target qualname...";
    search.value = depView.q;
    search.addEventListener("input", function () { depView.q = search.value.toLowerCase(); draw(); });
    toolbar.appendChild(search);
    root.appendChild(toolbar);
    var counter = el("div", "mini muted");
    root.appendChild(counter);
    var tableWrap = el("div");
    root.appendChild(tableWrap);
    var CAP = 800;

    function draw() {
      var rows = DATA.edges.filter(function (e) {
        var okK = depView.kind === "all" || e.kind === depView.kind;
        var okR = depView.resolution === "all" || e.resolution === depView.resolution;
        var okQ = !depView.q || haystack(e).indexOf(depView.q) >= 0;
        return okK && okR && okQ;
      });
      counter.textContent = "Showing " + Math.min(rows.length, CAP) + " of " + rows.length + " edges" +
        (rows.length > CAP ? " - refine filters" : "");
      tableWrap.textContent = "";
      var tbl = el("table", "tbl");
      var thead = el("thead");
      var hr = el("tr");
      ["Source", "Rel", "Target", "Kind", "Confidence", "Resolution", "Evidence"].forEach(function (h) {
        hr.appendChild(el("th", null, h));
      });
      thead.appendChild(hr); tbl.appendChild(thead);
      var tbody = el("tbody");
      rows.slice(0, CAP).forEach(function (e) {
        var tr = el("tr");
        var tdS = el("td"); tdS.appendChild(nodeLink(e.src)); tr.appendChild(tdS);
        tr.appendChild(el("td", "mini muted", relationGlyph(e.kind)));
        var tdD = el("td"); tdD.appendChild(nodeLink(e.dst)); tr.appendChild(tdD);
        tr.appendChild(el("td", "mini", e.kind));
        tr.appendChild(confConf(e.confidence));
        var tdR = el("td", "mini muted", e.resolution);
        tdR.title = RES_HELP[e.resolution] || "";
        tr.appendChild(tdR);
        var tdE = el("td", "mini");
        (e.evidence || []).slice(0, 3).forEach(function (loc, k) {
          if (k) tdE.appendChild(document.createTextNode(", "));
          tdE.appendChild(locBtn(loc.path, loc.line, 0));
        });
        if ((e.evidence || []).length > 3) tdE.appendChild(el("span", "mini muted", " +" + (e.evidence.length - 3)));
        tr.appendChild(tdE);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      tableWrap.appendChild(tbl);
    }
    draw();
  };
  function haystack(e) {
    return (nodesById[e.src] ? nodesById[e.src].qualname : e.src) + " " +
      (nodesById[e.dst] ? nodesById[e.dst].qualname : e.dst);
  }

  VIEWS.features = function (root) {
    root.appendChild(el("h2", "vt", "Feature map"));
    if (!DATA.features.length) {
      root.appendChild(el("div", "note", "No features assigned."));
      return;
    }
    DATA.features.forEach(function (f) {
      var card = el("div", "card pad");
      card.style.marginBottom = "12px";
      card.appendChild(el("h3", null, f.name));
      if (f.description) card.appendChild(el("div", "mini muted", f.description));
      var counts = {};
      f.nodes.forEach(function (id) {
        var n = nodesById[id];
        if (n) counts[n.kind] = (counts[n.kind] || 0) + 1;
      });
      var chips = el("div");
      Object.keys(counts).sort().forEach(function (k) {
        chips.appendChild(el("span", "chip", k + ": " + counts[k]));
      });
      var fCount = DATA.findings.filter(function (ff) {
        var n = ff.node_id && nodesById[ff.node_id];
        return n ? f.nodes.indexOf(n.id) >= 0 : (ff.loc ? f.files.indexOf(ff.loc.path) >= 0 : false);
      }).length;
      chips.appendChild(el("span", "chip", "findings: " + fCount));
      card.appendChild(chips);
      var files = el("div", "mini");
      files.style.marginTop = "4px";
      (f.files || []).slice(0, 16).forEach(function (path, k) {
        if (k) files.appendChild(document.createTextNode(" "));
        files.appendChild(locBtn(path, 0, 0));
      });
      if ((f.files || []).length > 16) files.appendChild(el("span", "mini muted", " +" + (f.files.length - 16) + " more"));
      card.appendChild(files);
      root.appendChild(card);
    });
  };

  VIEWS.quality = function (root) {
    root.appendChild(el("h2", "vt", "Data quality and methodology"));
    if (S.truncated) {
      root.appendChild(el("div", "note warn",
        "Graph was truncated: " + S.dropped_nodes + " nodes were dropped by the node cap. Re-run with a higher --max-nodes for a complete graph."));
    }
    var card = el("div", "card pad");
    card.appendChild(el("h3", null, "Run configuration"));
    var dl = el("dl", "meta");
    function metaRow(dt, dd) {
      dl.appendChild(el("dt", null, dt));
      dl.appendChild(el("dd", null, dd));
    }
    metaRow("Tool", (M.tool || "secdiagram") + " " + (M.tool_version || ""));
    metaRow("Schema version", String(DATA.schema_version));
    metaRow("Repository", M.name || "unknown");
    metaRow("Branch / commit", (M.branch || "-") + " / " + (M.commit ? String(M.commit).slice(0, 12) : "-"));
    metaRow("Python files", S.python_files === undefined ? "-" : String(S.python_files));
    metaRow("IaC files", S.iac_files === undefined ? "-" : String(S.iac_files));
    metaRow("Files discovered", M.files_discovered === undefined ? "-" : String(M.files_discovered));
    metaRow("Files skipped", M.files_skipped === undefined ? "-" : String(M.files_skipped));
    metaRow("Languages", Object.keys(M.languages || {}).sort().map(function (k) { return k + " (" + M.languages[k] + ")"; }).join(", ") || "(none detected)");
    metaRow("Unsupported security languages", (M.unsupported_security_languages || []).join(", ") || "(none)");
    metaRow("Config hash", M.config_hash || "-");
    metaRow("Finding confidence floor", M.finding_confidence_floor === undefined ? "-" : String(M.finding_confidence_floor));
    metaRow("Min edge confidence", S.min_confidence === undefined ? "-" : String(S.min_confidence));
    metaRow("Include globs", (S.include || []).join(", ") || "(none)");
    metaRow("Exclude globs", (S.exclude || []).join(", ") || "(none)");
    metaRow("Unresolved dynamic calls", String(S.unresolved_count));
    metaRow("Dropped nodes (cap)", String(S.dropped_nodes));
    metaRow("Findings total", String(DATA.findings.length));
    card.appendChild(dl);
    root.appendChild(card);

    var res = el("div", "card pad");
    res.style.marginTop = "12px";
    res.appendChild(el("h3", null, "Edge resolution distribution"));
    bar(res, S.edge_resolutions || {});
    var ul = el("ul", "mini muted");
    Object.keys(RES_HELP).sort().forEach(function (k) {
      ul.appendChild(el("li", null, k + ": " + RES_HELP[k]));
    });
    res.appendChild(ul);
    root.appendChild(res);

    var dist = el("div", "card pad");
    dist.style.marginTop = "12px";
    dist.appendChild(el("h3", null, "Component kinds"));
    bar(dist, S.node_kinds || {});
    root.appendChild(dist);

    var errs = el("div", "card pad");
    errs.style.marginTop = "12px";
    errs.appendChild(el("h3", null, "Files skipped (parse errors)"));
    var pe = S.parse_errors || [];
    if (!pe.length) {
      errs.appendChild(el("div", "mini muted", "None - every Python file parsed successfully."));
    } else {
      var ulErr = el("ul", "mini");
      pe.forEach(function (p) {
        var li = el("li", null);
        li.appendChild(locBtn(p, 0, 0));
        ulErr.appendChild(li);
      });
      errs.appendChild(ulErr);
    }
    root.appendChild(errs);

    var meth = el("div", "card pad");
    meth.style.marginTop = "12px";
    meth.appendChild(el("h3", null, "Methodology"));
    meth.appendChild(el("p", "mini", NOT.methodology || ""));
    meth.appendChild(el("p", "mini", NOT.limitations || ""));
    root.appendChild(meth);
  };

  VIEWS.narrative = function (root) {
    root.appendChild(el("h2", "vt", "Generated narrative"));
    if (!DATA.narrative) {
      root.appendChild(el("div", "note",
        "No narrative was generated. Run secdiagram with --ollama or --llm to add an evidence-grounded AI narrative."));
      return;
    }
    var pre = el("pre", "src");
    pre.textContent = DATA.narrative;
    pre.style.background = "var(--bg2)";
    pre.style.color = "var(--fg)";
    root.appendChild(pre);
  };

  var nav = document.getElementById("gd-nav");
  TABS.forEach(function (name) {
    var b = el("button", null, TAB_LABEL[name]);
    b.setAttribute("data-tab", name);
    b.addEventListener("click", function () {
      if (location.hash === "#" + name) route(); else location.hash = name;
    });
    nav.appendChild(b);
  });

  function setTab(name) {
    TABS.forEach(function (t) {
      var section = document.getElementById("view-" + t);
      if (t === name) {
        section.classList.add("active");
        section.textContent = "";
        (VIEWS[name] || function () {})(section);
      } else {
        section.classList.remove("active");
      }
    });
    Array.prototype.forEach.call(nav.children, function (b) {
      b.className = b.getAttribute("data-tab") === name ? "active" : "";
    });
  }
  function route() {
    var h = (location.hash || "").replace(/^#/, "");
    if (!h) { setTab("overview"); return; }
    var slash = h.indexOf("/");
    var kind = slash < 0 ? h : h.slice(0, slash);
    var id = slash < 0 ? "" : h.slice(slash + 1);
    if (kind === "node" && nodesById[id]) {
      setTab("components");
      setTimeout(function () { flashRow("row-node-" + id); }, 40);
      return;
    }
    if (kind === "finding" && findingsById[id]) {
      setTab("findings");
      setTimeout(function () {
        var row = document.getElementById("row-finding-" + id);
        if (row) {
          var det = row.nextElementSibling;
          if (det && det.style.display === "none") row.click();
          flashRow("row-finding-" + id);
        }
      }, 40);
      return;
    }
    if (TABS.indexOf(kind) >= 0) { setTab(kind); return; }
    setTab("overview");
  }
  function flashRow(rowId) {
    var row = document.getElementById(rowId);
    if (!row) return;
    row.scrollIntoView({ block: "center" });
    row.classList.add("flash");
    setTimeout(function () { row.classList.remove("flash"); }, 2100);
  }
  window.addEventListener("hashchange", route);

  document.getElementById("btn-theme").addEventListener("click", function () {
    var rootEl = document.documentElement;
    var dark = rootEl.getAttribute("data-theme") === "dark";
    var next = dark ? "light" : "dark";
    rootEl.setAttribute("data-theme", next);
    try { localStorage.setItem("gd-theme", next); } catch (err) { /* storage unavailable */ }
  });
  try {
    var saved = localStorage.getItem("gd-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  } catch (err) { /* storage unavailable */ }

  document.getElementById("btn-export-json").addEventListener("click", function () {
    download((M.name || "repository") + ".secdiagram.json", JSON.stringify(DATA, null, 2), "application/json");
  });

  route();
})();
</script>
</body>
</html>
"""
