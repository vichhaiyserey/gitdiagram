"""Deterministic JSON serialisation of the graph."""

from __future__ import annotations

import json
from pathlib import Path

from .model import Graph


def render_json(graph: Graph) -> str:
    return json.dumps(graph.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(graph: Graph, path: Path) -> None:
    """Stream the graph JSON to disk without materialising the full string."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(graph.to_dict(), handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
