"""Deterministic JSON serialisation of the graph."""

from __future__ import annotations

import json

from .model import Graph


def render_json(graph: Graph) -> str:
    return json.dumps(graph.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
