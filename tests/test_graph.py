from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gitdiagram_core.analyzer import AnalysisConfig, run_analysis
from gitdiagram_core.model import Loc, Node, stable_id

try:
    from .support import FIXTURE, fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE, fixture_result
    except (ImportError, ValueError):
        from support import FIXTURE, fixture_result


class GraphTests(unittest.TestCase):
    def test_nodes_and_edges(self) -> None:
        graph = fixture_result().graph
        by_qualname = {node.qualname: node for node in graph.nodes.values()}
        ids = {node.id: node.qualname for node in graph.nodes.values()}

        self.assertEqual(by_qualname["app.main.get_user"].kind, "endpoint")
        self.assertEqual(by_qualname["app.service.run_shell"].kind, "function")
        self.assertEqual(by_qualname["app.models.User"].kind, "class")
        self.assertIn("fastapi", by_qualname)
        self.assertIn("Dockerfile", {node.name for node in graph.nodes.values()})
        self.assertNotIn("os", by_qualname)
        self.assertNotIn("subprocess", by_qualname)

        triples = {(ids[edge.src], ids[edge.dst], edge.kind) for edge in graph.edges}
        self.assertIn(("app.main.get_user", "app.service.run_shell", "calls"), triples)
        self.assertIn(("app.main.get_user", "app.service.load_user", "calls"), triples)
        self.assertIn(("app.models.User", "app.models.Base", "inherits"), triples)

        contains = {(ids[edge.src], ids[edge.dst]) for edge in graph.edges if edge.kind == "contains"}
        self.assertIn(("app.main", "app.main.get_user"), contains)
        self.assertIn(("app.models.User", "app.models.User.save"), contains)

    def test_call_evidence_and_confidence(self) -> None:
        graph = fixture_result().graph
        ids = {node.id: node.qualname for node in graph.nodes.values()}
        edge = next(
            edge
            for edge in graph.edges
            if ids[edge.src] == "app.main.get_user"
            and ids[edge.dst] == "app.service.run_shell"
        )
        self.assertEqual(edge.confidence, 1.0)
        self.assertEqual(edge.resolution, "import")
        self.assertEqual(edge.evidence[0].path, "app/main.py")
        self.assertEqual(edge.evidence[0].line, 13)

    def test_parse_errors_and_meta(self) -> None:
        result = fixture_result()
        self.assertIn("app/broken.py", result.parse_errors)
        self.assertEqual(result.graph.meta["name"], "sample_app")
        self.assertEqual(result.graph.meta["python_files"], 8)
        self.assertGreater(result.graph.meta["unresolved_count"], 0)
        self.assertFalse(result.graph.meta["truncated"])

    def test_features(self) -> None:
        graph = fixture_result().graph
        names = {feature.name for feature in graph.features}
        self.assertEqual(names, {"app", "external", "infrastructure"})
        app_feature = next(feature for feature in graph.features if feature.name == "app")
        self.assertIn("app/main.py", app_feature.files)
        self.assertTrue(app_feature.nodes)

    def test_security_disabled(self) -> None:
        result = run_analysis(AnalysisConfig(root=FIXTURE, security=False))
        self.assertEqual(result.graph.findings, [])
        kinds = {node.kind for node in result.graph.nodes.values()}
        self.assertNotIn("infra", kinds)
        self.assertNotIn("workflow", kinds)

    def test_min_confidence_filters_edges(self) -> None:
        strict = run_analysis(AnalysisConfig(root=FIXTURE, min_confidence=1.0))
        loose = fixture_result()
        self.assertLessEqual(len(strict.graph.edges), len(loose.graph.edges))
        for edge in strict.graph.edges:
            if edge.kind not in {"contains", "imports"}:
                self.assertEqual(edge.confidence, 1.0)

    def test_max_nodes_pruning(self) -> None:
        capped = run_analysis(AnalysisConfig(root=FIXTURE, max_nodes=5))
        self.assertTrue(capped.graph.meta["analysis"]["truncated"])
        self.assertGreater(capped.graph.meta["analysis"]["dropped_nodes"], 0)
        self.assertLessEqual(len(capped.graph.nodes), 15)  # Python nodes capped at 5 + IaC nodes
        endpoint_nodes = [node for node in capped.graph.nodes.values() if node.kind == "endpoint"]
        self.assertTrue(endpoint_nodes, "Highest priority endpoints should be retained during pruning")

    def test_edge_deduplication(self) -> None:
        from gitdiagram_core.model import Graph
        g = Graph()
        n1 = Node(id="1", kind="function", name="a", qualname="mod.a")
        n2 = Node(id="2", kind="function", name="b", qualname="mod.b")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge("1", "2", "calls", confidence=0.8, evidence=[Loc("mod.py", 10)])
        g.add_edge("1", "2", "calls", confidence=0.9, evidence=[Loc("mod.py", 20)])
        g.dedupe_edges()
        self.assertEqual(len(g.edges), 1)
        self.assertEqual(g.edges[0].confidence, 0.9)
        self.assertEqual(len(g.edges[0].evidence), 2)

    def test_stable_id_determinism(self) -> None:
        id1 = stable_id("module", "app.main")
        id2 = stable_id("module", "app.main")
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 12)
        id3 = stable_id("module", "app.service")
        self.assertNotEqual(id1, id3)


if __name__ == "__main__":
    unittest.main()
