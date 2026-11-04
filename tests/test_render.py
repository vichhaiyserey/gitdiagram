from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.render_json import render_json
from secdiagram_core.render_markdown import render_markdown
from secdiagram_core.render_mermaid import render_mermaid
from secdiagram_core.render_sarif import render_sarif

try:
    from .support import fixture_result
except (ImportError, ValueError):
    try:
        from tests.support import fixture_result
    except (ImportError, ValueError):
        from support import fixture_result


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = fixture_result()
        cls.graph = cls.result.graph
        cls.meta = {
            "name": cls.result.repo.name,
            "commit": cls.result.repo.commit,
            "branch": cls.result.repo.branch,
            "dirty": cls.result.repo.dirty,
            "analysis": cls.graph.meta.get("analysis", {}),
        }

    def test_json_is_valid_and_stable(self) -> None:
        first = render_json(self.graph)
        second = render_json(self.graph)
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["meta"]["name"], "sample_app")
        self.assertEqual(len(payload["nodes"]), len(self.graph.nodes))
        ids = [node["id"] for node in payload["nodes"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_mermaid_contains_features_and_routes(self) -> None:
        text = render_mermaid(self.graph)
        self.assertIn("flowchart LR", text)
        self.assertIn("subgraph F_app", text)
        self.assertIn("GET /users/(user_id)", text)
        self.assertIn("n_", text)
        self.assertNotIn("None", text)
        self.assertEqual(text, render_mermaid(self.graph))

    def test_mermaid_click_links(self) -> None:
        text = render_mermaid(self.graph, "https://github.com/example/repo/blob/main")
        self.assertIn("click n_", text)
        self.assertIn("https://github.com/example/repo/blob/main/app/main.py", text)

    def test_mermaid_human_friendly_features(self) -> None:
        text = render_mermaid(self.graph, detail="architecture")
        self.assertIn("API & Entrypoints", text)
        self.assertIn("Models & Data", text)
        self.assertIn("📦 External Dependencies", text)
        self.assertIn("themeVariables", text)

    def test_mermaid_direction_and_themes(self) -> None:
        tb_text = render_mermaid(self.graph, direction="TB")
        self.assertIn("flowchart TB", tb_text)

        classic_text = render_mermaid(self.graph, theme="classic")
        self.assertNotIn("themeVariables", classic_text)

    def test_mermaid_max_diagram_nodes_capping(self) -> None:
        # Test capping nodes in architecture mode
        capped_text = render_mermaid(self.graph, detail="architecture", max_diagram_nodes=5)
        self.assertIn("flowchart LR", capped_text)
        # Should contain at most 5 node definitions plus subgraph lines
        node_lines = [line for line in capped_text.splitlines() if line.strip().startswith("n_") and "-->" not in line and "-.->" not in line and "==>" not in line]
        self.assertLessEqual(len(node_lines), 5)

    def test_markdown_is_cited_and_ascii(self) -> None:
        text = render_markdown(self.graph, self.meta)
        self.assertIn("# Architecture: sample_app", text)
        self.assertIn("app/main.py:12", text)
        self.assertIn("## Security review", text)
        self.assertIn("## Feature map", text)
        self.assertIn("critical", text)
        self.assertEqual(text, render_markdown(self.graph, self.meta))
        text.encode("ascii")

    def test_sarif(self) -> None:
        payload = json.loads(render_sarif(self.graph))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(
            run["tool"]["driver"]["informationUri"],
            "https://github.com/vichhaiyserey/secdiagram",
        )
        results = run["results"]
        self.assertEqual(len(results), len(self.graph.findings))
        self.assertTrue(all("ruleId" in result for result in results))
        self.assertTrue(all("partialFingerprints" in result for result in results))
        self.assertTrue(all(result["ruleIndex"] < len(run["tool"]["driver"]["rules"]) for result in results))
        rule = run["tool"]["driver"]["rules"][0]
        self.assertIn("precision", rule["properties"])
        self.assertIn("security-severity", rule["properties"])
        self.assertIn("help", rule)
        self.assertIn("invocations", run)
        self.assertIn("coverage", run["properties"])
        self.assertEqual(run["properties"]["coverage"]["toolVersion"], payload["runs"][0]["tool"]["driver"]["version"])

    def test_sarif_code_flows_trace_source_to_sink(self) -> None:
        payload = json.loads(render_sarif(self.graph))
        flows = [result for result in payload["runs"][0]["results"] if "codeFlows" in result]
        self.assertTrue(flows)
        steps = flows[0]["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertGreaterEqual(len(steps), 2)
        self.assertEqual(steps[0]["location"]["message"]["text"], "taint source")
        self.assertEqual(steps[-1]["location"]["message"]["text"], "sink")
        self.assertIn("relatedLocations", flows[0])


if __name__ == "__main__":
    unittest.main()
