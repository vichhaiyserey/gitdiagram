from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.discover import discover
from secdiagram_core.high_level import build_high_level_architecture
from secdiagram_core.java_index import (
    analyze_java_security,
    build_java_graph,
    index_java,
    parse_gradle,
    parse_pom,
)
from secdiagram_core.model import Graph

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_java"


class JavaIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = discover(FIXTURE)
        cls.index = index_java(cls.repo.root, cls.repo.rel_files)
        cls.graph = Graph()
        build_java_graph(cls.graph, cls.index)

    def test_files_and_manifest_detection(self) -> None:
        self.assertEqual(len(self.index.files), 4)
        self.assertEqual(self.index.property_files, ["src/main/resources/application.properties"])
        self.assertEqual(len(self.index.projects), 1)
        project = self.index.projects[0]
        self.assertEqual(project.name, "sample-java-shop")
        self.assertEqual(project.build_tool, "maven")
        self.assertIn("org.springframework.boot:spring-boot-starter-web", project.dependencies)

    def test_class_stereotypes_and_injection(self) -> None:
        controllers = [cls.qualname for cls in self.index.controllers()]
        services = [cls.qualname for cls in self.index.services()]
        self.assertEqual(controllers, ["com.example.shop.controller.UserController"])
        self.assertEqual(services, ["com.example.shop.service.UserService"])

        controller_file = self.index.files["src/main/java/com/example/shop/controller/UserController.java"]
        controller = controller_file.classes[0]
        self.assertEqual(controller.stereotype(), "controller")
        self.assertEqual(controller.request_mapping, "/users")
        injected = {field.name: field.type_name for field in controller.fields if field.is_injected()}
        self.assertEqual(injected, {"userService": "UserService"})

    def test_spring_routes_are_extracted(self) -> None:
        controller_file = self.index.files["src/main/java/com/example/shop/controller/UserController.java"]
        routes = {method.name: method.routes for method in controller_file.classes[0].methods}
        self.assertEqual(routes["getUser"], [{"method": "GET", "path": "/users/{id}"}])
        self.assertEqual(routes["search"], [{"method": "GET", "path": "/users/search"}])
        self.assertEqual(routes["run"], [{"method": "POST", "path": "/users/run"}])

    def test_graph_nodes_and_edges(self) -> None:
        kinds = {node.qualname: node.kind for node in self.graph.sorted_nodes()}
        self.assertEqual(kinds["com.example.shop.controller.UserController"], "class")
        self.assertEqual(kinds["com.example.shop.controller.UserController.getUser"], "endpoint")
        self.assertEqual(kinds["com.example.shop.service.UserService.findUser"], "method")

        endpoint = next(node for node in self.graph.sorted_nodes() if node.qualname.endswith(".getUser"))
        self.assertEqual(endpoint.attrs["routes"], [{"method": "GET", "path": "/users/{id}"}])
        call_edges = [
            (self.graph.nodes[edge.src].name, self.graph.nodes[edge.dst].name)
            for edge in self.graph.edges
            if edge.kind == "calls"
        ]
        self.assertIn(("UserService", "UserRepository"), call_edges)
        external = [node for node in self.graph.sorted_nodes() if node.kind == "external"]
        self.assertEqual([node.name for node in external], ["sample-java-shop"])

    def test_security_findings(self) -> None:
        findings = analyze_java_security(self.graph, self.index, self.repo.root, self.repo.name)
        by_category = {finding.category: finding for finding in findings}
        self.assertEqual(by_category["sql"].severity, "critical")
        self.assertEqual(by_category["sql"].cwe, "CWE-89")
        self.assertEqual(by_category["command"].severity, "critical")
        self.assertGreaterEqual(len(by_category["sql"].trace), 2)
        self.assertEqual(by_category["sql"].trace[-1].line, by_category["sql"].evidence[0].line)
        self.assertEqual(by_category["secret"].severity, "high")
        self.assertTrue(by_category["secret"].evidence[0].path.endswith("application.properties"))

    def test_gradle_manifest_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gradle = root / "build.gradle"
            gradle.write_text(
                'rootProject.name = "gradle-shop"\n'
                "dependencies {\n"
                '  implementation "org.springframework.boot:spring-boot-starter-web"\n'
                '  implementation "org.postgresql:postgresql:42.7.3"\n'
                "}\n",
                encoding="utf-8",
            )
            project = parse_gradle(root, "build.gradle")
            self.assertIsNotNone(project)
            assert project is not None
            self.assertEqual(project.name, "gradle-shop")
            self.assertEqual(project.build_tool, "gradle")
            self.assertIn("org.postgresql:postgresql", project.dependencies)


class JavaAnalyzerTests(unittest.TestCase):
    def test_run_analysis_integrates_java(self) -> None:
        result = run_analysis(AnalysisConfig(root=FIXTURE))
        self.assertEqual(result.java_files, 4)
        self.assertEqual(result.graph.meta["java_files"], 4)
        self.assertTrue(any(node.attrs.get("java") for node in result.graph.nodes.values()))
        self.assertTrue(any(finding.category in {"sql", "command"} for finding in result.graph.findings))

    def test_high_level_detects_java_and_avoids_python_misattribution(self) -> None:
        result = run_analysis(AnalysisConfig(root=FIXTURE))
        hla = build_high_level_architecture(FIXTURE, result.graph)
        self.assertIn("Java", hla.languages)
        self.assertIn("Spring Boot API", hla.frameworks)
        java_sub = next(s for s in hla.subsystems if s.id == "java_sample_java_shop")
        self.assertEqual(java_sub.tier, "gateway")
        self.assertTrue(any("Endpoints" in detail for detail in java_sub.details))
        self.assertNotIn("Src", {s.name for s in hla.subsystems})
        self.assertNotIn("Python", hla.languages)
        conn_pairs = {(c.src, c.dst) for c in hla.connections}
        self.assertIn(("java_sample_java_shop", "db_postgres"), conn_pairs)
        self.assertIn(("java_sample_java_shop", "cache_redis"), conn_pairs)

    def test_cli_writes_java_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            code = main(
                [
                    "--dir",
                    str(FIXTURE),
                    "--out",
                    str(out),
                    "--format",
                    "json,sarif",
                    "--quiet",
                ]
            )
            self.assertEqual(code, 0)
            graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            self.assertEqual(graph["meta"]["java_files"], 4)
            self.assertTrue(any(node["attrs"].get("java") for node in graph["nodes"]))
            sarif = json.loads((out / "security.sarif").read_text(encoding="utf-8"))
            rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
            self.assertTrue(any(rule.startswith("sql:") for rule in rule_ids))

    def test_parse_pom_xml_bomb_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. XML entity bomb attempt should be safely rejected
            bomb_pom = root / "bomb_pom.xml"
            bomb_pom.write_text(
                '<?xml version="1.0"?>\n'
                '<!DOCTYPE lolz [\n'
                ' <!ENTITY lol "lol">\n'
                ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
                ']>\n'
                '<project><artifactId>&lol1;</artifactId></project>',
                encoding="utf-8",
            )
            res = parse_pom(root, "bomb_pom.xml")
            self.assertIsNone(res)

            # 2. Path traversal escaping root should be rejected
            res_traversal = parse_pom(root, "../outside_pom.xml")
            self.assertIsNone(res_traversal)

    def test_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "a", root / "b"
            args = ["--dir", str(FIXTURE), "--format", "json,md,sarif", "--quiet"]
            self.assertEqual(main(args + ["--out", str(first)]), 0)
            self.assertEqual(main(args + ["--out", str(second)]), 0)
            for name in ("graph.json", "ARCHITECTURE.md", "security.sarif"):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
