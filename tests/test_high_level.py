from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.cli import main
from secdiagram_core.high_level import (
    build_high_level_architecture,
    render_mermaid_highlevel,
)
from secdiagram_core.model import Graph

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SAMPLE_APP_DIR = FIXTURES_DIR / "sample_app"
SAMPLE_DOTNET_DIR = FIXTURES_DIR / "sample_dotnet_app"
SAMPLE_NODEJS_DIR = FIXTURES_DIR / "sample_nodejs_app"


class HighLevelArchitectureTests(unittest.TestCase):
    def test_sample_app_python_high_level(self) -> None:
        result = run_analysis(AnalysisConfig(root=SAMPLE_APP_DIR))
        hla = build_high_level_architecture(SAMPLE_APP_DIR, result.graph)

        self.assertIn("Python", hla.languages)
        self.assertIn("Docker", hla.frameworks)

        subsystem_ids = {s.id for s in hla.subsystems}
        self.assertIn("client_ingress", subsystem_ids)
        self.assertIn("platform_docker", subsystem_ids)
        self.assertIn("py_app", subsystem_ids)
        self.assertIn("queue_celery", subsystem_ids)

        app_sub = next(s for s in hla.subsystems if s.id == "py_app")
        self.assertGreater(app_sub.findings_count, 0)
        self.assertEqual(app_sub.max_severity, "critical")

        # Verify connections
        conn_pairs = [(c.src, c.dst) for c in hla.connections]
        self.assertIn(("client_ingress", "py_app"), conn_pairs)
        self.assertIn(("py_app", "queue_celery"), conn_pairs)
        self.assertIn(("platform_docker", "py_app"), conn_pairs)

        mermaid = render_mermaid_highlevel(hla)
        self.assertIn("flowchart TB", mermaid)
        self.assertIn("Tier_Ingress", mermaid)
        self.assertIn("Tier_Gateway", mermaid)
        self.assertIn("Tier_Data", mermaid)
        self.assertIn("Tier_Platform", mermaid)
        self.assertIn("client_ingress ==|HTTPS / REST|==> py_app", mermaid)

    def test_sample_dotnet_app_high_level(self) -> None:
        hla = build_high_level_architecture(SAMPLE_DOTNET_DIR)

        self.assertIn("C# / .NET", hla.languages)
        self.assertTrue(bool({".NET", "ASP.NET Core Web API"} & set(hla.frameworks)))

        subsystem_names = {s.name for s in hla.subsystems}
        self.assertIn("Clients / Frontends", subsystem_names)
        self.assertIn("Shop.Api", subsystem_names)
        self.assertIn("Shop.Application", subsystem_names)
        self.assertIn("Shop.Domain", subsystem_names)
        self.assertIn("Shop.Infrastructure", subsystem_names)
        self.assertIn("PostgreSQL (postgres)", subsystem_names)
        self.assertIn("Redis (redis)", subsystem_names)
        self.assertIn("Stripe Payments", subsystem_names)

        # Inspect details
        api_sub = next(s for s in hla.subsystems if s.name == "Shop.Api")
        self.assertEqual(api_sub.tier, "gateway")
        self.assertEqual(api_sub.kind, "api")
        self.assertTrue(any("Endpoints" in d for d in api_sub.details))

        app_sub = next(s for s in hla.subsystems if s.name == "Shop.Application")
        self.assertTrue(any("CQRS Handlers" in d for d in app_sub.details))

        infra_sub = next(s for s in hla.subsystems if s.name == "Shop.Infrastructure")
        self.assertTrue(any("DbContexts" in d for d in infra_sub.details))

        # Inspect ProjectReference connections
        conn_pairs = [(c.src, c.dst, c.label) for c in hla.connections]
        self.assertTrue(any(c[0] == "dotnet_Shop_Api" and c[1] == "dotnet_Shop_Application" for c in conn_pairs))
        self.assertTrue(any(c[0] == "dotnet_Shop_Api" and c[1] == "dotnet_Shop_Infrastructure" for c in conn_pairs))
        self.assertTrue(any(c[0] == "dotnet_Shop_Application" and c[1] == "dotnet_Shop_Domain" for c in conn_pairs))
        self.assertTrue(any(c[0] == "dotnet_Shop_Infrastructure" and c[1] == "dotnet_Shop_Domain" for c in conn_pairs))

        # Inspect database and cache connections
        self.assertTrue(any(c[0] == "dotnet_Shop_Infrastructure" and c[1] == "db_postgres" for c in conn_pairs))
        self.assertTrue(any(c[0] == "dotnet_Shop_Infrastructure" and c[1] == "cache_redis" for c in conn_pairs))
        self.assertTrue(any(c[0] == "dotnet_Shop_Infrastructure" and c[1] == "ext_stripe_payments" for c in conn_pairs))

        mermaid = render_mermaid_highlevel(hla)
        self.assertIn("Shop.Api", mermaid)
        self.assertIn("Shop.Application", mermaid)
        self.assertIn("Shop.Infrastructure", mermaid)
        self.assertIn("Shop.Domain", mermaid)

    def test_dotnet_project_references_are_platform_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Web").mkdir()
            (root / "Core").mkdir()
            (root / "Web" / "Web.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup>'
                '<ProjectReference Include="..\\Core\\Core.csproj" />'
                "</ItemGroup></Project>",
                encoding="utf-8",
            )
            (root / "Core" / "Core.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"></Project>',
                encoding="utf-8",
            )
            hla = build_high_level_architecture(root, Graph())
            pairs = {(conn.src, conn.dst) for conn in hla.connections}
            self.assertIn(("dotnet_Web", "dotnet_Core"), pairs)

    def test_sample_nodejs_app_high_level(self) -> None:
        hla = build_high_level_architecture(SAMPLE_NODEJS_DIR)

        self.assertIn("JavaScript / TypeScript", hla.languages)
        self.assertTrue(any("Express" in f or "Prisma" in f for f in hla.frameworks))

        subsystem_names = {s.name for s in hla.subsystems}
        self.assertIn("sample-node-service", subsystem_names)
        self.assertIn("PostgreSQL Database", subsystem_names)
        self.assertIn("Redis Cache & Queue", subsystem_names)
        self.assertIn("Stripe Payments", subsystem_names)
        self.assertIn("AI LLM Provider", subsystem_names)

        node_sub = next(s for s in hla.subsystems if s.name == "sample-node-service")
        self.assertEqual(node_sub.tier, "gateway")
        self.assertTrue(any("2 Routes" in d for d in node_sub.details))
        self.assertTrue(any("2 Models" in d for d in node_sub.details))

        conn_pairs = [(c.src, c.dst) for c in hla.connections]
        self.assertIn(("client_ingress", "node_sample_node_service"), conn_pairs)
        self.assertIn(("node_sample_node_service", "db_postgres"), conn_pairs)
        self.assertIn(("node_sample_node_service", "cache_redis"), conn_pairs)
        self.assertIn(("node_sample_node_service", "ext_stripe_payments"), conn_pairs)
        self.assertIn(("node_sample_node_service", "ext_ai_provider"), conn_pairs)

        mermaid = render_mermaid_highlevel(hla)
        self.assertIn("sample-node-service", mermaid)
        self.assertIn("PostgreSQL Database", mermaid)
        self.assertIn("Prisma ORM", mermaid)

    def test_cli_outputs_both_diagrams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["--dir", str(SAMPLE_APP_DIR), "--out", str(out), "--quiet"])
            self.assertEqual(code, 0)

            # Both diagram.mmd and diagram-highlevel.mmd must be generated
            self.assertTrue((out / "diagram.mmd").exists())
            self.assertTrue((out / "diagram-highlevel.mmd").exists())
            self.assertTrue((out / "ARCHITECTURE.md").exists())

            arch_md = (out / "ARCHITECTURE.md").read_text(encoding="utf-8")
            self.assertIn("## System architecture overview (high-level)", arch_md)
            self.assertIn("```mermaid", arch_md)
            self.assertIn("Tier_Ingress", arch_md)

    def test_cli_high_level_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["--dir", str(SAMPLE_APP_DIR), "--out", str(out), "--high-level", "--quiet"])
            self.assertEqual(code, 0)

            diagram_mmd = (out / "diagram.mmd").read_text(encoding="utf-8")
            # When --high-level is active, diagram.mmd itself is the high-level diagram
            self.assertIn("High-Level System Architecture Diagram", diagram_mmd)
            self.assertIn("Tier_Ingress", diagram_mmd)

    def test_cli_high_level_image_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["--dir", str(SAMPLE_APP_DIR), "--out", str(out), "--image", "png", "--quiet"])
            self.assertEqual(code, 0)

            self.assertTrue((out / "diagram.png").exists())
            self.assertTrue((out / "diagram-highlevel.png").exists())
            self.assertGreater((out / "diagram-highlevel.png").stat().st_size, 0)
