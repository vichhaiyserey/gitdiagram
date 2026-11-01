from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gitdiagram_core.ast_index import index_repo
from gitdiagram_core.discover import discover
from gitdiagram_core.frameworks import annotate
from gitdiagram_core.resolver import Resolver

try:
    from .support import FIXTURE
except (ImportError, ValueError):
    try:
        from tests.support import FIXTURE
    except (ImportError, ValueError):
        from support import FIXTURE


class AstAndResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = discover(FIXTURE)
        cls.indexes = index_repo(cls.repo.root, cls.repo.python_files)
        annotate(cls.indexes)
        cls.resolver = Resolver(cls.indexes)

    def test_definitions_and_routes(self) -> None:
        main = self.indexes["app/main.py"]
        defs = {definition.name: definition for definition in main.defs}
        self.assertEqual(defs["get_user"].kind, "endpoint")
        self.assertIn(
            {"method": "GET", "path": "/users/{user_id}"},
            defs["get_user"].routes,
        )
        self.assertTrue(defs["get_user"].doc is None or isinstance(defs["get_user"].doc, str))

    def test_task_and_cli_detection(self) -> None:
        tasks = {definition.name: definition for definition in self.indexes["app/tasks.py"].defs}
        cli = {definition.name: definition for definition in self.indexes["app/cli.py"].defs}
        self.assertEqual(tasks["refresh_cache"].kind, "task")
        self.assertEqual(cli["main"].kind, "cli")

    def test_broken_file_is_reported(self) -> None:
        broken = self.indexes["app/broken.py"]
        self.assertIsNotNone(broken.error)
        self.assertIn("SyntaxError", broken.error)
        self.assertEqual(broken.defs, [])

    def test_imports_and_assignments(self) -> None:
        service = self.indexes["app/service.py"]
        targets = self.resolver.import_targets(service)
        modules = {target.target for target in targets}
        self.assertIn("sqlalchemy", modules)
        assigns = {assign.target: assign for assign in service.assigns}
        self.assertIn("query", assigns)
        self.assertIn("user_id", assigns["query"].value_names)
        self.assertIn("SELECT", assigns["query"].value_text)

    def test_local_call_resolution(self) -> None:
        main = self.indexes["app/main.py"]
        call = next(call for call in main.calls if call.callee == "run_shell")
        resolutions = self.resolver.resolve_callee(main, call)
        self.assertTrue(resolutions)
        self.assertEqual(resolutions[0].kind, "symbol")
        self.assertEqual(resolutions[0].target, "app.service.run_shell")
        self.assertEqual(resolutions[0].confidence, 1.0)

    def test_inheritance_and_super(self) -> None:
        models = self.indexes["app/models.py"]
        base = self.resolver.resolve_dotted(models, "Base", "app.models.User")
        self.assertEqual([(item.kind, item.target) for item in base], [("symbol", "app.models.Base")])
        call = next(call for call in models.calls if call.callee == "super().save")
        resolutions = self.resolver.resolve_callee(models, call)
        self.assertEqual([item.target for item in resolutions], ["app.models.Base.save"])

    def test_parameter_type_inference(self) -> None:
        service = self.indexes["app/service.py"]
        call = next(call for call in service.calls if call.callee == "session.execute")
        resolutions = self.resolver.resolve_callee(service, call)
        self.assertEqual(resolutions[0].kind, "external")
        self.assertEqual(resolutions[0].attrs["symbol"], "sqlalchemy.orm.Session.execute")

    def test_self_attribute_and_return_type_inference(self) -> None:
        models = self.indexes["app/models.py"]
        self_call = next(call for call in models.calls if call.callee == "self.repo.store")
        self_resolutions = self.resolver.resolve_callee(models, self_call)
        self.assertEqual([item.target for item in self_resolutions], ["app.models.Repo.store"])
        self.assertEqual(self_resolutions[0].method, "inferred")

        return_call = next(call for call in models.calls if call.callee == "store.persist")
        return_resolutions = self.resolver.resolve_callee(models, return_call)
        self.assertEqual([item.target for item in return_resolutions], ["app.models.Store.persist"])
        self.assertEqual(return_resolutions[0].method, "inferred")

    def test_external_resolution_without_graph_nodes(self) -> None:
        service = self.indexes["app/service.py"]
        call = next(call for call in service.calls if call.callee == "hashlib.md5")
        resolutions = self.resolver.resolve_callee(service, call)
        self.assertEqual(resolutions[0].kind, "external")
        self.assertEqual(resolutions[0].target, "hashlib")
        self.assertEqual(resolutions[0].attrs["symbol"], "hashlib.md5")

    def test_augmented_assignment_indexing(self) -> None:
        import tempfile
        from gitdiagram_core.ast_index import index_file
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            file_path = tmp_root / "example.py"
            file_path.write_text("x = 'a'\nx += 'b'\n", encoding="utf-8")
            index = index_file(tmp_root, "example.py")
            assign_targets = [a.target for a in index.assigns]
            self.assertEqual(assign_targets, ["x", "x"])
            self.assertEqual(index.assigns[1].value_text, "'b'")

    def test_star_import_resolution(self) -> None:
        import tempfile
        from gitdiagram_core.ast_index import index_repo
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "helpers.py").write_text("def helper_fn():\n    return 42\n", encoding="utf-8")
            (tmp_root / "consumer.py").write_text("from helpers import *\n\ndef run():\n    helper_fn()\n", encoding="utf-8")
            indexes = index_repo(tmp_root, ["helpers.py", "consumer.py"])
            res = Resolver(indexes)
            consumer_index = indexes["consumer.py"]
            call = consumer_index.calls[0]
            resolutions = res.resolve_callee(consumer_index, call)
            self.assertTrue(resolutions)
            self.assertEqual(resolutions[0].kind, "symbol")
            self.assertEqual(resolutions[0].target, "helpers.helper_fn")

    def test_package_reexport_resolution(self) -> None:
        import tempfile
        from gitdiagram_core.ast_index import index_repo
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            pkg_dir = tmp_root / "mypkg"
            pkg_dir.mkdir()
            (pkg_dir / "__init__.py").write_text("from .service import Worker\n", encoding="utf-8")
            (pkg_dir / "service.py").write_text("class Worker:\n    def work(self):\n        pass\n", encoding="utf-8")
            (tmp_root / "main.py").write_text("import mypkg\n\ndef start():\n    mypkg.Worker()\n", encoding="utf-8")
            indexes = index_repo(tmp_root, ["mypkg/__init__.py", "mypkg/service.py", "main.py"])
            res = Resolver(indexes)
            main_index = indexes["main.py"]
            call = main_index.calls[0]
            resolutions = res.resolve_callee(main_index, call)
            self.assertTrue(resolutions)
            self.assertEqual(resolutions[0].kind, "symbol")
            self.assertEqual(resolutions[0].target, "mypkg.service.Worker")


if __name__ == "__main__":
    unittest.main()
