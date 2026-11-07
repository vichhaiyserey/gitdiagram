from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secdiagram_core.analyzer import AnalysisConfig, run_analysis
from secdiagram_core.discover import discover
from secdiagram_core.java_index import analyze_java_security, build_java_graph, index_java
from secdiagram_core.model import Graph


def _analyze(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return run_analysis(AnalysisConfig(root=root))


def _java_findings(source: str):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "Demo.java").write_text(source, encoding="utf-8")
        repo = discover(root)
        index = index_java(repo.root, repo.rel_files)
        graph = Graph()
        build_java_graph(graph, index)
        return analyze_java_security(graph, index, repo.root, repo.name)


class PythonRelevanceTests(unittest.TestCase):
    def test_parameterized_sql_is_not_reported(self) -> None:
        result = _analyze(
            {
                "app.py": (
                    "from flask import Flask, request\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/users')\n"
                    "def users():\n"
                    "    uid = request.args.get('id')\n"
                    "    return app.db.session.execute("
                    "'SELECT * FROM users WHERE id = ?', (uid,))\n"
                )
            }
        )
        self.assertEqual([f for f in result.graph.findings if f.category == "sql"], [])

    def test_fstring_sql_is_reported(self) -> None:
        result = _analyze(
            {
                "app.py": (
                    "from flask import Flask, request\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/users')\n"
                    "def users():\n"
                    "    name = request.args.get('name')\n"
                    "    return app.db.session.execute("
                    "f\"SELECT * FROM users WHERE name = '{name}'\")\n"
                )
            }
        )
        sql = [f for f in result.graph.findings if f.category == "sql"]
        self.assertTrue(sql)
        self.assertTrue(all(item.severity == "critical" for item in sql))

    def test_argv_subprocess_is_not_reported(self) -> None:
        result = _analyze(
            {
                "app.py": (
                    "import subprocess\n"
                    "from flask import Flask, request\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/echo')\n"
                    "def echo():\n"
                    "    name = request.args.get('name')\n"
                    "    return subprocess.run(['echo', name], check=True)\n"
                )
            }
        )
        self.assertEqual([f for f in result.graph.findings if f.category == "command"], [])

    def test_sanitized_command_is_not_reported(self) -> None:
        result = _analyze(
            {
                "app.py": (
                    "import os\n"
                    "import shlex\n"
                    "from flask import Flask, request\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/echo')\n"
                    "def echo():\n"
                    "    name = request.args.get('name')\n"
                    "    return os.system('echo ' + shlex.quote(name))\n"
                )
            }
        )
        self.assertEqual([f for f in result.graph.findings if f.category == "command"], [])

    def test_modern_tokens_and_quoted_secrets(self) -> None:
        result = _analyze(
            {
                "config.py": (
                    "payload = 'sk-proj-mocktoken1234567890abcdefghij'\n"
                    "settings = {'client_secret': 'mock_secret_value_12345'}\n"
                )
            }
        )
        secrets = [f for f in result.graph.findings if f.category == "secret"]
        titles = " | ".join(finding.title for finding in secrets)
        self.assertIn("Possible hardcoded token", titles)
        self.assertIn("client_secret", titles.lower())

    def test_python_misconfig_text_scan(self) -> None:
        result = _analyze(
            {
                "settings.py": (
                    "DEBUG = True\n"
                    "ALLOWED_HOSTS = ['*']\n"
                    "check_hostname = False\n"
                )
            }
        )
        titles = {f.title for f in result.graph.findings if f.category == "misconfig"}
        self.assertIn("Debug mode enabled", titles)
        self.assertIn("Wildcard host header allowlist", titles)
        self.assertIn("TLS hostname verification disabled", titles)

    def test_xss_redirect_xxe_and_jwt(self) -> None:
        result = _analyze(
            {
                "app.py": (
                    "import jwt\n"
                    "from flask import Flask, request, redirect\n"
                    "from markupsafe import Markup\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/go')\n"
                    "def go():\n"
                    "    value = request.args.get('value')\n"
                    "    target = request.args.get('next')\n"
                    "    html = Markup(value)\n"
                    "    token = jwt.decode('x', options={'verify_signature': False})\n"
                    "    return redirect(target)\n"
                ),
                "xml.py": (
                    "from lxml import etree\n"
                    "from flask import Flask, request\n"
                    "app = Flask(__name__)\n"
                    "@app.route('/xml')\n"
                    "def parse():\n"
                    "    return etree.parse(request.files['xml'])\n"
                ),
            }
        )
        categories = {finding.category for finding in result.graph.findings}
        self.assertIn("xss", categories)
        self.assertIn("redirect", categories)
        self.assertIn("xxe", categories)
        self.assertIn("auth", categories)


class JavaRelevanceTests(unittest.TestCase):
    def test_local_taint_reaches_open_redirect(self) -> None:
        findings = _java_findings(
            "package demo;\n"
            "import javax.servlet.http.*;\n"
            "public class Demo {\n"
            "  public void go(HttpServletRequest request, HttpServletResponse response)"
            " throws Exception {\n"
            "    String next = request.getParameter(\"next\");\n"
            "    response.sendRedirect(next);\n"
            "  }\n"
            "}\n"
        )
        redirect = [f for f in findings if f.category == "redirect"]
        self.assertTrue(redirect)
        self.assertEqual(redirect[0].severity, "medium")
        self.assertGreaterEqual(len(redirect[0].trace), 2)

    def test_local_taint_reaches_xxe_sink(self) -> None:
        findings = _java_findings(
            "package demo;\n"
            "import javax.servlet.http.*;\n"
            "public class Demo {\n"
            "  public void parse(HttpServletRequest request) throws Exception {\n"
            "    String xml = request.getParameter(\"xml\");\n"
            "    javax.xml.parsers.DocumentBuilderFactory.newInstance()"
            ".newDocumentBuilder().parse(xml);\n"
            "  }\n"
            "}\n"
        )
        xxe = [f for f in findings if f.category == "xxe"]
        self.assertTrue(xxe)
        self.assertEqual(xxe[0].severity, "high")
        self.assertEqual(xxe[0].cwe, "CWE-611")

    def test_sanitized_java_sql_is_not_reported(self) -> None:
        findings = _java_findings(
            "package demo;\n"
            "import javax.servlet.http.*;\n"
            "public class Demo {\n"
            "  public Object find(HttpServletRequest request, Object entityManager)"
            " throws Exception {\n"
            "    String id = request.getParameter(\"id\");\n"
            "    return entityManager.createQuery(\"SELECT u FROM User u WHERE u.id=\""
            " + Integer.parseInt(id)).getResultList();\n"
            "  }\n"
            "}\n"
        )
        self.assertEqual([f for f in findings if f.category == "sql"], [])


if __name__ == "__main__":
    unittest.main()
