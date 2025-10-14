"""CLI tests for castellan subcommands and exit codes."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from castellan.cli import main  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBAPP = os.path.join(HERE, "demos", "01-basic", "webapp.yml")
K8S = os.path.join(HERE, "deploy", "k8s.yaml")


def run(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    old = (sys.stdout, sys.stderr, sys.stdin)
    sys.stdout, sys.stderr = out, err
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        code = main(argv)
    finally:
        sys.stdout, sys.stderr, sys.stdin = old
    return code, out.getvalue(), err.getvalue()


class AnalyzeTests(unittest.TestCase):
    def test_demo_exists(self):
        self.assertTrue(os.path.exists(WEBAPP))

    def test_analyze_table(self):
        code, out, _ = run(["analyze", WEBAPP])
        self.assertEqual(code, 0)
        self.assertIn("Acme Web Application", out)

    def test_analyze_json(self):
        code, out, _ = run(["analyze", WEBAPP, "--format", "json"])
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["system"], "Acme Web Application")
        self.assertIn("threats", d)

    def test_analyze_sarif(self):
        code, out, _ = run(["analyze", WEBAPP, "--format", "sarif"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_analyze_markdown_and_html(self):
        for fmt, needle in (("markdown", "# Threat Model"), ("html", "<!doctype html>")):
            code, out, _ = run(["analyze", WEBAPP, "--format", fmt])
            self.assertEqual(code, 0)
            self.assertIn(needle, out)

    def test_fail_on_high_nonzero(self):
        code, _, err = run(["analyze", WEBAPP, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("unmitigated", err)


class OtherCommandTests(unittest.TestCase):
    def test_validate_ok(self):
        code, out, _ = run(["validate", WEBAPP])
        self.assertEqual(code, 0)
        self.assertIn("VALID", out)

    def test_validate_bad_stdin(self):
        code, _, _ = run(["validate", "-"], stdin="elements: []\n")
        self.assertEqual(code, 1)

    def test_scan_iac_file(self):
        code, out, _ = run(["scan", K8S, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn("threats", json.loads(out))

    def test_import_yaml(self):
        code, out, _ = run(["import", K8S])
        self.assertEqual(code, 0)
        self.assertIn("elements:", out)

    def test_compliance(self):
        code, out, _ = run(["compliance", WEBAPP])
        self.assertEqual(code, 0)
        self.assertIn("Frameworks referenced", out)

    def test_library_stats_json(self):
        code, out, _ = run(["library", "stats", "--format", "json"])
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertGreaterEqual(d["compliance_frameworks"], 615)

    def test_library_frameworks_limit(self):
        code, out, _ = run(["library", "frameworks", "--format", "json", "--limit", "5"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 5)


if __name__ == "__main__":
    unittest.main()
