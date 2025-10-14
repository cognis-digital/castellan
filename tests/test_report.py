"""Report renderer tests for every output format."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from castellan import parse_spec, build_threat_model  # noqa: E402
from castellan import report  # noqa: E402

SPEC = """
name: Report System
elements:
  - name: user
    type: external_entity
  - name: api
    type: process
  - name: db
    type: datastore
    data_classification: pii
flows:
  - name: req
    from: user
    to: api
    crosses_boundary: true
"""


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = parse_spec(SPEC)
        cls.model = build_threat_model(cls.spec)

    def test_table(self):
        out = report.render(self.model, "table")
        self.assertIn("Report System", out)
        self.assertIn("Risk score", out)

    def test_json(self):
        d = json.loads(report.render(self.model, "json"))
        self.assertEqual(d["system"], "Report System")
        self.assertIn("summary", d)

    def test_sarif(self):
        d = json.loads(report.render(self.model, "sarif"))
        self.assertEqual(d["version"], "2.1.0")
        self.assertTrue(d["runs"][0]["tool"]["driver"]["rules"])

    def test_markdown(self):
        md = report.render(self.model, "markdown")
        self.assertIn("# Threat Model", md)
        self.assertIn("| ID |", md)

    def test_html(self):
        html = report.render(self.model, "html", spec=self.spec)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Report System", html)
        self.assertIn("mermaid", html)

    def test_mermaid_dfd(self):
        m = report.render_mermaid_dfd(self.spec)
        self.assertIn("flowchart LR", m)

    def test_mermaid_attack_tree(self):
        name, tree = next(iter(self.model.attack_trees.items()))
        m = report.render_mermaid_attack_tree(name, tree)
        self.assertIn("flowchart TD", m)

    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            report.render(self.model, "nope")


if __name__ == "__main__":
    unittest.main()
