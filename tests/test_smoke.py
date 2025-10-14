"""Smoke tests for THREATMODELER. Standard library only, no network."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatmodeler import (  # noqa: E402
    parse_spec,
    build_threat_model,
    SpecError,
    TOOL_NAME,
    TOOL_VERSION,
    STRIDE_CATEGORIES,
)
from threatmodeler.cli import main  # noqa: E402


SPEC = """
name: Test System
elements:
  - name: user
    type: external_entity
  - name: api
    type: process
    trusted: true
    controls:
      - mfa
  - name: db
    type: datastore
flows:
  - name: req
    from: user
    to: api
    encrypted: false
    crosses_boundary: true
  - name: store
    from: api
    to: db
    encrypted: true
"""


class ParseTests(unittest.TestCase):
    def test_parse_basic(self):
        spec = parse_spec(SPEC)
        self.assertEqual(spec.name, "Test System")
        self.assertEqual(len(spec.elements), 3)
        self.assertEqual(len(spec.flows), 2)
        api = spec.element("api")
        self.assertIsNotNone(api)
        self.assertEqual(api.type, "process")
        self.assertTrue(api.trusted)
        self.assertIn("mfa", api.metadata.get("controls", []))

    def test_missing_name_raises(self):
        with self.assertRaises(SpecError):
            parse_spec("elements:\n  - name: x\n    type: process\n")

    def test_unknown_type_raises(self):
        bad = "name: X\nelements:\n  - name: y\n    type: wormhole\n"
        with self.assertRaises(SpecError):
            parse_spec(bad)

    def test_flow_to_unknown_element_raises(self):
        bad = (
            "name: X\nelements:\n  - name: a\n    type: process\n"
            "flows:\n  - from: a\n    to: ghost\n"
        )
        with self.assertRaises(SpecError):
            parse_spec(bad)


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.model = build_threat_model(parse_spec(SPEC))

    def test_external_entity_only_spoof_repudiation(self):
        cats = {
            t.category for t in self.model.threats
            if t.target == "user" and t.target_kind == "element"
        }
        self.assertEqual(cats, {"Spoofing", "Repudiation"})

    def test_process_gets_all_six(self):
        cats = {
            t.category for t in self.model.threats
            if t.target == "api" and t.target_kind == "element"
        }
        self.assertEqual(cats, set(STRIDE_CATEGORIES.keys()))

    def test_control_marks_spoofing_mitigated(self):
        spoof = [
            t for t in self.model.threats
            if t.target == "api" and t.category == "Spoofing"
        ]
        self.assertEqual(len(spoof), 1)
        self.assertTrue(spoof[0].mitigated)

    def test_encrypted_flow_mitigates_disclosure(self):
        store_disc = [
            t for t in self.model.threats
            if t.target == "store" and t.category == "Information Disclosure"
        ]
        self.assertEqual(len(store_disc), 1)
        self.assertTrue(store_disc[0].mitigated)

    def test_attack_tree_for_process(self):
        self.assertIn("api", self.model.attack_trees)
        root = self.model.attack_trees["api"]
        self.assertEqual(root.operator, "OR")
        self.assertTrue(len(root.children) >= 6)

    def test_summary_counts(self):
        s = self.model.summary()
        self.assertEqual(s["total_threats"], len(self.model.threats))
        self.assertGreater(s["unmitigated"], 0)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.spec_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "demos", "01-basic", "webapp.yml",
        )

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr = old_out, old_err
        return code, out.getvalue(), err.getvalue()

    def test_demo_spec_exists(self):
        self.assertTrue(os.path.exists(self.spec_path))

    def test_analyze_table(self):
        code, out, _ = self._run(["analyze", self.spec_path])
        self.assertEqual(code, 0)
        self.assertIn("Acme Web Application", out)
        self.assertIn("SEVERITY", out)

    def test_analyze_json_is_valid(self):
        code, out, _ = self._run(["--format", "json", "analyze", self.spec_path])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["system"], "Acme Web Application")
        self.assertIn("threats", data)
        self.assertIn("attack_trees", data)
        self.assertIn("summary", data)

    def test_fail_on_high_returns_nonzero(self):
        code, _, err = self._run(["analyze", self.spec_path, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("unmitigated", err)

    def test_validate_ok(self):
        code, out, _ = self._run(["validate", self.spec_path])
        self.assertEqual(code, 0)
        self.assertIn("VALID", out)

    def test_validate_bad_spec_via_stdin(self):
        old = sys.stdin
        sys.stdin = io.StringIO("elements: []\n")
        try:
            code, _, _ = self._run(["validate", "-"])
        finally:
            sys.stdin = old
        self.assertEqual(code, 1)

    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "threatmodeler")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
