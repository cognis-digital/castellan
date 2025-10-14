"""Engine tests: parsing, STRIDE + LINDDUN derivation, scoring, attack trees."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from castellan import (  # noqa: E402
    parse_spec, build_threat_model, SpecError, TOOL_NAME, TOOL_VERSION,
    STRIDE_CATEGORIES, LINDDUN_CATEGORIES,
)
from castellan import scoring  # noqa: E402

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
    data_classification: pii
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
        self.assertTrue(spec.element("api").trusted)

    def test_missing_name_raises(self):
        with self.assertRaises(SpecError):
            parse_spec("elements:\n  - name: x\n    type: process\n")

    def test_unknown_type_raises(self):
        with self.assertRaises(SpecError):
            parse_spec("name: X\nelements:\n  - name: y\n    type: wormhole\n")

    def test_flow_to_unknown_element_raises(self):
        bad = ("name: X\nelements:\n  - name: a\n    type: process\n"
               "flows:\n  - from: a\n    to: ghost\n")
        with self.assertRaises(SpecError):
            parse_spec(bad)


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.model = build_threat_model(parse_spec(SPEC))

    def test_external_entity_only_spoof_repudiation(self):
        cats = {t.category for t in self.model.threats
                if t.target == "user" and t.target_kind == "element"
                and t.methodology == "STRIDE"}
        self.assertEqual(cats, {"Spoofing", "Repudiation"})

    def test_process_gets_all_six_stride(self):
        cats = {t.category for t in self.model.threats
                if t.target == "api" and t.target_kind == "element"
                and t.methodology == "STRIDE"}
        self.assertEqual(cats, set(STRIDE_CATEGORIES.keys()))

    def test_control_marks_spoofing_mitigated(self):
        spoof = [t for t in self.model.threats
                 if t.target == "api" and t.category == "Spoofing"]
        self.assertTrue(spoof and spoof[0].mitigated)

    def test_encrypted_flow_mitigates_disclosure(self):
        disc = [t for t in self.model.threats
                if t.target == "store" and t.category == "Information Disclosure"]
        self.assertTrue(disc and disc[0].mitigated)

    def test_pii_datastore_gets_linddun(self):
        methods = {t.methodology for t in self.model.threats if t.target == "db"}
        self.assertIn("LINDDUN", methods)
        cats = {t.category for t in self.model.threats
                if t.target == "db" and t.methodology == "LINDDUN"}
        self.assertTrue(cats.issubset(set(LINDDUN_CATEGORIES.keys())))

    def test_threats_have_references_and_compliance(self):
        injection = [t for t in self.model.threats if t.category == "Tampering"]
        self.assertTrue(injection)
        t = injection[0]
        self.assertTrue(t.compliance)            # mapped to frameworks
        self.assertGreater(t.risk, 0.0)
        self.assertIn(t.risk_level,
                      {"info", "low", "medium", "high", "critical"})

    def test_attack_tree_for_process(self):
        root = self.model.attack_trees["api"]
        self.assertEqual(root.operator, "OR")
        self.assertGreaterEqual(len(root.children), 6)

    def test_summary_shape(self):
        s = self.model.summary()
        for key in ("total_threats", "unmitigated", "risk_score",
                    "by_methodology", "by_category", "frameworks_referenced"):
            self.assertIn(key, s)
        self.assertLessEqual(s["risk_score"], 10.0)

    def test_to_dict_serializable(self):
        import json
        json.dumps(self.model.to_dict(), default=str)


class ScoringTests(unittest.TestCase):
    def test_exposure_raises_risk(self):
        base = scoring.compute_dread("Information Disclosure")
        exp = scoring.compute_dread("Information Disclosure", exposed=True,
                                    crosses_boundary=True)
        self.assertGreaterEqual(exp["risk"], base["risk"])

    def test_mitigation_lowers_risk(self):
        unm = scoring.compute_dread("Tampering")
        mit = scoring.compute_dread("Tampering", mitigated=True)
        self.assertLess(mit["risk"], unm["risk"])

    def test_aggregate_bounds(self):
        self.assertEqual(scoring.aggregate_risk([]), 0.0)
        self.assertLessEqual(scoring.aggregate_risk([9, 9, 9, 9]), 10.0)

    def test_identity_constants(self):
        self.assertEqual(TOOL_NAME, "castellan")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
