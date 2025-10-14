"""Library tests: catalog sizes are real, deterministic, and well-formed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from castellan import library  # noqa: E402
from castellan.data import frameworks as F  # noqa: E402
from castellan import compliance as C  # noqa: E402


class LibraryStatsTests(unittest.TestCase):
    def test_headline_counts(self):
        s = library.stats()
        # The bundled catalogs are large and real; these are floors, not ceilings.
        self.assertGreaterEqual(s["threat_scenarios"], 4605)
        self.assertGreaterEqual(s["security_requirements"], 3500)
        self.assertGreaterEqual(s["compliance_frameworks"], 615)

    def test_scenarios_are_unique_and_referenced(self):
        lib = library.build_threat_library()
        ids = [s.id for s in lib]
        self.assertEqual(len(ids), len(set(ids)))         # unique ids
        # most scenarios carry at least one external reference
        with_refs = [s for s in lib if s.cwe or s.capec or s.attack or s.owasp]
        self.assertGreater(len(with_refs), len(lib) // 2)

    def test_requirements_reference_scenarios(self):
        reqs = library.build_requirements()
        sc_ids = {s.id for s in library.build_threat_library()}
        self.assertTrue(all(r.derived_from in sc_ids for r in reqs[:200]))

    def test_deterministic(self):
        a = [s.id for s in library.build_threat_library()]
        b = [s.id for s in library.build_threat_library()]
        self.assertEqual(a, b)


class FrameworkTests(unittest.TestCase):
    def test_unique_ids(self):
        ids = F.ids()
        self.assertEqual(len(ids), len(set(ids)))

    def test_named(self):
        self.assertTrue(all(f.get("name") and f.get("id") for f in F.FRAMEWORKS))

    def test_compliance_mapping_covers_all_categories(self):
        from castellan.core import STRIDE_CATEGORIES, LINDDUN_CATEGORIES
        for cat in list(STRIDE_CATEGORIES) + list(LINDDUN_CATEGORIES):
            self.assertTrue(C.controls_for_category(cat),
                            f"no control mapping for {cat}")


if __name__ == "__main__":
    unittest.main()
