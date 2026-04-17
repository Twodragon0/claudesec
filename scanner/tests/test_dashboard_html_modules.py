"""
Smoke tests for the four dashboard HTML modules extracted in commit 7bd78d0.

Directly imports each module so that module-level syntax or import errors are
caught without going through the full dashboard-gen.py integration path.
"""

import sys
import types
import unittest
from pathlib import Path

LIB_DIR = Path(__file__).resolve().parents[1] / "lib"
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

import dashboard_html_helpers
import dashboard_html_builders
import dashboard_html_sections
import dashboard_template


class TestImportsAllFourModules(unittest.TestCase):
    def test_imports_all_four_modules(self):
        for mod in (
            dashboard_html_helpers,
            dashboard_html_builders,
            dashboard_html_sections,
            dashboard_template,
        ):
            self.assertIsInstance(mod, types.ModuleType)


class TestHelpersPureFunctions(unittest.TestCase):
    def test_infer_category_iam(self):
        result = dashboard_html_helpers._infer_category("IAM-001")
        self.assertEqual(result, "access-control")

    def test_has_cmd_bash_present(self):
        self.assertTrue(dashboard_html_helpers._has_cmd("bash"))

    def test_has_cmd_nonexistent(self):
        self.assertFalse(
            dashboard_html_helpers._has_cmd("definitely-not-a-real-binary-xyz-9999")
        )

    def test_compute_severity_counts_empty(self):
        counts = dashboard_html_helpers._compute_severity_counts({}, [])
        for key in ("n_crit", "n_high", "n_med", "n_low", "n_info", "policy_022_top"):
            self.assertIn(key, counts)
            self.assertEqual(counts[key], 0)

    def test_build_replacements_callable(self):
        self.assertTrue(callable(dashboard_html_helpers._build_replacements))


class TestTemplatePrimitives(unittest.TestCase):
    def test_load_html_template_callable(self):
        self.assertTrue(callable(dashboard_template._load_html_template))

    def test_apply_template_and_write_callable(self):
        self.assertTrue(callable(dashboard_template._apply_template_and_write))

    def test_get_architecture_diagram_html_callable(self):
        self.assertTrue(callable(dashboard_template._get_architecture_diagram_html))

    def test_get_architecture_diagram_html_returns_string(self):
        result = dashboard_template._get_architecture_diagram_html(None)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


if __name__ == "__main__":
    unittest.main()
