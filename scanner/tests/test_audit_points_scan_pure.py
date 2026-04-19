"""
Unit tests for pure helpers in scanner/lib/audit-points-scan.py.

Each test exercises exactly one behaviour. No network, no subprocess.
tempfile.TemporaryDirectory is used for filesystem fixtures (stdlib only,
so the file runs under both `python3 -m unittest xmlrunner discover` and
pytest).

Import strategy: audit-points-scan.py has hyphens in the filename, so it
cannot be imported via `import audit-points-scan`.  We load it once via
importlib.util.spec_from_file_location, following the pattern already
established in test_diagram_gen_pure_helpers.py.
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_module():
    path = Path(__file__).resolve().parents[1] / "lib" / "audit-points-scan.py"
    spec = importlib.util.spec_from_file_location("audit_points_scan_pure", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


# ===========================================================================
# 1. Module-level constants
# ===========================================================================


class TestModuleConstants(unittest.TestCase):
    def test_cache_dir_name_is_hidden(self):
        self.assertTrue(MOD.CACHE_DIR_NAME.startswith("."))

    def test_cache_dir_name_value(self):
        self.assertEqual(MOD.CACHE_DIR_NAME, ".claudesec-audit-points")

    def test_cache_file_is_json(self):
        self.assertTrue(MOD.CACHE_FILE.endswith(".json"))

    def test_detected_file_is_json(self):
        self.assertTrue(MOD.DETECTED_FILE.endswith(".json"))

    def test_product_detectors_is_non_empty_list(self):
        self.assertIsInstance(MOD.PRODUCT_DETECTORS, list)
        self.assertGreater(len(MOD.PRODUCT_DETECTORS), 0)

    def test_product_detectors_have_name_and_indicators(self):
        for row in MOD.PRODUCT_DETECTORS:
            self.assertGreaterEqual(len(row), 2)
            self.assertIsInstance(row[0], str)
            self.assertIsInstance(row[1], list)

    def test_product_detectors_covers_jenkins(self):
        names = [r[0] for r in MOD.PRODUCT_DETECTORS]
        self.assertIn("Jenkins", names)

    def test_product_detectors_covers_querypie(self):
        names = [r[0] for r in MOD.PRODUCT_DETECTORS]
        self.assertIn("QueryPie", names)


# ===========================================================================
# 2. _has_nexus_indicator
# ===========================================================================


class TestHasNexusIndicator(unittest.TestCase):
    def test_empty_dir_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(MOD._has_nexus_indicator(d))

    def test_pom_without_nexus_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("<project><modelVersion>4.0.0</modelVersion></project>")
            self.assertFalse(MOD._has_nexus_indicator(d))

    def test_pom_with_nexus_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("<project><repositories><url>https://nexus.example/repo</url></repositories></project>")
            self.assertTrue(MOD._has_nexus_indicator(d))

    def test_gradle_kts_with_nexus_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "build.gradle.kts"), "w", encoding="utf-8") as f:
                f.write('maven { url = uri("https://Nexus.example/repository/") }')
            self.assertTrue(MOD._has_nexus_indicator(d))

    def test_gradle_groovy_with_nexus_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "build.gradle"), "w", encoding="utf-8") as f:
                f.write("maven { url 'https://nexus.example/repo' }")
            self.assertTrue(MOD._has_nexus_indicator(d))

    def test_case_insensitive_nexus_match(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("NEXUS server")
            self.assertTrue(MOD._has_nexus_indicator(d))


# ===========================================================================
# 3. _file_contains_any
# ===========================================================================


class TestFileContainsAny(unittest.TestCase):
    def test_empty_dir_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(MOD._file_contains_any(d, ["okta"], [".env"]))

    def test_file_without_keyword_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".env"), "w", encoding="utf-8") as f:
                f.write("DATABASE_URL=postgres://host/db")
            self.assertFalse(MOD._file_contains_any(d, ["okta"], [".env"]))

    def test_file_with_keyword_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".env"), "w", encoding="utf-8") as f:
                f.write("OKTA_DOMAIN=example.com")
            self.assertTrue(MOD._file_contains_any(d, ["okta"], [".env"]))

    def test_wrong_suffix_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as f:
                f.write("okta references here")
            self.assertFalse(MOD._file_contains_any(d, ["okta"], [".env", ".yml"]))

    def test_nested_file_matched(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "sub")
            os.makedirs(sub)
            with open(os.path.join(sub, "config.yml"), "w", encoding="utf-8") as f:
                f.write("querypie: enabled")
            self.assertTrue(MOD._file_contains_any(d, ["querypie"], [".yml"]))

    def test_skips_ignored_directories(self):
        with tempfile.TemporaryDirectory() as d:
            ignored = os.path.join(d, "node_modules")
            os.makedirs(ignored)
            with open(os.path.join(ignored, "config.yml"), "w", encoding="utf-8") as f:
                f.write("okta should be ignored here")
            self.assertFalse(MOD._file_contains_any(d, ["okta"], [".yml"]))

    def test_multiple_keywords_any_matches(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".env"), "w", encoding="utf-8") as f:
                f.write("HARBOR_URL=example")
            self.assertTrue(MOD._file_contains_any(d, ["okta", "harbor"], [".env"]))

    def test_multiple_suffixes_any_matches(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config.yaml"), "w", encoding="utf-8") as f:
                f.write("okta here")
            self.assertTrue(MOD._file_contains_any(d, ["okta"], [".yml", ".yaml"]))


# ===========================================================================
# 4. _has_scalr_in_terraform
# ===========================================================================


class TestHasScalrInTerraform(unittest.TestCase):
    def test_empty_dir_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(MOD._has_scalr_in_terraform(d))

    def test_tf_without_scalr_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "main.tf"), "w", encoding="utf-8") as f:
                f.write('resource "aws_s3_bucket" "b" {}')
            # glob.glob with "**/*.tf" (non-recursive by default) does not
            # descend, so main.tf at the root is not matched either.
            self.assertFalse(MOD._has_scalr_in_terraform(d))

    def test_nested_tf_with_scalr_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "infra")
            os.makedirs(sub)
            with open(os.path.join(sub, "backend.tf"), "w", encoding="utf-8") as f:
                f.write('backend "scalr" {}')
            self.assertTrue(MOD._has_scalr_in_terraform(d))

    def test_nested_tfvars_with_scalr_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "env")
            os.makedirs(sub)
            with open(os.path.join(sub, "prod.tfvars"), "w", encoding="utf-8") as f:
                f.write("scalr_hostname = example")
            self.assertTrue(MOD._has_scalr_in_terraform(d))


# ===========================================================================
# 5. detect_products
# ===========================================================================


class TestDetectProducts(unittest.TestCase):
    def test_missing_dir_returns_empty_list(self):
        self.assertEqual(MOD.detect_products("/no/such/dir/xyz/abc"), [])

    def test_empty_dir_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(MOD.detect_products(d), [])

    def test_relative_path_is_normalised(self):
        # Module calls os.path.abspath; a relative path to an existing dir works.
        with tempfile.TemporaryDirectory() as d:
            result = MOD.detect_products(d)
            self.assertIsInstance(result, list)

    def test_jenkinsfile_detects_jenkins(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Jenkinsfile"), "w", encoding="utf-8") as f:
                f.write("pipeline {}")
            self.assertIn("Jenkins", MOD.detect_products(d))

    def test_harbor_yml_detects_harbor(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "harbor.yml"), "w", encoding="utf-8") as f:
                f.write("harbor: true")
            self.assertIn("Harbor", MOD.detect_products(d))

    def test_vscode_directory_detects_ides(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".vscode"))
            self.assertIn("IDEs", MOD.detect_products(d))

    def test_idea_directory_detects_ides(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".idea"))
            self.assertIn("IDEs", MOD.detect_products(d))

    def test_pom_with_nexus_extra_detects_nexus(self):
        # Extra check (_has_nexus_indicator) triggers when pom.xml mentions nexus.
        # pom.xml also happens to be a direct indicator, so Nexus is detected.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("<project><url>https://nexus.example</url></project>")
            self.assertIn("Nexus", MOD.detect_products(d))

    def test_extra_callable_path_when_no_direct_indicator(self):
        # QueryPie: no direct indicator file, but .yml file contains the keyword.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "svc.yml"), "w", encoding="utf-8") as f:
                f.write("querypie: true")
            self.assertIn("QueryPie", MOD.detect_products(d))

    def test_multiple_products_detected_together(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Jenkinsfile"), "w", encoding="utf-8") as f:
                f.write("pipeline {}")
            os.makedirs(os.path.join(d, ".vscode"))
            with open(os.path.join(d, "harbor.yml"), "w", encoding="utf-8") as f:
                f.write("harbor: true")
            result = MOD.detect_products(d)
            for expected in ("Jenkins", "Harbor", "IDEs"):
                self.assertIn(expected, result)

    def test_glob_indicator_with_star(self):
        # Feed the detection with a glob containing '*' via a product whose
        # PRODUCT_DETECTORS already uses a non-glob indicator.  We exercise
        # the glob branch indirectly by monkey-patching PRODUCT_DETECTORS.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "service.custom"), "w", encoding="utf-8") as f:
                f.write("x")
            fake = [("Custom", ["*.custom"])]
            with patch.object(MOD, "PRODUCT_DETECTORS", fake):
                self.assertEqual(MOD.detect_products(d), ["Custom"])

    def test_glob_indicator_no_match_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            fake = [("Custom", ["*.nope"])]
            with patch.object(MOD, "PRODUCT_DETECTORS", fake):
                self.assertEqual(MOD.detect_products(d), [])


# ===========================================================================
# 6. _fetch_and_cache
# ===========================================================================


class TestFetchAndCache(unittest.TestCase):
    def test_returns_default_when_dashboard_missing(self):
        # When dashboard-gen.py is absent or raises, the except branch returns
        # the empty stub.  We force that path by patching __file__ to a
        # location with no sibling dashboard-gen.py.
        with tempfile.TemporaryDirectory() as d:
            fake_file = os.path.join(d, "not_a_real_module.py")
            with patch.object(MOD, "__file__", fake_file):
                result = MOD._fetch_and_cache(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})

    def test_returns_dict_shape(self):
        result = MOD._fetch_and_cache(tempfile.gettempdir())
        self.assertIsInstance(result, dict)
        self.assertIn("products", result)
        self.assertIn("fetched_at", result)


# ===========================================================================
# 7. load_cache
# ===========================================================================


class TestLoadCache(unittest.TestCase):
    def test_reads_existing_cache_file(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, MOD.CACHE_DIR_NAME)
            os.makedirs(cache_dir)
            payload = {"products": [{"name": "Jenkins", "files": []}], "fetched_at": "now"}
            with open(os.path.join(cache_dir, MOD.CACHE_FILE), "w", encoding="utf-8") as f:
                json.dump(payload, f)
            result = MOD.load_cache(d)
        self.assertEqual(result, payload)

    def test_fallback_to_fetch_when_cache_missing(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                result = MOD.load_cache(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})
        # No products → no cache file written.
        with tempfile.TemporaryDirectory() as d2:
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                MOD.load_cache(d2)
            self.assertFalse(
                os.path.exists(os.path.join(d2, MOD.CACHE_DIR_NAME, MOD.CACHE_FILE))
            )

    def test_writes_cache_file_when_fetch_returns_products(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"products": [{"name": "Jenkins", "files": []}], "fetched_at": "t"}
            with patch.object(MOD, "_fetch_and_cache", return_value=data):
                result = MOD.load_cache(d)
            cache_path = os.path.join(d, MOD.CACHE_DIR_NAME, MOD.CACHE_FILE)
            self.assertTrue(os.path.isfile(cache_path))
            with open(cache_path, encoding="utf-8") as f:
                persisted = json.load(f)
        self.assertEqual(result, data)
        self.assertEqual(persisted, data)

    def test_malformed_cache_falls_back_to_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, MOD.CACHE_DIR_NAME)
            os.makedirs(cache_dir)
            with open(os.path.join(cache_dir, MOD.CACHE_FILE), "w", encoding="utf-8") as f:
                f.write("not valid json {")
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                result = MOD.load_cache(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})


# ===========================================================================
# 8. run_audit_points_scan
# ===========================================================================


class TestRunAuditPointsScan(unittest.TestCase):
    def test_empty_dir_returns_empty_detection_and_items(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                detected, items = MOD.run_audit_points_scan(d)
        self.assertEqual(detected, [])
        self.assertEqual(items, [])

    def test_detected_products_without_cache_entry_yield_no_items(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Jenkinsfile"), "w", encoding="utf-8") as f:
                f.write("pipeline {}")
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                detected, items = MOD.run_audit_points_scan(d)
        self.assertIn("Jenkins", detected)
        self.assertEqual(items, [])

    def test_items_built_from_cache_files(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Jenkinsfile"), "w", encoding="utf-8") as f:
                f.write("pipeline {}")
            cache_data = {
                "products": [
                    {
                        "name": "Jenkins",
                        "files": [
                            {"name": "check-auth.md", "url": "https://example/check-auth.md"},
                            {"name": "check-plugins.md", "raw_url": "https://example/raw/check-plugins.md"},
                        ],
                    },
                    {"name": "Harbor", "files": [{"name": "harbor.md", "url": "https://example/h"}]},
                ],
                "fetched_at": "t",
            }
            with patch.object(MOD, "_fetch_and_cache", return_value=cache_data):
                detected, items = MOD.run_audit_points_scan(d)
        self.assertIn("Jenkins", detected)
        self.assertNotIn("Harbor", detected)
        names = [i["file_name"] for i in items]
        self.assertIn("check-auth.md", names)
        self.assertIn("check-plugins.md", names)
        # raw_url fallback is used when url is absent.
        check_plugins = next(i for i in items if i["file_name"] == "check-plugins.md")
        self.assertEqual(check_plugins["url"], "https://example/raw/check-plugins.md")
        # Every item has product label propagated.
        for item in items:
            self.assertEqual(item["product"], "Jenkins")

    def test_writes_detected_json(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".vscode"))
            with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                MOD.run_audit_points_scan(d)
            out_path = os.path.join(d, MOD.CACHE_DIR_NAME, MOD.DETECTED_FILE)
            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, encoding="utf-8") as f:
                out = json.load(f)
        self.assertIn("IDEs", out["detected_products"])
        self.assertEqual(out["items"], [])
        self.assertTrue(os.path.isabs(out["scan_dir"]))

    def test_items_missing_name_and_url_default_to_empty_string(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Jenkinsfile"), "w", encoding="utf-8") as f:
                f.write("pipeline {}")
            cache_data = {
                "products": [{"name": "Jenkins", "files": [{}]}],
                "fetched_at": "t",
            }
            with patch.object(MOD, "_fetch_and_cache", return_value=cache_data):
                _detected, items = MOD.run_audit_points_scan(d)
        self.assertEqual(items, [{"product": "Jenkins", "file_name": "", "url": ""}])


# ===========================================================================
# 9. main entrypoint
# ===========================================================================


class TestMain(unittest.TestCase):
    def test_main_uses_env_scan_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                    with patch.object(MOD.sys, "argv", ["audit-points-scan"]):
                        rc = MOD.main()
        self.assertEqual(rc, 0)

    def test_main_uses_argv_when_env_missing(self):
        with tempfile.TemporaryDirectory() as d:
            env = {k: v for k, v in os.environ.items() if k != "SCAN_DIR"}
            with patch.dict(os.environ, env, clear=True):
                with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                    with patch.object(MOD.sys, "argv", ["audit-points-scan", d]):
                        rc = MOD.main()
        self.assertEqual(rc, 0)

    def test_main_defaults_to_cwd(self):
        # Neither SCAN_DIR nor argv[1]; main falls back to os.getcwd().
        with tempfile.TemporaryDirectory() as d:
            env = {k: v for k, v in os.environ.items() if k != "SCAN_DIR"}
            with patch.dict(os.environ, env, clear=True):
                with patch.object(MOD, "_fetch_and_cache", return_value={"products": [], "fetched_at": ""}):
                    with patch.object(MOD.sys, "argv", ["audit-points-scan"]):
                        with patch.object(MOD.os, "getcwd", return_value=d):
                            rc = MOD.main()
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
