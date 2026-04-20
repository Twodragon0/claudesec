"""
Unit tests for scanner/lib/dashboard_html_helpers.py.

Pure helpers covered: _infer_category, _scanner_default_action,
_redact_target, _rel_link, _has_cmd (with shutil.which mocked),
_cmd_pill, _compute_severity_counts, _compute_severity_bars,
_build_replacements.

Each test exercises one behaviour and is independent of any other
test (no shared mutable state, no network).  Tests are stdlib-only and
pass under both pytest (the CI runner) and plain `python3 -m unittest`
discovery. No third-party test deps beyond what the test exercises.
"""

import hashlib
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_html_helpers as helpers  # noqa: E402


# ===========================================================================
# 1. _infer_category
# ===========================================================================


class TestInferCategory(unittest.TestCase):
    def test_iam_prefix_maps_to_access_control(self):
        self.assertEqual(helpers._infer_category("IAM-001"), "access-control")

    def test_lowercase_input_uppercased(self):
        self.assertEqual(helpers._infer_category("iam-002"), "access-control")

    def test_infra_prefix(self):
        self.assertEqual(helpers._infer_category("INFRA-42"), "infra")

    def test_docker_prefix_maps_to_infra(self):
        self.assertEqual(helpers._infer_category("DOCKER-1"), "infra")

    def test_net_prefix_maps_to_network(self):
        self.assertEqual(helpers._infer_category("NET-9"), "network")

    def test_tls_prefix_maps_to_network(self):
        self.assertEqual(helpers._infer_category("TLS-1"), "network")

    def test_nmap_prefix_maps_to_network(self):
        self.assertEqual(helpers._infer_category("NMAP-3"), "network")

    def test_cicd_prefix(self):
        self.assertEqual(helpers._infer_category("CICD-1"), "cicd")

    def test_code_and_sast_prefixes(self):
        self.assertEqual(helpers._infer_category("CODE-1"), "code")
        self.assertEqual(helpers._infer_category("SAST-2"), "code")

    def test_ai_and_llm_prefixes(self):
        self.assertEqual(helpers._infer_category("AI-1"), "ai")
        self.assertEqual(helpers._infer_category("LLM-9"), "ai")

    def test_cloud_family_prefixes(self):
        for prefix in ("CLOUD", "AWS", "GCP", "AZURE"):
            self.assertEqual(helpers._infer_category(f"{prefix}-1"), "cloud")

    def test_mac_and_cis_prefixes_map_to_macos(self):
        self.assertEqual(helpers._infer_category("MAC-1"), "macos")
        self.assertEqual(helpers._infer_category("CIS-1"), "macos")

    def test_saas_and_zia_prefixes(self):
        self.assertEqual(helpers._infer_category("SAAS-API-022"), "saas")
        self.assertEqual(helpers._infer_category("ZIA-1"), "saas")

    def test_win_and_kisa_prefixes_map_to_windows(self):
        self.assertEqual(helpers._infer_category("WIN-1"), "windows")
        self.assertEqual(helpers._infer_category("KISA-7"), "windows")

    def test_prowler_prefix(self):
        self.assertEqual(helpers._infer_category("PROWLER-5"), "prowler")

    def test_unknown_prefix_returns_other(self):
        self.assertEqual(helpers._infer_category("FOO-1"), "other")

    def test_no_dash_uses_full_id_uppercased(self):
        # Without a dash, the full id is uppercased and looked up.
        self.assertEqual(helpers._infer_category("iam"), "access-control")
        self.assertEqual(helpers._infer_category("xyz"), "other")


# ===========================================================================
# 2. _scanner_default_action
# ===========================================================================


class TestScannerDefaultAction(unittest.TestCase):
    def test_known_categories_return_specific_text(self):
        for cat in (
            "access-control",
            "infra",
            "network",
            "cicd",
            "code",
            "ai",
            "cloud",
            "macos",
            "saas",
            "windows",
            "prowler",
            "other",
        ):
            msg = helpers._scanner_default_action(cat)
            self.assertIsInstance(msg, str)
            self.assertGreater(len(msg), 0)

    def test_unknown_category_returns_generic_fallback(self):
        msg = helpers._scanner_default_action("not-a-real-category")
        self.assertIn("Review findings", msg)


# ===========================================================================
# 3. _redact_target
# ===========================================================================


class TestRedactTarget(unittest.TestCase):
    def test_empty_value_returns_empty(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", None)
            self.assertEqual(helpers._redact_target(""), "")

    def test_none_value_returns_empty(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", None)
            self.assertEqual(helpers._redact_target(None), "")

    def test_show_env_returns_value_unchanged(self):
        with patch.dict(
            os.environ, {"CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS": "1"}, clear=False
        ):
            self.assertEqual(helpers._redact_target("example.com"), "example.com")

    def test_default_hashes_value(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", None)
            result = helpers._redact_target("example.com")
        expected_hash = hashlib.sha256(b"example.com").hexdigest()[:10]
        self.assertEqual(result, f"target-{expected_hash}")

    def test_show_env_other_value_still_redacts(self):
        with patch.dict(
            os.environ, {"CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS": "0"}, clear=False
        ):
            result = helpers._redact_target("example.com")
        self.assertTrue(result.startswith("target-"))

    def test_whitespace_only_value_returns_empty(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", None)
            # After .strip(), whitespace input becomes "", returned as-is.
            self.assertEqual(helpers._redact_target("   "), "")


# ===========================================================================
# 4. _rel_link
# ===========================================================================


class TestRelLink(unittest.TestCase):
    def test_path_is_stripped_of_leading_slash(self):
        out = helpers._rel_link("/reports/x.html")
        self.assertIn('href="reports/x.html"', out)
        self.assertIn(">reports/x.html<", out)

    def test_label_used_when_provided(self):
        out = helpers._rel_link("/a.html", label="Report A")
        self.assertIn(">Report A<", out)

    def test_none_path_handled(self):
        out = helpers._rel_link(None)
        self.assertIn('href=""', out)

    def test_label_is_escaped(self):
        out = helpers._rel_link("x.html", label="<script>")
        self.assertIn("&lt;script&gt;", out)
        self.assertNotIn("<script>", out)


# ===========================================================================
# 5. _has_cmd  (shutil.which mocked)
# ===========================================================================


class TestHasCmd(unittest.TestCase):
    def test_present_when_which_returns_path(self):
        with patch("dashboard_html_helpers.shutil.which", return_value="/usr/bin/ls"):
            self.assertTrue(helpers._has_cmd("ls"))

    def test_absent_when_which_returns_none(self):
        with patch("dashboard_html_helpers.shutil.which", return_value=None):
            self.assertFalse(helpers._has_cmd("nope"))

    def test_exception_returns_false(self):
        with patch(
            "dashboard_html_helpers.shutil.which", side_effect=OSError("boom")
        ):
            self.assertFalse(helpers._has_cmd("x"))


# ===========================================================================
# 6. _cmd_pill
# ===========================================================================


class TestCmdPill(unittest.TestCase):
    def test_present_uses_env_on_and_filled_dot(self):
        out = helpers._cmd_pill("trivy", True)
        self.assertIn("env-on", out)
        self.assertIn("ep-st on", out)
        self.assertIn("●", out)

    def test_absent_uses_env_off_and_open_dot(self):
        out = helpers._cmd_pill("trivy", False)
        self.assertIn("env-off", out)
        self.assertIn("ep-st off", out)
        self.assertIn("○", out)

    def test_name_is_escaped(self):
        out = helpers._cmd_pill("<bad>", True)
        self.assertIn("&lt;bad&gt;", out)
        self.assertNotIn("<bad>", out)

    def test_note_rendered_when_provided(self):
        out = helpers._cmd_pill("nmap", True, note="v7.95")
        self.assertIn("v7.95", out)

    def test_note_omitted_when_empty(self):
        out = helpers._cmd_pill("nmap", True, note="")
        self.assertNotIn("margin-top", out)


# ===========================================================================
# 7. _compute_severity_counts
# ===========================================================================


class TestComputeSeverityCounts(unittest.TestCase):
    def test_sums_provider_summary_values(self):
        prov_summary = {
            "aws": {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5},
            "gcp": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 2},
        }
        result = helpers._compute_severity_counts(prov_summary, [])
        self.assertEqual(result["n_crit"], 1)
        self.assertEqual(result["n_high"], 3)
        self.assertEqual(result["n_med"], 3)
        self.assertEqual(result["n_low"], 4)
        self.assertEqual(result["n_info"], 7)
        self.assertEqual(result["policy_022_top"], 0)

    def test_findings_severity_merged_into_counts(self):
        findings = [
            {"severity": "critical", "id": "X-1"},
            {"severity": "HIGH", "id": "X-2"},
            {"severity": "Medium", "id": "X-3"},
            {"severity": "low", "id": "X-4"},
            {"severity": "informational", "id": "X-5"},
            {"severity": "", "id": "X-6"},
        ]
        result = helpers._compute_severity_counts({}, findings)
        self.assertEqual(result["n_crit"], 1)
        # Non-lowercase severities are not counted because the code lowercases
        # the severity first — so "HIGH" matches "high".
        self.assertEqual(result["n_high"], 1)
        self.assertEqual(result["n_med"], 1)
        self.assertEqual(result["n_low"], 1)

    def test_policy_022_counted_case_insensitive(self):
        findings = [
            {"severity": "high", "id": "saas-api-022"},
            {"severity": "high", "id": "SAAS-API-022-X"},
            {"severity": "high", "id": "OTHER"},
        ]
        result = helpers._compute_severity_counts({}, findings)
        self.assertEqual(result["policy_022_top"], 2)

    def test_missing_informational_key_defaults_to_zero(self):
        prov_summary = {
            "aws": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        result = helpers._compute_severity_counts(prov_summary, [])
        self.assertEqual(result["n_info"], 0)

    def test_empty_inputs_return_zero_counts(self):
        result = helpers._compute_severity_counts({}, [])
        self.assertEqual(result["n_crit"], 0)
        self.assertEqual(result["n_high"], 0)
        self.assertEqual(result["n_med"], 0)
        self.assertEqual(result["n_low"], 0)
        self.assertEqual(result["n_info"], 0)
        self.assertEqual(result["policy_022_top"], 0)


# ===========================================================================
# 8. _compute_severity_bars
# ===========================================================================


class TestComputeSeverityBars(unittest.TestCase):
    def test_all_zero_uses_one_denominator(self):
        # max(0, 1) == 1 so every bar should be 0.0.
        bars = helpers._compute_severity_bars(0, 0, 0, 0, 0)
        self.assertEqual(bars["bar_crit"], 0.0)
        self.assertEqual(bars["bar_high"], 0.0)
        self.assertEqual(bars["bar_med"], 0.0)
        self.assertEqual(bars["bar_warn"], 0.0)
        self.assertEqual(bars["bar_low"], 0.0)

    def test_percentages_sum_close_to_100(self):
        bars = helpers._compute_severity_bars(1, 1, 1, 1, 1)
        total = bars["bar_crit"] + bars["bar_high"] + bars["bar_med"] \
            + bars["bar_warn"] + bars["bar_low"]
        # Each bucket is 20.0 so the sum should be exactly 100.0.
        self.assertAlmostEqual(total, 100.0, places=1)
        self.assertEqual(bars["bar_crit"], 20.0)

    def test_rounding_is_one_decimal(self):
        # 1/3 = 33.333… → rounded to 33.3.
        bars = helpers._compute_severity_bars(1, 1, 1, 0, 0)
        self.assertEqual(bars["bar_crit"], 33.3)
        self.assertEqual(bars["bar_high"], 33.3)
        self.assertEqual(bars["bar_med"], 33.3)


# ===========================================================================
# 9. _build_replacements
# ===========================================================================


class TestBuildReplacements(unittest.TestCase):
    def test_maps_positional_values_to_template_keys(self):
        keys = helpers._TEMPLATE_KEYS
        values = list(range(len(keys)))
        result = helpers._build_replacements(*values)
        for i, key in enumerate(keys):
            self.assertIn(key, result)
            self.assertEqual(result[key], str(i))

    def test_stringifies_values(self):
        # Passing mixed types — all should be converted to str.
        result = helpers._build_replacements(1, "two", 3.5, None)
        self.assertEqual(result["VERSION"], "1")
        self.assertEqual(result["NOW"], "two")
        self.assertEqual(result["DURATION"], "3.5")
        self.assertEqual(result["PASSED"], "None")

    def test_fewer_values_truncates_result(self):
        # zip() stops at the shorter sequence, so only 2 keys populated.
        result = helpers._build_replacements("a", "b")
        self.assertEqual(len(result), 2)
        self.assertEqual(result["VERSION"], "a")
        self.assertEqual(result["NOW"], "b")

    def test_no_values_returns_empty_dict(self):
        self.assertEqual(helpers._build_replacements(), {})


if __name__ == "__main__":
    unittest.main()
