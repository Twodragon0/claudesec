"""
Unit tests for scanner/lib/dashboard_mapping.py.

Covers pure constants (OWASP_2025, OWASP_LLM_2025, CATEGORY_META, ARCH_DOMAINS,
COMPLIANCE_FRAMEWORKS, OWASP_TO_ARCH) and pure mapping functions
(get_check_en, map_findings_to_owasp, map_architecture,
_match_prowler_compliance, map_compliance).

Tests are stdlib-only and work under both unittest (xmlrunner discover) and
pytest. No pytest import, no internal IPs, no network, no shared state.
"""

import importlib
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_mapping as dm  # noqa: E402


def _reload_with_fallback():
    """Reload dashboard_mapping with compliance-map.py import forced to fail.

    Returns a freshly-loaded module object whose inline fallback definitions
    (_match_prowler_compliance, map_compliance, COMPLIANCE_CONTROL_MAP) are
    the ones used instead of the external compliance_map module.
    """
    # Force the spec_from_file_location call to raise so the except branch
    # runs and _COMPLIANCE_IMPORTED stays False. The inline definitions at
    # module scope then become the active ones.
    with patch(
        "importlib.util.spec_from_file_location",
        side_effect=RuntimeError("forced fallback"),
    ):
        if "dashboard_mapping" in sys.modules:
            del sys.modules["dashboard_mapping"]
        fallback_mod = importlib.import_module("dashboard_mapping")
    return fallback_mod


# ===========================================================================
# 1. CHECK_EN_MAP / DEFAULT_SUMMARY / DEFAULT_ACTION
# ===========================================================================


class TestCheckEnMapConstants(unittest.TestCase):
    def test_default_summary_is_non_empty_string(self):
        assert isinstance(dm.DEFAULT_SUMMARY, str)
        assert len(dm.DEFAULT_SUMMARY) > 0

    def test_default_action_is_non_empty_string(self):
        assert isinstance(dm.DEFAULT_ACTION, str)
        assert len(dm.DEFAULT_ACTION) > 0

    def test_check_en_map_entries_have_summary_and_action(self):
        assert isinstance(dm.CHECK_EN_MAP, dict)
        assert len(dm.CHECK_EN_MAP) > 10
        for key, val in dm.CHECK_EN_MAP.items():
            assert isinstance(key, str) and key
            assert "summary" in val and isinstance(val["summary"], str)
            assert "action" in val and isinstance(val["action"], str)

    def test_known_aws_key_present(self):
        assert "guardduty_is_enabled" in dm.CHECK_EN_MAP
        assert "s3_bucket_public_access" in dm.CHECK_EN_MAP


# ===========================================================================
# 2. get_check_en
# ===========================================================================


class TestGetCheckEn(unittest.TestCase):
    def test_exact_key_match_returns_mapped_entry(self):
        result = dm.get_check_en("guardduty_is_enabled")
        assert "GuardDuty" in result["summary"]
        assert "GuardDuty" in result["action"]

    def test_keyword_substring_match(self):
        # "mfa" substring appears in the key list
        result = dm.get_check_en("some-check-with-mfa-in-it")
        assert result["summary"] != dm.DEFAULT_SUMMARY

    def test_case_insensitive_match(self):
        result = dm.get_check_en("BRANCH_PROTECTION")
        assert "branch protection" in result["summary"].lower()

    def test_unknown_check_falls_back_to_default(self):
        result = dm.get_check_en("completely_unrelated_xyz_123")
        assert result["summary"] == dm.DEFAULT_SUMMARY
        assert result["action"] == dm.DEFAULT_ACTION

    def test_empty_string_returns_default(self):
        result = dm.get_check_en("")
        assert result["summary"] == dm.DEFAULT_SUMMARY
        assert result["action"] == dm.DEFAULT_ACTION

    def test_none_input_returns_default(self):
        result = dm.get_check_en(None)
        assert result["summary"] == dm.DEFAULT_SUMMARY
        assert result["action"] == dm.DEFAULT_ACTION

    def test_returned_dict_has_required_keys(self):
        result = dm.get_check_en("encrypt")
        assert set(result.keys()) == {"summary", "action"}


# ===========================================================================
# 3. OWASP_2025 constant
# ===========================================================================


class TestOwasp2025Constant(unittest.TestCase):
    def test_has_ten_entries(self):
        assert len(dm.OWASP_2025) == 10

    def test_entries_have_required_keys(self):
        for entry in dm.OWASP_2025:
            for key in ("id", "name", "desc", "summary", "action", "url"):
                assert key in entry, f"Missing {key}"

    def test_ids_are_unique_and_ordered(self):
        ids = [e["id"] for e in dm.OWASP_2025]
        assert ids == sorted(ids)
        assert len(set(ids)) == 10

    def test_urls_point_to_owasp_org(self):
        for e in dm.OWASP_2025:
            assert e["url"].startswith("https://owasp.org/")


# ===========================================================================
# 4. OWASP_CHECK_MAP
# ===========================================================================


class TestOwaspCheckMap(unittest.TestCase):
    def test_all_owasp_ids_have_keyword_list(self):
        for entry in dm.OWASP_2025:
            oid = entry["id"]
            assert oid in dm.OWASP_CHECK_MAP
            assert isinstance(dm.OWASP_CHECK_MAP[oid], list)
            assert len(dm.OWASP_CHECK_MAP[oid]) > 0

    def test_all_keywords_are_lowercase_strings(self):
        for oid, kws in dm.OWASP_CHECK_MAP.items():
            for kw in kws:
                assert isinstance(kw, str)
                assert kw == kw.lower()


# ===========================================================================
# 5. OWASP_LLM_2025 constant
# ===========================================================================


class TestOwaspLlm2025Constant(unittest.TestCase):
    def test_has_ten_entries(self):
        assert len(dm.OWASP_LLM_2025) == 10

    def test_ids_use_llm_prefix(self):
        for e in dm.OWASP_LLM_2025:
            assert e["id"].startswith("LLM")

    def test_entries_have_required_keys(self):
        for entry in dm.OWASP_LLM_2025:
            for key in ("id", "name", "desc", "summary", "action", "url"):
                assert key in entry


# ===========================================================================
# 6. map_findings_to_owasp
# ===========================================================================


class TestMapFindingsToOwasp(unittest.TestCase):
    def _f(self, check="", title="", message=""):
        return {"check": check, "title": title, "message": message}

    def test_empty_list_returns_all_categories_empty(self):
        result = dm.map_findings_to_owasp([])
        assert set(result.keys()) == {e["id"] for e in dm.OWASP_2025}
        for findings in result.values():
            assert findings == []

    def test_branch_protection_maps_to_a01(self):
        f = self._f(check="branch_protection", title="Branch", message="none")
        result = dm.map_findings_to_owasp([f])
        assert f in result["A01:2025"]

    def test_encrypt_keyword_maps_to_a04(self):
        f = self._f(check="tls_missing", title="encrypt traffic", message="")
        result = dm.map_findings_to_owasp([f])
        assert f in result["A04:2025"]

    def test_each_finding_goes_into_first_matching_category_only(self):
        # "branch_protection" matches A01 first, even though "logging"
        # (A09) also appears elsewhere in the keyword map.
        f = self._f(check="branch_protection logging", title="", message="")
        result = dm.map_findings_to_owasp([f])
        placed = sum(1 for findings in result.values() if f in findings)
        assert placed == 1
        assert f in result["A01:2025"]

    def test_unmatched_finding_not_placed_anywhere(self):
        f = self._f(check="no_match_here", title="z", message="z")
        result = dm.map_findings_to_owasp([f])
        for findings in result.values():
            assert f not in findings

    def test_case_insensitive_match(self):
        f = self._f(check="MFA_DISABLED", title="", message="")
        result = dm.map_findings_to_owasp([f])
        assert f in result["A07:2025"]


# ===========================================================================
# 7. COMPLIANCE_FRAMEWORKS
# ===========================================================================


class TestComplianceFrameworks(unittest.TestCase):
    def test_is_non_empty_list(self):
        assert isinstance(dm.COMPLIANCE_FRAMEWORKS, list)
        assert len(dm.COMPLIANCE_FRAMEWORKS) >= 5

    def test_each_framework_has_required_keys(self):
        for fw in dm.COMPLIANCE_FRAMEWORKS:
            assert "name" in fw and fw["name"]
            assert "url" in fw and fw["url"].startswith("http")
            assert "desc" in fw and fw["desc"]

    def test_includes_major_frameworks(self):
        names = {fw["name"] for fw in dm.COMPLIANCE_FRAMEWORKS}
        for expected in (
            "OWASP Top 10:2025",
            "ISO 27001:2022",
            "PCI-DSS v4.0.1",
            "NIST CSF 2.0",
            "CIS Benchmarks",
        ):
            assert expected in names


# ===========================================================================
# 8. COMPLIANCE_CONTROL_MAP
# ===========================================================================


class TestComplianceControlMap(unittest.TestCase):
    def test_is_dict_with_framework_keys(self):
        assert isinstance(dm.COMPLIANCE_CONTROL_MAP, dict)
        assert len(dm.COMPLIANCE_CONTROL_MAP) > 0

    def test_every_control_has_required_shape(self):
        for framework, controls in dm.COMPLIANCE_CONTROL_MAP.items():
            assert isinstance(framework, str)
            assert isinstance(controls, list)
            for ctrl in controls:
                for key in ("control", "name", "desc", "action", "checks"):
                    assert key in ctrl, f"{framework}: missing {key}"
                assert isinstance(ctrl["checks"], list)


# ===========================================================================
# 9. _match_prowler_compliance
# ===========================================================================


class TestMatchProwlerCompliance(unittest.TestCase):
    def test_no_compliance_field_returns_false(self):
        assert dm._match_prowler_compliance({}, "ISO 27001:2022") is False

    def test_empty_compliance_returns_false(self):
        assert (
            dm._match_prowler_compliance({"compliance": {}}, "PCI-DSS") is False
        )

    def test_key_substring_match(self):
        finding = {"compliance": {"ISO27001": ["A.8.2"]}}
        assert dm._match_prowler_compliance(finding, "iso27001") is True

    def test_value_list_substring_match(self):
        finding = {"compliance": {"framework": ["PCI-DSS v4.0.1"]}}
        assert dm._match_prowler_compliance(finding, "PCI-DSS") is True

    def test_value_string_substring_match(self):
        finding = {"compliance": {"framework": "NIST 800-53"}}
        assert dm._match_prowler_compliance(finding, "nist") is True

    def test_unrelated_compliance_returns_false(self):
        finding = {"compliance": {"other": ["SOC2"]}}
        assert dm._match_prowler_compliance(finding, "HIPAA") is False


# ===========================================================================
# 10. map_compliance
# ===========================================================================


class TestMapCompliance(unittest.TestCase):
    def _f(self, check="", title="", message="", compliance=None):
        d = {"check": check, "title": title, "message": message}
        if compliance is not None:
            d["compliance"] = compliance
        return d

    def test_empty_findings_every_control_passes(self):
        result = dm.map_compliance([])
        for framework, controls in result.items():
            assert framework in dm.COMPLIANCE_CONTROL_MAP
            for ctrl in controls:
                assert ctrl["status"] == "PASS"
                assert ctrl["count"] == 0
                assert ctrl["findings"] == []

    def test_keyword_match_triggers_fail(self):
        f = self._f(check="mfa_missing", title="MFA", message="No MFA")
        result = dm.map_compliance([f])
        iso = result["ISO 27001:2022"]
        a85 = next(c for c in iso if c["control"] == "A.8.5")
        assert a85["status"] == "FAIL"
        assert a85["count"] == 1

    def test_findings_capped_at_five(self):
        findings = [
            self._f(check="encrypt", title=f"t{i}", message="m") for i in range(10)
        ]
        result = dm.map_compliance(findings)
        iso = result["ISO 27001:2022"]
        a824 = next(c for c in iso if c["control"] == "A.8.24")
        assert a824["count"] == 10
        assert len(a824["findings"]) == 5

    def test_prowler_native_compliance_fallback(self):
        # Finding has no matching keyword, but native compliance references ISO.
        f = self._f(
            check="unrelated",
            title="unrelated",
            message="unrelated",
            compliance={"ISO 27001:2022": ["A.8.5"]},
        )
        result = dm.map_compliance([f])
        iso_controls = result["ISO 27001:2022"]
        # All ISO controls should pick this up via native fallback.
        assert all(c["status"] == "FAIL" for c in iso_controls)


# ===========================================================================
# 11. ARCH_DOMAINS
# ===========================================================================


class TestArchDomains(unittest.TestCase):
    def test_is_non_empty_list(self):
        assert isinstance(dm.ARCH_DOMAINS, list)
        assert len(dm.ARCH_DOMAINS) >= 6

    def test_each_domain_has_required_keys(self):
        for d in dm.ARCH_DOMAINS:
            for key in ("name", "icon", "checks", "summary", "action"):
                assert key in d
            assert isinstance(d["checks"], list)
            assert len(d["checks"]) > 0

    def test_domain_names_are_unique(self):
        names = [d["name"] for d in dm.ARCH_DOMAINS]
        assert len(names) == len(set(names))


# ===========================================================================
# 12. ARCH_DOMAIN_LINKS
# ===========================================================================


class TestArchDomainLinks(unittest.TestCase):
    def test_entries_have_owasp_compliance_scanner(self):
        for link in dm.ARCH_DOMAIN_LINKS:
            assert "owasp" in link
            assert "compliance" in link
            assert "scanner" in link
            assert isinstance(link["owasp"], list)
            assert isinstance(link["compliance"], list)
            assert isinstance(link["scanner"], list)

    def test_compliance_entries_are_framework_control_tuples(self):
        for link in dm.ARCH_DOMAIN_LINKS:
            for item in link["compliance"]:
                assert isinstance(item, tuple)
                assert len(item) == 2
                assert isinstance(item[0], str) and isinstance(item[1], str)


# ===========================================================================
# 13. OWASP_TO_ARCH
# ===========================================================================


class TestOwaspToArch(unittest.TestCase):
    def test_has_entries_for_all_owasp_prefixes(self):
        # Keys use "A01", "A02", ... without the :2025 suffix.
        for i in range(1, 11):
            key = f"A{i:02d}"
            assert key in dm.OWASP_TO_ARCH

    def test_values_are_domain_index_lists(self):
        max_idx = len(dm.ARCH_DOMAINS) - 1
        for key, indices in dm.OWASP_TO_ARCH.items():
            assert isinstance(indices, list)
            for idx in indices:
                assert 0 <= idx <= max_idx


# ===========================================================================
# 14. map_architecture
# ===========================================================================


class TestMapArchitecture(unittest.TestCase):
    def _f(self, check="", title="", message=""):
        return {"check": check, "title": title, "message": message}

    def test_empty_findings_returns_domain_shape(self):
        result = dm.map_architecture([])
        assert len(result) == len(dm.ARCH_DOMAINS)
        for entry in result:
            assert entry["fail_count"] == 0
            assert entry["findings"] == []
            assert "links" in entry
            assert "name" in entry and "icon" in entry

    def test_mfa_finding_hits_identity_and_access(self):
        f = self._f(check="mfa_disabled", title="", message="")
        result = dm.map_architecture([f])
        iam = next(d for d in result if d["name"] == "Identity & Access")
        assert iam["fail_count"] == 1
        assert iam["findings"] == [f]

    def test_findings_capped_at_ten(self):
        findings = [self._f(check="tls_bad", title=f"t{i}") for i in range(15)]
        result = dm.map_architecture(findings)
        net = next(d for d in result if d["name"] == "Network & TLS")
        assert net["fail_count"] == 15
        assert len(net["findings"]) == 10

    def test_non_matching_finding_not_placed(self):
        f = self._f(check="zzz_nothing", title="", message="")
        result = dm.map_architecture([f])
        for entry in result:
            assert f not in entry["findings"]

    def test_links_attached_per_index(self):
        result = dm.map_architecture([])
        for i, entry in enumerate(result):
            if i < len(dm.ARCH_DOMAIN_LINKS):
                assert entry["links"] == dm.ARCH_DOMAIN_LINKS[i]
            else:
                assert entry["links"] == {
                    "owasp": [],
                    "compliance": [],
                    "scanner": [],
                }


# ===========================================================================
# 15. CATEGORY_META
# ===========================================================================


class TestCategoryMeta(unittest.TestCase):
    def test_is_non_empty_dict(self):
        assert isinstance(dm.CATEGORY_META, dict)
        assert len(dm.CATEGORY_META) > 5

    def test_each_entry_has_icon_label_desc(self):
        for key, meta in dm.CATEGORY_META.items():
            assert isinstance(key, str) and key
            for required in ("icon", "label", "desc"):
                assert required in meta, f"{key}: missing {required}"
                assert isinstance(meta[required], str)
                assert meta[required]

    def test_expected_categories_present(self):
        for cat in (
            "access-control",
            "infra",
            "network",
            "cicd",
            "code",
            "cloud",
            "other",
        ):
            assert cat in dm.CATEGORY_META


# ===========================================================================
# 16. __all__ exports
# ===========================================================================


class TestAllExports(unittest.TestCase):
    def test_all_exports_resolve(self):
        for name in dm.__all__:
            assert hasattr(dm, name), f"Missing export: {name}"


# ===========================================================================
# 17. Fallback branch (inline definitions when compliance-map.py import fails)
# ===========================================================================


class TestFallbackBranch(unittest.TestCase):
    """Exercise the inline fallback definitions at lines 603-605, 608, 931-976.

    When compliance-map.py cannot be imported, dashboard_mapping defines
    COMPLIANCE_CONTROL_MAP, _match_prowler_compliance, and map_compliance
    inline. These tests reload the module with the external import forced to
    fail so the fallback code runs.
    """

    @classmethod
    def setUpClass(cls):
        cls.fb = _reload_with_fallback()

    @classmethod
    def tearDownClass(cls):
        # Restore the canonical module for any later tests in the same run.
        if "dashboard_mapping" in sys.modules:
            del sys.modules["dashboard_mapping"]
        importlib.import_module("dashboard_mapping")

    def test_fallback_compliance_control_map_populated(self):
        assert isinstance(self.fb.COMPLIANCE_CONTROL_MAP, dict)
        # Inline fallback covers ISO, ISMS-P, PCI-DSS, NIST, CIS.
        for fw in (
            "ISO 27001:2022",
            "KISA ISMS-P",
            "PCI-DSS v4.0.1",
            "NIST 800-53 Rev5",
            "CIS Benchmarks",
        ):
            assert fw in self.fb.COMPLIANCE_CONTROL_MAP

    def test_fallback_match_prowler_compliance_key_hit(self):
        finding = {"compliance": {"ISO 27001": ["A.8.2"]}}
        assert self.fb._match_prowler_compliance(finding, "iso 27001") is True

    def test_fallback_match_prowler_compliance_value_list_hit(self):
        finding = {"compliance": {"framework": ["PCI-DSS v4.0.1"]}}
        assert self.fb._match_prowler_compliance(finding, "pci-dss") is True

    def test_fallback_match_prowler_compliance_value_string_hit(self):
        finding = {"compliance": {"framework": "NIST"}}
        assert self.fb._match_prowler_compliance(finding, "nist") is True

    def test_fallback_match_prowler_compliance_empty(self):
        assert self.fb._match_prowler_compliance({}, "ISO") is False
        assert (
            self.fb._match_prowler_compliance({"compliance": {}}, "ISO") is False
        )

    def test_fallback_match_prowler_compliance_miss(self):
        finding = {"compliance": {"other": ["SOC2"]}}
        assert self.fb._match_prowler_compliance(finding, "HIPAA") is False

    def test_fallback_map_compliance_empty_all_pass(self):
        result = self.fb.map_compliance([])
        for controls in result.values():
            for ctrl in controls:
                assert ctrl["status"] == "PASS"
                assert ctrl["count"] == 0
                assert ctrl["findings"] == []

    def test_fallback_map_compliance_keyword_fail(self):
        f = {"check": "mfa", "title": "missing", "message": ""}
        result = self.fb.map_compliance([f])
        iso = result["ISO 27001:2022"]
        a85 = next(c for c in iso if c["control"] == "A.8.5")
        assert a85["status"] == "FAIL"
        assert a85["count"] == 1

    def test_fallback_map_compliance_findings_capped_at_five(self):
        findings = [
            {"check": "encrypt", "title": f"t{i}", "message": ""} for i in range(7)
        ]
        result = self.fb.map_compliance(findings)
        iso = result["ISO 27001:2022"]
        a824 = next(c for c in iso if c["control"] == "A.8.24")
        assert a824["count"] == 7
        assert len(a824["findings"]) == 5

    def test_fallback_map_compliance_native_fallback(self):
        f = {
            "check": "unrelated",
            "title": "unrelated",
            "message": "unrelated",
            "compliance": {"ISO 27001:2022": ["A.8.5"]},
        }
        result = self.fb.map_compliance([f])
        # Native compliance reference fires on every ISO control.
        for ctrl in result["ISO 27001:2022"]:
            assert ctrl["status"] == "FAIL"


if __name__ == "__main__":
    unittest.main()
