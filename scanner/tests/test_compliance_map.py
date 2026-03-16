"""Unit tests for scanner/lib/compliance-map.py standalone module."""

import importlib.util
import os
import unittest

# Load compliance-map.py via importlib (hyphen in filename)
_spec = importlib.util.spec_from_file_location(
    "compliance_map",
    os.path.join(os.path.dirname(__file__), "..", "lib", "compliance-map.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP
map_compliance = _mod.map_compliance
compliance_summary = _mod.compliance_summary
_match_prowler_compliance = _mod._match_prowler_compliance


def _make_finding(check="chk", title="", message="", compliance=None):
    """Helper to build a minimal finding dict."""
    f = {"check": check, "title": title, "message": message}
    if compliance is not None:
        f["compliance"] = compliance
    return f


class TestComplianceControlMap(unittest.TestCase):
    """Verify the structure of the compliance control map."""

    def test_has_five_frameworks(self):
        self.assertEqual(len(COMPLIANCE_CONTROL_MAP), 5)

    def test_expected_framework_names(self):
        expected = {
            "ISO 27001:2022",
            "KISA ISMS-P",
            "PCI-DSS v4.0.1",
            "NIST 800-53 Rev5",
            "CIS Benchmarks",
        }
        self.assertEqual(set(COMPLIANCE_CONTROL_MAP.keys()), expected)

    def test_each_control_has_required_fields(self):
        required = {"control", "name", "desc", "action", "checks", "status"}
        for fw, controls in COMPLIANCE_CONTROL_MAP.items():
            for ctrl in controls:
                with self.subTest(framework=fw, control=ctrl["control"]):
                    self.assertTrue(
                        required.issubset(ctrl.keys()),
                        f"Missing fields in {fw}/{ctrl['control']}",
                    )
                    self.assertIsInstance(ctrl["checks"], list)
                    self.assertGreater(len(ctrl["checks"]), 0)

    def test_control_counts_per_framework(self):
        counts = {fw: len(ctrls) for fw, ctrls in COMPLIANCE_CONTROL_MAP.items()}
        self.assertEqual(counts["ISO 27001:2022"], 7)
        self.assertEqual(counts["KISA ISMS-P"], 6)
        self.assertEqual(counts["PCI-DSS v4.0.1"], 7)
        self.assertEqual(counts["NIST 800-53 Rev5"], 10)
        self.assertEqual(counts["CIS Benchmarks"], 8)


class TestMatchProwlerCompliance(unittest.TestCase):
    """Test _match_prowler_compliance helper."""

    def test_no_compliance_field(self):
        finding = {"check": "x", "title": "t", "message": "m"}
        self.assertFalse(_match_prowler_compliance(finding, "ISO 27001:2022"))

    def test_empty_compliance(self):
        finding = {"compliance": {}}
        self.assertFalse(_match_prowler_compliance(finding, "NIST"))

    def test_key_match_exact_substring(self):
        # Key must be a substring of framework_key or vice versa (case-insensitive)
        finding = {"compliance": {"nist 800-53": ["AC-2"]}}
        self.assertTrue(_match_prowler_compliance(finding, "NIST 800-53 Rev5"))

    def test_key_no_match_due_to_format(self):
        # "NIST-800-53" (hyphenated) != "nist 800-53 rev5" (spaces) — no substring match
        finding = {"compliance": {"NIST-800-53": ["AC-2"]}}
        self.assertFalse(_match_prowler_compliance(finding, "NIST 800-53 Rev5"))

    def test_value_match(self):
        finding = {"compliance": {"framework": ["ISO 27001:2022 A.8.2"]}}
        self.assertTrue(_match_prowler_compliance(finding, "ISO 27001:2022"))

    def test_value_string(self):
        finding = {"compliance": {"std": "pci-dss v4.0.1 req 6"}}
        self.assertTrue(_match_prowler_compliance(finding, "PCI-DSS v4.0.1"))

    def test_no_match(self):
        finding = {"compliance": {"SOC2": ["CC6.1"]}}
        self.assertFalse(_match_prowler_compliance(finding, "ISO 27001:2022"))


class TestMapCompliance(unittest.TestCase):
    """Test map_compliance with various finding sets."""

    def test_empty_findings_all_pass(self):
        result = map_compliance([])
        for fw, controls in result.items():
            for ctrl in controls:
                with self.subTest(framework=fw, control=ctrl["control"]):
                    self.assertEqual(ctrl["status"], "PASS")
                    self.assertEqual(ctrl["count"], 0)
                    self.assertEqual(ctrl["findings"], [])

    def test_keyword_match_triggers_fail(self):
        findings = [_make_finding(check="mfa_disabled", title="MFA not enabled", message="User lacks MFA")]
        result = map_compliance(findings)
        # ISO A.8.5 checks for "mfa" keyword -> should FAIL
        iso_controls = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertEqual(iso_controls["A.8.5"]["status"], "FAIL")
        self.assertGreaterEqual(iso_controls["A.8.5"]["count"], 1)

    def test_unrelated_finding_does_not_trigger(self):
        findings = [_make_finding(check="random_check", title="Unrelated", message="Nothing special")]
        result = map_compliance(findings)
        iso_controls = {c["control"]: c for c in result["ISO 27001:2022"]}
        # A.5.1 checks for "security_policy" — no match
        self.assertEqual(iso_controls["A.5.1"]["status"], "PASS")

    def test_native_compliance_match(self):
        findings = [
            _make_finding(
                check="some_check",
                title="Some title",
                message="Some message",
                compliance={"CIS Benchmarks": ["CIS-1.1"]},
            )
        ]
        result = map_compliance(findings)
        cis_controls = {c["control"]: c for c in result["CIS Benchmarks"]}
        # Native compliance key "CIS Benchmarks" matches framework key exactly
        self.assertEqual(cis_controls["CIS-1.1"]["status"], "FAIL")

    def test_native_compliance_no_match_hyphenated_key(self):
        """Hyphenated key 'CIS-Benchmark' does not substring-match 'CIS Benchmarks'."""
        findings = [
            _make_finding(
                check="some_check",
                title="Some title",
                message="Some message",
                compliance={"CIS-Benchmark": ["CIS-1.1"]},
            )
        ]
        result = map_compliance(findings)
        cis_controls = {c["control"]: c for c in result["CIS Benchmarks"]}
        self.assertEqual(cis_controls["CIS-1.1"]["status"], "PASS")

    def test_findings_capped_at_five(self):
        findings = [_make_finding(check="mfa_issue", title=f"MFA #{i}", message="mfa") for i in range(10)]
        result = map_compliance(findings)
        iso_controls = {c["control"]: c for c in result["ISO 27001:2022"]}
        ctrl = iso_controls["A.8.5"]
        self.assertEqual(ctrl["count"], 10)
        self.assertEqual(len(ctrl["findings"]), 5)

    def test_multiple_frameworks_affected(self):
        findings = [_make_finding(check="tls_weak", title="TLS 1.0 in use", message="Weak tls detected")]
        result = map_compliance(findings)
        # TLS keyword should hit ISO A.8.24, KISA 2.7.1, PCI Req 1, NIST SC-8, CIS-8.1
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        pci = {c["control"]: c for c in result["PCI-DSS v4.0.1"]}
        nist = {c["control"]: c for c in result["NIST 800-53 Rev5"]}
        self.assertEqual(iso["A.8.24"]["status"], "FAIL")
        self.assertEqual(pci["Req 1"]["status"], "FAIL")
        self.assertEqual(nist["SC-8"]["status"], "FAIL")

    def test_result_preserves_control_metadata(self):
        result = map_compliance([])
        ctrl = result["ISO 27001:2022"][0]
        self.assertIn("control", ctrl)
        self.assertIn("name", ctrl)
        self.assertIn("desc", ctrl)
        self.assertIn("action", ctrl)
        self.assertIn("checks", ctrl)
        self.assertIn("status", ctrl)
        self.assertIn("count", ctrl)
        self.assertIn("findings", ctrl)


class TestComplianceSummary(unittest.TestCase):
    """Test compliance_summary aggregation."""

    def test_all_pass(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        for fw, stats in summary.items():
            with self.subTest(framework=fw):
                self.assertEqual(stats["fail"], 0)
                self.assertEqual(stats["pass"], stats["total"])
                self.assertGreater(stats["total"], 0)

    def test_mixed_pass_fail(self):
        findings = [_make_finding(check="mfa_off", title="MFA disabled", message="No MFA")]
        cmap = map_compliance(findings)
        summary = compliance_summary(cmap)
        # At least one framework should have failures
        any_fail = any(s["fail"] > 0 for s in summary.values())
        self.assertTrue(any_fail)

    def test_summary_totals_match_controls(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        for fw in COMPLIANCE_CONTROL_MAP:
            expected_total = len(COMPLIANCE_CONTROL_MAP[fw])
            self.assertEqual(summary[fw]["total"], expected_total)
            self.assertEqual(summary[fw]["pass"] + summary[fw]["fail"], expected_total)

    def test_summary_keys_match_frameworks(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        self.assertEqual(set(summary.keys()), set(COMPLIANCE_CONTROL_MAP.keys()))


if __name__ == "__main__":
    unittest.main()
