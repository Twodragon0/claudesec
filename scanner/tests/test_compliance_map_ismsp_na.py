"""
Focused tests for the ISMS-P 3.x PII/privacy "N/A" pilot.

Background
----------
The 11 ISMS-P 3.x controls (개인정보 처리단계별 요구사항: consent, privacy policy,
data-subject rights, pseudonymization, cross-border transfer, third-party
sharing, deletion/retention) are governance/legal controls that a technical
scanner cannot assess. Rendering them as PASS whenever no keyword/native
finding happens to match (the pre-existing `count==0 -> PASS` default) is a
false compliance assurance. They are tagged `"assessable": False` in
`COMPLIANCE_CONTROL_MAP["KISA ISMS-P"]` and `map_compliance()` always reports
their status as `"N/A"`, excluded from the pass/fail totals computed by
`compliance_summary()`.

This is a PILOT scoped to ISMS-P 3.x only — no other framework's controls are
tagged non-assessable.

stdlib-only (importlib to load the hyphenated `compliance-map.py` module, same
approach as `test_compliance_map.py`). No network, no on-disk fixtures.
"""

import importlib.util
import os
import unittest

_spec = importlib.util.spec_from_file_location(
    "compliance_map_ismsp_na",
    os.path.join(os.path.dirname(__file__), "..", "lib", "compliance-map.py"),
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP
map_compliance = _mod.map_compliance
compliance_summary = _mod.compliance_summary

ISMSP_PII_CONTROL_IDS = {
    "3.1.1", "3.1.3", "3.1.4", "3.2.1", "3.2.5",
    "3.3.1", "3.3.4", "3.4.1", "3.5.1", "3.5.2", "3.5.3",
}


def _make_finding(check="chk", title="", message=""):
    return {"check": check, "title": title, "message": message}


class TestIsmspPiiControlsTagged(unittest.TestCase):
    """The 11 ISMS-P 3.x PII controls are tagged assessable=False; no others are."""

    def test_exactly_eleven_controls_are_non_assessable(self):
        ismsp = COMPLIANCE_CONTROL_MAP["KISA ISMS-P"]
        non_assessable_ids = {c["control"] for c in ismsp if not c.get("assessable", True)}
        self.assertEqual(non_assessable_ids, ISMSP_PII_CONTROL_IDS)
        self.assertEqual(len(non_assessable_ids), 11)

    def test_no_other_framework_has_non_assessable_controls(self):
        for fw, controls in COMPLIANCE_CONTROL_MAP.items():
            if fw == "KISA ISMS-P":
                continue
            with self.subTest(framework=fw):
                for ctrl in controls:
                    self.assertTrue(
                        ctrl.get("assessable", True),
                        f"{fw}/{ctrl['control']} unexpectedly tagged non-assessable "
                        "— this pilot is scoped to ISMS-P 3.x only.",
                    )


class TestMapComplianceNaStatus(unittest.TestCase):
    """map_compliance() always reports N/A for non-assessable controls."""

    def test_all_eleven_ismsp_pii_controls_are_na_with_no_findings(self):
        result = map_compliance([])
        ismsp = {c["control"]: c for c in result["KISA ISMS-P"]}
        for control_id in ISMSP_PII_CONTROL_IDS:
            with self.subTest(control=control_id):
                self.assertEqual(ismsp[control_id]["status"], "N/A")

    def test_assessable_control_never_reports_na(self):
        result = map_compliance([])
        for fw, controls in result.items():
            for ctrl in controls:
                if ctrl.get("assessable", True):
                    with self.subTest(framework=fw, control=ctrl["control"]):
                        self.assertNotEqual(ctrl["status"], "N/A")

    def test_matching_keyword_does_not_flip_na_control_to_fail(self):
        """A finding whose text contains an N/A control's own keyword must not
        move it out of N/A — it stays N/A but the match is still recorded
        (count/findings) as an informational signal for human review."""
        # "3.1.1" checks include "consent"; craft a finding containing it.
        finding = _make_finding(
            check="consent_missing",
            title="Consent not recorded",
            message="No consent on file for this user",
        )
        result = map_compliance([finding])
        ismsp = {c["control"]: c for c in result["KISA ISMS-P"]}
        ctrl = ismsp["3.1.1"]
        self.assertEqual(ctrl["status"], "N/A")
        self.assertGreaterEqual(ctrl["count"], 1)
        self.assertTrue(len(ctrl["findings"]) >= 1)

    def test_all_eleven_ismsp_pii_controls_stay_na_even_with_matching_findings(self):
        """Cross-check across all 11 controls: each one's own first keyword,
        when present in a finding's text, still yields N/A (not FAIL)."""
        ismsp_controls = {c["control"]: c for c in COMPLIANCE_CONTROL_MAP["KISA ISMS-P"]}
        for control_id in ISMSP_PII_CONTROL_IDS:
            keyword = ismsp_controls[control_id]["checks"][0]
            finding = _make_finding(
                check="test_check",
                title=f"Finding containing {keyword}",
                message=f"This mentions {keyword} directly.",
            )
            result = map_compliance([finding])
            ctrl = {c["control"]: c for c in result["KISA ISMS-P"]}[control_id]
            with self.subTest(control=control_id, keyword=keyword):
                self.assertEqual(ctrl["status"], "N/A")


class TestComplianceSummaryExcludesNa(unittest.TestCase):
    """compliance_summary() reports na=11 for KISA ISMS-P and excludes N/A
    controls from total (total = pass + fail)."""

    def test_ismsp_na_count_is_eleven(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        self.assertEqual(summary["KISA ISMS-P"]["na"], 11)

    def test_ismsp_total_excludes_na_controls(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        stats = summary["KISA ISMS-P"]
        self.assertEqual(stats["total"], stats["pass"] + stats["fail"])
        total_controls = len(COMPLIANCE_CONTROL_MAP["KISA ISMS-P"])
        self.assertEqual(stats["total"], total_controls - stats["na"])
        self.assertEqual(total_controls, 42)
        self.assertEqual(stats["total"], 31)

    def test_frameworks_without_na_controls_have_na_zero(self):
        cmap = map_compliance([])
        summary = compliance_summary(cmap)
        for fw in COMPLIANCE_CONTROL_MAP:
            if fw == "KISA ISMS-P":
                continue
            with self.subTest(framework=fw):
                self.assertEqual(summary[fw]["na"], 0)
                self.assertEqual(summary[fw]["total"], len(COMPLIANCE_CONTROL_MAP[fw]))


class TestAssessableControlRegression(unittest.TestCase):
    """Regression: an assessable control still behaves PASS/FAIL as before."""

    def test_assessable_control_with_match_is_fail(self):
        finding = _make_finding(check="mfa_disabled", title="MFA not enabled", message="User lacks MFA")
        result = map_compliance([finding])
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertEqual(iso["A.8.5"]["status"], "FAIL")

    def test_assessable_control_without_match_is_pass(self):
        finding = _make_finding(check="random_check", title="Unrelated", message="Nothing special")
        result = map_compliance([finding])
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertEqual(iso["A.5.1"]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
