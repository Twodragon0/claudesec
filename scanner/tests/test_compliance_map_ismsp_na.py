"""
Tests for the framework-wide governance/legal/human "N/A" (non-assessable) set.

Background
----------
Governance, legal, and human-obligation controls have no automated NIST SP
800-53A *Test* method: a technical scanner cannot assess "management commitment",
"security-awareness training", a documented "information security policy", or the
processing of personal data. Rendering them PASS whenever no keyword/native
finding happens to match (the pre-existing `count==0 -> PASS` default) is a false
compliance assurance. Such controls are tagged `"assessable": False` in
`COMPLIANCE_CONTROL_MAP`; `map_compliance()` always reports their status as
`"N/A"`, excluded from the pass/fail totals computed by `compliance_summary()`.

This started as an ISMS-P 3.x PII/privacy pilot (#309) and now extends
framework-wide to governance/legal/human controls in the frameworks where the
gap actually exists: KISA ISMS-P (11 PII 3.x + management/policy/training),
KISA ISMS Simple (governance/policy + PII/legal), and ISO 27001:2022 (A.5.1).
NIST 800-53 stays fully assessable (CA-7 keeps genuine monitoring signal).

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

# The 11 original ISMS-P 3.x PII/privacy controls (the #309 pilot).
ISMSP_PII_CONTROL_IDS = {
    "3.1.1", "3.1.3", "3.1.4", "3.2.1", "3.2.5",
    "3.3.1", "3.3.4", "3.4.1", "3.5.1", "3.5.2", "3.5.3",
}

# Single source of truth: every non-assessable control per framework.
# Frameworks absent from this dict MUST have zero non-assessable controls.
EXPECTED_NON_ASSESSABLE = {
    # 11 PII 3.x controls + management commitment, policy management, awareness.
    "KISA ISMS-P": ISMSP_PII_CONTROL_IDS | {"1.1.1", "2.1.1", "2.2.4"},
    # governance/policy + PII/legal.
    "KISA ISMS Simple": {"S-1.1", "S-2.1", "S-3.1", "S-3.2", "S-3.3", "S-3.4"},
    # the sole Organizational-theme ISO control (all others are A.8 Technological).
    "ISO 27001:2022": {"A.5.1"},
}

# Keyword tokens that never appear in any scanner finding text (verified 0-emission
# across scanner/checks/**). A KISA control whose entire `checks` set is a subset
# of these can only ever render as a false-PASS, so it MUST be non-assessable.
NEVER_EMITTED_TOKENS = {
    "security_policy", "governance", "training", "awareness", "education",
    "deletion", "retention", "destroy", "lifecycle", "data_subject",
    "right_to_access", "right_to_delete", "portability",
}

# The two KISA frameworks have no native Prowler compliance path, so a pure
# never-matcher there is a permanent false-PASS (unlike native-path frameworks).
KISA_FRAMEWORKS = ("KISA ISMS-P", "KISA ISMS Simple")


def _make_finding(check="chk", title="", message=""):
    return {"check": check, "title": title, "message": message}


class TestNonAssessableControlsTagged(unittest.TestCase):
    """Every non-assessable control is exactly the EXPECTED_NON_ASSESSABLE set."""

    def test_ismsp_pii_pilot_controls_still_tagged(self):
        ismsp = COMPLIANCE_CONTROL_MAP["KISA ISMS-P"]
        non_assessable_ids = {c["control"] for c in ismsp if not c.get("assessable", True)}
        # The original 11 PII controls must remain tagged.
        self.assertTrue(ISMSP_PII_CONTROL_IDS.issubset(non_assessable_ids))

    def test_each_framework_non_assessable_set_matches_expected(self):
        for fw, controls in COMPLIANCE_CONTROL_MAP.items():
            with self.subTest(framework=fw):
                actual = {c["control"] for c in controls if not c.get("assessable", True)}
                self.assertEqual(
                    actual,
                    EXPECTED_NON_ASSESSABLE.get(fw, set()),
                    f"{fw} non-assessable set drifted from EXPECTED_NON_ASSESSABLE.",
                )

    def test_no_other_framework_has_non_assessable_controls(self):
        """Frameworks not in EXPECTED_NON_ASSESSABLE (NIST/CIS/PCI) must have none."""
        for fw, controls in COMPLIANCE_CONTROL_MAP.items():
            if fw in EXPECTED_NON_ASSESSABLE:
                continue
            with self.subTest(framework=fw):
                for ctrl in controls:
                    self.assertTrue(
                        ctrl.get("assessable", True),
                        f"{fw}/{ctrl['control']} unexpectedly tagged non-assessable "
                        "— it is not in EXPECTED_NON_ASSESSABLE.",
                    )

    def test_nist_ca7_stays_assessable(self):
        nist = {c["control"]: c for c in COMPLIANCE_CONTROL_MAP["NIST 800-53 Rev5"]}
        self.assertTrue(nist["CA-7"].get("assessable", True))


class TestSelectionCompleteness(unittest.TestCase):
    """Non-tautological guard: no assessable KISA control is a pure never-matcher.

    Any KISA control (no native Prowler path) whose entire `checks` set is a
    subset of the known 0-emission tokens can only render as a false-PASS. Such a
    control MUST be non-assessable — this catches a future governance/PII control
    silently re-introducing a false-PASS without touching EXPECTED_NON_ASSESSABLE.
    """

    def test_pure_never_matchers_in_kisa_are_non_assessable(self):
        for fw in KISA_FRAMEWORKS:
            for ctrl in COMPLIANCE_CONTROL_MAP[fw]:
                checks = set(ctrl["checks"])
                if checks and checks.issubset(NEVER_EMITTED_TOKENS):
                    with self.subTest(framework=fw, control=ctrl["control"]):
                        self.assertFalse(
                            ctrl.get("assessable", True),
                            f"{fw}/{ctrl['control']} is a pure never-matcher "
                            f"(checks {sorted(checks)} all 0-emission) but is still "
                            "assessable — it would render a permanent false-PASS.",
                        )


class TestMapComplianceNaStatus(unittest.TestCase):
    """map_compliance() always reports N/A for non-assessable controls."""

    def test_all_non_assessable_controls_are_na_with_no_findings(self):
        result = map_compliance([])
        for fw, ids in EXPECTED_NON_ASSESSABLE.items():
            controls = {c["control"]: c for c in result[fw]}
            for control_id in ids:
                with self.subTest(framework=fw, control=control_id):
                    self.assertEqual(controls[control_id]["status"], "N/A")

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

    def test_newly_tagged_governance_control_stays_na_with_matching_finding(self):
        """Extend the N/A-never-FAIL invariant to newly-tagged controls:
        ISMS-P 2.2.4 (training) and ISO A.5.1 (security_policy) each keep N/A
        even when a finding matches their own keyword."""
        # 2.2.4 checks include "training".
        f_training = _make_finding(
            check="training_gap",
            title="Security training overdue",
            message="Annual training not completed",
        )
        ismsp = {c["control"]: c for c in map_compliance([f_training])["KISA ISMS-P"]}
        self.assertEqual(ismsp["2.2.4"]["status"], "N/A")
        self.assertGreaterEqual(ismsp["2.2.4"]["count"], 1)

        # A.5.1 checks include "security_policy".
        f_policy = _make_finding(
            check="security_policy_missing",
            title="No security_policy documented",
            message="security_policy file absent",
        )
        iso = {c["control"]: c for c in map_compliance([f_policy])["ISO 27001:2022"]}
        self.assertEqual(iso["A.5.1"]["status"], "N/A")
        self.assertGreaterEqual(iso["A.5.1"]["count"], 1)

    def test_all_non_assessable_controls_stay_na_even_with_matching_findings(self):
        """Cross-check across every non-assessable control: each one's own first
        keyword, when present in a finding's text, still yields N/A (not FAIL)."""
        for fw, ids in EXPECTED_NON_ASSESSABLE.items():
            controls = {c["control"]: c for c in COMPLIANCE_CONTROL_MAP[fw]}
            for control_id in ids:
                keyword = controls[control_id]["checks"][0]
                finding = _make_finding(
                    check="test_check",
                    title=f"Finding containing {keyword}",
                    message=f"This mentions {keyword} directly.",
                )
                result = map_compliance([finding])
                ctrl = {c["control"]: c for c in result[fw]}[control_id]
                with self.subTest(framework=fw, control=control_id, keyword=keyword):
                    self.assertEqual(ctrl["status"], "N/A")


class TestComplianceSummaryExcludesNa(unittest.TestCase):
    """compliance_summary() counts the expected na per framework and excludes
    N/A controls from total (total = pass + fail)."""

    def test_na_counts_match_expected_per_framework(self):
        summary = compliance_summary(map_compliance([]))
        for fw in COMPLIANCE_CONTROL_MAP:
            with self.subTest(framework=fw):
                expected_na = len(EXPECTED_NON_ASSESSABLE.get(fw, set()))
                self.assertEqual(summary[fw]["na"], expected_na)

    def test_ismsp_total_excludes_na_controls(self):
        summary = compliance_summary(map_compliance([]))
        stats = summary["KISA ISMS-P"]
        self.assertEqual(stats["total"], stats["pass"] + stats["fail"])
        total_controls = len(COMPLIANCE_CONTROL_MAP["KISA ISMS-P"])
        self.assertEqual(stats["total"], total_controls - stats["na"])
        self.assertEqual(total_controls, 42)
        self.assertEqual(stats["na"], 14)
        self.assertEqual(stats["total"], 28)

    def test_totals_are_allowlist_aware_for_every_framework(self):
        summary = compliance_summary(map_compliance([]))
        for fw, controls in COMPLIANCE_CONTROL_MAP.items():
            with self.subTest(framework=fw):
                stats = summary[fw]
                expected_na = len(EXPECTED_NON_ASSESSABLE.get(fw, set()))
                self.assertEqual(stats["na"], expected_na)
                self.assertEqual(stats["total"], stats["pass"] + stats["fail"])
                self.assertEqual(stats["total"], len(controls) - expected_na)


class TestAssessableControlRegression(unittest.TestCase):
    """Regression: an assessable control still behaves PASS/FAIL as before."""

    def test_assessable_control_with_match_is_fail(self):
        finding = _make_finding(check="mfa_disabled", title="MFA not enabled", message="User lacks MFA")
        result = map_compliance([finding])
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertEqual(iso["A.8.5"]["status"], "FAIL")

    def test_assessable_control_without_match_is_pass(self):
        # A.5.1 now renders N/A, so assert on A.8.9 (checks
        # configuration/misconfigur/default — the fixture text matches none).
        finding = _make_finding(check="random_check", title="Unrelated", message="Nothing special")
        result = map_compliance([finding])
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertEqual(iso["A.8.9"]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
