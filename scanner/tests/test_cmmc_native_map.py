"""
Tests for the CMMC 2.0 Level 2 framework and its `native_only` contract.

WHY CMMC IS DIFFERENT FROM THE OTHER SEVEN FRAMEWORKS
-----------------------------------------------------
Every other framework in `COMPLIANCE_CONTROL_MAP` carries a keyword list and
falls back to substring matching when Prowler ships no mapping. CMMC carries
none, on measurement: a prototype keyword set built from the vocabulary of the
target checks themselves reached 34.2% coverage (CM 1/22, SI 1/13). Keywords
here would manufacture wrong answers rather than approximate right ones, so the
controls are tagged `native_only` and report N/A — never PASS — when Prowler's
`nist_800_171_revision_2_*.json` is unavailable.

The three properties pinned below are the ones that make that safe:

1. **The id normalizer maps to the right family.** Prowler writes 800-171 ids
   with underscores (`3_13_5`), and a non-greedy family read would file every
   `3_1x_*` requirement under family 1 (AC) instead of 13 (SC) / 14 (SI) — real
   checks attached to the wrong domain, silently.
2. **Absence is N/A, not PASS.** The `count == 0 -> PASS` default is a false
   compliance assurance for a control that was never evaluated.
3. **Presence flips it back.** With a mapping loaded the domain scores
   PASS/FAIL by exact check-id membership, like every other native control.

Hermetic: fixtures are written to a tmpdir and pointed at with
`CLAUDESEC_PROWLER_COMPLIANCE_DIR`. Prowler is not required, in CI or locally.

Reference: CMMC 2.0 Level 2 practices are NIST SP 800-171 Rev. 2 requirements
(32 CFR Part 170); domains correspond to requirement families 3.1–3.14.
"""

import importlib.util
import json
import os
import tempfile
import unittest

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")

FRAMEWORK = "CMMC 2.0 Level 2"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_LIB, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pnm = _load("prowler_native_map_cmmc", "prowler_native_map.py")


def _write_fixture(root, provider, filename, requirements):
    d = os.path.join(root, provider)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
        json.dump({"Requirements": requirements}, fh)


class TestCmmcDomainNormalizer(unittest.TestCase):
    def test_underscore_ids_map_to_their_family_domain(self):
        for raw, want in (
            ("3_1_1", "AC"),
            ("3_3_8", "AU"),
            ("3_4_6", "CM"),
            ("3_5_10", "IA"),
            ("3_6_2", "IR"),
            ("3_11_3", "RA"),
            ("3_12_4", "CA"),
            ("3_13_16", "SC"),
            ("3_14_7", "SI"),
        ):
            self.assertEqual(pnm._cmmc_domain(raw), want, raw)

    def test_two_digit_family_is_not_read_as_family_one(self):
        """The bug this exists for: `3_13_5` filed under AC instead of SC would
        attach 50 boundary-protection checks to Access Control."""
        self.assertEqual(pnm._cmmc_domain("3_13_5"), "SC")
        self.assertEqual(pnm._cmmc_domain("3_14_1"), "SI")
        self.assertEqual(pnm._cmmc_domain("3_10_1"), "PE")
        self.assertNotEqual(pnm._cmmc_domain("3_13_5"), pnm._cmmc_domain("3_1_5"))

    def test_dotted_form_is_accepted(self):
        """The standard prints `3.13.5`; Prowler writes `3_13_5`. Accepting both
        means a Prowler re-spelling degrades to nothing, not to silence."""
        self.assertEqual(pnm._cmmc_domain("3.13.5"), "SC")
        self.assertEqual(pnm._cmmc_domain("3.1.1"), "AC")

    def test_unparseable_or_unknown_family_returns_none(self):
        # None omits the requirement; a guess would attach checks to a wrong
        # domain, which is worse than having no opinion.
        for bad in ("", "governance", "3_1", "3_99_1", "4_1_1", "x_1_1"):
            self.assertIsNone(pnm._cmmc_domain(bad), bad)

    def test_domain_table_covers_families_3_1_through_3_14(self):
        self.assertEqual(
            set(pnm.CMMC_DOMAINS), {f"3_{n}" for n in range(1, 15)}
        )
        self.assertEqual(len(set(pnm.CMMC_DOMAINS.values())), 14)


class TestCmmcSourceRegistration(unittest.TestCase):
    def test_framework_reads_the_800_171_file(self):
        pattern, normalize = pnm.FRAMEWORK_SOURCES[FRAMEWORK]
        self.assertEqual(pattern, "nist_800_171_revision_2_*.json")
        self.assertIs(normalize, pnm._cmmc_domain)

    def test_cis_stays_deliberately_absent(self):
        """Adding CIS needs a control-id remap first; regression pin so the
        CMMC addition is not read as permission to wire CIS in the same way."""
        self.assertNotIn("CIS Benchmarks", pnm.FRAMEWORK_SOURCES)


class TestCmmcLoader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        prev = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR")
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = self.root
        self.addCleanup(self._restore, prev)

    @staticmethod
    def _restore(prev):
        if prev is None:
            os.environ.pop("CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        else:
            os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = prev

    def test_requirements_collapse_into_domain_unions(self):
        _write_fixture(
            self.root,
            "aws",
            "nist_800_171_revision_2_aws.json",
            [
                {"Id": "3_1_1", "Checks": ["iam_a"]},
                {"Id": "3_1_2", "Checks": ["iam_b"]},
                {"Id": "3_13_1", "Checks": ["vpc_a"]},
            ],
        )
        native = pnm.load_framework(FRAMEWORK)
        self.assertEqual(native["AC"], frozenset({"iam_a", "iam_b"}))
        self.assertEqual(native["SC"], frozenset({"vpc_a"}))

    def test_families_without_checks_are_absent_not_empty(self):
        _write_fixture(
            self.root,
            "aws",
            "nist_800_171_revision_2_aws.json",
            [
                {"Id": "3_2_1", "Checks": []},
                {"Id": "3_7_1"},
                {"Id": "3_1_1", "Checks": ["iam_a"]},
            ],
        )
        native = pnm.load_framework(FRAMEWORK)
        self.assertEqual(sorted(native), ["AC"])
        self.assertNotIn("AT", native)
        self.assertNotIn("MA", native)

    def test_other_frameworks_do_not_pick_up_the_800_171_file(self):
        """`nist_800_53_revision_5_*.json` and `nist_800_171_revision_2_*.json`
        share a prefix; the 800-53 glob must not swallow the 171 file."""
        _write_fixture(
            self.root,
            "aws",
            "nist_800_171_revision_2_aws.json",
            [{"Id": "3_1_1", "Checks": ["iam_a"]}],
        )
        self.assertEqual(pnm.load_framework("NIST 800-53 Rev5"), {})
        self.assertEqual(pnm.load_framework(FRAMEWORK)["AC"], frozenset({"iam_a"}))


class TestCmmcControlMapShape(unittest.TestCase):
    def setUp(self):
        self.cm = _load("compliance_map_cmmc_shape", "compliance-map.py")

    def test_controls_are_exactly_the_fourteen_domains(self):
        controls = self.cm.COMPLIANCE_CONTROL_MAP[FRAMEWORK]
        self.assertEqual(
            {c["control"] for c in controls}, set(pnm.CMMC_DOMAINS.values())
        )
        self.assertEqual(len(controls), 14)

    def test_every_control_is_native_only_with_no_keywords(self):
        for ctrl in self.cm.COMPLIANCE_CONTROL_MAP[FRAMEWORK]:
            with self.subTest(control=ctrl["control"]):
                self.assertTrue(ctrl.get("native_only"))
                self.assertEqual(ctrl["checks"], [])

    def test_no_control_is_declared_non_assessable(self):
        """CMMC's N/A is conditional on Prowler's data, not declared — tagging a
        domain `assessable: False` would freeze it N/A even once mapped."""
        for ctrl in self.cm.COMPLIANCE_CONTROL_MAP[FRAMEWORK]:
            self.assertTrue(ctrl.get("assessable", True), ctrl["control"])


class TestCmmcWithoutProwlerMapping(unittest.TestCase):
    """Property 2: absence is N/A, not PASS."""

    def setUp(self):
        prev = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR")
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = os.path.join(
            os.path.dirname(__file__), "no-such-prowler-compliance-dir"
        )
        self.addCleanup(TestCmmcLoader._restore, prev)
        self.cm = _load("compliance_map_cmmc_absent", "compliance-map.py")
        self.cm._native_mapping()

    def _cmmc(self, findings):
        return {c["control"]: c for c in self.cm.map_compliance(findings)[FRAMEWORK]}

    def test_every_domain_is_na_and_marked_unmapped(self):
        for control, ctrl in self._cmmc([]).items():
            with self.subTest(control=control):
                self.assertEqual(ctrl["status"], "N/A")
                self.assertEqual(ctrl["match_source"], "unmapped")

    def test_a_finding_full_of_domain_vocabulary_still_does_not_score(self):
        """The keyword path is not merely empty for CMMC, it is not taken. A
        finding whose text is saturated with access-control language must not
        flip AC to FAIL, because nothing authorised that association."""
        finding = {
            "check": "iam_policy_allows_privilege_escalation",
            "title": "Access control failure: IAM policy grants admin",
            "message": "access control audit logging encryption incident media",
        }
        ctrl = self._cmmc([finding])["AC"]
        self.assertEqual(ctrl["status"], "N/A")
        self.assertEqual(ctrl["count"], 0)

    def test_summary_scores_nothing_rather_than_scoring_a_perfect_pass(self):
        summary = self.cm.compliance_summary(self.cm.map_compliance([]))[FRAMEWORK]
        self.assertEqual(summary["na"], 14)
        self.assertEqual(summary["pass"], 0)
        self.assertEqual(summary["fail"], 0)
        self.assertEqual(summary["total"], 0)


class TestCmmcWithProwlerMapping(unittest.TestCase):
    """Property 3: presence flips the domain back to exact scoring."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        prev = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR")
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = self._tmp.name
        self.addCleanup(TestCmmcLoader._restore, prev)
        _write_fixture(
            self._tmp.name,
            "aws",
            "nist_800_171_revision_2_aws.json",
            [
                {"Id": "3_1_1", "Checks": ["iam_root_mfa_enabled"]},
                {"Id": "3_13_1", "Checks": ["ec2_securitygroup_default_restrict"]},
            ],
        )
        self.cm = _load("compliance_map_cmmc_present", "compliance-map.py")

    def _cmmc(self, findings):
        # `provider: aws` throughout: 800-171 is an AWS-only source, so a
        # finding from anywhere else cannot evidence it (TestCmmcProviderScope).
        return {
            c["control"]: c
            for c in self.cm.map_compliance(findings, scanned_providers={"aws"})[
                FRAMEWORK
            ]
        }

    def test_mapped_domain_fails_on_exact_check_id(self):
        finding = {
            "check": "iam_root_mfa_enabled",
            "title": "",
            "message": "",
            "provider": "aws",
        }
        ctrl = self._cmmc([finding])["AC"]
        self.assertEqual(ctrl["status"], "FAIL")
        self.assertEqual(ctrl["match_source"], "prowler")
        self.assertEqual(ctrl["count"], 1)

    def test_mapped_domain_passes_when_its_checks_are_clean(self):
        finding = {
            "check": "some_unrelated_check",
            "title": "",
            "message": "",
            "provider": "aws",
        }
        ctrl = self._cmmc([finding])["AC"]
        self.assertEqual(ctrl["status"], "PASS")
        self.assertEqual(ctrl["match_source"], "prowler")

    def test_matching_is_by_check_id_only_not_by_text(self):
        finding = {
            "check": "unrelated",
            "title": "iam_root_mfa_enabled",
            "message": "iam_root_mfa_enabled",
            "provider": "aws",
        }
        self.assertEqual(self._cmmc([finding])["AC"]["status"], "PASS")

    def test_unmapped_domains_stay_na_alongside_mapped_ones(self):
        """Partial coverage must not promote the rest of the framework: with
        only AC and SC mapped, the other 12 domains remain N/A."""
        controls = self._cmmc([])
        self.assertEqual(controls["AC"]["status"], "PASS")
        self.assertEqual(controls["SC"]["status"], "PASS")
        for domain in ("AT", "AU", "CA", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SI"):
            with self.subTest(control=domain):
                self.assertEqual(controls[domain]["status"], "N/A")
                self.assertEqual(controls[domain]["match_source"], "unmapped")


class TestCmmcProviderScope(unittest.TestCase):
    """The false-PASS this scope exists to stop.

    `load_framework()` reads the INSTALLED Prowler package, not the scan.
    Prowler ships 800-171 for AWS only, and the shipped image strips
    `prowler/providers/{azure,gcp,...}` while keeping `prowler/compliance/**` —
    so a Kubernetes scan carries a fully-populated AWS mapping that matches
    none of its findings. Without the provider scope all nine mapped domains
    take the `prowler` branch, match 0, and fall through to `count == 0 -> PASS`:
    a perfect CMMC score for an estate that produced no CMMC evidence.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        prev = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR")
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = self._tmp.name
        self.addCleanup(TestCmmcLoader._restore, prev)
        _write_fixture(
            self._tmp.name,
            "aws",
            "nist_800_171_revision_2_aws.json",
            [
                {"Id": "3_1_1", "Checks": ["iam_root_mfa_enabled"]},
                {"Id": "3_13_1", "Checks": ["ec2_securitygroup_default_restrict"]},
            ],
        )
        self.cm = _load("compliance_map_cmmc_scope", "compliance-map.py")

    def _cmmc(self, findings, providers=None):
        return {
            c["control"]: c
            for c in self.cm.map_compliance(findings, scanned_providers=providers)[
                FRAMEWORK
            ]
        }

    def test_scope_is_derived_from_the_file_that_supplied_the_mapping(self):
        """Derived, not declared: the fixture lives in `aws/`, so that is the
        scope. A hand-written constant would have to be kept in step with every
        Prowler release."""
        self.assertEqual(pnm.framework_providers(FRAMEWORK), frozenset({"aws"}))
        self.assertEqual(pnm.framework_providers(FRAMEWORK), frozenset({"aws"}))

    def test_kubernetes_only_run_reports_na_not_a_perfect_score(self):
        findings = [
            {
                "check": "core_minimize_admission_privileged_containers",
                "title": "t",
                "message": "m",
                "provider": "kubernetes",
            }
        ]
        controls = self._cmmc(findings)
        for control, ctrl in controls.items():
            with self.subTest(control=control):
                self.assertEqual(ctrl["status"], "N/A")
                self.assertEqual(ctrl["match_source"], "unmapped")
        summary = self.cm.compliance_summary(self.cm.map_compliance(findings))[FRAMEWORK]
        self.assertEqual(summary, {"pass": 0, "fail": 0, "na": 14, "total": 0})

    def test_azure_only_run_is_equally_unevidenced(self):
        findings = [
            {"check": "aks_something", "title": "t", "message": "m", "provider": "azure"}
        ]
        self.assertEqual(self._cmmc(findings)["AC"]["status"], "N/A")

    def test_an_aws_run_still_scores(self):
        findings = [
            {
                "check": "iam_root_mfa_enabled",
                "title": "t",
                "message": "m",
                "provider": "aws",
            }
        ]
        controls = self._cmmc(findings)
        self.assertEqual(controls["AC"]["status"], "FAIL")
        self.assertEqual(controls["AC"]["match_source"], "prowler")

    def test_a_mixed_run_containing_aws_still_scores(self):
        findings = [
            {"check": "x", "title": "t", "message": "m", "provider": "kubernetes"},
            {
                "check": "iam_root_mfa_enabled",
                "title": "t",
                "message": "m",
                "provider": "aws",
            },
        ]
        self.assertEqual(self._cmmc(findings)["AC"]["status"], "FAIL")

    def test_explicit_provider_list_credits_a_clean_aws_scan(self):
        """A clean provider emits zero FAIL findings and so is invisible in the
        findings list. The caller knows better, and PASS is the right answer
        there — this is why `scanned_providers` exists as a parameter."""
        derived = self._cmmc([])
        self.assertEqual(derived["AC"]["status"], "N/A")
        explicit = self._cmmc([], providers={"aws"})
        self.assertEqual(explicit["AC"]["status"], "PASS")
        self.assertEqual(explicit["AC"]["match_source"], "prowler")

    def test_explicit_non_aws_provider_list_does_not_credit_the_framework(self):
        controls = self._cmmc([], providers={"kubernetes", "gcp"})
        self.assertEqual(controls["AC"]["status"], "N/A")
        self.assertEqual(controls["SC"]["status"], "N/A")

    def test_a_framework_with_no_file_at_all_is_not_gated(self):
        """Only frameworks that HAVE a native file get a scope. One running
        purely on keywords must not be gated into silence by an empty set."""
        self.assertEqual(set(pnm.native_control_providers()), {FRAMEWORK})
        result = self.cm.map_compliance(
            [{"check": "x", "title": "t", "message": "m", "provider": "kubernetes"}]
        )
        iso = {c["control"]: c for c in result["ISO 27001:2022"]}
        self.assertNotEqual(iso["A.8.9"]["status"], "N/A")
        self.assertEqual(iso["A.8.9"]["match_source"], "keyword")


class TestCmmcIsRendered(unittest.TestCase):
    """The framework has to reach the dashboard, with its coverage limit stated."""

    def setUp(self):
        import sys

        if _LIB not in sys.path:
            sys.path.insert(0, os.path.abspath(_LIB))

    def test_compliance_html_renders_the_framework_and_its_domains(self):
        from dashboard_html_compliance import _build_compliance_html

        cmap = {
            FRAMEWORK: [
                {
                    "control": "AC",
                    "name": "Access Control (800-171 §3.1)",
                    "desc": "d",
                    "action": "a",
                    "checks": [],
                    "native_only": True,
                    "status": "N/A",
                    "count": 0,
                    "findings": [],
                    "match_source": "unmapped",
                }
            ]
        }
        html = _build_compliance_html(cmap)
        self.assertIn("CMMC 2.0 Level 2", html)
        self.assertIn("Access Control (800-171 §3.1)", html)
        self.assertIn("N/A", html)

    def test_the_aws_only_coverage_limit_is_stated_in_the_output(self):
        """A limit that only lives in a source comment is one the dashboard's
        reader never sees."""
        from dashboard_html_compliance import COMP_FW_NOTES, _build_compliance_html

        self.assertIn(FRAMEWORK, COMP_FW_NOTES)
        self.assertIn("AWS only", COMP_FW_NOTES[FRAMEWORK])
        html = _build_compliance_html(
            {
                FRAMEWORK: [
                    {
                        "control": "AC",
                        "name": "n",
                        "desc": "d",
                        "action": "a",
                        "checks": [],
                        "status": "N/A",
                        "count": 0,
                        "findings": [],
                        "match_source": "unmapped",
                    }
                ]
            }
        )
        self.assertIn("comp-fw-note", html)
        self.assertIn("AWS only", html)

    def test_a_framework_without_a_note_renders_none(self):
        from dashboard_html_compliance import _build_compliance_html

        html = _build_compliance_html(
            {
                "ISO 27001:2022": [
                    {
                        "control": "A.8.5",
                        "name": "n",
                        "desc": "d",
                        "action": "a",
                        "checks": ["mfa"],
                        "status": "PASS",
                        "count": 0,
                        "findings": [],
                        "match_source": "keyword",
                    }
                ]
            }
        )
        self.assertNotIn("comp-fw-note", html)

    def test_the_note_style_exists_in_the_dashboard_template(self):
        with open(os.path.join(_LIB, "dashboard-template.html"), encoding="utf-8") as fh:
            self.assertIn(".comp-fw-note{", fh.read())

    def test_the_framework_chip_list_carries_cmmc(self):
        from dashboard_compliance import COMPLIANCE_FRAMEWORKS

        names = {f["name"] for f in COMPLIANCE_FRAMEWORKS}
        self.assertIn(FRAMEWORK, names)


if __name__ == "__main__":
    unittest.main()
