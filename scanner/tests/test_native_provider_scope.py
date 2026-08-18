"""
Tests for the provider scope on Prowler's native compliance mapping.

THE FAILURE THIS EXISTS FOR
---------------------------
`load_framework()` reads the INSTALLED Prowler package, not the scan. Prowler
ships each framework for some providers and not others, so a mapping is
populated whenever Prowler is installed — including on a run that scanned none
of those providers. Every natively-mapped control then matches zero findings
and takes the `count == 0 -> PASS` default.

Measured on a Kubernetes-only scan against Prowler 5.30.1, with 62 real
Kubernetes check ids from Prowler's own `pci_4.0_kubernetes.json` and
`iso27001_2022_kubernetes.json` supplied as FAIL findings:

    framework            before (unscoped)      after (scoped)
    NIST 800-53 Rev5     10 pass /  0 fail      5 pass /  5 fail
    SOC 2 (TSC)           6 pass /  0 fail      3 pass /  3 fail
    KISA ISMS-P          20 pass /  7 fail      9 pass / 18 fail
    PCI-DSS v4.0.1        0 pass /  7 fail      unchanged (k8s file exists)
    ISO 27001:2022        3 pass /  3 fail      unchanged (ditto)

NIST 800-53 and SOC 2 were reporting a PERFECT score on an estate whose
evidence they had never been able to read. Prowler ships both for AWS only
(SOC 2 also azure and gcp — still not kubernetes). Five NIST failures, three
SOC 2 failures and eleven KISA failures were hidden.

WHY THE SCOPE IS DERIVED AND NOT DECLARED
------------------------------------------
#455 scoped CMMC with a hand-written `{framework: providers}` dict. The
measurement above is why that shape cannot hold: it was already wrong for three
more frameworks the moment it was written, and the correct answer differs per
Prowler version. The provider is the directory each file was loaded from —
already on disk, already walked by `load_framework()`.

Hermetic: fixtures are written to a tmpdir and pointed at with
`CLAUDESEC_PROWLER_COMPLIANCE_DIR`. Prowler is not required.
"""

import importlib.util
import json
import os
import tempfile
import unittest

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_LIB, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pnm = _load("prowler_native_map_scope", "prowler_native_map.py")


def _write_fixture(root, provider, filename, requirements):
    d = os.path.join(root, provider)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
        json.dump({"Requirements": requirements}, fh)


class _ScopedFixture(unittest.TestCase):
    """Base: a tmpdir compliance tree with the env override restored on exit."""

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


class TestScopeDerivation(_ScopedFixture):
    def test_scope_is_the_directory_the_file_came_from(self):
        _write_fixture(self.root, "aws", "nist_800_53_revision_5_aws.json",
                       [{"Id": "ac_2", "Checks": ["iam_a"]}])
        self.assertEqual(
            pnm.framework_providers("NIST 800-53 Rev5"), frozenset({"aws"})
        )

    def test_multi_provider_frameworks_collect_every_directory(self):
        for provider in ("aws", "azure", "gcp"):
            _write_fixture(self.root, provider, f"soc2_{provider}.json",
                           [{"Id": "cc_6_1", "Checks": [f"{provider}_check"]}])
        self.assertEqual(
            pnm.framework_providers("SOC 2 (TSC)"),
            frozenset({"aws", "azure", "gcp"}),
        )

    def test_a_framework_with_no_file_scopes_to_nothing(self):
        self.assertEqual(pnm.framework_providers("SOC 2 (TSC)"), frozenset())

    def test_an_unregistered_framework_scopes_to_nothing(self):
        self.assertEqual(pnm.framework_providers("Not A Framework"), frozenset())

    def test_scopes_omit_frameworks_with_no_file_rather_than_mapping_them_empty(self):
        """An empty set would read as "scoped to nothing" and gate a framework
        that has no native mapping to gate — silencing its keyword path."""
        _write_fixture(self.root, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["x"]}])
        scopes = pnm.native_control_providers()
        self.assertEqual(set(scopes), {"SOC 2 (TSC)"})
        self.assertNotIn("NIST 800-53 Rev5", scopes)

    def test_derivation_agrees_with_the_mapping_it_scopes(self):
        """A framework that loaded a mapping must have a non-empty scope, or the
        gate would close on evidence that does exist."""
        for provider in ("aws", "azure"):
            _write_fixture(self.root, provider, f"soc2_{provider}.json",
                           [{"Id": "cc_6_1", "Checks": [f"{provider}_check"]}])
        for framework in pnm.load_all():
            with self.subTest(framework=framework):
                self.assertTrue(pnm.framework_providers(framework))

    def test_a_file_that_contributes_nothing_does_not_widen_the_scope(self):
        """Existence is not contribution. A provider file that parses to no
        control must stay out of the scope, or the gate opens for a provider
        whose evidence can never match — the very PASS this closes."""
        _write_fixture(self.root, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["real_check"]}])
        # Every requirement checkless.
        _write_fixture(self.root, "azure", "soc2_azure.json",
                       [{"Id": "cc_6_2", "Checks": []}, {"Id": "cc_6_3"}])
        # Present but unparseable.
        d = os.path.join(self.root, "gcp")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "soc2_gcp.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(pnm.framework_providers("SOC 2 (TSC)"), frozenset({"aws"}))


class TestEveryFrameworkIsScoped(_ScopedFixture):
    """A single-framework fixture cannot catch a scope that skips frameworks.

    Measured defeat (2026-08-18): adding `if framework in ("PCI-DSS v4.0.1",
    "ISO 27001:2022", "KISA ISMS-P"): continue` to `native_control_providers()`
    left the whole suite at `2258 passed` while restoring KISA ISMS-P to
    20 pass / 7 fail on a Kubernetes-only run — re-hiding the eleven failures
    this change exists to expose. Every assertion here therefore runs against a
    tree holding files for ALL six registered frameworks at once.
    """

    # Provider layout of Prowler 5.30.1, verified against the tag. This is the
    # regression pin the doc table claims; a Prowler bump that moves a file
    # must fail here rather than drift the docs silently.
    EXPECTED = {
        "ISO 27001:2022": {"aws", "azure", "gcp", "kubernetes", "m365", "nhn"},
        "PCI-DSS v4.0.1": {"aws", "azure", "gcp", "kubernetes"},
        "SOC 2 (TSC)": {"aws", "azure", "gcp"},
        "KISA ISMS-P": {"aws"},
        "NIST 800-53 Rev5": {"aws"},
        "CMMC 2.0 Level 2": {"aws"},
    }
    FILENAMES = {
        "ISO 27001:2022": "iso27001_2022_{p}.json",
        "PCI-DSS v4.0.1": "pci_4.0_{p}.json",
        "SOC 2 (TSC)": "soc2_{p}.json",
        "KISA ISMS-P": "kisa_isms_p_2023_{p}.json",
        "NIST 800-53 Rev5": "nist_800_53_revision_5_{p}.json",
        "CMMC 2.0 Level 2": "nist_800_171_revision_2_{p}.json",
    }
    # One real requirement id per framework, so each file contributes a control.
    REQ_ID = {
        "ISO 27001:2022": "A.8.5",
        "PCI-DSS v4.0.1": "1.2.5.1",
        "SOC 2 (TSC)": "cc_6_1",
        "KISA ISMS-P": "2.9.4",
        "NIST 800-53 Rev5": "ac_2",
        "CMMC 2.0 Level 2": "3_1_1",
    }

    def setUp(self):
        super().setUp()
        for framework, providers in self.EXPECTED.items():
            for provider in providers:
                _write_fixture(
                    self.root,
                    provider,
                    self.FILENAMES[framework].format(p=provider),
                    [{"Id": self.REQ_ID[framework], "Checks": [f"{provider}_check"]}],
                )

    def test_every_registered_framework_with_a_mapping_is_scoped(self):
        scopes = pnm.native_control_providers()
        self.assertEqual(set(scopes), set(pnm.FRAMEWORK_SOURCES))
        self.assertEqual(set(scopes), set(pnm.load_all()))

    def test_each_scope_matches_the_5_30_1_provider_layout(self):
        for framework, providers in self.EXPECTED.items():
            with self.subTest(framework=framework):
                self.assertEqual(
                    pnm.framework_providers(framework), frozenset(providers)
                )

    def test_no_framework_is_gated_off_a_provider_it_ships_for(self):
        cm = _load("compliance_map_all_frameworks", "compliance-map.py")
        for framework, providers in self.EXPECTED.items():
            for provider in sorted(providers):
                with self.subTest(framework=framework, provider=provider):
                    result = cm.map_compliance([], scanned_providers={provider})
                    sources = {c["match_source"] for c in result[framework]}
                    self.assertIn("prowler", sources)

    def test_every_framework_is_gated_off_a_provider_none_of_them_ship_for(self):
        """`github` has no file for any registered framework, so no framework
        may keep its native mapping on a GitHub-only run."""
        cm = _load("compliance_map_all_gated", "compliance-map.py")
        for framework in self.EXPECTED:
            with self.subTest(framework=framework):
                result = cm.map_compliance([], scanned_providers={"github"})
                sources = {c["match_source"] for c in result[framework]}
                self.assertNotIn("prowler", sources)


class TestGatingIsPerControlNotPerFramework(_ScopedFixture):
    """A framework-level scope leaves the same false-PASS inside the framework.

    `load_framework()` MERGES every provider file into one check set per
    control, so "ISO ships for kubernetes" can be true while an individual
    control's checks are all AWS. Measured at 5.30.1, ISO has such controls in
    both directions: `A.8.9`, `A.8.4`, `A.8.7` are aws-only and `A.5.2` is
    kubernetes-only — so even an AWS run had controls reporting PASS on
    evidence they could not read.
    """

    def setUp(self):
        super().setUp()
        # `A.8.5` is evidenced by both providers, `A.8.9` only by aws.
        _write_fixture(self.root, "aws", "iso27001_2022_aws.json", [
            {"Id": "A.8.5", "Checks": ["aws_mfa"]},
            {"Id": "A.8.9", "Checks": ["aws_config_baseline"]},
        ])
        _write_fixture(self.root, "kubernetes", "iso27001_2022_kubernetes.json", [
            {"Id": "A.8.5", "Checks": ["apiserver_auth_mode_include_rbac"]},
        ])
        self.cm = _load("compliance_map_per_control", "compliance-map.py")

    def _iso(self, findings, providers=None):
        return {
            c["control"]: c
            for c in self.cm.map_compliance(findings, scanned_providers=providers)[
                "ISO 27001:2022"
            ]
        }

    def test_the_framework_is_in_scope_for_kubernetes(self):
        self.assertIn("kubernetes", pnm.framework_providers("ISO 27001:2022"))

    def test_a_control_only_aws_can_evidence_is_gated_off_a_kubernetes_run(self):
        controls = self._iso([], providers={"kubernetes"})
        # A.8.5 has a kubernetes check, so it stays on the exact mapping.
        self.assertEqual(controls["A.8.5"]["match_source"], "prowler")
        # A.8.9 does not. Reporting PASS here is the bug.
        self.assertEqual(controls["A.8.9"]["match_source"], "keyword")

    def test_the_same_control_keeps_the_native_path_on_an_aws_run(self):
        controls = self._iso([], providers={"aws"})
        self.assertEqual(controls["A.8.9"]["match_source"], "prowler")
        self.assertEqual(controls["A.8.5"]["match_source"], "prowler")

    def test_control_providers_records_each_control_separately(self):
        per = pnm.control_providers("ISO 27001:2022")
        self.assertEqual(per["A.8.5"], frozenset({"aws", "kubernetes"}))
        self.assertEqual(per["A.8.9"], frozenset({"aws"}))


class TestEvidenceSourceIsVisible(unittest.TestCase):
    """Gating that nothing displays is gating an operator cannot audit.

    Before this, `match_source` was produced by `map_compliance` and rendered
    nowhere, so a control decided by Prowler's exact mapping and one decided by
    a substring approximation — measured at 41.5% fidelity against that same
    mapping — looked identical in the dashboard.
    """

    def setUp(self):
        import sys

        if _LIB not in sys.path:
            sys.path.insert(0, os.path.abspath(_LIB))

    @staticmethod
    def _ctrl(control, source, status="PASS"):
        return {
            "control": control,
            "name": control,
            "desc": "d",
            "action": "a",
            "checks": [],
            "status": status,
            "count": 0,
            "findings": [],
            "match_source": source,
        }

    def _html(self, controls, framework="NIST 800-53 Rev5"):
        from dashboard_html_compliance import _build_compliance_html

        return _build_compliance_html({framework: controls})

    def test_a_gated_framework_says_so(self):
        html = self._html([self._ctrl("AC-2", "keyword"), self._ctrl("AU-2", "keyword")])
        self.assertIn("comp-fw-source", html)
        self.assertIn("2 keyword", html)
        self.assertNotIn("exact", html)

    def test_a_native_framework_reports_exact(self):
        html = self._html([self._ctrl("AC-2", "prowler")])
        self.assertIn("1 exact", html)

    def test_a_mixed_framework_reports_both_in_a_stable_order(self):
        html = self._html([
            self._ctrl("AC-2", "prowler"),
            self._ctrl("AU-2", "keyword"),
            self._ctrl("CA-7", "keyword"),
        ])
        self.assertLess(html.index("1 exact"), html.index("2 keyword"))

    def test_unmapped_controls_are_named_not_assessed(self):
        html = self._html(
            [self._ctrl("AC", "unmapped", status="N/A")], framework="CMMC 2.0 Level 2"
        )
        self.assertIn("1 not assessed", html)

    def test_controls_without_a_source_render_no_row(self):
        from dashboard_html_compliance import _evidence_source_html

        self.assertEqual(_evidence_source_html([]), "")
        bare = {"control": "X", "status": "PASS"}
        self.assertEqual(_evidence_source_html([bare]), "")

    def test_an_unknown_source_is_shown_rather_than_dropped(self):
        """A source this renderer does not know about must still be counted —
        silently omitting it would understate the framework's control count."""
        from dashboard_html_compliance import _evidence_source_html

        html = _evidence_source_html([self._ctrl("X", "some_future_source")])
        self.assertIn("1 some_future_source", html)

    def test_the_source_row_style_exists_in_the_template(self):
        with open(os.path.join(_LIB, "dashboard-template.html"), encoding="utf-8") as fh:
            template = fh.read()
        for cls in (".comp-fw-source{", ".comp-src-prowler{", ".comp-src-keyword{"):
            self.assertIn(cls, template)


class TestProviderSlugsAgreeOnBothSides(_ScopedFixture):
    """The scope speaks Prowler's COMPLIANCE DIRECTORY names; `scanned_providers`
    speaks ClaudeSec's finding slugs. A pair that should match but does not
    would gate away real evidence — a worse failure than the one being fixed,
    because it is silent in the other direction.

    The emitted set is read out of `integration.sh` rather than copied, and NOT
    taken from `dashboard_providers.PROVIDER_LABELS` — that is a UI label table,
    not the emitting side. The difference is load-bearing: `PROVIDER_LABELS` has
    an `nhn` key, but the NHN block runs `_prowler_scan "openstack"`, so no run
    ever emits `prowler-nhn.ocsf.json`. A test pinned to the label table would
    assert a parity that is not the one the gate uses, and would not catch a
    rename on the emitting side.

    Prowler 5.30.1 compliance directories, verified against the tag (17):
    alibabacloud, aws, azure, cloudflare, gcp, github, googleworkspace, iac,
    kubernetes, llm, m365, mongodbatlas, nhn, okta, openstack, oraclecloud,
    stackit.
    """

    PROWLER_COMPLIANCE_DIRS = {
        "alibabacloud", "aws", "azure", "cloudflare", "gcp", "github",
        "googleworkspace", "iac", "kubernetes", "llm", "m365",
        "mongodbatlas", "nhn", "okta", "openstack", "oraclecloud", "stackit",
    }
    # Slugs ClaudeSec emits that Prowler has no compliance directory for.
    # `image` is a container-image scan, not a cloud estate, so no compliance
    # file can ever be scoped to it.
    EXPECTED_UNMATCHED = {"image"}

    @staticmethod
    def _emitted_slugs():
        """Every provider `integration.sh` actually scans, parsed from source."""
        import re

        path = os.path.join(
            os.path.dirname(__file__), "..", "checks", "prowler", "integration.sh"
        )
        with open(path, encoding="utf-8") as fh:
            return set(re.findall(r'_prowler_scan\s+"([a-z0-9]+)"', fh.read()))

    def test_the_emitting_side_is_readable_and_non_trivial(self):
        """Guard the extraction, not just the assertion: a regex that silently
        matched nothing would make every parity check below vacuous."""
        slugs = self._emitted_slugs()
        self.assertGreaterEqual(len(slugs), 10)
        self.assertIn("aws", slugs)
        self.assertIn("kubernetes", slugs)

    def test_every_emitted_slug_prowler_knows_is_spelled_identically(self):
        unmatched = self._emitted_slugs() - self.PROWLER_COMPLIANCE_DIRS
        self.assertEqual(
            unmatched,
            self.EXPECTED_UNMATCHED,
            "A slug ClaudeSec emits no longer matches Prowler's compliance "
            "directory name — the gate would drop that provider's evidence.",
        )

    def test_nhn_is_labelled_but_never_emitted(self):
        """Pin the asymmetry so the `nhn` row of ISO's scope is understood as
        unreachable rather than assumed live. If NHN ever scans under its own
        name, this fails and the parity above starts covering it."""
        dp = _load("dashboard_providers_scope", "dashboard_providers.py")
        self.assertIn("nhn", dp.PROVIDER_LABELS)
        self.assertNotIn("nhn", self._emitted_slugs())
        self.assertIn("openstack", self._emitted_slugs())

    def test_kubernetes_variants_normalise_to_prowlers_directory_name(self):
        """`_normalize_provider` folds k8s/eks into `kubernetes`, which is
        exactly Prowler's directory name. A mismatch here would gate every
        framework off a Kubernetes scan."""
        pcs = _load("prowler_compliance_summary_scope", "prowler_compliance_summary.py")
        for name in ("prowler-k8s.ocsf.json", "prowler-kubernetes.ocsf.json",
                     "prowler-eks-prod.ocsf.json"):
            self.assertEqual(pcs._provider_of("/x/" + name), "kubernetes", name)
        self.assertIn("kubernetes", self.PROWLER_COMPLIANCE_DIRS)

    def test_a_scoped_framework_gates_on_slugs_the_scanner_can_emit(self):
        for provider in ("aws", "azure", "gcp"):
            _write_fixture(self.root, provider, f"soc2_{provider}.json",
                           [{"Id": "cc_6_1", "Checks": ["x"]}])
        self.assertTrue(
            pnm.framework_providers("SOC 2 (TSC)") <= self._emitted_slugs()
        )


class TestForeignProviderRunDoesNotScoreAFreePass(_ScopedFixture):
    """The regression this change is for, on a keyword-bearing framework."""

    def setUp(self):
        super().setUp()
        _write_fixture(
            self.root,
            "aws",
            "nist_800_53_revision_5_aws.json",
            [
                {"Id": "ac_2", "Checks": ["iam_user_mfa_enabled"]},
                {"Id": "au_2", "Checks": ["cloudtrail_multi_region_enabled"]},
            ],
        )
        self.cm = _load("compliance_map_scope_under_test", "compliance-map.py")

    def _nist(self, findings, providers=None):
        return {
            c["control"]: c
            for c in self.cm.map_compliance(findings, scanned_providers=providers)[
                "NIST 800-53 Rev5"
            ]
        }

    def test_kubernetes_run_falls_back_to_keywords_instead_of_passing(self):
        finding = {
            "check": "apiserver_audit_log_path_set",
            "title": "API server audit log path not set",
            "message": "audit logging is disabled on the api server",
            "provider": "kubernetes",
        }
        ctrl = self._nist([finding])["AU-2"]
        self.assertEqual(ctrl["match_source"], "keyword")
        self.assertEqual(ctrl["status"], "FAIL")

    def test_the_same_run_used_to_report_prowler_and_pass(self):
        """Pin the direction of the change: with the scope removed the control
        is decided by an AWS check list it can never match, i.e. PASS."""
        finding = {
            "check": "apiserver_audit_log_path_set",
            "title": "audit log path not set",
            "message": "audit logging disabled",
            "provider": "kubernetes",
        }
        unscoped = self.cm._native_provider_scope
        self.cm._native_provider_scope = lambda framework, control: None
        try:
            ctrl = self._nist([finding])["AU-2"]
            self.assertEqual(ctrl["match_source"], "prowler")
            self.assertEqual(ctrl["status"], "PASS")
        finally:
            self.cm._native_provider_scope = unscoped

    def test_an_aws_run_is_unchanged(self):
        finding = {
            "check": "iam_user_mfa_enabled",
            "title": "",
            "message": "",
            "provider": "aws",
        }
        ctrl = self._nist([finding])["AC-2"]
        self.assertEqual(ctrl["match_source"], "prowler")
        self.assertEqual(ctrl["status"], "FAIL")

    def test_a_mixed_run_containing_a_covered_provider_keeps_the_native_path(self):
        findings = [
            {"check": "x", "title": "t", "message": "m", "provider": "kubernetes"},
            {
                "check": "iam_user_mfa_enabled",
                "title": "",
                "message": "",
                "provider": "aws",
            },
        ]
        self.assertEqual(self._nist(findings)["AC-2"]["match_source"], "prowler")

    def test_a_clean_covered_provider_still_scores_when_declared(self):
        derived = self._nist([])
        self.assertEqual(derived["AC-2"]["match_source"], "keyword")
        explicit = self._nist([], providers={"aws"})
        self.assertEqual(explicit["AC-2"]["match_source"], "prowler")
        self.assertEqual(explicit["AC-2"]["status"], "PASS")

    def test_gating_never_turns_a_keyword_framework_into_na(self):
        """Only `native_only` controls become N/A when gated. A control with
        keywords must fall back to them, not disappear."""
        finding = {
            "check": "apiserver_x",
            "title": "t",
            "message": "m",
            "provider": "kubernetes",
        }
        for control in self._nist([finding]).values():
            with self.subTest(control=control["control"]):
                self.assertNotEqual(control["status"], "N/A")


class TestGithubFindingsKeepTheKeywordPath(_ScopedFixture):
    """A GitHub-only run is out of scope for every REGISTERED framework, so it
    keeps keywords — which the mapping plan requires, since GitHub findings are
    the case that path exists for.

    Prowler 5.30.1 does ship one file under `compliance/github/`,
    `cis_1.0_github.json`, but CIS is deliberately absent from
    `FRAMEWORK_SOURCES` (its control ids need a remap first), so no registered
    framework has a github file. `test_no_registered_framework_matches_the_only
    _github_file` pins that, because the day CIS is registered this class's
    premise changes.
    """

    def setUp(self):
        super().setUp()
        _write_fixture(self.root, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["s3_bucket_public_access"]}])
        self.cm = _load("compliance_map_github_scope", "compliance-map.py")

    def test_no_registered_framework_matches_the_only_github_file(self):
        import fnmatch

        for framework, (pattern, _) in pnm.FRAMEWORK_SOURCES.items():
            with self.subTest(framework=framework):
                self.assertFalse(
                    fnmatch.fnmatch("cis_1.0_github.json", pattern),
                    f"{framework} would claim Prowler's github file.",
                )

    def test_github_only_run_matches_on_keywords(self):
        finding = {
            "check": "branch_protection_disabled",
            "title": "Branch protection is not enabled",
            "message": "no required approval on the default branch",
            "provider": "github",
        }
        ctrl = {
            c["control"]: c
            for c in self.cm.map_compliance([finding])["SOC 2 (TSC)"]
        }["CC8"]
        self.assertEqual(ctrl["match_source"], "keyword")
        self.assertEqual(ctrl["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
