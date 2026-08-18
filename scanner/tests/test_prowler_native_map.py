"""
Tests for `scanner/lib/prowler_native_map.py` and its use by `map_compliance()`.

Prowler assigns checks to requirements by intent, in data it ships; the keyword
map approximates that with substrings. Measured on the 16 KISA ISMS-P controls
where both have an opinion, the keywords reproduced 41.5% — `2.9.4` (백업·복구)
scoring 0 of 58 while listing `backup`, `snapshot` and `restore`, because
Prowler's backup checks contain none of those literal substrings.

These tests pin the three properties that make the native path safe to prefer:

1. **Exactness.** A natively-mapped control matches on check-id membership and
   NOTHING else. A finding whose text is full of the control's keywords does not
   match if its check id is not in Prowler's list — that is the entire point, and
   it is the one behaviour a reader is most likely to assume works the old way.
2. **Fallback survives.** Prowler's data is sparse (26 of 101 KISA requirements
   carry any check), so most controls still run on keywords. A change that
   silently dropped the keyword path would blank them.
3. **Absence is inert.** Prowler is optional. With it missing, every control must
   behave exactly as before.

Hermetic: fixtures are written to a tmpdir and pointed at with
`CLAUDESEC_PROWLER_COMPLIANCE_DIR`. Nothing here requires Prowler to be
installed, which is also true of CI.
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


pnm = _load("prowler_native_map_under_test", "prowler_native_map.py")


def _write_fixture(root, provider, filename, requirements):
    d = os.path.join(root, provider)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, filename), "w", encoding="utf-8") as fh:
        json.dump({"Requirements": requirements}, fh)


class TestIdNormalizers(unittest.TestCase):
    """Requirement ids do not agree across frameworks; each source normalizes."""

    def test_soc2_collapses_to_series(self):
        # The repo maps SOC 2 at series granularity, Prowler at sub-criterion.
        for raw in ("cc_6_1", "CC6.1", "cc-6-7"):
            self.assertEqual(pnm._soc2_series(raw), "CC6", raw)

    def test_nist_control_form(self):
        for raw, want in (("ac_2_1", "AC-2"), ("ac-17", "AC-17"), ("si_4", "SI-4")):
            self.assertEqual(pnm._nist_control(raw), want, raw)

    def test_pci_requirement_form(self):
        self.assertEqual(pnm._pci_requirement("1.2.5.1"), "Req 1")
        self.assertEqual(pnm._pci_requirement("10.7.2"), "Req 10")

    def test_unparseable_ids_return_none_rather_than_a_wrong_control(self):
        # Returning a guess here would attach real checks to the wrong control.
        for bad in ("", "governance", "x_1"):
            self.assertIsNone(pnm._soc2_series(bad))
            self.assertIsNone(pnm._pci_requirement(bad))


class TestLoader(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = self.root
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.environ.pop, "CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)

    def test_merges_providers_for_one_framework(self):
        # A control is satisfied by evidence from whichever provider was scanned,
        # so aws + azure files merge rather than the last one winning.
        _write_fixture(self.root, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["a_check"]}])
        _write_fixture(self.root, "azure", "soc2_azure.json",
                       [{"Id": "cc_6_6", "Checks": ["b_check"]}])
        native = pnm.load_framework("SOC 2 (TSC)")
        self.assertEqual(native["CC6"], frozenset({"a_check", "b_check"}))

    def test_requirements_without_checks_are_omitted_not_stored_empty(self):
        # An empty set and "no native opinion" must not be confused: the first
        # would mark a control as having zero evidence, the second falls back to
        # keywords. Prowler's KISA file has 75 such requirements.
        _write_fixture(self.root, "aws", "soc2_aws.json", [
            {"Id": "cc_1_1", "Checks": []},
            {"Id": "cc_2_1"},
            {"Id": "cc_6_1", "Checks": ["real_check"]},
        ])
        native = pnm.load_framework("SOC 2 (TSC)")
        self.assertEqual(sorted(native), ["CC6"])

    def test_unknown_framework_returns_empty(self):
        self.assertEqual(pnm.load_framework("Not A Framework"), {})

    def test_missing_directory_returns_empty(self):
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = os.path.join(self.root, "nope")
        self.assertEqual(pnm.prowler_compliance_dirs(), [])
        self.assertEqual(pnm.load_framework("SOC 2 (TSC)"), {})

    def test_malformed_json_is_skipped_not_fatal(self):
        d = os.path.join(self.root, "aws")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "soc2_aws.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(pnm.load_framework("SOC 2 (TSC)"), {})


class TestMapComplianceUsesNative(unittest.TestCase):
    """The behaviour that makes the native path worth having."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = self._tmp.name
        self.addCleanup(os.environ.pop, "CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        _write_fixture(self._tmp.name, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["s3_bucket_public_access"]}])
        # Fresh module each time: map_compliance caches the native mapping.
        self.cm = _load("compliance_map_native_under_test", "compliance-map.py")

    def _soc2(self, findings):
        return {c["control"]: c for c in self.cm.map_compliance(findings)["SOC 2 (TSC)"]}

    def test_native_control_matches_by_check_id(self):
        f = {"check": "s3_bucket_public_access", "title": "", "message": ""}
        ctrl = self._soc2([f])["CC6"]
        self.assertEqual(ctrl["status"], "FAIL")
        self.assertEqual(ctrl["match_source"], "prowler")

    def test_native_control_ignores_keyword_text(self):
        # THE point of this change. `mfa`, `encrypt` and `publicly` are all CC6
        # keywords; under the old path this finding matched. With a native
        # mapping present it must not, because its check id is not in the list.
        f = {
            "check": "some_unrelated_check",
            "title": "mfa and encrypt and publicly accessible",
            "message": "unrestricted ingress 0.0.0.0/0",
        }
        ctrl = self._soc2([f])["CC6"]
        self.assertEqual(ctrl["status"], "PASS")
        self.assertEqual(ctrl["count"], 0)

    def test_controls_without_native_data_still_use_keywords(self):
        # Only CC6 is in the fixture. CC7 must keep working on keywords, or the
        # sparse half of every framework goes dark.
        f = {"check": "cloudtrail_x", "title": "logging disabled", "message": ""}
        ctrl = self._soc2([f])["CC7"]
        self.assertEqual(ctrl["match_source"], "keyword")
        self.assertEqual(ctrl["status"], "FAIL")

    def test_non_assessable_stays_na_even_with_native_checks(self):
        # CC1 is governance; a native mapping must not resurrect it as PASS/FAIL.
        _write_fixture(self._tmp.name, "aws", "soc2_aws.json", [
            {"Id": "cc_1_1", "Checks": ["some_check"]},
        ])
        cm = _load("compliance_map_na_under_test", "compliance-map.py")
        ctrl = {c["control"]: c for c in cm.map_compliance(
            [{"check": "some_check", "title": "", "message": ""}]
        )["SOC 2 (TSC)"]}["CC1"]
        self.assertEqual(ctrl["status"], "N/A")


class TestPackageDiscovery(unittest.TestCase):
    """The no-override path: find the installed Prowler package.

    CI has no Prowler, so this is driven with a fake package injected into
    `sys.modules` rather than by installing one — which also keeps the test
    honest about what the code actually reads (`submodule_search_locations`,
    then `origin`).
    """

    def setUp(self):
        os.environ.pop("CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _with_spec(self, spec):
        import importlib.util as ilu

        original = ilu.find_spec
        ilu.find_spec = lambda name: spec if name == "prowler" else original(name)
        self.addCleanup(setattr, ilu, "find_spec", original)

    def test_uses_submodule_search_locations(self):
        os.makedirs(os.path.join(self._tmp.name, "compliance"))
        self._with_spec(type("S", (), {
            "submodule_search_locations": [self._tmp.name], "origin": None})())
        self.assertEqual(pnm.prowler_compliance_dirs(),
                         [os.path.join(self._tmp.name, "compliance")])

    def test_falls_back_to_origin_when_no_search_locations(self):
        os.makedirs(os.path.join(self._tmp.name, "compliance"))
        self._with_spec(type("S", (), {
            "submodule_search_locations": [],
            "origin": os.path.join(self._tmp.name, "__init__.py")})())
        self.assertEqual(pnm.prowler_compliance_dirs(),
                         [os.path.join(self._tmp.name, "compliance")])

    def test_package_without_compliance_dir_yields_nothing(self):
        self._with_spec(type("S", (), {
            "submodule_search_locations": [self._tmp.name], "origin": None})())
        self.assertEqual(pnm.prowler_compliance_dirs(), [])

    def test_prowler_not_installed(self):
        self._with_spec(None)
        self.assertEqual(pnm.prowler_compliance_dirs(), [])

    def test_find_spec_raising_is_not_fatal(self):
        # A broken sys.path entry can make find_spec raise; the scanner must not
        # die inside a compliance lookup because of it.
        import importlib.util as ilu

        original = ilu.find_spec

        def boom(name):
            if name == "prowler":
                raise ImportError("broken meta path")
            return original(name)

        ilu.find_spec = boom
        self.addCleanup(setattr, ilu, "find_spec", original)
        self.assertEqual(pnm.prowler_compliance_dirs(), [])


class TestIdentityAndSkips(unittest.TestCase):
    """The two branches the framework-specific tests do not reach."""

    def test_identity_normalizer(self):
        # KISA and ISO ids are already in the repo's form.
        self.assertEqual(pnm._identity("2.9.4"), "2.9.4")
        self.assertEqual(pnm._identity("A.8.5"), "A.8.5")


class TestUnnormalizableRequirement(unittest.TestCase):
    def test_requirement_whose_id_cannot_normalize_is_dropped(self):
        # A requirement Prowler ships with an id the normalizer cannot parse must
        # be skipped, NOT attached to some fallback control — that would give a
        # real control someone else's checks.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = tmp.name
        self.addCleanup(os.environ.pop, "CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        _write_fixture(tmp.name, "aws", "soc2_aws.json", [
            {"Id": "not_a_cc_id", "Checks": ["orphan_check"]},
            {"Id": "cc_6_1", "Checks": ["real_check"]},
        ])
        native = pnm.load_framework("SOC 2 (TSC)")
        self.assertEqual(sorted(native), ["CC6"])
        self.assertNotIn("orphan_check", native["CC6"])


class TestLoadAll(unittest.TestCase):
    def test_load_all_includes_only_frameworks_with_data(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = tmp.name
        self.addCleanup(os.environ.pop, "CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        _write_fixture(tmp.name, "aws", "soc2_aws.json",
                       [{"Id": "cc_6_1", "Checks": ["x"]}])
        loaded = pnm.load_all()
        # An empty framework must be absent, not present-and-empty: map_compliance
        # treats "no key" as "fall back to keywords".
        self.assertEqual(sorted(loaded), ["SOC 2 (TSC)"])
        self.assertEqual(loaded["SOC 2 (TSC)"]["CC6"], frozenset({"x"}))


class TestNativeLoadFailureIsInert(unittest.TestCase):
    def test_map_compliance_survives_a_broken_loader(self):
        # compliance-map.py is imported by output.sh via importlib during a bare
        # scan. If the sibling module is missing or raises, the scan must still
        # produce a compliance section rather than dying inside it.
        cm = _load("compliance_map_broken_loader", "compliance-map.py")
        lib = os.path.join(os.path.dirname(__file__), "..", "lib")
        original = os.path.dirname
        os.path.dirname = lambda p: "/nonexistent" if lib in str(p) else original(p)
        try:
            cm._NATIVE_CACHE = None
            self.assertEqual(cm._native_mapping(), {})
        finally:
            os.path.dirname = original


class TestAbsenceIsInert(unittest.TestCase):
    def test_without_prowler_every_control_uses_keywords(self):
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = "/nonexistent-dir-for-test"
        self.addCleanup(os.environ.pop, "CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        cm = _load("compliance_map_absent_under_test", "compliance-map.py")
        result = cm.map_compliance([])
        sources = {c["match_source"] for controls in result.values() for c in controls}
        self.assertEqual(sources, {"keyword"})


if __name__ == "__main__":
    unittest.main()
