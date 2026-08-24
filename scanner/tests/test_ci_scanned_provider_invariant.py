"""Regression guard: `scanned_providers` may only ever name a provider whose
Prowler evidence file actually decoded.

THE INVARIANT. `load_prowler_files`' keys are not a convenience — `dashboard-gen.py`
passes them verbatim as `map_compliance(all_findings, scanned_providers=set(providers))`,
where the #455 gate uses them to decide whether a control had evidence it could
have read. So a provider present with an EMPTY finding list asserts "Prowler
assessed this and found nothing", which is the strongest claim the dashboard can
make. Returning `[]` for a file that never decoded therefore laundered an unread
file into a clean bill of health.

THE INCIDENT, measured 2026-08-24 before the fix. One 0x80 byte spliced into a
3-finding `prowler-aws.ocsf.json` — realistic, since any non-UTF-8 byte in a
cloud resource tag, owner or description produces it:

    clean utf-8    providers=['aws'] findings=3 -> NIST AC-2 FAIL  source='prowler'
    one 0x80 byte  providers=['aws'] findings=0 -> NIST AC-2 PASS  source='prowler'
    no file at all providers=[]      findings=0 -> NIST AC-2 PASS  source='keyword'

Three real `iam_user_mfa_enabled` FAILs ("Root account lacks MFA") became a PASS
carrying `match_source="prowler"`. Note the third row: a MISSING file already
degraded provenance to `keyword`, so the corrupt file was the WORSE of the two —
it kept the authoritative label while resting on nothing, and nothing on screen
distinguished the two.

This is the #454/#455/#459 false-PASS class reached through the LOADER, which
those PRs never touched. `prowler_compliance_summary.py` has had it right all
along by adding the provider only after the parse succeeds.

WHY THIS GUARD EXECUTES RATHER THAN GREPS. A source pin on `errors="replace"` or
on the `if items is None: continue` line would be defeated by any refactor that
preserves the tokens and loses the behaviour — the exact class ADR-001 §5 and
#404 were written about ("executing the gate closed all ten shapes at once
where three parser fixes closed one, four, then six"). So this drives the real
loader and, for the assertion that matters, the real `map_compliance`. It imports
`scanner/lib` deliberately; the "guards stay stdlib-only" convention exists to
keep guards coverage-neutral and PyYAML-free, and two guards already import
scanner/lib for the same reason (`test_ci_provider_labels_sync.py`,
`test_ci_diagram_gen_canonical_sync.py`). No network: the native Prowler mapping
is supplied from a fixture through `CLAUDESEC_PROWLER_COMPLIANCE_DIR`, which
exists precisely so tests need not have Prowler installed.

DIRECTION: both, and both matter.
- Under-claim is the bypass: an unread provider must never appear. Fails closed.
- Over-correction is a real regression too: a file that legitimately holds `[]`
  means assessed-and-clean, and dropping THAT would silently stop reporting every
  clean provider. `test_empty_file_still_counts_as_scanned` pins it.

KNOWN LIMIT (deliberate). When one of several files for the same provider fails
and a sibling succeeds, the provider stays claimed, because a real FAIL is
evidence regardless of what else was unreadable and dropping it would hide
genuine findings — the opposite failure and the worse one. That residual is an
over-claim on completeness, documented in `load_prowler_files` and asserted here
by `test_sibling_file_failure_keeps_the_readable_findings` so the trade-off is
pinned rather than assumed.
"""

import json
import os
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scanner" / "lib"))

import dashboard_data_loader as loader  # noqa: E402


def _finding(check="iam_user_mfa_enabled"):
    return {
        "status_code": "FAIL",
        "severity": "High",
        "metadata": {"event_code": check},
        "finding_info": {"title": "Root account lacks MFA", "desc": "Enable MFA"},
        "resources": [{"name": "acct-1", "type": "AwsAccount"}],
        "unmapped": {"compliance": {}},
    }


def _write(dirpath, filename, payload):
    p = Path(dirpath, filename)
    p.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
    return p


class TestScannedProviderInvariant(unittest.TestCase):
    """The loader half, driven directly."""

    def test_loader_is_importable(self):
        """Canary. Without it, a moved module turns every test below into an
        import error that reads as infrastructure noise rather than as the guard
        failing to guard."""
        self.assertTrue(hasattr(loader, "load_prowler_files"))
        self.assertTrue(hasattr(loader, "_load_single_prowler_file"))

    def test_unreadable_file_is_not_claimed_as_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", "NOT JSON{{{")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                got = loader.load_prowler_files(d)
        self.assertNotIn(
            "aws",
            got,
            "a provider whose file did not decode is present in the scanned set, "
            "so map_compliance will score controls as assessed against evidence "
            "that was never read",
        )
        self.assertTrue(
            any("could not be read" in str(c.message) for c in caught),
            "the provider was dropped SILENTLY — that trades a false PASS for an "
            "invisible gap, which is the #445/#446/#448 shape",
        )

    def test_missing_file_signals_unread_not_empty(self):
        name, items = loader._load_single_prowler_file("/no/such/prowler-aws.ocsf.json")
        self.assertEqual(name, "aws")
        self.assertIsNone(items, "`[]` here means 'assessed, clean' — reserve it")

    def test_non_utf8_byte_recovers_every_finding(self):
        """The fix must RECOVER, not merely refuse to lie. Dropping the provider
        alone would still lose 3 real FAILs to one stray byte."""
        payload = bytearray(json.dumps([_finding() for _ in range(50)]).encode())
        payload[200:200] = b"\x80"
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", bytes(payload))
            got = loader.load_prowler_files(d)
        self.assertIn("aws", got)
        self.assertEqual(
            len(got["aws"]), 50, "recovery must be exact, not approximate"
        )

    def test_empty_file_still_counts_as_scanned(self):
        """Opposite direction (see DIRECTION in the module docstring).

        Only presence is asserted for every shape. `{}` is deliberately NOT
        pinned to `[]`: `_parse_ocsf_json` decodes a bare object as one record, so
        that file yields `[{}]`. That is pre-existing behaviour untouched by this
        fix, and writing `assertEqual(got["aws"], [])` for it — as the first draft
        of this test did — asserts the parser's shape rather than this guard's
        invariant, which is presence.
        """
        # `"[ ]"` and `"{ }"` are here on purpose: an earlier draft of the loader
        # decided this by comparing `content` against a list of empty spellings,
        # which read legal whitespace-bearing empty JSON as garbage and dropped a
        # clean provider. The rule is the grammar, so the spacing must not matter.
        for payload in ("[]", "[ ]", "{}", "{ }", "", "  \n "):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as d:
                _write(d, "prowler-aws.ocsf.json", payload)
                got = loader.load_prowler_files(d)
                self.assertIn(
                    "aws",
                    got,
                    "a genuinely empty evidence file means assessed-and-clean; "
                    "dropping it would stop reporting every clean provider",
                )
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", "[]")
            self.assertEqual(loader.load_prowler_files(d)["aws"], [])

    def test_sibling_file_failure_keeps_the_readable_findings(self):
        """The documented residual, pinned so it stays a decision."""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-k8s-a.ocsf.json", json.dumps([_finding()]))
            _write(d, "prowler-k8s-b.ocsf.json", "NOT JSON{{{")
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                got = loader.load_prowler_files(d)
        self.assertIn("kubernetes", got)
        self.assertEqual(len(got["kubernetes"]), 1)


class TestComplianceVerdictCannotRestOnAnUnreadFile(unittest.TestCase):
    """The half that actually matters: drive `map_compliance` and compare verdicts.

    The loader assertions above can all pass while the consumer still reaches a
    false PASS by some other route, which is why the incident is reproduced here
    end-to-end rather than argued from the loader's return value.
    """

    @classmethod
    def setUpClass(cls):
        # A minimal native mapping so the #455 gate path is LIVE. Without it
        # `_native_mapping()` is empty, every control falls back to keywords, and
        # the whole native/provider-scope branch this guard exists for is never
        # executed — a run that reports OK having tested nothing. Measured: with
        # Prowler absent and no fixture, the pre-fix code showed ZERO changed
        # verdicts, which reads as "no bug" and is simply the wrong measurement.
        cls._tmp = tempfile.TemporaryDirectory()
        aws = Path(cls._tmp.name, "aws")
        aws.mkdir()
        (aws / "nist_800_53_revision_5_aws.json").write_text(
            json.dumps({"Requirements": [{"Id": "ac_2", "Checks": ["iam_user_mfa_enabled"]}]})
        )
        cls._prev = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR")
        os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = cls._tmp.name
        os.environ.setdefault("CLAUDESEC_DASHBOARD_OFFLINE", "1")

        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_cm_guard", REPO_ROOT / "scanner" / "lib" / "compliance-map.py"
        )
        cls.cm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cm)
        from dashboard_data_analysis import analyze_prowler

        # staticmethod, or attribute access binds it and `self` arrives as the
        # first positional argument.
        cls.analyze = staticmethod(analyze_prowler)

    @classmethod
    def tearDownClass(cls):
        if cls._prev is None:
            os.environ.pop("CLAUDESEC_PROWLER_COMPLIANCE_DIR", None)
        else:
            os.environ["CLAUDESEC_PROWLER_COMPLIANCE_DIR"] = cls._prev
        cls._tmp.cleanup()

    def test_native_fixture_is_actually_loaded(self):
        """Positive control for setUpClass. Prove the harness can reach the code
        before trusting anything it reports (probe-checklist item 6)."""
        native = self.cm._native_mapping()
        self.assertIn("NIST 800-53 Rev5", native)
        self.assertIn("AC-2", native["NIST 800-53 Rev5"])

    def _ac2(self, payload):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", payload)
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                providers = loader.load_prowler_files(d)
        _, all_findings = self.analyze(providers)
        res = self.cm.map_compliance(all_findings, scanned_providers=set(providers))
        for ctrl in res.get("NIST 800-53 Rev5", []):
            if ctrl.get("control") == "AC-2":
                return ctrl.get("status"), ctrl.get("match_source")
        self.fail("AC-2 missing from the NIST result — fixture or control map moved")

    def test_clean_evidence_reports_the_real_failure(self):
        """Positive control for the pair below: the FAIL has to be reachable
        before its absence can mean anything."""
        self.assertEqual(
            self._ac2(json.dumps([_finding() for _ in range(3)])),
            ("FAIL", "prowler"),
        )

    def test_one_bad_byte_does_not_turn_a_fail_into_a_prowler_backed_pass(self):
        payload = bytearray(json.dumps([_finding() for _ in range(3)]).encode())
        payload[60:60] = b"\x80"
        status, source = self._ac2(bytes(payload))
        self.assertEqual(
            (status, source),
            ("FAIL", "prowler"),
            "one non-UTF-8 byte changed the compliance verdict; before the fix "
            "this was ('PASS', 'prowler')",
        )

    def test_garbage_evidence_never_claims_prowler_provenance(self):
        """A file that cannot be read at all may still end up PASS — there is no
        evidence either way — but it must NOT wear the `prowler` label, which is
        what made the corrupt case worse than the missing one."""
        status, source = self._ac2("NOT JSON{{{")
        self.assertNotEqual(
            source,
            "prowler",
            f"AC-2 reports match_source={source!r} on an unparseable evidence file",
        )


class TestGuardFailsAgainstTheOldBehaviour(unittest.TestCase):
    """Non-vacuity (ADR-001 §4). Restores the pre-fix loader and proves the
    assertions above actually fire — a guard nobody has watched fail is not
    evidence (#408)."""

    @staticmethod
    def _pre_fix_load_single(fpath):
        """Verbatim shape of the code before 2026-08-24: strict decode, and `[]`
        on any exception."""
        raw = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
        name = loader._normalize_provider(raw)
        try:
            with open(fpath, encoding="utf-8") as f:
                return name, loader._parse_ocsf_json(f.read().strip())
        except Exception:
            return name, []

    def test_old_loader_is_caught(self):
        original = loader._load_single_prowler_file
        loader._load_single_prowler_file = self._pre_fix_load_single
        try:
            with tempfile.TemporaryDirectory() as d:
                _write(d, "prowler-aws.ocsf.json", "NOT JSON{{{")
                with warnings.catch_warnings(record=True):
                    warnings.simplefilter("always")
                    got = loader.load_prowler_files(d)
            self.assertIn(
                "aws",
                got,
                "the pre-fix loader no longer reproduces the defect, so the "
                "assertions in this file prove nothing — re-derive them",
            )
            self.assertEqual(got["aws"], [])
        finally:
            loader._load_single_prowler_file = original

    def test_old_loader_loses_findings_to_one_byte(self):
        original = loader._load_single_prowler_file
        loader._load_single_prowler_file = self._pre_fix_load_single
        try:
            payload = bytearray(json.dumps([_finding() for _ in range(50)]).encode())
            payload[200:200] = b"\x80"
            with tempfile.TemporaryDirectory() as d:
                _write(d, "prowler-aws.ocsf.json", bytes(payload))
                got = loader.load_prowler_files(d)
            self.assertEqual(got.get("aws"), [], "pre-fix behaviour not reproduced")
        finally:
            loader._load_single_prowler_file = original


if __name__ == "__main__":
    unittest.main()
