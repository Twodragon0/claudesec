"""Regression guard: `scanned_providers` may only ever name a provider whose
Prowler evidence file actually decoded.

TWO IMPLEMENTATIONS, TWO DOORS. `dashboard_data_loader.load_prowler_files` and
`diagram_data.load_prowler_files` are independent copies of the same loader.
#471 fixed only the first, so this guard covered only the first — and the
diagram copy kept mapping an unread file to `[]` until 2026-08-25. Both are
asserted here now; adding a third copy without a class in this file is the
regression this paragraph exists to prevent.

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

import glob
import json
import os
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scanner" / "lib"))

import dashboard_data_loader as loader  # noqa: E402
import diagram_data  # noqa: E402


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


class TestDiagramDataCarriesTheSameInvariant(unittest.TestCase):
    """The SECOND implementation. `diagram_data.load_prowler_files` is a separate
    copy of the same loader and it violated the invariant for as long as the
    dashboard one did — #471 fixed only `dashboard_data_loader`, so this file
    guarded one of the two doors.

    The claim here is narrower but the same shape: these keys become
    `aggregate_scan_data`'s `prowler_providers`, and every key also gets a
    `prowler_summary[prov] = {"fail": n, "total": n}` entry. Mapping an unread
    file to `[]` therefore drew the provider on the architecture diagram as
    `0 fail / 0 total` — scanned and clean — on evidence that never decoded.
    There is no `match_source` to launder here, which is why this is the milder
    half; it is still a claim the repository cannot support.
    """

    def test_module_is_importable(self):
        """Canary — see `test_loader_is_importable`."""
        self.assertTrue(hasattr(diagram_data, "load_prowler_files"))

    def test_unreadable_file_is_not_claimed_as_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = _write(d, "prowler-aws.ocsf.json", json.dumps([_finding()]))
            real_open = open

            def _raise_on_ocsf(path, *args, **kwargs):
                if str(path) == str(fpath):
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_ocsf):
                got = diagram_data.load_prowler_files(d)
        self.assertNotIn("aws", got)

    def test_garbage_is_not_claimed_as_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", "NOT JSON{{{")
            got = diagram_data.load_prowler_files(d)
        self.assertNotIn("aws", got)

    def test_non_utf8_byte_recovers_every_finding(self):
        """The recovery half. 50 findings, one 0x80 spliced in — delta must be 0,
        not merely non-empty, or `errors="replace"` could silently drop records
        and still pass."""
        payload = bytearray(json.dumps([_finding() for _ in range(50)]).encode())
        payload[200:200] = b"\x80"
        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", bytes(payload))
            got = diagram_data.load_prowler_files(d)
        self.assertEqual(len(got.get("aws", [])), 50)

    def test_empty_file_still_counts_as_scanned(self):
        """DIRECTION check. Over-correcting here would stop drawing every clean
        provider. `[ ]` is legal, empty JSON and must not read as garbage."""
        for spelling in ("[]", "[ ]", "\n[]\n"):
            with self.subTest(spelling=spelling):
                with tempfile.TemporaryDirectory() as d:
                    _write(d, "prowler-aws.ocsf.json", spelling)
                    got = diagram_data.load_prowler_files(d)
                self.assertIn("aws", got)
                self.assertEqual(got["aws"], [])

    def test_pre_fix_diagram_loader_reproduces_the_defect(self):
        """Non-vacuity (ADR-001 §4) — verbatim shape of the code before this
        change, proving the three assertions above actually fire."""
        def _pre_fix(prowler_dir):
            providers = {}
            for fpath in sorted(
                glob.glob(os.path.join(prowler_dir, "prowler-*.ocsf.json"))
            ):
                name = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
                try:
                    with open(fpath) as f:
                        providers[name] = diagram_data._parse_ocsf_json(f.read().strip())
                except Exception:
                    providers[name] = []
            return providers

        with tempfile.TemporaryDirectory() as d:
            _write(d, "prowler-aws.ocsf.json", "NOT JSON{{{")
            got = _pre_fix(d)
        self.assertEqual(
            got.get("aws"),
            [],
            "the pre-fix diagram loader no longer reproduces the defect, so the "
            "assertions in this class prove nothing — re-derive them",
        )


class TestUnreadNetworkArtifactIsNotEvidence(unittest.TestCase):
    """The THIRD data path with this shape, and the one where the claim is
    actively load-bearing.

    `load_network_tool_results` used to append `{"hosts": []}` for an nmap file
    it could not parse and `{"data": {}}` for an sslscan file it could not read.
    Three consumers took that as real evidence, and the third one matters most:

      * `dashboard_html_builders` drew an "Nmap scan summary" card — identical to
        a scan that ran and found no open ports — and an "SSL/TLS scan" card
        reading "(JSON data available)", the opposite of true;
      * `dashboard_html_overview`'s `nmap_count`/`ssl_count` counted it;
      * `network_evidence` in `build_priority_queue_html` went truthy on it,
        which SUPPRESSED "network or Datadog telemetry missing" from
        `visibility_gaps`. A corrupt artifact hid the warning that there was no
        network evidence.

    Measured before the fix, one truncated `nmap-*.xml` + one truncated
    `sslscan-*.json`:

        nmap_scans      [{'name': 'nmap-prod.xml', 'hosts': []}]
        sslscan_results [{'name': 'sslscan-prod.json', 'data': {}}]
        warnings raised 0
        nmap_count=1 ssl_count=1 -> network_evidence=True
        visibility_gaps []

    This EXECUTES the real overview builder rather than re-deriving the boolean,
    for the reason in this file's header: a re-derived copy of the condition
    passes while the shipped one regresses.
    """

    _GAP = "network or Datadog telemetry missing"

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("CLAUDESEC_DASHBOARD_OFFLINE", "1")
        import dashboard_html_overview
        cls.overview = dashboard_html_overview

    @staticmethod
    def _unreadable_network_dir(dirpath):
        Path(dirpath, "nmap-prod.xml").write_text("<nmaprun><host", encoding="utf-8")
        Path(dirpath, "sslscan-prod.json").write_text("{ truncated", encoding="utf-8")

    def test_unreadable_artifacts_are_dropped_and_announced(self):
        with tempfile.TemporaryDirectory() as d:
            self._unreadable_network_dir(d)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                net = loader.load_network_tool_results(d)
        self.assertEqual(net["nmap_scans"], [])
        self.assertEqual(net["sslscan_results"], [])
        messages = " ".join(str(c.message) for c in caught)
        for name in ("nmap-prod.xml", "sslscan-prod.json"):
            with self.subTest(artifact=name):
                self.assertIn(name, messages)

    def test_unreadable_artifacts_do_not_suppress_the_visibility_gap(self):
        """The assertion that matters. Driven through the real builder."""
        with tempfile.TemporaryDirectory() as d:
            self._unreadable_network_dir(d)
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")
                net = loader.load_network_tool_results(d)
        html = self.overview.build_priority_queue_html([], {}, 0, 0, net, {})
        self.assertIn(self._GAP, html)

    def test_real_evidence_still_suppresses_the_gap(self):
        """DIRECTION check. Over-correcting would report the gap forever, which
        is just as wrong and much noisier."""
        with tempfile.TemporaryDirectory() as d:
            Path(d, "sslscan-good.json").write_text('{"ciphers": []}', encoding="utf-8")
            net = loader.load_network_tool_results(d)
        self.assertEqual(len(net["sslscan_results"]), 1)
        html = self.overview.build_priority_queue_html([], {}, 0, 0, net, {})
        self.assertNotIn(self._GAP, html)

    def test_builder_emits_the_gap_when_there_is_no_evidence_at_all(self):
        """Non-vacuity, by EXECUTION rather than by grepping the source.

        The first draft asserted the string was present in
        `dashboard_html_overview.py`. `test_ci_guard_assertion_scoping` rejected
        that and was right: commenting the control out leaves the token in the
        file, so the check stays green while the control is dead (ADR-001).
        Driving the builder with an empty network/Datadog payload proves the
        string is really emitted, so `assertNotIn` above cannot pass by the
        wording having changed.
        """
        empty_net = loader.load_network_tool_results("/no/such/dir")
        html = self.overview.build_priority_queue_html([], {}, 0, 0, empty_net, {})
        self.assertIn(self._GAP, html)


if __name__ == "__main__":
    unittest.main()
