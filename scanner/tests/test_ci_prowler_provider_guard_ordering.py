"""
Regression guard: `_prowler_provider_available` MUST precede `_prowler_report`
for every provider in `scanner/checks/prowler/integration.sh`.

Background
----------
`integration.sh` (merged in #238) added per-provider availability guards so
the lean container image emits an accurate "not included in this build" skip
instead of the misleading auth-warning that `_prowler_report` emits when it
finds no output file ("Check authentication and permissions for <provider>").
The guard pattern is:

    if ! _prowler_provider_available "<provider>"; then
        skip ...
    else
        ...
        _prowler_report "<provider>" ...
    fi

If a future edit reorders these — placing `_prowler_report` on an earlier line
than the corresponding `_prowler_provider_available` call within the same
provider block — the build-parity fix silently regresses. This test asserts the
ordering at lint-time so that regression is caught before merge.

The shell-level source-ordering assertion lives in
`scanner/tests/test_prowler_provider_build_parity.sh` (#241). This test
promotes the same invariant into the pytest CI-invariant suite alongside the
other `test_ci_*.py` config guards, so it participates in the required
`scanner-unit-tests` CI gate.

Detection strategy
------------------
For each provider section (lines between consecutive `# ── <Label> ──` header
comments or EOF), collect:
  - every line matching `_prowler_provider_available "<provider>"` (guard)
  - every line matching `_prowler_report` (report sink)

Both patterns are matched only in the *provider scan block* that starts at the
`# ── Provider Scans` header — the function *definitions* of
`_prowler_provider_available` and `_prowler_report` appear earlier in the file
and are excluded by scoping to provider sections.

For each provider section that contains both a guard and a report call, the
test asserts: min(guard line numbers) < min(report call line numbers).

Also includes a self-test on a synthetic bad-ordering string to verify the
detector catches a violation (mutation-style, as required by the test suite
conventions).

stdlib-only: no PyYAML, no third-party deps. Runs under pytest (CI) and
`python3 -m unittest`. No network, no subprocess.
"""

import re
import sys
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_inline_comment  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_SH = REPO_ROOT / "scanner" / "checks" / "prowler" / "integration.sh"

# The header comment pattern that separates provider sections.
# Matches lines like:  # ── AWS ──...  or  # ── Microsoft 365 ──...
_SECTION_HEADER_RE = re.compile(r"^# ── ")

# The sentinel header that marks the start of the provider scan block.
# Function *definitions* (_prowler_provider_available, _prowler_report) appear
# before this point and are intentionally excluded.
_PROVIDER_SCANS_HEADER_RE = re.compile(r"^# ── Provider Scans")

# Matches a guard call:  _prowler_provider_available "azure"
# Captures the provider name as group 1.
_GUARD_CALL_RE = re.compile(r'\b_prowler_provider_available\s+"([^"]+)"')

# Matches any report sink call:  _prowler_report "Azure" ...
# We don't need the provider name from the call; we just need the line number.
_REPORT_CALL_RE = re.compile(r'\b_prowler_report\s+')


def _parse_provider_sections(
    text: str,
) -> List[Tuple[str, List[Tuple[str, int]], List[int]]]:
    """Parse integration.sh and return per-section ordering data.

    Returns a list of tuples:
        (section_label, guard_hits, report_line_numbers)
    where:
        section_label       -- the text of the ``# ── <Label> ──`` header (for
                               diagnostics only)
        guard_hits          -- list of (provider_name, line_number) for each
                               _prowler_provider_available call in this section
        report_line_numbers -- list of line numbers for each _prowler_report
                               call in this section

    Only sections at or after the ``# ── Provider Scans`` header are included,
    so function definitions earlier in the file are excluded.
    """
    lines = text.splitlines()
    results: List[Tuple[str, List[Tuple[str, int]], List[int]]] = []

    # Phase 1: find the line index where provider scans begin.
    scan_start = None
    for idx, line in enumerate(lines):
        if _PROVIDER_SCANS_HEADER_RE.match(line):
            scan_start = idx
            break

    if scan_start is None:
        # Cannot locate the provider scan block — return empty so the
        # existence test catches it.
        return results

    # Phase 2: split lines from scan_start onward into sections delimited by
    # `# ── ... ──` headers, then extract guard/report hits per section.
    current_label: str = ""
    current_guards: List[Tuple[str, int]] = []
    current_reports: List[int] = []

    def _flush(
        label: str,
        guards: List[Tuple[str, int]],
        reports: List[int],
    ) -> None:
        if label and (guards or reports):
            results.append((label, guards[:], reports[:]))

    for idx in range(scan_start, len(lines)):
        raw = lines[idx]
        lineno = idx + 1  # 1-based

        # Section headers ARE comments (`# ── AWS ──`), so detect them on the RAW
        # line. For guard/report CALL detection, ignore comment content (F-8):
        # skip whole-line comments and strip trailing inline comments, so a guard
        # surviving only in a comment cannot mask a real guard that is now after
        # the report (which would skew the min(guard)<min(report) ordering check).
        if _SECTION_HEADER_RE.match(raw):
            _flush(current_label, current_guards, current_reports)
            current_label = raw.strip()
            current_guards = []
            current_reports = []
            continue

        active = "" if raw.lstrip().startswith("#") else strip_inline_comment(raw)

        m = _GUARD_CALL_RE.search(active)
        if m:
            current_guards.append((m.group(1), lineno))

        if _REPORT_CALL_RE.search(active):
            current_reports.append(lineno)

    _flush(current_label, current_guards, current_reports)
    return results


class TestProwlerProviderGuardOrdering(unittest.TestCase):
    """Assert ``_prowler_provider_available`` precedes ``_prowler_report`` in
    every provider section of integration.sh."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text: str = (
            INTEGRATION_SH.read_text(encoding="utf-8")
            if INTEGRATION_SH.is_file()
            else ""
        )
        cls.sections = _parse_provider_sections(cls.text)

    def test_integration_sh_exists(self) -> None:
        self.assertTrue(
            INTEGRATION_SH.is_file(),
            f"integration.sh not found at {INTEGRATION_SH} — path assumption broke",
        )

    def test_provider_scans_block_found(self) -> None:
        """The ``# ── Provider Scans`` sentinel must exist so the scoped parse
        cannot silently pass on a restructured file."""
        self.assertTrue(
            re.search(r"^# ── Provider Scans", self.text, re.MULTILINE) is not None,
            "Could not find '# ── Provider Scans' header in integration.sh — "
            "the file structure changed and this guard needs to be updated.",
        )

    def test_sections_detected(self) -> None:
        """At least one provider section with both guard and report calls must
        be detected — a zero count means the parser regressed."""
        sections_with_both = [
            label
            for label, guards, reports in self.sections
            if guards and reports
        ]
        self.assertGreater(
            len(sections_with_both),
            0,
            "No provider sections with both a guard and a report call were "
            "found — the section parser may have broken.",
        )

    def test_guard_precedes_report_in_every_provider_section(self) -> None:
        """For every provider section that contains both a
        ``_prowler_provider_available`` guard call and a ``_prowler_report``
        call, the earliest guard line must precede the earliest report line."""
        violations: List[str] = []

        for section_label, guards, reports in self.sections:
            if not guards or not reports:
                # Section has only one type — ordering is not applicable.
                continue

            first_guard_lineno = min(lineno for _, lineno in guards)
            first_report_lineno = min(reports)

            if first_guard_lineno >= first_report_lineno:
                providers_in_section = ", ".join(
                    f'"{p}" (line {ln})' for p, ln in guards
                )
                violations.append(
                    f"  Section {section_label!r}: "
                    f"_prowler_report at line {first_report_lineno} appears "
                    f"BEFORE _prowler_provider_available guard "
                    f"[{providers_in_section}] at line {first_guard_lineno}. "
                    f"The availability guard MUST run first so a stripped "
                    f"provider emits an accurate skip instead of a misleading "
                    f"auth warning (#238)."
                )

        self.assertEqual(
            violations,
            [],
            "_prowler_provider_available guard ordering violated:\n"
            + "\n".join(violations),
        )


class TestProviderGuardOrderingDetectorSelfTest(unittest.TestCase):
    """Mutation-style self-test: verify the detector catches a bad ordering.

    Synthetic integration.sh content is constructed with ``_prowler_report``
    appearing BEFORE ``_prowler_provider_available`` for a provider, and the
    test asserts ``_parse_provider_sections`` + ordering logic flags it.
    """

    # A minimal synthetic script fragment that mirrors integration.sh structure.
    # The `_prowler_report` call appears at an earlier line than the guard.
    # This is the bad-ordering (report before guard) the detector must catch.
    _BAD_ORDERING = """\
#!/usr/bin/env bash
# ── Provider Scans ──────────────────────────────────────────────────────────

# ── Fake Provider ────────────────────────────────────────────────────────────

if has_credentials "fakeprovider"; then
  _fake_json=$(_prowler_scan "fakeprovider")
  _prowler_report "FakeProvider" "$_fake_json" "PROWLER-FAKE"
else
  if ! _prowler_provider_available "fakeprovider"; then
    skip "PROWLER-FAKE-001" "Fake scan" "Provider not in this build."
  fi
fi
"""

    # Good ordering: guard before report.
    _GOOD_ORDERING = """\
#!/usr/bin/env bash
# ── Provider Scans ──────────────────────────────────────────────────────────

# ── Fake Provider ────────────────────────────────────────────────────────────

if ! _prowler_provider_available "fakeprovider"; then
  skip "PROWLER-FAKE-001" "Fake scan" "Provider not in this build."
else
  _fake_json=$(_prowler_scan "fakeprovider")
  _prowler_report "FakeProvider" "$_fake_json" "PROWLER-FAKE"
fi
"""

    def _check_ordering(self, text: str) -> List[str]:
        """Run the ordering check and return violation strings (empty = pass)."""
        sections = _parse_provider_sections(text)
        violations: List[str] = []
        for section_label, guards, reports in sections:
            if not guards or not reports:
                continue
            first_guard = min(ln for _, ln in guards)
            first_report = min(reports)
            if first_guard >= first_report:
                violations.append(
                    f"section={section_label!r} "
                    f"guard_line={first_guard} report_line={first_report}"
                )
        return violations

    def test_bad_ordering_is_detected(self) -> None:
        """The detector MUST flag a report call that precedes its guard."""
        violations = self._check_ordering(self._BAD_ORDERING)
        self.assertTrue(
            violations,
            "Detector did NOT catch the bad ordering (report before guard). "
            "The invariant check is broken — it would silently pass on a real "
            "regression.",
        )

    def test_good_ordering_is_not_flagged(self) -> None:
        """The detector must NOT raise a false positive for correct ordering."""
        violations = self._check_ordering(self._GOOD_ORDERING)
        self.assertEqual(
            violations,
            [],
            "Detector raised a false positive on correctly-ordered content: "
            + str(violations),
        )

    # F-8: a guard COMMENTED OUT above the report must not mask a real guard that
    # now sits AFTER the report. Without comment-stripping, the commented guard's
    # earlier line number satisfies min(guard)<min(report) and the bug hides.
    _COMMENTED_GUARD_MASKS_BAD_ORDER = """\
#!/usr/bin/env bash
# ── Provider Scans ──────────────────────────────────────────────────────────

# ── Fake Provider ────────────────────────────────────────────────────────────

# _prowler_provider_available "fakeprovider"   # decoy: guard only in a comment
_fake_json=$(_prowler_scan "fakeprovider")
_prowler_report "FakeProvider" "$_fake_json" "PROWLER-FAKE"
_prowler_provider_available "fakeprovider"
"""

    def test_commented_guard_does_not_mask_bad_ordering(self) -> None:
        violations = self._check_ordering(self._COMMENTED_GUARD_MASKS_BAD_ORDER)
        self.assertTrue(
            violations,
            "F-8: a guard surviving only in a comment masked a real guard placed "
            "AFTER the report — the ordering check was evaded.",
        )


if __name__ == "__main__":
    unittest.main()
