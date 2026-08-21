"""
Regression test: lock the scan baseline to grade A.

WHAT WAS WRONG WITH THIS FILE
-----------------------------
It read ``scan-report.json`` from the repo root and asserted a ``summary`` /
``results`` shape. Both halves were broken, in opposite directions:

1. **Wrong file.** ``scanner/claudesec`` emits TWO incompatible JSON documents
   for the same scan. ``scan -f json`` produces
   ``{"summary": {...}, "results": [...]}`` — exactly the shape asserted here.
   The persisted ``scan-report.json`` (written by ``print_json_summary`` on the
   dashboard path) is FLAT: ``{"passed", "failed", ..., "findings"}``, with
   ``findings`` carrying ``severity`` rather than ``status``. So the assertions
   were written against the CLI output and pointed at the persisted file:
   ``KeyError: 'summary'`` on the first line of ``setUp`` whenever a report
   existed.

2. **Never ran anyway.** It skipped itself when the file was absent — and
   ``scan-report.json`` is gitignored, so in CI it is ALWAYS absent. The class
   had never executed there. A test that cannot fail is not a lock; the grade-A
   baseline it advertises was never enforced. (``score >= 100`` was also
   unreachable in practice: the score is 0-100 and a full scan of this repo
   measures 90.)

HOW IT RUNS NOW
---------------
CI generates the report explicitly with ``scan -f json -o <file>`` — a flag that
until now parsed its argument, printed "Report saved to <file>", and wrote
nothing — and sets ``CLAUDESEC_REQUIRE_BASELINE=1``. With that variable set a
MISSING report is a FAILURE rather than a skip, which is the only thing that
stops this file from silently going dark again. Locally, without the variable,
it still skips so a fresh clone is not blocked.

Thresholds are floors, not the measured values, so ordinary CI variance (a
linter absent on the runner turning a pass into a skip) does not produce a red
build. ``failed == 0`` is the assertion that actually carries the baseline.

Security baseline references:
- OWASP Top 10 (https://owasp.org/www-project-top-ten/)
- NIST SP 800-53 Rev 5 — the scanner control mapping tracks NIST controls.
"""

import json
import os
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Distinct from the flat ``scan-report.json`` on purpose: the two files carry
# different schemas, and pointing a schema-specific test at a shared name is
# what produced the KeyError above.
_REPORT_PATH = Path(
    os.environ.get(
        "CLAUDESEC_BASELINE_REPORT", str(_REPO_ROOT / "scan-report-baseline.json")
    )
)
_REQUIRED = os.environ.get("CLAUDESEC_REQUIRE_BASELINE") == "1"


def _load_report():
    if not _REPORT_PATH.exists():
        return None
    with _REPORT_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


_REPORT = _load_report()
_SKIP_REASON = (
    f"{_REPORT_PATH} not found — generate it with "
    "`scanner/claudesec scan -f json -o scan-report-baseline.json`, or set "
    "CLAUDESEC_REQUIRE_BASELINE=1 to make its absence fatal (CI does)."
)


class TestBaselineReportIsPresent(unittest.TestCase):
    """Absence is fatal where the report is supposed to exist.

    Without this, the whole file reverts to the failure mode it is being fixed
    for: green because nothing ran.
    """

    def test_report_exists_when_required(self):
        if not _REQUIRED:
            self.skipTest("CLAUDESEC_REQUIRE_BASELINE is not set (local run)")
        self.assertIsNotNone(
            _REPORT,
            f"CLAUDESEC_REQUIRE_BASELINE=1 but no report at {_REPORT_PATH}. The "
            "generating step did not run, or `-o` silently wrote nothing again.",
        )


@unittest.skipIf(_REPORT is None, _SKIP_REASON)
class TestScanReportBaseline(unittest.TestCase):
    """Assert the report meets the grade-A baseline."""

    def setUp(self):
        self.summary = _REPORT["summary"]
        self.results = _REPORT.get("results", [])

    # ── the scan actually happened ────────────────────────────────────────

    def test_report_is_not_vacuous(self):
        # A zero-check report would satisfy every assertion below. This is the
        # positive control for all of them.
        self.assertGreater(
            self.summary.get("total", 0), 0, "report contains zero checks"
        )
        self.assertTrue(self.results, "report contains no per-check results")

    def test_summary_has_the_documented_shape(self):
        # Pins the CONTRACT, so a future change to `-f json` that renames or
        # nests these keys fails here rather than silently skipping.
        for key in (
            "total",
            "passed",
            "failed",
            "warnings",
            "skipped",
            "score",
            "grade",
        ):
            self.assertIn(key, self.summary, f"summary is missing {key!r}")
        for result in self.results:
            self.assertIn("id", result)
            self.assertIn("status", result)

    # ── summary assertions ───────────────────────────────────────────────

    def test_grade_is_A(self):
        self.assertEqual(
            self.summary["grade"],
            "A",
            f"expected grade 'A', got {self.summary['grade']!r}",
        )

    def test_failed_is_zero(self):
        self.assertEqual(
            self.summary["failed"],
            0,
            f"expected 0 failed checks, got {self.summary['failed']}",
        )

    def test_score_at_least_90(self):
        # Floor, not the measured value (97 for access-control,cicd,code on
        # 2026-08-14). `>= 100` was the old assertion and is unreachable for any
        # scope that carries a single warning.
        self.assertGreaterEqual(
            self.summary["score"],
            90,
            f"expected score >= 90, got {self.summary['score']}",
        )

    def test_passed_at_least_20(self):
        self.assertGreaterEqual(
            self.summary["passed"],
            20,
            f"expected >= 20 passed checks, got {self.summary['passed']}",
        )

    # ── per-result assertions ────────────────────────────────────────────

    def test_no_result_has_status_fail(self):
        failed = [r for r in self.results if r.get("status") == "fail"]
        self.assertEqual(
            failed,
            [],
            f"{len(failed)} result(s) with status='fail': "
            + ", ".join(r.get("id", "<no-id>") for r in failed),
        )


if __name__ == "__main__":
    unittest.main()
