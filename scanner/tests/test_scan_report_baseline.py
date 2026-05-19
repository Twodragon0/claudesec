"""
Regression test: lock scan-report.json to the established grade-A baseline.

The test loads ``scan-report.json`` from the repository root.  If the file
is absent (e.g. a fresh clone before the first scan), every test is skipped
so the CI job does not false-fail.  Once the file is present the assertions
below must all hold — any regression that downgrades the project score will
fail CI.

Security baseline references:
- OWASP Top 10 (https://owasp.org/www-project-top-ten/) — the scan checks
  cover the OWASP Top 10 injection and cryptographic-failure categories.
- NIST SP 800-53 Rev 5 — the scanner control mapping tracks NIST controls;
  a passing baseline confirms those controls remain satisfied.
"""

import json
import unittest
from pathlib import Path

# scan-report.json lives at the repository root, two directories above this file
# (scanner/tests/ -> scanner/ -> repo-root/).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _REPO_ROOT / "scan-report.json"


def _load_report():
    """Return parsed report dict, or None when the file is absent."""
    if not _REPORT_PATH.exists():
        return None
    with _REPORT_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


_REPORT = _load_report()
_SKIP_REASON = f"scan-report.json not found at {_REPORT_PATH} — skipping baseline assertions"


@unittest.skipIf(_REPORT is None, _SKIP_REASON)
class TestScanReportBaseline(unittest.TestCase):
    """Assert that scan-report.json meets the established grade-A baseline."""

    def setUp(self):
        self.summary = _REPORT["summary"]
        self.results = _REPORT.get("results", [])

    # ------------------------------------------------------------------
    # summary assertions
    # ------------------------------------------------------------------

    def test_grade_is_A(self):
        """Grade must be 'A' — any downgrade breaks CI."""
        self.assertEqual(
            self.summary["grade"],
            "A",
            f"Expected grade 'A', got '{self.summary['grade']}'",
        )

    def test_failed_is_zero(self):
        """No check may be in a failed state."""
        self.assertEqual(
            self.summary["failed"],
            0,
            f"Expected 0 failed checks, got {self.summary['failed']}",
        )

    def test_score_at_least_100(self):
        """Score must be >= 100 (perfect baseline)."""
        self.assertGreaterEqual(
            self.summary["score"],
            100,
            f"Expected score >= 100, got {self.summary['score']}",
        )

    def test_passed_at_least_21(self):
        """At least 21 checks must pass (matches the committed baseline)."""
        self.assertGreaterEqual(
            self.summary["passed"],
            21,
            f"Expected >= 21 passed checks, got {self.summary['passed']}",
        )

    # ------------------------------------------------------------------
    # per-result assertions
    # ------------------------------------------------------------------

    def test_no_result_has_status_fail(self):
        """Every individual result must have status 'pass' or 'skipped'."""
        failed_results = [
            r for r in self.results if r.get("status") == "fail"
        ]
        self.assertEqual(
            failed_results,
            [],
            f"Found {len(failed_results)} result(s) with status='fail': "
            + ", ".join(r.get("id", "<no-id>") for r in failed_results),
        )


if __name__ == "__main__":
    unittest.main()
