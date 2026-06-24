"""
Regression guard for the CI coverage gate thresholds in
`.github/workflows/lint.yml`.

These constants are the only thing standing between a coverage regression and a
green build. They have been silently weakened/desynced before (see the kcov
path-discovery incident, PRs #119/#120, and the floor lineage in the
`kcov-debug` skill). This test asserts the two enforced thresholds are still
PRESENT and have not been lowered:

- Python (`scanner-unit-tests`): `--cov-fail-under=N`, N >= 99
- Bash   (`scanner-shell-coverage`): `threshold = X.0`, X >= 90

Semantics are `>=`, not `==`: ratcheting a floor UP is allowed (and should not
break this test), but lowering or removing a gate trips it. If you intentionally
raise a floor, this test keeps passing; if you intentionally LOWER one, update
the corresponding minimum here in the same PR and explain why.

stdlib-only; passes under pytest (the CI runner) and `python3 -m unittest`.
No network, no subprocess.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines, strip_inline_comment  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

# Minimum acceptable enforced floors. Raise these ONLY in the same PR that
# raises the matching value in lint.yml.
MIN_PYTHON_COV_FAIL_UNDER = 99
MIN_BASH_COVERAGE_THRESHOLD = 90.0


def active_text(text):
    """`text` with whole-line AND trailing-inline `#` comments removed, so a
    floor value surviving only in a comment cannot satisfy the gate check
    (comment-evasion false-negative class — F-2)."""
    return "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )


class TestCiCoverageThresholds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.text = active_text(raw)

    def test_lint_yml_exists(self):
        self.assertTrue(
            LINT_YML.is_file(),
            f"CI workflow not found at {LINT_YML} — path assumption broke",
        )

    def test_python_cov_fail_under_present_and_not_lowered(self):
        matches = [int(m) for m in re.findall(r"--cov-fail-under=(\d+)", self.text)]
        self.assertTrue(
            matches,
            "No `--cov-fail-under=N` found in lint.yml — the Python coverage "
            "gate has been removed.",
        )
        worst = min(matches)
        self.assertGreaterEqual(
            worst,
            MIN_PYTHON_COV_FAIL_UNDER,
            f"Python coverage gate lowered to {worst}% (min allowed "
            f"{MIN_PYTHON_COV_FAIL_UNDER}%). If intentional, update "
            f"MIN_PYTHON_COV_FAIL_UNDER in this test and justify in the PR.",
        )

    def test_bash_coverage_threshold_present_and_not_lowered(self):
        matches = [
            float(m) for m in re.findall(r"threshold\s*=\s*(\d+(?:\.\d+)?)", self.text)
        ]
        self.assertTrue(
            matches,
            "No `threshold = X` found in lint.yml — the bash (kcov) coverage "
            "gate has been removed.",
        )
        worst = min(matches)
        self.assertGreaterEqual(
            worst,
            MIN_BASH_COVERAGE_THRESHOLD,
            f"Bash coverage gate lowered to {worst}% (min allowed "
            f"{MIN_BASH_COVERAGE_THRESHOLD}%). If intentional, update "
            f"MIN_BASH_COVERAGE_THRESHOLD in this test and justify in the PR.",
        )


class TestCoverageCommentEvasion(unittest.TestCase):
    """F-2: a floor surviving only in a comment must not satisfy the gate."""

    def test_commented_floor_is_not_counted(self):
        mutant = "# pytest --cov-fail-under=99\nrun: pytest  # was --cov-fail-under=99"
        scan = active_text(mutant)
        self.assertEqual(
            re.findall(r"--cov-fail-under=(\d+)", scan),
            [],
            "comment-evasion: a `--cov-fail-under` surviving only in a whole-line "
            "or trailing comment must NOT count as an active coverage gate.",
        )

    def test_active_floor_is_counted(self):
        scan = active_text("run: pytest --cov-fail-under=99")
        self.assertEqual(re.findall(r"--cov-fail-under=(\d+)", scan), ["99"])


if __name__ == "__main__":
    unittest.main()
