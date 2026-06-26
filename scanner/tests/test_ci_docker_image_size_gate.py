"""
Regression guard for the Docker image-size gate in
`.github/workflows/lint.yml` (the `dashboard-regression-check` job).

The scanner runtime image was reduced from ~1.47 GB to ~513 MB by stripping
unused prowler cloud-provider SDKs in cycle #217-#237. The `max_mb=N` check in
the "Check image size" step is the only thing keeping that win from silently
regressing — e.g. re-adding a stripped provider (~700 MB) or loosening the cap
back toward the old 1.8 GB.

This test asserts the gate is PRESENT and has NOT been loosened above the
locked-in ceiling:

- `max_mb = N`, N <= 600

Semantics are `<=`, not `==`: tightening the cap DOWN is allowed (and should not
break this test), but loosening or removing it trips the guard. If you
intentionally raise the cap (e.g. a justified trivy/kubectl bump), update
MAX_IMAGE_SIZE_MB here in the same PR and explain why.

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

# Maximum acceptable image-size cap (MB). Lower this freely; raise it ONLY in
# the same PR that raises the matching `max_mb` in lint.yml, with rationale.
MAX_IMAGE_SIZE_MB = 600


def active_text(text):
    """`text` with whole-line AND trailing-inline `#` comments removed, so a
    cap value surviving only in a comment cannot satisfy the gate check
    (comment-evasion false-negative class)."""
    return "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )


class TestCiDockerImageSizeGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.text = active_text(raw)

    def test_lint_yml_exists(self):
        self.assertTrue(
            LINT_YML.is_file(),
            f"CI workflow not found at {LINT_YML} — path assumption broke",
        )

    def test_image_size_cap_present_and_not_loosened(self):
        matches = [int(m) for m in re.findall(r"max_mb\s*=\s*(\d+)", self.text)]
        self.assertTrue(
            matches,
            "No `max_mb=N` found in lint.yml — the Docker image-size gate has "
            "been removed (the dashboard-regression-check size check).",
        )
        worst = max(matches)
        self.assertLessEqual(
            worst,
            MAX_IMAGE_SIZE_MB,
            f"Docker image-size cap loosened to {worst} MB (max allowed "
            f"{MAX_IMAGE_SIZE_MB} MB). Re-adding a stripped prowler provider or "
            f"reverting toward the old 1.8 GB cap would slip through. If "
            f"intentional, update MAX_IMAGE_SIZE_MB in this test and justify in "
            f"the PR.",
        )

    def test_size_check_fails_build_on_breach(self):
        # The gate must actually fail the job (`exit 1`) when the cap is
        # exceeded — a cap that only echoes is not a gate.
        self.assertRegex(
            self.text,
            r"size_mb\b.*-gt.*max_mb",
            "The image-size step must compare size_mb against max_mb (the "
            "`[ size_mb -gt max_mb ]` breach check).",
        )
        self.assertIn(
            "exit 1",
            self.text,
            "The image-size step must `exit 1` on breach so the build fails.",
        )


class TestImageSizeCommentEvasion(unittest.TestCase):
    """A cap surviving only in a comment must not satisfy the gate."""

    def test_commented_cap_is_not_counted(self):
        mutant = "# max_mb=9999\nrun: echo hi  # max_mb=9999"
        scan = active_text(mutant)
        self.assertEqual(
            re.findall(r"max_mb\s*=\s*(\d+)", scan),
            [],
            "comment-evasion: a `max_mb=` surviving only in a whole-line or "
            "trailing comment must NOT count as an active size gate.",
        )

    def test_active_cap_is_counted(self):
        scan = active_text("          max_mb=600")
        self.assertEqual(re.findall(r"max_mb\s*=\s*(\d+)", scan), ["600"])


if __name__ == "__main__":
    unittest.main()
