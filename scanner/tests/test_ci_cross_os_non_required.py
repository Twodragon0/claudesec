"""
Regression guard: the cross-OS live-runner workflow must stay NON-REQUIRED.

`.github/workflows/cross-os-checks.yml` runs the macOS CIS / Windows KISA scanner
checks on real `macos-latest` / `windows-latest` runners. Those runners are
expensive (macOS billed 10x, Windows 2x Linux) and their verdicts depend on
uncontrolled runner state, so the workflow is INTENTIONALLY informational: it is
a standalone workflow, NOT wired into `lint.yml`'s required `lint-gate` pipeline,
and its jobs are NOT branch-protection required contexts. Branch protection
requires only `Lint` (lint-gate) + `Security Scan Gate`.

The silent-weakening this guards: someone folds the OS-runner jobs into `lint.yml`
(or adds them to `lint-gate.needs`), making every PR merge-block on a flaky,
costly cross-OS run. Branch-protection config lives in GitHub settings (not the
repo), so the strongest STATIC proxy is: the OS-runner workflow stays a separate
file, and `lint.yml` never references it or its OS runners.

stdlib-only (regex/line scanning, no PyYAML — not installed in the
`scanner-unit-tests` job). No network/subprocess. Passes under pytest and
`python3 -m unittest`.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
CROSS_OS_YML = WORKFLOW_DIR / "cross-os-checks.yml"
LINT_YML = WORKFLOW_DIR / "lint.yml"

# Tokens that, if they appear in lint.yml, would mean the OS-runner jobs were
# pulled into the required lint pipeline (the exact regression this guards).
FORBIDDEN_IN_LINT = ("cross-os", "live-os-checks", "macos-latest", "windows-latest")


class TestCrossOsWorkflowNonRequired(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cross = CROSS_OS_YML.read_text(encoding="utf-8") if CROSS_OS_YML.is_file() else ""
        cls.lint = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_cross_os_workflow_exists(self):
        # Canary: a moved/renamed file should fail loudly here, not vacuously.
        self.assertTrue(
            CROSS_OS_YML.is_file(),
            f"{CROSS_OS_YML} not found — if the cross-OS workflow was renamed, "
            "update CROSS_OS_YML and FORBIDDEN_IN_LINT in this guard.",
        )

    def test_cross_os_is_a_standalone_informational_lane(self):
        # workflow_dispatch + schedule are the informational triggers that mark
        # this as a non-PR-gating lane; their presence confirms intent.
        self.assertRegex(
            self.cross,
            r"(?m)^\s*workflow_dispatch:\s*$",
            "cross-os-checks.yml lost its workflow_dispatch trigger — it should "
            "remain a standalone, manually/scheduled informational lane.",
        )
        self.assertIn(
            "macos-latest",
            self.cross,
            "cross-os-checks.yml no longer references an OS runner — parsing/intent broke.",
        )

    def test_lint_yml_does_not_absorb_cross_os(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")
        hits = [tok for tok in FORBIDDEN_IN_LINT if tok in self.lint]
        self.assertEqual(
            hits,
            [],
            "lint.yml now references the cross-OS live-runner workflow / OS runners "
            f"({', '.join(hits)}). That would make the expensive, flaky macOS/Windows "
            "runs part of the REQUIRED lint pipeline and block merges. Keep cross-OS "
            "checks in their own non-required workflow. If this is truly intended, "
            "update FORBIDDEN_IN_LINT here with a justification.",
        )

    def test_cross_os_job_names_do_not_collide_with_required_contexts(self):
        # Required contexts are "Lint" and "Security Scan Gate". A cross-OS job
        # display name matching either would let it masquerade as a required check.
        for ctx in ("Security Scan Gate",):
            self.assertNotRegex(
                self.cross,
                rf"(?m)^\s*name:\s*{re.escape(ctx)}\s*$",
                f"A cross-OS job is named '{ctx}', colliding with a required "
                "branch-protection context. Rename it.",
            )


if __name__ == "__main__":
    unittest.main()
