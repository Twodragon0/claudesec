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
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    strip_comment_lines,
    strip_inline_comment,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
CROSS_OS_YML = WORKFLOW_DIR / "cross-os-checks.yml"
LINT_YML = WORKFLOW_DIR / "lint.yml"

# Name tokens that, if they appear in lint.yml, mean the OS-runner jobs were
# pulled into the required lint pipeline (the exact regression this guards).
FORBIDDEN_NAME_TOKENS = ("cross-os", "live-os-checks")
# Any macOS/Windows runner label, VERSION-AGNOSTIC — `macos-latest`, `macos-14`,
# `windows-latest`, `windows-2022`, … The hyphen is required so it never matches
# a test-script name like `test_check_macos_cis_security.sh` (`macos_`) or a path
# like `macos/cis-security` (`macos/`); only real runner labels use `<os>-<ver>`.
_OS_RUNNER_RE = re.compile(r"\b(?:macos|windows)-[a-z0-9.]+\b")

# Required branch-protection contexts a cross-OS job name must NOT collide with.
REQUIRED_CONTEXTS = ("Lint", "Security Scan Gate")


def _lint_absorption_hits(lint_text: str) -> list:
    """OS-runner / cross-OS references in lint.yml, comment-immune. Whole-line
    AND trailing inline `#` comments are stripped so a prose mention of a runner
    can't false-positive, then name tokens + version-agnostic OS runner labels
    are collected."""
    stripped = "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(lint_text).splitlines()
    )
    hits = [tok for tok in FORBIDDEN_NAME_TOKENS if tok in stripped]
    hits += sorted(set(_OS_RUNNER_RE.findall(stripped)))
    return hits


def active_scan(text):
    """`text` with whole-line AND trailing inline `#` comments removed.

    The runner label lives in a YAML `runs-on:` value, so the whitespace-boundary
    `strip_inline_comment` is the correct stripper here (`;#` is literal scalar
    content in YAML, not a comment). Without stripping, the presence check below
    is satisfied by a commented-out `runs-on: macos-latest` and goes inert."""
    return "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )


class TestCrossOsWorkflowNonRequired(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cross = CROSS_OS_YML.read_text(encoding="utf-8") if CROSS_OS_YML.is_file() else ""
        cls.cross_scan = active_scan(cls.cross)
        cls.lint = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_cross_os_workflow_exists(self):
        # Canary: a moved/renamed file should fail loudly here, not vacuously.
        self.assertTrue(
            CROSS_OS_YML.is_file(),
            f"{CROSS_OS_YML} not found — if the cross-OS workflow was renamed, "
            "update CROSS_OS_YML in this guard.",
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
            self.cross_scan,
            "cross-os-checks.yml no longer references an OS runner — parsing/intent broke.",
        )

    def test_lint_yml_does_not_absorb_cross_os(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")
        hits = _lint_absorption_hits(self.lint)
        self.assertEqual(
            hits,
            [],
            "lint.yml now references the cross-OS live-runner workflow / OS runners "
            f"({', '.join(hits)}). That would make the expensive, flaky macOS/Windows "
            "runs part of the REQUIRED lint pipeline and block merges. Keep cross-OS "
            "checks in their own non-required workflow. The OS-runner match is "
            "version-agnostic (macos-14/windows-2022 etc.), so a version-bumped "
            "label cannot slip past.",
        )

    def test_cross_os_job_names_do_not_collide_with_required_contexts(self):
        # A cross-OS job display name matching EITHER required context
        # ("Lint" or "Security Scan Gate") would let it masquerade as a required
        # check — both must be checked (the audit found "Lint" was omitted).
        for ctx in REQUIRED_CONTEXTS:
            self.assertNotRegex(
                self.cross,
                rf"(?m)^\s*name:\s*{re.escape(ctx)}\s*$",
                f"A cross-OS job is named '{ctx}', colliding with a required "
                "branch-protection context. Rename it.",
            )



class TestCrossOsScanScoping(unittest.TestCase):
    """`macos-latest` was asserted against the RAW workflow text, so a
    commented-out `runs-on:` kept the check green (inert)."""

    def test_commented_runner_is_not_counted(self):
        for mutant in ("        # runs-on: macos-latest",
                       "        runs-on: ubuntu-latest  # was macos-latest"):
            with self.subTest(mutant=mutant):
                self.assertNotIn("macos-latest", active_scan(mutant))

    def test_live_runner_is_counted(self):
        self.assertIn("macos-latest", active_scan("        runs-on: macos-latest"))


class TestCrossOsGuardSelfTest(unittest.TestCase):
    """Mutation self-tests for the version-agnostic / both-contexts hardening."""

    def test_version_pinned_runner_is_detected(self):
        # The audit bypass: fold OS jobs in with `macos-14`/`windows-2022` labels
        # that the old fixed `macos-latest`/`windows-latest` list missed.
        mutant = (
            "name: Lint\njobs:\n  lint-gate:\n    needs: [os-matrix]\n"
            "  os-matrix:\n    strategy:\n      matrix:\n"
            "        os: [macos-14, windows-2022]\n    runs-on: ${{ matrix.os }}\n"
        )
        hits = _lint_absorption_hits(mutant)
        self.assertIn("macos-14", hits)
        self.assertIn("windows-2022", hits)

    def test_prose_comment_runner_is_not_flagged(self):
        # A commented-out runner label must NOT trip the guard (comment-immune).
        clean = (
            "name: Lint\njobs:\n"
            "  test:\n    runs-on: ubuntu-latest  # not macos-14, never\n"
            "    steps:\n      - run: bash scanner/tests/test_check_macos_cis.sh\n"
        )
        self.assertEqual(_lint_absorption_hits(clean), [])

    def test_lint_named_cross_os_job_collides(self):
        # A cross-OS job named exactly "Lint" must be caught (the omitted context).
        mutant = "jobs:\n  live-os-checks:\n    name: Lint\n    runs-on: macos-14\n"
        self.assertRegex(mutant, r"(?m)^\s*name:\s*Lint\s*$")
        self.assertIn("Lint", REQUIRED_CONTEXTS)


if __name__ == "__main__":
    unittest.main()
