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
    explicit_key_lines,
    strip_comment_lines,
    strip_inline_comment,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
CROSS_OS_YML = WORKFLOW_DIR / "cross-os-checks.yml"
LINT_YML = WORKFLOW_DIR / "lint.yml"

# Name tokens that, if they appear in lint.yml, mean the OS-runner jobs were
# pulled into the required lint pipeline (the exact regression this guards).
FORBIDDEN_NAME_TOKENS = ("cross-os", "live-os-checks")
# Any macOS/Windows runner label, VERSION-AGNOSTIC and case-INSENSITIVE —
# `macos-latest`, `macos-14`, `macOS-14`, `windows-latest`, `windows-2022`, …
# GitHub runner labels are case-insensitive, so `macOS-14` is the same runner as
# `macos-14` (without IGNORECASE the capitalized form evaded — ADR-001 §3). The
# hyphen is required so it never matches a test-script name like
# `test_check_macos_cis_security.sh` (`macos_`) or a path `macos/cis-security`.
_OS_RUNNER_RE = re.compile(r"\b(?:macos|windows)-[a-z0-9.]+\b", re.IGNORECASE)

# A runner label only counts when it appears in a RUNNER context — a `runs-on:`
# key or a matrix `os:` key (scalar, flow-array, or block-list items) — NOT in
# arbitrary `run:`/`name:` text. `windows-1252` (a charset) and `macos-universal`
# (a build arch) share the runner-label SHAPE but are not runners; scoping to the
# context is the only way to exclude them without also dropping real `<os>-<ver>`
# labels, since a charset like `windows-1252` is indistinguishable by shape from a
# version like `windows-2022` (ADR-001 §3 false-positive finding).
# The `runs-on:`/`os:` key is read bare OR quoted: `"runs-on": macos-14` selects
# the same runner, and the bare-only regex let it become a REQUIRED merge gate
# with this guard green (2026-08-06 sweep). See yaml_key_pattern.
_RUNNER_KEY_RE = re.compile(
    rf"^(\s*)(?:{yaml_key_pattern('runs-on')}|{yaml_key_pattern('os')})\s*:(.*)$"
)
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s*(.+)$")

# Required branch-protection contexts a cross-OS job name must NOT collide with.
REQUIRED_CONTEXTS = ("Lint", "Security Scan Gate")


def _lint_absorption_hits(lint_text: str) -> list:
    """OS-runner / cross-OS references in lint.yml, comment-immune and context-
    scoped. Whole-line AND trailing inline `#` comments are stripped first (a
    prose mention of a runner can't false-positive), then OS-runner labels are
    collected ONLY from `runs-on:`/matrix `os:` contexts (scalar, flow-array, or
    a following block list) so a charset/arch token in `run:`/`name:` text does
    not false-trip this REQUIRED-lint guard, while the match stays version- and
    case-agnostic. FORBIDDEN_NAME_TOKENS stay a whole-text scan (job/workflow
    references, not runner labels)."""
    lines = [
        strip_inline_comment(ln) for ln in strip_comment_lines(lint_text).splitlines()
    ]
    labels: list = []
    in_os_list, key_indent = False, -1
    for ln in lines:
        key = _RUNNER_KEY_RE.match(ln)
        if key:
            key_indent = len(key.group(1))
            labels += _OS_RUNNER_RE.findall(key.group(2))  # scalar or flow-array
            in_os_list = key.group(2).strip() == ""  # bare key may head a block list
            continue
        if in_os_list:
            item = _LIST_ITEM_RE.match(ln)
            if item and len(item.group(1)) >= key_indent:
                labels += _OS_RUNNER_RE.findall(item.group(2))
                continue
            if ln.strip():  # a non-list, non-blank line ends the block
                in_os_list = False
    text = "\n".join(lines)
    hits = [tok for tok in FORBIDDEN_NAME_TOKENS if tok in text]
    hits += sorted(set(labels))
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
            # Key AND value may be quoted — `"name": "Lint"` is the same display
            # name, so a bare-only pattern let the masquerade through.
            self.assertNotRegex(
                self.cross,
                rf"""(?m)^\s*{yaml_key_pattern('name')}\s*:\s*["']?{re.escape(ctx)}["']?\s*$""",
                f"A cross-OS job is named '{ctx}', colliding with a required "
                "branch-protection context. Rename it.",
            )
            self.assertEqual(
                explicit_key_lines(self.cross, "name", "runs-on"),
                [],
                "A `name:`/`runs-on:` key in cross-os-checks.yml uses YAML's "
                "explicit-key form (`? key` / `: value`), which no matcher here "
                "can read. Use the ordinary `key: value` form.",
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

    def test_capitalized_runner_is_detected(self):
        # GitHub runner labels are case-INSENSITIVE; `macOS-14` is the same runner
        # as `macos-14`. A case-sensitive match lets the capitalized form evade.
        mutant = "name: Lint\njobs:\n  os:\n    runs-on: macOS-14\n"
        hits = _lint_absorption_hits(mutant)
        self.assertIn("macOS-14", hits, "capitalized `macOS-14` runner evaded the guard")

    def test_array_runs_on_capitalized_is_detected(self):
        # Flow-array runs-on with a capitalized label must still be caught.
        mutant = (
            "name: Lint\njobs:\n  os:\n"
            "    runs-on: [self-hosted, macOS-latest]\n"
        )
        self.assertIn("macOS-latest", _lint_absorption_hits(mutant))

    def test_block_style_matrix_os_is_detected(self):
        # Block-style matrix `os:` list (not just flow `[...]`) must be scanned.
        mutant = (
            "name: Lint\njobs:\n  os-matrix:\n    strategy:\n      matrix:\n"
            "        os:\n          - macos-14\n          - windows-2022\n"
            "    runs-on: ${{ matrix.os }}\n"
        )
        hits = _lint_absorption_hits(mutant)
        self.assertIn("macos-14", hits)
        self.assertIn("windows-2022", hits)

    def test_charset_and_arch_tokens_are_not_flagged(self):
        # `windows-1252` (charset) and `macos-universal` (arch) share the runner
        # label SHAPE but live in `run:`/`name:` text, not a runner context. The
        # match must be scoped so they do not false-trip the REQUIRED lint guard.
        clean = (
            "name: Lint\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: iconv -f windows-1252 in.txt > out.txt\n"
            "      - name: Build macos-universal bundle\n"
        )
        self.assertEqual(
            _lint_absorption_hits(clean), [],
            "a charset/arch token (windows-1252 / macos-universal) in run:/name: "
            "text false-tripped the required-lint OS-runner guard.",
        )

    def test_lint_named_cross_os_job_collides(self):
        # A cross-OS job named exactly "Lint" must be caught (the omitted context).
        mutant = "jobs:\n  live-os-checks:\n    name: Lint\n    runs-on: macos-14\n"
        self.assertRegex(mutant, r"(?m)^\s*name:\s*Lint\s*$")
        self.assertIn("Lint", REQUIRED_CONTEXTS)


if __name__ == "__main__":
    unittest.main()
