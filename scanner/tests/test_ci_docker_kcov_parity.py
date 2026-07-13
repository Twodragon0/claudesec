"""
Regression guard: the local Docker kcov harness (`scripts/verify-shell-coverage-docker.sh`)
stays in sync with the CI `scanner-shell-coverage` job in `.github/workflows/lint.yml`.

Background
----------
`verify-shell-coverage-docker.sh` exists to reproduce the CI bash-coverage gate
locally (kcov is Linux/ptrace-only, so macOS devs run it in a container). Its
whole value is being CI-exact: it declares `INCLUDE=`, `EXCLUDE=`, and `FLOOR=`
that MUST match the `--include-pattern` / `--exclude-pattern` and coverage
threshold the CI job uses. When they drift, the local harness silently measures
a different set of files (or floor) than CI, so a dev can see "PASS locally" for
a change CI then rejects — or, worse, the harness's lax patterns pass a change
that craters real CI coverage.

This drift has already happened: PR #336 found the local `INCLUDE` was missing
`checks_credentials.sh` (present in CI since the credentials split), and had to
add `test_run_category_checks.sh` to `EXCLUDE` in BOTH places at once. Nothing
prevented the next divergence — this guard does.

The load-bearing invariants:
  1. The docker script's `INCLUDE` == CI's `--include-pattern` (as a set).
  2. The docker script's `EXCLUDE` == CI's `--exclude-pattern` (as a set).
  3. The docker script's `FLOOR` == CI's enforced coverage threshold.
  4. CI's own tty and non-tty kcov invocations use identical include/exclude
     patterns (a single canonical value to compare against).

A legitimate coordinated change (e.g. splitting a new lib file and adding its
pattern to both files) stays green — the guard pins *equality of the two
sources*, not any specific pattern list.

stdlib-only (no PyYAML). Regex/substring scanning. No `scanner/lib` import (does
not touch the 99% coverage gate). No network, no subprocess. Runs under pytest
(the CI runner) and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
DOCKER_SH = REPO_ROOT / "scripts" / "verify-shell-coverage-docker.sh"

# Shared guard primitive (whole-line comment stripping). Import as a top-level
# module so it resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# CI kcov invocation flags (any number of occurrences; tty + non-tty).
CI_INCLUDE_RE = re.compile(r"--include-pattern=(\S+)")
CI_EXCLUDE_RE = re.compile(r"--exclude-pattern=(\S+)")
# CI enforced floor: `threshold = 90.0` in the Python enforce step.
CI_FLOOR_RE = re.compile(r"^\s*threshold\s*=\s*(\d+(?:\.\d+)?)\s*$", re.MULTILINE)

# Docker harness declarations: INCLUDE="...", EXCLUDE="...", FLOOR="...".
DOCKER_INCLUDE_RE = re.compile(r'^INCLUDE="([^"]*)"', re.MULTILINE)
DOCKER_EXCLUDE_RE = re.compile(r'^EXCLUDE="([^"]*)"', re.MULTILINE)
DOCKER_FLOOR_RE = re.compile(r'^FLOOR="([^"]*)"', re.MULTILINE)


def _pattern_set(csv: str) -> set:
    """Parse a comma-separated kcov pattern list into a set (order/dupes ignored),
    stripping a trailing backslash line-continuation and whitespace."""
    csv = csv.rstrip("\\").strip()
    return {p.strip() for p in csv.split(",") if p.strip()}


def _unique(values: list):
    """If every element of `values` is equal, return that element; else return
    the list of distinct values (a divergence to report). Empty -> None."""
    distinct = sorted(set(values))
    if not distinct:
        return None
    if len(distinct) == 1:
        return distinct[0]
    return distinct


def _as_float(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def violations(lint_text: str, docker_text: str) -> list:
    """Every way the two sources disagree. Empty list == in sync."""
    problems = []
    lint = strip_comment_lines(lint_text)
    docker = strip_comment_lines(docker_text)

    # --- CI side: collect every include/exclude occurrence, require consistency.
    ci_includes = CI_INCLUDE_RE.findall(lint)
    ci_excludes = CI_EXCLUDE_RE.findall(lint)
    if not ci_includes:
        problems.append(
            "CI lint.yml has no --include-pattern= (the scanner-shell-coverage "
            "kcov invocation moved or was removed) — cannot verify parity."
        )
    if not ci_excludes:
        problems.append(
            "CI lint.yml has no --exclude-pattern= (the scanner-shell-coverage "
            "kcov invocation moved or was removed) — cannot verify parity."
        )

    ci_inc = _unique([",".join(sorted(_pattern_set(v))) for v in ci_includes])
    ci_exc = _unique([",".join(sorted(_pattern_set(v))) for v in ci_excludes])
    if isinstance(ci_inc, list):
        problems.append(
            "CI lint.yml's kcov --include-pattern differs between invocations "
            f"(tty vs non-tty): {ci_inc}. They must be identical."
        )
    if isinstance(ci_exc, list):
        problems.append(
            "CI lint.yml's kcov --exclude-pattern differs between invocations "
            f"(tty vs non-tty): {ci_exc}. They must be identical."
        )

    ci_floor_m = CI_FLOOR_RE.search(lint)
    ci_floor = _as_float(ci_floor_m.group(1)) if ci_floor_m else None
    if ci_floor is None:
        problems.append(
            "CI lint.yml has no `threshold = <float>` coverage floor — the "
            "enforce step moved or was removed; cannot verify FLOOR parity."
        )

    # --- Docker side.
    d_inc_m = DOCKER_INCLUDE_RE.search(docker)
    d_exc_m = DOCKER_EXCLUDE_RE.search(docker)
    d_floor_m = DOCKER_FLOOR_RE.search(docker)
    if not d_inc_m:
        problems.append('verify-shell-coverage-docker.sh has no INCLUDE="..." declaration.')
    if not d_exc_m:
        problems.append('verify-shell-coverage-docker.sh has no EXCLUDE="..." declaration.')
    if not d_floor_m:
        problems.append('verify-shell-coverage-docker.sh has no FLOOR="..." declaration.')

    # --- Compare (only when both sides parsed).
    if ci_includes and d_inc_m and not isinstance(ci_inc, list):
        ci_set = _pattern_set(ci_includes[0])
        d_set = _pattern_set(d_inc_m.group(1))
        if ci_set != d_set:
            problems.append(
                "INCLUDE drift: docker harness "
                f"{sorted(d_set)} != CI --include-pattern {sorted(ci_set)}. "
                "Sync scripts/verify-shell-coverage-docker.sh to lint.yml."
            )
    if ci_excludes and d_exc_m and not isinstance(ci_exc, list):
        ci_set = _pattern_set(ci_excludes[0])
        d_set = _pattern_set(d_exc_m.group(1))
        if ci_set != d_set:
            problems.append(
                "EXCLUDE drift: docker harness "
                f"{sorted(d_set)} != CI --exclude-pattern {sorted(ci_set)}. "
                "Sync scripts/verify-shell-coverage-docker.sh to lint.yml."
            )
    if ci_floor is not None and d_floor_m:
        d_floor = _as_float(d_floor_m.group(1))
        if d_floor is None or d_floor != ci_floor:
            problems.append(
                f"FLOOR drift: docker harness FLOOR={d_floor_m.group(1)!r} != "
                f"CI threshold {ci_floor}. Sync the local floor to CI."
            )
    return problems


class TestDockerKcovParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lint = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.docker = DOCKER_SH.read_text(encoding="utf-8") if DOCKER_SH.is_file() else ""

    def test_sources_exist(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found.")
        self.assertTrue(DOCKER_SH.is_file(), f"{DOCKER_SH} not found.")

    def test_in_sync(self):
        problems = violations(self.lint, self.docker)
        self.assertEqual(
            problems, [],
            "Local Docker kcov harness has drifted from CI (lint.yml):\n  "
            + "\n  ".join(problems),
        )


class TestDockerKcovParityMutation(unittest.TestCase):
    """Two minimal in-sync fixtures + mutations, so the guard is proven to FAIL
    on each drift class (not just pass on the live, already-synced files)."""

    _LINT = "\n".join(
        [
            "            if [[ \"$name\" == *_tty ]]; then",
            "              kcov --include-pattern=checks.sh,output.sh \\",
            "                --exclude-pattern=api-checks.sh,test_x.sh \\",
            "                \"kcov-out/$name\" \"$sh\"",
            "            else",
            "              kcov --include-pattern=checks.sh,output.sh \\",
            "                --exclude-pattern=api-checks.sh,test_x.sh \\",
            "                \"kcov-out/$name\" \"$sh\"",
            "            fi",
            "          threshold = 90.0",
        ]
    )
    _DOCKER = "\n".join(
        [
            'INCLUDE="checks.sh,output.sh"',
            'EXCLUDE="api-checks.sh,test_x.sh"',
            'FLOOR="90.0"',
        ]
    )

    def test_good_passes(self):
        self.assertEqual(violations(self._LINT, self._DOCKER), [])

    def test_order_and_dupes_ignored(self):
        docker = 'INCLUDE="output.sh,checks.sh,checks.sh"\nEXCLUDE="test_x.sh,api-checks.sh"\nFLOOR="90.0"'
        self.assertEqual(violations(self._LINT, docker), [])

    def test_include_drift_detected(self):
        docker = self._DOCKER.replace('INCLUDE="checks.sh,output.sh"', 'INCLUDE="checks.sh"')
        self.assertTrue(
            any("INCLUDE drift" in p for p in violations(self._LINT, docker)),
            "Mutation FAILED: a missing INCLUDE pattern was NOT detected.",
        )

    def test_exclude_drift_detected(self):
        docker = self._DOCKER.replace("test_x.sh", "")
        self.assertTrue(
            any("EXCLUDE drift" in p for p in violations(self._LINT, docker)),
            "Mutation FAILED: a missing EXCLUDE pattern was NOT detected.",
        )

    def test_floor_drift_detected(self):
        docker = self._DOCKER.replace('FLOOR="90.0"', 'FLOOR="85.0"')
        self.assertTrue(
            any("FLOOR drift" in p for p in violations(self._LINT, docker)),
            "Mutation FAILED: a floor mismatch was NOT detected.",
        )

    def test_ci_internal_inconsistency_detected(self):
        # tty invocation includes an extra pattern the non-tty one lacks.
        lint = self._LINT.replace(
            "--include-pattern=checks.sh,output.sh \\\n                --exclude-pattern=api-checks.sh,test_x.sh",
            "--include-pattern=checks.sh,output.sh,extra.sh \\\n                --exclude-pattern=api-checks.sh,test_x.sh",
            1,
        )
        self.assertTrue(
            any("differs between invocations" in p for p in violations(lint, self._DOCKER)),
            "Mutation FAILED: divergent tty/non-tty CI patterns were NOT detected.",
        )

    def test_comment_only_pattern_does_not_satisfy(self):
        # A pattern that appears ONLY in a comment must not count as CI's real value.
        docker = (
            "# --include-pattern=checks.sh,output.sh (doc only)\n"
            'INCLUDE="checks.sh"\n'
            'EXCLUDE="api-checks.sh,test_x.sh"\n'
            'FLOOR="90.0"'
        )
        self.assertTrue(
            any("INCLUDE drift" in p for p in violations(self._LINT, docker)),
            "Mutation FAILED: a comment-only pattern was treated as the real value.",
        )


if __name__ == "__main__":
    unittest.main()
