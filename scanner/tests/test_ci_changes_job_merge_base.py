"""
Regression guard: EVERY `changes` (Detect changed paths) job that diffs a PR base
against its head must compute the changed files in a way that CANNOT hard-fail
with "fatal: no merge base".

Background
----------
The job path-gates the heavy downstream jobs (scanner/docker/coverage). For a
`pull_request` event it diffs the base against the head. The original form was:

    git fetch origin "$BASE_SHA" --depth=1
    FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA")

`--depth=1` fetches the base as a parent-less shallow graft, so the three-dot
(merge-base) diff dies with `fatal: no merge base` whenever the PR branch is
behind a moved `main` — which cascades to the Lint / Security Scan Gate
aggregators and blocks the merge. (Reproduced against a shallow base + behind
branch.) The fix fetches the base WITH ancestry and falls back to a two-endpoint
diff (which needs no merge base) and finally `HEAD~1`.

Invariants asserted (PR-event branch only):
  1. The base fetch is NOT solely `git fetch origin "$BASE_SHA" --depth=1` — a
     non-shallow fetch of the base is attempted (so a merge base is reachable).
  2. The `"$BASE_SHA"..."$HEAD_SHA"` three-dot diff has a `|| git diff ...`
     fallback (so a "no merge base" degrades instead of failing the step).

A legitimate rewrite that keeps a fallback / deepened fetch stays green; removing
the fallback or reverting to a shallow-only base fetch trips the guard.

SCOPE: originally `lint.yml` only, which is exactly how the bug survived. The
identical shallow-only shape was still live in `security-scan.yml` and
`dashboard-control-smoke.yml` and both hard-failed on the first PR branched from
a `main` that then moved (observed 2026-08-07, run 31150981399 / 31150982066:
`fatal: c8a89c8...e52f07e: no merge base`). The consequences differ and both are
bad: `security-scan.yml`'s failure cascades to the REQUIRED `Security Scan Gate`
and blocks the merge loudly, while `dashboard-control-smoke.yml`'s makes the smoke
job report `skipping` — coverage silently lost, job reads green. The guard is now
discovery-based: every workflow whose `run:` body contains the PR three-dot
`"$BASE_SHA"..."$HEAD_SHA"` diff is checked, so a NEW workflow copying the buggy
shape is caught rather than needing to be remembered.

stdlib-only. No `scanner/lib` import (does not touch the 99% coverage gate).
No network, no subprocess. Runs under pytest and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
LINT_YML = WORKFLOWS_DIR / "lint.yml"

# The PR three-dot diff whose PRESENCE makes a workflow in scope. Discovery beats
# an allowlist here: the bug spread by copy-paste, so any workflow that grows this
# shape is checked automatically.
_IN_SCOPE_MARKER = '"$BASE_SHA"..."$HEAD_SHA"'

# Workflows that MUST be found in scope. A rewrite that drops the three-dot diff
# from one of these would otherwise remove it from the guard's reach silently.
_REQUIRED_IN_SCOPE = ("lint.yml", "security-scan.yml", "dashboard-control-smoke.yml")


def in_scope_workflows():
    """(name, text) for every workflow carrying the PR three-dot base/head diff."""
    found = []
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if _IN_SCOPE_MARKER in text:
            found.append((path.name, text))
    return found

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    join_continuations,
    strip_comment_lines,
    strip_inline_comment_sh,
)

# The PR-event three-dot diff, with backslash-continuations joined onto one line.
_PR_DIFF_RE = re.compile(
    r'git diff --name-only\s+"\$BASE_SHA"\.\.\."\$HEAD_SHA".*?\|\|\s*git diff'
)
# A non-shallow base fetch (i.e. `git fetch origin "$BASE_SHA"` NOT immediately
# followed by --depth=1). We assert the first base fetch on the joined line is
# the deepened one.
_BASE_FETCH_RE = re.compile(r'git fetch origin "\$BASE_SHA"(?!\s+--depth=1)')


def _joined(text: str) -> str:
    # Drop BOTH whole-line `#` comments AND trailing inline SHELL comments BEFORE
    # joining/scanning so a required token (the `|| git diff` fallback, the
    # non-shallow base fetch) surviving only in a comment — whole-line, trailing
    # ` # ...`, OR the bash command-separator form `...;#...` (a real comment with
    # no space) — cannot satisfy a presence check on the active shallow/no-fallback
    # line (ADR-001 §1). This is shell, so `strip_inline_comment_sh` (not the
    # whitespace-only variant) is required.
    body = strip_comment_lines(text)
    body = "\n".join(strip_inline_comment_sh(ln) for ln in body.splitlines())
    return join_continuations(body)


def violations(text: str) -> list:
    joined = _joined(text)
    problems = []
    if not _PR_DIFF_RE.search(joined):
        problems.append(
            'The PR-event `git diff "$BASE_SHA"..."$HEAD_SHA"` has no `|| git diff` '
            "fallback — a shallow/behind base makes it hard-fail with "
            '"no merge base" and block the merge.'
        )
    if not _BASE_FETCH_RE.search(joined):
        problems.append(
            'No non-shallow `git fetch origin "$BASE_SHA"` (only a --depth=1 '
            "fetch) — the base has no ancestry, so the three-dot merge-base diff "
            "cannot resolve."
        )
    return problems


class TestChangesJobMergeBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = in_scope_workflows()

    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_expected_workflows_are_in_scope(self):
        # Canary: if discovery finds nothing (or loses a known workflow), every
        # per-workflow assertion below would pass vacuously.
        names = {name for name, _ in self.workflows}
        for required in _REQUIRED_IN_SCOPE:
            with self.subTest(workflow=required):
                self.assertIn(
                    required,
                    names,
                    f"{required} no longer carries the PR three-dot base/head diff "
                    "— either it was rewritten (update _REQUIRED_IN_SCOPE) or "
                    "discovery broke and this guard has gone vacuous",
                )

    def test_pr_diff_has_fallback(self):
        for name, text in self.workflows:
            with self.subTest(workflow=name):
                self.assertRegex(
                    _joined(text), _PR_DIFF_RE,
                    f"{name}: the PR-event base/head diff must have a `|| git diff` "
                    'fallback so a "no merge base" cannot fail the changes job.',
                )

    def test_base_fetch_is_deepened(self):
        for name, text in self.workflows:
            with self.subTest(workflow=name):
                self.assertRegex(
                    _joined(text), _BASE_FETCH_RE,
                    f"{name}: the base must be fetched with ancestry (a `git fetch "
                    'origin "$BASE_SHA"` without --depth=1), not only shallow.',
                )

    def test_all_invariants_hold(self):
        for name, text in self.workflows:
            with self.subTest(workflow=name):
                self.assertEqual(violations(text), [], f"{name} regressed")


class TestChangesJobMergeBaseMutation(unittest.TestCase):
    _GOOD = (
        'git fetch origin "$BASE_SHA" >/dev/null 2>&1 '
        '|| git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA" 2>/dev/null '
        '|| git diff --name-only "$BASE_SHA" "$HEAD_SHA" 2>/dev/null '
        '|| git diff --name-only HEAD~1..HEAD)\n'
    )
    _BAD = (
        'git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA")\n'
    )

    # The active code regressed to _BAD, but the good tokens survive ONLY in a
    # leading `#` comment block. A comment-blind matcher stays green here.
    _COMMENT_EVASION = (
        '# Reference (do not delete without reading this):\n'
        '#   git fetch origin "$BASE_SHA" >/dev/null 2>&1 || true\n'
        '#   FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA" 2>/dev/null '
        '|| git diff --name-only HEAD~1..HEAD)\n'
        'git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA")\n'
    )

    def test_good_passes(self):
        self.assertEqual(violations(self._GOOD), [])

    def test_bad_form_is_detected(self):
        self.assertEqual(len(violations(self._BAD)), 2, violations(self._BAD))

    # Active code is _BAD, but the good tokens survive ONLY in TRAILING inline
    # comments on those active lines (whole-line stripping alone misses this).
    _TRAILING_COMMENT_EVASION = (
        'git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true  '
        '# git fetch origin "$BASE_SHA" >/dev/null 2>&1 || true\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA")  '
        '# 2>/dev/null || git diff --name-only HEAD~1..HEAD\n'
    )

    def test_comment_only_survival_is_detected(self):
        # ADR-001 §1: a token living only in a `#` comment must NOT satisfy the
        # invariant. Both controls are absent from the active code, so both
        # violations must fire despite the good forms surviving in comments.
        self.assertEqual(
            len(violations(self._COMMENT_EVASION)), 2,
            "comment-evasion regression: the fallback/deepened-fetch tokens "
            "survived only in comments but the guard did not fire — "
            f"got {violations(self._COMMENT_EVASION)}",
        )

    # No space before `#`: `...;#...` is a real bash comment a whitespace-only
    # stripper misses (3rd-pass finding).
    _METACHAR_COMMENT_EVASION = (
        'git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true;'
        '#git fetch origin "$BASE_SHA" >/dev/null 2>&1 || true\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA");'
        '#2>/dev/null || git diff --name-only HEAD~1..HEAD\n'
    )

    def test_trailing_comment_survival_is_detected(self):
        # The good tokens ride TRAILING comments on the active _BAD lines.
        self.assertEqual(
            len(violations(self._TRAILING_COMMENT_EVASION)), 2,
            "trailing-comment-evasion regression: the fallback/deepened-fetch "
            "tokens survived only in trailing comments on the active lines but "
            f"the guard did not fire — got {violations(self._TRAILING_COMMENT_EVASION)}",
        )

    def test_metachar_comment_survival_is_detected(self):
        # The good tokens ride `;#` command-separator comments on the _BAD lines.
        self.assertEqual(
            len(violations(self._METACHAR_COMMENT_EVASION)), 2,
            "metachar-comment-evasion regression: the fallback/deepened-fetch "
            "tokens survived only in `;#` bash comments on the active lines but "
            f"the guard did not fire — got {violations(self._METACHAR_COMMENT_EVASION)}",
        )

    # The good tokens ride `` `#... ` `` backtick comments (4th-pass finding).
    _BACKTICK_COMMENT_EVASION = (
        'git fetch origin "$BASE_SHA" --depth=1 >/dev/null 2>&1 || true`'
        '#git fetch origin "$BASE_SHA" >/dev/null 2>&1 || true`\n'
        'FILES=$(git diff --name-only "$BASE_SHA"..."$HEAD_SHA")`'
        '#2>/dev/null || git diff --name-only HEAD~1..HEAD`\n'
    )

    def test_backtick_comment_survival_is_detected(self):
        self.assertEqual(
            len(violations(self._BACKTICK_COMMENT_EVASION)), 2,
            "backtick-comment-evasion regression: the fallback/deepened-fetch "
            "tokens survived only in `` `#... ` `` bash comments but the guard did "
            f"not fire — got {violations(self._BACKTICK_COMMENT_EVASION)}",
        )


if __name__ == "__main__":
    unittest.main()
