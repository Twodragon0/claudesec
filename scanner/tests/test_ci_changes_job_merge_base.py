"""
Regression guard: the `changes` (Detect changed paths) job in `lint.yml` must
compute the PR's changed files in a way that CANNOT hard-fail with
"fatal: no merge base".

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

stdlib-only. No `scanner/lib` import (does not touch the 99% coverage gate).
No network, no subprocess. Runs under pytest and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import join_continuations  # noqa: E402

# The PR-event three-dot diff, with backslash-continuations joined onto one line.
_PR_DIFF_RE = re.compile(
    r'git diff --name-only\s+"\$BASE_SHA"\.\.\."\$HEAD_SHA".*?\|\|\s*git diff'
)
# A non-shallow base fetch (i.e. `git fetch origin "$BASE_SHA"` NOT immediately
# followed by --depth=1). We assert the first base fetch on the joined line is
# the deepened one.
_BASE_FETCH_RE = re.compile(r'git fetch origin "\$BASE_SHA"(?!\s+--depth=1)')


def _joined(text: str) -> str:
    return join_continuations(text)


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
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_pr_diff_has_fallback(self):
        self.assertRegex(
            _joined(self.text), _PR_DIFF_RE,
            'The PR-event base/head diff must have a `|| git diff` fallback so a '
            '"no merge base" cannot fail the changes job.',
        )

    def test_base_fetch_is_deepened(self):
        self.assertRegex(
            _joined(self.text), _BASE_FETCH_RE,
            'The base must be fetched with ancestry (a `git fetch origin '
            '"$BASE_SHA"` without --depth=1), not only shallow.',
        )

    def test_all_invariants_hold(self):
        self.assertEqual(violations(self.text), [])


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

    def test_good_passes(self):
        self.assertEqual(violations(self._GOOD), [])

    def test_bad_form_is_detected(self):
        self.assertEqual(len(violations(self._BAD)), 2, violations(self._BAD))


if __name__ == "__main__":
    unittest.main()
