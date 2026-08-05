"""
Regression guard: the two REQUIRED workflows — `lint.yml` (`Lint`) and
`security-scan.yml` (`Security Scan Gate`) — must keep their `pull_request:`
trigger UNSCOPED: no `branches:` / `branches-ignore:` filter, and no
workflow-level `paths:` / `paths-ignore:` filter.

Two distinct incidents, one invariant
-------------------------------------
**`branches:` — the stacked-PR blind spot (this PR).** `on.pull_request.branches`
filters by the PR's *base* ref. With `branches: [main]`, a stacked PR (base = a
feature branch) never triggers these workflows at all, so neither required
context ever reports on it and the change is unverifiable until its base merges.
Measured 2026-08-05: PR #384 (base = a feature branch) got **3 checks** with
`Lint` and `Security Scan Gate` absent; the same branch retargeted to `main` as
PR #385 got **28 checks**, all required contexts SUCCESS.

**`paths-ignore:` — the #186 merge-block.** A workflow-level path filter on a
REQUIRED check makes it never report for PRs that *do* target `main`, and
branch protection then waits forever — a permanent merge block. The sanctioned
pattern is job-level gating with an `always()` aggregator (the `changes` job +
`lint-gate` / `security-gate`), which this repo already uses.

The two are opposite failure directions of the same root cause — a
workflow-level trigger filter on a required check — so one guard pins both.
Note they are NOT symmetric: removing `branches:` is strictly additive (PRs
targeting `main` behave identically, so the #186 mode cannot recur), whereas
adding `paths-ignore:` is the #186 mode itself.

Scope
-----
Deliberately limited to the two workflows whose checks are REQUIRED contexts on
`main` (`DESIRED_CONTEXTS` in `scripts/sync-repo-protection.sh`, pinned by
`test_ci_branch_protection_codified.py`). Non-required workflows may filter
freely — `dast-baseline.yml` legitimately carries both `branches: [main, develop]`
and `paths-ignore:`, and is intentionally NOT covered here.

Direction: presence-of-violation. Re-adding any of the four filter keys under
`pull_request:` in either file trips this guard. The `push:` trigger keeps its
`branches: [main]` scope and is not inspected.

stdlib-only (no PyYAML — absent from requirements-ci.txt). Does not import
`scanner/lib`, so it never moves the 99% coverage gate. No network, no
subprocess. Runs under pytest (the CI runner) and `python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SP 800-218 (SSDF) PO.3, PW.4.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import extract_on_block  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# Only the workflows behind a REQUIRED branch-protection context.
REQUIRED_WORKFLOWS = {
    "Lint": WORKFLOW_DIR / "lint.yml",
    "Security Scan Gate": WORKFLOW_DIR / "security-scan.yml",
}

# Filter keys that must not appear under `pull_request:`. `branches*` narrows by
# base ref (the stacked-PR blind spot); `paths*` narrows by diff content (#186).
FORBIDDEN_FILTER_KEYS = ("branches", "branches-ignore", "paths", "paths-ignore")

_PR_KEY_RE = re.compile(r"^(\s*)pull_request:\s*(.*)$")


def pull_request_block(text: str) -> str:
    """The content nested under the top-level `on:` -> `pull_request:` key.

    Built on `extract_on_block`, which already drops whole-line comments and
    trailing inline comments and handles bare/quoted `on:` keys — so the
    rationale comment sitting above `pull_request:` in each workflow cannot
    satisfy or trip a check here.

    Membership is decided by INDENTATION relative to the `pull_request:` key,
    and the block ends at the first non-blank line indented at or above it. A
    flow-style value on the key line itself (`pull_request: {branches: [main]}`)
    is captured too, so that form cannot slip past a block-only scan.

    `pull_request_target:` is a different key and is never matched: the regex
    requires the `:` immediately after `pull_request`.

    Returns "" when the workflow has no `pull_request:` trigger at all — callers
    must assert the trigger exists separately (see `test_pull_request_trigger_present`),
    or an empty block would pass the filter checks vacuously.
    """
    body, indent = [], None
    for line in extract_on_block(text).splitlines():
        if indent is None:
            m = _PR_KEY_RE.match(line)
            if m:
                indent = len(m.group(1))
                if m.group(2).strip():
                    body.append(m.group(2))  # flow-style value on the key line
            continue
        if not line.strip():
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break  # dedent to a sibling trigger (`push:`, `schedule:`, ...)
        body.append(line)
    return "\n".join(body)


def filter_violations(text: str, label: str) -> list:
    """Forbidden trigger-filter keys found under `pull_request:`."""
    block = pull_request_block(text)
    found = []
    for key in FORBIDDEN_FILTER_KEYS:
        # Anchor to a mapping key so a `branches` substring inside a value
        # (or the longer `branches-ignore`) is attributed exactly once.
        if re.search(rf"(?m)(?:^|[\s{{,]){re.escape(key)}\s*:", block):
            found.append(f"{label}: `{key}:` under `pull_request:`")
    return found


class TestRequiredWorkflowPrTriggerScope(unittest.TestCase):
    def test_workflows_exist(self):
        for ctx, path in REQUIRED_WORKFLOWS.items():
            self.assertTrue(
                path.is_file(),
                f"{path} not found — the workflow behind the REQUIRED '{ctx}' "
                "context has been deleted or moved.",
            )

    def test_pull_request_trigger_present(self):
        # Canary: without this, an entirely removed `pull_request:` trigger
        # would make the filter checks below pass on an empty block.
        for ctx, path in REQUIRED_WORKFLOWS.items():
            with self.subTest(context=ctx):
                on_block = extract_on_block(path.read_text(encoding="utf-8"))
                self.assertRegex(
                    on_block,
                    r"(?m)^\s*pull_request:",
                    f"{path.name} lost its `pull_request:` trigger — the REQUIRED "
                    f"'{ctx}' context would never report on any PR.",
                )

    def test_no_trigger_filter_narrows_a_required_check(self):
        problems = []
        for path in REQUIRED_WORKFLOWS.values():
            problems += filter_violations(
                path.read_text(encoding="utf-8"), path.name
            )
        self.assertEqual(
            problems,
            [],
            "A REQUIRED workflow narrowed its `pull_request:` trigger:\n  "
            + "\n  ".join(problems)
            + "\n\n`branches:`/`branches-ignore:` hides the check from stacked PRs "
            "(base != main), which then cannot be verified at all — PR #384 got 3 "
            "checks vs 28 for the same branch based on main (#385).\n"
            "`paths:`/`paths-ignore:` is the #186 failure mode: the required check "
            "never reports and branch protection blocks the merge forever.\n"
            "Gate at the JOB level instead — the `changes` job plus the "
            "`lint-gate` / `security-gate` `always()` aggregator.",
        )


class TestPullRequestBlockParser(unittest.TestCase):
    """Mutation self-tests for `pull_request_block` / `filter_violations`."""

    _CLEAN = "on:\n  push:\n    branches: [main]\n  pull_request:\n\njobs:\n  a:\n"
    _BRANCHES = (
        "on:\n  push:\n    branches: [main]\n"
        "  pull_request:\n    branches: [main]\n\njobs:\n  a:\n"
    )
    _PATHS_IGNORE = (
        "on:\n  pull_request:\n    paths-ignore:\n      - 'docs/**'\n\njobs:\n  a:\n"
    )
    _FLOW = "on:\n  pull_request: {branches: [main]}\n\njobs:\n  a:\n"
    # The `push:` trigger legitimately keeps `branches: [main]` — it must not
    # leak into the `pull_request:` block and cause a false positive.
    _PUSH_ONLY = "on:\n  pull_request:\n  push:\n    branches: [main]\n\njobs:\n  a:\n"
    # A rationale comment naming the forbidden key must not trip the check.
    _COMMENTED = (
        "on:\n  # no `branches:` filter here on purpose\n"
        "  pull_request:  # not scoped to main\n\njobs:\n  a:\n"
    )
    # `pull_request_target:` is a different trigger and is out of scope.
    _TARGET = (
        "on:\n  pull_request:\n"
        "  pull_request_target:\n    branches: [main]\n\njobs:\n  a:\n"
    )

    def test_clean_workflow_has_no_violation(self):
        self.assertEqual(filter_violations(self._CLEAN, "w.yml"), [])

    def test_branches_filter_is_detected(self):
        self.assertEqual(
            filter_violations(self._BRANCHES, "w.yml"),
            ["w.yml: `branches:` under `pull_request:`"],
        )

    def test_paths_ignore_filter_is_detected(self):
        self.assertIn(
            "w.yml: `paths-ignore:` under `pull_request:`",
            filter_violations(self._PATHS_IGNORE, "w.yml"),
        )

    def test_flow_style_filter_on_the_key_line_is_detected(self):
        self.assertEqual(
            filter_violations(self._FLOW, "w.yml"),
            ["w.yml: `branches:` under `pull_request:`"],
        )

    def test_push_branches_does_not_leak_into_the_pr_block(self):
        self.assertEqual(
            filter_violations(self._PUSH_ONLY, "w.yml"),
            [],
            "The `push:` trigger's own `branches: [main]` was attributed to "
            "`pull_request:` — a sibling key ends the block.",
        )

    def test_commented_filter_is_not_flagged(self):
        self.assertEqual(filter_violations(self._COMMENTED, "w.yml"), [])

    def test_pull_request_target_filter_is_out_of_scope(self):
        self.assertEqual(
            filter_violations(self._TARGET, "w.yml"),
            [],
            "`pull_request_target:` is a different trigger; its `branches:` "
            "filter must not be attributed to `pull_request:`.",
        )

    def test_real_workflows_parse_to_a_locatable_block(self):
        # Guards against a silent parser regression that returns "" for the real
        # files, which would make the invariant check pass vacuously.
        for path in REQUIRED_WORKFLOWS.values():
            with self.subTest(workflow=path.name):
                on_block = extract_on_block(path.read_text(encoding="utf-8"))
                self.assertIn("pull_request:", on_block)


if __name__ == "__main__":
    unittest.main()
