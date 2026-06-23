"""
Regression guard: `.github/workflows/dependabot-auto-merge.yml` must keep its
security-load-bearing invariants — the fork guard, the auto-arm allowlists, the
hard-exclude paths, and the no-bypass rules.

Background
----------
This workflow runs on `pull_request_target`, which grants a *write-scoped*
`GITHUB_TOKEN`. That makes every one of the following a security control whose
silent removal would be a real regression (OWASP CICD-SEC-1 Insufficient Flow
Control / CICD-SEC-4 Poisoned Pipeline Execution; NIST SSDF PW.4/PO.3):

  1. **Fork guard** — the job's `if:` must require BOTH
       `github.actor == 'dependabot[bot]'`  AND
       `github.event.pull_request.head.repo.full_name == github.repository`
     Dropping either lets a fork's PR trigger a write-token workflow
     ("pwn request"). The workflow comment explicitly says: never let a fork
     trigger this.
  2. **Hard-exclude paths** — a PR touching `Dockerfile*`, `.github/**`,
     `scanner/`, `hooks/`, or `scripts/` must NOT auto-arm (sensitive surfaces:
     prowler/alpine freeze, CI pipeline, scanner/hook code, automation scripts).
     Removing a `case` arm would silently auto-merge changes to that surface.
  3. **Update-type allowlist** — only `version-update:semver-patch` /
     `semver-minor` may auto-arm; `semver-major` is hard-excluded. Broadening
     this would auto-merge breaking bumps.
  4. **Ecosystem allowlist** — only `pip|docker|github-actions`. Adding e.g.
     `npm` here is a policy change that must be reviewed, not slipped in.
  5. **No bypass** — the arm must stay `gh pr merge --auto` (server-side, still
     gated by branch protection + the human code-owner review). `--admin` must
     never appear (it would bypass `require_code_owner_reviews`), and the broken
     `gh pr review --approve` bot self-approve removed in #249 must not return
     (it approves as `github-actions[bot]`, which is NOT a code owner, giving a
     false-green signal — empirically proven on PR #235).

Incident lineage: #249 reworked this workflow (dropped the broken bot-approve,
auto-arm safe updates only); #250 enabled `allow_auto_merge=true`. This guard
locks that hard-won topology so it can't be silently weakened.

Mutation self-test
------------------
`TestDependabotAutoMergeGuardMutation` builds a synthetic known-good workflow
snippet, confirms it passes, then verifies each invariant is detected when
removed (or when a forbidden token is introduced), and that the real on-disk
workflow passes cleanly.

stdlib-only (no PyYAML — it is not in requirements-ci.txt). Substring checks,
not regex, so the `.` `*` `|` `(` in the case patterns are matched literally.
No `scanner/lib` import (does not touch the 99% coverage gate). No network, no
subprocess. Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines, strip_inline_comment  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependabot-auto-merge.yml"

# Invariants that MUST be present verbatim. Each maps to a control described in
# the module docstring. Tightening (adding more excludes) is always allowed;
# removing an entry requires revising this guard with a documented rationale.
REQUIRED_TOKENS = {
    # 1. Fork guard (both halves required)
    "fork_guard_actor": "github.actor == 'dependabot[bot]'",
    "fork_guard_same_repo": (
        "github.event.pull_request.head.repo.full_name == github.repository"
    ),
    # 2. Hard-exclude path case arms (exact arms — these strings live only in
    #    the `case "$path" in` block, never in the surrounding commentary)
    "exclude_dockerfile": "Dockerfile|Dockerfile.nginx|Dockerfile.*)",
    "exclude_github": ".github/*|.github)",
    "exclude_scanner": "scanner/*|scanner)",
    "exclude_hooks": "hooks/*|hooks)",
    "exclude_scripts": "scripts/*|scripts)",
    # 3. semver-major hard-exclude + update-type allowlist
    "semver_major_excluded": '"$UPDATE_TYPE" = "version-update:semver-major"',
    "eligible_update_types": (
        "version-update:semver-patch|version-update:semver-minor)"
    ),
    # 4. Ecosystem allowlist
    "eligible_ecosystems": "pip|docker|github-actions)",
    # 5. The arm must be server-side auto-merge (gated by branch protection)
    "arm_is_auto_merge": "gh pr merge --auto",
    # Sanity: this is the pull_request_target workflow we think it is
    "trigger_pull_request_target": "pull_request_target:",
}

# Tokens that MUST NOT appear — re-introducing any is a regression.
FORBIDDEN_TOKENS = {
    # --admin would bypass require_code_owner_reviews (org policy + #250).
    "admin_bypass": "--admin",
    # The broken bot self-approve removed in #249 (approves as a non-code-owner).
    "bot_self_approve": "pr review --approve",
}


def _violations(text: str) -> list:
    """Return a list of problem descriptions for REQUIRED/FORBIDDEN violations.

    Whole-line AND trailing-inline `#` comments are stripped first (F-3 + 2nd-review
    Finding 2): a fork-guard token surviving only in a comment must NOT satisfy a
    REQUIRED check (the real `if:` could be neutered to `true`), and a `--admin`
    in a trailing comment must NOT false-trip a FORBIDDEN check. The case-arm /
    fork-guard strings carry no inline `#`, so stripping is safe for them. (A
    `--admin` in non-comment prose, e.g. an `echo`, is an accepted residual
    false-positive — substring matching can't tell prose from a command.)
    """
    scan = "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )
    problems = []
    for name, tok in sorted(REQUIRED_TOKENS.items()):
        if tok not in scan:
            problems.append(f"MISSING required invariant [{name}]: {tok!r}")
    for name, tok in sorted(FORBIDDEN_TOKENS.items()):
        if tok in scan:
            problems.append(f"FORBIDDEN token present [{name}]: {tok!r}")
    return problems


class TestDependabotAutoMergeGuard(unittest.TestCase):
    """Guards that the on-disk auto-merge workflow keeps every invariant."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def test_workflow_exists(self):
        self.assertTrue(
            WORKFLOW.is_file(),
            f".github/workflows/dependabot-auto-merge.yml not found at {WORKFLOW} — "
            "the Dependabot auto-arm gate has been deleted or moved.",
        )

    def test_all_invariants_hold(self):
        problems = _violations(self.text)
        self.assertEqual(
            problems,
            [],
            "dependabot-auto-merge.yml lost a security invariant or gained a "
            "forbidden token. Each of these protects a pull_request_target "
            "write-token workflow:\n  "
            + "\n  ".join(problems)
            + "\n\nRestore the invariant, or (if the change is intentional) update "
            "REQUIRED_TOKENS / FORBIDDEN_TOKENS in this guard with a rationale.",
        )

    def test_fork_guard_present(self):
        self.assertIn(
            REQUIRED_TOKENS["fork_guard_actor"], self.text,
            "Fork guard missing the actor==dependabot[bot] check — a fork PR could "
            "trigger this write-token workflow.",
        )
        self.assertIn(
            REQUIRED_TOKENS["fork_guard_same_repo"], self.text,
            "Fork guard missing the same-repo (head.repo.full_name==github.repository) "
            "check — a fork PR could trigger this write-token workflow (pwn request).",
        )

    def test_hard_exclude_paths_present(self):
        for key in (
            "exclude_dockerfile", "exclude_github", "exclude_scanner",
            "exclude_hooks", "exclude_scripts",
        ):
            self.assertIn(
                REQUIRED_TOKENS[key], self.text,
                f"Hard-exclude path arm [{key}] removed — Dependabot PRs touching "
                "that sensitive surface could auto-merge without human review.",
            )

    def test_update_type_and_ecosystem_allowlists(self):
        self.assertIn(
            REQUIRED_TOKENS["eligible_update_types"], self.text,
            "Update-type allowlist changed — only semver-patch/minor may auto-arm.",
        )
        self.assertIn(
            REQUIRED_TOKENS["semver_major_excluded"], self.text,
            "semver-major hard-exclude removed — major bumps could auto-arm.",
        )
        self.assertIn(
            REQUIRED_TOKENS["eligible_ecosystems"], self.text,
            "Ecosystem allowlist changed from pip|docker|github-actions — a policy "
            "change that must be reviewed, not slipped in.",
        )

    def test_no_bypass_tokens(self):
        for key, tok in FORBIDDEN_TOKENS.items():
            self.assertNotIn(
                tok, self.text,
                f"Forbidden token [{key}] {tok!r} present — it would bypass the "
                "human code-owner review gate or re-introduce the broken #249 "
                "bot self-approve.",
            )


class TestDependabotAutoMergeGuardMutation(unittest.TestCase):
    """Mutation self-tests: the detector must fire on known-bad inputs and stay
    quiet on the known-good real file."""

    # Minimal synthetic snippet containing every REQUIRED token and no FORBIDDEN
    # token. Order/structure is irrelevant — the guard is substring-based.
    _GOOD = "\n".join(
        [
            "on:",
            "  pull_request_target:",
            "    types: [opened, synchronize]",
            "if: >-",
            "  github.actor == 'dependabot[bot]' &&",
            "  github.event.pull_request.head.repo.full_name == github.repository",
            'case "$path" in',
            "  Dockerfile|Dockerfile.nginx|Dockerfile.*)",
            "  .github/*|.github)",
            "  scanner/*|scanner)",
            "  hooks/*|hooks)",
            "  scripts/*|scripts)",
            'if [ "$UPDATE_TYPE" = "version-update:semver-major" ]; then',
            "  version-update:semver-patch|version-update:semver-minor) ;;",
            "  pip|docker|github-actions) ;;",
            'gh pr merge --auto --squash "$PR_URL"',
        ]
    )

    def test_good_snippet_passes(self):
        self.assertEqual(
            _violations(self._GOOD), [],
            "Mutation self-test BROKEN: a known-good snippet reported violations:\n  "
            + "\n  ".join(_violations(self._GOOD)),
        )

    def test_dropping_fork_guard_is_detected(self):
        mutant = self._GOOD.replace(
            "  github.event.pull_request.head.repo.full_name == github.repository",
            "",
        )
        self.assertTrue(
            any("fork_guard_same_repo" in p for p in _violations(mutant)),
            "Mutation FAILED: removing the same-repo fork guard was NOT detected.",
        )

    def test_fork_guard_surviving_only_in_comment_is_detected(self):
        # F-3 (comment-evasion): neuter the real same-repo fork guard but leave
        # the token alive in a `#` comment — the guard must still fire.
        mutant = self._GOOD.replace(
            "  github.event.pull_request.head.repo.full_name == github.repository",
            "  # github.event.pull_request.head.repo.full_name == github.repository",
        )
        self.assertTrue(
            any("fork_guard_same_repo" in p for p in _violations(mutant)),
            "Mutation FAILED (F-3): the same-repo fork guard surviving only in a "
            "comment satisfied the REQUIRED check — comment-evasion not defended.",
        )

    def test_dropping_a_hard_exclude_path_is_detected(self):
        mutant = self._GOOD.replace("  scanner/*|scanner)", "")
        self.assertTrue(
            any("exclude_scanner" in p for p in _violations(mutant)),
            "Mutation FAILED: removing the scanner/ hard-exclude was NOT detected.",
        )

    def test_broadening_update_types_is_detected(self):
        # Replace the patch/minor-only arm with one that also admits major.
        mutant = self._GOOD.replace(
            "  version-update:semver-patch|version-update:semver-minor) ;;",
            "  version-update:semver-patch|version-update:semver-minor"
            "|version-update:semver-major) ;;",
        )
        self.assertTrue(
            any("eligible_update_types" in p for p in _violations(mutant)),
            "Mutation FAILED: broadening the update-type allowlist was NOT detected.",
        )

    def test_broadening_ecosystems_is_detected(self):
        mutant = self._GOOD.replace(
            "  pip|docker|github-actions) ;;",
            "  pip|docker|github-actions|npm) ;;",
        )
        self.assertTrue(
            any("eligible_ecosystems" in p for p in _violations(mutant)),
            "Mutation FAILED: broadening the ecosystem allowlist was NOT detected.",
        )

    def test_admin_bypass_is_detected(self):
        mutant = self._GOOD.replace(
            'gh pr merge --auto --squash "$PR_URL"',
            'gh pr merge --auto --squash --admin "$PR_URL"',
        )
        self.assertTrue(
            any("admin_bypass" in p for p in _violations(mutant)),
            "Mutation FAILED: a --admin bypass was NOT detected.",
        )

    def test_reintroducing_bot_self_approve_is_detected(self):
        mutant = self._GOOD + '\ngh pr review --approve "$PR_URL"'
        self.assertTrue(
            any("bot_self_approve" in p for p in _violations(mutant)),
            "Mutation FAILED: re-introducing the #249 bot self-approve was NOT detected.",
        )

    def test_real_workflow_clean(self):
        if not WORKFLOW.is_file():
            self.skipTest("workflow not found — covered by TestDependabotAutoMergeGuard")
        problems = _violations(WORKFLOW.read_text(encoding="utf-8"))
        self.assertEqual(
            problems, [],
            "The real dependabot-auto-merge.yml failed the invariant validator:\n  "
            + "\n  ".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
