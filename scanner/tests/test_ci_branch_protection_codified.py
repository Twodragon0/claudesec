"""
Regression guard: branch protection is codified as infrastructure-as-code in
`scripts/sync-repo-protection.sh`, and the nightly `protection-drift-watch.yml`
notifier stays wired to it correctly.

Background
----------
`main` branch protection is the outermost control: it is what forces every
change through the two required status checks (`Lint`, `Security Scan Gate`),
through CODEOWNERS review, and what keeps repo admins from force-pushing. Those
settings live on GitHub's side, but their *desired state* is codified in
`scripts/sync-repo-protection.sh` (single source of truth, #250) and watched for
drift nightly by `protection-drift-watch.yml` (#251).

Silently weakening the codified desired state would not fail any build — it would
just quietly make `--apply` reconfigure the repo to a weaker posture, or make the
drift watch stop detecting a regression. Each invariant below is therefore a
control whose silent removal disables enforcement
(OWASP CICD-SEC-1 Insufficient Flow Control / CICD-SEC-7 Insecure System
Configuration; NIST SSDF SP 800-218 PO.3/PW.4):

  1. **Required-status contexts** — `DESIRED_CONTEXTS` must keep BOTH
     `"Lint"` and `"Security Scan Gate"`. Dropping either un-requires that
     aggregator, so a PR could merge with that whole gate red. (The "two
     required checks" contract documented in ci-config-regression-guards.md.)
  2. **enforce_admins=true** — admins (including the owner) are NOT exempt from
     branch protection. Flipping to false would let an admin force-push to main.
  3. **strict=true** — PRs must be up to date with main before merge.
  4. **require_code_owner_reviews=true** — every touched path needs a CODEOWNERS
     match; this is what makes `require_code_owner_reviews` actually gate.
  5. **Safe-by-default dry-run** — the script must `set -euo pipefail` and the
     no-flag / `--dry-run` invocation must NOT write (only `--apply` mutates).
  6. **Drift marker contract** — the script emits the literal `DRIFT DETECTED`
     string and the watch workflow greps for exactly that string to tell real
     drift apart from a tooling/auth error. If either side changes the marker,
     the nightly watch silently reclassifies every drift as a tooling error and
     never opens an alert issue.
  7. **Notifier is not a PR gate** — `protection-drift-watch.yml` must keep its
     `schedule:` trigger and must NEVER gain a `pull_request` /
     `pull_request_target` trigger (it is a scheduled notifier and must not
     become a required PR status check), and its tooling-error branch must keep
     `exit 1` so a silent auth failure is never read as "clean".

Direction: presence/`==` (exact desired values). Tightening (adding contexts,
adding more `exit 1` paths) stays green; loosening trips the guard.

Mutation self-test
------------------
`TestBranchProtectionCodifiedMutation` builds synthetic known-good script/workflow
snippets, confirms they pass, then verifies each invariant is detected when
weakened, and that the real on-disk files pass cleanly.

Hardened (sec-review, 2026-06-19) against false negatives: whole-line comments
are stripped before every presence check so a token living only in a comment
cannot satisfy it (BP-5/BP-8); the `on:` block parser handles flow-style
(`on: [push, pull_request]`) and quoted (`'on':` / `"on":`) keys (BP-1/BP-2);
and each boolean `DESIRED_*` var must be assigned exactly once to its expected
value, so a second last-wins `="false"` cannot hide behind the first `="true"`
(BP-4).

stdlib-only (no PyYAML — not in requirements-ci.txt). Line scanning + small
regexes that never match commentary (comments are stripped first). No
`scanner/lib` import (does not touch the 99% coverage gate). No network, no
subprocess. Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "sync-repo-protection.sh"
WATCH = REPO_ROOT / ".github" / "workflows" / "protection-drift-watch.yml"

# Literal desired-state assignments that MUST be present verbatim in the script.
# Tightening the posture (e.g. adding a context) is allowed; weakening any of
# these requires revising this guard with a documented rationale.
REQUIRED_SCRIPT_TOKENS = {
    # 1. Both required status-check contexts (order-exact: this is how the script
    #    writes the desired set).
    "desired_contexts": 'DESIRED_CONTEXTS=\'["Lint","Security Scan Gate"]\'',
    # 2. Admins are not exempt from branch protection.
    "enforce_admins_true": 'DESIRED_ENFORCE_ADMINS="true"',
    # 3. Up-to-date-before-merge.
    "strict_true": 'DESIRED_STRICT="true"',
    # 4. CODEOWNERS review required.
    "code_owner_reviews_true": 'DESIRED_CODE_OWNER_REVIEWS="true"',
    # 5. Safe-by-default: strict bash mode + default dry-run arm.
    "strict_bash_mode": "set -euo pipefail",
    "default_is_dry_run": '--dry-run|"") MODE="dry-run"',
    # 6. The drift marker the watch workflow greps for.
    "drift_marker": "DRIFT DETECTED",
}

# Required tokens in the drift-watch workflow.
REQUIRED_WATCH_TOKENS = {
    # 6. Same marker, on the consumer side.
    "drift_marker_grep": 'grep -q "DRIFT DETECTED"',
    # 7. Scheduled notifier + fail-on-tooling-error.
    "schedule_trigger": "schedule:",
    "fail_on_error_exit": "exit 1",
}


# Boolean desired-state vars that must be assigned exactly once to "true"
# (BP-4: a second last-wins `="false"` would weaken the posture while the first
# `="true"` still satisfies the token presence check).
BOOLEAN_DESIRED = {
    "DESIRED_ENFORCE_ADMINS": "true",
    "DESIRED_STRICT": "true",
    "DESIRED_CODE_OWNER_REVIEWS": "true",
}
_ASSIGN_RE = re.compile(r'^\s*(DESIRED_\w+)=["\']?([^"\'\s#]+)')


def _strip_comment_lines(text: str) -> str:
    """Drop whole-line comments (lstrip starts with '#') so a token that lives
    only in a comment cannot satisfy a presence check (sec-review BP-5/BP-8)."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _on_key_inline(line: str):
    """If `line` is a top-level `on:` mapping key (bare or quoted, BP-2), return
    the text after the colon — possibly empty, or flow-style content like
    `[push, pull_request]` (BP-1). Otherwise return None."""
    s = line.rstrip()
    # Only top-level keys (no leading indentation) are real `on:` triggers.
    if s != s.lstrip():
        return None
    for key in ("on:", "'on':", '"on":'):
        if s == key:
            return ""
        if s.startswith(key):
            return s[len(key):]
    return None


def _extract_on_block(text: str) -> str:
    """Return the workflow's top-level `on:` trigger content: the inline
    remainder of the `on:` line (flow style, BP-1) PLUS the indented child lines
    under it, up to the next top-level key. Whole-line comments are dropped so
    prose like '# ... MUST NOT run on pull_request events' is never matched, and
    bare/quoted `on:` keys are both handled (BP-2)."""
    body = []
    in_on = False
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if not in_on:
            inline = _on_key_inline(line)
            if inline is not None:
                in_on = True
                if inline.strip():
                    body.append(inline)  # flow-style content on the `on:` line
            continue
        # Inside the on: block. A new top-level key (non-space first char,
        # non-empty) ends it.
        if line and not line[0].isspace():
            break
        body.append(line)
    return "\n".join(body)


def script_violations(text: str) -> list:
    scan = _strip_comment_lines(text)
    problems = [
        f"MISSING required script invariant [{name}]: {tok!r}"
        for name, tok in sorted(REQUIRED_SCRIPT_TOKENS.items())
        if tok not in scan
    ]
    # BP-4: each boolean desired var assigned exactly once, to its expected value.
    for var, expected in sorted(BOOLEAN_DESIRED.items()):
        assigns = []
        for line in scan.splitlines():
            m = _ASSIGN_RE.match(line)
            if m and m.group(1) == var:
                assigns.append(m.group(2))
        if len(assigns) != 1:
            problems.append(
                f"BP-4 [{var}] must be assigned exactly once (found {len(assigns)}: "
                f"{assigns}) — a second assignment (bash last-wins) could silently "
                "override the posture."
            )
        elif assigns[0] != expected:
            problems.append(
                f"BP-4 [{var}] assigned {assigns[0]!r}, expected {expected!r} — "
                "branch-protection posture weakened."
            )
    return problems


def watch_violations(text: str) -> list:
    scan = _strip_comment_lines(text)
    problems = [
        f"MISSING required watch invariant [{name}]: {tok!r}"
        for name, tok in sorted(REQUIRED_WATCH_TOKENS.items())
        if tok not in scan
    ]
    # Bare `pull_request` substring catches both `pull_request:` (block style) and
    # flow-style `[push, pull_request]`, and subsumes `pull_request_target`.
    if "pull_request" in _extract_on_block(text):
        problems.append(
            "FORBIDDEN pull_request(_target) trigger in the on: block — the drift "
            "watch is a scheduled notifier and must never become a PR status check."
        )
    return problems


class TestBranchProtectionCodified(unittest.TestCase):
    """Guards the on-disk codified branch protection + its drift watch."""

    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8") if SCRIPT.is_file() else ""
        cls.watch = WATCH.read_text(encoding="utf-8") if WATCH.is_file() else ""

    def test_script_exists(self):
        self.assertTrue(
            SCRIPT.is_file(),
            f"{SCRIPT} not found — the codified branch-protection desired state "
            "has been deleted or moved.",
        )

    def test_watch_workflow_exists(self):
        self.assertTrue(
            WATCH.is_file(),
            f"{WATCH} not found — the nightly branch-protection drift watch has "
            "been deleted or moved.",
        )

    def test_required_contexts_present(self):
        self.assertIn(
            REQUIRED_SCRIPT_TOKENS["desired_contexts"], self.script,
            "DESIRED_CONTEXTS no longer pins both 'Lint' and 'Security Scan Gate' "
            "— --apply would un-require a mandatory status check, letting a PR "
            "merge with that whole gate red. Restore both contexts or update this "
            "guard with a rationale.",
        )

    def test_enforce_admins_true(self):
        self.assertIn(
            REQUIRED_SCRIPT_TOKENS["enforce_admins_true"], self.script,
            "DESIRED_ENFORCE_ADMINS is no longer \"true\" — admins would become "
            "exempt from branch protection and could force-push to main.",
        )

    def test_all_script_invariants_hold(self):
        problems = script_violations(self.script)
        self.assertEqual(
            problems, [],
            "scripts/sync-repo-protection.sh weakened a codified branch-protection "
            "invariant:\n  " + "\n  ".join(problems)
            + "\n\nRestore the desired value, or (if intentional) update "
            "REQUIRED_SCRIPT_TOKENS in this guard with a rationale.",
        )

    def test_all_watch_invariants_hold(self):
        problems = watch_violations(self.watch)
        self.assertEqual(
            problems, [],
            "protection-drift-watch.yml lost a drift-watch invariant:\n  "
            + "\n  ".join(problems)
            + "\n\nRestore it, or (if intentional) update REQUIRED_WATCH_TOKENS / "
            "this guard with a rationale.",
        )

    def test_drift_marker_contract(self):
        # The marker is a contract between producer (script) and consumer (watch).
        self.assertIn(
            "DRIFT DETECTED", self.script,
            "Script no longer emits the 'DRIFT DETECTED' marker.",
        )
        self.assertIn(
            'grep -q "DRIFT DETECTED"', self.watch,
            "Watch workflow no longer greps for the 'DRIFT DETECTED' marker — it "
            "would silently reclassify real drift as a tooling error and never "
            "open an alert issue.",
        )

    def test_notifier_has_no_pr_trigger(self):
        on_block = _extract_on_block(self.watch)
        self.assertNotIn(
            "pull_request", on_block,
            "protection-drift-watch.yml gained a pull_request(_target) trigger in "
            "its on: block — it is a scheduled notifier and must never become a "
            "required PR status check.",
        )
        self.assertIn(
            "schedule:", on_block,
            "protection-drift-watch.yml lost its schedule: trigger — drift would "
            "no longer be caught nightly.",
        )


class TestBranchProtectionCodifiedMutation(unittest.TestCase):
    """Mutation self-tests: the detectors must fire on known-bad inputs and stay
    quiet on the known-good real files."""

    _GOOD_SCRIPT = "\n".join(
        [
            "set -euo pipefail",
            'DESIRED_STRICT="true"',
            'DESIRED_CONTEXTS=\'["Lint","Security Scan Gate"]\'',
            'DESIRED_CODE_OWNER_REVIEWS="true"',
            'DESIRED_ENFORCE_ADMINS="true"',
            '  --dry-run|"") MODE="dry-run" ;;',
            '    lines.append(f"  DRIFT DETECTED in: {x}")',
        ]
    )

    _GOOD_WATCH = "\n".join(
        [
            "# This workflow MUST NOT run on pull_request events.",
            "on:",
            "  schedule:",
            "    - cron: '0 16 * * *'",
            "  workflow_dispatch:",
            "permissions:",
            "  contents: read",
            '          elif grep -q "DRIFT DETECTED" /tmp/drift-report.txt; then',
            "          exit 1",
        ]
    )

    def test_good_snippets_pass(self):
        self.assertEqual(script_violations(self._GOOD_SCRIPT), [])
        self.assertEqual(watch_violations(self._GOOD_WATCH), [])

    def test_dropping_a_required_context_is_detected(self):
        mutant = self._GOOD_SCRIPT.replace(
            'DESIRED_CONTEXTS=\'["Lint","Security Scan Gate"]\'',
            'DESIRED_CONTEXTS=\'["Lint"]\'',
        )
        self.assertTrue(
            any("desired_contexts" in p for p in script_violations(mutant)),
            "Mutation FAILED: dropping 'Security Scan Gate' from the required "
            "contexts was NOT detected.",
        )

    def test_disabling_enforce_admins_is_detected(self):
        mutant = self._GOOD_SCRIPT.replace(
            'DESIRED_ENFORCE_ADMINS="true"', 'DESIRED_ENFORCE_ADMINS="false"'
        )
        self.assertTrue(
            any("enforce_admins_true" in p for p in script_violations(mutant)),
            "Mutation FAILED: flipping enforce_admins to false was NOT detected.",
        )

    def test_changing_the_drift_marker_is_detected(self):
        mutant = self._GOOD_SCRIPT.replace("DRIFT DETECTED", "DRIFT FOUND")
        self.assertTrue(
            any("drift_marker" in p for p in script_violations(mutant)),
            "Mutation FAILED: renaming the DRIFT DETECTED marker (breaking the "
            "watch grep contract) was NOT detected.",
        )

    def test_pr_trigger_in_on_block_is_detected(self):
        mutant = self._GOOD_WATCH.replace(
            "  workflow_dispatch:",
            "  workflow_dispatch:\n  pull_request:\n    branches: [main]",
        )
        problems = watch_violations(mutant)
        self.assertTrue(
            any("pull_request" in p for p in problems),
            "Mutation FAILED: a pull_request trigger added to the on: block was "
            "NOT detected.",
        )

    def test_comment_mentioning_pull_request_does_not_false_positive(self):
        # The real workflow has a '# MUST NOT run on pull_request events' comment
        # OUTSIDE the on: block — it must not be read as a trigger.
        self.assertEqual(
            watch_violations(self._GOOD_WATCH), [],
            "False positive: prose mentioning 'pull_request' was treated as a "
            "trigger. Only the on: block should be scanned for triggers.",
        )

    def test_flow_style_pull_request_trigger_is_detected(self):
        # BP-1: flow-style on: list with pull_request must be caught.
        mutant = "\n".join(
            [
                "on: [schedule, workflow_dispatch, pull_request]",
                "permissions:",
                "  contents: read",
                '          elif grep -q "DRIFT DETECTED" /tmp/drift-report.txt; then',
                "          exit 1",
                "  schedule:",  # keep the schedule token present in full text
            ]
        )
        self.assertTrue(
            any("pull_request" in p for p in watch_violations(mutant)),
            "Mutation FAILED (BP-1): a flow-style `on: [..., pull_request]` trigger "
            "was NOT detected.",
        )

    def test_quoted_on_key_pull_request_is_detected(self):
        # BP-2: quoted 'on': key must still be parsed as the on: block.
        mutant = "\n".join(
            [
                "'on':",
                "  schedule:",
                "    - cron: '0 16 * * *'",
                "  pull_request:",
                "    branches: [main]",
                "permissions:",
                '          elif grep -q "DRIFT DETECTED" /tmp/drift-report.txt; then',
                "          exit 1",
            ]
        )
        self.assertTrue(
            any("pull_request" in p for p in watch_violations(mutant)),
            "Mutation FAILED (BP-2): a quoted `'on':` key with a pull_request "
            "trigger was NOT detected.",
        )

    def test_comment_only_token_does_not_satisfy_check(self):
        # BP-5: enforce_admins="true" only in a comment, active value "false".
        mutant = self._GOOD_SCRIPT.replace(
            'DESIRED_ENFORCE_ADMINS="true"',
            '# legacy: DESIRED_ENFORCE_ADMINS="true"\nDESIRED_ENFORCE_ADMINS="false"',
        )
        problems = script_violations(mutant)
        self.assertTrue(
            problems,
            "Mutation FAILED (BP-5): enforce_admins='true' surviving only in a "
            "comment while the active assignment is 'false' was NOT detected.",
        )

    def test_second_enforce_admins_assignment_is_detected(self):
        # BP-4: a second last-wins assignment to "false".
        mutant = self._GOOD_SCRIPT + '\nDESIRED_ENFORCE_ADMINS="false"'
        self.assertTrue(
            any("BP-4" in p and "DESIRED_ENFORCE_ADMINS" in p
                for p in script_violations(mutant)),
            "Mutation FAILED (BP-4): a duplicate DESIRED_ENFORCE_ADMINS assignment "
            "(last-wins override) was NOT detected.",
        )

    def test_real_files_clean(self):
        if SCRIPT.is_file():
            self.assertEqual(
                script_violations(SCRIPT.read_text(encoding="utf-8")), [],
                "The real sync-repo-protection.sh failed the invariant validator.",
            )
        if WATCH.is_file():
            self.assertEqual(
                watch_violations(WATCH.read_text(encoding="utf-8")), [],
                "The real protection-drift-watch.yml failed the invariant validator.",
            )


if __name__ == "__main__":
    unittest.main()
