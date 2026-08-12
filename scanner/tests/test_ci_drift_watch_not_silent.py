"""
Regression guard: `protection-drift-watch.yml` must never degrade SILENTLY.

THE RISK (a green check for work that never happened)
----------------------------------------------------
The watcher reads `repos/{repo}/branches/main/protection`, which the built-in
`GITHUB_TOKEN` cannot do, so it needs a `REPO_ADMIN_TOKEN` PAT. That secret does
not exist yet. The workflow's original graceful-degradation branch logged a
`::warning::` and exited 0 — and because GitHub Actions has **no `neutral`
conclusion for a regular job** (only success / failure / cancelled / skipped; the
Docker-action exit-code-78 neutral was removed in 2019), every one of those runs
reported **success**.

Measured incident (2026-08-06): the daily schedule fired correctly and every run
was green, while the drift check had **never once executed** since the workflow
landed in #251. Branch-protection drift — the thing that guards the required
merge contexts and `enforce_admins` — was unmonitored the whole time, with no
signal anywhere. `gh api repos/.../actions/secrets` returned `total_count: 0`,
confirming the secret's absence rather than inferring it.

The fix was to surface the degraded state as a self-healing `protection-drift`
issue (the repo convention for notifier workflows, cf. `lychee-redirect-sweep.yml`
#298) plus a run-summary statement. This guard keeps that promise: the
"token missing" branch must do something VISIBLE, not just log.

WHAT IT CHECKS / DOES NOT
-------------------------
- Direction: PRESENCE of the escalation path. There must be a step gated on
  `token_present == 'false'` that creates or edits an issue, and the label lookup
  it depends on must be reachable in that same condition (otherwise it would
  duplicate the issue on every run instead of updating one).
- The workflow must keep its `schedule:` trigger and must NOT gain a
  `pull_request` trigger — it is a notifier and must never become a required check
  (stated as an invariant in its own header comment, never enforced until now).
- It does NOT assert the issue's wording, and it does NOT require the job to FAIL
  when the token is absent. Failing a notifier daily forever is notification
  fatigue, not signal; that trade-off is documented in the workflow header and is
  a deliberate product decision, not an oversight this guard should police.
- Scans the comment-stripped text, so a step parked behind a `#` cannot satisfy
  the presence checks. The stripping itself is ADR-001 §1 (shared comment-stripping
  primitives); the "inert-guard" label is ADR-001 §2 (scope the haystack), which is
  the class #383 meta-guarded.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    explicit_key_lines,
    extract_on_block,
    strip_comment_lines,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DRIFT_WATCH = REPO_ROOT / ".github" / "workflows" / "protection-drift-watch.yml"

# The degraded-mode condition, as written in the workflow. Whitespace-tolerant so
# reformatting the `if:` does not trip the guard.
_TOKEN_ABSENT_RE = re.compile(
    r"""steps\.token_check\.outputs\.token_present\s*==\s*['"]false['"]"""
)
# Something that actually reaches a human: creating or editing an issue.
_ISSUE_ACTION_RE = re.compile(r"""gh\s+issue\s+(?:create|edit)\b""")


def steps_gated_on_token_absent(text: str) -> list:
    """The `- name:` values of steps whose `if:` references the token-absent
    condition, read from the comment-stripped workflow.

    Indentation-based: a step starts at a `- name:`/`- uses:` list item and ends at
    the next one, so a condition is attributed to the step it belongs to."""
    lines = strip_comment_lines(text).splitlines()
    blocks, current = [], None
    for raw in lines:
        if re.match(r"^\s*-\s+(?:name|uses):", raw):
            if current is not None:
                blocks.append(current)
            current = [raw]
        elif current is not None:
            current.append(raw)
    if current is not None:
        blocks.append(current)

    out = []
    for block in blocks:
        body = "\n".join(block)
        if not _TOKEN_ABSENT_RE.search(body):
            continue
        m = re.match(r"^\s*-\s+name:\s*(.+?)\s*$", block[0])
        out.append(m.group(1) if m else block[0].strip())
    return out


def escalates_when_token_absent(text: str) -> bool:
    """True if at least one token-absent-gated step actually opens/edits an issue.

    A step that only `echo`es is NOT escalation — that is precisely the shape which
    reported green for weeks."""
    lines = strip_comment_lines(text).splitlines()
    blocks, current = [], None
    for raw in lines:
        if re.match(r"^\s*-\s+(?:name|uses):", raw):
            if current is not None:
                blocks.append(current)
            current = [raw]
        elif current is not None:
            current.append(raw)
    if current is not None:
        blocks.append(current)
    return any(
        _TOKEN_ABSENT_RE.search("\n".join(b)) and _ISSUE_ACTION_RE.search("\n".join(b))
        for b in blocks
    )


class TestDriftWatchDoesNotFailSilently(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            DRIFT_WATCH.read_text(encoding="utf-8") if DRIFT_WATCH.is_file() else ""
        )

    def test_workflow_exists(self):
        self.assertTrue(DRIFT_WATCH.is_file(), f"{DRIFT_WATCH} not found")

    def test_degraded_mode_is_escalated_not_just_logged(self):
        self.assertTrue(
            steps_gated_on_token_absent(self.text),
            "No step is gated on `token_present == 'false'`. The workflow must do "
            "something when REPO_ADMIN_TOKEN is missing — a job that no-ops reports "
            "SUCCESS (Actions has no `neutral` for a regular job), which is how this "
            "watch ran green for weeks without ever reading branch protection.",
        )
        self.assertTrue(
            escalates_when_token_absent(self.text),
            "The token-absent branch exists but never calls `gh issue create/edit`. "
            "An `echo`/`::warning::` alone is invisible — that is the exact regression "
            "this guard exists to prevent. Keep the self-healing "
            "`protection-drift` issue.",
        )

    def test_existing_issue_lookup_is_reachable_when_token_absent(self):
        # Without the lookup, the escalation step cannot find the open issue and
        # would open a NEW one on every scheduled run — turning one actionable
        # signal into daily spam, which gets muted, which is silence again.
        lookup = [
            name
            for name in steps_gated_on_token_absent(self.text)
            if "existing" in name.lower() or "find" in name.lower()
        ]
        self.assertTrue(
            lookup,
            "The 'find existing open drift issue' step is not reachable when the "
            "token is absent, so the escalation would create a duplicate issue every "
            "run instead of updating one. Add the token-absent condition to its "
            f"`if:`. Steps currently gated on it: {steps_gated_on_token_absent(self.text)}",
        )

    def test_keeps_schedule_and_never_gains_pull_request(self):
        on_block = extract_on_block(self.text)
        self.assertTrue(
            re.search(rf"(?m)^\s*{yaml_key_pattern('schedule')}\s*:", on_block),
            "protection-drift-watch.yml lost its `schedule:` trigger — a watcher that "
            "only runs on demand watches nothing.",
        )
        forbidden = [
            key
            for key in ("pull_request", "pull_request_target")
            if re.search(rf"(?m)^\s*{yaml_key_pattern(key)}\s*:", on_block)
        ]
        self.assertEqual(
            forbidden,
            [],
            "protection-drift-watch.yml gained a "
            f"{', '.join(forbidden)} trigger. It is a scheduled notifier and must "
            "never become a required PR status check (its own header says so).",
        )
        self.assertEqual(
            explicit_key_lines(self.text, "schedule", "pull_request"),
            [],
            "A trigger key uses YAML's explicit-key form (`? key` / `: value`), which "
            "the checks above cannot read. Use the ordinary `key: value` form.",
        )


class TestDriftWatchDetectorMutation(unittest.TestCase):
    """Non-vacuity: the detectors must FIRE on the log-only shape (the real
    pre-fix workflow) and stay QUIET on the escalating shape."""

    _LOG_ONLY = "\n".join(
        [
            "jobs:",
            "  drift-watch:",
            "    steps:",
            "      - name: Verify admin token is configured",
            "        id: token_check",
            "        run: echo token_present=false >> $GITHUB_OUTPUT",
            "      - name: Warn",
            "        if: steps.token_check.outputs.token_present == 'false'",
            "        run: echo '::warning::no token'",
        ]
    )
    _ESCALATING = "\n".join(
        [
            "jobs:",
            "  drift-watch:",
            "    steps:",
            "      - name: Find existing open drift issue",
            "        if: steps.token_check.outputs.token_present == 'false'",
            "        run: gh issue list --label protection-drift",
            "      - name: Surface missing admin token as an issue",
            "        if: steps.token_check.outputs.token_present == 'false'",
            "        run: gh issue create --label protection-drift --body-file /tmp/b.md",
        ]
    )

    def test_fires_on_log_only_degradation(self):
        self.assertTrue(
            steps_gated_on_token_absent(self._LOG_ONLY),
            "the token-absent step itself was not detected",
        )
        self.assertFalse(
            escalates_when_token_absent(self._LOG_ONLY),
            "Mutation FAILED: a branch that only echoes a warning was accepted as "
            "escalation — the exact silent-success shape this guard targets.",
        )

    def test_quiet_on_escalating_shape(self):
        self.assertTrue(
            escalates_when_token_absent(self._ESCALATING),
            "False negative: a branch that opens an issue was not recognised as "
            "escalation.",
        )

    def test_commented_out_escalation_does_not_count(self):
        commented = self._ESCALATING.replace(
            "        run: gh issue create --label protection-drift --body-file /tmp/b.md",
            "        # run: gh issue create --label protection-drift --body-file /tmp/b.md",
        )
        self.assertFalse(
            escalates_when_token_absent(commented),
            "Mutation FAILED: a `#`-commented `gh issue create` satisfied the "
            "escalation check (inert-guard class — the scan must strip comments).",
        )

    def test_step_attribution_does_not_leak_across_steps(self):
        # A condition on one step must not credit a `gh issue create` that lives in
        # a DIFFERENT, unconditional step.
        split = "\n".join(
            [
                "jobs:",
                "  drift-watch:",
                "    steps:",
                "      - name: Warn only",
                "        if: steps.token_check.outputs.token_present == 'false'",
                "        run: echo '::warning::no token'",
                "      - name: Unrelated issue step",
                "        run: gh issue create --title x",
            ]
        )
        self.assertFalse(
            escalates_when_token_absent(split),
            "Mutation FAILED: a `gh issue create` in an unrelated, unconditional step "
            "was credited to the token-absent branch — step attribution is broken.",
        )

    def test_real_workflow_escalates(self):
        text = DRIFT_WATCH.read_text(encoding="utf-8")
        self.assertTrue(
            escalates_when_token_absent(text),
            "positive control: the real workflow must satisfy the detector",
        )


if __name__ == "__main__":
    unittest.main()
