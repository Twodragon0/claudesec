"""
Regression guard: `dast-freshness-watch.yml` keeps watching whether the nightly
DAST scan RUNS AT ALL — the failure mode no job inside that scan can report.

THE RISK (an absence has no colour)
-----------------------------------
`dast-full-scan.yml` used to be gated on the `DAST_TARGET_URL` repo variable.
Unset, the job was SKIPPED and the workflow conclusion was a clean `skipped`:
42 consecutive nights of ZERO DAST, nothing red, nobody told (measured
2026-08-06). #497 removed the gate — the nightly now scans this repo's own
dashboard container, so it cannot skip — and removed the `coverage-notice` job
along with it, correctly: a notice about a missing variable would have reported
"not running" on every night the scan ran fine.

That closed the SKIP half and left the STOP half open. A schedule that never
fires produces no run at all, so there is nothing to be skipped, nothing to be
red, and the workflow's history simply ends while the Actions list keeps showing
the last green run. It is a strictly quieter failure than the one #497 fixed.
Each of these produces it, and none is hypothetical:

  - GitHub disables every `schedule:` in a repository after 60 days without
    commit activity.
  - `gh workflow disable`, or Actions turned off repo-wide.
  - `schedule:` delivery is best-effort and can be dropped; this repo has a ~10h
    delay on record (run 33070461602, 2026-08-27 12:08 UTC for an 02:00 cron).
  - The workflow file is renamed/deleted, or the default branch changes.
  - Runs happen but every one FAILS, so no successful scan exists.

WHAT THIS GUARD CHECKS / DOES NOT
---------------------------------
Direction is PRESENCE of a liveness check that can actually reach a human, plus
the three properties without which it is decorative:

1. **Triggers.** `schedule:` (a watcher that only runs on demand watches
   nothing) AND `push:` — the second is not redundant. A watcher whose only
   automatic trigger is cron shares the exact failure mode it exists to catch:
   the 60-day inactivity shutdown and a repo-wide Actions disable take out EVERY
   schedule, the watcher's included. `push` is the one path that survives them.
   `pull_request(_target)` is forbidden: a notifier must never become a required
   PR status check.
2. **Scope.** The Actions query must filter `event: 'schedule'` and
   `status: 'success'`. Without the event filter a hand-pressed
   `workflow_dispatch` masks a dead cron — "someone was present" is not "the
   schedule is alive", and accepting it rebuilds the looks-covered-is-not shape
   in a new place. Without the success filter an all-red streak reads as
   coverage.
3. **Escalation and self-healing.** It must open/update an issue (an
   `core.info` that nobody reads is how `protection-drift-watch.yml` ran green
   for weeks — #396), must CLOSE that issue when the scan is fresh again (a
   notifier that never retracts gets muted, which is silence again), and must
   `core.setFailed` when the API read throws, because "I could not check" must
   never conclude the same as "I checked and it is fine".
4. **Coupling to the thing watched.** `WATCHED_WORKFLOW` must name a workflow
   that EXISTS and that declares `schedule:`. Watching a cron-less workflow
   would alarm forever; watching a renamed one would alarm forever too, which is
   why the API error path is a hard failure rather than a verdict.

It does NOT require the job to FAIL when the scan is stale. Repo convention for
notifier workflows (`lychee-redirect-sweep.yml` #298, `protection-drift-watch.yml`
#396): Actions has no `neutral` conclusion for a regular job, and a notifier that
is red every day until someone acts trains the owner to ignore it. That trade-off
is a documented product decision, not an oversight for this guard to police.

It does NOT re-assert SHA pinning — `test_ci_gate_topology.test_every_uses_is_sha_pinned`
already covers every `uses:` in every workflow.

THRESHOLD BOUNDS
----------------
`MAX_AGE_HOURS` is asserted `> 24` and `<= 72`, and the bounds are the two ways
the check stops working rather than a taste preference. The watched cron period
is 24h and delivery is best-effort, so a threshold at or below the period fires
on ordinary jitter (the ~10h delay above would have tripped a 24h window) and a
notifier that cries wolf gets muted. Above 72h, three whole nights of no DAST
pass before anyone is told, which is close enough to the six silent weeks this
whole lineage is about. Changing the nightly cadence means changing this
constant in the same PR — that is the coupling being pinned.

Scans the comment-stripped text in BOTH comment syntaxes the file uses: YAML `#`
lines and, inside the `script:` block scalar, JavaScript `//` lines. The workflow
header explains at length what the script must do, so a raw substring scan would
be satisfied by the EXPLANATION of a control that had been deleted (ADR-001 §2,
the inert-guard class).

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.

OWASP CICD-SEC-10 (Insufficient Logging and Visibility); NIST SP 800-137 (ISCM)
— continuous monitoring is only continuous if something verifies it is running.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    explicit_key_lines,
    extract_on_block,
    strip_comment_lines,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
WATCH = WORKFLOW_DIR / "dast-freshness-watch.yml"

MIN_THRESHOLD_HOURS = 24  # exclusive — see THRESHOLD BOUNDS above
MAX_THRESHOLD_HOURS = 72  # inclusive

_WATCHED_RE = re.compile(r"^\s*WATCHED_WORKFLOW:\s*(?P<name>[^\s#]+)\s*$", re.M)
_MAX_AGE_RE = re.compile(r"""^\s*MAX_AGE_HOURS:\s*['"]?(?P<hours>\d+)['"]?\s*$""", re.M)

_EVENT_FILTER_RE = re.compile(r"""\bevent:\s*['"]schedule['"]""")
_STATUS_FILTER_RE = re.compile(r"""\bstatus:\s*['"]success['"]""")
_ISSUE_WRITE_RE = re.compile(r"""\bissues\.(?:create|update)\s*\(""")
_ISSUE_CLOSE_RE = re.compile(r"""\bstate:\s*['"]closed['"]""")
_SET_FAILED_RE = re.compile(r"""\bcore\.setFailed\s*\(""")


def active(text: str) -> str:
    """`text` with whole-line comments dropped in BOTH syntaxes it contains.

    YAML `#` lines come out via the shared primitive; JavaScript `//` lines need
    their own pass because they live inside a block scalar, where YAML sees
    ordinary content. Both matter here for the same reason: this workflow's
    header spends sixty lines explaining what the script does, so every token the
    checks below look for is also present as prose or as a JS section divider.

    Only WHOLE-line comments are dropped. A trailing `// ...` on a line of real
    code leaves executable code behind, so removing the whole line would be the
    false-alarm direction."""
    return "\n".join(
        line
        for line in strip_comment_lines(text).splitlines()
        if not line.lstrip().startswith("//")
    )


def trigger_problems(text: str) -> list:
    """Problems with the `on:` block: missing liveness triggers, or a PR trigger.

    Read from the `on:` block only, so the header's prose (which names
    `pull_request` precisely to forbid it) cannot false-trip the scan, and
    comment-stripped inside the block for the same reason one level down."""
    problems = []
    on_block = active(extract_on_block(text))
    for key, why in (
        (
            "schedule",
            "a watcher with no cron only runs when someone asks, and nobody asks "
            "about a scan they believe is running",
        ),
        (
            "push",
            "cron is the mechanism being watched — GitHub disables every "
            "`schedule:` after 60 days of repo inactivity, taking this watcher "
            "with it. `push` to main is the trigger that survives that, and it "
            "is when a human is present to be told",
        ),
    ):
        if not re.search(rf"(?m)^\s*{yaml_key_pattern(key)}\s*:", on_block):
            problems.append(f"`on:` lost its `{key}:` trigger — {why}.")

    for key in ("pull_request", "pull_request_target"):
        if re.search(rf"(?m)^\s*{yaml_key_pattern(key)}\s*:", on_block):
            problems.append(
                f"`on:` gained a `{key}:` trigger. This is a notifier and must "
                "never become a required PR status check (its own header says so)."
            )

    unscannable = explicit_key_lines(text, "schedule", "push", "pull_request")
    if unscannable:
        problems.append(
            "A trigger key uses YAML's explicit-key form (`? key` / `: value`), "
            f"which the checks above cannot read: {unscannable!r}. Use the "
            "ordinary `key: value` form."
        )
    return problems


def scope_problems(text: str) -> list:
    """Problems with WHAT the freshness query counts as coverage."""
    body = active(text)
    problems = []
    if not _EVENT_FILTER_RE.search(body):
        problems.append(
            "The run query no longer filters `event: 'schedule'`. A "
            "`workflow_dispatch` run proves someone pressed a button, not that "
            "the cron is alive, so counting manual runs lets a hand-run scan mask "
            "a dead schedule — the same looks-covered-is-not shape #497 fixed."
        )
    if not _STATUS_FILTER_RE.search(body):
        problems.append(
            "The run query no longer filters `status: 'success'`. Runs that fire "
            "and FAIL would then count as freshness, so an all-red nightly would "
            "report as covered."
        )
    return problems


def escalation_problems(text: str) -> list:
    """Problems with the paths that reach a human (or fail loudly)."""
    body = active(text)
    problems = []
    if not _ISSUE_WRITE_RE.search(body):
        problems.append(
            "Nothing calls `issues.create`/`issues.update`. A `core.info`/"
            "`core.warning` alone is invisible — that is exactly how "
            "`protection-drift-watch.yml` reported green for weeks (#396)."
        )
    if not _ISSUE_CLOSE_RE.search(body):
        problems.append(
            "Nothing sets `state: 'closed'`, so the notice never retracts. A "
            "stale issue that stays open after the scan recovers gets muted, and "
            "a muted notifier is silence again."
        )
    if not _SET_FAILED_RE.search(body):
        problems.append(
            "The Actions-API read has no `core.setFailed` path. An unreadable "
            "check that exits 0 concludes the same as a healthy one — the failure "
            "mode this workflow exists to prevent, reproduced one level up."
        )
    return problems


def swallow_problems(text: str) -> list:
    """`continue-on-error` anywhere in this workflow.

    The only thing that fails this job is a tooling error, which is precisely the
    verdict `continue-on-error` discards. There is no legitimate use here, so the
    check is a flat ban rather than an allowlist."""
    body = active(text)
    problems = []
    if re.search(rf"(?m)^\s*{yaml_key_pattern('continue-on-error')}\s*:", body):
        problems.append(
            "`continue-on-error` found. The job's only failure is the tooling "
            "error that means 'DAST freshness is UNKNOWN'; swallowing it turns "
            "the watcher itself into a green no-op."
        )
    unscannable = explicit_key_lines(text, "continue-on-error")
    if unscannable:
        problems.append(
            "`? continue-on-error` explicit-key form found, which the check above "
            f"cannot read: {unscannable!r}."
        )
    return problems


def permission_problems(text: str) -> list:
    """The workflow must be able to write issues, or every escalation 403s."""
    body = active(text)
    if not re.search(r"(?m)^\s*issues:\s*write\s*$", body):
        return [
            "No `issues: write` permission. Every `issues.create/update` call "
            "would 403 and the escalation path would exist but never land."
        ]
    return []


class TestDastFreshnessWatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WATCH.read_text(encoding="utf-8") if WATCH.is_file() else ""

    def test_workflow_exists(self):
        self.assertTrue(
            WATCH.is_file(),
            f"{WATCH} not found. The nightly DAST scan cannot report its own "
            "absence — if the schedule stops firing there is no run to be red. "
            "Removing this watcher restores the invisible-gap state of #399.",
        )

    def test_triggers(self):
        self.assertEqual(trigger_problems(self.text), [])

    def test_query_scope(self):
        self.assertEqual(scope_problems(self.text), [])

    def test_escalation_and_self_healing(self):
        self.assertEqual(escalation_problems(self.text), [])

    def test_verdict_is_not_swallowed(self):
        self.assertEqual(swallow_problems(self.text), [])

    def test_can_write_issues(self):
        self.assertEqual(permission_problems(self.text), [])

    def test_threshold_is_within_useful_bounds(self):
        m = _MAX_AGE_RE.search(active(self.text))
        self.assertIsNotNone(
            m,
            "No `MAX_AGE_HOURS: <n>` found. The staleness threshold must stay a "
            "reviewable constant in the workflow, not a literal buried in the "
            "script body.",
        )
        hours = int(m.group("hours"))
        self.assertGreater(
            hours,
            MIN_THRESHOLD_HOURS,
            f"MAX_AGE_HOURS={hours} is at or below the 24h cron period, so "
            "ordinary best-effort jitter trips it (a ~10h delay is already on "
            "record). A notifier that cries wolf gets muted.",
        )
        self.assertLessEqual(
            hours,
            MAX_THRESHOLD_HOURS,
            f"MAX_AGE_HOURS={hours} lets three or more whole nights of zero DAST "
            "pass unreported, which is the six-silent-weeks failure this lineage "
            "exists to end.",
        )


class TestWatchedWorkflowCoupling(unittest.TestCase):
    """The thing being watched must exist and must actually have a schedule.

    Both directions alarm FOREVER if broken, and a permanently-red notifier is
    indistinguishable from a broken one after the second week."""

    @classmethod
    def setUpClass(cls):
        cls.text = WATCH.read_text(encoding="utf-8") if WATCH.is_file() else ""
        m = _WATCHED_RE.search(active(cls.text))
        cls.watched_name = m.group("name") if m else None

    def test_watched_workflow_is_named(self):
        self.assertIsNotNone(
            self.watched_name,
            "No `WATCHED_WORKFLOW: <file>` env entry. The target must be a named "
            "constant the guard can follow, not a value interpolated at run time.",
        )

    def test_watched_workflow_exists(self):
        # Vacuity canary AND the real no-ghost check: a renamed target makes the
        # API read 404 every night, which this workflow reports as a hard failure
        # — correct, but the cheaper place to catch it is the PR that renames it.
        target = WORKFLOW_DIR / self.watched_name
        self.assertTrue(
            target.is_file(),
            f"WATCHED_WORKFLOW names {self.watched_name!r}, which is not a file in "
            f"{WORKFLOW_DIR}. Rename the reference in the same change.",
        )

    def test_watched_workflow_has_a_schedule(self):
        target = WORKFLOW_DIR / self.watched_name
        on_block = strip_comment_lines(
            extract_on_block(target.read_text(encoding="utf-8"))
        )
        self.assertTrue(
            re.search(rf"(?m)^\s*{yaml_key_pattern('schedule')}\s*:", on_block),
            f"{self.watched_name} has no `schedule:` trigger, so there will never "
            "be a scheduled run to be fresh and this watcher would alarm forever. "
            "If the nightly claim is being dropped, drop this watcher in the same "
            "change — do not leave a permanently-red notice nobody can satisfy.",
        )
        self.assertTrue(
            re.search(r"(?m)^\s*-\s*cron:", on_block),
            f"{self.watched_name} declares `schedule:` with no `cron:` entry.",
        )


class TestDetectorMutation(unittest.TestCase):
    """Non-vacuity: each detector must FIRE on a real disabling edit of the REAL
    workflow and stay QUIET on the shipped one. Fixtures are mutations of the
    file on disk, not hand-written lookalikes, so a rewrite of the workflow
    invalidates the fixture loudly (`apply_mutation` refuses a no-op) instead of
    leaving a tautology behind."""

    @classmethod
    def setUpClass(cls):
        cls.clean = WATCH.read_text(encoding="utf-8")

    def test_dropping_the_schedule_is_caught(self):
        mutant = apply_mutation(self.clean, "    - cron: '30 14 * * *'", "")
        mutant = apply_mutation(mutant, "\n  schedule:\n", "\n")
        assert_disables(trigger_problems, self.clean, mutant, "schedule removed")

    def test_dropping_the_push_trigger_is_caught(self):
        # The subtle regression: the watcher still "works" every night, and only
        # stops the day GitHub disables schedules — the day it is needed.
        mutant = apply_mutation(
            self.clean, "  push:\n    branches: [main]\n", ""
        )
        assert_disables(trigger_problems, self.clean, mutant, "push removed")

    def test_gaining_a_pull_request_trigger_is_caught(self):
        mutant = apply_mutation(
            self.clean, "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"
        )
        assert_disables(trigger_problems, self.clean, mutant, "pull_request added")

    def test_counting_manual_runs_is_caught(self):
        mutant = apply_mutation(self.clean, "                event: 'schedule',\n", "")
        assert_disables(scope_problems, self.clean, mutant, "event filter dropped")

    def test_counting_failed_runs_is_caught(self):
        mutant = apply_mutation(self.clean, "                status: 'success',\n", "")
        assert_disables(scope_problems, self.clean, mutant, "status filter dropped")

    def test_downgrading_the_tooling_error_to_a_log_is_caught(self):
        mutant = apply_mutation(self.clean, "core.setFailed(", "core.info(")
        assert_disables(escalation_problems, self.clean, mutant, "setFailed -> info")

    def test_a_js_commented_close_branch_does_not_count(self):
        # The comment-evasion class in its JavaScript spelling: the close path is
        # still visible in the diff, still greppable, and dead.
        mutant = apply_mutation(
            self.clean,
            "                  state: 'closed',",
            "                  // state: 'closed',",
        )
        assert_disables(
            escalation_problems, self.clean, mutant, "close branch commented out"
        )

    def test_a_job_level_continue_on_error_is_caught(self):
        mutant = apply_mutation(
            self.clean,
            "    timeout-minutes: 5\n",
            "    timeout-minutes: 5\n    continue-on-error: true\n",
        )
        assert_disables(
            swallow_problems, self.clean, mutant, "job continue-on-error"
        )

    def test_dropping_issues_write_is_caught(self):
        mutant = apply_mutation(self.clean, "  issues: write\n", "")
        assert_disables(
            permission_problems, self.clean, mutant, "issues: write removed"
        )

    def test_a_yaml_commented_mention_does_not_count_as_the_control(self):
        # The other comment syntax, and the reason the YAML pass exists at all.
        # The header is sixty lines of prose about what this script must do, so
        # the realistic regression is a control deleted while an explanation of
        # it survives — and `_ISSUE_CLOSE_RE` is unanchored, so a `#` line
        # mentioning `state: 'closed'` really does satisfy an unstripped scan.
        # Verified by BOTH directions below: caught with stripping, and shown to
        # be a genuine bypass without it.
        mutant = apply_mutation(
            self.clean, "                  state: 'closed',\n", ""
        )
        mutant = apply_mutation(
            mutant,
            "# WHY AN ISSUE AND NOT A FAILING JOB",
            "# The recovery path sets state: 'closed' on the notice.\n"
            "# WHY AN ISSUE AND NOT A FAILING JOB",
        )
        self.assertFalse(
            _ISSUE_CLOSE_RE.search(mutant) is None,
            "fixture is stale: the planted comment should be findable in the RAW "
            "text, or this proves nothing about stripping",
        )
        assert_disables(
            escalation_problems, self.clean, mutant, "close branch left only in prose"
        )

    def test_no_false_alarm_on_the_shipped_workflow(self):
        # Positive control for all five detectors at once.
        self.assertEqual(
            (
                trigger_problems(self.clean)
                + scope_problems(self.clean)
                + escalation_problems(self.clean)
                + swallow_problems(self.clean)
                + permission_problems(self.clean)
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
