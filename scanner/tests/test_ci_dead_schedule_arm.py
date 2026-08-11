"""
Regression guard: no workflow relies on a `schedule` arm it can never take.

THE RISK (a gate that silently never runs)
------------------------------------------
Path-gated jobs in this repo take the form

    if: needs.changes.outputs.<bucket> == 'true' || github.event_name == 'schedule'

The second arm is the escape hatch: it is what guarantees a job whose bucket is
rarely touched still gets revalidated periodically. If the workflow itself has no
`schedule:` trigger, that arm can NEVER evaluate true, and the job runs only when
its bucket happens to be edited. Nothing fails; the job just reports `skipped`
forever, which reads as green.

WHY IT IS NEEDED HERE (incident-backed bar)
-------------------------------------------
`lint.yml` had seven such jobs and NO `schedule:` trigger (verified over 1118
historical runs: 654 `pull_request` + 464 `push`, zero `schedule`). Measured
consequences:

- `npm-audit`: ZERO real executions for ~7 weeks / 117 `main` commits — its
  bucket (`package*.json` / `.nvmrc`) was last touched in `e5b9bbb`. A newly
  disclosed advisory against the locked tree would have gone unnoticed
  indefinitely.
- `pip-audit`: likewise dark, until a `requirements-fork-guard.txt` edit finally
  fired it and it failed on the spot with accumulated runner drift
  (`setuptools` PYSEC-2026-3447) — a failure that looked like it belonged to the
  unrelated PR that surfaced it.

The fix was a weekly `schedule:` on `lint.yml`; this guard is what keeps the
promise. It is deliberately repo-wide rather than `lint.yml`-specific: the trap is
generic and the next workflow to grow a `schedule` arm should not have to
rediscover it. Contrast `security-scan.yml`, which DOES carry
`schedule: '0 9 * * 1'` — its arm is live and firing weekly. That is the shape
this guard requires.

WHAT IT CHECKS / DOES NOT
-------------------------
- Direction: **consistency**. For every workflow, IF any job's `if:` references
  `github.event_name == 'schedule'` (or `contains(... 'schedule')`), THEN the
  workflow's own `on:` block must declare `schedule:`. Removing the trigger while
  leaving the arms, or adding an arm to a workflow with no trigger, both trip it.
- It does NOT require a schedule where no job asks for one, and it does NOT check
  the cron cadence — a schedule that exists but is wrong is a different question
  and would need a policy this repo has not set.
- The `on:` block is located with the shared `extract_on_block` (handles
  bare/quoted `on:`); `schedule` and the job `if:` key are matched with
  `yaml_key_pattern` so a quoted form counts as present. An `? schedule`
  explicit-key form fails closed via `explicit_key_lines`, since the literal
  `schedule:` never appears there for any matcher to find.
- Scans workflows in BOTH extensions (composite actions have no `on:`, so
  `workflow_and_action_files` is deliberately NOT used here).

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import re
import sys
import unittest
from glob import glob
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
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# A line gates on the schedule event when it references `github.event_name` AND a
# quoted `schedule` token. Deliberately NOT an enumeration of comparison shapes:
# a first attempt matched `== 'schedule'`, the reversed comparison, and
# `contains(...)` separately, and the `contains` pattern immediately failed on
# `contains(fromJSON('["schedule","push"]'), github.event_name)` because its
# `[^)]*` could not span the `)` inside `fromJSON(...)`. Enumerating expression
# syntax is the mistake ADR-001 §5 warns about; the *co-occurrence* is the real
# invariant and it holds for every spelling, present and future.
#
# Error direction is safe: a line that merely mentions both (say an `echo`) causes
# this guard to DEMAND a `schedule:` trigger — a false alarm a reviewer resolves in
# seconds, never a silent bypass.
_EVENT_NAME_RE = re.compile(r"github\.event_name")
_SCHEDULE_TOKEN_RE = re.compile(r"""["']schedule["']""")


def workflow_files() -> list:
    """Workflow files in BOTH extensions (Actions honours `.yml` and `.yaml`)."""
    return sorted(
        glob(str(WORKFLOW_DIR / "*.yml")) + glob(str(WORKFLOW_DIR / "*.yaml"))
    )


def has_schedule_arm(text: str) -> bool:
    """True if any line of `text` gates on the `schedule` event.

    Comment lines are dropped first: a commented-out arm is not a live promise, so
    demanding a trigger for it would be a false alarm. Matched per LINE, so an
    unrelated `github.event_name` elsewhere in the file cannot pair up with a
    `'schedule'` token far away."""
    return any(
        _EVENT_NAME_RE.search(ln) and _SCHEDULE_TOKEN_RE.search(ln)
        for ln in strip_comment_lines(text).splitlines()
    )


def declares_schedule_trigger(text: str) -> bool:
    """True if the workflow's top-level `on:` block declares `schedule:`.

    Scoped to the `on:` block via `extract_on_block`, so a `schedule:` key nested
    under something else (or the word appearing in a job name) does not count."""
    on_block = extract_on_block(text)
    return bool(
        re.search(rf"(?m)^\s*{yaml_key_pattern('schedule')}\s*:", on_block)
    )


def dead_schedule_arm_workflows(paths=None) -> list:
    """`(filename, reason)` for every workflow whose `schedule` arm can never fire."""
    out = []
    for path in paths if paths is not None else workflow_files():
        text = Path(path).read_text(encoding="utf-8")
        name = Path(path).name
        if not has_schedule_arm(text):
            continue
        if explicit_key_lines(text, "schedule"):
            out.append(
                (name, "declares `schedule` with the explicit-key form (`? schedule`), "
                        "which no matcher here can read — use `schedule:`")
            )
            continue
        if not declares_schedule_trigger(text):
            out.append(
                (name, "a job `if:` gates on `github.event_name == 'schedule'` but the "
                        "workflow has NO `schedule:` trigger, so that arm can never be "
                        "true and the job runs only when its path bucket is touched")
            )
    return out


class TestNoDeadScheduleArm(unittest.TestCase):
    def test_workflow_dir_canary(self):
        self.assertTrue(
            workflow_files(),
            f"No workflow files found under {WORKFLOW_DIR} — path assumption broke",
        )

    def test_every_schedule_arm_has_a_schedule_trigger(self):
        offenders = [f"{name}: {reason}" for name, reason in dead_schedule_arm_workflows()]
        self.assertEqual(
            offenders,
            [],
            "Workflow(s) rely on a `schedule` arm that can never fire. Either add a "
            "`schedule:` trigger to the workflow's `on:` block, or remove the dead "
            "`|| github.event_name == 'schedule'` from the job `if:` so the gating is "
            "honest about when the job actually runs:\n  " + "\n  ".join(offenders),
        )

    def test_lint_yml_keeps_its_weekly_schedule(self):
        # The specific incident this guard was written for: lint.yml's seven
        # path-gated jobs (npm-audit / pip-audit most acutely) depend on it.
        lint = WORKFLOW_DIR / "lint.yml"
        self.assertTrue(lint.is_file(), f"{lint} not found")
        text = lint.read_text(encoding="utf-8")
        self.assertTrue(
            has_schedule_arm(text),
            "lint.yml no longer has any `schedule`-gated job. If the path-gating "
            "design changed, update this guard in the same PR.",
        )
        self.assertTrue(
            declares_schedule_trigger(text),
            "lint.yml lost its `schedule:` trigger. npm-audit and pip-audit then "
            "revalidate ONLY when their path bucket is edited — npm-audit went ~7 "
            "weeks / 117 commits without a single real execution the last time this "
            "was the case, and pip-audit accumulated a real CVE unnoticed.",
        )


class TestDeadScheduleArmDetectorMutation(unittest.TestCase):
    """Non-vacuity: the detector must FIRE on the arm-without-trigger shape and
    stay QUIET on both correct shapes (trigger present; no arm at all)."""

    _ARM_NO_TRIGGER = "\n".join(
        [
            "on:",
            "  pull_request:",
            "jobs:",
            "  audit:",
            "    if: needs.changes.outputs.npm_deps == 'true' || github.event_name == 'schedule'",
            "    runs-on: ubuntu-latest",
        ]
    )
    _ARM_WITH_TRIGGER = "\n".join(
        [
            "on:",
            "  pull_request:",
            "  schedule:",
            "    - cron: '0 5 * * 3'",
            "jobs:",
            "  audit:",
            "    if: needs.changes.outputs.npm_deps == 'true' || github.event_name == 'schedule'",
        ]
    )
    _NO_ARM_NO_TRIGGER = "\n".join(
        ["on:", "  pull_request:", "jobs:", "  build:", "    runs-on: ubuntu-latest"]
    )

    def _detect(self, text):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "wf.yml")
            p.write_text(text, encoding="utf-8")
            return dead_schedule_arm_workflows([str(p)])

    def test_fires_on_arm_without_trigger(self):
        self.assertTrue(
            self._detect(self._ARM_NO_TRIGGER),
            "Mutation FAILED: a job gating on the schedule event in a workflow with "
            "no `schedule:` trigger was not flagged — the exact lint.yml defect.",
        )

    def test_quiet_when_trigger_present(self):
        self.assertEqual(
            self._detect(self._ARM_WITH_TRIGGER),
            [],
            "False positive: a workflow that DOES declare `schedule:` was flagged.",
        )

    def test_quiet_when_no_arm(self):
        self.assertEqual(
            self._detect(self._NO_ARM_NO_TRIGGER),
            [],
            "False positive: a workflow with no schedule-gated job was required to "
            "have a `schedule:` trigger.",
        )

    def test_quoted_on_and_schedule_keys_count_as_present(self):
        wf = "\n".join(
            [
                '"on":',
                "  pull_request:",
                '  "schedule":',
                "    - cron: '0 5 * * 3'",
                "jobs:",
                "  audit:",
                "    if: github.event_name == 'schedule'",
            ]
        )
        self.assertEqual(
            self._detect(wf),
            [],
            "False positive: a quoted `\"on\":`/`\"schedule\":` key was not "
            "recognised, so a correctly-scheduled workflow was flagged.",
        )

    def test_commented_arm_does_not_demand_a_trigger(self):
        wf = "\n".join(
            [
                "on:",
                "  pull_request:",
                "jobs:",
                "  audit:",
                "    # if: github.event_name == 'schedule'",
                "    if: needs.changes.outputs.npm_deps == 'true'",
            ]
        )
        self.assertEqual(
            self._detect(wf),
            [],
            "False positive: a commented-out schedule arm is not a live promise and "
            "must not require a trigger.",
        )

    def test_flags_explicit_key_schedule(self):
        wf = "\n".join(
            [
                "on:",
                "  pull_request:",
                "  ? schedule",
                "  : [{cron: '0 5 * * 3'}]",
                "jobs:",
                "  audit:",
                "    if: github.event_name == 'schedule'",
            ]
        )
        self.assertTrue(
            self._detect(wf),
            "tripwire FAILED: an explicit-key `? schedule` trigger was silently "
            "accepted, but no matcher here can read it — fail closed instead.",
        )

    def test_detects_contains_style_arm(self):
        wf = "\n".join(
            [
                "on:",
                "  pull_request:",
                "jobs:",
                "  audit:",
                "    if: contains(fromJSON('[\"schedule\",\"push\"]'), github.event_name)",
            ]
        )
        self.assertTrue(
            self._detect(wf),
            "Mutation FAILED: a `contains(...)`-style schedule arm was not "
            "recognised, so the same dead-arm shape escapes with a different "
            "spelling.",
        )

    def test_real_workflows_scanned_not_empty(self):
        # Guards against a silent path/parse break making the repo-wide test above
        # pass vacuously: at least one real workflow must have a schedule arm.
        armed = [
            Path(p).name
            for p in workflow_files()
            if has_schedule_arm(Path(p).read_text(encoding="utf-8"))
        ]
        self.assertTrue(
            armed,
            "No workflow in this repo has a `schedule`-gated job — either the arms "
            "were all removed (update this guard) or the scan broke.",
        )


if __name__ == "__main__":
    unittest.main()
