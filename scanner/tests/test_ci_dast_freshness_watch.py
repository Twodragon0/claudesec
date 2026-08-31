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
Direction is that a liveness check EXISTS, CAN RUN, and can reach a human. The
first version asserted only the first of those by scanning the whole file for
substrings, and an independent adversarial pass defeated it four ways at
`21 passed` while also finding a fifth defect it never checked for at all — the
missing `actions: read` grant, which made every single run 403 on its first API
call. All five are now pinned, each proven on disk to turn this file red (see
`TestDetectorMutation`); the structural machinery that closes them, and why
enumerating four more patterns was the wrong fix, is documented above the
helpers. Five properties:

0. **Permissions cover the calls.** `listWorkflowRuns` is an Actions-API read,
   and GitHub sets every permission a `permissions:` block does not name to
   `none`. `contents: read` + `issues: write` therefore means `actions: none`.
   Read as direct CHILDREN of the single top-level `permissions:` key, because
   the byte-identical `issues: write` line under a step's `env:` grants nothing
   and a whole-file regex cannot tell the two apart.

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
    top_level_blocks,
    top_level_mapping,
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
_ISSUE_CLOSE_RE = re.compile(r"""\bstate:\s*['"]closed['"]""")

# Required workflow-level permissions, each with the call it exists for. Both are
# asserted as DIRECT CHILDREN of the one top-level `permissions:` key — see
# `permission_problems` and the shared `top_level_mapping` primitive.
REQUIRED_PERMISSIONS = {
    "actions": (
        "read",
        "`listWorkflowRuns` is an Actions-API read. GitHub sets every permission "
        "a `permissions:` block does not name to `none`, so omitting this 403s on "
        "the first call of EVERY run and the workflow reports 'freshness UNKNOWN' "
        "forever without ever reaching the issue logic.",
    ),
    "issues": (
        "write",
        "every `issues.create`/`issues.update` call would 403, so the escalation "
        "path would exist but never land.",
    ),
}


# ---------------------------------------------------------------------------
# Structural helpers.
#
# The first version of this guard scanned the whole comment-stripped file for
# substrings, and an independent adversarial pass defeated it FOUR separate ways
# at `21 passed` — every one of them the same defect, which is why the fix is
# structural rather than four more patterns (ADR-001 §5):
#
#   1. the `else { issues.create(...) }` branch — the FIRST-EVER alarm — replaced
#      by a `core.warning`, satisfied by the three `issues.update(` calls that
#      remain elsewhere;
#   2. the `catch` downgraded to `core.warning` + `runs = []` (an API error then
#      reads as "never ran"), with a dead `if (false) { core.setFailed(...) }`
#      planted to satisfy the presence check;
#   3. `issues: write` deleted from `permissions:` and re-planted inside the
#      step's `env:`, where it is an environment variable and grants nothing;
#   4. a decoy `listWorkflowRuns` carrying both filters placed in front of the
#      REAL, unfiltered one whose result is what `runs` is assigned from.
#
# Presence proves a token exists. It never proves the token belongs to the call
# that runs. So these helpers answer "which call / which block / which key's
# child", and every count is asserted EXACTLY so a second copy cannot shadow the
# first — the same discipline #497 used on its own `target:` assertion.
# ---------------------------------------------------------------------------


def script_body(text: str):
    """The JavaScript inside the step's `script: |` block scalar, or None.

    Everything structural below is scoped to this, so a token in the YAML header
    or in an `env:` value cannot stand in for code."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)script:\s*\|[-+]?\s*$", line)
        if not m:
            continue
        indent = len(m.group(1))
        body = []
        for cont in lines[i + 1:]:
            if cont.strip() and (len(cont) - len(cont.lstrip())) <= indent:
                break
            body.append(cont)
        return "\n".join(body)
    return None


def _scan_js(js: str):
    """One pass over `js` producing two LENGTH-PRESERVED masks.

    - `structural`: literals AND `//` comments blanked — for brace/paren matching,
      because a `(` inside a string is not structure.
    - `code`: only `//` comments blanked, literals kept — for CONTENT matching,
      because `event: 'schedule'` must stay readable while the same text sitting
      in a comment must not count.

    Both are needed and neither substitutes for the other: matching content on
    `structural` would erase every value being asserted, and matching it on the
    raw text let a `// state: 'closed'` satisfy the close check. Literal state is
    tracked in the SAME walk, so a `//` inside a URL string is not mistaken for a
    comment — the direction that would silently blank real code."""
    structural = list(js)
    code = list(js)
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        if c == "/" and i + 1 < n and js[i + 1] == "/":
            while i < n and js[i] != "\n":
                structural[i] = code[i] = " "
                i += 1
            continue
        if c in "'\"`":
            quote = c
            structural[i] = " "
            i += 1
            while i < n:
                if js[i] == "\\":
                    structural[i] = " "
                    if i + 1 < n:
                        structural[i + 1] = " "
                    i += 2
                    continue
                if js[i] == quote:
                    structural[i] = " "
                    i += 1
                    break
                if js[i] != "\n":
                    structural[i] = " "
                i += 1
            continue
        i += 1
    return "".join(structural), "".join(code)


def mask_js(js: str) -> str:
    """The structural mask — see `_scan_js`."""
    return _scan_js(js)[0]


def code_only(js: str) -> str:
    """The comment-blanked, literal-preserving mask — see `_scan_js`."""
    return _scan_js(js)[1]


def _balanced_end(masked: str, start: int, opener: str, closer: str):
    """Index just past the `closer` matching the `opener` at `masked[start]`."""
    depth = 0
    for j in range(start, len(masked)):
        if masked[j] == opener:
            depth += 1
        elif masked[j] == closer:
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def call_arguments(js: str, callee: str) -> list:
    """Argument text of every LIVE call to `callee`, comments already blanked.

    Spans are located on the structural mask and sliced from the comment-blanked
    `code` mask, which shares its offsets — so a commented-out call is not found
    at all, and a commented-out key inside a live call does not satisfy a content
    check. Returns one entry per call site, so the CALLER can assert HOW MANY:
    a decoy is only invisible to a check that never counts."""
    structural, code = _scan_js(js)
    spans = []
    for m in re.finditer(re.escape(callee) + r"\s*\(", structural):
        open_idx = m.end() - 1
        end = _balanced_end(structural, open_idx, "(", ")")
        if end is not None:
            spans.append(code[open_idx + 1: end - 1])
    return spans


def catch_bodies(js: str) -> list:
    """The comment-blanked body of every live `catch (...) { ... }` block."""
    structural, code = _scan_js(js)
    out = []
    for m in re.finditer(r"\bcatch\s*\(", structural):
        args_end = _balanced_end(structural, m.end() - 1, "(", ")")
        if args_end is None:
            continue
        brace = structural.find("{", args_end)
        if brace == -1:
            continue
        end = _balanced_end(structural, brace, "{", "}")
        if end is not None:
            out.append(code[brace + 1: end - 1])
    return out


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
    """Problems with WHAT the freshness query counts as coverage.

    Bound to the ONE `listWorkflowRuns` call. Defeat #4 put a fully-filtered decoy
    in front of the real, unfiltered call — the filters were present, and the
    query that fed `runs` had neither."""
    js = script_body(text)
    if js is None:
        return ["No `script: |` block found — the step body cannot be read."]
    calls = call_arguments(js, "listWorkflowRuns")
    if len(calls) != 1:
        return [
            f"Expected exactly ONE `listWorkflowRuns(` call, found {len(calls)}. "
            "Refusing to guess which one feeds `runs`: a second call is how a "
            "filtered decoy hides an unfiltered real query. If a second call is "
            "genuinely needed, teach this guard which one is authoritative."
        ]
    args = calls[0]
    problems = []
    if not _EVENT_FILTER_RE.search(args):
        problems.append(
            "The run query does not filter `event: 'schedule'`. A "
            "`workflow_dispatch` run proves someone pressed a button, not that "
            "the cron is alive, so counting manual runs lets a hand-run scan mask "
            "a dead schedule — the same looks-covered-is-not shape #497 fixed."
        )
    if not _STATUS_FILTER_RE.search(args):
        problems.append(
            "The run query does not filter `status: 'success'`. Runs that fire "
            "and FAIL would then count as freshness, so an all-red nightly would "
            "report as covered."
        )
    return problems


def escalation_problems(text: str) -> list:
    """Problems with the paths that reach a human (or fail loudly).

    Every check is bound to a call or a block and asserts a COUNT. Presence alone
    was defeated twice: the first-ever-alarm `issues.create` was deleted while
    unrelated `issues.update` calls kept the pattern satisfied, and the `catch`
    was downgraded to a warning while a dead `if (false) { core.setFailed(...) }`
    kept that pattern satisfied."""
    js = script_body(text)
    if js is None:
        return ["No `script: |` block found — the step body cannot be read."]
    problems = []

    creates = call_arguments(js, "issues.create")
    if len(creates) != 1:
        problems.append(
            f"Expected exactly ONE `issues.create(` call, found {len(creates)}. "
            "That call IS the first-ever alarm — the branch taken the first time "
            "staleness is detected, and every time the notice does not exist yet. "
            "Deleting it leaves the workflow able only to update a notice nobody "
            "ever opened."
        )

    updates = call_arguments(js, "issues.update")
    if not updates:
        problems.append(
            "Nothing calls `issues.update(`. A `core.info`/`core.warning` alone is "
            "invisible — exactly how `protection-drift-watch.yml` reported green "
            "for weeks (#396)."
        )
    elif not any(_ISSUE_CLOSE_RE.search(a) for a in updates):
        problems.append(
            "No `issues.update(` call sets `state: 'closed'`, so the notice never "
            "retracts. A stale issue that stays open after the scan recovers gets "
            "muted, and a muted notifier is silence again. (Checked inside the "
            "call arguments: a `state: 'closed'` sitting anywhere else is prose.)"
        )

    catches = catch_bodies(js)
    if not catches:
        problems.append(
            "The Actions-API read has no `catch` block at all, so a throw would "
            "propagate uncontrolled."
        )
    else:
        in_catch = sum(len(call_arguments(c, "core.setFailed")) for c in catches)
        total = len(call_arguments(js, "core.setFailed"))
        if in_catch != 1 or total != 1:
            problems.append(
                f"`core.setFailed(` must appear exactly once and inside the "
                f"`catch` block; found {total} in the script, {in_catch} in a "
                "`catch`. An unreadable check that exits 0 concludes the same as a "
                "healthy one, and a dead `if (false) { core.setFailed(...) }` "
                "satisfies any check that only counts occurrences file-wide."
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
    """The granted scopes must cover the calls the script makes.

    Read as DIRECT CHILDREN of the single top-level `permissions:` key. Defeat #3
    deleted `issues: write` from that block and re-planted the identical line
    inside the step's `env:`, where it is an environment variable granting
    nothing — indistinguishable to a whole-file line regex.

    Direction is COVERAGE, not an exact set: extra scopes are a separate concern
    (`test_ci_gate_topology` and review own least-privilege), while a MISSING one
    silently breaks the feature at runtime with a green YAML lint.

    Both reads go through the shared `top_level_*` primitives rather than a local
    parser: hand-rolling this extractor is exactly what let the same bypass recur
    three times across separate guards, so there is one implementation to attack
    and one to fix."""
    blocks = top_level_blocks(text, "permissions")
    if len(blocks) != 1:
        return [
            f"Expected exactly ONE top-level `permissions:` block, found "
            f"{len(blocks)}. With none, the token falls back to a repo/org default "
            "this guard cannot see; with two, YAML keeps the last and review reads "
            "the first."
        ]
    declared = top_level_mapping(text, "permissions")
    problems = []
    for key, (value, why) in sorted(REQUIRED_PERMISSIONS.items()):
        got = declared.get(key)
        if got != value:
            problems.append(
                f"`permissions:` must grant `{key}: {value}` (found {got!r}) — {why} "
                "GitHub's rule: \"If you specify the access for any of these "
                "permissions, all of those that are not specified are set to "
                '`none`."'
            )
    return problems


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

    # --- the four bypasses an independent adversarial pass found, each of which
    # --- read `21 passed` against the presence-scanning first version ----------

    def test_deleting_the_first_ever_alarm_is_caught(self):
        # Bypass #1: the `else { issues.create(...) }` branch — the path taken the
        # FIRST time staleness is ever detected — replaced by a warning. Three
        # `issues.update(` calls elsewhere kept the old `issues\.(create|update)`
        # pattern satisfied, so the single most important path could be deleted
        # silently.
        mutant = apply_mutation(
            self.clean, "await github.rest.issues.create(", "await core.warning("
        )
        found = assert_disables(
            escalation_problems, self.clean, mutant, "issues.create branch deleted"
        )
        self.assertTrue(
            any("ONE `issues.create(` call" in p for p in found),
            f"fired for the wrong reason: {found!r}",
        )

    def test_a_dead_setfailed_decoy_does_not_cover_a_swallowed_catch(self):
        # Bypass #2: the catch downgraded to a warning that sets `runs = []` — so
        # an API error reads as "never ran" — with a dead `if (false)` decoy left
        # behind to satisfy a file-wide presence check.
        mutant = apply_mutation(
            self.clean,
            "              core.setFailed(",
            "              runs = []; core.warning(",
        )
        mutant = apply_mutation(
            mutant,
            "            const workflowId = process.env.WATCHED_WORKFLOW;",
            "            if (false) { core.setFailed('unreachable decoy'); }\n"
            "            const workflowId = process.env.WATCHED_WORKFLOW;",
        )
        found = assert_disables(
            escalation_problems, self.clean, mutant, "setFailed decoy outside catch"
        )
        self.assertTrue(
            any("inside the `catch`" in p for p in found),
            f"fired for the wrong reason: {found!r}",
        )

    def test_a_permission_line_under_env_does_not_grant_anything(self):
        # Bypass #3: `issues: write` deleted from `permissions:` and re-planted in
        # the step's `env:`, where it is an environment variable. Byte-identical
        # line, completely different meaning — invisible to a whole-file regex.
        mutant = apply_mutation(self.clean, "\n  issues: write", "")
        mutant = apply_mutation(
            mutant, "          ISSUE_LABEL: dast", "          issues: write"
        )
        found = assert_disables(
            permission_problems, self.clean, mutant, "issues: write moved to env"
        )
        self.assertTrue(
            any("`issues: write`" in p for p in found),
            f"fired for the wrong reason: {found!r}",
        )

    def test_a_permission_nested_one_level_deeper_does_not_grant_anything(self):
        # Bypass #3 one level down, and the reason this guard reads through the
        # shared `top_level_mapping` instead of its own parser. The local copy
        # matched a child at ANY indent, so re-planting `issues: write` under a
        # nested key inside the same block satisfied it — green while defeated,
        # measured against the deleted copy before the swap. The shared primitive
        # returns only entries at the block's own minimum indent.
        mutant = apply_mutation(
            self.clean, "\n  issues: write", "\n  x:\n    issues: write"
        )
        found = assert_disables(
            permission_problems, self.clean, mutant, "issues: write nested deeper"
        )
        self.assertTrue(
            any("`issues: write`" in p for p in found),
            f"fired for the wrong reason: {found!r}",
        )

    def test_a_quoted_permission_value_is_not_a_false_alarm(self):
        # Opposite direction, same swap. YAML quoting is cosmetic, so `'write'`
        # grants exactly what `write` does; the local copy kept the quotes in the
        # value and would have reported a defect that is not there.
        mutant = apply_mutation(
            self.clean, "\n  issues: write", "\n  issues: 'write'"
        )
        self.assertEqual(permission_problems(mutant), [])

    def test_a_filtered_decoy_query_does_not_cover_an_unfiltered_real_one(self):
        # Bypass #4: a fully-filtered decoy call placed ahead of the real query,
        # which is then unfiltered. Both filter substrings are present; the call
        # whose result becomes `runs` has neither.
        mutant = apply_mutation(
            self.clean,
            "              const res = await github.rest.actions.listWorkflowRuns({",
            "              await github.rest.actions.listWorkflowRuns({\n"
            "                event: 'schedule',\n"
            "                status: 'success',\n"
            "              });\n"
            "              const res = await github.rest.actions.listWorkflowRuns({",
        )
        found = assert_disables(
            scope_problems, self.clean, mutant, "decoy listWorkflowRuns"
        )
        self.assertTrue(
            any("found 2" in p for p in found), f"fired for the wrong reason: {found!r}"
        )

    def test_dropping_actions_read_is_caught(self):
        # The bug that actually shipped. Not a bypass — nothing checked it at all,
        # and it made every run 403 on the first API call.
        mutant = apply_mutation(self.clean, "\n  actions: read", "")
        found = assert_disables(
            permission_problems, self.clean, mutant, "actions: read removed"
        )
        self.assertTrue(
            any("`actions: read`" in p for p in found),
            f"fired for the wrong reason: {found!r}",
        )

    def test_a_url_containing_a_double_slash_is_not_mistaken_for_a_comment(self):
        # No-false-alarm direction for the comment masker. If `//` inside a string
        # were treated as a comment start, the rest of that line — real code —
        # would be blanked, and the guard would report a defect that is not there.
        js = "f({ event: 'schedule', url: 'https://example.test/x', status: 'success' });"
        self.assertIn("event: 'schedule'", code_only(js))
        self.assertIn("status: 'success'", code_only(js))
        self.assertEqual(len(call_arguments(js, "f")), 1)

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
