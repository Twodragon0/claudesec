#!/usr/bin/env python3
"""Detect check-runs stuck `in_progress` after their workflow run has CONCLUDED,
and re-run the owning workflow.

THE FAILURE THIS EXISTS FOR (observed 2026-08-11, PR #424)
----------------------------------------------------------
GitHub reported the `Lint` workflow run as `completed success` while three of its
check-runs stayed `in_progress` — including the two REQUIRED contexts' — so branch
protection kept `mergeStateStatus=BLOCKED` with nothing left to run:

    gh run view <id> --json status,conclusion   ->  completed success
    gh api .../check-runs                       ->  Lint in_progress (25 min)
                                                    Docker Dashboard Smoke Test
                                                      in_progress (30 min), all
                                                      of its STEPS completed

Re-running the workflow issued fresh check-runs and the PR went `CLEAN` within
minutes. Nothing had failed, so the repo's existing "rerun a failed workflow up to
twice" rule did not apply and `gh pr checks` looked like ordinary slowness — which
is why this needs its own detector rather than a longer timeout.

THE TEST, AND WHY IT IS DELIBERATELY NARROW
-------------------------------------------
A check-run is STUCK only when all three hold:

1. the check-run is not `completed`;
2. it maps to a workflow run that IS `completed` (via the run id in its
   `details_url` — the check-run's `name` is a JOB name and matching it against
   `workflowName` is ambiguous: `Lint` is both a workflow and a job here);
3. it has been running longer than `--stuck-minutes` (default 20).

All three, because each alone is normal: (1) is any running job, (2) can lag by
seconds at the end of a run, and (3) is how long a docker build legitimately takes.
Requiring the conjunction is what keeps this from re-running healthy work — a
re-run is not free and it resets the review's evidence.

An external app's check (GitGuardian and friends) has no workflow run behind it, so
it is REPORTED and never re-run: there is nothing to re-run, and pretending
otherwise would hide a genuinely pending third-party scan.

Read-only unless `--rerun` is passed. `gh` is the only dependency; the decision
logic (`select_stuck`) is pure and unit-tested in
`scanner/tests/test_gh_rerun_stuck_checks.py`.
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

_RUN_ID_RE = re.compile(r"/actions/runs/(\d+)")


def run_id_from_details_url(url) -> int:
    """The workflow run id in a check-run's `details_url`, or 0 if there is none.

    0 means "not a workflow check-run" — an external app's URL points at that app,
    not at `/actions/runs/<id>`."""
    if not url:
        return 0
    m = _RUN_ID_RE.search(str(url))
    return int(m.group(1)) if m else 0


def _parse_ts(value):
    """A GitHub ISO-8601 timestamp as an aware datetime, or None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def select_stuck(check_runs, runs, now, stuck_minutes: int = 20):
    """`(stuck, external, pending)` classification of `check_runs`.

    - `stuck`: dicts with `name`, `run_id`, `age_minutes` — the workflow concluded
      but the check-run never did, for longer than the threshold.
    - `external`: incomplete check-runs with no workflow run behind them. Reported,
      never re-run.
    - `pending`: incomplete check-runs whose workflow is still running, or that are
      not old enough yet. Left alone.

    Pure: takes the API payloads and the clock as arguments so every branch is
    unit-testable without the network."""
    by_id = {}
    for r in runs:
        rid = r.get("databaseId") or r.get("id")
        if rid:
            by_id[int(rid)] = r
    cutoff = timedelta(minutes=stuck_minutes)

    stuck, external, pending = [], [], []
    for cr in check_runs:
        if cr.get("status") == "completed":
            continue
        name = cr.get("name", "?")
        rid = run_id_from_details_url(cr.get("details_url") or cr.get("detailsUrl"))
        started = _parse_ts(cr.get("started_at") or cr.get("startedAt"))
        age = (now - started) if started else timedelta(0)
        entry = {"name": name, "run_id": rid, "age_minutes": int(age.total_seconds() // 60)}
        if not rid:
            external.append(entry)
            continue
        run = by_id.get(rid)
        # An unknown run id is NOT treated as stuck: the run list may simply not
        # cover it (a different commit, pagination), and re-running on a guess is
        # the one outcome worse than waiting.
        if run is None or run.get("status") != "completed":
            pending.append(entry)
            continue
        if age < cutoff:
            pending.append(entry)
            continue
        stuck.append(entry)
    return stuck, external, pending


def _gh_json(args):
    out = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=True, timeout=120
    ).stdout
    return json.loads(out or "[]")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pr", help="pull request number")
    ap.add_argument("--stuck-minutes", type=int, default=20)
    ap.add_argument(
        "--rerun",
        action="store_true",
        help="re-run the owning workflow(s). Without this the script only reports.",
    )
    args = ap.parse_args(argv)

    head = _gh_json(["pr", "view", args.pr, "--json", "headRefOid"])["headRefOid"]
    check_runs = _gh_json(
        ["api", f"repos/{{owner}}/{{repo}}/commits/{head}/check-runs", "--jq", ".check_runs"]
    )
    runs = _gh_json(
        ["run", "list", "--commit", head, "--limit", "50", "--json",
         "databaseId,status,conclusion,workflowName"]
    )

    stuck, external, pending = select_stuck(
        check_runs, runs, datetime.now(timezone.utc), args.stuck_minutes
    )
    for entry in pending:
        print(f"  pending   {entry['name']} ({entry['age_minutes']}m)")
    for entry in external:
        print(f"  external  {entry['name']} ({entry['age_minutes']}m) — no workflow run to re-run")
    if not stuck:
        print("no stuck check-runs")
        return 0

    for entry in stuck:
        print(f"  STUCK     {entry['name']} ({entry['age_minutes']}m, run {entry['run_id']})")
    if not args.rerun:
        print("\nre-run with --rerun (this re-runs the whole workflow, not one job)")
        return 0
    for rid in sorted({e["run_id"] for e in stuck}):
        print(f"re-running run {rid}")
        subprocess.run(["gh", "run", "rerun", str(rid)], check=True, timeout=120)
    return 0


if __name__ == "__main__":
    sys.exit(main())
