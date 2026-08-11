"""
Unit tests for `scripts/gh_rerun_stuck_checks.py`'s decision logic.

The script re-runs CI on the maintainer's behalf, so its predicate is the part that
matters: too loose and it re-runs healthy work (wasting minutes and resetting the
evidence a reviewer just read), too tight and the PR stays BLOCKED with nothing left
to run. Every branch is exercised here against the payload shapes `gh` returns —
`select_stuck` is pure and takes the clock as an argument for exactly that reason.

Modelled on the real 2026-08-11 incident (PR #424): the `Lint` run reported
`completed success` while its check-runs — including both required contexts' — sat
`in_progress` for 25+ minutes with every step completed.

stdlib-only; no network, no subprocess, no `scanner/lib` import. Passes under pytest
and `python3 -m unittest`.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from gh_rerun_stuck_checks import run_id_from_details_url, select_stuck  # noqa: E402

NOW = datetime(2026, 8, 11, 15, 30, tzinfo=timezone.utc)
RUN_URL = "https://github.com/o/r/actions/runs/31504280368/job/93821831557"


def check(name, status="in_progress", minutes_ago=30, url=RUN_URL):
    return {
        "name": name,
        "status": status,
        "started_at": (NOW - timedelta(minutes=minutes_ago)).isoformat(),
        "details_url": url,
    }


def run(status="completed", conclusion="success", rid=31504280368):
    return {"databaseId": rid, "status": status, "conclusion": conclusion,
            "workflowName": "Lint"}


class TestRunIdFromDetailsUrl(unittest.TestCase):
    def test_extracts_the_run_id(self):
        self.assertEqual(run_id_from_details_url(RUN_URL), 31504280368)

    def test_run_url_without_a_job_segment(self):
        self.assertEqual(
            run_id_from_details_url("https://github.com/o/r/actions/runs/42"), 42
        )

    def test_external_app_url_yields_zero(self):
        # GitGuardian & friends point at their own dashboard; there is no run to
        # re-run and treating 0 as a run id would be a wild guess.
        self.assertEqual(
            run_id_from_details_url("https://dashboard.gitguardian.com/incidents/1"), 0
        )

    def test_missing_url_yields_zero(self):
        self.assertEqual(run_id_from_details_url(None), 0)
        self.assertEqual(run_id_from_details_url(""), 0)


class TestSelectStuck(unittest.TestCase):
    def test_the_real_incident_is_detected(self):
        stuck, external, pending = select_stuck([check("Lint")], [run()], NOW)
        self.assertEqual([e["name"] for e in stuck], ["Lint"])
        self.assertEqual(stuck[0]["run_id"], 31504280368)
        self.assertEqual(stuck[0]["age_minutes"], 30)
        self.assertEqual((external, pending), ([], []))

    def test_a_completed_check_run_is_ignored(self):
        stuck, external, pending = select_stuck(
            [check("Lint", status="completed")], [run()], NOW
        )
        self.assertEqual((stuck, external, pending), ([], [], []))

    def test_a_still_running_workflow_is_left_alone(self):
        # THE false-positive that matters: an ordinary long job. Nothing here may
        # re-run work that is still progressing.
        stuck, _, pending = select_stuck(
            [check("Docker Dashboard Smoke Test")], [run(status="in_progress")], NOW
        )
        self.assertEqual(stuck, [])
        self.assertEqual([e["name"] for e in pending], ["Docker Dashboard Smoke Test"])

    def test_below_the_threshold_is_left_alone(self):
        stuck, _, pending = select_stuck([check("Lint", minutes_ago=5)], [run()], NOW)
        self.assertEqual(stuck, [])
        self.assertEqual(len(pending), 1)

    def test_threshold_is_configurable_and_inclusive_of_older_runs(self):
        runs = [run()]
        self.assertEqual(select_stuck([check("Lint", minutes_ago=21)], runs, NOW, 20)[0][0]["name"], "Lint")
        self.assertEqual(select_stuck([check("Lint", minutes_ago=19)], runs, NOW, 20)[0], [])

    def test_an_external_check_is_reported_not_rerun(self):
        stuck, external, pending = select_stuck(
            [check("GitGuardian Security Checks", url="https://dashboard.gitguardian.com/x")],
            [run()],
            NOW,
        )
        self.assertEqual(stuck, [])
        self.assertEqual([e["name"] for e in external], ["GitGuardian Security Checks"])
        self.assertEqual(pending, [])

    def test_an_unknown_run_id_is_pending_not_stuck(self):
        # The run list may not cover the id (another commit, pagination). Guessing
        # would re-run on no evidence, which is worse than waiting.
        stuck, _, pending = select_stuck([check("Lint")], [run(rid=999)], NOW)
        self.assertEqual(stuck, [])
        self.assertEqual(len(pending), 1)

    def test_a_missing_start_time_is_not_treated_as_ancient(self):
        # A null `started_at` gives age 0, so it can never cross the threshold. The
        # safe direction: an un-timestamped check is never re-run on that basis.
        cr = check("Lint")
        cr["started_at"] = None
        stuck, _, pending = select_stuck([cr], [run()], NOW)
        self.assertEqual(stuck, [])
        self.assertEqual(len(pending), 1)

    def test_camel_case_payload_keys_are_accepted(self):
        # `gh api` returns snake_case, `gh run list --json` camelCase; a caller
        # mixing them must not silently classify everything as external.
        cr = {"name": "Lint", "status": "in_progress",
              "startedAt": (NOW - timedelta(minutes=30)).isoformat(),
              "detailsUrl": RUN_URL}
        stuck, external, _ = select_stuck([cr], [{"id": 31504280368, "status": "completed"}], NOW)
        self.assertEqual([e["name"] for e in stuck], ["Lint"])
        self.assertEqual(external, [])

    def test_multiple_stuck_checks_on_one_run_dedupe_to_one_rerun(self):
        stuck, _, _ = select_stuck(
            [check("Lint"), check("Docker Dashboard Smoke Test")], [run()], NOW
        )
        self.assertEqual(len({e["run_id"] for e in stuck}), 1)
        self.assertEqual(len(stuck), 2)


if __name__ == "__main__":
    unittest.main()
