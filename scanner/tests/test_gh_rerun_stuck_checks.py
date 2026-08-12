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

`main()`'s EXIT CODES are pinned here too, because `scripts/gh-merge-ready-pr.sh`
now calls this from its merge wait loop and branches on the status: 0 = nothing
stuck, 10 = stuck (reported), 11 = stuck (re-run issued), 1 = `gh` failed, 2 =
usage error. Before that contract existed every path returned 0, so the caller
had no signal short of grepping stdout. `main()` is driven with a stubbed
`_gh_json`/`subprocess.run`.

stdlib-only; no network, no real subprocess, no `scanner/lib` import. Passes under
pytest and `python3 -m unittest`.
"""

import io
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import gh_rerun_stuck_checks as detector  # noqa: E402
from gh_rerun_stuck_checks import run_id_from_details_url, select_stuck  # noqa: E402

MERGE_SH = REPO_ROOT / "scripts" / "gh-merge-ready-pr.sh"

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


def live_check(name="Lint", minutes_ago=30, url=RUN_URL, status="in_progress"):
    """A check-run timestamped against the REAL clock.

    `main()` calls `datetime.now()` itself, so these cases cannot use the frozen
    NOW the pure-function tests use."""
    started = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return {"name": name, "status": status, "started_at": started.isoformat(),
            "details_url": url}


def stub_gh_json(check_runs, runs, head="0" * 40):
    """A `_gh_json` stand-in dispatching on the `gh` argv the script builds."""
    def _stub(args):
        if args[:2] == ["pr", "view"]:
            return {"headRefOid": head}
        if args[0] == "api":
            return check_runs
        if args[0] == "run":
            return runs
        raise AssertionError(f"unexpected gh invocation: {args}")
    return _stub


class MainExitCodeCase(unittest.TestCase):
    def run_main(self, argv, check_runs, runs, gh_json=None, rerun_side_effect=None):
        """`(exit_code, stdout, rerun_calls)` for `main(argv)`, fully stubbed.

        stderr lands in `self.stderr`: exit 1 is reached by two different guards
        (query vs classification) and a test that only checks the code cannot
        tell them apart — which would let the two being merged back into one
        read as green."""
        with mock.patch.object(detector, "_gh_json", gh_json or stub_gh_json(check_runs, runs)), \
                mock.patch.object(detector.subprocess, "run") as run_mock:
            run_mock.side_effect = rerun_side_effect
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = detector.main(argv)
        self.stderr = err.getvalue()
        return code, out.getvalue(), [c.args[0] for c in run_mock.call_args_list]


class TestMainExitCodes(MainExitCodeCase):
    def test_nothing_stuck_exits_zero(self):
        code, out, calls = self.run_main(
            ["424"], [live_check(status="completed")], [run()]
        )
        self.assertEqual(code, 0)
        self.assertIn("no stuck check-runs", out)
        self.assertEqual(calls, [])

    def test_only_pending_and_external_exits_zero(self):
        # THE negative case: incomplete check-runs exist and the exit code must
        # still be 0, or the caller re-runs (or nags about) healthy work.
        code, out, calls = self.run_main(
            ["424"],
            [live_check("Docker Dashboard Smoke Test", minutes_ago=45),
             live_check("GitGuardian", url="https://dashboard.gitguardian.com/x")],
            [run(status="in_progress")],
        )
        self.assertEqual(code, 0)
        self.assertIn("pending", out)
        self.assertIn("external", out)
        self.assertEqual(calls, [])

    def test_stuck_report_only_exits_10_and_reruns_nothing(self):
        code, out, calls = self.run_main(["424"], [live_check()], [run()])
        self.assertEqual(code, detector.EXIT_STUCK_FOUND)
        self.assertEqual(code, 10)
        self.assertIn("STUCK", out)
        self.assertEqual(calls, [])

    def test_stuck_with_rerun_exits_11_and_reruns_once_per_run_id(self):
        code, out, calls = self.run_main(
            ["424", "--rerun"],
            [live_check("Lint"), live_check("Docker Dashboard Smoke Test")],
            [run()],
        )
        self.assertEqual(code, detector.EXIT_STUCK_RERUN)
        self.assertEqual(code, 11)
        self.assertIn("re-running run 31504280368", out)
        self.assertEqual(calls, [["gh", "run", "rerun", "31504280368"]])

    def test_gh_query_failure_exits_1(self):
        # An unknown verdict must not read as "nothing stuck" (0).
        def boom(args):
            raise subprocess.CalledProcessError(1, ["gh", *args])

        code, _, calls = self.run_main(["424"], [], [], gh_json=boom)
        self.assertEqual(code, detector.EXIT_GH_ERROR)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [])
        self.assertIn("gh query failed", self.stderr)

    def test_malformed_gh_payload_exits_1(self):
        # KeyError on the FIRST call (`headRefOid` absent) -> the QUERY guard.
        code, _, _ = self.run_main(
            ["424"], [], [], gh_json=lambda args: {"unexpected": "shape"}
        )
        self.assertEqual(code, 1)
        self.assertIn("gh query failed", self.stderr)

    def test_null_check_runs_exits_1_without_a_traceback(self):
        # `gh api --jq .check_runs` prints `null` when the key is absent, which
        # json-decodes to None. Iterating that is a TypeError raised INSIDE
        # select_stuck, so the CLASSIFICATION guard must be the one to report it.
        code, _, _ = self.run_main(["424"], None, [run()])
        self.assertEqual(code, 1)
        self.assertIn("unexpected gh payload", self.stderr)
        self.assertNotIn("gh query failed", self.stderr)

    def test_null_run_list_exits_1_without_a_traceback(self):
        code, _, _ = self.run_main(["424"], [live_check()], None)
        self.assertEqual(code, 1)
        self.assertIn("unexpected gh payload", self.stderr)

    def test_error_envelope_instead_of_a_list_exits_1(self):
        # An API error envelope: iterating a dict yields str keys, so the first
        # `cr.get(...)` is an AttributeError, not a TypeError.
        code, _, _ = self.run_main(["424"], {"message": "Not Found"}, [run()])
        self.assertEqual(code, 1)
        self.assertIn("unexpected gh payload", self.stderr)
        self.assertIn("AttributeError", self.stderr)

    def test_rerun_failure_exits_1_not_11(self):
        code, _, calls = self.run_main(
            ["424", "--rerun"], [live_check()], [run()],
            rerun_side_effect=subprocess.CalledProcessError(1, ["gh", "run", "rerun"]),
        )
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)

    def test_usage_error_exits_2(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                detector.main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_stuck_minutes_is_forwarded_from_the_cli(self):
        # Scope: this proves the DETECTOR honours the flag. That
        # `gh-merge-ready-pr.sh` actually passes it is a separate claim, pinned by
        # executing the caller in scanner/tests/test_gh_merge_ready_stuck_probe.sh
        # (scenario 10, `at-the-bound`) — dropping `--stuck-minutes` from
        # `stuck_args` leaves every test in THIS file green.
        # A threshold above the age must flip the verdict back to 0.
        args = (["424", "--stuck-minutes", "60"], [live_check(minutes_ago=30)], [run()])
        self.assertEqual(self.run_main(*args)[0], 0)
        self.assertEqual(
            self.run_main(["424", "--stuck-minutes", "10"], args[1], args[2])[0], 10
        )

    def test_the_codes_stay_out_of_the_shells_reserved_range(self):
        codes = [detector.EXIT_OK, detector.EXIT_GH_ERROR,
                 detector.EXIT_STUCK_FOUND, detector.EXIT_STUCK_RERUN]
        self.assertEqual(len(set(codes)), 4)
        for code in codes:
            self.assertLess(code, 126, "126/127/128+n belong to the shell")


class TestShellCallerAgreesOnTheCodes(unittest.TestCase):
    """`gh-merge-ready-pr.sh` hard-codes the two stuck codes; pin them together.

    A silent drift here is the worst failure mode available: the loop would
    classify a real detection as "probe failed" and keep waiting."""

    def setUp(self):
        self.text = MERGE_SH.read_text(encoding="utf-8")

    def _shell_const(self, name):
        m = re.search(rf"^{name}=(\d+)$", self.text, re.MULTILINE)
        self.assertIsNotNone(m, f"{name} not declared in {MERGE_SH.name}")
        return int(m.group(1))

    def test_found_and_rerun_codes_match_the_detector(self):
        self.assertEqual(self._shell_const("STUCK_EXIT_FOUND"), detector.EXIT_STUCK_FOUND)
        self.assertEqual(self._shell_const("STUCK_EXIT_RERUN"), detector.EXIT_STUCK_RERUN)


if __name__ == "__main__":
    unittest.main()
