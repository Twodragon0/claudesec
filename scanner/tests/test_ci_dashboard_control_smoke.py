"""
Regression guard for the dashboard control-liveness smoke (`dashboard-control-smoke.yml`).

The smoke job empirically catches the one dead-control regression class the
source/pytest guards cannot: a `data-action` value emitted with NO matching
dispatcher case (or a renamed case), plus a reintroduced inline `onclick` the
meta-CSP silently blocks. Its value is entirely contingent on THREE properties
that a well-meaning edit could silently strip while leaving the workflow "green":

1. **Hermetic/offline.** The dashboard generator makes live GitHub API calls
   unless `CLAUDESEC_DASHBOARD_OFFLINE` is truthy — the un-gated-call class that
   drove the multi-minute kcov hangs (#190). The workflow must set it at
   workflow/job level AND the harness wrapper must self-export it, so the smoke
   can never silently start depending on (or hanging on) the network.

2. **Path-gated, not required.** The `smoke` job must be gated on the `changes`
   job's `dashboard` output so docs-only PRs skip it. It is intentionally a
   NON-required check (a simple path-gate, no `always()` aggregator — that
   pattern is reserved for required checks, per the paths-ignore/#186 incident).

3. **Bounded + actually runs the harness.** The browser step must carry a
   per-step `timeout-minutes` (a hung headless Chrome must not burn the full job
   budget) and must invoke the real harness wrapper. Both harness files must
   exist on disk (a workflow pointing at a deleted script is a silent no-op).

Direction is PRESENCE of each load-bearing token in the comment-stripped YAML,
so a token surviving only in a `#` comment cannot satisfy an invariant.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess, does not import scanner/lib (so it never moves the
measured coverage gate). Passes under pytest (the CI runner) and
`python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PW.4.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dashboard-control-smoke.yml"
HARNESS_MJS = REPO_ROOT / "scanner" / "tests" / "dashboard-control-liveness.mjs"
HARNESS_SH = REPO_ROOT / "scanner" / "tests" / "test_dashboard_control_liveness.sh"


class TestDashboardControlSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        cls.text = strip_comment_lines(cls.raw)

    def test_workflow_exists(self):
        self.assertTrue(
            WORKFLOW.is_file(),
            f"{WORKFLOW} missing — the control-liveness smoke job was removed",
        )

    def test_offline_env_at_workflow_level(self):
        # `CLAUDESEC_DASHBOARD_OFFLINE: "1"` (quoting/spacing tolerant).
        self.assertRegex(
            self.text,
            r"CLAUDESEC_DASHBOARD_OFFLINE:\s*['\"]?1['\"]?",
            "workflow no longer sets CLAUDESEC_DASHBOARD_OFFLINE=1 — the generator "
            "would make live GitHub API calls and could hang the job (#190)",
        )

    def test_harness_self_exports_offline(self):
        # Belt-and-suspenders: the wrapper must not depend on the CI env alone.
        sh = HARNESS_SH.read_text(encoding="utf-8") if HARNESS_SH.is_file() else ""
        self.assertRegex(
            strip_comment_lines(sh),
            r"export\s+CLAUDESEC_DASHBOARD_OFFLINE=1",
            "test_dashboard_control_liveness.sh no longer self-exports "
            "CLAUDESEC_DASHBOARD_OFFLINE=1",
        )

    def test_smoke_is_path_gated(self):
        # A `changes` job emits a `dashboard` output; `smoke` gates on it.
        self.assertIn(
            "dashboard: ${{ steps.detect.outputs.dashboard }}",
            self.text,
            "the `changes` job no longer exposes the `dashboard` path-gate output",
        )
        self.assertRegex(
            self.text,
            r"if:\s*needs\.changes\.outputs\.dashboard\s*==\s*'true'",
            "the `smoke` job is no longer path-gated on needs.changes.outputs."
            "dashboard — docs-only PRs would run the browser smoke unnecessarily",
        )

    def test_browser_step_is_bounded_and_runs_harness(self):
        # Per-step timeout so a hung headless Chrome can't burn the job budget.
        self.assertRegex(
            self.text,
            r"timeout-minutes:\s*\d+",
            "no per-step timeout-minutes on the smoke job — a hung Chrome would "
            "run to the job cap",
        )
        # The workflow must invoke the real harness wrapper.
        self.assertIn(
            "bash scanner/tests/test_dashboard_control_liveness.sh",
            self.text,
            "the smoke job no longer invokes the control-liveness harness wrapper",
        )

    def test_harness_files_exist(self):
        for p in (HARNESS_MJS, HARNESS_SH):
            with self.subTest(path=p.name):
                self.assertTrue(
                    p.is_file(),
                    f"{p} missing — the smoke workflow would be a silent no-op",
                )


if __name__ == "__main__":
    unittest.main()
