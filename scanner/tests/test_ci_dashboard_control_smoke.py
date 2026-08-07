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

3. **Bounded + actually runs the harness.** EACH browser step must carry a
   per-step `timeout-minutes` (a hung headless Chrome must not burn the full job
   budget) and must invoke a real harness wrapper. Every harness file must exist
   on disk (a workflow pointing at a deleted script is a silent no-op).

4. **The path-gate actually fires for the files it claims to cover.** A
   path-gated job that never runs reads green, which is exactly how this repo lost
   npm-audit and the nightly DAST for weeks (#396/#397). So the gate is not merely
   asserted to *mention* the paths: this guard EXTRACTS the `grep -E` regex from
   the workflow and RUNS it against each covered path (and against control paths
   that must NOT match). A gate that stops matching `claudesec-asset-dashboard.html`
   fails a test instead of silently skipping the smoke.

TWO dashboards are driven (scan + ISMS asset), each in its own bounded step, so
the step-scoping helper is parameterised by invocation rather than assuming one.

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
TESTS_DIR = REPO_ROOT / "scanner" / "tests"

# Shared browser runner + both suites' wrappers and inputs. A workflow step
# pointing at any deleted file here is a silent no-op, so all of them are pinned.
HARNESS_FILES = [
    TESTS_DIR / "dashboard-control-liveness.mjs",
    TESTS_DIR / "test_dashboard_control_liveness.sh",
    TESTS_DIR / "asset-dashboard-assertions.js",
    TESTS_DIR / "test_asset_dashboard_control_liveness.sh",
    TESTS_DIR / "fixtures" / "asset-dashboard-data.json",
]

# Every wrapper the workflow must invoke, one bounded step each.
HARNESS_INVOCATIONS = [
    "bash scanner/tests/test_dashboard_control_liveness.sh",
    "bash scanner/tests/test_asset_dashboard_control_liveness.sh",
]

# Repo paths the `changes` path-gate MUST match (a miss silently skips the smoke)…
GATED_PATHS = [
    "scanner/lib/dashboard-template.html",
    "scanner/lib/dashboard-gen.py",
    "claudesec-asset-dashboard.html",
    "scanner/tests/dashboard-control-liveness.mjs",
    "scanner/tests/asset-dashboard-assertions.js",
    "scanner/tests/fixtures/asset-dashboard-data.json",
    "scanner/tests/test_dashboard_control_liveness.sh",
    "scanner/tests/test_asset_dashboard_control_liveness.sh",
    ".github/workflows/dashboard-control-smoke.yml",
]

# …and paths it must NOT match, so the gate is a real filter and not `.*`.
UNGATED_PATHS = [
    "README.md",
    "docs/guides/hourly-operations.md",
    "scanner/tests/test_check_access_control.sh",
    ".github/workflows/lint.yml",
    "claudesec-asset-dashboard-live.html",  # generated output, not the template
]


def harness_step_block(text, invocation):
    """The single `- name:` step block that runs `invocation`, or None.

    Scoping is load-bearing for the per-step `timeout-minutes` assertion: this
    workflow also carries JOB-level `timeout-minutes` keys, so an unscoped search
    is satisfied by those and cannot detect removal of the per-step cap it claims
    to guard (inert-guard class — the same defect as the unscoped `exit 1` in
    test_ci_docker_image_size_gate.py).

    Matching is on the full `run:` line, not a substring: the scan wrapper's path
    (`test_dashboard_control_liveness.sh`) is a proper SUFFIX of the asset one
    (`test_asset_dashboard_control_liveness.sh`) only in the other direction, but
    a future rename could make one contain the other and silently fold two steps
    into one "found 2, return None" — so each candidate line is compared exactly.
    """
    blocks, cur, marker_indent = [], None, 0
    for line in text.splitlines():
        m = re.match(r"^(\s*)-\s+name:", line)
        if m:
            if cur is not None:
                blocks.append("\n".join(cur))
            cur, marker_indent = [line], len(m.group(1))
        elif cur is not None:
            # A non-blank line indented at or above the `-` marker's column ends
            # the step: it belongs to the job (or to the next job) instead. The
            # LAST step used to run to EOF, so a later job's job-level
            # `timeout-minutes:` satisfied the per-step-cap assertion below — the
            # exact leak this scoping exists to prevent, just from the other
            # side (verified 2026-08-07 by deleting the real per-step cap and
            # appending an ordinary `publish:` job: the guard stayed green).
            if line.strip() and (len(line) - len(line.lstrip())) <= marker_indent:
                blocks.append("\n".join(cur))
                cur = None
                continue
            cur.append(line)
    if cur is not None:
        blocks.append("\n".join(cur))
    hits = [
        b
        for b in blocks
        if any(
            ln.strip() == "run: " + invocation
            for ln in b.splitlines()
        )
    ]
    return hits[0] if len(hits) == 1 else None


def path_gate_regex(text):
    """The ERE the `changes` job feeds to `grep -E`, or None.

    Extracted rather than hand-copied so the guard can EXECUTE the real gate. The
    literal is a single-quoted YAML scalar on its own continuation line inside the
    `run:` block, e.g.

        match=$(printf '%s\\n' "$FILES" | grep -E \\
          '^(scanner/lib/|claudesec-asset-dashboard\\.html$|...)' \\
          || true)
    """
    for line in text.splitlines():
        stripped = line.strip().rstrip("\\").strip()
        if stripped.startswith("'^(") and stripped.endswith("'"):
            return stripped[1:-1]
    return None


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
        # Belt-and-suspenders: neither wrapper may depend on the CI env alone.
        for wrapper in (
            TESTS_DIR / "test_dashboard_control_liveness.sh",
            TESTS_DIR / "test_asset_dashboard_control_liveness.sh",
        ):
            with self.subTest(wrapper=wrapper.name):
                sh = wrapper.read_text(encoding="utf-8") if wrapper.is_file() else ""
                self.assertRegex(
                    strip_comment_lines(sh),
                    r"export\s+CLAUDESEC_DASHBOARD_OFFLINE=1",
                    f"{wrapper.name} no longer self-exports "
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

    def test_browser_steps_are_bounded_and_run_harnesses(self):
        # BOTH dashboards must be driven, each from its own bounded step.
        for invocation in HARNESS_INVOCATIONS:
            with self.subTest(invocation=invocation):
                self.assertIn(
                    invocation,
                    self.text,
                    f"the smoke job no longer invokes `{invocation}` — that "
                    "dashboard would lose its control-liveness coverage",
                )
                # Per-step timeout so a hung headless Chrome can't burn the job
                # budget. Scoped to THIS step: unscoped, the workflow's job-level
                # `timeout-minutes` keys satisfy it and removing the per-step cap
                # goes undetected.
                step = harness_step_block(self.text, invocation)
                self.assertIsNotNone(
                    step,
                    "could not isolate exactly one `- name:` step invoking "
                    f"`{invocation}` — step parsing broke, or the invocation moved",
                )
                self.assertRegex(
                    step,
                    r"timeout-minutes:\s*\d+",
                    f"no per-step timeout-minutes on the `{invocation}` step — a "
                    "hung Chrome would run to the job cap (a job-level timeout "
                    "elsewhere does not count)",
                )

    def test_harness_files_exist(self):
        for p in HARNESS_FILES:
            with self.subTest(path=p.name):
                self.assertTrue(
                    p.is_file(),
                    f"{p} missing — the smoke workflow would be a silent no-op",
                )


class TestPathGateActuallyFires(unittest.TestCase):
    """The path-gate is EXECUTED, not just read.

    A path-gated job that never runs reads green — the exact failure mode that
    left npm-audit dark for ~7 weeks and the nightly DAST skipped for ~42 nights
    (#396/#397). Asserting that the workflow *mentions* a path proves nothing:
    the regex could mention it in a branch that never matches. So the real ERE is
    extracted from the workflow and run against each path it must cover.
    """

    @classmethod
    def setUpClass(cls):
        raw = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        cls.pattern = path_gate_regex(strip_comment_lines(raw))

    def test_gate_regex_is_extractable(self):
        self.assertIsNotNone(
            self.pattern,
            "could not extract the `changes` job's grep -E path-gate regex — the "
            "extractor's shape assumption broke, so every gate test below would "
            "be vacuous",
        )

    def test_gate_matches_every_covered_path(self):
        for path in GATED_PATHS:
            with self.subTest(path=path):
                self.assertIsNotNone(
                    re.search(self.pattern, path),
                    f"the path-gate does NOT match {path!r} — a change to it would "
                    "skip the browser smoke and the job would report green",
                )

    def test_gate_rejects_unrelated_paths(self):
        # Canary against a gate degraded to `.*` (which would make the matches
        # above pass while gating nothing).
        for path in UNGATED_PATHS:
            with self.subTest(path=path):
                self.assertIsNone(
                    re.search(self.pattern, path),
                    f"the path-gate matches unrelated path {path!r} — the gate has "
                    "become a no-op filter",
                )


class TestHarnessStepScoping(unittest.TestCase):
    """Mutation self-tests for `harness_step_block`.

    The unscoped `assertRegex(text, r"timeout-minutes:\\s*\\d+")` this replaced
    could not detect removal of the harness step's own cap, because the workflow
    carries job-level `timeout-minutes` keys that satisfied the pattern.
    """

    _SCAN = HARNESS_INVOCATIONS[0]
    _ASSET = HARNESS_INVOCATIONS[1]
    _JOB_LEVEL = "jobs:\n  smoke:\n    timeout-minutes: 8\n    steps:\n"
    _GOOD = (
        _JOB_LEVEL + "      - name: Run smoke\n"
        "        timeout-minutes: 5\n"
        f"        run: {_SCAN}\n"
    )
    # Per-step cap gone; the JOB-level one remains — the exact shape the old
    # unscoped check called green.
    _NO_STEP_CAP = _JOB_LEVEL + "      - name: Run smoke\n" f"        run: {_SCAN}\n"
    # A LATER step has a cap; the harness step does not.
    _CAP_ON_WRONG_STEP = (
        _JOB_LEVEL + "      - name: Run smoke\n"
        f"        run: {_SCAN}\n"
        "      - name: Upload artifact\n"
        "        timeout-minutes: 5\n"
        "        run: echo up\n"
    )
    # Both wrappers present; only the ASSET step lost its cap. An invocation-blind
    # helper would return the scan step (which has one) and call this green.
    _ASSET_CAP_MISSING = (
        _JOB_LEVEL + "      - name: Run scan smoke\n"
        "        timeout-minutes: 5\n"
        f"        run: {_SCAN}\n"
        "      - name: Run asset smoke\n"
        f"        run: {_ASSET}\n"
    )

    def test_good_step_has_cap(self):
        self.assertRegex(
            harness_step_block(self._GOOD, self._SCAN), r"timeout-minutes:\s*\d+"
        )

    def test_job_level_cap_does_not_satisfy(self):
        step = harness_step_block(self._NO_STEP_CAP, self._SCAN)
        self.assertIsNotNone(step)
        self.assertNotRegex(
            step,
            r"timeout-minutes:\s*\d+",
            "Scoping failure: a JOB-level timeout leaked into the harness step, "
            "so removing the per-step cap would go undetected.",
        )

    def test_later_step_cap_does_not_satisfy(self):
        step = harness_step_block(self._CAP_ON_WRONG_STEP, self._SCAN)
        self.assertIsNotNone(step)
        self.assertNotRegex(step, r"timeout-minutes:\s*\d+")

    def test_each_invocation_isolates_its_own_step(self):
        scan = harness_step_block(self._ASSET_CAP_MISSING, self._SCAN)
        asset = harness_step_block(self._ASSET_CAP_MISSING, self._ASSET)
        self.assertIsNotNone(scan)
        self.assertIsNotNone(asset)
        self.assertRegex(scan, r"timeout-minutes:\s*\d+")
        self.assertNotRegex(
            asset,
            r"timeout-minutes:\s*\d+",
            "Scoping failure: the asset step picked up the scan step's cap, so a "
            "missing per-step timeout on the asset smoke would go undetected.",
        )

    def test_missing_invocation_returns_none(self):
        self.assertIsNone(harness_step_block(self._JOB_LEVEL, self._SCAN))

    def test_later_job_level_cap_does_not_leak_into_the_last_step(self):
        # The harness step is the LAST step of its job, so its block used to run
        # to EOF and absorb the NEXT job's job-level keys — a later
        # `timeout-minutes` then satisfied the per-step assertion and removing the
        # real cap went undetected (stripper/haystack audit, finding 7).
        wf = (
            self._NO_STEP_CAP
            + "  publish:\n    timeout-minutes: 10\n    runs-on: ubuntu-latest\n"
        )
        step = harness_step_block(wf, self._SCAN)
        self.assertIsNotNone(step)
        self.assertNotRegex(
            step,
            r"timeout-minutes:\s*\d+",
            "Scoping failure: a LATER job's job-level timeout leaked into the "
            "harness step block, so removing the per-step cap would go undetected.",
        )

    def test_real_workflow_isolates_one_step_per_invocation(self):
        raw = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        text = strip_comment_lines(raw)
        for invocation in HARNESS_INVOCATIONS:
            with self.subTest(invocation=invocation):
                step = harness_step_block(text, invocation)
                self.assertIsNotNone(
                    step, f"step for `{invocation}` not isolated in the real workflow"
                )
                self.assertIn(invocation, step)


if __name__ == "__main__":
    unittest.main()
