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
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    apply_regex_mutation,
    explicit_key_lines,
    job_block,
    key_column,
    strip_comment_lines,
    strip_inline_comment,
    top_level_mapping,
    yaml_key_pattern,
)

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
        # Read as a DIRECT CHILD of the top-level `env:`, which is what the test
        # name has always claimed and what nothing checked. The old whole-file
        # `assertRegex` was satisfied by the string anywhere: deleting the real
        # `env:` entry (PyYAML confirmed `env: None`) and leaving
        # `echo "CLAUDESEC_DASHBOARD_OFFLINE: 1"` inside a `run: |` read
        # `18 passed`, with the #190 hang class fully reopened at job level.
        env = top_level_mapping(self.text, "env")
        self.assertEqual(
            env.get("CLAUDESEC_DASHBOARD_OFFLINE"),
            "1",
            "workflow no longer sets CLAUDESEC_DASHBOARD_OFFLINE=1 at the top "
            "level — the generator would make live GitHub API calls and could "
            f"hang the job (#190). Top-level env: {env!r}",
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
        # Both halves are read from the OWNING JOB's block, at that job's own
        # derived key column. The old whole-file scan proved only that the text
        # existed somewhere: rewiring the `smoke` gate to
        # `needs.changes.outputs.markdown` (PyYAML confirmed
        # `{'smoke': "needs.changes.outputs.markdown == 'true'"}`, i.e. the
        # browser smoke skips on every dashboard-only PR — a coverage loss, not
        # a cost one) with the original expression left in a `run: |` echo read
        # `18 passed`. Same defect `test_ci_reachability` already fixed for
        # `scanner-unit-tests`; it was never applied to this sibling.
        changes = job_block(self.text, "changes")
        self.assertIsNotNone(
            changes, "the `changes` job is gone or duplicated in this workflow"
        )
        self.assertRegex(
            changes,
            r"(?m)^\s*dashboard:\s*\$\{\{\s*steps\.detect\.outputs\.dashboard\s*\}\}",
            "the `changes` job no longer exposes the `dashboard` path-gate output "
            "(an undeclared output reads as the empty string, so the gate below "
            "would be false on every event and `smoke` would skip forever)",
        )

        smoke = job_block(self.text, "smoke")
        self.assertIsNotNone(
            smoke, "the `smoke` job is gone or duplicated in this workflow"
        )
        col = key_column(smoke)
        self.assertIsNotNone(col, "the `smoke` job has an empty body")
        gate_lines = [
            strip_inline_comment(line).strip()
            for line in smoke.splitlines()
            if re.match(rf"^ {{{col}}}{yaml_key_pattern('if')}\s*:", line)
        ]
        self.assertEqual(
            len(gate_lines),
            1,
            f"expected exactly ONE job-level `if:` on `smoke`, found "
            f"{len(gate_lines)}: {gate_lines!r}",
        )
        self.assertRegex(
            gate_lines[0],
            r"needs\.changes\.outputs\.dashboard\s*==\s*'true'",
            "the `smoke` job's own gate no longer references "
            f"needs.changes.outputs.dashboard — it reads {gate_lines[0]!r}. A gate "
            "naming a different (or misspelled) output is false on every event, so "
            "the browser smoke would skip forever while this workflow reads green.",
        )
        self.assertEqual(
            explicit_key_lines(self.text, "if"),
            [],
            "`? if` explicit-key form found, which the gate reader cannot see.",
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


class TestPresenceIsNotAttribution(unittest.TestCase):
    """Both bypasses that were LIVE on `main` until this PR, pinned.

    Each was measured green-while-defeated first (`18 passed` with the control
    genuinely gone), with PyYAML used to confirm the mutation took effect rather
    than trusting the edit — two earlier probes of these same shapes produced
    YAML GitHub would have rejected, and a guard passing on an unparseable file
    is a much weaker claim than a guard passing on a valid, broken one."""

    @classmethod
    def setUpClass(cls):
        cls.text = strip_comment_lines(WORKFLOW.read_text(encoding="utf-8"))

    def test_an_echoed_offline_var_does_not_cover_a_deleted_env_entry(self):
        # PyYAML on the mutant: `env: None` — the #190 hang class fully reopened
        # at job level, while the string is still greppable in a `run: |`.
        mutant = apply_regex_mutation(
            self.text, r'(?m)^  CLAUDESEC_DASHBOARD_OFFLINE: "1"\n', "", count=1
        )
        mutant = apply_regex_mutation(
            mutant,
            r"(?m)^(        run: \|\n)",
            '\\1          echo "CLAUDESEC_DASHBOARD_OFFLINE: 1"\n',
            count=0,
        )
        self.assertIn("CLAUDESEC_DASHBOARD_OFFLINE", mutant, "fixture stale")
        self.assertNotIn(
            "CLAUDESEC_DASHBOARD_OFFLINE",
            top_level_mapping(mutant, "env"),
            "A shell `echo` of the variable satisfied the top-level `env:` check.",
        )
        self.assertEqual(
            top_level_mapping(self.text, "env").get("CLAUDESEC_DASHBOARD_OFFLINE"),
            "1",
            "positive control: the real workflow must still set it",
        )

    def test_an_echoed_gate_does_not_cover_a_rewired_job_gate(self):
        # PyYAML on the mutant: `{'smoke': "needs.changes.outputs.markdown ==
        # 'true'"}`. An output name that does not exist is the empty string, so
        # the gate is false on every event and the browser smoke skips FOREVER —
        # a coverage loss that reads exactly like a healthy path-gated skip.
        mutant = apply_mutation(
            self.text,
            "needs.changes.outputs.dashboard == 'true'",
            "needs.changes.outputs.markdown == 'true'",
        )
        mutant = apply_regex_mutation(
            mutant,
            r"(?m)^(        run: \|\n)",
            "\\1          echo \"if: needs.changes.outputs.dashboard == 'true'\"\n",
            count=0,
        )
        self.assertIn("needs.changes.outputs.dashboard", mutant, "fixture stale")
        smoke = job_block(mutant, "smoke")
        self.assertIsNotNone(smoke, "fixture stale: smoke job not found")
        col = key_column(smoke)
        gates = [
            strip_inline_comment(line).strip()
            for line in smoke.splitlines()
            if re.match(rf"^ {{{col}}}{yaml_key_pattern('if')}\s*:", line)
        ]
        self.assertEqual(len(gates), 1, f"fixture stale: gates={gates!r}")
        self.assertNotRegex(
            gates[0],
            r"needs\.changes\.outputs\.dashboard\s*==\s*'true'",
            "A gate expression echoed from a shell line satisfied the check while "
            "the smoke job's real gate named a different output.",
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


class TestCommentCannotHideAStepCap(unittest.TestCase):
    """`harness_step_block` is comment-BLIND; the immunity lives in its CALLER.

    The 2026-08-11 block-truncation sweep (#419) fixed five collectors that ended a
    block at a `#` line, because YAML does not — a mapping entry after a comment is
    still in the mapping. This collector has the same shape and was left alone with
    the verdict "no observable effect", which was not good enough: it turned out to
    be IMMUNE, but for a reason nothing pinned.

    `setUpClass` builds `cls.text` with `strip_comment_lines(cls.raw)`, so comments
    are gone before any block is collected. Measured both ways on the real
    workflow, with a dash-column comment planted above the first harness step's
    `timeout-minutes`:

        harness_step_block(RAW,      invocation)  -> None      <- collector truncates
        harness_step_block(STRIPPED, invocation)  -> the step, cap intact

    So a reader auditing the collector alone sees a bug, and a reader auditing the
    guard sees none. Both are half right, and the half that keeps the guard correct
    is one line in `setUpClass` that nothing asserted. If `cls.text` is ever wired
    to `cls.raw` — the obvious "simplification" — the per-step cap assertion starts
    reporting "step parsing broke" on any workflow whose author regrouped keys with
    a comment, and the fix would look like deleting the assertion.

    This pins the CALLER's contract rather than the collector's internals, so
    hardening the collector later (harmless, just redundant) does not invalidate
    it."""

    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def _with_dash_column_comment(self):
        """The real workflow with a `# regrouped` line at the dash column of the
        first harness step, immediately above its `timeout-minutes`."""
        lines = self.raw.splitlines(keepends=True)
        cap = next(
            (j for j, ln in enumerate(lines) if re.match(r"^ {8}timeout-minutes:", ln)),
            None,
        )
        self.assertIsNotNone(cap, "no step-level `timeout-minutes:` found — fixture stale")
        step = max(
            k for k in range(cap) if re.match(r"^\s*-\s+(?:name|uses):", lines[k])
        )
        dash = len(lines[step]) - len(lines[step].lstrip())
        return "".join(lines[:cap] + [" " * dash + "# regrouped\n"] + lines[cap:]), dash

    def test_the_guard_still_sees_the_cap_through_a_comment(self):
        mutant, _ = self._with_dash_column_comment()
        self.assertNotEqual(mutant, self.raw, "mutation did not apply — vacuous")
        step = harness_step_block(strip_comment_lines(mutant), HARNESS_INVOCATIONS[0])
        self.assertIsNotNone(
            step,
            "a comment at the step's dash column hid the harness step from the "
            "per-step cap assertion. The strip in `setUpClass` is what prevents "
            "this — do not wire the assertions to the raw text.",
        )
        self.assertRegex(step, r"timeout-minutes:\s*\d+")

    def test_the_collector_alone_is_comment_blind(self):
        # The other half, pinned so the docstring above cannot go stale: fed RAW
        # text the collector DOES truncate. This is why the strip is load-bearing
        # and not incidental tidiness.
        mutant, _ = self._with_dash_column_comment()
        self.assertIsNone(
            harness_step_block(mutant, HARNESS_INVOCATIONS[0]),
            "the collector no longer truncates at a comment — if it was hardened "
            "deliberately, say so here; the strip in setUpClass is still required "
            "by the other assertions in this file",
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
