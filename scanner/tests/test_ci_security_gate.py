"""
Regression guards for the security-scan workflow's enforcement topology.

`main` branch protection requires exactly two checks: `Lint` (lint.yml's
lint-gate) and `Security Scan Gate` (security-scan.yml). The latter is an
`always()` aggregator whose pass/fail is derived from its `needs:` results — so
silently dropping a dependency from `needs`, removing `if: always()`, or
loosening the pass-set would neuter the only security required-check without any
visible failure. This guards that topology (cf. test_ci_gate_topology.py for the
lint-gate analogue, and project memory paths-ignore-vs-branch-protection #186).

Also guards both DAST triggers:
- the PR-time signal (`dast-baseline.yml`) still triggers on `pull_request`
  (not silently downgraded to schedule/dispatch-only); and
- the nightly full scan (`dast-full-scan.yml`) keeps its `schedule:` trigger
  (silently removing it would stop nightly DAST with no visible failure).

Scope note: action SHA-pinning for these files is already covered by
test_ci_gate_topology.py (it globs all workflows) — NOT duplicated here.

Scope note 2 — the severity block is NOT guarded here any more. Whether the scan
job actually fails on a CRITICAL (and keeps HIGH non-blocking) is proven by
EXECUTING the gate in test_ci_security_gate_behaviour.py. This file used to
assert it by text through `conditional_body_from`, which searched the block
anchor in RAW text while comment-stripping only the body it returned — so a
single `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi` anchored the scan inside
itself and certified a DELETED gate. Three successive line-scanner fixes were
each defeated (1 shape, then 4, then 6), which is ADR-001 §4's redesign signal.
The function and its seven comment-evasion self-tests are deleted rather than
kept as belt-and-braces: a second, weaker proof of an invariant that already has
a behavioural one is not redundancy, it is a defect with a maintenance cost and
a standing entry in `test_ci_strip_before_match.KNOWN_STRIP_ORDER_EXCEPTIONS`
(now empty again). What remains below is what text scanning uniquely covers —
the enforcement TOPOLOGY, which has no runtime to execute.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Runs under pytest (CI) and `python3 -m unittest`.
Does not import scanner/lib, so it does not affect the measured coverage gate.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    extract_on_block,
    strip_inline_comment,
)


# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
SECURITY_SCAN = WORKFLOW_DIR / "security-scan.yml"
DAST_BASELINE = WORKFLOW_DIR / "dast-baseline.yml"
DAST_FULL_SCAN = WORKFLOW_DIR / "dast-full-scan.yml"

# Dependencies the Security Scan Gate MUST aggregate. Removing any of these from
# `needs:` would let that job fail without blocking a merge.
GATE_REQUIRED_NEEDS = {"changes", "scan", "lighthouse"}


def gate_block_from(text):
    """The `security-scan-gate:` job block (its 2-space header to the next
    2-space top-level key, or EOF), with trailing inline `#` comments stripped
    per line so a commented token can't satisfy the gate checks (F-5b)."""
    out, in_gate = [], False
    for raw in text.splitlines():
        if re.match(r"^  security-scan-gate:\s*$", raw):
            in_gate = True
            out.append(strip_inline_comment(raw))
            continue
        if in_gate:
            if re.match(r"^  [A-Za-z0-9_-]+:", raw):  # next top-level job
                break
            out.append(strip_inline_comment(raw))
    return "\n".join(out)


def gate_needs_from(text):
    """The set of jobs under the gate job's `needs:` key ONLY (block- or
    flow-style). Scoping to the `needs:` sub-block (not a findall over the whole
    job block) prevents a `- foo` list item elsewhere — a matrix entry, a step
    input — from masking a dependency dropped from `needs:` (F-5a)."""
    needs, in_needs = [], False
    for raw in gate_block_from(text).splitlines():
        flow = re.match(r"^    needs:\s*\[(.*)\]\s*$", raw)
        if flow:
            needs += re.findall(r"[A-Za-z0-9_-]+", flow.group(1))
            continue
        if re.match(r"^    needs:\s*$", raw):
            in_needs = True
            continue
        if in_needs:
            m = re.match(r"^      -\s*([A-Za-z0-9_-]+)\s*$", raw)
            if m:
                needs.append(m.group(1))
            elif re.match(r"^    [A-Za-z]", raw):  # next 4-space key under the job
                in_needs = False
    return set(needs)


class TestSecurityScanGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            SECURITY_SCAN.read_text(encoding="utf-8")
            if SECURITY_SCAN.is_file()
            else ""
        )

    def _gate_block(self):
        return gate_block_from(self.text)

    def test_security_scan_yml_exists(self):
        self.assertTrue(SECURITY_SCAN.is_file(), f"{SECURITY_SCAN} not found")

    def test_gate_job_present_and_required_name(self):
        block = self._gate_block()
        self.assertTrue(block, "security-scan-gate job block not found")
        self.assertIn(
            "name: Security Scan Gate",
            block,
            "The gate's display name must stay 'Security Scan Gate' — branch "
            "protection requires that exact check name.",
        )

    def test_gate_runs_always(self):
        self.assertRegex(
            self._gate_block(),
            r"if:\s*always\(\)",
            "security-scan-gate must keep `if: always()` so it emits a status "
            "check even when scan/lighthouse are skipped.",
        )

    def test_gate_aggregates_required_needs(self):
        # Scoped to the gate job's `needs:` sub-block (F-5a) — not a findall over
        # the whole job block, which a list item elsewhere could satisfy.
        needs = gate_needs_from(self.text)
        missing = GATE_REQUIRED_NEEDS - needs
        self.assertEqual(
            missing,
            set(),
            "Security Scan Gate dropped required dependencies from `needs:` "
            "(would no longer block merges on their failure): "
            + ", ".join(sorted(missing)),
        )

    def test_gate_passset_not_loosened(self):
        # The fail condition must remain "result not in (success, skipped)".
        # Adding e.g. 'failure' to the pass-set would silently neuter the gate.
        self.assertRegex(
            self._gate_block(),
            r"""not\s+in\s*\(\s*["']success["']\s*,\s*["']skipped["']\s*\)""",
            "Security Scan Gate pass-set changed — it must fail when any "
            "dependency result is not exactly success/skipped.",
        )


class TestDastBaselinePrTrigger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            DAST_BASELINE.read_text(encoding="utf-8") if DAST_BASELINE.is_file() else ""
        )

    def test_dast_baseline_yml_exists(self):
        self.assertTrue(DAST_BASELINE.is_file(), f"{DAST_BASELINE} not found")

    def test_triggers_on_pull_request(self):
        # F-9: use the shared extract_on_block (handles flow-style `on: [..]`,
        # quoted `'on':`, and strips comments) instead of a block-only `^on:$`
        # parser that missed those forms. `pull_request` present in the on: block
        # (block or flow) satisfies the trigger; comments are already stripped.
        on_block = extract_on_block(self.text)
        self.assertTrue(on_block, "dast-baseline.yml `on:` block not found")
        self.assertIn(
            "pull_request",
            on_block,
            "dast-baseline.yml must keep its `pull_request` trigger — losing it "
            "would silently demote the DAST scan to schedule/dispatch-only, "
            "removing per-PR signal.",
        )


class TestDastFullScanSchedule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            DAST_FULL_SCAN.read_text(encoding="utf-8")
            if DAST_FULL_SCAN.is_file()
            else ""
        )

    def test_dast_full_scan_yml_exists(self):
        self.assertTrue(DAST_FULL_SCAN.is_file(), f"{DAST_FULL_SCAN} not found")

    def test_triggers_on_schedule(self):
        # F-9: shared extract_on_block (flow/quoted/comment-aware) — see baseline.
        on_block = extract_on_block(self.text)
        self.assertTrue(on_block, "dast-full-scan.yml `on:` block not found")
        self.assertIn(
            "schedule",
            on_block,
            "dast-full-scan.yml must keep its `schedule:` trigger — removing it "
            "would silently stop the nightly full DAST scan with no visible "
            "failure (parallels the dast-baseline pull_request guard).",
        )

    def test_unset_target_is_surfaced_not_silently_skipped(self):
        # Keeping the `schedule:` trigger is NOT enough: the scan job is gated on
        # `vars.DAST_TARGET_URL != ''`, so with the variable unset the job is
        # SKIPPED and the workflow conclusion is a clean `skipped`. Measured
        # 2026-08-06: 42 consecutive nightly runs reported `skipped` after the
        # variable was unset around 2026-06-25 — six weeks of ZERO automated DAST,
        # with no red build anywhere, while the workflow name still promised
        # nightly coverage. Actions has no `neutral` conclusion for a regular job,
        # so the only honest signal is an artifact.
        #
        # Direction: PRESENCE of the escalation path. Scanned comment-stripped so a
        # `#`-parked notice job cannot satisfy it (inert-guard class, ADR-001 §2).
        active = "\n".join(
            strip_inline_comment(ln)
            for ln in self.text.splitlines()
            if not ln.lstrip().startswith("#")
        )
        self.assertRegex(
            active,
            r"(?m)^\s*coverage-notice\s*:",
            "dast-full-scan.yml lost its `coverage-notice` job. Without it, an unset "
            "DAST_TARGET_URL makes the nightly scan skip SILENTLY (clean `skipped`, "
            "no red build) while the workflow still advertises nightly coverage. If "
            "nightly DAST is intentionally paused, rename the workflow and drop the "
            "claim in the same change — then update this guard.",
        )
        self.assertIn(
            "issues.create",
            active,
            "the `coverage-notice` job no longer opens an issue — a `core.warning` "
            "alone is invisible, which is exactly the failure mode this guards.",
        )
        self.assertIn(
            "DAST_TARGET_URL",
            active,
            "the notice job must read DAST_TARGET_URL to know whether coverage is "
            "live; without it the notice cannot self-heal when the target returns.",
        )


class TestGateNeedsScopingAndPassset(unittest.TestCase):
    """F-5: needs aggregation is scoped to the `needs:` sub-block, and the pass-set
    check ignores comments."""

    def test_needs_scoped_to_needs_block(self):
        mutant = "\n".join(
            [
                "  security-scan-gate:",
                "    needs:",
                "      - scan",
                "      - lighthouse",
                "    steps:",
                "      - with:",
                "          deps:",
                "            - changes",  # decoy list item — NOT a gate dependency
                "  next-job:",
            ]
        )
        self.assertNotIn(
            "changes",
            gate_needs_from(mutant),
            "F-5a: a `- changes` list item outside the `needs:` sub-block was "
            "wrongly counted as a gate dependency.",
        )

    def test_passset_surviving_only_in_comment_does_not_satisfy(self):
        mutant = "\n".join(
            [
                "  security-scan-gate:",
                "    steps:",
                '      - run: echo keep  # not in ("success", "skipped")',
                "  next-job:",
            ]
        )
        self.assertNotRegex(
            gate_block_from(mutant),
            r"""not\s+in\s*\(\s*["']success["']\s*,\s*["']skipped["']\s*\)""",
            "F-5b: the pass-set surviving only in a `#` comment must not satisfy "
            "the gate's not-loosened check.",
        )


if __name__ == "__main__":
    unittest.main()
