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
each defeated (1 shape, then 4, then 6), which is ADR-001 §5's redesign signal.
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
    apply_mutation,
    extract_on_block,
    job_block,
    job_needs,
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
    """The `security-scan-gate:` job block, via the shared `job_block`.

    Was a local parser until 2026-08-10. It was BYPASSABLE, proven on a mutated
    copy of the real workflow: its header matched `^  security-scan-gate:` bare
    only, and its terminator `^  [A-Za-z0-9_-]+:` did not match a QUOTED sibling
    job key — so a job written `  "post-gate-notify":` below the gate did not end
    the block, and the gate could lose its own `if: always()` while
    `test_gate_runs_always` still found one, borrowed from that sibling. The
    shared `job_block` reads the header bare or quoted, bounds the block by
    INDENTATION (so a top-level key ends it too), and returns None rather than
    guessing when the key appears zero or many times.

    Kept as a named indirection because this guard's tests assert on it, and it
    carries the two things `job_block` deliberately does not: normalising None to
    "" for the `assertTrue(block)` canary, and F-5b inline-comment stripping.

    F-5b IS LOAD-BEARING and nearly lost in this swap. The old parser stripped a
    trailing `#` comment from every line it kept, so a token surviving only in a
    comment cannot satisfy a gate check; `job_block` returns raw lines. Swapping
    the parser without re-adding the strip broke
    `test_passset_surviving_only_in_comment_does_not_satisfy` immediately — a
    reminder that "equal on the happy path" is not equivalence. The first
    equivalence check here compared only the parsed `needs:` set, which is
    identical either way, and would have shipped the regression.
    """
    block = job_block(text, "security-scan-gate")
    if block is None:
        return ""
    return "\n".join(strip_inline_comment(ln) for ln in block.splitlines())


def gate_needs_from(text):
    """The set of jobs under the gate's `needs:` key ONLY, via the shared
    `job_needs`.

    The scoping this used to hand-roll — read the `needs:` sub-block, not a
    findall over the whole job — is the shared helper's documented contract, so a
    `- foo` list item elsewhere still cannot mask a dropped dependency. Verified
    equal on the real workflow before the swap: both return
    {changes, lighthouse, scan}.
    """
    return set(job_needs(gate_block_from(text)))


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


class TestGateBlockBoundaryMutation(unittest.TestCase):
    """The block boundary is as load-bearing as the assertions over it: a block
    that runs past the job lets a NEIGHBOURING job satisfy a gate check."""

    @classmethod
    def setUpClass(cls):
        cls.real = SECURITY_SCAN.read_text(encoding="utf-8")

    def _gate_without_always(self):
        # Drop every `if: always()` — including the three COMMENT lines above the
        # real one that quote it verbatim. Missing those is what made the first
        # version of this probe report a bypass that was not there: the guard's
        # own comment-evasion class, biting the fixture instead of the guard.
        return "\n".join(
            ln for ln in self.real.splitlines() if "if: always()" not in ln
        ) + "\n"

    def test_quoted_sibling_job_does_not_lend_the_gate_its_always(self):
        mutant = self._gate_without_always() + (
            '  "post-gate-notify":\n'
            "    if: always()\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo notify\n"
        )
        self.assertNotRegex(
            gate_block_from(mutant),
            r"if:\s*always\(\)",
            "the gate block ran past its own job into a QUOTED sibling and "
            "borrowed that job's `if: always()`. Proven bypassable before "
            "2026-08-10: the old terminator `^  [A-Za-z0-9_-]+:` did not match a "
            "quoted job key, so `test_gate_runs_always` passed while the gate had "
            "lost the key it exists to protect.",
        )

    def test_bare_sibling_job_also_terminates_the_block(self):
        mutant = self._gate_without_always() + (
            "  post-gate-notify:\n    if: always()\n    runs-on: ubuntu-latest\n"
        )
        self.assertNotRegex(gate_block_from(mutant), r"if:\s*always\(\)")

    def test_quoted_gate_header_is_still_found(self):
        # The other direction of the same class: a quoted `"security-scan-gate":`
        # used to yield an EMPTY block, which fails every positive assertion at
        # once — a false alarm rather than a bypass, but still a guard broken by
        # an ordinary authoring style.
        mutant = apply_mutation(
            self.real, "  security-scan-gate:\n", '  "security-scan-gate":\n'
        )
        self.assertEqual(
            gate_needs_from(mutant),
            GATE_REQUIRED_NEEDS,
            "a quoted gate job key made the block unreadable",
        )

    def test_real_file_block_is_scoped_to_the_gate(self):
        # Vacuity canary in the other direction: the block must not be empty, and
        # must not contain a marker from the preceding job.
        blk = gate_block_from(self.real)
        self.assertTrue(blk)
        self.assertIn("name: Security Scan Gate", blk)
        self.assertNotIn("name: Lighthouse Audit", blk)


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

    def test_nightly_cannot_be_gated_into_silence(self):
        """The scan must not be gated on a repo variable, and its target must not
        depend on one being set.

        HISTORY, and why the invariant moved (#399, 2026-08-26). The job used to
        carry `if: … || vars.DAST_TARGET_URL != ''`. With the variable unset it
        was SKIPPED, the workflow conclusion was a clean `skipped`, and nothing
        was red — measured 2026-08-06: 42 consecutive nightly runs reported
        `skipped` after the variable was unset around 2026-06-25, six weeks of
        ZERO automated DAST, with `gh api .../actions/variables` returning
        total_count: 0. Actions has no `neutral` conclusion for a regular job.

        The previous version of this guard required a `coverage-notice` job to
        make that state visible. The state is now impossible instead: the nightly
        scans this repo's own dashboard container, so there is nothing to
        configure and nothing to skip. A notice about a missing variable would
        report "not running" on every night the scan ran fine, so requiring one
        would now be requiring a lie.

        Direction: ABSENCE of the configuration dependency. Re-adding a `vars.`
        gate, or making the target read a variable, trips this.
        """
        active = "\n".join(
            strip_inline_comment(ln)
            for ln in self.text.splitlines()
            if not ln.lstrip().startswith("#")
        )
        self.assertNotIn(
            "vars.DAST_TARGET_URL",
            active,
            "dast-full-scan.yml reads `vars.DAST_TARGET_URL` again. That is the "
            "construct that made 42 consecutive nightly runs report a clean "
            "`skipped`: an unset variable either skips the job or points the scan "
            "at whatever host a stale variable names. The nightly target is the "
            "repo's own container; an authorized external target goes through "
            "`workflow_dispatch`.",
        )
        self.assertNotRegex(
            active,
            r"(?m)^\s*if:.*vars\.",
            "the scan job is gated on a repo variable again — a gate whose "
            "unset state is a clean `skipped` rather than a failure.",
        )
        # Bound to the `target:` LINE, not to the file. A bare
        # `assertIn("http://localhost:11777", active)` was satisfied by the
        # `until curl -sf http://localhost:11777/` wait loop in the container-start
        # step, so deleting the fallback from the target expression left this
        # green — the inert-assertion class (ADR-001 §2), found by mutating it.
        target_lines = [
            ln for ln in active.splitlines() if re.match(r"^\s*target:\s*", ln)
        ]
        self.assertEqual(
            len(target_lines),
            1,
            f"expected exactly one `target:` line, found {len(target_lines)}: "
            f"{target_lines}",
        )
        self.assertIn(
            "http://localhost:11777",
            target_lines[0],
            "the scan's `target:` lost its local-container fallback, so an empty "
            "`workflow_dispatch` input has nothing to scan and the nightly is back "
            f"to depending on configuration. Line: {target_lines[0].strip()}",
        )
        self.assertIn(
            "docker compose up -d dashboard",
            active,
            "nothing starts the container the scan targets, so the nightly would "
            "scan a closed port and report a clean run.",
        )

    def test_external_target_input_is_not_required(self):
        """`workflow_dispatch` must accept an EMPTY target.

        `required: true` on the input would force every manual run to name an
        external host — the opposite of the #399 decision, and the shape that
        makes someone paste in a host they are not authorized to scan
        (NIST SP 800-115). Empty means the local container.
        """
        active = "\n".join(
            strip_inline_comment(ln)
            for ln in self.text.splitlines()
            if not ln.lstrip().startswith("#")
        )
        idx = active.find("target_url:")
        self.assertNotEqual(idx, -1, "the `target_url` input is gone")
        block = active[idx : idx + 400]
        self.assertNotRegex(
            block,
            r"(?m)^\s*required:\s*true",
            "`target_url` is `required: true` again, so a manual run cannot scan "
            "the local container and must name an external host.",
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
