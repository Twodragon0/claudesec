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
    shell_if_body,
    strip_inline_comment,
)


def conditional_body_from(text, var):
    """The body of `if [ "$<var>" -gt 0 ]; then ... fi`, or None.

    Inline shell `#` comments are stripped per line BEFORE anything else, so a
    commented-out `# exit 1` — INCLUDING the bash command-separator form
    `;#exit 1` (a real comment with no preceding space, which a whitespace-only
    stripper misses) — can neither satisfy nor falsely trip the severity-block
    checks (comment-evasion class, F-1; 3rd-pass finding). The closing `fi` is
    found by a BALANCED if/fi depth count — NOT the first `fi` — so a nested
    `if … fi` inside the block (or a heredoc) cannot terminate the capture early
    and hide a trailing `exit 1` (2nd-review Finding 1). `elif`/`else`/`then` are
    not `\\bfi\\b`/`\\bif\\b` tokens, so they don't perturb the count.

    Two silent bypasses of the CRITICAL merge block, both found by the 2026-08-07
    stripper/haystack audit, both with a runnable PoC on bash AND on this
    function, both now closed:

    H1 (CRITICAL) — the anchor used to be searched in the RAW text while only the
    BODY was comment-stripped. One comment line,
    `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi`, therefore anchored the scan
    inside itself and handed back ` exit 1; ` as the body: bash exited 0 on a
    CRITICAL finding (merge allowed) and this guard reported the gate intact.
    That is the ADR-001 §2 rule — strip, THEN match — applied to the anchor and
    not just the haystack.

    H2 (HIGH, was latent) — when the depth count never reached 0 the function
    used to return the ENTIRE remainder of the file. Commenting the block out
    line-by-line leaves an unbalanced `fi`-less region, so the body ran to EOF and
    ANY later `exit 1` in security-scan.yml satisfied the check. Adding one
    ordinary `… || exit 1` step to the gate job was enough to turn the canonical
    "temporarily disable the block" edit green. It now fails CLOSED: no balanced
    `fi` -> None -> the consumer's `assertIsNotNone` fires.

    Both are handled by the shared `shell_if_body` primitive, so the sibling
    image-size gate (`test_ci_docker_image_size_gate.breach_block`) — which had
    the same H2 hole, live — cannot drift away from the fix.
    """
    return shell_if_body(
        text, r'\[\s*"\$' + re.escape(var) + r'"\s+-gt\s+0\s*\]\s*;\s*then'
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


class TestScanCriticalSeverityBlock(unittest.TestCase):
    """The `scan` job must FAIL the build on any CRITICAL finding (exit 1), and
    keep HIGH findings non-blocking (warning only) — the documented gate that was
    previously warn-only-despite-the-comment (resolved in #206). Reverting it to
    warn-only would silently disable the CRITICAL merge block."""

    @classmethod
    def setUpClass(cls):
        cls.text = (
            SECURITY_SCAN.read_text(encoding="utf-8")
            if SECURITY_SCAN.is_file()
            else ""
        )

    def _conditional_body(self, var):
        return conditional_body_from(self.text, var)

    def test_critical_block_exits_nonzero(self):
        body = self._conditional_body("CRITS")
        self.assertIsNotNone(
            body, "Could not find the `[ \"$CRITS\" -gt 0 ]` severity gate block"
        )
        self.assertRegex(
            body,
            r"\bexit\s+1\b",
            "The scan job must `exit 1` on CRITICAL findings so the Security Scan "
            "Gate blocks the merge — do not revert it to warning-only (#206).",
        )

    def test_high_block_stays_nonblocking(self):
        body = self._conditional_body("HIGHS")
        # HIGH handling may exist (warning) or not; if present it must NOT exit 1.
        if body is not None:
            self.assertNotRegex(
                body,
                r"\bexit\s+1\b",
                "HIGH findings must remain non-blocking (warning only); only "
                "CRITICAL blocks the merge.",
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


class TestSeverityBlockCommentEvasion(unittest.TestCase):
    """F-1 (CRITICAL): a commented-out `exit 1` must not satisfy the merge block."""

    def test_commented_exit_one_does_not_satisfy(self):
        mutant = 'if [ "$CRITS" -gt 0 ]; then\n  echo warn  # exit 1\nfi'
        body = conditional_body_from(mutant, "CRITS") or ""
        self.assertNotRegex(
            body,
            r"\bexit\s+1\b",
            "comment-evasion: a `# exit 1` surviving only in a comment must NOT "
            "satisfy the CRITICAL merge-block check.",
        )

    def test_metachar_commented_exit_one_does_not_satisfy(self):
        # `;#exit 1` is a REAL bash comment (verified: the exit never runs) with
        # no space before `#` — a whitespace-only stripper misses it (3rd-pass
        # CRITICAL finding). The gate would falsely certify the merge-block intact.
        mutant = 'if [ "$CRITS" -gt 0 ]; then\n  echo "no longer blocking";#exit 1\nfi'
        body = conditional_body_from(mutant, "CRITS") or ""
        self.assertNotRegex(
            body,
            r"\bexit\s+1\b",
            "metachar comment-evasion: a `;#exit 1` (real bash comment, no space) "
            "surviving only in a comment must NOT satisfy the CRITICAL merge-block.",
        )

    def test_backtick_commented_exit_one_does_not_satisfy(self):
        # `` `#exit 1` `` — a `#` right after an opening backtick is also a real
        # bash comment (4th-pass finding).
        mutant = 'if [ "$CRITS" -gt 0 ]; then\n  echo "downgraded"`#exit 1`\nfi'
        body = conditional_body_from(mutant, "CRITS") or ""
        self.assertNotRegex(
            body,
            r"\bexit\s+1\b",
            "backtick comment-evasion: a `` `#exit 1` `` surviving only in a "
            "comment must NOT satisfy the CRITICAL merge-block.",
        )

    def test_ansi_c_commented_exit_one_does_not_satisfy(self):
        # 5th-pass finding (ADR-001 §2): `$'\''` is ONE ANSI-C string (the `\'` is
        # an escaped literal quote), so ` #exit 1` is a real bash comment — verified
        # by execution: the exit never runs, the gate does NOT block. A single-quote
        # stripper with no escape awareness re-opens the quote at the trailing `'`,
        # runs off the line "in a quote", never strips the `#`, and lets the dead
        # `exit 1` satisfy the merge-block. Regression direction: presence.
        mutant = (
            'if [ "$CRITS" -gt 0 ]; then\n'
            + r"""  : $'\'' #exit 1"""
            + "\nfi"
        )
        body = conditional_body_from(mutant, "CRITS") or ""
        self.assertNotRegex(
            body,
            r"\bexit\s+1\b",
            "ANSI-C comment-evasion: an `exit 1` surviving only in a `$'\\''`-"
            "prefixed bash comment must NOT satisfy the CRITICAL merge-block.",
        )

    def test_commented_out_block_does_not_anchor_the_scan(self):
        # H1 (CRITICAL, 2026-08-07 audit): the anchor was searched in RAW text, so
        # a one-line comment holding the whole block anchored the scan inside
        # itself and returned ` exit 1; ` as the body. Verified by execution: bash
        # exits 0 on a CRITICAL finding while this returned a satisfying body.
        mutant = (
            '          # was: if [ "$CRITS" -gt 0 ]; then exit 1; fi  (disabled)\n'
            '          echo "no gate"\n'
        )
        body = conditional_body_from(mutant, "CRITS")
        self.assertIsNone(
            body,
            "comment-anchored evasion: a `#`-commented copy of the severity block "
            "must not be found as the block itself.",
        )

    def test_unbalanced_block_fails_closed(self):
        # H2 (HIGH): with no balanced `fi`, returning the rest of the file let ANY
        # later `exit 1` certify the dead block. Must be None, not a mega-body.
        mutant = (
            'if [ "$CRITS" -gt 0 ]; then\n'
            "  echo warn\n"
            "# fi   <- block commented out; the closer is gone\n"
            "steps:\n"
            "  - run: test -f x || exit 1\n"
        )
        self.assertIsNone(
            conditional_body_from(mutant, "CRITS"),
            "unbalanced if/fi must fail CLOSED — returning the rest of the file "
            "lets an unrelated `exit 1` satisfy the CRITICAL merge-block check.",
        )

    def test_if_inside_a_message_does_not_extend_the_body(self):
        # The word `if` in an error string is not a bash `if`. Counting it would
        # push the body past the real `fi` and (with fail-closed) turn an ordinary
        # message edit into a false alarm.
        mutant = (
            'if [ "$CRITS" -gt 0 ]; then\n'
            '  echo "failing the build if any critical is found"\n'
            "  exit 1\n"
            "fi\n"
            "echo after\n"
        )
        body = conditional_body_from(mutant, "CRITS")
        self.assertIsNotNone(body, "a plain `if` in a message broke the depth count")
        self.assertNotIn("after", body, "body ran past the closing `fi`")
        self.assertRegex(body, r"\bexit\s+1\b")

    def test_real_exit_one_satisfies(self):
        good = 'if [ "$CRITS" -gt 0 ]; then\n  exit 1\nfi'
        self.assertRegex(conditional_body_from(good, "CRITS"), r"\bexit\s+1\b")

    def test_exit_one_after_nested_fi_is_captured(self):
        # 2nd-review Finding 1: a nested `if … fi` must not terminate the capture
        # before the outer `exit 1` (balanced fi-counter, not first-fi).
        nested = (
            'if [ "$CRITS" -gt 0 ]; then\n'
            '  if [ "$X" -ge 1 ]; then\n    echo inner\n  fi\n'
            "  exit 1\n"
            "fi"
        )
        self.assertRegex(
            conditional_body_from(nested, "CRITS"),
            r"\bexit\s+1\b",
            "Balanced-fi FAILED: `exit 1` after a nested `fi` was not captured — "
            "a nested-if restructuring could silently disable the merge block.",
        )


if __name__ == "__main__":
    unittest.main()
