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
from _ci_guard_util import strip_inline_comment  # noqa: E402


def conditional_body_from(text, var):
    """The body of `if [ "$<var>" -gt 0 ]; then ... fi`.

    Trailing inline `#` comments are stripped per line first, so a commented-out
    `# exit 1` can neither satisfy nor falsely trip the severity-block checks
    (comment-evasion class, F-1). The closing `fi` is found by a BALANCED if/fi
    depth count — NOT the first `fi` — so a nested `if … fi` inside the block (or
    a heredoc) cannot terminate the capture early and hide a trailing `exit 1`
    (2nd-review Finding 1). `elif`/`else`/`then` are not `\\bfi\\b`/`\\bif\\b`
    tokens, so they don't perturb the count.
    """
    m = re.search(
        r'\[\s*"\$' + re.escape(var) + r'"\s+-gt\s+0\s*\]\s*;\s*then',
        text,
    )
    if not m:
        return None
    # Comment-stripped remainder after the CRITS `then` (so a `# fi`/`# if` in a
    # comment cannot skew the depth count).
    rest = "\n".join(strip_inline_comment(ln) for ln in text[m.end():].splitlines())
    depth, end = 1, len(rest)
    for tk in re.finditer(r"\bif\b|\bfi\b", rest):
        depth += 1 if tk.group(0) == "if" else -1
        if depth == 0:
            end = tk.start()
            break
    return rest[:end]


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

    def _on_block(self):
        # The `on:` region: from `^on:` to the next top-level key (`jobs:` etc.).
        out, in_on = [], False
        for raw in self.text.splitlines():
            if re.match(r"^on:\s*$", raw):
                in_on = True
                continue
            if in_on:
                if re.match(r"^[A-Za-z]", raw):  # next top-level key (jobs:, etc.)
                    break
                out.append(raw)
        return "\n".join(out)

    def test_dast_baseline_yml_exists(self):
        self.assertTrue(DAST_BASELINE.is_file(), f"{DAST_BASELINE} not found")

    def test_triggers_on_pull_request(self):
        on_block = self._on_block()
        self.assertTrue(on_block, "dast-baseline.yml `on:` block not found")
        self.assertRegex(
            on_block,
            r"^\s*pull_request:",
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

    def _on_block(self):
        # The `on:` region: from `^on:` to the next top-level key (`jobs:` etc.).
        out, in_on = [], False
        for raw in self.text.splitlines():
            if re.match(r"^on:\s*$", raw):
                in_on = True
                continue
            if in_on:
                if re.match(r"^[A-Za-z]", raw):  # next top-level key (jobs:, etc.)
                    break
                out.append(raw)
        return "\n".join(out)

    def test_dast_full_scan_yml_exists(self):
        self.assertTrue(DAST_FULL_SCAN.is_file(), f"{DAST_FULL_SCAN} not found")

    def test_triggers_on_schedule(self):
        on_block = self._on_block()
        self.assertTrue(on_block, "dast-full-scan.yml `on:` block not found")
        self.assertRegex(
            on_block,
            r"^\s*schedule:",
            "dast-full-scan.yml must keep its `schedule:` trigger — removing it "
            "would silently stop the nightly full DAST scan with no visible "
            "failure (parallels the dast-baseline pull_request guard).",
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
