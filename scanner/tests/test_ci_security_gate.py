"""
Regression guards for the security-scan workflow's enforcement topology.

`main` branch protection requires exactly two checks: `Lint` (lint.yml's
lint-gate) and `Security Scan Gate` (security-scan.yml). The latter is an
`always()` aggregator whose pass/fail is derived from its `needs:` results — so
silently dropping a dependency from `needs`, removing `if: always()`, or
loosening the pass-set would neuter the only security required-check without any
visible failure. This guards that topology (cf. test_ci_gate_topology.py for the
lint-gate analogue, and project memory paths-ignore-vs-branch-protection #186).

Also guards that the PR-time DAST signal (`dast-baseline.yml`) is not silently
downgraded to schedule/dispatch-only by asserting it still triggers on
`pull_request`.

Scope note: action SHA-pinning for these files is already covered by
test_ci_gate_topology.py (it globs all workflows) — NOT duplicated here.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Runs under pytest (CI) and `python3 -m unittest`.
Does not import scanner/lib, so it does not affect the measured coverage gate.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
SECURITY_SCAN = WORKFLOW_DIR / "security-scan.yml"
DAST_BASELINE = WORKFLOW_DIR / "dast-baseline.yml"

# Dependencies the Security Scan Gate MUST aggregate. Removing any of these from
# `needs:` would let that job fail without blocking a merge.
GATE_REQUIRED_NEEDS = {"changes", "scan", "lighthouse"}


class TestSecurityScanGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            SECURITY_SCAN.read_text(encoding="utf-8")
            if SECURITY_SCAN.is_file()
            else ""
        )

    def _gate_block(self):
        # Capture the `security-scan-gate:` job block: from its 2-space header to
        # the next 2-space top-level key (or EOF). 4-space child keys (name:,
        # needs:, steps:, ...) do not terminate the block.
        out, in_gate = [], False
        for raw in self.text.splitlines():
            if re.match(r"^  security-scan-gate:\s*$", raw):
                in_gate = True
                out.append(raw)
                continue
            if in_gate:
                if re.match(r"^  [A-Za-z0-9_-]+:", raw):  # next top-level job
                    break
                out.append(raw)
        return "\n".join(out)

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
        block = self._gate_block()
        # `needs:` block-list items within the gate job
        needs = set(re.findall(r"^\s*-\s*([A-Za-z0-9_-]+)\s*$", block, re.MULTILINE))
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


if __name__ == "__main__":
    unittest.main()
