"""
Regression guard for the published-package provenance monitor
`.github/workflows/provenance-verify.yml`.

Supply-chain integrity invariants, all silently weakenable:

1. **It stays a scheduled monitor** — must keep a `schedule:` trigger. Dropping
   it turns the supply-chain check into a manual-only step nobody runs, so a lost
   signature/provenance on the published package goes unnoticed.

2. **It NEVER becomes a required PR check** — must NOT gain a `pull_request` or
   `pull_request_target` trigger. claudesec has zero runtime deps, so a per-PR
   `npm audit signatures` verifies nothing about the PR (it checks the *published*
   artifact); wiring it into PRs would add a flaky, network-bound, value-free gate
   (and `pull_request_target` would be an untrusted-input write-token foot-gun).

3. **It actually runs the verification** — must invoke `npm audit signatures`,
   the command that checks the npm registry signature + SLSA provenance attestation
   of the installed package (OWASP A08 — Software & Data Integrity Failures).

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess, does not import scanner/lib. Passes under pytest and
`python3 -m unittest`. Action SHA-pinning is covered by test_ci_gate_topology.py.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "provenance-verify.yml"


def _strip_comment(line: str) -> str:
    return re.sub(r"\s+#.*$", "", line)


class TestProvenanceVerifyWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def test_workflow_exists(self):
        self.assertTrue(WORKFLOW.is_file(), f"{WORKFLOW} not found")

    def test_keeps_schedule_trigger(self):
        self.assertRegex(
            self.text,
            r"(?m)^\s*schedule:\s*$",
            "provenance-verify.yml lost its `schedule:` trigger — the published "
            "package provenance/signature check would no longer run periodically.",
        )
        # A bare `schedule:` with no cron entry is invalid (and a plausible
        # mistaken weakening that would silently stop the cadence) — require one.
        self.assertRegex(
            self.text,
            r"(?m)^\s*-\s*cron:\s*['\"][^'\"]+['\"]\s*$",
            "schedule trigger has no `- cron:` expression — the periodic run "
            "would never fire.",
        )

    def test_no_pull_request_trigger(self):
        offenders = [
            ln.strip()
            for ln in self.text.splitlines()
            if re.match(r"\s*pull_request(_target)?:", _strip_comment(ln))
        ]
        self.assertEqual(
            offenders,
            [],
            "provenance-verify.yml gained a pull_request(_target) trigger — a "
            "zero-dep `npm audit signatures` adds no PR value and must not become "
            "a required/flaky PR gate:\n  " + "\n  ".join(offenders),
        )

    def test_runs_npm_audit_signatures(self):
        self.assertRegex(
            self.text,
            r"\bnpm\s+audit\s+signatures\b",
            "provenance-verify.yml no longer runs `npm audit signatures` — the "
            "actual registry-signature + SLSA-provenance verification is gone.",
        )


if __name__ == "__main__":
    unittest.main()
