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

4. **It verifies right after each publish** — must keep a `workflow_run` trigger
   on the "Publish to npm" workflow. The published artifact only changes on a
   release, so post-publish verification is the highest-value cadence; dropping
   the trigger would leave only the daily safety-net schedule, so a freshly
   published artifact with a lost signature/provenance could sit unverified for
   up to a day.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess, does not import scanner/lib. Passes under pytest and
`python3 -m unittest`. Action SHA-pinning is covered by test_ci_gate_topology.py.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import extract_on_block  # noqa: E402

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

    def test_keeps_workflow_run_post_publish_trigger(self):
        # The `on:` block must keep a `workflow_run` trigger on "Publish to npm",
        # so the published artifact is verified right after each release (the
        # cadence that maps to when it actually changes). Whole-line comments are
        # stripped so prose mentioning the trigger can't satisfy the check.
        on_block = extract_on_block(self.text)
        self.assertRegex(
            on_block,
            r"(?m)^\s*workflow_run:\s*$",
            "provenance-verify.yml lost its `workflow_run:` trigger — the "
            "published artifact would no longer be verified right after a publish, "
            "leaving only the daily safety-net schedule.",
        )
        self.assertRegex(
            on_block,
            r"Publish to npm",
            "the `workflow_run` trigger no longer references the \"Publish to "
            "npm\" workflow — post-publish verification would never fire.",
        )
        # Guard the firing condition too: a `workflow_run:` key whose `types`
        # dropped `completed` (or went empty) would never fire — a silent, vacuous
        # weakening the key-presence check above cannot see.
        self.assertRegex(
            on_block,
            r"(?m)^\s*types:\s*\[[^\]]*\bcompleted\b[^\]]*\]\s*$",
            "the `workflow_run` trigger no longer fires on `types: [completed]` — "
            "post-publish verification would never run.",
        )


if __name__ == "__main__":
    unittest.main()
