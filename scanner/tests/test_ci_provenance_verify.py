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
from _ci_guard_util import (  # noqa: E402
    explicit_key_lines,
    extract_on_block,
    non_comment_lines,
    strip_inline_comment as _strip_comment,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "provenance-verify.yml"

# `npm audit signatures` in COMMAND position: at the start of a line or right
# after a shell separator/keyword. Scoping is load-bearing — the workflow names
# the command in four whole-line comments AND inside two `echo "::error::…"`
# strings, so a bare substring/regex search stays green after the real
# invocation is deleted (inert-guard class, verified by the mutation self-test
# below).
_AUDIT_SIG_CMD_RE = re.compile(
    r"(?:^|;|&&|\|\||\(|\{|!|\bif\b|\bthen\b|\belse\b|\bdo\b)"
    r"\s*npm\s+audit\s+signatures\b"
)


def audit_signatures_invoked(text):
    """True when `npm audit signatures` is actually RUN, not merely mentioned.

    Drops whole-line comments, strips trailing comments, requires the token in
    command position, and rejects a match sitting inside a double-quoted string
    (an even number of `"` must precede it on the line) so an `echo "… npm audit
    signatures …"` cannot satisfy the invariant.
    """
    for raw in non_comment_lines(text):
        line = _strip_comment(raw)
        for m in _AUDIT_SIG_CMD_RE.finditer(line):
            if line.count('"', 0, m.start()) % 2 == 0:
                return True
    return False


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
        # The key is matched bare OR quoted: `"pull_request_target":` resolves to
        # the same trigger, and an adversarial sweep proved the bare-only regex let
        # it back in with this guard green — on a workflow whose whole point is
        # release-attestation integrity.
        pr_key = yaml_key_pattern("pull_request")
        prt_key = yaml_key_pattern("pull_request_target")
        offenders = [
            ln.strip()
            for ln in self.text.splitlines()
            if re.match(rf"\s*(?:{pr_key}|{prt_key}):", _strip_comment(ln))
        ]
        # ...and fail closed on the explicit-key form, where the literal
        # `pull_request_target:` never appears for any matcher to find.
        offenders += explicit_key_lines(
            self.text, "pull_request", "pull_request_target"
        )
        self.assertEqual(
            offenders,
            [],
            "provenance-verify.yml gained a pull_request(_target) trigger — a "
            "zero-dep `npm audit signatures` adds no PR value and must not become "
            "a required/flaky PR gate:\n  " + "\n  ".join(offenders),
        )

    def test_runs_npm_audit_signatures(self):
        self.assertTrue(
            audit_signatures_invoked(self.text),
            "provenance-verify.yml no longer RUNS `npm audit signatures` — the "
            "actual registry-signature + SLSA-provenance verification is gone. "
            "Mentioning it in a comment or an `echo` string does not count.",
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


class TestAuditSignaturesInvocationScoping(unittest.TestCase):
    """Mutation self-tests for `audit_signatures_invoked`.

    The bare `assertRegex(text, r"npm audit signatures")` this replaced could
    not detect deletion of the real invocation: the workflow's own explanatory
    comments and its `echo "::error::npm audit signatures FAILED …"` message
    satisfied the pattern on their own.
    """

    def test_real_invocation_counts(self):
        self.assertTrue(
            audit_signatures_invoked(
                "          if npm audit signatures > sig.log 2>&1; then\n"
            )
        )

    def test_bare_command_counts(self):
        self.assertTrue(audit_signatures_invoked("          npm audit signatures\n"))

    def test_whole_line_comment_does_not_count(self):
        self.assertFalse(
            audit_signatures_invoked(
                "# `npm audit signatures` verifies the registry signature\n"
                "          # No -e on purpose: the npm audit signatures exit is\n"
            )
        )

    def test_echo_string_does_not_count(self):
        self.assertFalse(
            audit_signatures_invoked(
                '            echo "::error::npm audit signatures FAILED for x"\n'
            )
        )

    def test_trailing_comment_does_not_count(self):
        self.assertFalse(
            audit_signatures_invoked("          true  # npm audit signatures\n")
        )

    def test_gutted_workflow_is_detected(self):
        # The realistic weakening: the invocation swapped for a no-op while every
        # comment and echo mentioning it stays. Must be False.
        gutted = (
            "# `npm audit signatures` verifies BOTH the registry signature and\n"
            "          # the `npm audit signatures` non-zero exit is the signal\n"
            "          if true > sig.log 2>&1; then\n"
            '            echo "::error::npm audit signatures FAILED for x"\n'
        )
        self.assertFalse(
            audit_signatures_invoked(gutted),
            "Inert-guard regression: a workflow that only MENTIONS the command "
            "must not satisfy the invocation check.",
        )


class TestTriggerKeyQuotingMutation(unittest.TestCase):
    """Non-vacuity for the 2026-08-06 sweep fix: a quoted or explicit-key
    `pull_request_target:` must be caught. Before it, both forms re-added a
    write-token PR trigger to the release-attestation workflow, guard green."""

    def _offenders(self, text):
        pr_key = yaml_key_pattern("pull_request")
        prt_key = yaml_key_pattern("pull_request_target")
        found = [
            ln.strip()
            for ln in text.splitlines()
            if re.match(rf"\s*(?:{pr_key}|{prt_key}):", _strip_comment(ln))
        ]
        return found + explicit_key_lines(text, "pull_request", "pull_request_target")

    def test_fires_on_quoted_and_explicit_pr_triggers(self):
        for body in (
            '  "pull_request_target":\n    types: [opened]',
            "  'pull_request':\n    branches: [main]",
            "  ? pull_request_target\n  : {types: [opened]}",
            "  pull_request_target:\n    types: [opened]",
        ):
            with self.subTest(body=body.splitlines()[0].strip()):
                self.assertTrue(
                    self._offenders("on:\n" + body + "\njobs: {}"),
                    "Mutation FAILED: a quoted/explicit `pull_request(_target)` "
                    "trigger evaded the scan on the provenance workflow.",
                )

    def test_quiet_on_the_real_workflow_and_on_comments(self):
        self.assertEqual(
            self._offenders("on:\n  # pull_request_target: not a real trigger\n  push:\n"),
            [],
            "False positive: a commented-out trigger was reported as live.",
        )


if __name__ == "__main__":
    unittest.main()
