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

5. **No status the verify step writes may be TERMINAL-SILENT** — every value it
   writes to `$GITHUB_OUTPUT` must be read by some later step, the non-`ok` ones
   must escalate to an issue, `ok` must CLOSE that issue, and the install-failure
   status must be reached only after >= 3 attempts.

   Measured incident (audit 2026-08-12, fixed in the PR that added this section):
   the install-failure branch wrote `status=transient` and **nothing read it** —
   the only readers were two `status == 'failed'` steps. A *permanent* install
   failure (package unpublished/renamed, registry blocking the runner, a broken
   npm self-upgrade, an npm-side auth change) therefore exited 0 having verified
   nothing, forever, and GitHub Actions has no `neutral` conclusion for a regular
   job — success / failure / cancelled / skipped only — so every one of those runs
   reported **green**. Executed, on the pre-fix file, driving the branch with `gh`
   and `npm` stubs: `gh calls: 0`, no step summary, and an already-open
   `provenance-watch` issue left untouched. Same class as #396/#397.

   The four sub-assertions are one rule each, in the order a regression would
   arrive:

   - *consumer completeness* — writes ⊆ reads, derived from the file rather than
     enumerated, so a NEW status branch added later must also be consumed;
   - *escalation* — a consumer that only `echo`es is the shape that went green, so
     each non-`ok` status needs a step calling `gh issue create/edit`;
   - *self-healing* — `ok` must `gh issue close`, because an alert only a human can
     retire becomes noise, gets muted, and a muted alert is the same
     green-that-should-be-red in reverse;
   - *persistence* — the install must be retried >= 3 times and the status written
     only AFTER the loop. Escalating on the first failure is alert fatigue, which
     is what earns the mute. Direction `>=`: raising the attempt count stays green.

   Deliberately NOT asserted: that the install-failure branch FAILS the run. It is
   a notifier, not a gate (`exit 1` daily on an upstream registry condition trains
   the owner to ignore it) — the same documented trade-off as the sibling
   `protection-drift-watch.yml`, and a product decision this guard must not police.

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
    apply_mutation,
    apply_regex_mutation,
    explicit_key_lines,
    extract_on_block,
    non_comment_lines,
    step_blocks,
    strip_inline_comment as _strip_comment,
    strip_inline_comment_sh,
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


# --- invariant 5: no terminal-silent status ---------------------------------
#
# All of these read `step_blocks()` output, which is comment-stripped and
# dash-column attributed, so a control parked behind a `#` satisfies nothing and a
# `gh issue create` in an unrelated unconditional step is never credited to a
# gated one.

MIN_INSTALL_ATTEMPTS = 3

# `echo "status=install-failed" >> "$GITHUB_OUTPUT"` in any quoting style.
_STATUS_WRITE_RE = re.compile(
    r"""status=([A-Za-z0-9_-]+)["']?\s*>>\s*["']?\$\{?GITHUB_OUTPUT"""
)
_STEP_ID_RE = re.compile(rf"""(?m)^\s+{yaml_key_pattern('id')}\s*:\s*([\w-]+)\s*$""")
_ISSUE_ALERT_RE = re.compile(r"""gh\s+issue\s+(?:create|edit)\b""")
_ISSUE_CLOSE_RE = re.compile(r"""gh\s+issue\s+close\b""")


def _sh_stripped(block):
    """A block with trailing SHELL comments dropped too. `step_blocks` removes
    whole-line comments; this also kills `true  # status=x >> $GITHUB_OUTPUT`, the
    inline form a whitespace-only stripper on a shell line would keep."""
    return "\n".join(strip_inline_comment_sh(ln) for ln in block.splitlines())


def status_producers(text):
    """{step_id: {status values it writes to $GITHUB_OUTPUT}}.

    Derived, not enumerated: a status branch added tomorrow is picked up by the
    consumer-completeness assertion without editing this guard. A producing step
    with no `id:` maps under `""`, which no consumer can reference — so it fails
    closed rather than being skipped."""
    out = {}
    for block in step_blocks(text):
        body = _sh_stripped(block)
        written = set(_STATUS_WRITE_RE.findall(body))
        if not written:
            continue
        m = _STEP_ID_RE.search(block)
        out.setdefault(m.group(1) if m else "", set()).update(written)
    return out


def status_consumers(text, step_id):
    """{status value: [step blocks referencing it]} for `steps.<step_id>.outputs.status`."""
    ref = re.compile(
        rf"""steps\.{re.escape(step_id)}\.outputs\.status\s*==\s*['"]([A-Za-z0-9_-]+)['"]"""
    )
    out = {}
    for block in step_blocks(text):
        for value in set(ref.findall(_sh_stripped(block))):
            out.setdefault(value, []).append(block)
    return out


def _retry_loop_body(run_body):
    """(iteration_count, body_text) of the `for` loop that wraps the claudesec
    install, or (0, "") when the install is not inside one.

    Enumerates ONE loop shape (`for x in a b c; do ... done`) on purpose: any other
    spelling makes this fail, which is the false-ALARM direction — the author
    updates the guard. The direction that would be a bypass (no retry at all, or a
    loop the install is not inside) fails too."""
    lines = _sh_stripped(run_body).splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*for\s+\w+\s+in\s+([^;]+);\s*do\s*$", line)
        if not m:
            continue
        depth, body = 1, []
        for nxt in lines[i + 1:]:
            s = nxt.strip()
            if re.match(r"^(?:for|while|until)\b", s):
                depth += 1
            elif s == "done":
                depth -= 1
                if depth == 0:
                    break
            body.append(nxt)
        text = "\n".join(body)
        if re.search(r"npm\s+install\s+claudesec", text):
            return len(m.group(1).split()), text
    return 0, ""


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


class TestNoTerminalSilentStatus(unittest.TestCase):
    """Invariant 5. Every status the verify step writes must reach a human."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        cls.producers = status_producers(cls.text)

    def test_exactly_one_step_produces_the_status(self):
        # Canary: everything below is scoped to this step, so a rename/move must
        # fail loudly here rather than making the rest pass vacuously.
        self.assertEqual(
            sorted(self.producers),
            ["verify"],
            "the step writing `status=` to $GITHUB_OUTPUT is no longer a single "
            f"step with `id: verify` (found {sorted(self.producers)}). Update this "
            "guard together with the workflow — an unreadable producer id means no "
            "consumer can be verified.",
        )

    def test_every_status_written_is_consumed(self):
        written = self.producers.get("verify", set())
        self.assertTrue(written, "no `status=` output found in the verify step")
        consumed = set(status_consumers(self.text, "verify"))
        orphans = sorted(written - consumed)
        self.assertEqual(
            orphans,
            [],
            f"status value(s) {orphans} are written by the verify step and read by "
            "NOTHING — a terminal-silent branch. That branch exits 0 having verified "
            "nothing, and Actions has no `neutral` conclusion for a regular job, so "
            "the monitor reports green forever (the measured `status=transient` "
            "incident). Give it a consumer step gated on "
            "`steps.verify.outputs.status == '<value>'`.",
        )

    def test_non_ok_statuses_escalate_to_an_issue(self):
        consumers = status_consumers(self.text, "verify")
        for value in sorted(self.producers.get("verify", set()) - {"ok"}):
            with self.subTest(status=value):
                self.assertTrue(
                    any(
                        _ISSUE_ALERT_RE.search(_sh_stripped(b))
                        for b in consumers.get(value, [])
                    ),
                    f"status '{value}' has a consumer but none of its steps calls "
                    "`gh issue create/edit`. An `echo`/`::warning::` alone is "
                    "invisible — that is the exact shape that reported green while "
                    "nothing was verified. Keep the self-healing `provenance-watch` "
                    "issue.",
                )

    def test_ok_status_closes_the_issue(self):
        consumers = status_consumers(self.text, "verify")
        self.assertTrue(
            any(
                _ISSUE_CLOSE_RE.search(_sh_stripped(b))
                for b in consumers.get("ok", [])
            ),
            "no step gated on `status == 'ok'` calls `gh issue close`. Without the "
            "self-healing half the alert outlives its cause, gets muted, and a muted "
            "alert is the same green-that-should-be-red this guard exists for.",
        )

    def test_install_failure_needs_persistence_not_one_attempt(self):
        verify = [b for b in step_blocks(self.text) if _STEP_ID_RE.search(b)
                  and _STEP_ID_RE.search(b).group(1) == "verify"]
        self.assertEqual(len(verify), 1, "verify step block not uniquely found")
        attempts, loop_body = _retry_loop_body(verify[0])
        self.assertGreaterEqual(
            attempts,
            MIN_INSTALL_ATTEMPTS,
            f"`npm install claudesec` is retried {attempts} time(s), below the "
            f"{MIN_INSTALL_ATTEMPTS}-attempt floor. Escalating on a single failure "
            "opens an issue for every registry blip; that is alert fatigue, and a "
            "muted alert is silence again. Raising the count is fine (direction is "
            ">=); a non-`for` retry spelling means updating this guard.",
        )
        self.assertNotRegex(
            loop_body,
            _STATUS_WRITE_RE.pattern.replace("([A-Za-z0-9_-]+)", "install-failed"),
            "the install-failure status is written INSIDE the retry loop, so the "
            "first failed attempt already escalates and the retries buy nothing.",
        )


class TestTerminalSilentStatusMutation(unittest.TestCase):
    """Non-vacuity for invariant 5, scored per assertion (probe checklist item 8):
    each mutant names the one assertion it must turn RED."""

    @classmethod
    def setUpClass(cls):
        cls.real = WORKFLOW.read_text(encoding="utf-8")

    def _run(self, mutant, method):
        cls = TestNoTerminalSilentStatus
        orig_read = WORKFLOW.read_text
        try:
            cls.text = mutant
            cls.producers = status_producers(mutant)
            # Do NOT call setUpClass here: it would reload the real file over the
            # mutant, which is how a whole audit once measured green (#297).
            getattr(cls(method), method)()
        finally:
            cls.text = orig_read(encoding="utf-8")
            cls.producers = status_producers(cls.text)

    def _assert_red(self, mutant, method, label):
        with self.assertRaises(AssertionError, msg=f"{label}: guard stayed GREEN"):
            self._run(mutant, method)

    def test_pre_fix_shape_is_detected(self):
        # The REAL pre-fix shape: `status=transient` written, only `failed` read.
        pre_fix = "\n".join(
            [
                "jobs:",
                "  verify:",
                "    steps:",
                "      - name: Install published claudesec and verify signatures",
                "        id: verify",
                "        run: |",
                "          if ! npm install claudesec@latest > install.log 2>&1; then",
                '            echo "::warning::Could not install (transient?)."',
                '            echo "status=transient" >> "$GITHUB_OUTPUT"',
                "            exit 0",
                "          fi",
                "          if npm audit signatures > sig.log 2>&1; then",
                '            echo "status=ok" >> "$GITHUB_OUTPUT"',
                "          else",
                '            echo "status=failed" >> "$GITHUB_OUTPUT"',
                "          fi",
                "      - name: Open alert issue on verification failure (idempotent)",
                "        if: steps.verify.outputs.status == 'failed'",
                "        run: gh issue create --label provenance-watch",
                "      - name: Fail the run on verification failure",
                "        if: steps.verify.outputs.status == 'failed'",
                "        run: exit 1",
            ]
        )
        self.assertEqual(
            status_producers(pre_fix), {"verify": {"transient", "ok", "failed"}}
        )
        self._assert_red(
            pre_fix, "test_every_status_written_is_consumed", "pre-fix transient orphan"
        )
        # ...and it also had no self-healing close path.
        self._assert_red(
            pre_fix, "test_ok_status_closes_the_issue", "pre-fix has no close step"
        )
        self._assert_red(
            pre_fix,
            "test_install_failure_needs_persistence_not_one_attempt",
            "pre-fix escalated on the first attempt",
        )

    def test_status_orphaned_everywhere_is_detected(self):
        # EVERY reference retargeted (count=0 = all three: the label step, the
        # lookup step and the escalation step), so `install-failed` is written and
        # read by nothing — the pre-fix condition, reproduced on today's file.
        mutant = apply_regex_mutation(
            self.real,
            r"steps\.verify\.outputs\.status == 'install-failed'",
            "steps.verify.outputs.status == 'nobody-reads-this'",
            count=0,
        )
        self._assert_red(
            mutant,
            "test_every_status_written_is_consumed",
            "all install-failed consumers retargeted",
        )

    def test_only_the_escalating_consumer_removed_is_detected(self):
        # Scored per assertion. Retargeting ONLY the escalation step leaves the
        # status *consumed* (the label + lookup steps still reference it), so
        # `test_every_status_written_is_consumed` is CORRECTLY green here — the
        # runtime consequence is "nothing opens an issue", and that is the
        # assertion that must fire. My first probe asserted the wrong one and read
        # the guard's correct green as a gap.
        mutant = apply_regex_mutation(
            self.real,
            r"if: steps\.verify\.outputs\.status == 'install-failed'",
            "if: false",
            count=1,
        )
        self._run(mutant, "test_every_status_written_is_consumed")  # still green
        self._assert_red(
            mutant,
            "test_non_ok_statuses_escalate_to_an_issue",
            "escalating consumer removed",
        )

    def test_escalation_downgraded_to_echo_is_detected(self):
        mutant = apply_mutation(
            self.real,
            'gh issue create --repo "${GITHUB_REPOSITORY}" \\\n'
            '              --title "${title}" \\\n'
            "              --label provenance-watch \\\n"
            "              --body-file /tmp/install-failed-body.md",
            'echo "would open an issue"',
        )
        mutant = apply_mutation(
            mutant,
            'gh issue edit "${EXISTING_ISSUE}" --repo "${GITHUB_REPOSITORY}" \\\n'
            '              --title "${title}" --body-file /tmp/install-failed-body.md',
            'echo "would update an issue"',
        )
        self._assert_red(
            mutant,
            "test_non_ok_statuses_escalate_to_an_issue",
            "install-failed consumer only echoes",
        )

    def test_escalation_parked_behind_a_comment_is_detected(self):
        # Anchored on `/tmp/install-failed-body.md`, which occurs only in the
        # install-failed step: `            gh issue create --repo` occurs TWICE
        # (the `failed` step has one too), and a count=1 literal replace hit the
        # WRONG step, leaving this step's escalation fully intact — the guard's
        # green was right and the probe was broken (checklist item 7).
        mutant = apply_mutation(
            self.real,
            'gh issue create --repo "${GITHUB_REPOSITORY}" \\\n'
            '              --title "${title}" \\\n'
            "              --label provenance-watch \\\n"
            "              --body-file /tmp/install-failed-body.md",
            '# gh issue create --label provenance-watch --body-file /tmp/install-failed-body.md',
        )
        mutant = apply_mutation(
            mutant,
            'gh issue edit "${EXISTING_ISSUE}" --repo "${GITHUB_REPOSITORY}" \\\n'
            '              --title "${title}" --body-file /tmp/install-failed-body.md',
            '# gh issue edit "${EXISTING_ISSUE}" --body-file /tmp/install-failed-body.md',
        )
        self._assert_red(
            mutant,
            "test_non_ok_statuses_escalate_to_an_issue",
            "inert-guard class: `#`-commented escalation",
        )

    def test_close_step_deleted_is_detected(self):
        mutant = apply_mutation(
            self.real,
            'gh issue close "${EXISTING_ISSUE}" --repo "${GITHUB_REPOSITORY}" \\\n'
            "            --reason completed",
            'echo "left open"',
        )
        self._assert_red(
            mutant, "test_ok_status_closes_the_issue", "self-healing close removed"
        )

    def test_retry_loop_shortened_is_detected(self):
        mutant = apply_mutation(self.real, "for attempt in 1 2 3; do", "for attempt in 1; do")
        self._assert_red(
            mutant,
            "test_install_failure_needs_persistence_not_one_attempt",
            "retry floor lowered to 1",
        )

    def test_escalating_inside_the_loop_is_detected(self):
        # Keeps the 3-attempt loop but writes the status on the FIRST failure.
        mutant = apply_mutation(
            self.real,
            '            echo "::warning::install attempt ${attempt}/3 of claudesec@latest failed"',
            '            echo "status=install-failed" >> "$GITHUB_OUTPUT"',
        )
        self._assert_red(
            mutant,
            "test_install_failure_needs_persistence_not_one_attempt",
            "status written inside the retry loop",
        )

    def test_real_workflow_passes_every_assertion(self):
        # Positive control: the harness above must be able to report GREEN too,
        # otherwise every RED it produced is meaningless.
        for method in (
            "test_exactly_one_step_produces_the_status",
            "test_every_status_written_is_consumed",
            "test_non_ok_statuses_escalate_to_an_issue",
            "test_ok_status_closes_the_issue",
            "test_install_failure_needs_persistence_not_one_attempt",
        ):
            with self.subTest(method=method):
                self._run(self.real, method)


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
