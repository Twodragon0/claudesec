"""
Regression guard: a watcher's computed state must reach a consumer.

THE DEFECT THIS PINS
--------------------
`lychee-redirect-sweep.yml` wrote `state=error` and every downstream `if:` tested
only `findings` or `clean`. A lychee tooling blip therefore produced a
`::warning::` inside a GREEN job and nothing else — no issue, no red, no signal.
`lint.yml`'s own suppression note is what makes that expensive: the PR-time
`link-check` runs with `--accept '100..=599'`, so a 404 PASSES there by design,
and "if that sweep is ever removed OR GOES DARK, link rot has NO detector
anywhere in CI." A sweep that silently errors IS going dark.

`prowler-python-watch.yml` had the sibling shape without an output: it captured
`result_code` and never read it (shellcheck SC2034), and printed the SAME
"Still frozen" line whether it had reached a verdict or had failed to reach PyPI
at all. Two states collapsed into one, both green.

SCOPED ON PURPOSE, AND HERE IS THE MEASUREMENT
----------------------------------------------
This does NOT try to be a general dataflow analyser over every workflow. A
survey across all 17 (2026-09-03) reported four "unconsumed" states in
`npm-publish.yml` that are all FALSE POSITIVES: those outputs are re-exported at
job level (`outputs:` -> `${{ steps.v.outputs.* }}`) and consumed as
`needs.detect.outputs.*`, one of them inside a `run:` body rather than an `if:`.
Chasing that indirection generically buys false alarms, and a guard people have
to fight gets weakened rather than repaired (#414). So the state enums are
DECLARED below, per watcher, where they can be enumerated exactly.

Terminal states — written but deliberately consumed by nobody — are ALLOWLISTED
rather than exempted by a rule, so each one is a reviewed decision. That is the
discipline that would have caught the original defect: someone would have had to
write down why `error` had no consumer.

stdlib-only (`re`, `pathlib`) — no PyYAML, no `scanner/lib` import.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF PO.3.
"""

import re
import unittest
from pathlib import Path

from _ci_guard_util import step_blocks, strip_comment_lines

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

SWEEP = WORKFLOWS / "lychee-redirect-sweep.yml"
PROWLER_WATCH = WORKFLOWS / "prowler-python-watch.yml"

# (workflow path, step id, output key) whose values are a literal state enum.
STATE_ENUMS = ((SWEEP, "result", "state"),)

# Values written but deliberately unconsumed. Asserted EQUAL, not as a ceiling:
# a new terminal state fails until it is justified here, and wiring one up ALSO
# fails until it is removed. Empty today — `clean`, `findings` and `error` all
# drive a step.
ALLOWED_TERMINAL_STATES: frozenset = frozenset()

_WRITE_RE = re.compile(
    r'echo\s+"(?P<key>[a-z0-9_]+)=(?P<val>[A-Za-z0-9_.-]+)"\s*>>\s*"?\$\{?GITHUB_OUTPUT\}?"?'
)


def written_states(text, step_id, key):
    """The literal values written to `GITHUB_OUTPUT` for `key`, from any step."""
    out = set()
    for line in strip_comment_lines(text).splitlines():
        m = _WRITE_RE.search(line)
        if m and m.group("key") == key:
            out.add(m.group("val"))
    return out


def consuming_conditions(text, step_id, key):
    """Every step `if:` expression that references `steps.<step_id>.outputs.<key>`.

    Reads whole step BLOCKS rather than single lines, because a folded
    `if: >-` splits the reference and the literal across lines and a line scan
    would report a live consumer as missing — an under-read here is a FALSE
    ALARM, which is the direction that gets a guard deleted."""
    ref = f"steps.{step_id}.outputs.{key}"
    found = []
    for block in step_blocks(text):
        if "if:" not in block or ref not in block:
            continue
        found.append(" ".join(block.split()))
    return found


class TestInputsAreLocatable(unittest.TestCase):
    def test_workflows_exist(self):
        for path in (SWEEP, PROWLER_WATCH):
            self.assertTrue(path.is_file(), f"{path} not found — a path broke")

    def test_states_are_found(self):
        for path, step_id, key in STATE_ENUMS:
            states = written_states(path.read_text(encoding="utf-8"), step_id, key)
            self.assertGreaterEqual(
                len(states),
                3,
                f"{path.name}: expected the {key!r} enum to have >= 3 values, "
                f"found {sorted(states)}. A collapsed enum means every "
                "assertion below passes vacuously.",
            )

    def test_the_detector_would_notice_a_missing_consumer(self):
        """Positive control: a state nothing tests must come back unconsumed."""
        text = SWEEP.read_text(encoding="utf-8")
        self.assertEqual(
            [c for c in consuming_conditions(text, "result", "state")
             if "'nonexistent-state'" in c],
            [],
            "a value that is never written somehow matched a consumer — the "
            "matcher is too loose to prove anything",
        )


class TestEveryStateHasAConsumer(unittest.TestCase):
    def test_states_are_consumed(self):
        unconsumed = []
        for path, step_id, key in STATE_ENUMS:
            text = path.read_text(encoding="utf-8")
            conditions = consuming_conditions(text, step_id, key)
            for value in sorted(written_states(text, step_id, key)):
                entry = f"{path.name}:{step_id}.{key} == '{value}'"
                if entry in ALLOWED_TERMINAL_STATES:
                    continue
                if not any(f"'{value}'" in cond for cond in conditions):
                    unconsumed.append(entry)
        self.assertEqual(
            unconsumed,
            [],
            "watcher state(s) written but tested by no step — the watcher "
            "computes a verdict and then drops it, which reads as a green run "
            "with nothing wrong.\n  " + "\n  ".join(unconsumed) + "\nEither add "
            "a step keyed on it, or add it to ALLOWED_TERMINAL_STATES with the "
            "reason it is deliberately terminal.",
        )

    def test_allowlist_has_no_stale_entries(self):
        live = set()
        for path, step_id, key in STATE_ENUMS:
            text = path.read_text(encoding="utf-8")
            for value in written_states(text, step_id, key):
                live.add(f"{path.name}:{step_id}.{key} == '{value}'")
        stale = sorted(ALLOWED_TERMINAL_STATES - live)
        self.assertEqual(
            stale,
            [],
            f"ALLOWED_TERMINAL_STATES entries for states nothing writes: {stale}. "
            "Remove them — an allowlist that outlives its subject is how the "
            "next reader concludes the exemption is still needed.",
        )


class TestProwlerWatchDistinguishesNoVerdict(unittest.TestCase):
    """The same class without an output: two states printed as one.

    Scoped to the step's own block, because `prowler_version` and the word
    `unknown` both appear elsewhere in the file (the parse defaults) and a
    whole-file `assertIn` would pass while the BRANCH was gone — presence vs
    attribution (#504)."""

    STEP_MARKER = "Check prowler Python ceiling"

    @classmethod
    def setUpClass(cls):
        text = PROWLER_WATCH.read_text(encoding="utf-8")
        cls.block = next(
            (b for b in step_blocks(text) if cls.STEP_MARKER in b), None
        )

    def test_step_block_is_found(self):
        self.assertIsNotNone(
            self.block,
            f"step {self.STEP_MARKER!r} not found in {PROWLER_WATCH.name} — if "
            "it was renamed, update STEP_MARKER deliberately",
        )

    def test_the_captured_exit_code_is_read(self):
        """`result_code=$?` with no reader is shellcheck SC2034 and was the bug."""
        self.assertRegex(
            self.block,
            r'\$\{result_code\}|"\$result_code"|\[\s*"\$\{result_code\}"',
            "`result_code` is captured but never read. An exit code the script "
            "documents as 0 (frozen) or 2 (lifted) can then be anything at all "
            "and the watcher still reports 'Still frozen'.",
        )

    def test_no_verdict_is_distinguishable_from_still_frozen(self):
        self.assertIn(
            'prowler_version}" = "unknown"',
            self.block,
            "the step does not branch on `prowler_version = unknown`, so a run "
            "that could not reach PyPI prints the same 'Still frozen' line as a "
            "real verdict. Those are different facts and must read differently.",
        )
        self.assertIn(
            "GITHUB_STEP_SUMMARY",
            self.block,
            "the no-verdict case is not written to the step summary. A "
            "`::warning::` alone is invisible in a green run's list — the whole "
            "failure mode this branch exists to end.",
        )


class TestGuardIsNonVacuous(unittest.TestCase):
    """Mutations drive the REAL detectors against the REAL files (#504)."""

    def test_removing_the_error_arm_is_caught(self):
        text = SWEEP.read_text(encoding="utf-8")
        mutant = text.replace(
            "        if: steps.result.outputs.state == 'error'\n",
            "        if: steps.result.outputs.state == 'findings'\n",
            1,
        )
        self.assertNotEqual(mutant, text, "mutation fixture is stale")
        conditions = consuming_conditions(mutant, "result", "state")
        self.assertFalse(
            any("'error'" in c for c in conditions),
            "the mutation did NOT actually orphan the `error` state — check that "
            "possibility FIRST before assuming the guard has a gap",
        )

    def test_todays_states_are_all_consumed(self):
        """Negative control for the mutation above: unmutated, `error` IS found."""
        conditions = consuming_conditions(
            SWEEP.read_text(encoding="utf-8"), "result", "state"
        )
        self.assertTrue(
            any("'error'" in c for c in conditions),
            "no step consumes the `error` state on the real file — if the guard "
            "cannot see the arm that exists, its clean verdicts are void",
        )


if __name__ == "__main__":
    unittest.main()
