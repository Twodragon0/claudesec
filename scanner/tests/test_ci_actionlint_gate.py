#!/usr/bin/env python3
"""Regression guard: `actionlint` is a CI GATE, not a manual pre-PR habit.

actionlint used to be a manual step. Every PR body in this repo records
`actionlint … rc=0`, but `grep -rn actionlint .github/workflows/*.yml` returned
nothing — so the claim rested on whoever opened the PR having run it. Measured
when this guard was written: `actionlint` exited **1** on `main`, on a SC2129 in
`prowler-python-watch.yml` that had been there for weeks with every PR body
claiming a clean run.

It became load-bearing when the round-2 review of #468 could not settle whether
the exotic YAML key shapes it found were loadable by Actions at all: the closest
available oracle was a tool CI did not run.

Three things are pinned, and the SECOND is the one worth explaining:

1. a step EXECUTES actionlint — not merely installs it;
2. `shellcheck` is asserted BEFORE that. actionlint runs its shellcheck-backed
   rules only when `shellcheck` is on PATH and SILENTLY SKIPS them otherwise,
   exiting 0 either way. A runner-image change that dropped shellcheck would
   halve this gate with no signal — the same "premise wrong, reads as working"
   shape as the dead kcov detection in #466;
3. the binary is pinned by VERSION and verified by SHA256. A linter fetched over
   the network is exactly where a mutable ref hurts (OWASP CICD-SEC-3,
   "Dependency Chain Abuse").

Plus the two ways a job goes quiet regardless of what it runs: the wrong path
bucket, and absence from the required aggregator.

EVERYTHING READS EXECUTED SHELL, via `test_ci_reachability.executed_shell`.
The step's own explanation NAMES `actionlint` and `shellcheck` several times, so
matching the raw block would make "the invocation was deleted" indistinguishable
from "the invocation is present" — the presence-vs-attribution class this repo
has paid for repeatedly (#440, and twice inside `test_ci_guard_self_verify`).
`executed_shell` is IMPORTED rather than re-derived: it already handles both
`run:` spellings, strips YAML and bash comments, consumes and discards a block
scalar belonging to any other key, and credits `run:` only at the step's own
column. Writing a fresh extractor instead of importing that one is a mistake
this repo's own docs record making twice.

Stdlib only, no PyYAML: this runs in `ci-guards`, which installs nothing.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ci_guard_util import (  # noqa: E402
    apply_live_mutation,
    assert_disables,
    job_block,
    job_needs,
    key_column,
    strip_comment_lines,
    strip_inline_comment,
    yaml_key_pattern,
)
from test_ci_reachability import executed_shell  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

JOB = "actionlint"
CHANGES_JOB = "changes"
GATE_JOB = "lint-gate"
BUCKET = "ci_config"

#: `shellcheck` in COMMAND POSITION — start of line, or after a separator.
#: `(` is deliberately ABSENT from the class: the step echoes the version via
#: `$(shellcheck --version | awk …)`, and a command substitution inside an
#: `echo` is not the fail-closed assertion. With `(` admitted, deleting the real
#: assertion left that echo satisfying this check — measured on the first draft
#: of this guard, in the branch it was recovered from.
_SHELLCHECK_ASSERT_RE = re.compile(r"(?:^|[;&|])[ \t]*shellcheck\b", re.M)
#: The invocation itself, anchored so a path argument cannot narrow it: the step
#: relies on actionlint discovering every workflow, which is what makes a NEW
#: workflow covered the day it lands.
_INVOKE_RE = re.compile(r"^\s*/tmp/actionlint\s*$", re.M)
#: The SECOND pass. actionlint SUPPRESSES SC2154 ("referenced but not assigned")
#: in its default shellcheck pass, and that suppression cost this repo a broken
#: scheduled workflow — #539 deleted a `result_code=` capture whose only reader
#: was further down the same `run:` body, `set -u` aborted the step on the
#: ordinary path, plain `shellcheck` reported it, and `actionlint` exited 0.
#: Pinned because it is one line away from deletion and its absence is silent.
_SC2154_PASS_RE = re.compile(
    r'^\s*SHELLCHECK_OPTS="--include=SC2154"\s+/tmp/actionlint\s*$', re.M
)
#: EVERY env pin below is LINE-ANCHORED, and the block they are searched in is
#: comment-stripped first. Unanchored, all four were satisfiable by a COMMENT —
#: measured, each of `ACTIONLINT_VERSION`, `ACTIONLINT_SHA256`,
#: `SHELLCHECK_VERSION` and `SHELLCHECK_SHA256` left this function returning `[]`
#: when the pin survived only as `# NAME: value`. The sharp case is not even
#: fail-closed: put `SHELLCHECK_VERSION: 0.9.0` live and `# … 0.11.0` above it,
#: and the parity check reads the COMMENT, reports agreement, and the job
#: happily installs and asserts 0.9.0 — restoring the exact asymmetry the pin
#: exists to close. `_ACTION_SHELLCHECK_VER_RE` was the only one already
#: anchored (`^\s*version:`), and it was the only one that survived the sweep.
_SHA_PIN_RE = re.compile(r"^\s*ACTIONLINT_SHA256\s*:\s*([0-9a-f]{64})\b", re.M)
#: The shellcheck this job installs, and the one `shell-lint` hands the pinned
#: action. ONE SPEC IN TWO FILES, so they are compared as data below — the
#: `ADJUDICATORS`/`CANARY_CLASSES` idiom. They were NOT equal before this pin:
#: measured on the first run of the actionlint job, `ubuntu-latest` shipped
#: shellcheck 0.9.0 while `shell-lint` pinned v0.11.0, so any rule added in
#: 0.10/0.11 was enforced on `.sh` files and silently absent from workflow
#: `run:` bodies.
_SC_VER_RE = re.compile(
    r"^\s*SHELLCHECK_VERSION\s*:\s*['\"]?(\d+\.\d+(?:\.\d+)?)", re.M
)
_SC_SHA_RE = re.compile(r"^\s*SHELLCHECK_SHA256\s*:\s*([0-9a-f]{64})\b", re.M)
#: THE WHOLE LINE, both ends. As a bare `re.search` this accepted
#: `… grep -qx "version: ${SHELLCHECK_VERSION}" || true` — measured: the
#: assertion is then a no-op, and combined with an `export PATH` that APPENDS
#: instead of prepending, the job silently lints with the runner image's
#: shellcheck while every check here stays quiet. Either half alone is
#: fail-closed; together they are not.
_SC_VERSION_ASSERT_RE = re.compile(
    r'^\s*shellcheck --version \| grep -qx "version: \$\{SHELLCHECK_VERSION\}"\s*$',
    re.M,
)
SHELL_LINT_JOB = "shell-lint"
_ACTION_SHELLCHECK_VER_RE = re.compile(
    r"ludeeus/action-shellcheck@[0-9a-f]+.*?^\s*version:\s*v?(\d+\.\d+(?:\.\d+)?)",
    re.S | re.M,
)
_VER_PIN_RE = re.compile(
    r"^\s*ACTIONLINT_VERSION\s*:\s*['\"]?(\d+\.\d+\.\d+)", re.M
)
#: PER ARTIFACT, not "a `sha256sum -c` appears somewhere". Once this step
#: verified TWO downloads, a single bare check let either verification stand
#: in for the other's absence — measured: deleting the actionlint one left
#: the detector quiet because shellcheck's was still there.
_SHA_VERIFY_RES = {
    "actionlint": re.compile(
        r'echo "\$\{ACTIONLINT_SHA256\}\s+/tmp/actionlint\.tgz"\s*\|\s*sha256sum -c'
    ),
    "shellcheck": re.compile(
        r'echo "\$\{SHELLCHECK_SHA256\}\s+/tmp/shellcheck\.tar\.xz"\s*\|\s*sha256sum -c'
    ),
}


def actionlint_gate_problems(lint_text: str) -> list:
    """Everything wrong with how `lint.yml` enforces actionlint."""
    problems = []
    block = job_block(lint_text, JOB)
    if block is None:
        return [
            f"job `{JOB}` not found in lint.yml. actionlint is then a manual "
            "habit again, and a habit is not a gate."
        ]

    # The gate, read at the job's DERIVED key column with inline comments
    # stripped, and matched on the FULL `needs.<job>.outputs.<name> == 'true'`
    # rather than the bare bucket name — the substring form was defeated three
    # ways on the sibling jobs (inverted, ANDed with another bucket, surviving
    # only in a comment).
    col = key_column(block)
    gate = None
    if col is not None:
        pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern('if')}\s*:(?P<rest>.*)$")
        for raw in block.splitlines():
            m = pat.match(strip_inline_comment(raw))
            if m:
                gate = m.group("rest").strip()
                break
    if gate is None:
        problems.append(f"job `{JOB}` has no job-level `if:` gate")
    elif f"needs.{CHANGES_JOB}.outputs.{BUCKET} == 'true'" not in gate:
        problems.append(
            f"job `{JOB}` is gated on `if: {gate}`, which does not read "
            f"`needs.{CHANGES_JOB}.outputs.{BUCKET} == 'true'`. `{BUCKET}` is "
            "the bucket that matches `.github/**`; gated on `shell` this job "
            "would SKIP on a workflow-only PR — a linter dark on exactly the "
            "changes it lints, which is the class that left pip-audit (#392) "
            "and npm-audit (#394) reading green while running never."
        )

    executed = executed_shell(block)

    if not _INVOKE_RE.search(executed):
        problems.append(
            f"job `{JOB}` does not EXECUTE a bare `/tmp/actionlint`. Installing "
            "the binary is not running it, and a path argument would pin the "
            "scan to a list that a new workflow is not on."
        )

    if not _SC2154_PASS_RE.search(executed):
        problems.append(
            f"job `{JOB}` does not run the SC2154 pass "
            '(`SHELLCHECK_OPTS="--include=SC2154" /tmp/actionlint`). actionlint '
            "suppresses that code by default, so a variable read but never "
            "assigned passes the first pass and kills the step at runtime under "
            "`set -u` — which is how #539 broke `prowler-python-watch`. It must "
            "be a SECOND invocation: `--include` is exclusive, so folding it "
            "into the first would disable every other rule."
        )

    # `SHELLCHECK_OPTS` MAY APPEAR ONLY ON THE SC2154 LINE. Read from the
    # comment-stripped BLOCK rather than the executed shell, because the
    # narrowing that matters is not a shell line at all: an `env:` entry applies
    # to BOTH invocations and, since `--include` is exclusive, reduces the
    # default pass to SC2154 only — every other rule off, nothing in any `run:`
    # changed, and a reader of executed shell alone sees no difference.
    # SCOPE: the job block AND the workflow preamble. A `SHELLCHECK_OPTS` at
    # WORKFLOW level applies to every job including this one, and it sits
    # outside `job_block` — measured, the whole file scanned only per-job left
    # this function returning `[]` while the default pass was reduced to SC2154
    # alone. `shell-lint`'s own `SHELLCHECK_OPTS: -x` is deliberately NOT in
    # scope: it is step-scoped there and cannot reach this job, and flagging it
    # would be a false alarm on a legitimate setting.
    preamble = lint_text.split("\njobs:\n", 1)[0]
    stray = [
        ln.strip()
        for ln in strip_comment_lines(preamble + "\n" + block).splitlines()
        if "SHELLCHECK_OPTS" in ln and not _SC2154_PASS_RE.match(ln)
    ]
    if stray:
        problems.append(
            f"job `{JOB}` sets `SHELLCHECK_OPTS` somewhere other than the "
            f"SC2154 pass: {stray}. `--include` is exclusive, so anything that "
            "reaches the first invocation turns every other shellcheck rule off "
            "while leaving the run body unchanged."
        )

    assertion = _SHELLCHECK_ASSERT_RE.search(executed)
    if assertion is None:
        problems.append(
            f"job `{JOB}` does not assert `shellcheck` in command position. "
            "actionlint runs its shellcheck-backed rules ONLY when shellcheck "
            "is on PATH and silently skips them otherwise, exiting 0 either "
            "way — so without this the gate can halve itself with no signal."
        )
    else:
        invocation = _INVOKE_RE.search(executed)
        if invocation and assertion.start() > invocation.start():
            problems.append(
                f"job `{JOB}` asserts `shellcheck` AFTER running actionlint. "
                "The run it is meant to qualify has already happened."
            )

    if not _VER_PIN_RE.search(block):
        problems.append(
            f"job `{JOB}` does not pin `ACTIONLINT_VERSION` to an exact "
            "version. A floating release changes the gate between runs."
        )
    if not _SHA_PIN_RE.search(block):
        problems.append(
            f"job `{JOB}` does not pin `ACTIONLINT_SHA256`. A linter fetched "
            "over the network with no digest is the mutable-ref case OWASP "
            "CICD-SEC-3 names."
        )
    unverified = sorted(
        name for name, rx in _SHA_VERIFY_RES.items() if not rx.search(executed)
    )
    if unverified:
        problems.append(
            f"job `{JOB}` declares a sha256 for {unverified} but never VERIFIES "
            "it against that artifact. A digest nothing checks is decoration, "
            "and with two downloads in one step a single bare `sha256sum -c` "
            "lets one verification stand in for the other's absence."
        )

    # SHELLCHECK, PINNED AND EQUAL TO THE OTHER JOB'S PIN. Not "a shellcheck is
    # present": the runner image's copy was 0.9.0 while `shell-lint` pinned
    # v0.11.0, so the same repo linted `.sh` files and workflow `run:` bodies
    # with different rule sets and nothing said so.
    sc_ver = _SC_VER_RE.search(block)
    if sc_ver is None:
        problems.append(
            f"job `{JOB}` does not pin `SHELLCHECK_VERSION`. It would then lint "
            "with whatever the runner image ships, which is free to change and "
            "is not the version `shell-lint` enforces."
        )
    if not _SC_SHA_RE.search(block):
        problems.append(
            f"job `{JOB}` does not pin `SHELLCHECK_SHA256` for the binary it "
            "downloads — the mutable-ref case OWASP CICD-SEC-3 names."
        )
    if not _SC_VERSION_ASSERT_RE.search(executed):
        problems.append(
            f"job `{JOB}` does not ASSERT the installed shellcheck version "
            "(anchored `grep -qx`). Downloading a pinned archive and then "
            "linting with whatever is first on PATH is a pin that pins nothing."
        )

    shell_lint = job_block(lint_text, SHELL_LINT_JOB)
    if shell_lint is None:
        problems.append(
            f"job `{SHELL_LINT_JOB}` not found, so the version this job pins "
            "cannot be compared against the one it is supposed to match."
        )
    elif sc_ver is not None:
        other = _ACTION_SHELLCHECK_VER_RE.search(shell_lint)
        if other is None:
            problems.append(
                f"`{SHELL_LINT_JOB}` no longer passes a `version:` to "
                "`ludeeus/action-shellcheck`, so the two pins cannot be "
                "compared and one of them is now unconstrained."
            )
        elif other.group(1) != sc_ver.group(1):
            problems.append(
                f"shellcheck version drift: `{JOB}` installs "
                f"{sc_ver.group(1)} but `{SHELL_LINT_JOB}` pins "
                f"{other.group(1)}. One spec in two files; whichever is stale, "
                "the two jobs are enforcing different rule sets and neither "
                "says so."
            )

    gate_block = job_block(lint_text, GATE_JOB)
    if gate_block is None:
        problems.append(f"aggregator job `{GATE_JOB}` not found")
    elif JOB not in job_needs(gate_block):
        problems.append(
            f"`{GATE_JOB}` does not list `{JOB}` in `needs:`. Only `Lint` is a "
            "required context, so this job could go red while the merge stays "
            "green."
        )
    return problems


class TestActionlintIsAGate(unittest.TestCase):
    def setUp(self):
        self.assertTrue(LINT_YML.is_file(), LINT_YML)
        self.lint = LINT_YML.read_text(encoding="utf-8")

    def test_actionlint_is_a_gate_not_a_manual_step(self):
        self.assertEqual(actionlint_gate_problems(self.lint), [])


class TestTheActionlintGuardIsNonVacuous(unittest.TestCase):
    """Each direction MUTATES the real file, so a detector that never fires
    fails here rather than reading green alongside the control."""

    def setUp(self):
        self.lint = LINT_YML.read_text(encoding="utf-8")
        self.block = job_block(self.lint, JOB)
        self.assertIsNotNone(self.block, "fixture is stale — the job moved")

    def _mutate(self, old, new, label, *, expect_live=1):
        """LIVE lines only. This step is the worst case for a bare
        `str.replace`: its explanation quotes almost every command it runs, and
        the comment comes FIRST. `apply_live_mutation` raises on a comment-only
        hit instead of editing prose and proving nothing — the failure that,
        measured twice elsewhere in this suite, read as "the detector is
        broken"."""
        mutated_block = apply_live_mutation(
            self.block, old, new, syntax="sh", expect_live=expect_live
        )
        mutant = self.lint.replace(self.block, mutated_block, 1)
        self.assertNotEqual(mutant, self.lint, f"mutation did not apply: {label}")
        return assert_disables(actionlint_gate_problems, self.lint, mutant, label)

    def test_removing_the_invocation_is_caught(self):
        self._mutate("\n          /tmp/actionlint\n", "\n", "invocation deleted")

    def test_commenting_out_the_invocation_is_not_execution(self):
        # The step's prose names `actionlint` a dozen times, so a raw-text
        # scanner cannot tell this from the real thing.
        self._mutate(
            "\n          /tmp/actionlint\n",
            "\n          # /tmp/actionlint\n",
            "invocation commented out",
        )

    def test_narrowing_the_invocation_to_a_path_is_caught(self):
        self._mutate(
            "\n          /tmp/actionlint\n",
            "\n          /tmp/actionlint .github/workflows/lint.yml\n",
            "invocation narrowed to one file",
        )

    def test_dropping_the_sc2154_pass_is_caught(self):
        self._mutate(
            '\n          SHELLCHECK_OPTS="--include=SC2154" /tmp/actionlint\n',
            "\n",
            "SC2154 pass deleted",
        )

    def test_hoisting_shellcheck_opts_to_env_is_caught(self):
        # The narrowing that is NOT a deleted line. `--include` is EXCLUSIVE, so
        # a `SHELLCHECK_OPTS` at env level applies to BOTH invocations and
        # reduces the first pass to SC2154 only — measured: the default pass
        # then reports nothing else, including the SC2129 that was this gate's
        # first real finding. Nothing in the `run:` body changes, so a check
        # that reads only the executed shell cannot see it.
        self._mutate(
            "          ACTIONLINT_VERSION: 1.7.12\n",
            '          SHELLCHECK_OPTS: "--include=SC2154"\n'
            "          ACTIONLINT_VERSION: 1.7.12\n",
            "SHELLCHECK_OPTS hoisted to env",
        )

    def test_dropping_the_sha_verification_is_caught(self):
        self._mutate(
            '\n          echo "${ACTIONLINT_SHA256}  /tmp/actionlint.tgz" | sha256sum -c -\n',
            "\n",
            "sha256 declared but never verified",
        )

    def test_shellcheck_version_drift_between_the_two_jobs_is_caught(self):
        # Mutated on the ACTIONLINT side so `shell-lint`'s pin — the one the
        # repo has enforced for longer — stays the reference.
        self._mutate(
            "          SHELLCHECK_VERSION: 0.11.0\n",
            "          SHELLCHECK_VERSION: 0.9.0\n",
            "shellcheck pins drift apart",
        )

    def test_dropping_the_shellcheck_version_assertion_is_caught(self):
        """Downloading a pinned archive and then linting with whatever is first
        on PATH is a pin that pins nothing — and the `export PATH` line stays,
        so the step still LOOKS like it installed something.

        This also covers the command-position check: the
        `echo "shellcheck: $(shellcheck --version …)"` line REMAINS after the
        mutation, so the token is still in the step, inside a command
        substitution that is not an assertion. `(` is excluded from the
        command-position class precisely so that echo cannot stand in."""
        self._mutate(
            '\n          shellcheck --version | grep -qx "version: ${SHELLCHECK_VERSION}"\n',
            "\n",
            "installed version never asserted",
        )

    def test_dropping_the_shellcheck_sha_pin_is_caught(self):
        self._mutate(
            "          SHELLCHECK_SHA256: 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198\n",
            "",
            "shellcheck binary unpinned",
        )

    def test_every_env_pin_parked_in_a_comment_is_caught(self):
        """Presence vs attribution, for the sixth time in this series.

        All four pins were unanchored `re.search` over the RAW block, so each
        was satisfiable by a `# NAME: value` comment. The sharp case is not even
        fail-closed: `SHELLCHECK_VERSION: 0.9.0` live with `# … 0.11.0` above it
        made the parity check read the COMMENT and report agreement, while the
        job installed and asserted 0.9.0 — the exact asymmetry the pin exists to
        close, restored with every check green."""
        for name, live in (
            ("ACTIONLINT_VERSION", "          ACTIONLINT_VERSION: 1.7.12\n"),
            (
                "ACTIONLINT_SHA256",
                "          ACTIONLINT_SHA256: "
                "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8\n",
            ),
            ("SHELLCHECK_VERSION", "          SHELLCHECK_VERSION: 0.11.0\n"),
            (
                "SHELLCHECK_SHA256",
                "          SHELLCHECK_SHA256: "
                "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198\n",
            ),
        ):
            with self.subTest(pin=name):
                self._mutate(live, "          # " + live.strip() + "\n", f"{name} comment-only")

    def test_a_live_pin_shadowed_by_a_comment_is_read_from_the_LIVE_line(self):
        """The fail-OPEN half, kept separate because it is the dangerous one.

        A comment claiming the right version above a live line carrying the
        wrong one must read as DRIFT, not as agreement."""
        self._mutate(
            "          SHELLCHECK_VERSION: 0.11.0\n",
            "          # SHELLCHECK_VERSION: 0.11.0\n          SHELLCHECK_VERSION: 0.9.0\n",
            "comment claims parity, live line drifts",
        )

    def test_neutering_the_version_assertion_with_or_true_is_caught(self):
        """`|| true` makes the assertion a no-op while leaving every token in
        place. Fail-closed on its own — the pinned binary is still first on
        PATH — but combined with an `export PATH` that APPENDS, the job lints
        with the runner image's copy and nothing says so."""
        self._mutate(
            'grep -qx "version: ${SHELLCHECK_VERSION}"\n',
            'grep -qx "version: ${SHELLCHECK_VERSION}" || true\n',
            "assertion neutered with || true",
        )

    def test_a_workflow_level_shellcheck_opts_is_caught(self):
        """Outside the job block entirely, so a per-job scan cannot see it —
        and workflow-level `env:` reaches every job. Since `--include` is
        exclusive it would reduce the default pass to SC2154 alone."""
        mutant = self.lint.replace(
            "\njobs:\n", '\nenv:\n  SHELLCHECK_OPTS: "--include=SC2154"\n\njobs:\n', 1
        )
        self.assertNotEqual(mutant, self.lint, "fixture is stale — `jobs:` moved")
        assert_disables(
            actionlint_gate_problems, self.lint, mutant, "workflow-level SHELLCHECK_OPTS"
        )

    def test_dropping_the_version_pin_is_caught(self):
        self._mutate(
            "          ACTIONLINT_VERSION: 1.7.12\n",
            "          ACTIONLINT_VERSION: latest\n",
            "version pin floated",
        )

    def test_rewiring_the_gate_to_another_bucket_is_caught(self):
        self._mutate(
            f"needs.{CHANGES_JOB}.outputs.{BUCKET} == 'true'",
            f"needs.{CHANGES_JOB}.outputs.shell == 'true'",
            "gated on a bucket that does not match .github/**",
        )

    def test_removing_the_job_from_the_aggregator_is_caught(self):
        mutant = self.lint.replace(
            "      - ci-guards\n      - renderer-canary\n      - actionlint\n",
            "      - ci-guards\n      - renderer-canary\n",
            1,
        )
        self.assertNotEqual(mutant, self.lint, "fixture is stale — needs: moved")
        assert_disables(
            actionlint_gate_problems, self.lint, mutant, "dropped from lint-gate"
        )

    def test_renaming_the_job_fails_closed(self):
        mutant = self.lint.replace(f"\n  {JOB}:\n", "\n  workflow-lint:\n", 1)
        self.assertNotEqual(mutant, self.lint, "fixture is stale — job key moved")
        assert_disables(
            actionlint_gate_problems, self.lint, mutant, "job renamed"
        )


if __name__ == "__main__":
    unittest.main()
