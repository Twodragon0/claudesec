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
    assert_disables,
    job_block,
    job_needs,
    key_column,
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
_SHA_PIN_RE = re.compile(r"ACTIONLINT_SHA256\s*:\s*([0-9a-f]{64})\b")
_VER_PIN_RE = re.compile(r"ACTIONLINT_VERSION\s*:\s*['\"]?(\d+\.\d+\.\d+)")
_SHA_VERIFY_RE = re.compile(r"sha256sum\s+-c\b")


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
    if not _SHA_VERIFY_RE.search(executed):
        problems.append(
            f"job `{JOB}` declares a sha256 but never VERIFIES it — no "
            "`sha256sum -c` runs. A digest nothing checks is decoration."
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

    def _mutate(self, old, new, label):
        self.assertIn(old, self.block, f"fixture is stale: {label}")
        mutant = self.lint.replace(
            self.block, self.block.replace(old, new, 1), 1
        )
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

    def test_dropping_the_shellcheck_assertion_is_caught(self):
        # The `echo "shellcheck: $(shellcheck --version …)"` line REMAINS, which
        # is the point: the token is still in the step, inside a command
        # substitution that is not an assertion.
        self._mutate(
            "\n          shellcheck --version >/dev/null\n",
            "\n",
            "shellcheck assertion deleted, echo left behind",
        )

    def test_dropping_the_sha_verification_is_caught(self):
        self._mutate(
            '\n          echo "${ACTIONLINT_SHA256}  /tmp/actionlint.tgz" | sha256sum -c -\n',
            "\n",
            "sha256 declared but never verified",
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
