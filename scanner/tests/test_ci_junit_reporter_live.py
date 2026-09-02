"""The scanner-unit-test JUnit reporter must be configured so it can actually run.

This guards a REPORTER, not a gate — stated up front because the rest of this
suite protects enforcement. The incident that earned it: the `Publish scanner
unittest report` step printed TWO `##[error]` lines on every single run for its
entire life, including green pushes to `main`. Measured 2026-09-02 on run
33578709890, a GREEN `main` push:

    ##[error]Failed to retrieve root test suite from file (test-reports/coverage.xml)
    ##[error]Failed to create checks using the provided token.
             (HttpError: Resource not accessible by integration)

Neither was fatal, because `fail_on_parse_error` and `fail_on_failure` both
default to false. So an `##[error]` inside a green job is invisible, and the
`JUnit Test Report` check run this repo believed it published had never once
existed. Same family as everything else in this directory: a control that reads
green while doing nothing.

Two invariants:

1. `report_paths` names EXACTLY the file the pytest step writes with
   `--junitxml=`. The old value was the glob `test-reports/*.xml`, which also
   matched the Cobertura `coverage.xml` from `--cov-report=xml:` — a coverage
   report handed to a JUnit parser. Cross-referenced against the PRODUCING step
   rather than pinned as a literal, so relocating the file updates both sides or
   fails here.

2. The step does not attempt an API call the job's token cannot make. Creating a
   check run needs `checks: write`; this workflow grants `contents: read` and
   nothing else. Invariant: EITHER the job's effective `permissions` include
   `checks: write`, OR the step sets `annotate_only: true` (the action documents
   it as "will not create a check run"). Either shape is legitimate; having
   NEITHER is the regression. `test_permission_arm_is_reachable` is the positive
   control proving the first arm is live rather than dead text.

Direction: equality / presence — any change trips. If a change here is
deliberate, update this guard and record which of the two shapes in (2) you
chose and why.

Refs OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF PW.4.
"""

import re
import unittest
from pathlib import Path

from _ci_guard_util import (
    apply_mutation,
    assert_disables,
    block_ends_at,
    job_block,
    key_line,
    step_blocks,
    strip_comment_lines,
    strip_inline_comment,
    top_level_mapping,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

JOB = "scanner-unit-tests"
ACTION = "mikepenz/action-junit-report"


def _mapping_under(block, key):
    """The DIRECT scalar children of the first `key:` header in `block`.

    The job-level counterpart of `top_level_mapping`, which is column-0 only.
    Children are every line indented past the header's own column, ended by
    `block_ends_at` so a comment or blank line cannot truncate the mapping and
    hide a grant beneath it (#419's three-way bypass)."""
    lines = strip_comment_lines(block).splitlines()
    for i, line in enumerate(lines):
        parsed = key_line(line)
        if not parsed or parsed[1] != key:
            continue
        col = parsed[0]
        out = {}
        for rest in lines[i + 1:]:
            if block_ends_at(rest, col):
                break
            child = key_line(strip_inline_comment(rest))
            if child and child[0] > col:
                out[child[1]] = child[2].strip().strip("\"'")
        return out
    return None


def _scalar(block, key):
    """The value of `key` in `block`, or None. Comment-stripped, unquoted."""
    for line in strip_comment_lines(block).splitlines():
        parsed = key_line(strip_inline_comment(line))
        if parsed and parsed[1] == key:
            return parsed[2].strip().strip("\"'")
    return None


def reporter_findings(text):
    """Findings for the JUnit-reporter invariants. Empty list == invariants hold.

    A single detector rather than one per assertion, so the mutation self-tests
    below drive the EXACT function CI runs (#504: a guard whose self-tests assert
    against a re-implementation cannot notice its own scoping is missing)."""
    job = job_block(text, JOB)
    if job is None:
        return [f"job `{JOB}` not found uniquely in lint.yml — guard cannot run"]

    steps = step_blocks(job)
    reporters = [s for s in steps if ACTION in s]
    if len(reporters) != 1:
        return [
            f"expected exactly 1 `{ACTION}` step in `{JOB}`, found "
            f"{len(reporters)} — if the reporter moved or was replaced, update "
            "this guard deliberately rather than deleting it"
        ]
    reporter = reporters[0]

    producers = [s for s in steps if "--junitxml=" in s]
    if len(producers) != 1:
        return [
            f"expected exactly 1 step passing `--junitxml=` in `{JOB}`, found "
            f"{len(producers)} — cannot cross-reference `report_paths`"
        ]
    m = re.search(r"--junitxml=(\S+)", producers[0])
    produced = m.group(1).rstrip("\\").strip("\"'")

    findings = []

    declared = _scalar(reporter, "report_paths")
    if declared != produced:
        findings.append(
            f"report_paths is {declared!r} but the pytest step writes JUnit XML "
            f"to {produced!r}. A glob here also feeds the Cobertura "
            "`coverage.xml` to a JUnit parser, which prints an `##[error]` on "
            "every run. Point `report_paths` at exactly the `--junitxml=` path."
        )

    perms = _mapping_under(job, "permissions") or top_level_mapping(text, "permissions")
    has_checks_write = perms.get("checks") in ("write",)
    annotate_only = (_scalar(reporter, "annotate_only") or "").lower() == "true"
    if not has_checks_write and not annotate_only:
        findings.append(
            "the reporter will try to create a check run with a token that "
            f"cannot: effective permissions for `{JOB}` are {perms!r}, which "
            "lack `checks: write`, and the step does not set "
            "`annotate_only: true`. Pick one — grant `checks: write` (adds a new "
            "check run to every PR; the merge-wait loop in "
            "`dependabot-auto-merge.yml` has to reason about it) or keep "
            "`annotate_only: true` (annotates the current job instead)."
        )

    return findings


class TestJunitReporterLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_reporter_is_configured_to_work(self):
        self.assertEqual(reporter_findings(self.text), [])


class TestJunitReporterDetectors(unittest.TestCase):
    """Non-vacuous verification: every mutation drives `reporter_findings`."""

    @classmethod
    def setUpClass(cls):
        cls.clean = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_glob_report_paths_is_caught(self):
        """The exact historical value, which swept in `coverage.xml`."""
        assert_disables(
            reporter_findings,
            self.clean,
            apply_mutation(
                self.clean,
                "report_paths: 'test-reports/pytest-junit.xml'",
                "report_paths: 'test-reports/*.xml'",
            ),
            label="report_paths widened back to a glob",
        )

    def test_deleting_annotate_only_is_caught(self):
        assert_disables(
            reporter_findings,
            self.clean,
            apply_mutation(self.clean, "\n          annotate_only: true", ""),
            label="annotate_only deleted with no `checks: write` to replace it",
        )

    def test_flipping_annotate_only_is_caught(self):
        assert_disables(
            reporter_findings,
            self.clean,
            apply_mutation(
                self.clean, "annotate_only: true", "annotate_only: false"
            ),
            label="annotate_only turned off",
        )

    def test_permission_arm_is_reachable(self):
        """POSITIVE CONTROL for the `checks: write` arm of invariant 2.

        Without this, `test_deleting_annotate_only_is_caught` would still pass if
        the permissions arm were dead text that can never be satisfied — the
        finding would fire for the wrong reason and nobody would know. Grant
        `checks: write` AND delete `annotate_only`: the detector must go quiet.
        Absence is only evidence once you have watched the thing be present
        (probe checklist item 8)."""
        granted = apply_mutation(
            self.clean,
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\n  checks: write\n",
        )
        mutant = apply_mutation(granted, "\n          annotate_only: true", "")
        self.assertEqual(
            reporter_findings(mutant),
            [],
            "the `checks: write` arm never satisfies the invariant, so "
            "`test_deleting_annotate_only_is_caught` proves nothing about it",
        )

    def test_removing_the_reporter_step_fails_closed(self):
        assert_disables(
            reporter_findings,
            self.clean,
            apply_mutation(self.clean, ACTION, "some-other/action"),
            label="reporter action swapped out",
        )


if __name__ == "__main__":
    unittest.main()
