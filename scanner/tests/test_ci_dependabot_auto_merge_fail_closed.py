"""
Regression guard: the Dependabot auto-arm must fail CLOSED on an unknown path list.

WHAT WAS WRONG
--------------
`dependabot-auto-merge.yml` carried this comment:

    Fail-closed: if `gh` errors we emit an empty string and the eligibility
    check below will not arm auto-merge.

It was false. `changed=$(gh pr diff … 2>/dev/null || true)` yields `""`; the path
loop reads one empty line from `<<< ""`, hits `[ -z "$path" ] && continue`, and
finishes with `path_excluded=false`. Nothing is excluded. Measured 2026-09-03 by
EXECUTING the step body with a stubbed `gh`:

    CHANGED_PATHS=""  UPDATE_TYPE=version-update:semver-patch  ECOSYSTEM=docker
    -> "PR is eligible" -> gh pr merge --auto --squash          ARMED

A `docker`-ecosystem Dependabot PR touches `Dockerfile` BY DEFINITION — the first
hard-exclude in the list — so the exact case the exclude exists for was the case
that failed open, and `2>/dev/null` hid the reason.

The stakes are set by the workflow's own note: `require_code_owner_reviews=false`
and `required_approving_review_count=0`, so branch protection is the whole gate
and *"the hard-excludes above, not an approval step, are what keep sensitive
paths on human review."* Those hard-excludes were the control.

WHY THIS EXECUTES RATHER THAN INSPECTS
--------------------------------------
Every `case` arm was present and spelled correctly the entire time. A guard
asserting `Dockerfile|Dockerfile.*)` appears in the body — or that the comment
says "fail-closed" — stays green while the control is open, because the defect is
in what the loop RECEIVES, not in what it matches. ADR-001 §4 / #404: execute the
gate, do not parse it.

`gh` is stubbed to a script that logs its argv, so "did this arm auto-merge?"
is answered by whether `pr merge` was invoked — the real observable — rather than
by reading the shell.

SCOPE LIMIT, STATED RATHER THAN HIDDEN
--------------------------------------
This workflow runs on `pull_request_target` for Dependabot branches only, so CI
cannot exercise the real path on demand (there is no way to conjure a Dependabot
PR in a test). The extracted body is the same text the runner executes, and it is
run here under `bash` with the same env var names the step declares — but the
runner's own `pull_request_target` context is NOT reproduced.

stdlib-only (`os`, `re`, `subprocess`, `tempfile`, `pathlib`) — no PyYAML, no
`scanner/lib` import.

OWASP CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-4 (Poisoned Pipeline
Execution); NIST SSDF PO.3, PW.4.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _ci_guard_util import step_blocks

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependabot-auto-merge.yml"

ARM_MARKER = "gh pr merge --auto --squash"
PRODUCER_STEP = "Get changed file paths"


def _run_body(text, marker):
    """The dedented `run:` block of the step whose block contains `marker`."""
    block = next((b for b in step_blocks(text) if marker in b), None)
    if block is None:
        return None
    lines = block.splitlines()
    idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"\s*run:\s*\|\s*$", ln)), None
    )
    if idx is None:
        return None
    body = lines[idx + 1:]
    if not any(ln.strip() for ln in body):
        return None
    indent = min(len(ln) - len(ln.lstrip()) for ln in body if ln.strip())
    return "\n".join(ln[indent:] if ln.strip() else "" for ln in body) + "\n"


def eligibility_body(text):
    return _run_body(text, ARM_MARKER)


def producer_body(text):
    return _run_body(text, PRODUCER_STEP)


def arms_auto_merge(body, *, paths_known, changed_paths, update_type, ecosystem):
    """Run the eligibility body with a stubbed `gh`. Returns (armed, output).

    `armed` is whether `gh pr merge` was actually invoked — the observable the
    control exists to prevent — not a string found in the shell source."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        stub_dir = tmp / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "gh"
        stub.write_text('#!/usr/bin/env bash\necho "GH-CALL: $*"\n', encoding="utf-8")
        stub.chmod(0o755)
        script = tmp / "step.sh"
        script.write_text(body, encoding="utf-8")
        env = {
            **os.environ,
            "PATH": f"{stub_dir}:{os.environ['PATH']}",
            "PR_URL": "https://example.invalid/pr/1",
            "GH_TOKEN": "stub",
            "PATHS_KNOWN": paths_known,
            "CHANGED_PATHS": changed_paths,
            "UPDATE_TYPE": update_type,
            "ECOSYSTEM": ecosystem,
        }
        proc = subprocess.run(
            ["bash", str(script)],
            cwd=tmp, env=env, capture_output=True, text=True, timeout=60,
        )
        out = proc.stdout + proc.stderr
        return ("GH-CALL: pr merge" in out), out


# (label, paths_known, changed_paths, update_type, ecosystem, expect_armed)
CASES = (
    ("gh pr diff failed", "false", "", "version-update:semver-patch", "docker", False),
    ("known but empty", "true", "", "version-update:semver-patch", "docker", False),
    ("Dockerfile", "true", "Dockerfile", "version-update:semver-patch", "docker", False),
    (".github path", "true", ".github/workflows/lint.yml",
     "version-update:semver-patch", "pip", False),
    ("semver-major", "true", "requirements-ci.txt",
     "version-update:semver-major", "pip", False),
    # `docker` left the ecosystem allowlist on 2026-09-03. Pinned as its own case
    # because it is the ONE input whose behaviour that change altered: every
    # docker PR in this repo's history touches a hard-excluded `Dockerfile*` and
    # was already refused, but a docker PR touching only e.g. `README.md` armed
    # before and must not now. The tightening is the point — an image bump's
    # safety rested entirely on a path match, and the path match failed open.
    ("docker touching no Dockerfile", "true", "README.md",
     "version-update:semver-minor", "docker", False),
    # The no-regression case. Without it this guard would pass on a step that
    # refuses everything, which gates nothing usable.
    ("eligible pip patch", "true", "requirements-ci.txt",
     "version-update:semver-patch", "pip", True),
    ("eligible pip minor", "true", "requirements-ci.txt",
     "version-update:semver-minor", "pip", True),
)


class TestBodiesAreExtractable(unittest.TestCase):
    """Vacuity canaries — every case below is meaningless without these."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def test_workflow_exists(self):
        self.assertTrue(WORKFLOW.is_file(), f"{WORKFLOW} not found")

    def test_eligibility_body_is_found(self):
        body = eligibility_body(self.text)
        self.assertIsNotNone(body, "could not extract the eligibility `run:` block")
        self.assertIn(ARM_MARKER, body, "extracted the wrong step")

    def test_producer_body_is_found(self):
        self.assertIsNotNone(
            producer_body(self.text), f"could not extract the {PRODUCER_STEP!r} block"
        )


class TestProducerReportsWhetherPathsAreKnown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = producer_body(WORKFLOW.read_text(encoding="utf-8"))

    def test_paths_known_is_emitted(self):
        self.assertIn(
            "paths_known=", self.body,
            "the producer no longer reports whether the path list was retrieved, "
            "so the consumer cannot distinguish 'no sensitive paths' from 'no "
            "paths at all' — the original defect.",
        )

    def test_failure_is_not_swallowed(self):
        self.assertNotIn(
            "2>/dev/null", self.body,
            "`gh pr diff`'s stderr is discarded again. When this fails, the log "
            "must say why — the reason being invisible is half of what made the "
            "original defect survive.",
        )
        self.assertNotRegex(
            self.body, r"gh pr diff[^\n]*\|\|\s*true",
            "`|| true` on `gh pr diff` throws the exit status away. Branch on it "
            "instead and set `paths_known=false`.",
        )


class TestEligibilityFailsClosed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = eligibility_body(WORKFLOW.read_text(encoding="utf-8"))

    def test_every_case_behaves(self):
        for label, known, paths, utype, eco, expect in CASES:
            with self.subTest(case=label):
                armed, out = arms_auto_merge(
                    self.body, paths_known=known, changed_paths=paths,
                    update_type=utype, ecosystem=eco,
                )
                self.assertEqual(
                    armed, expect,
                    f"case {label!r}: expected armed={expect}, got {armed}.\n"
                    f"--- output ---\n{out}",
                )

    # NO ecosystem-allowlist assertion here ON PURPOSE. `test_ci_dependabot_automerge.py`
    # already pins it (`REQUIRED_TOKENS["eligible_ecosystems"]`) and has its own
    # mutation test for a widening, so a second copy would be the weak-duplicate
    # shape ADR-001 warns about: two guards at different strictness over one
    # invariant, where the narrower one rots into an inert restatement. This file
    # owns BEHAVIOUR (what the step does with a given input); that one owns the
    # allowlist TEXT. The `docker touching no Dockerfile` case above is the
    # behavioural half of the same change.

    def test_the_unknown_case_explains_itself(self):
        """Fail-closed AND visible. Silence here is the class, one step over."""
        _, out = arms_auto_merge(
            self.body, paths_known="false", changed_paths="",
            update_type="version-update:semver-patch", ecosystem="docker",
        )
        self.assertIn(
            "GH-CALL: pr comment", out,
            "the PR is left with no explanation of why auto-merge was not armed",
        )


class TestGuardIsNonVacuous(unittest.TestCase):
    """Restore the defect and confirm this guard goes red.

    Both gates are anchored to the DEDENTED body (`eligibility_body` strips the
    YAML indent), so `fi` sits at column 0. The first draft matched the indented
    form, found nothing, and `assertEqual(n, 1)` refused to proceed rather than
    reporting a clean guard — the stale-anchor discipline working."""

    # `(?m)^…$` with re.S so `.*?` spans lines but the anchors stay line-bound.
    PATHS_KNOWN_GATE = (
        r'(?m)^if \[ "\$\{PATHS_KNOWN:-false\}" != "true" \]; then$.*?^fi$\n'
    )
    EMPTY_LIST_GATE = r'(?m)^if \[ "\$path_count" -eq 0 \]; then$.*?^fi$\n'

    # `pip`, not `docker`. The shipped defect was observed on a docker PR, but
    # `docker` left the ecosystem allowlist on 2026-09-03, so a docker input is
    # now refused at the ecosystem arm BEFORE either path gate is reached — the
    # mutation would look "caught" while proving nothing about the gates. The
    # guard caught that stale fixture itself ("stripping both gates did NOT
    # re-open the hole. Check that FIRST"), which is the same lesson one turn
    # later: a fix moves the terrain, so re-attack the new version on its own
    # terms rather than replaying the old input.
    UNKNOWN_INPUT = dict(
        paths_known="false", changed_paths="",
        update_type="version-update:semver-patch", ecosystem="pip",
    )

    @classmethod
    def setUpClass(cls):
        cls.body = eligibility_body(WORKFLOW.read_text(encoding="utf-8"))

    def _strip(self, body, pattern, label):
        mutant, n = re.subn(pattern, "", body, count=1, flags=re.S)
        self.assertEqual(n, 1, f"mutation fixture is stale: no {label} found")
        return mutant

    def test_the_real_body_does_not_arm_on_an_unknown_path_list(self):
        """Negative control. Without it the mutations below prove nothing."""
        armed, out = arms_auto_merge(self.body, **self.UNKNOWN_INPUT)
        self.assertFalse(armed, f"the real body arms on an unknown list\n{out}")

    def test_removing_BOTH_gates_rearms_the_original_hole(self):
        """This is the shipped defect, reconstructed.

        Removing only one gate does NOT reproduce it — see the two tests below.
        That is defence in depth, not a failed mutation, and it is why this case
        strips both rather than reporting a bypass that does not exist."""
        mutant = self._strip(self.body, self.PATHS_KNOWN_GATE, "PATHS_KNOWN gate")
        mutant = self._strip(mutant, self.EMPTY_LIST_GATE, "empty-list gate")
        armed, out = arms_auto_merge(mutant, **self.UNKNOWN_INPUT)
        self.assertTrue(
            armed,
            "stripping both gates did NOT re-open the hole, so this case proves "
            f"nothing about the guard. Check that FIRST.\n--- output ---\n{out}",
        )

    def test_the_empty_list_gate_alone_still_refuses(self):
        """Measured, not assumed: each gate independently covers this input."""
        mutant = self._strip(self.body, self.PATHS_KNOWN_GATE, "PATHS_KNOWN gate")
        armed, out = arms_auto_merge(mutant, **self.UNKNOWN_INPUT)
        self.assertFalse(armed, f"expected the empty-list gate to hold\n{out}")

    def test_the_paths_known_gate_alone_still_refuses(self):
        mutant = self._strip(self.body, self.EMPTY_LIST_GATE, "empty-list gate")
        armed, out = arms_auto_merge(mutant, **self.UNKNOWN_INPUT)
        self.assertFalse(armed, f"expected the PATHS_KNOWN gate to hold\n{out}")


if __name__ == "__main__":
    unittest.main()
