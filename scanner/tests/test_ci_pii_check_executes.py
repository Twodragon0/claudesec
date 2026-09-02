"""
Regression guard: the `pii-check` step must actually RUN `hooks/pii-check.sh`.

WHY THIS EXECUTES INSTEAD OF INSPECTING
---------------------------------------
`lint.yml`'s PII step scanned NOTHING from 2026-08-26 (#496) to 2026-09-02, on a
job `lint-gate` requires, and reported success every time. A `#` comment sat
between two `\\`-continued `find` lines. Bash removes `\\`+newline BEFORE
tokenizing, so the `#` opened a comment on the JOINED line and terminated
`find`; `-print0 | xargs -0 -r bash hooks/pii-check.sh` became a separate
command whose first word is `-print0`. Measured on run 33596066956, a GREEN push
to `main`: `line 10: -print0: command not found`, raw `find` output in the log,
hook never invoked. It exited 0 because the default `run:` shell is `bash -e {0}`
with no pipefail: 127 in the left half of a pipe, `xargs -0 -r` sees EOF and
declines, pipeline status is the right half's 0.

Every config-shape assertion available stayed green, and one existed:
`test_ci_required_jobs_exist.py` asserts the JOB EXISTS, not that its body
invokes the hook — presence vs attribution, one level up from #504. A guard that
checked "the body contains `hooks/pii-check.sh`" would ALSO have stayed green,
because the string is right there, in a command that never runs. So this guard
runs the real block and checks the hook's own output.

WHAT IS ASSERTED, AND WHY BOTH DIRECTIONS ARE NEEDED
----------------------------------------------------
1. Against a tree containing a PII pattern: the block exits NON-ZERO **and** the
   hook's own verdict line appears. Exit status alone is not enough — once the
   block carries `set -euo pipefail`, the broken version ALSO exits non-zero
   (127), so a status-only assertion would pass on the very regression this
   guard exists to catch. The hook's output is the only proof it ran.
2. Against a clean tree: the block exits ZERO. Without this, a block that failed
   unconditionally would satisfy (1) while gating nothing usable.

The fixture's PII pattern is ASSEMBLED AT RUNTIME and written to a tmpdir, never
committed: a checked-in `/Users/<name>/` fixture would be flagged by this very
hook and by the repo's push-protection ruleset
([[project-github-push-protection-fixtures]]).

stdlib-only (`re`, `shutil`, `subprocess`, `tempfile`, `pathlib`) — no PyYAML.
Does not import `scanner/lib`, so it does not affect the 99% coverage gate.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF PW.7. Executing the gate
rather than parsing it is ADR-001 §4 (#404).
"""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
HOOK = REPO_ROOT / "hooks" / "pii-check.sh"

STEP_NAME = "Check for PII and personal information"
# The hook's own verdict line (hooks/pii-check.sh). Its presence is the only
# evidence the hook executed; `find`/`xargs` never print it.
HOOK_VERDICT = "PII issue(s) detected"


def pii_step_body(text):
    """The shell body of the PII step's `run: |` block, dedented.

    Bounded by indentation: the block ends at the first later non-blank line
    indented at or left of the `run:` key. Comment lines are deliberately KEPT —
    they are the subject here, and stripping them would delete the exact defect
    this guard reproduces."""
    lines = text.splitlines()
    name_re = re.compile(rf"^(\s*)-\s+name:\s*{re.escape(STEP_NAME)}\s*$")
    start = None
    for i, line in enumerate(lines):
        if name_re.match(line):
            start = i
            break
    if start is None:
        return None

    run_re = re.compile(r"^(\s*)run:\s*\|\s*$")
    run_col = None
    body = []
    for line in lines[start + 1:]:
        if run_col is None:
            m = run_re.match(line)
            if m:
                run_col = len(m.group(1))
                continue
            # A following step began before any `run: |` — fail closed.
            if re.match(r"^\s*-\s+name:", line):
                return None
            continue
        if line.strip() and (len(line) - len(line.lstrip())) <= run_col:
            break
        body.append(line)

    while body and not body[-1].strip():
        body.pop()
    if not body:
        return None
    indent = min(len(ln) - len(ln.lstrip()) for ln in body if ln.strip())
    return "\n".join(ln[indent:] if ln.strip() else "" for ln in body) + "\n"


def run_body(body, *, with_pii):
    """Run `body` in a throwaway tree. Returns (returncode, combined output).

    `bash -e` and nothing else, because that is EXACTLY GitHub's default `run:`
    shell (`shell: /usr/bin/bash -e {0}`, visible in the run log). Adding
    pipefail here would hide the very status-masking that made the defect
    invisible."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / "hooks").mkdir()
        shutil.copy2(HOOK, tmp / "hooks" / "pii-check.sh")
        (tmp / "clean.py").write_text("VALUE = 'nothing sensitive'\n", encoding="utf-8")
        if with_pii:
            # Assembled, never a literal in this file — see the module docstring.
            marker = "/" + "Users" + "/probeuser/"
            (tmp / "planted.py").write_text(
                f"CONFIG_PATH = '{marker}notes'\n", encoding="utf-8"
            )
        script = tmp / "step.sh"
        script.write_text(body, encoding="utf-8")
        proc = subprocess.run(
            ["bash", "-e", str(script)],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode, proc.stdout + proc.stderr


class TestPiiStepIsLocatable(unittest.TestCase):
    """Vacuity canaries — every assertion below is meaningless without these."""

    def test_inputs_exist(self):
        for path in (LINT_YML, HOOK):
            self.assertTrue(path.is_file(), f"{path} not found — a path broke")

    def test_step_body_is_extractable(self):
        body = pii_step_body(LINT_YML.read_text(encoding="utf-8"))
        self.assertIsNotNone(
            body,
            f"could not extract the `run:` block of step {STEP_NAME!r} from "
            "lint.yml. If the step was renamed, update STEP_NAME deliberately "
            "rather than deleting this guard.",
        )
        self.assertIn(
            "hooks/pii-check.sh",
            body,
            "the extracted block does not even mention the hook — the extractor "
            "is reading the wrong step",
        )

    def test_hook_itself_detects_the_fixture(self):
        """Positive control on the HOOK, separate from the step body.

        If the hook stopped detecting the planted pattern, every assertion below
        would go green for the wrong reason — the step would be running a
        detector that finds nothing, which is the same outcome by another route.
        """
        with tempfile.TemporaryDirectory() as td:
            planted = Path(td) / "planted.py"
            planted.write_text(
                "CONFIG_PATH = '" + "/" + "Users" + "/probeuser/notes'\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["bash", str(HOOK), str(planted)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertNotEqual(proc.returncode, 0, "hook did not flag the fixture")
        self.assertIn(HOOK_VERDICT, proc.stdout + proc.stderr)


class TestPiiStepActuallyScans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8")
        cls.body = pii_step_body(cls.text)

    def test_planted_pii_is_caught(self):
        rc, out = run_body(self.body, with_pii=True)
        self.assertIn(
            HOOK_VERDICT,
            out,
            "the PII step did not produce the hook's verdict line, so the hook "
            "NEVER RAN. This is the 2026-08-26 regression: a `#` comment "
            "between `\\`-continued `find` lines truncates the command and "
            f"leaves `-print0` as a command name.\n--- output ---\n{out}",
        )
        self.assertNotEqual(
            rc, 0, f"planted PII did not fail the step.\n--- output ---\n{out}"
        )

    def test_clean_tree_passes(self):
        rc, out = run_body(self.body, with_pii=False)
        self.assertEqual(
            rc, 0, f"the PII step fails on a clean tree.\n--- output ---\n{out}"
        )
        self.assertNotIn(HOOK_VERDICT, out)


class TestFindIsNotContinued(unittest.TestCase):
    """The structural half of the fix: no `\\` continuation to split.

    The defect needs a `\\`-continued line for a comment to land after. With the
    `find` on one physical line the arrangement cannot be built at all, which is
    stronger than detecting it. Asserted here so a future re-wrap for
    readability fails loudly rather than silently reopening the class."""

    @classmethod
    def setUpClass(cls):
        cls.body = pii_step_body(LINT_YML.read_text(encoding="utf-8"))

    def test_no_line_continuations_in_the_step_body(self):
        continued = [
            ln for ln in self.body.splitlines()
            if ln.rstrip().endswith("\\") and not ln.strip().startswith("#")
        ]
        self.assertEqual(
            continued,
            [],
            "the PII step body has `\\` line continuations again. A `#` comment "
            "placed after one of them silently truncates the command — that is "
            "the 2026-08-26 regression, dead for a week on a required gate. "
            "Keep the pipeline on one physical line.\n  "
            + "\n  ".join(continued),
        )

    def test_pipefail_is_set(self):
        """Second layer, kept for the shapes it DOES cover (see the step comment)."""
        self.assertIn(
            "set -euo pipefail",
            self.body,
            "`set -euo pipefail` was removed from the PII step. GitHub's default "
            "`run:` shell is `bash -e {0}` with no pipefail, which is what let a "
            "127 in the left half of this pipeline read as success.",
        )


class TestGuardIsNonVacuous(unittest.TestCase):
    """Prove this guard fails on the REAL incident, reconstructed.

    The current body has no continuation to mutate (see `TestFindIsNotContinued`),
    so the fixture rebuilds the historical `\\`-continued form and re-inserts the
    comment. Both sub-shapes are covered because they FAIL DIFFERENTLY, and only
    one of them is caught by `set -euo pipefail` — measured, not assumed."""

    @classmethod
    def setUpClass(cls):
        cls.body = pii_step_body(LINT_YML.read_text(encoding="utf-8"))
        # The historical arrangement, rebuilt from the body's own pipeline so it
        # cannot drift away from what the step really runs.
        pipeline = next(
            ln for ln in cls.body.splitlines()
            if ln.strip().startswith("find ") and "pii-check.sh" in ln
        )
        head, _, tail = pipeline.partition(" ! -path './.claudesec-assets/*'")
        assert tail, "could not split the pipeline — fixture is stale"
        cls.head, cls.tail = head, " ! -path './.claudesec-assets/*'" + tail

    def _historical(self, comment_before_last):
        """Rebuild the `\\`-continued form with a comment inserted.

        `comment_before_last=True` reproduces the shape that actually shipped
        (orphan starts with `-print0`); False puts the comment earlier, so the
        orphan starts with `!` and bash reads it as pipeline NEGATION."""
        mid, _, last = self.tail.rpartition(" -print0")
        last = "-print0" + last
        comment = "# a comment an author might add while regrouping"
        if comment_before_last:
            lines = [self.head + " \\", mid.strip() + " \\", comment, last]
        else:
            lines = [self.head + " \\", comment, mid.strip() + " \\", last]
        return "set -euo pipefail\n" + "\n".join(lines) + "\n"

    def test_shipped_shape_is_caught(self):
        mutant = self._historical(comment_before_last=True)
        rc, out = run_body(mutant, with_pii=True)
        self.assertNotIn(
            HOOK_VERDICT,
            out,
            "the mutation did NOT disable the scan, so this case proves nothing "
            f"about the guard. Check that possibility FIRST.\n{out}",
        )
        self.assertIn("-print0", out, f"expected the orphaned `-print0`\n{out}")
        # This is the sub-shape pipefail covers.
        self.assertNotEqual(rc, 0, f"expected pipefail to make it loud\n{out}")

    def test_negation_shape_is_caught_and_pipefail_does_not_cover_it(self):
        """The reason the guard exists rather than just `set -euo pipefail`.

        Orphan begins with `!`, so bash NEGATES the pipeline's status: the step
        exits 0 even under pipefail. Detection here comes only from the hook's
        verdict line being absent."""
        mutant = self._historical(comment_before_last=False)
        rc, out = run_body(mutant, with_pii=True)
        self.assertNotIn(HOOK_VERDICT, out, f"scan was not disabled\n{out}")
        self.assertEqual(
            rc,
            0,
            "expected `!`-negation to mask the failure even under pipefail — if "
            "this now exits non-zero, bash semantics changed and the step "
            "comment claiming pipefail is insufficient should be re-measured.\n"
            f"{out}",
        )


if __name__ == "__main__":
    unittest.main()
