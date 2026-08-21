"""The CI-config guards must RUN on the files they guard.

A guard that cannot execute on the PR that violates its invariant is decoration.
Every `test_ci_*.py` in this directory runs in exactly two jobs, and until #462
one of them did not exist:

- `scanner-unit-tests` — under pytest, with the 99% coverage gate. Gated on the
  `scanner` diff bucket, which also gates `scanner-shell-coverage` (kcov,
  minutes). Widening THAT bucket to `.github/**` would run the whole scanner +
  kcov set on every Dependabot action bump, which is the cost this repo
  path-gates to avoid (#180/#181) — so eleven guarded workflows sat outside it as
  a documented, deliberate gap.
- `ci-guards` — this file's subject. `unittest discover` over `test_ci_*.py` and
  nothing else, on the broad `ci_config` bucket. Measured at 874 tests / 3.6s in
  a venv with ZERO third-party packages, so it needs a checkout and a Python and
  no `pip install`, and admitting a path costs ~20s instead of minutes.

THE INCIDENT
------------
`test_ci_template_pin_policy.py::test_installed_template_pins_match_ours`
asserts an INSTALLED template mirrors the SHA this repo actually runs — it is the
only freshness mechanism `templates/` has, because Dependabot scans
`.github/workflows/` and never an arbitrary directory.

Dependabot PR #460 bumped `github/codeql-action` from v4.37.6 to v4.37.7 in
`.github/workflows/dast-full-scan.yml`, the single place this repo runs it, and
left `templates/codeql.yml` three lines behind. NEITHER path matched the
`scanner` bucket, so `scanner-unit-tests` reported `skipped` and the one guard
written for that invariant never ran on the PR that broke it. Reproduced locally
before the fix:

    bump dast-full-scan.yml only -> test_ci_template_pin_policy.py
      2 failed, 15 passed
      templates/codeql.yml line 45 / 51 / 54 — pinned 5595ccaf… but this repo
      runs ff2f1c62…
    restore -> 17 passed

The successor PR #462 DID fail that guard, but only by accident: the grouped
bump also touched `lint.yml`, which is in the `scanner` bucket. Same class as the
`pip-audit` drift of #392 — a path gate hiding drift from the guard written for
it — and the same reason `npm-audit` ran zero times for seven weeks (#394): a
job that does not run reads exactly like a job that found nothing.

WHAT THIS PINS
--------------
1. `ci_config` is DECLARED in the `changes` job's `outputs:` map. This is the
   vacuity hazard specific to the design: `needs.<job>.outputs.<name>` for an
   undeclared name evaluates to the empty string, so the `if:` is false forever
   and `ci-guards` skips silently on every PR. A skipped job reads green.
2. Every workflow and composite-action file matches the `ci_config` bucket,
   matched with the REAL regex the way the job's `grep -E` does it. Derived from
   `workflow_and_action_files()`, so a NEW workflow or a new
   `.github/actions/<name>/action.yml` is covered the day it lands — no
   classification table to rot.
3. Every INSTALLED template matches it too, derived from `scripts/setup.sh` via
   `test_ci_template_pin_policy.installed_workflow_templates` rather than listed,
   so a third installed template inherits the coverage.
4. `ci-guards` exists, is gated on `ci_config`, is wired into `lint-gate.needs`,
   and its step really invokes `unittest discover` over `test_ci_*.py`.

DIRECTION is coverage, in one direction only: widening `ci_config` is always safe
here (it can only run more validation, for seconds) and narrowing it trips this
guard. The bucket is deliberately broader than what items 2 and 3 derive — it
also carries `package.json`, `lighthouserc.json`, `bin/`, `.claude/skills/` and
others that individual guards pin — and that surplus is NOT asserted, because a
"mentioned by basename" proxy over the whole repo pulls in `LICENSE`, `README.md`
and a dozen `docs/` files that no guard actually reads (measured: 140 files
matched, 52 outside the `scanner` bucket, most of them prose mentions). Asserting
the derivable half and over-including the rest is the honest split.

NOT COVERED, deliberately: that `ci-guards` can FAIL. It is in
`lint-gate.needs`, so `test_ci_required_graph_not_disabled` already owns
`continue-on-error` / `if: false` / step-redirect keys for it — and it caught
`working-directory:` on this job's first draft, which mattered because
`unittest discover` exits 0 on "Ran 0 tests", making a relocated cwd a silent
vacuous pass. Duplicating that rule here would be two owners for one invariant.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    job_block,
    job_needs,
    key_column,
    step_blocks,
    strip_comment_lines,
    strip_inline_comment,
    workflow_and_action_files,
    yaml_key_pattern,
)
from test_ci_template_pin_policy import (  # noqa: E402
    installed_workflow_templates,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
SETUP_SH = REPO_ROOT / "scripts" / "setup.sh"

GUARD_JOB = "ci-guards"
CHANGES_JOB = "changes"
GATE_JOB = "lint-gate"
BUCKET_OUTPUT = "ci_config"

# The bucket's own `match '<regex>'` call, anchored on the output key so a
# sibling bucket cannot be read by mistake. Scoped to the `changes` job by the
# caller, because `re.search` otherwise takes the first hit in the file.
_BUCKET_RE = re.compile(r"""echo\s+"ci_config=\$\(match\s+'(?P<pattern>[^']+)'\)""")

# `python3 -m unittest discover` over this directory's guard pattern. Read from
# the step's `run:` body, comment-stripped, so a commented-out invocation or a
# mention in an explanatory note cannot pass for execution — the exact
# false-positive that made `main` MENTION two shell tests it never ran (#440).
_DISCOVER_RE = re.compile(
    r"unittest\s+discover\b[^\n]*?-p\s+['\"]test_ci_\*\.py['\"]"
)


def bucket_pattern(lint_text: str):
    """The `ci_config` bucket's regex source, or None if unlocatable.

    Read from the `changes` job block with comment lines removed: that job
    carries several paragraphs of explanation which quote bucket-shaped text,
    and a commented example must never be mistaken for the live bucket."""
    block = job_block(lint_text, CHANGES_JOB)
    if block is None:
        return None
    m = _BUCKET_RE.search(strip_comment_lines(block))
    return m.group("pattern") if m else None


def declared_outputs(lint_text: str) -> list:
    """Output names declared in the `changes` job's `outputs:` mapping.

    An `if:` reading an UNDECLARED output gets the empty string and is false
    forever, so this list is what makes the gate real rather than decorative."""
    block = job_block(lint_text, CHANGES_JOB)
    if block is None:
        return []
    job_col = key_column(block)
    if job_col is None:
        return []
    out, in_outputs = [], False
    pat = re.compile(rf"^ {{{job_col}}}{yaml_key_pattern('outputs')}\s*:\s*$")
    entry = re.compile(rf"^ {{{job_col + 2}}}([A-Za-z0-9_-]+)\s*:")
    for raw in block.splitlines():
        line = strip_inline_comment(raw)
        if not line.strip():
            continue
        if pat.match(line):
            in_outputs = True
            continue
        if not in_outputs:
            continue
        m = entry.match(line)
        if m:
            out.append(m.group(1))
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= job_col:
            break
    return out


def guard_job_problems(lint_text: str) -> list:
    """Everything wrong with how `ci-guards` is declared, wired and gated."""
    problems = []

    if BUCKET_OUTPUT not in declared_outputs(lint_text):
        problems.append(
            f"`{CHANGES_JOB}` does not declare `{BUCKET_OUTPUT}` in its `outputs:` "
            f"map. `needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT}` would then be the "
            f"empty string, `{GUARD_JOB}`'s `if:` would be false on every event, "
            "and the job would report `skipped` — indistinguishable from green — "
            "forever. This is how `npm-audit` ran zero times for seven weeks."
        )

    block = job_block(lint_text, GUARD_JOB)
    if block is None:
        problems.append(
            f"job `{GUARD_JOB}` not found exactly once in lint.yml. The "
            "`test_ci_*.py` guards would then run only in `scanner-unit-tests`, "
            "whose bucket excludes `.github/**` and `templates/**` — the gap that "
            "let PR #460 skip every guard for the workflow it edited."
        )
        return problems

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
        problems.append(
            f"job `{GUARD_JOB}` has no job-level `if:`. That is not a coverage "
            "regression (an ungated job always runs) but it is not this design "
            "either — say so deliberately if intended."
        )
    elif f"needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT}" not in gate:
        problems.append(
            f"job `{GUARD_JOB}` is gated on `if: {gate}`, which does not read "
            f"`needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT}`. A correct bucket wired "
            "to nothing is not a gate."
        )

    runs = [
        blk for blk in step_blocks(block)
        if _DISCOVER_RE.search(blk)
    ]
    if not runs:
        problems.append(
            f"no step in `{GUARD_JOB}` invokes `unittest discover ... -p "
            "'test_ci_*.py'`. The job would report success while running nothing "
            "that guards anything."
        )

    gate_block = job_block(lint_text, GATE_JOB)
    if gate_block is None:
        problems.append(f"aggregator job `{GATE_JOB}` not found")
    elif GUARD_JOB not in job_needs(gate_block):
        problems.append(
            f"`{GATE_JOB}` does not list `{GUARD_JOB}` in `needs:`. Branch "
            f"protection requires only `Lint` ({GATE_JOB}'s display name), so a "
            "job outside that graph cannot block a merge no matter what it finds."
        )
    return problems


def uncovered_paths(pattern: str) -> list:
    """Repo-relative paths a guard reads that the `ci_config` bucket misses.

    Matched with the REAL regex against the real path, exactly as the job's
    `grep -E` does, so an equivalent rewrite of the alternation stays green."""
    if not pattern:
        return ["bucket pattern not found"]
    bucket = re.compile(pattern)
    targets = [str(Path(p).relative_to(REPO_ROOT)) for p in workflow_and_action_files()]
    if SETUP_SH.is_file():
        for name in installed_workflow_templates(SETUP_SH.read_text(encoding="utf-8")):
            targets.append(f"templates/{name}")
    return sorted(p for p in targets if not bucket.match(p))


class TestGuardJobIsWiredAndGated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_lint_yml_exists(self):
        """Canary: every assertion below is vacuous without it."""
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_bucket_is_locatable(self):
        """Canary: an unfindable bucket must fail loudly, not silently pass."""
        self.assertIsNotNone(
            bucket_pattern(self.raw),
            f"could not find `echo \"{BUCKET_OUTPUT}=$(match '...')\"` in the "
            f"`{CHANGES_JOB}` job — it was renamed or restructured.",
        )

    def test_guard_job_is_declared_gated_and_required(self):
        self.assertEqual(guard_job_problems(self.raw), [])

    def test_every_workflow_and_installed_template_is_covered(self):
        self.assertEqual(uncovered_paths(bucket_pattern(self.raw)), [])


class TestSelfVerifyDetectorIsNonVacuous(unittest.TestCase):
    """Mutation self-tests. Each plants a real regression and requires a RED."""

    def setUp(self):
        self.lint = LINT_YML.read_text(encoding="utf-8")

    # --- the derived-coverage half ------------------------------------------

    def test_control_the_real_bucket_covers_everything(self):
        """Item 6 of the guard conventions: the harness must be able to report
        GREEN on the real file, or every RED below proves nothing."""
        self.assertEqual(uncovered_paths(bucket_pattern(self.lint)), [])

    def test_derived_target_set_is_populated(self):
        """The denominator must not be empty. `templates/codeql.yml` and
        `.github/workflows/dast-full-scan.yml` are the two paths from the #460
        incident and are named explicitly so a discovery regression that drops
        them cannot pass as 'nothing uncovered'."""
        pattern = bucket_pattern(self.lint)
        targets = [str(Path(p).relative_to(REPO_ROOT)) for p in workflow_and_action_files()]
        targets += [
            f"templates/{n}"
            for n in installed_workflow_templates(SETUP_SH.read_text(encoding="utf-8"))
        ]
        self.assertGreaterEqual(len(targets), 15, f"only found {sorted(targets)}")
        self.assertIn(".github/workflows/dast-full-scan.yml", targets)
        self.assertIn("templates/codeql.yml", targets)
        self.assertIn(
            ".github/actions/token-expiry-gate/action.yml", targets,
            "composite actions dropped out of the derived set — a PR editing only "
            "one would stop being covered",
        )
        self.assertTrue(pattern)

    def test_dropping_templates_from_the_bucket_is_caught(self):
        """THE #460 regression: `templates/` out of the bucket means the
        installed-template pin guard cannot run on a template edit."""
        mutant = apply_mutation(self.lint, "|templates/", "|__templates_removed__/")
        uncovered = uncovered_paths(bucket_pattern(mutant))
        self.assertIn("templates/codeql.yml", uncovered)
        self.assertNotIn(
            ".github/workflows/dast-full-scan.yml", uncovered,
            "fixture must remove ONLY the templates alternative, or the RED does "
            "not isolate the invariant under test",
        )

    def test_dropping_dot_github_from_the_bucket_is_caught(self):
        """The other half of #460: the workflow side of the same comparison."""
        mutant = apply_mutation(self.lint, "^(\\.github/|", "^(__dot_github__/|")
        uncovered = uncovered_paths(bucket_pattern(mutant))
        self.assertIn(".github/workflows/dast-full-scan.yml", uncovered)
        self.assertIn(".github/actions/token-expiry-gate/action.yml", uncovered)
        self.assertNotIn("templates/codeql.yml", uncovered)

    def test_a_commented_bucket_is_not_the_live_one(self):
        """The `changes` job quotes bucket-shaped text in its own explanation. A
        decoy above the real line must not be what gets read."""
        real = bucket_pattern(self.lint)
        self.assertIsNotNone(real)
        anchor = f"""            echo "ci_config=$(match '{real}')\""""
        decoy = """            # echo "ci_config=$(match '^(decoy/)')\"\n"""
        mutant = apply_mutation(self.lint, anchor, decoy + anchor)
        self.assertEqual(bucket_pattern(mutant), real)

    # --- the wiring half ----------------------------------------------------

    def test_undeclared_output_is_caught(self):
        """The vacuity hazard unique to this design: an `if:` reading an output
        the producing job never declares is false forever, and the job reports
        `skipped`, which reads green."""
        assert_disables(
            guard_job_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "      ci_config: ${{ steps.detect.outputs.ci_config }}\n",
                "",
            ),
            "ci_config not declared in changes.outputs",
        )

    def test_removing_the_job_from_the_aggregator_is_caught(self):
        """A job outside `lint-gate.needs` cannot block a merge."""
        assert_disables(
            guard_job_problems,
            self.lint,
            apply_mutation(self.lint, "      - ci-guards\n", ""),
            "ci-guards dropped from lint-gate.needs",
        )

    def test_rewiring_the_gate_to_another_bucket_is_caught(self):
        """Mutates the output NAME only, so the bucket stays byte-for-byte
        perfect and the RED can come from nothing else."""
        assert_disables(
            guard_job_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "    if: needs.changes.outputs.ci_config == 'true'"
                " || github.event_name == 'schedule'",
                "    if: needs.changes.outputs.markdown == 'true'"
                " || github.event_name == 'schedule'",
            ),
            "ci-guards gated on a different bucket",
        )

    def test_a_step_that_stops_running_the_guards_is_caught(self):
        """The job may not become a green no-op."""
        assert_disables(
            guard_job_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "python3 -m unittest discover -s . -p 'test_ci_*.py'",
                "echo 'skipping the guards'",
            ),
            "ci-guards runs nothing",
        )

    def test_a_commented_out_invocation_is_not_execution(self):
        """A `#`-parked invocation must not satisfy the run check — the
        false-positive shape that made `main` MENTION two shell tests it never
        executed."""
        problems = guard_job_problems(
            apply_mutation(
                self.lint,
                "          out=$(python3 -m unittest discover -s . -p 'test_ci_*.py' 2>&1) || {",
                "          # out=$(python3 -m unittest discover -s . -p 'test_ci_*.py' 2>&1) || {\n"
                "          out=$(echo skipped) || {",
            )
        )
        self.assertTrue(
            problems,
            "a commented-out `unittest discover` was accepted as execution",
        )

    def test_renaming_the_job_fails_closed(self):
        """A rename must be reported, not treated as 'nothing to check'."""
        problems = guard_job_problems(
            apply_mutation(self.lint, "  ci-guards:\n", "  ci-gaurds:\n")
        )
        self.assertTrue(problems)
        self.assertIn("not found exactly once", problems[0])


if __name__ == "__main__":
    unittest.main()
