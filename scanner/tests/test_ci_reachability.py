"""
Regression guard: a test that EXISTS is actually REACHED by a CI job that can fail.

Two independent ways this repo has silently failed that, both fixed in the PR that
adds this file, both the same class — "every guard was correct and none of them
ran":

  A. `scanner/tests/test_*.sh` reached only by a loop that could not fail.
  B. `test_ci_*.py` guards for a workflow not reached when THAT WORKFLOW changes,
     because the diff bucket gating the only pytest job did not list it.

A and B are separate `TestCase` classes below; each carries its own incident,
direction and mutation proofs.

=============================================================================
A. SHELL-TEST REGISTRATION
=============================================================================

WHY (the incident, #437 -> this PR)
-----------------------------------
Two facts combined to make 21 shell tests decorative:

1. `scanner-unit-tests` runs shell tests from an EXPLICIT list of one step per
   file. It does not auto-discover, so adding `scanner/tests/test_foo.sh` to the
   repo wires it into nothing.
2. `scanner-shell-coverage` DOES glob `scanner/tests/test_*.sh` — and until this
   PR that loop turned every non-zero rc into `echo WARN:` text, so the step
   could not fail. Measured under real kcov v42 on Linux with a real SUT
   regression (output.sh `_score_to_grade` C boundary 70->75):
   `test_print_summary_score_to_grade.sh` exited 1 with its `score 70 -> C`
   assertion red while the step exited 0 and `lint-gate` (the REQUIRED `Lint`
   context, which lists that job in `needs:`) read success.

So a test could be written, reviewed, merged, and silently never gate anything —
the worst kind of green, because the file's existence reads as coverage. The kcov
loop now propagates real failures, and this guard keeps the fast-path list
complete so a new test cannot repeat the pattern.

DIRECTION
---------
Presence, and COMPLETE in one direction only: every file on disk must appear.
Adding a step is always fine; deleting one, or adding a test file without a step,
fails. A test that legitimately cannot run on the `scanner-unit-tests` runner goes
in `RUNS_ELSEWHERE` with the workflow that does run it, and that claim is checked
too — the table is not a place to park an unrun test.

WHAT COUNTS AS "REGISTERED" — and why it is not a substring search
-----------------------------------------------------------------
Only text that the runner EXECUTES: the value of a `run:` key inside the
`scanner-unit-tests` job, with YAML comment lines dropped and, inside a `run:`
block scalar, bash comments stripped as well. That distinction is the whole
guard, not a detail. `lint.yml` on `main` at the time of writing MENTIONED
`test_output_coverage.sh` and `test_print_summary_score_to_grade.sh` in the kcov
job's explanatory comments while executing neither of them from the fast path — a
raw substring guard would have read those two comments as registration and
reported the exact opposite of the truth. Every mutation self-test below plants
the filename somewhere non-executing (a comment, a step `name:`, a commented-out
step) and requires it to still be reported missing.

CONSTRAINTS (repo guard conventions)
------------------------------------
- stdlib-only: no PyYAML (not in `requirements-ci.txt`).
- No `scanner/lib` import, so the 99% lib coverage gate is untouched.
- Green under both `pytest` and `python3 -m unittest`.
- All presence/regex work routed through `scanner/tests/_ci_guard_util.py`
  primitives (ADR-001 §1) — `job_block` (which itself uses `key_column`
  and `block_ends_at`, so a comment cannot truncate the job), `key_column`,
  `yaml_key_pattern`, `explicit_key_lines`, `workflow_and_action_files`,
  `strip_inline_comment`, `strip_inline_comment_sh`, `on_key_inline`, and the
  mutation helpers.

DELIBERATELY NOT USING A STEP SPLITTER
--------------------------------------
This guard never asks "which step is this?", only "what shell does the job
execute?", so it does not use a step-block collector (`step_blocks`) and does not
look for `- name:` at all. That is not a shortcut, it removes a failure mode: a
splitter keyed on the dash column can be over-split by a `run: |` body containing
a literal `- name:` line, whereas here a block scalar is bounded purely by
indentation relative to its OWN `run:` key column, so such a line is consumed as
scalar content — which is exactly what the runner does with it. If a future
invariant here needs real step boundaries, use the shared primitive rather than
growing this collector into one.

KNOWN LIMITATIONS, both in the FALSE-ALARM direction (the guard sees less than the
runner, so it over-reports; neither can hide an unregistered test):
- A `run:` written as a multi-line FOLDED PLAIN scalar (`run: bash` on one line,
  the path on the next) is read as only its first line, so the path would be
  missed and the test reported unregistered. No such step exists; the fix is to
  write it on one line or use `run: |`.
- The path must carry its `scanner/tests/` prefix, which is how every step in the
  job invokes it. `cd scanner/tests && bash test_x.sh` would be missed.

=============================================================================
B. GUARDED WORKFLOWS MUST BE IN THE `scanner` DIFF BUCKET
=============================================================================

`scanner-unit-tests` is the ONLY job in the repo that runs pytest (verified: the
sole `python3 -m pytest` invocation across `.github/workflows/*.yml`), so it is the
only job that runs the `test_ci_*.py` guards. It is gated on
`needs.changes.outputs.scanner`, whose bucket is a `grep -E` alternation in the
`changes` job.

The hole: a workflow that guards exist FOR was not itself in that alternation, so a
PR touching only that workflow skipped every guard written to protect it. Measured
by executing the real bucket regex against a one-path file list:

    scanner=false   <- .github/workflows/security-scan.yml
    scanner=true    <- .github/workflows/lint.yml

`security-scan.yml` is named by SEVEN guards, one of which
(`test_ci_security_gate_behaviour.py`) executes the CRITICAL gate — so the gate's
own guard did not run on PRs that edited the gate. `lint.yml` had been added to the
bucket for exactly this reason, with a comment saying so; the fix is the symmetric
one.

DIRECTION: presence of each `MUST_BE_IN_BUCKET` path in the alternation. Widening
the bucket is always safe for correctness (it only runs MORE validation) and costs
CI minutes; narrowing it trips this guard.

KNOWN GAP, ENUMERATED RATHER THAN CLOSED
----------------------------------------
Eleven further workflows are named by guards and remain outside the bucket
(`KNOWN_BUCKET_GAP`). Closing all of them would make every workflow-only PR — most
of them Dependabot action bumps — run the full scanner + kcov set, and this repo
path-gates deliberately for CI cost (#180/#181). The two admitted here are the ones
where a skipped guard silently weakens a BRANCH-PROTECTION-REQUIRED check
(`Lint`, `Security Scan Gate`).

That is a shipped false negative, so it carries the cost argument the guard
conventions require, plus a mechanism so it cannot rot: `MUST_BE_IN_BUCKET` and
`KNOWN_BUCKET_GAP` together must equal the DERIVED set of guarded workflows. A new
guarded workflow therefore lands in neither and fails this guard, forcing a
conscious in-or-out decision instead of quietly joining the gap. Revisit trigger:
any workflow in the gap list becoming a required context, or a guard for one of
them failing to catch a real regression because it did not run.
"""

import glob
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    block_ends_at,
    explicit_key_lines,
    job_block,
    key_column,
    on_key_inline,
    step_blocks,
    strip_comment_lines,
    strip_inline_comment,
    strip_inline_comment_sh,
    top_level_jobs,
    workflow_and_action_files,
    yaml_key_pattern,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
SHELL_TEST_GLOB = "scanner/tests/test_*.sh"
JOB = "scanner-unit-tests"

# Tests that CANNOT run in `scanner-unit-tests` (ubuntu-latest, no browser) mapped
# to the workflow that does run them. Each entry is an environment constraint, not
# a preference:
#
#   *_live.sh                       -> need a macOS / Windows runner (cross-os matrix)
#   *dashboard_control_liveness.sh  -> need headless Chrome (CHROME_BIN)
#
# Both owner workflows report their own PR check, so these tests do gate — but
# note NEITHER is a branch-protection-required context (required today: `Lint`,
# `Security Scan Gate`), so the gate is weaker than the fast path. Do not add an
# entry here to silence this guard: `test_runs_elsewhere_table_has_no_ghosts`
# rejects a name that is not on disk, and `test_runs_elsewhere_is_really_run_there`
# rejects one its owner workflow does not reference outside the trigger block.
RUNS_ELSEWHERE = {
    "test_check_macos_cis_security_live.sh": "cross-os-checks.yml",
    "test_check_windows_kisa_security_live.sh": "cross-os-checks.yml",
    "test_dashboard_control_liveness.sh": "dashboard-control-smoke.yml",
    "test_asset_dashboard_control_liveness.sh": "dashboard-control-smoke.yml",
}

# `run:` bare or quoted, optionally introduced by a sequence dash. `prefix` is
# captured so the KEY's own column is derived rather than assumed — a `steps:`
# list may legally sit at its parent key's indent, which walks every step out from
# under a fixed anchor (the `keys_at_column` lesson).
_RUN_KEY_RE = re.compile(
    rf"^(?P<prefix>\s*(?:-\s+)?){yaml_key_pattern('run')}\s*:(?P<rest>.*)$"
)
# A block-scalar HEADER: `|` or `>` followed by the chomping (`+`/`-`) and explicit
# indentation (a digit) indicators IN EITHER ORDER — the YAML spec permits both
# `|2-` and `|-2`, and an adversarial pass found the first draft
# (`[|>][+-]?\d*`) missed `|2-`, `>2-` and `|2+`. All three are valid YAML
# (confirmed with PyYAML), so the miss was real: the header would have been read as
# a plain inline value and the scalar body — the shell — never collected. Direction
# was false-alarm (a registered test reported as missing), but the fix is to model
# the grammar rather than enumerate the orderings. Over-accepting a malformed
# header like `|+-2` is harmless: such a document does not parse, so it never runs.
_BLOCK_SCALAR_RE = re.compile(r"^[|>][0-9+-]*\s*$")
_SHELL_TEST_TOKEN_RE = re.compile(r"scanner/tests/(test_[A-Za-z0-9_]+\.sh)")


def shell_tests_on_disk() -> list:
    """Every shell test file name, sorted. The denominator of the whole guard."""
    return sorted(Path(p).name for p in glob.glob(str(REPO_ROOT / SHELL_TEST_GLOB)))


def executed_shell(text: str) -> str:
    """The shell the runner would EXECUTE from every `run:` in `text`.

    Handles both spellings a step may use, and drops what does not execute:

    - a whole-line YAML `#` comment is skipped;
    - a plain inline value has its trailing YAML comment stripped;
    - a block scalar (`run: |`, `run: >-`, `run: |2`) contributes its indented
      body, each line passed through the bash-aware comment stripper, because that
      body is SHELL and a `#` line in it does not run.

    The block-scalar branch is what keeps the kcov job's long explanatory comments
    — which name two shell tests verbatim — from counting as execution.
    """
    lines = text.splitlines()
    out = []
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        if raw.lstrip().startswith("#"):
            continue
        m = _RUN_KEY_RE.match(raw)
        if not m:
            continue
        key_col = len(m.group("prefix"))
        rest = m.group("rest").strip()
        if _BLOCK_SCALAR_RE.match(rest):
            while i < n:
                body = lines[i]
                if body.strip() and (len(body) - len(body.lstrip())) <= key_col:
                    break  # dedent ends the scalar
                i += 1
                out.append(strip_inline_comment_sh(body))
        else:
            out.append(strip_inline_comment(rest))
    return "\n".join(out)


def registered_in_job(lint_text: str):
    """`(set_of_registered_basenames, problems)` for the `scanner-unit-tests` job.

    Fails CLOSED: a job block that cannot be located, or an unscannable
    explicit-key `? run` / `? steps` form, is returned as a problem rather than as
    an empty set — an empty set would satisfy nothing and read as "all missing",
    or worse, mask a real answer.
    """
    problems = []
    unscannable = explicit_key_lines(lint_text, "run", "steps")
    if unscannable:
        problems.append(
            "YAML explicit-key form found, which no line matcher can read: "
            f"{unscannable!r}. Rewrite as `key: value` so registration stays "
            "verifiable."
        )
    block = job_block(lint_text, JOB)
    if block is None:
        problems.append(
            f"job `{JOB}` not found exactly once in lint.yml — it was renamed, "
            "removed or duplicated. This guard cannot verify registration, and "
            "the shell-test fast path may be gone entirely."
        )
        return set(), problems
    return set(_SHELL_TEST_TOKEN_RE.findall(executed_shell(block))), problems


def _strip_trigger_block(text: str) -> str:
    """`text` with whole-line comments AND the top-level `on:` block removed.

    A filename under `on.pull_request.paths` is a TRIGGER FILTER, not execution.
    `cross-os-checks.yml` lists both `_live.sh` tests in its `paths:` as well as in
    its matrix, so without this subtraction the ownership check below would still
    pass after the matrix entry — the thing that actually runs the test — was
    deleted. Verified by mutation (`test_paths_only_mention_is_not_ownership`).
    """
    out, in_on = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if not in_on:
            if on_key_inline(line) is not None:
                in_on = True
                continue
            out.append(line)
            continue
        if line.strip() and not line[0].isspace():  # dedent to the next top-level key
            in_on = False
            out.append(line)
    return "\n".join(out)


# RUNS_ELSEWHERE entries whose owner reaches the test through a matrix VALUE
# (`run: bash ${{ matrix.test }}`) instead of naming it in a `run:`. ENUMERATED,
# never inferred, so a NEW exemption this guard cannot locate FAILS rather than
# silently opting out of the rc-swallow check below.
#
# The indirection itself is still only reference-checked — see KNOWN LIMITATIONS.
MATRIX_INDIRECTION = {
    "test_check_macos_cis_security_live.sh",
    "test_check_windows_kisa_security_live.sh",
}

# `continue-on-error` turns a red step green; a step-level `if:` can stop it
# running at all. Either one turns a RUNS_ELSEWHERE exemption into the precise
# defect this PR exists to fix — a test that exists, is "reached", and gates
# nothing. Found by adversarial review: `continue-on-error: true` on
# `dashboard-control-smoke.yml`'s asset-dashboard step read
#
#     reachability          32 passed
#     whole test_ci_* suite  823 passed
#
# because ownership was asserted as a REFERENCE and never as a verdict. Neither
# owner workflow is a required context, so `test_ci_required_graph_not_disabled`
# — which catches exactly this on the fast path — does not reach them. The fast
# path has defence in depth; the exemptions had none.
_SWALLOW_STEP_KEYS = ("continue-on-error", "if")
_SWALLOW_JOB_KEYS = ("continue-on-error",)


def _seq_item_key_column(block: str):
    """The key column of a `- key:` sequence item: one level in from its own dash.

    Derived from the real dash run (`-`, `-  `, ...) rather than assumed to be two
    characters, the same reason `_RUN_KEY_RE` captures its prefix."""
    m = re.match(r"^(\s*-\s+)", block.splitlines()[0])
    return len(m.group(1)) if m else None


def _keys_at(block: str, col: int, keys) -> list:
    """Which of `keys` appear as mapping keys at exactly `col` in `block`."""
    out = []
    for key in keys:
        pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern(key)}\s*:")
        if any(pat.match(strip_inline_comment(ln)) for ln in block.splitlines()):
            out.append(key)
    return out


def _enclosing_job_block(owner_text: str, step_block: str):
    """The job block containing `step_block`, or None."""
    anchor = step_block.splitlines()[0]
    for job in top_level_jobs(owner_text):
        block = job_block(owner_text, job)
        if block is not None and anchor in strip_comment_lines(block):
            return block
    return None


def exemption_swallow_problems(owner_text: str, owner: str, test_name: str) -> list:
    """Problems with HOW `owner_text` runs `test_name`: located, and can it fail?

    Fails CLOSED in both directions — a test named by no executed `run:` is
    reported (unless it is a documented matrix indirection), and so is one whose
    step or job can swallow its exit code."""
    running = [
        blk for blk in step_blocks(owner_text)
        if test_name in executed_shell(blk)
    ]
    if not running:
        if test_name in MATRIX_INDIRECTION:
            return []
        return [
            f"{owner} names {test_name} but no step's `run:` invokes it, and it is "
            "not in MATRIX_INDIRECTION. Either the step was dropped (the test now "
            "runs nowhere) or the invocation moved behind an indirection this guard "
            "cannot read — add it to MATRIX_INDIRECTION with a reason, or register "
            f"the test in `{JOB}`."
        ]
    problems = []
    for blk in running:
        col = _seq_item_key_column(blk)
        if col is None:
            problems.append(
                f"{owner}: could not derive the key column of the step running "
                f"{test_name}, so this guard cannot verify it can fail."
            )
            continue
        bad = _keys_at(blk, col, _SWALLOW_STEP_KEYS)
        if bad:
            problems.append(
                f"{owner}: the step running {test_name} carries {bad} at step level. "
                f"`{test_name}` is EXEMPT from registration in `{JOB}` on the promise "
                "that this step gates it; a swallowed or skipped step keeps the "
                "exemption while the verdict disappears — the same 'runs but cannot "
                "fail' defect this guard was written for."
            )
        job = _enclosing_job_block(owner_text, blk)
        if job is None:
            problems.append(
                f"{owner}: the step running {test_name} is in no locatable job."
            )
            continue
        job_col = key_column(job)
        if job_col is None:
            continue
        bad_job = _keys_at(job, job_col, _SWALLOW_JOB_KEYS)
        if bad_job:
            problems.append(
                f"{owner}: the JOB running {test_name} carries {bad_job} at job "
                "level, which makes every step in it non-fatal."
            )
    return problems


# --- B. guarded workflows must be in the `scanner` diff bucket ----------------

# The bucket's own `match '<regex>'` call in the `changes` job. Anchored on the
# output key so the docker/markdown buckets cannot be read by mistake.
_SCANNER_BUCKET_RE = re.compile(
    r"""echo\s+"scanner=\$\(match\s+'(?P<pattern>[^']+)'\)"""
)

# Workflows whose guards MUST run when the workflow itself is edited, because a
# guard skipped there weakens a branch-protection-required check.
MUST_BE_IN_BUCKET = {
    "lint.yml": "hosts every required-check aggregator and the only pytest job",
    "security-scan.yml": "hosts the required `Security Scan Gate`; 7 guards pin it, "
                         "one of which executes the CRITICAL gate",
}

# Named by guards, deliberately NOT in the bucket: none reports a required context,
# and admitting them would run the full scanner + kcov set on every workflow-only
# PR. Reason is the workflow's role, not a promise about its guards.
KNOWN_BUCKET_GAP = {
    "cross-os-checks.yml": "non-required macOS/Windows matrix (weekly + path-gated)",
    "dashboard-control-smoke.yml": "non-required headless-Chrome smoke",
    "dast-baseline.yml": "non-required DAST",
    "dast-full-scan.yml": "non-required nightly DAST",
    "dependabot-auto-merge.yml": "automation, not a check",
    "lighthouse.yml": "non-required perf audit",
    "lychee-redirect-sweep.yml": "monthly notifier",
    "npm-publish.yml": "release-time only, runs on tag/version bump",
    "og-meta-verify.yml": "non-required metadata check",
    "protection-drift-watch.yml": "scheduled drift notifier",
    "provenance-verify.yml": "non-required daily provenance check",
}


# The `changes` job output the pytest job must CONSULT. Direction B proves the
# bucket CONTAINS the right paths; on its own it never proved the job READS that
# bucket, and nothing else in the repo pinned the link (`grep -rn
# "outputs.scanner" scanner/tests/test_ci_*.py` found only prose). Adversarial
# review defeated the whole of Direction B through that gap: rewiring
# `scanner-unit-tests`'s `if:` to `needs.changes.outputs.markdown` left the
# alternation byte-for-byte perfect, made a `security-scan.yml`-only PR skip
# every guard again, and read
#
#     reachability          32 passed
#     whole test_ci_* suite  823 passed
#
# — the exact incident Direction B exists to close, reproduced with Direction B
# green. A correct bucket wired to nothing is not a gate.
BUCKET_OUTPUT_REF = "needs.changes.outputs.scanner"


def job_gate_expression(lint_text: str, job_key: str):
    """`(expr_or_None, problems)` — the JOB-level `if:` of `job_key`.

    `(None, [])` means the job carries no `if:` at all, which is SAFE and must
    stay green: an ungated job always runs, so it cannot skip the guards. Only a
    gate that EXISTS and names the wrong output is a hole, so this reports the
    expression and lets the caller judge it.

    Read at the job's OWN derived key column, for two reasons measured elsewhere
    in this repo: `scanner-unit-tests` contains several STEP-level `if:` keys that
    a whole-block search would happily return instead, and deriving the column
    rather than hardcoding `^ {4}` means dedenting the job body (valid YAML, a
    cosmetic diff) does not walk the matcher off its target.

    Continuation lines are joined, because a job gate is legitimately spread over
    several lines in this file (`lint.yml`'s docker-smoke gate is) and reading only
    the key line would see half an expression.
    """
    problems = []
    unscannable = explicit_key_lines(lint_text, "if")
    if unscannable:
        problems.append(
            "YAML explicit-key `? if` form found, which no line matcher can read: "
            f"{unscannable!r}. Rewrite as `if: <expr>` so the job's gate stays "
            "verifiable."
        )
        return None, problems
    block = job_block(lint_text, job_key)
    if block is None:
        problems.append(
            f"job `{job_key}` not found exactly once in lint.yml — it was renamed, "
            "removed or duplicated, so this guard cannot verify what gates it."
        )
        return None, problems
    col = key_column(block)
    if col is None:
        problems.append(f"job `{job_key}` has an empty body")
        return None, problems
    pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern('if')}\s*:(?P<rest>.*)$")
    lines = block.splitlines()
    for i, raw in enumerate(lines):
        m = pat.match(strip_inline_comment(raw))
        if not m:
            continue
        parts = [m.group("rest").strip()]
        for cont in lines[i + 1:]:
            if block_ends_at(cont, col):
                break
            parts.append(strip_inline_comment(cont).strip())
        return " ".join(p for p in parts if p), problems
    return None, problems


def bucket_gate_problems(lint_text: str) -> list:
    """Detector form of the invariant above, so the mutation self-tests can drive
    it on synthetic text as well as on the real file."""
    expr, problems = job_gate_expression(lint_text, JOB)
    if problems:
        return problems
    if expr is None:
        return []  # ungated job always runs — safe
    if BUCKET_OUTPUT_REF not in expr:
        return [
            f"job `{JOB}` is gated on `if: {expr}`, which does not reference "
            f"`{BUCKET_OUTPUT_REF}`. It is the only job that runs pytest, hence "
            "the only job that runs every `test_ci_*.py` guard, so a gate wired to "
            "any other bucket silently skips all of them for the PRs the `scanner` "
            "bucket was widened to cover. Widening the bucket is worthless if the "
            "job does not read it."
        ]
    return []


def scanner_bucket_pattern(lint_text: str):
    """The `scanner` bucket's regex source, or None if it cannot be located.

    Read from the comment-stripped text so a bucket quoted in an explanatory
    comment — and this job has several — cannot be mistaken for the live one.
    """
    active = strip_comment_lines(lint_text)
    m = _SCANNER_BUCKET_RE.search(active)
    return m.group("pattern") if m else None


def guarded_workflows() -> dict:
    """`{workflow filename: [guard files naming it]}`, DERIVED, not listed.

    Any `test_ci_*.py` mentioning a workflow's filename is treated as guarding it.
    Deliberately generous: the question is "would a reviewer expect this guard to
    run when that workflow changes", and a mention is the cheapest complete proxy.
    Over-inclusion only forces an in-or-out decision, never hides one.
    """
    out = {}
    guards = sorted(Path(REPO_ROOT / "scanner" / "tests").glob("test_ci_*.py"))
    texts = {g.name: g.read_text(encoding="utf-8") for g in guards}
    for wf in workflow_and_action_files():
        name = Path(wf).name
        if name == "action.yml" or name == "action.yaml":
            continue  # composite actions are not path-gated by this bucket
        namers = sorted(g for g, t in texts.items() if name in t)
        if namers:
            out[name] = namers
    return out


class TestGuardedWorkflowsAreInTheScannerBucket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.pattern = scanner_bucket_pattern(cls.raw)

    def test_bucket_pattern_is_locatable(self):
        """Canary: an unfindable bucket must fail loudly. Every assertion below is
        vacuous without it."""
        self.assertIsNotNone(
            self.pattern,
            "could not find the `scanner=$(match '...')` bucket in the `changes` "
            "job of lint.yml — it was renamed or restructured, so this guard "
            "cannot verify which paths re-run the guards.",
        )

    def test_pytest_job_actually_reads_the_scanner_bucket(self):
        """The bucket must be WIRED to the job, not merely correct.

        Without this, every other assertion in this class is satisfiable while the
        guards skip: the alternation stays perfect and the job consults a different
        output. That is not a hypothetical — it is how adversarial review defeated
        the whole of Direction B at `823 passed`."""
        self.assertEqual(bucket_gate_problems(self.raw), [])

    def test_required_workflows_are_in_the_bucket(self):
        """The invariant. Matching is done with the REAL regex against the real
        path, the same way the job's `grep -E` does it, rather than by looking for
        the literal alternative — an equivalent rewrite of the alternation must
        stay green."""
        self.assertIsNotNone(self.pattern, "bucket not found")
        bucket = re.compile(self.pattern)
        for name, why in sorted(MUST_BE_IN_BUCKET.items()):
            with self.subTest(workflow=name):
                path = f".github/workflows/{name}"
                self.assertTrue(
                    bucket.match(path),
                    f"{path} does not match lint.yml's `scanner` diff bucket, so a "
                    f"PR touching only that file skips `scanner-unit-tests` — the "
                    f"only job that runs pytest, hence the only job that runs the "
                    f"guards written for it. This one matters because it {why}. "
                    f"Add `|\\.github/workflows/{name.replace('.', chr(92) + '.')}` "
                    "to the alternation.",
                )

    def test_bucket_membership_lists_cover_every_guarded_workflow(self):
        """No-ghost / no-orphan, in both directions, so the admitted gap cannot rot.

        A NEW workflow that guards start pinning appears in neither table and fails
        here, forcing an explicit in-or-out decision rather than silently inheriting
        the gap. A deleted workflow left behind in a table also fails.
        """
        derived = set(guarded_workflows())
        classified = set(MUST_BE_IN_BUCKET) | set(KNOWN_BUCKET_GAP)
        unclassified = sorted(derived - classified)
        self.assertEqual(
            unclassified, [],
            "these workflows are named by `test_ci_*.py` guards but are in neither "
            f"MUST_BE_IN_BUCKET nor KNOWN_BUCKET_GAP: {unclassified}. Decide: if a "
            "skipped guard there could weaken a REQUIRED check, add the path to the "
            "bucket in lint.yml and to MUST_BE_IN_BUCKET; otherwise record it in "
            "KNOWN_BUCKET_GAP with the reason.",
        )
        stale = sorted(classified - derived)
        self.assertEqual(
            stale, [],
            f"these entries no longer correspond to a guarded workflow: {stale}. "
            "Remove them so the tables cannot exempt a future file by that name.",
        )

    def test_tables_are_disjoint(self):
        both = sorted(set(MUST_BE_IN_BUCKET) & set(KNOWN_BUCKET_GAP))
        self.assertEqual(both, [], f"listed as both required and gap: {both}")

    def test_known_gap_entries_carry_a_reason(self):
        """A gap entry with an empty reason is a heading, not a cost argument."""
        blank = sorted(k for k, v in KNOWN_BUCKET_GAP.items() if not v.strip())
        self.assertEqual(blank, [], f"gap entries missing a reason: {blank}")


class TestBucketDetectorIsNonVacuous(unittest.TestCase):
    """Mutation self-tests for invariant B."""

    def setUp(self):
        self.lint = LINT_YML.read_text(encoding="utf-8")

    def _matches(self, text, name):
        pattern = scanner_bucket_pattern(text)
        self.assertIsNotNone(pattern, "bucket not found in fixture")
        return bool(re.compile(pattern).match(f".github/workflows/{name}"))

    def test_control_both_required_workflows_match_today(self):
        """Item 6: the harness must be able to report GREEN on the real file."""
        for name in MUST_BE_IN_BUCKET:
            with self.subTest(workflow=name):
                self.assertTrue(self._matches(self.lint, name))

    def test_dropping_security_scan_from_the_bucket_is_caught(self):
        mutant = apply_mutation(
            self.lint, r"|\.github/workflows/security-scan\.yml", ""
        )
        self.assertFalse(self._matches(mutant, "security-scan.yml"))
        self.assertTrue(
            self._matches(mutant, "lint.yml"),
            "fixture must remove ONLY the security-scan alternative, or the RED "
            "does not isolate the invariant under test",
        )

    def test_dropping_lint_from_the_bucket_is_caught(self):
        mutant = apply_mutation(self.lint, r"|\.github/workflows/lint\.yml|", "|")
        self.assertFalse(self._matches(mutant, "lint.yml"))

    def test_a_commented_out_bucket_is_not_the_live_one(self):
        """The bucket line duplicated into a comment ABOVE the real one must not be
        what gets read. Without comment stripping, `re.search` would find the
        comment first and report on a bucket the runner never evaluates."""
        real = (
            """            echo "scanner=$(match '^(scanner/|scripts/|hooks/"""
            """|Dockerfile|docker-compose|requirements.*\\.txt|lychee\\.toml$"""
            """|\\.github/workflows/lint\\.yml|\\.github/workflows/security-scan\\.yml)')\""""
        )
        # No `assertIn(real, self.lint)` staleness check here on purpose: it would
        # be a presence assertion against the RAW file (the inert-guard shape
        # `test_ci_guard_assertion_scoping` flags), and `apply_mutation` below
        # already raises at the mistake site if the anchor has gone stale.
        decoy = """            # echo "scanner=$(match '^(decoy/)')\"\n"""
        mutant = apply_mutation(self.lint, real, decoy + real)
        self.assertTrue(
            self._matches(mutant, "security-scan.yml"),
            "a commented-out decoy bucket was read instead of the live one",
        )
        self.assertFalse(self._matches(mutant, "decoy/x"))

    def test_guarded_workflow_discovery_is_populated(self):
        """The derived denominator must not be empty, or the coverage test passes
        vacuously."""
        derived = guarded_workflows()
        self.assertIn("security-scan.yml", derived)
        self.assertIn("lint.yml", derived)
        self.assertGreaterEqual(len(derived), 10, f"only found {sorted(derived)}")

    # --- the bucket must be WIRED to the job, not merely correct ---------------

    def test_control_the_real_job_reads_the_bucket(self):
        """Item 6: the detector must be able to report GREEN on the real file."""
        expr, problems = job_gate_expression(self.lint, JOB)
        self.assertEqual(problems, [])
        self.assertIsNotNone(expr, f"`{JOB}` has no job-level `if:` on the real file")
        self.assertIn(BUCKET_OUTPUT_REF, expr)

    def test_rewiring_the_job_gate_to_another_bucket_is_caught(self):
        """THE bypass adversarial review found. Deliberately mutates only the
        output NAME, so the bucket alternation stays byte-for-byte perfect and the
        RED can come from nothing else."""
        assert_disables(
            bucket_gate_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "    if: needs.changes.outputs.scanner == 'true'"
                " || github.event_name == 'schedule'",
                "    if: needs.changes.outputs.markdown == 'true'"
                " || github.event_name == 'schedule'",
            ),
            "pytest job gated on a different bucket",
        )

    def test_removing_the_job_gate_entirely_stays_green(self):
        """Direction. An UNGATED job always runs, so it cannot skip the guards —
        deleting the `if:` is a CI-cost regression, not a coverage one, and a guard
        that reddens on it would be wrong."""
        mutant = apply_mutation(
            self.lint,
            "    if: needs.changes.outputs.scanner == 'true'"
            " || github.event_name == 'schedule'\n",
            "",
        )
        self.assertIsNone(job_gate_expression(mutant, JOB)[0])
        self.assertEqual(bucket_gate_problems(mutant), [])

    def test_a_step_level_if_is_not_the_job_gate(self):
        """The job has several step-level `if:` keys. A whole-block search would
        return one of them and read green after the JOB gate was rewired."""
        mutant = apply_mutation(
            self.lint,
            "    if: needs.changes.outputs.scanner == 'true'"
            " || github.event_name == 'schedule'",
            "    if: needs.changes.outputs.markdown == 'true'"
            " || github.event_name == 'schedule'\n"
            "    # a step below still mentions the scanner bucket:",
        )
        self.assertTrue(
            bucket_gate_problems(mutant),
            "a step-level or commented mention of the bucket was accepted as the "
            "job gate",
        )

    def test_explicit_key_if_fails_closed(self):
        """`? if` is valid YAML no line matcher can read. It must be reported, not
        silently treated as an absent (and therefore safe) gate."""
        mutant = apply_mutation(
            self.lint,
            "    if: needs.changes.outputs.scanner == 'true'"
            " || github.event_name == 'schedule'",
            "    ? if\n    : needs.changes.outputs.markdown == 'true'",
        )
        problems = bucket_gate_problems(mutant)
        self.assertTrue(problems)
        self.assertIn("explicit-key", problems[0])

    def test_quoted_job_gate_key_is_still_read(self):
        """`"if":` is the #391/#393 quoted-key class. The gate must stay readable,
        or quoting the key would make a rewired gate invisible again."""
        mutant = apply_mutation(
            self.lint,
            "    if: needs.changes.outputs.scanner == 'true'",
            '    "if": needs.changes.outputs.scanner == \'true\'',
        )
        self.assertEqual(bucket_gate_problems(mutant), [])
        mutant2 = apply_mutation(
            self.lint,
            "    if: needs.changes.outputs.scanner == 'true'",
            '    "if": needs.changes.outputs.markdown == \'true\'',
        )
        self.assertTrue(bucket_gate_problems(mutant2))


class TestExemptionVerdictIsNonVacuous(unittest.TestCase):
    """Mutation self-tests for the RUNS_ELSEWHERE rc-swallow rule.

    Anchored on `dashboard-control-smoke.yml`, whose steps name their tests in a
    `run:` directly. `cross-os-checks.yml` reaches its two through a matrix value
    and is covered only by the reference check (MATRIX_INDIRECTION)."""

    OWNER = "dashboard-control-smoke.yml"
    TEST = "test_asset_dashboard_control_liveness.sh"

    def setUp(self):
        self.text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")

    def _problems(self, text):
        return exemption_swallow_problems(text, self.OWNER, self.TEST)

    def test_control_the_real_owner_gates_the_test(self):
        """Item 6: GREEN on the real file, or every RED below is meaningless."""
        self.assertEqual(self._problems(self.text), [])

    def test_step_level_continue_on_error_is_caught(self):
        """THE bypass adversarial review found."""
        assert_disables(
            self._problems,
            self.text,
            apply_mutation(
                self.text,
                "      - name: Run asset dashboard control-liveness smoke\n",
                "      - name: Run asset dashboard control-liveness smoke\n"
                "        continue-on-error: true\n",
            ),
            "exempted test's step swallows its rc",
        )

    def test_step_level_if_is_caught(self):
        """A step that may not run is not a verdict either."""
        self.assertTrue(
            self._problems(
                apply_mutation(
                    self.text,
                    "      - name: Run asset dashboard control-liveness smoke\n",
                    "      - name: Run asset dashboard control-liveness smoke\n"
                    "        if: false\n",
                )
            )
        )

    def test_job_level_continue_on_error_is_caught(self):
        """One level out, the same defect — the class `block_ends_at`'s docstring
        records as a live three-way bypass on `security-scan.yml`."""
        self.assertTrue(
            self._problems(
                apply_mutation(
                    self.text,
                    "  smoke:\n",
                    "  smoke:\n    continue-on-error: true\n",
                )
            )
        )

    def test_dropping_the_invocation_is_caught(self):
        """A step that mentions the test in its `name:` but no longer runs it."""
        self.assertTrue(
            self._problems(
                apply_mutation(
                    self.text,
                    "run: bash scanner/tests/test_asset_dashboard_control_liveness.sh",
                    'run: echo "skipped"',
                )
            )
        )

    def test_matrix_indirection_table_has_no_ghosts(self):
        """An entry here opts a test out of the verdict check, so it must be a real
        RUNS_ELSEWHERE name — otherwise the table could exempt a future file."""
        stray = sorted(MATRIX_INDIRECTION - set(RUNS_ELSEWHERE))
        self.assertEqual(stray, [], f"MATRIX_INDIRECTION names non-exempt tests: {stray}")


class TestShellTestRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.disk = shell_tests_on_disk()

    def test_lint_yml_exists(self):
        """Canary: a moved/renamed workflow must fail loudly, not vacuously."""
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_disk_set_is_populated(self):
        """Canary: an empty denominator satisfies 'everything is registered'."""
        self.assertGreaterEqual(
            len(self.disk), 40,
            f"only {len(self.disk)} `{SHELL_TEST_GLOB}` files found — the glob or "
            "the test directory moved, so this guard would pass vacuously.",
        )

    def test_job_block_is_locatable(self):
        registered, problems = registered_in_job(self.raw)
        self.assertEqual(problems, [], "; ".join(problems))
        self.assertGreaterEqual(
            len(registered), 40,
            f"only {len(registered)} shell tests are executed by `{JOB}` — the "
            "explicit list was gutted.",
        )

    def test_every_shell_test_is_registered_or_documented(self):
        registered, problems = registered_in_job(self.raw)
        self.assertEqual(problems, [], "; ".join(problems))
        missing = [
            name for name in self.disk
            if name not in registered and name not in RUNS_ELSEWHERE
        ]
        self.assertEqual(
            missing, [],
            "these `scanner/tests/test_*.sh` files are not executed by the "
            f"`{JOB}` job, so nothing that can fail runs them on the fast path:\n"
            + "\n".join(f"  - {m}" for m in missing)
            + f"\n\nAdd one step per file to `{JOB}` in .github/workflows/lint.yml:\n"
            "      - name: Run bash unit tests (<what it covers>)\n"
            "        run: bash scanner/tests/<file>\n"
            "If the test genuinely cannot run there (needs another runner OS or a "
            "browser), add it to RUNS_ELSEWHERE in this file with the workflow "
            "that does run it.",
        )

    def test_runs_elsewhere_table_has_no_ghosts(self):
        """A stale entry is a hole: it exempts a name nothing checks."""
        gone = sorted(set(RUNS_ELSEWHERE) - set(self.disk))
        self.assertEqual(
            gone, [],
            f"RUNS_ELSEWHERE exempts files that no longer exist: {gone}. Remove "
            "the entries so the table cannot exempt a future file by that name.",
        )

    def test_runs_elsewhere_is_really_run_there(self):
        """The exemption must name a workflow that really references the test.

        Weaker than the `run:`-scoped rule used for the fast path, and
        deliberately so: `cross-os-checks.yml` invokes `bash ${{ matrix.test }}`,
        so the filename lives in a matrix VALUE, and modelling that indirection
        buys nothing for four hand-maintained entries. What it does catch is the
        realistic decay — the owner workflow dropping the test, or keeping only a
        `paths:` trigger mention (subtracted above). Residual: a mention in a
        `name:` would satisfy it.
        """
        known = {Path(p).name for p in workflow_and_action_files()}
        for test_name, owner in sorted(RUNS_ELSEWHERE.items()):
            with self.subTest(test=test_name):
                self.assertIn(
                    owner, known,
                    f"RUNS_ELSEWHERE points {test_name} at {owner}, which is not a "
                    "workflow or composite action file GitHub Actions executes.",
                )
                text = (LINT_YML.parent / owner).read_text(encoding="utf-8")
                self.assertIn(
                    test_name, _strip_trigger_block(text),
                    f"{owner} no longer references {test_name} outside its trigger "
                    "block, so that test now runs nowhere. Register it in "
                    f"`{JOB}` or restore its step in {owner}.",
                )

    def test_the_124_carve_out_requires_the_cap_to_have_fired(self):
        """rc=124 alone must NOT buy the non-fatal arm.

        The kcov loop fails on every non-zero rc except 124, which stays a warning
        because a killed test has no verdict to report (#431). But 124 is not
        exclusively a timeout here: nine of these shell tests end
        `exit "$TEST_FAILED"` — the COUNT of failed assertions — and
        `test_output_functions.sh` runs 206, so 124 red assertions exit 124.
        Executing the real branch against rc=124/elapsed=1 produced
        `::warning:: TIMED OUT` and a green step. `timeout 30` cannot kill sooner
        than 30s, so the fix is to conjoin `elapsed`, and this pins it: dropping
        the second test restores the laundering path silently.
        """
        active = strip_comment_lines(self.raw)
        m = re.search(r'if\s+\[\s*"\$rc"\s+-eq\s+124\s*\](?P<rest>[^\n]*)', active)
        self.assertIsNotNone(
            m,
            "could not find the `rc -eq 124` carve-out in lint.yml's kcov loop — it "
            "was restructured, so this guard cannot verify the cap condition.",
        )
        self.assertRegex(
            m.group("rest"),
            r'&&\s*\[\s*"\$elapsed"\s+-ge\s+30\s*\]',
            "the rc=124 arm is not conjoined with an `elapsed >= 30` test, so a "
            "124-VALUED assertion verdict (124 failed assertions) is laundered into "
            "the non-fatal TIMED OUT arm and the step reads green.",
        )

    def test_exemptions_run_in_a_step_that_can_fail(self):
        """An exemption must point at a VERDICT, not at a mention.

        `test_runs_elsewhere_is_really_run_there` above proves the owner still
        references the test. That is necessary and not sufficient: a referenced
        test whose step carries `continue-on-error` runs and reports nothing, so
        the exemption survives while the gate it promised is gone."""
        for test_name, owner in sorted(RUNS_ELSEWHERE.items()):
            with self.subTest(test=test_name):
                text = (LINT_YML.parent / owner).read_text(encoding="utf-8")
                self.assertEqual(
                    exemption_swallow_problems(text, owner, test_name), [],
                )

    def test_offline_guard_covers_the_dashboard_tests(self):
        """The dashboard tests are only safe in this job because of the job-level
        `CLAUDESEC_DASHBOARD_OFFLINE`.

        Registering `test_generate_html_dashboard.sh` / `test_output_coverage.sh`
        put `generate_html_dashboard()` on the fast path. Without the guard,
        `dashboard-gen.py` makes live GitHub API calls (#190: 120s -> 3.7s with
        it). Asserted one level INSIDE the job's own derived key column, so a
        step-level `env:` for a single step cannot pass for the job-wide guarantee,
        and so dedenting the job body (valid YAML, a cosmetic diff) does not walk
        the assertion off its target the way a hardcoded `^ {4}` would.
        """
        block = job_block(self.raw, JOB)
        self.assertIsNotNone(block, f"job `{JOB}` not found")
        job_col = key_column(block)
        self.assertIsNotNone(job_col, f"job `{JOB}` has an empty body")
        pat = re.compile(
            rf"^ {{{job_col + 2}}}{yaml_key_pattern('CLAUDESEC_DASHBOARD_OFFLINE')}"
            r"\s*:\s*['\"]?1['\"]?\s*$"
        )
        hits = [ln for ln in block.splitlines() if pat.match(strip_inline_comment(ln))]
        self.assertTrue(
            hits,
            f"`{JOB}` has no job-level CLAUDESEC_DASHBOARD_OFFLINE: \"1\". The "
            "dashboard shell tests registered in this job would make live GitHub "
            "API calls and can hang for minutes (#190).",
        )


class TestRegistrationDetectorIsNonVacuous(unittest.TestCase):
    """Mutation self-tests. Each plants the filename somewhere that does NOT
    execute and requires the collector to still report it missing — the failure
    mode a raw substring guard has, which `main` would have hit on two real
    comments."""

    TARGET = "test_print_summary_score_to_grade.sh"

    def setUp(self):
        self.lint = LINT_YML.read_text(encoding="utf-8")
        self.step = (
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            f"        run: bash scanner/tests/{self.TARGET}\n"
        )

    def _missing(self, text):
        registered, problems = registered_in_job(text)
        self.assertEqual(problems, [], "; ".join(problems))
        return self.TARGET not in registered

    def test_control_the_real_file_registers_the_target(self):
        """Item 6 of the probe checklist: prove the harness can report GREEN on the
        real file before trusting any RED it produces."""
        self.assertFalse(
            self._missing(self.lint),
            f"{self.TARGET} is not detected as registered in the REAL lint.yml — "
            "the collector is broken, so every RED below is meaningless.",
        )

    def test_deleting_the_step_is_caught(self):
        self.assertTrue(self._missing(apply_mutation(self.lint, self.step, "")))

    def test_commenting_out_the_step_is_caught(self):
        """The plain-deletion sibling: the token is still in the file, in a YAML
        comment. This is the shape that defeats a raw-text presence check."""
        commented = "".join(f"      # {ln.strip()}\n" for ln in self.step.splitlines())
        mutant = apply_mutation(self.lint, self.step, commented)
        self.assertIn(self.TARGET, mutant, "fixture must keep the token in the file")
        self.assertTrue(self._missing(mutant))

    def test_name_only_mention_is_not_registration(self):
        """The filename moved into the step's `name:` — it reads like a step and
        executes nothing."""
        mutant = apply_mutation(
            self.lint, self.step,
            f"      - name: Run bash unit tests (scanner/tests/{self.TARGET})\n"
            "        run: true\n",
        )
        self.assertIn(self.TARGET, mutant)
        self.assertTrue(self._missing(mutant))

    def test_bash_comment_inside_a_block_scalar_is_not_registration(self):
        """Inside `run: |` the body is SHELL, so a `#` line does not execute. This
        is how the kcov job's own comments name two tests without running them."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: |\n"
            f"          # bash scanner/tests/{self.TARGET}\n"
            "          true\n",
        )
        self.assertIn(self.TARGET, mutant)
        self.assertTrue(self._missing(mutant))

    def test_block_scalar_run_does_register(self):
        """The other direction, so the block-scalar branch is proven to be ENTERED
        rather than merely present (#378's inert self-test lesson): the same step
        rewritten as a block scalar must still count."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: |\n"
            f"          bash scanner/tests/{self.TARGET}\n",
        )
        self.assertFalse(
            self._missing(mutant),
            "a `run: |` block scalar must count as registration — the collector's "
            "block-scalar branch is not working.",
        )

    def test_every_block_scalar_header_ordering_is_collected(self):
        """Pins the adversarial finding that produced `_BLOCK_SCALAR_RE`'s current
        form. YAML allows the chomping and explicit-indentation indicators in EITHER
        order, and the first draft matched only `[+-]?\\d*`, so `|2-`, `>2-` and
        `|2+` were read as plain inline values and their shell bodies were never
        collected. All eleven spellings below parse (checked against PyYAML while
        writing this); none may be missed.
        """
        for header in ("|", "|-", "|+", ">", ">-", ">+",
                       "|2", "|-2", "|2-", "|+2", "|2+"):
            with self.subTest(header=header):
                mutant = apply_mutation(
                    self.lint, self.step,
                    "      - name: Run bash unit tests (print_summary score-to-grade)\n"
                    f"        run: {header}\n"
                    f"          bash scanner/tests/{self.TARGET}\n",
                )
                self.assertFalse(
                    self._missing(mutant),
                    f"a `run: {header}` block scalar body was not collected",
                )

    def test_trailing_yaml_comment_does_not_hide_a_real_step(self):
        """False-alarm direction: `run: bash x.sh  # note` still registers."""
        mutant = apply_mutation(
            self.lint, self.step,
            self.step.replace(
                f"{self.TARGET}\n", f"{self.TARGET}  # slowest of the three\n"
            ),
        )
        self.assertFalse(self._missing(mutant))

    def test_a_new_unregistered_test_file_is_caught(self):
        """The forward-looking case: a file appears on disk with no step. Uses the
        real detector against a disk list with one extra name, since the guard's
        job is exactly this comparison."""
        registered, problems = registered_in_job(self.lint)
        self.assertEqual(problems, [], "; ".join(problems))
        disk = shell_tests_on_disk() + ["test_brand_new_thing.sh"]
        missing = [
            n for n in disk if n not in registered and n not in RUNS_ELSEWHERE
        ]
        self.assertEqual(missing, ["test_brand_new_thing.sh"])

    def test_renaming_the_job_fails_closed(self):
        """A vanished job must be a PROBLEM, not an empty registered set silently
        reported as 'all 54 missing' (or, worse, as nothing at all)."""
        mutant = apply_mutation(self.lint, f"\n  {JOB}:\n", "\n  scanner-unit-tsets:\n")
        registered, problems = registered_in_job(mutant)
        self.assertEqual(registered, set())
        self.assertTrue(problems, "renamed job must be reported as a problem")
        self.assertIn(JOB, problems[0])

    def test_explicit_key_run_fails_closed(self):
        """`? run` / `: value` is the same mapping key with the substring `run:`
        absent, so it is unscannable rather than unmatched. Tripwire, per the
        `unscannable_run_keys` precedent."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        ? run\n"
            f"        : bash scanner/tests/{self.TARGET}\n",
        )
        _, problems = registered_in_job(mutant)
        self.assertTrue(problems, "explicit-key form must be reported")
        self.assertIn("explicit-key", problems[0])

    def test_offline_guard_removal_is_caught(self):
        mutant = apply_mutation(
            self.lint, '      CLAUDESEC_DASHBOARD_OFFLINE: "1"\n', ""
        )
        t = TestShellTestRegistration()
        t.raw = mutant
        t.disk = shell_tests_on_disk()
        with self.assertRaises(AssertionError):
            t.test_offline_guard_covers_the_dashboard_tests()


class TestRunsElsewhereOwnershipIsNonVacuous(unittest.TestCase):
    """The ownership check needs its own mutation proof: it is the only thing
    standing between `RUNS_ELSEWHERE` and a parking lot for unrun tests."""

    OWNER = "cross-os-checks.yml"
    TEST = "test_check_macos_cis_security_live.sh"

    def setUp(self):
        self.text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")

    def test_control_owner_really_references_the_test(self):
        self.assertIn(self.TEST, _strip_trigger_block(self.text))

    def test_dropping_the_matrix_entry_is_caught(self):
        mutant = apply_mutation(
            self.text, f"            test: scanner/tests/{self.TEST}\n", ""
        )
        self.assertNotIn(self.TEST, _strip_trigger_block(mutant))

    def test_paths_only_mention_is_not_ownership(self):
        """POSITIVE CONTROL for `_strip_trigger_block`. The matrix entry is gone but
        the `on.pull_request.paths` mention remains, so the raw file still contains
        the name — only the subtraction distinguishes them. Without it this
        assertion would pass with the test running nowhere."""
        mutant = apply_mutation(
            self.text, f"            test: scanner/tests/{self.TEST}\n", ""
        )
        self.assertIn(
            self.TEST, mutant,
            "fixture must leave the `paths:` mention in place, or it proves nothing",
        )
        self.assertIn(f"- 'scanner/tests/{self.TEST}'", mutant)
        self.assertNotIn(self.TEST, _strip_trigger_block(mutant))


if __name__ == "__main__":
    unittest.main()
