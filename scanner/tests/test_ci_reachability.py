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

The denominator is `scanner/tests/test_*.sh`, NON-recursively, matching the kcov
loop's own glob. A test one directory down is therefore reached by neither runner
AND absent from the denominator, so `test_no_shell_test_hides_in_a_subdirectory`
keeps the directory flat rather than silently changing which files CI runs.

WHAT COUNTS AS "REGISTERED" — and why it is not a substring search
-----------------------------------------------------------------
An INVOCATION inside text the runner EXECUTES. Two independent narrowings, each
of which was found to be load-bearing by adversarial review:

1. EXECUTED text only — the value of a `run:` key inside the `scanner-unit-tests`
   job, with YAML comment lines dropped, bash comments stripped inside a `run:`
   block scalar, and any OTHER key's block scalar consumed and discarded.
   `lint.yml` on `main` at the time of writing MENTIONED `test_output_coverage.sh`
   and `test_print_summary_score_to_grade.sh` in the kcov job's explanatory
   comments while executing neither from the fast path, and a `NOTE: |` body
   holding a `run:`-shaped line reads as a step to a line matcher while PyYAML
   reports the step's shell as `true`.
2. An INVOCATION, not an appearance — the path must sit at a command position
   after an interpreter or `./`. The runner really does execute
   `run: echo "TEMPORARILY DISABLED: bash scanner/tests/test_checks_helpers.sh"`;
   nothing in it executes the test, and the earlier bare-path matcher counted it.

Every mutation self-test below plants the filename somewhere non-executing (a
comment, a step `name:`, a commented-out step, another key's block scalar, an
`echo`) and requires it to still be reported missing.

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

KNOWN LIMITATIONS
-----------------
FALSE-ALARM direction (the guard sees less than the runner, so it over-reports;
none of these can hide an unregistered test):
- A `run:` written as a multi-line FOLDED PLAIN scalar (`run: bash` on one line,
  the path on the next) is read as only its first line, so the path would be
  missed and the test reported unregistered. No such step exists; the fix is to
  write it on one line or use `run: |`.
- The path must carry its `scanner/tests/` prefix, which is how every step in the
  job invokes it. `cd scanner/tests && bash test_x.sh` would be missed.
- The interpreter must be at a command position, or be `pty_run.py bash` — the one
  launcher in use. Another wrapper (`timeout 30 bash x.sh`) is not recognized; add
  the specific wrapper to `_INVOCATION_PREFIX` rather than admitting arbitrary
  leading words, which would re-admit `echo bash x.sh`.

FALSE-NEGATIVE direction (can hide an unrun test), documented rather than closed:
- HEREDOC bodies inside a real `run: |` are not modelled, so an invocation quoted
  in one (`cat <<'EOF'` / `bash scanner/tests/test_x.sh` / `EOF`) counts as
  registration. Same limitation `strip_inline_comment_sh` documents; no step in
  this repo writes one, and closing it needs a heredoc state machine.
- The command-position test is not quote-aware, so `echo "DISABLED; bash
  scanner/tests/test_x.sh"` counts. See `_INVOCATION_PREFIX` for why masking
  quoted spans would be a worse trade.

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
Eleven further workflows and the two composite actions under `.github/actions/`
are named by guards and remain outside the bucket (`KNOWN_BUCKET_GAP`). Closing
all of them would make every workflow-only PR — most of them Dependabot action
bumps — run the full scanner + kcov set, and this repo path-gates deliberately for
CI cost (#180/#181). The two admitted here are the ones where a skipped guard
silently weakens a BRANCH-PROTECTION-REQUIRED check (`Lint`,
`Security Scan Gate`).

The composite actions used to be `continue`d out of the derived set with the
reason "not path-gated by this bucket", which restated the hole instead of
deciding it — so, alone among executable Actions files, they got no in-or-out
decision. They are now keyed by PATH (both are named `action.yml`, so a basename
key would collide them) and classified, which also means a NEW composite action
lands in neither table and fails until someone classifies it.

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
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    apply_regex_mutation,
    assert_disables,
    block_ends_at,
    explicit_key_lines,
    job_block,
    key_column,
    key_line,
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
SHELL_TEST_DIR = "scanner/tests"
SHELL_TEST_GLOB = f"{SHELL_TEST_DIR}/test_*.sh"
# The same names at ANY depth. The glob above is non-recursive and so is the kcov
# loop's `for sh in scanner/tests/test_*.sh`, so a nested test is invisible to
# BOTH — see `test_no_shell_test_hides_in_a_subdirectory`.
RECURSIVE_SHELL_TEST_GLOB = f"{SHELL_TEST_DIR}/**/test_*.sh"
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
# rejects a name that is not on disk, `test_runs_elsewhere_is_really_run_there`
# rejects one no step of its owner INVOKES (directly or through the verified
# matrix indirection), and `test_exemptions_run_in_a_step_that_can_fail` rejects
# one whose step or job can swallow the verdict.
RUNS_ELSEWHERE = {
    "test_check_macos_cis_security_live.sh": "cross-os-checks.yml",
    "test_check_windows_kisa_security_live.sh": "cross-os-checks.yml",
    "test_dashboard_control_liveness.sh": "dashboard-control-smoke.yml",
    "test_asset_dashboard_control_liveness.sh": "dashboard-control-smoke.yml",
}

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

# An INVOCATION, not a mention. The path must sit where a shell would actually
# run it: at a command position (start of line, or after `;`, `&`, `|`, `(`,
# `&&`, `||`), introduced by an interpreter or by `./`.
#
# The bare-path version this replaces counted any appearance of the path in an
# executed `run:`, so
#
#     run: echo "TEMPORARILY DISABLED: bash scanner/tests/test_checks_helpers.sh"
#
# read as registration at `47 passed` — the runner really does execute that step,
# and nothing in it executes the test. Requiring an interpreter is not sufficient
# on its own (the string above CONTAINS `bash `); the command position is what
# rejects it, because `:` and `"` are not command separators.
#
# `pty_run.py` is admitted explicitly because it is the one launcher this repo
# uses (`python3 scanner/tests/pty_run.py bash scanner/tests/test_aws_sso_tty.sh`),
# where `bash` is an ARGUMENT and not at a command position.
#
# KNOWN LIMITATION, false-alarm direction: any OTHER wrapper before the
# interpreter (`timeout 30 bash x.sh`, `env FOO=1 bash x.sh`) is not recognized
# and would be reported unregistered. No step in `scanner-unit-tests` uses one;
# admitting arbitrary leading words would re-admit `echo bash x.sh`, so the
# remedy is to add the specific wrapper here, as `pty_run.py` was.
#
# KNOWN LIMITATION, false-negative direction: the command-position test is not
# quote-aware, so a separator INSIDE a string still reads as one —
# `run: echo "DISABLED; bash scanner/tests/test_x.sh"` counts as registration
# (measured). Strictly narrower than the bare-path matcher this replaced, which
# needed no separator at all. NOT closed on purpose: masking quoted spans before
# matching trades it for a worse false-alarm class, since an apostrophe in
# ordinary prose (`echo don't && bash x.sh`) would swallow the rest of the line
# and hide a real invocation (#414 — a guard broken by ordinary authoring gets
# weakened by its users).
_INVOCATION_PREFIX = (
    r"(?:^|[;&|({]|&&|\|\|)[ \t]*"         # command position, incl. a brace group
    r"['\"]?"                               # a quoted `run:` VALUE
    r"(?:python3\s+\S*pty_run\.py\s+)?"    # the one launcher in use
    r"(?:(?:bash|sh)[ \t]+(?:-\S+[ \t]+)*|\./)"  # interpreter (+options), or ./
    r"['\"]?"                               # a quoted path
    r"(?:\./)?"
)
_SHELL_TEST_INVOCATION_RE = re.compile(
    _INVOCATION_PREFIX + rf"{SHELL_TEST_DIR}/(test_[A-Za-z0-9_]+\.sh)", re.M
)


def shell_tests_on_disk() -> list:
    """Every shell test file name, sorted. The denominator of the whole guard."""
    return sorted(Path(p).name for p in glob.glob(str(REPO_ROOT / SHELL_TEST_GLOB)))


def nested_shell_tests() -> list:
    """`test_*.sh` files BELOW `scanner/tests/`, repo-relative, sorted.

    Must stay empty: see `test_no_shell_test_hides_in_a_subdirectory`."""
    top = set(glob.glob(str(REPO_ROOT / SHELL_TEST_GLOB)))
    return sorted(
        str(Path(p).relative_to(REPO_ROOT))
        for p in glob.glob(str(REPO_ROOT / RECURSIVE_SHELL_TEST_GLOB), recursive=True)
        if p not in top
    )


def executed_shell(text: str) -> str:
    """The shell the runner would EXECUTE from every `run:` in `text`.

    Handles both spellings a step may use, and drops what does not execute:

    - a whole-line YAML `#` comment is skipped;
    - a plain inline value has its trailing YAML comment stripped;
    - a block scalar (`run: |`, `run: >-`, `run: |2`) contributes its indented
      body, each line passed through the bash-aware comment stripper, because that
      body is SHELL and a `#` line in it does not run;
    - a block scalar belonging to ANY OTHER key is consumed and DISCARDED.

    That last clause is not symmetry for its own sake. Tracking scalar state only
    for `run:` let the scanner walk into every other key's scalar body and match a
    `run:`-shaped line inside it — a real step, at `47 passed`, while PyYAML
    reported the executed shell as `true`:

        - name: Note about the helpers test
          env:
            NOTE: |
              run: bash scanner/tests/test_checks_helpers.sh
          run: true

    `key_line` is used rather than a `run:`-only matcher so the consume-and-discard
    arm cannot be bypassed by quoting the owning key (`"env":`).

    The block-scalar branch is also what keeps the kcov job's long explanatory
    comments — which name two shell tests verbatim — from counting as execution.

    KNOWN LIMITATIONS, all in the guard-sees-LESS direction except the last:
    - a `run:` written as a multi-line FOLDED PLAIN scalar is read as only its
      first line;
    - the path must carry its `scanner/tests/` prefix (`cd scanner/tests && bash
      test_x.sh` is missed);
    - HEREDOC bodies inside a real `run: |` are not modelled, so an invocation
      quoted in a heredoc (`cat <<'EOF'` / `bash scanner/tests/test_x.sh` / `EOF`)
      still counts as registration. This one CAN hide an unrun test. It is the same
      limitation `strip_inline_comment_sh` documents, no step in this repo writes
      one, and closing it needs a heredoc state machine rather than a line matcher.
    """
    blocks = step_blocks(text)
    if not blocks:
        # `text` is already a single step block (the exemption helpers pass one),
        # or it contains no `steps:` at all — in which case the scan below finds
        # no step column and credits nothing, which is the fail-safe answer.
        blocks = [text]
    return "\n".join(_executed_shell_of_step(b) for b in blocks)


def _executed_shell_of_step(step: str) -> str:
    """The shell ONE step executes, crediting `run:` only at the step's own column.

    The column restriction is the whole point. Before it, `is_run = name == "run"`
    fired at ANY nesting depth, so a `run:` one level in — under `with:`, `env:`
    or `outputs:` — counted as execution. Adversarial review of #465 measured six
    shapes; the sharpest needs no block scalar at all:

        - name: a
          uses: ./.github/actions/token-expiry-gate
          with:
            run: bash scanner/tests/test_x.sh

    PyYAML: the step has keys `['name', 'uses', 'with']` and NO `run` key. The
    guard reported the test as registered on the fast path, at `61 passed`.
    A step's `run:` is a direct child of its own sequence item, never deeper, so
    the column IS the discriminator.
    """
    col = _seq_item_key_column(step)
    lines = step.splitlines()
    out = []
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        if raw.lstrip().startswith("#"):
            continue
        parsed = key_line(raw)
        if parsed is None:
            continue
        key_col, name, rest = parsed
        rest = strip_inline_comment(rest).strip()
        # `col is None` means the caller handed us something that is not a
        # sequence item; credit nothing rather than guess a column.
        is_run = name == "run" and col is not None and key_col == col
        if _BLOCK_SCALAR_RE.match(rest):
            body = []
            while i < n:
                line = lines[i]
                if line.strip() and (len(line) - len(line.lstrip())) <= key_col:
                    break  # dedent ends the scalar
                i += 1
                body.append(line)
            if is_run:
                out += [strip_inline_comment_sh(b) for b in body]
        elif is_run:
            out.append(rest)
    return "\n".join(out)


def invoked_shell_tests(shell: str) -> set:
    """The shell tests `shell` actually INVOKES, by basename."""
    return set(_SHELL_TEST_INVOCATION_RE.findall(shell))


# A line whose value OPENS a block scalar. Used to find keys `key_line` cannot
# read, whose scalar body would otherwise be walked into as if it were shell.
_BLOCK_SCALAR_TAIL_RE = re.compile(r":\s*[|>][0-9+-]*\s*$")


def unreadable_block_scalar_keys(text: str) -> list:
    """Lines that OPEN a block scalar but whose key `key_line` cannot read.

    `key_line`'s bare-key class is `[^\\s:#]+`, so a REAL YAML key containing a
    space, a `:` or a `#` — and the explicit `? key` / `: |` form — come back as
    None. `executed_shell` then never enters its consume-and-discard arm for that
    key and walks straight into the scalar BODY, where a `run:`-shaped line used
    to read as execution. Adversarial review of #465 measured four such spellings
    (`MY NOTE: |`, `a:b: |`, `a#b: |`, `? env` / `: |`), each making an
    unregistered test read as registered while PyYAML reported the step executing
    `true`.

    The step-column restriction in `_executed_shell_of_step` already closes the
    execution side of that. This is the second half: a scalar whose OWNER cannot
    be identified is a scalar whose body cannot be safely classified, so it is
    REPORTED rather than silently skipped — the same fail-closed convention this
    file already applies to the explicit-key `? run` / `? steps` form.

    Direction: presence of an unreadable owner, not presence of a `run:` inside
    it. Reporting only the ones that happen to contain a shell-test path today
    would make the tripwire depend on the payload it is meant to be blind to.
    """
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw.lstrip().startswith("#"):
            continue
        if not _BLOCK_SCALAR_TAIL_RE.search(strip_inline_comment(raw)):
            continue
        if key_line(raw) is None:
            out.append(f"line {lineno}: {raw.strip()!r}")
    return out


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
    opaque = unreadable_block_scalar_keys(lint_text)
    if opaque:
        problems.append(
            "block scalar opened by a key this scanner cannot read: "
            f"{opaque!r}. Its body cannot be classified, so a `run:`-shaped line "
            "inside it would read as execution. Rewrite the key as a plain, "
            "quoted or unspaced `key: value` so ownership stays verifiable."
        )
    block = job_block(lint_text, JOB)
    if block is None:
        problems.append(
            f"job `{JOB}` not found exactly once in lint.yml — it was renamed, "
            "removed or duplicated. This guard cannot verify registration, and "
            "the shell-test fast path may be gone entirely."
        )
        return set(), problems
    return invoked_shell_tests(executed_shell(block)), problems


# RUNS_ELSEWHERE entries whose owner reaches the test through a matrix VALUE
# (`run: bash ${{ matrix.test }}`) instead of naming it in a `run:`. ENUMERATED,
# never inferred, so a NEW exemption this guard cannot locate FAILS rather than
# silently opting out of the checks below.
#
# The entry no longer WAIVES the invocation check, it SELECTS the mechanism to
# verify: `_matrix_running_steps` must find both halves of the indirection (a
# matrix key whose value is the test, and a step that invokes
# `${{ matrix.<key> }}` as a command), and the steps it finds then go through the
# same rc-swallow checks as a directly-invoked one. Under the previous
# reference-only treatment, rewriting `cross-os-checks.yml`'s
# `run: bash ${{ matrix.test }}` to `run: echo "skipping ${{ matrix.test }}"` left
# both exempted `*_live.sh` tests running NOWHERE at `47 passed`.
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
    """`(job_key, block)` for the job containing `step_block`, or `(None, None)`.

    Matched on the WHOLE step block, and required to be UNIQUE. The first version
    matched the step's first LINE as a substring anywhere in the file, so a second
    job with a byte-identical `- name:` line — a retry job, a split matrix —
    redirected the check. Adversarial review of #465 measured it: with a decoy job
    added, `top_level_jobs` read `['decoy', 'changes', 'smoke']`, the guard picked
    `decoy:`, inspected its `['runs-on', 'steps']`, and reported GREEN while
    PyYAML had `jobs.smoke.continue-on-error = True`.

    Ambiguity is returned as "not found" rather than resolved by guessing, so the
    caller reports a problem instead of validating the wrong job."""
    needle = strip_comment_lines(step_block).strip()
    hits = []
    for job in top_level_jobs(owner_text):
        block = job_block(owner_text, job)
        if block is not None and needle and needle in strip_comment_lines(block):
            hits.append((job, block))
    return hits[0] if len(hits) == 1 else (None, None)


def _matrix_keys_naming(owner_text: str, test_name: str) -> list:
    """Matrix keys whose VALUE is `scanner/tests/<test_name>`, sorted.

    Read with `key_line` over the comment-stripped text, so a quoted key
    (`"test": scanner/tests/x.sh`) is seen and a `paths:` sequence item — which is
    not a mapping key at all — is not."""
    out = set()
    wanted = {f"{SHELL_TEST_DIR}/{test_name}", f"./{SHELL_TEST_DIR}/{test_name}"}
    for raw in strip_comment_lines(owner_text).splitlines():
        parsed = key_line(raw)
        if parsed is None:
            continue
        _, name, rest = parsed
        if strip_inline_comment(rest).strip().strip("\"'") in wanted:
            out.add(name)
    return sorted(out)


def _matrix_invocation_re(key: str):
    """`${{ matrix.<key> }}` INVOKED as a command, not merely interpolated.

    Same command-position rule as `_SHELL_TEST_INVOCATION_RE`, and for the same
    reason: `run: echo "skipping ${{ matrix.test }}"` interpolates the key while
    executing nothing, and a plain presence check reads it as the invocation."""
    return re.compile(
        _INVOCATION_PREFIX + r"\$\{\{\s*matrix\." + re.escape(key) + r"\s*\}\}", re.M
    )


def _matrix_running_steps(owner_text: str, owner: str, test_name: str):
    """`(steps, problems)` for a test reached through a matrix value.

    BOTH halves of the indirection must be present: a matrix key carrying the
    test's path, and a step that invokes that key. Verifying only the first is
    what let the `run:` be rewritten to an `echo` with the guard green."""
    keys = _matrix_keys_naming(owner_text, test_name)
    if not keys:
        return [], [
            f"{owner} is the documented MATRIX_INDIRECTION owner of {test_name} but "
            "no matrix key carries that path any more, so the test runs nowhere. "
            f"Restore the matrix entry or register the test in `{JOB}`."
        ]
    # SAME JOB, both halves. `_matrix_keys_naming` and `step_blocks` are both
    # whole-file, so before this the matrix entry and the step consuming it could
    # sit in two unrelated jobs and still satisfy "both halves present".
    # Adversarial review of #465 moved the macOS matrix entry verbatim into a
    # second, parked job and measured `61 passed` / `Ran 903 tests OK` while the
    # test ran nowhere. A matrix value only reaches a step through its OWN job's
    # `strategy:`, so co-location is the invariant, not co-existence.
    steps = []
    for job in top_level_jobs(owner_text):
        block = job_block(owner_text, job)
        if block is None:
            continue
        job_keys = _matrix_keys_naming(block, test_name)
        if not job_keys:
            continue
        steps += [
            blk for blk in step_blocks(block)
            for key in job_keys
            if _matrix_invocation_re(key).search(executed_shell(blk))
        ]
    if not steps:
        return [], [
            f"{owner} names {test_name} only as the value of matrix key(s) {keys}, "
            "and no step INVOKES that key as a command (`run: bash ${{ matrix."
            f"{keys[0]} }}}}`). Interpolating it in an `echo` runs the step and not "
            "the test — the exemption survives while the verdict disappears."
        ]
    return steps, []


def locate_exemption_steps(owner_text: str, owner: str, test_name: str):
    """`(steps, problems)` — the steps of `owner_text` that RUN `test_name`.

    Fails CLOSED: a test invoked by no executed `run:` and reachable through no
    documented indirection is reported rather than treated as run."""
    steps = [
        blk for blk in step_blocks(owner_text)
        if test_name in invoked_shell_tests(executed_shell(blk))
    ]
    if steps:
        return steps, []
    if test_name in MATRIX_INDIRECTION:
        return _matrix_running_steps(owner_text, owner, test_name)
    return [], [
        f"{owner} names {test_name} but no step's `run:` invokes it, and it is "
        "not in MATRIX_INDIRECTION. Either the step was dropped (the test now "
        "runs nowhere) or the invocation moved behind an indirection this guard "
        "cannot read — add it to MATRIX_INDIRECTION with a reason, or register "
        f"the test in `{JOB}`."
    ]


def exemption_swallow_problems(owner_text: str, owner: str, test_name: str) -> list:
    """Problems with HOW `owner_text` runs `test_name`: located, and can it fail?

    Fails CLOSED in both directions — a test no step invokes is reported, and so
    is one whose step or job can swallow its exit code. Matrix-reached tests get
    the SAME swallow checks as directly-invoked ones; exempting them was the other
    half of the asymmetry that made the two `cross-os-checks.yml` entries less
    protected than the two `dashboard-control-smoke.yml` ones while this table
    presented them as equivalent."""
    running, problems = locate_exemption_steps(owner_text, owner, test_name)
    if problems:
        return problems
    # Fail closed on the explicit-key form for every swallow key. `_keys_at` reads
    # bare and quoted keys but cannot see `? continue-on-error` / `: true`, which
    # adversarial review of #465 measured GREEN at both step and job level while
    # PyYAML reported the key set. Same tripwire convention this file already uses
    # for `run` / `steps` / `if`.
    opaque = explicit_key_lines(
        owner_text, *_SWALLOW_STEP_KEYS, *_SWALLOW_JOB_KEYS
    )
    if opaque:
        return [
            f"{owner}: YAML explicit-key form found for a swallow key, which no "
            f"line matcher can read: {opaque!r}. Rewrite as `key: value` so the "
            f"exemption for {test_name} stays verifiable."
        ]
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
        job_key, job = _enclosing_job_block(owner_text, blk)
        if job is None:
            problems.append(
                f"{owner}: the step running {test_name} is in no UNIQUELY locatable "
                "job. Either no job block contains it, or more than one does — a "
                "second job with an identical step would make this check inspect "
                "the wrong one, so it refuses to guess."
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
        problems += _disabled_job_problems(owner_text, owner, test_name, job_key)
    return problems


# A job `if:` that references NEITHER of these is a constant, and a constant gate
# is a disabled job rather than a conditional one.
_LIVE_GATE_REFS = ("needs.", "github.", "inputs.", "vars.", "env.")


def _disabled_job_problems(owner_text: str, owner: str, test_name: str, job_key):
    """Problems if the exemption's job is switched OFF rather than gated.

    `if` is a step-level swallow key but was NOT a job-level one, even though
    `test_job_level_continue_on_error_is_caught` says "one level out, the same
    defect". Adversarial review of #465 put `if: false` on `cross-os-checks.yml`'s
    matrix job and measured `61 passed` / `Ran 903 tests OK` with both `*_live.sh`
    exemptions running nowhere on the platform they exist for. Reproduced here
    before the fix.

    It cannot simply be added to `_SWALLOW_JOB_KEYS`: `dashboard-control-smoke.yml`
    legitimately carries a job-level `if: needs.changes.outputs.dashboard == 'true'`
    path gate, and presence-matching would redden the real file. So the rule is
    about the EXPRESSION — a gate that consults something (`needs.`, `github.`,
    `inputs.`, `vars.`, `env.`) is a path/event gate and fine; one that consults
    nothing is a constant, and a constant gate is an off switch.

    Deliberately conservative in the other direction: an expression this cannot
    classify is treated as LIVE, because a false alarm on a legitimate gate is the
    failure mode that gets a guard deleted (#414)."""
    if job_key is None:
        return []
    expr, gate_problems = job_gate_expression(owner_text, job_key)
    if gate_problems:
        return [f"{owner}: {p}" for p in gate_problems]
    if expr is None:
        return []
    if any(ref in expr for ref in _LIVE_GATE_REFS):
        return []
    return [
        f"{owner}: the JOB running {test_name} is gated on `if: {expr}`, which "
        f"references none of {list(_LIVE_GATE_REFS)} — it is a CONSTANT, so the job "
        f"never runs. `{test_name}` is EXEMPT from registration in `{JOB}` on the "
        "promise that this job gates it; a job switched off keeps the exemption "
        "while the verdict disappears."
    ]


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
#
# The two `.github/actions/**/action.yml` entries are keyed by PATH, not basename,
# because both composite actions are named `action.yml` and a basename key would
# collide. They used to be `continue`d out of the derived set entirely, with the
# reason "composite actions are not path-gated by this bucket" — which restated the
# hole instead of deciding it. They ARE guarded (`workflow_and_action_files()`
# scans `.github/actions/**`, and `test_ci_injection_surface` /
# `test_ci_template_pin_policy` scan them), and the bucket does not match them:
#
#     .github/actions/token-expiry-gate/action.yml   -> False
#     .github/actions/datadog-ci-collect/action.yml  -> False
#
KNOWN_BUCKET_GAP = {
    ".github/actions/datadog-ci-collect/action.yml":
        "guards reached via the `ci-guards` job, not the `scanner` bucket",
    ".github/actions/token-expiry-gate/action.yml":
        "guards reached via the `ci-guards` job, not the `scanner` bucket",
    "cross-os-checks.yml": "non-required macOS/Windows matrix (weekly + path-gated)",
    "dashboard-control-smoke.yml": "non-required headless-Chrome smoke",
    "dast-baseline.yml": "non-required DAST",
    "dast-freshness-watch.yml": "nightly-DAST liveness notifier",
    "dast-full-scan.yml": "non-required nightly DAST",
    "dependabot-auto-merge.yml": "automation, not a check",
    "lighthouse.yml": "non-required perf audit",
    "lychee-redirect-sweep.yml": "monthly notifier",
    "npm-publish.yml": "release-time only, runs on tag/version bump",
    "og-meta-verify.yml": "non-required metadata check",
    "protection-drift-watch.yml": "scheduled drift notifier",
    "prowler-python-watch.yml": "scheduled alpine-unblock notifier",
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


COMPOSITE_ENTRYPOINTS = ("action.yml", "action.yaml")


def _bucket_key(path: Path) -> str:
    """The table key for an executable Actions file.

    A workflow is keyed by BASENAME (unique under `.github/workflows/`); a
    composite action by its repo-relative PATH, because every composite action is
    named `action.yml` and a basename key would make the two collide into one
    entry — silently classifying both by whichever was seen last."""
    if path.name in COMPOSITE_ENTRYPOINTS:
        # `path.parent.name` was the LEAF directory only, which reproduced the
        # very collision this docstring claims to fix: adversarial review of #465
        # showed `actions/aws/deploy/action.yml` and `actions/gcp/deploy/action.yml`
        # both keying to `.github/actions/deploy/action.yml` — one classification
        # silently covering two actions, and `_bucket_path` then measuring the
        # bucket regex against a path that does not exist. `uses: ./.github/
        # actions/aws/deploy` is valid and `workflow_and_action_files()` globs
        # `**/action.yml` recursively, so nesting is reachable.
        # Every directory level from the `actions` component down, so
        # `actions/aws/deploy/action.yml` and `actions/gcp/deploy/action.yml` key
        # DISTINCTLY. Anchored on the component rather than on `REPO_ROOT` or
        # `ACTION_DIR` because the self-tests swap `ACTION_DIR` to a tempdir, and
        # a module-level import of it would be a stale snapshot while
        # `relative_to(REPO_ROOT)` would raise on the tempdir path.
        parts = path.parts
        if "actions" in parts:
            start = len(parts) - 1 - parts[::-1].index("actions")
            return ".github/" + "/".join(parts[start:])
        return path.as_posix()
    return path.name


def _bucket_path(key: str) -> str:
    """The repo-relative path the `changes` job's `grep -E` would see for `key`."""
    return key if "/" in key else f".github/workflows/{key}"


def guarded_workflows() -> dict:
    """`{table key: [guard files naming it]}`, DERIVED, not listed.

    Any `test_ci_*.py` mentioning a workflow's filename is treated as guarding it.
    Deliberately generous: the question is "would a reviewer expect this guard to
    run when that workflow changes", and a mention is the cheapest complete proxy.
    Over-inclusion only forces an in-or-out decision, never hides one.

    Composite actions used to be skipped here, which meant a PR editing only
    `.github/actions/<name>/action.yml` got no in-or-out decision at all — a
    silent `continue` where every workflow gets a classified entry. They are
    matched on their ENTRYPOINT NAME as well as their directory name, because that
    is how a guard reaches them: none lists them individually, they arrive through
    `workflow_and_action_files()`, which enumerates `action.yml`/`action.yaml`. The
    consequence is intended — a NEW composite action is guarded by construction, so
    it lands in neither table and fails until someone classifies it."""
    out = {}
    guards = sorted(Path(REPO_ROOT / "scanner" / "tests").glob("test_ci_*.py"))
    texts = {g.name: g.read_text(encoding="utf-8") for g in guards}
    for wf in workflow_and_action_files():
        path = Path(wf)
        tokens = {path.name}
        if path.name in COMPOSITE_ENTRYPOINTS:
            tokens.add(path.parent.name)
        namers = sorted(g for g, t in texts.items() if any(tok in t for tok in tokens))
        if namers:
            out[_bucket_key(path)] = namers
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
                path = _bucket_path(name)
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

    def test_composite_actions_get_a_classification(self):
        """Composite actions were `continue`d out of the derived set, so a PR
        editing only `.github/actions/<name>/action.yml` got no in-or-out decision
        at all — while every workflow got one. They are guarded
        (`test_ci_injection_surface`, `test_ci_template_pin_policy`) and the bucket
        does not match them, so the honest outcome is a classified entry.

        Asserted on the DERIVED set rather than on the literal table, so this fails
        for a new composite action too (via
        `test_bucket_membership_lists_cover_every_guarded_workflow`) instead of
        pinning today's two names."""
        derived = guarded_workflows()
        composites = sorted(k for k in derived if k.startswith(".github/actions/"))
        self.assertTrue(
            composites,
            "no composite action appears in the derived guarded set — this repo has "
            "two, so either they moved or they are being skipped again",
        )
        for key in composites:
            with self.subTest(action=key):
                self.assertIn(
                    key, set(MUST_BE_IN_BUCKET) | set(KNOWN_BUCKET_GAP),
                    f"{key} is scanned by {derived[key]} and is classified nowhere.",
                )

    def test_composite_actions_really_are_outside_the_bucket(self):
        """The gap entries' premise, measured with the REAL regex. If the bucket
        ever starts matching `.github/actions/**`, these two belong in
        MUST_BE_IN_BUCKET instead and this fails to say so."""
        self.assertIsNotNone(self.pattern, "bucket not found")
        bucket = re.compile(self.pattern)
        for key in sorted(KNOWN_BUCKET_GAP):
            if not key.startswith(".github/actions/"):
                continue
            with self.subTest(action=key):
                self.assertFalse(
                    bucket.match(key),
                    f"{key} now MATCHES the `scanner` bucket, so it is no longer a "
                    "gap — move it to MUST_BE_IN_BUCKET with the reason.",
                )


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
        self.assertIn(".github/actions/token-expiry-gate/action.yml", derived)
        self.assertGreaterEqual(len(derived), 10, f"only found {sorted(derived)}")

    def test_a_new_composite_action_is_unclassified_and_caught(self):
        """The forcing mechanism, driven. A second composite action named
        `action.yml` must produce its OWN key — a basename key would collide the two
        into one entry and classify both by whichever was seen last — and must be
        reported as unclassified until someone decides it.

        Same tempdir + `_ci_guard_util.ACTION_DIR` swap
        `test_ci_injection_surface` uses, so the live files do not leak in."""
        import _ci_guard_util

        original = _ci_guard_util.ACTION_DIR
        try:
            with tempfile.TemporaryDirectory() as tmp:
                act = Path(tmp, "actions")
                for name in ("token-expiry-gate", "brand-new-thing"):
                    (act / name).mkdir(parents=True)
                    Path(act, name, "action.yml").write_text(
                        "runs: {}\n", encoding="utf-8"
                    )
                _ci_guard_util.ACTION_DIR = act
                derived = guarded_workflows()
        finally:
            _ci_guard_util.ACTION_DIR = original
        self.assertIn(".github/actions/brand-new-thing/action.yml", derived)
        self.assertIn(".github/actions/token-expiry-gate/action.yml", derived)
        unclassified = sorted(
            set(derived) - (set(MUST_BE_IN_BUCKET) | set(KNOWN_BUCKET_GAP))
        )
        self.assertEqual(unclassified, [".github/actions/brand-new-thing/action.yml"])

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


class TestRound2ReviewFindingsAreClosed(unittest.TestCase):
    """Mutation self-tests for the six findings of the independent adversarial
    review of #465. Every one was measured GREEN on `5063c25` before the fix and
    is pinned here; none was a live hole, all six were one edit away."""

    T = "scanner/tests/test_x.sh"

    def _step(self, body):
        return "jobs:\n  j:\n    steps:\n" + body

    def _credited(self, doc):
        return bool(invoked_shell_tests(executed_shell(doc)))

    # --- H3: a `run:` at any nesting depth counted as execution -------------

    def test_run_nested_under_with_is_not_execution(self):
        """The sharpest of the six: the step has NO `run:` key at all (PyYAML
        confirms `['name', 'uses', 'with']`) and the guard reported the test as
        registered on the fast path."""
        doc = self._step(
            f"      - name: a\n        uses: ./.github/actions/token-expiry-gate\n"
            f"        with:\n          run: bash {self.T}\n"
        )
        self.assertFalse(self._credited(doc))

    def test_run_nested_under_env_is_not_execution(self):
        doc = self._step(
            f"      - name: a\n        env:\n          run: bash {self.T}\n"
            f"        run: true\n"
        )
        self.assertFalse(self._credited(doc))

    def test_a_step_level_run_is_still_execution(self):
        """The positive control. Column-restricting must not stop crediting the
        real thing — 50 registrations depend on it."""
        for body in (
            f"      - name: a\n        run: bash {self.T}\n",
            f"      - name: a\n        run: |\n          bash {self.T}\n",
        ):
            with self.subTest(body=body):
                doc = self._step(body)
                self.assertTrue(self._credited(doc))

    def test_unreadable_block_scalar_owners_fail_closed(self):
        """`key_line`'s bare class is `[^\\s:#]+`, so a key with a space, a `:` or
        a `#`, and the explicit `? key` form, read as NOT-a-key — and the scanner
        walked into their scalar bodies. Four spellings, each measured crediting
        an unregistered test while PyYAML reported the step executing `true`."""
        for owner in ("MY NOTE", "a:b", "a#b"):
            with self.subTest(owner=owner):
                doc = self._step(
                    f"      - name: a\n        env:\n          {owner}: |\n"
                    f"            run: bash {self.T}\n        run: true\n"
                )
                self.assertFalse(self._credited(doc))
                self.assertTrue(
                    unreadable_block_scalar_keys(doc),
                    f"`{owner}: |` must be REPORTED, not silently skipped",
                )
        explicit = self._step(
            f"      - name: a\n        ? env\n        : |\n"
            f"            run: bash {self.T}\n        run: true\n"
        )
        self.assertFalse(self._credited(explicit))
        self.assertTrue(unreadable_block_scalar_keys(explicit))

    def test_a_readable_owner_is_not_reported(self):
        """Direction. A quoted or plain owner is readable, so the tripwire must
        stay quiet — it fires on unreadable OWNERS, never on the payload."""
        for owner in ('"NOTE"', "NOTE", "'NOTE'"):
            with self.subTest(owner=owner):
                doc = self._step(
                    f"      - name: a\n        env:\n          {owner}: |\n"
                    f"            run: bash {self.T}\n        run: true\n"
                )
                self.assertEqual(unreadable_block_scalar_keys(doc), [])

    def test_the_real_lint_yml_has_no_unreadable_owners(self):
        """Canary: the tripwire must be quiet on the file it guards, or it is a
        blanket failure rather than a detector."""
        self.assertEqual(unreadable_block_scalar_keys(LINT_YML.read_text("utf-8")), [])

    # --- M2: nested composite actions collided into one key ----------------

    def test_nested_composite_actions_key_distinctly(self):
        """`path.parent.name` keyed by the LEAF directory, so `aws/deploy` and
        `gcp/deploy` collided — the exact collision `_bucket_key`'s docstring
        claims to fix, and `_bucket_path` then measured the bucket regex against a
        path that does not exist."""
        import _ci_guard_util

        original = _ci_guard_util.ACTION_DIR
        try:
            with tempfile.TemporaryDirectory() as tmp:
                act = Path(tmp, "actions")
                for rel in ("aws/deploy", "gcp/deploy", "flat-thing"):
                    (act / rel).mkdir(parents=True)
                    Path(act, rel, "action.yml").write_text("runs: {}\n", "utf-8")
                _ci_guard_util.ACTION_DIR = act
                keys = [
                    _bucket_key(Path(f))
                    for f in workflow_and_action_files()
                    if Path(f).name in COMPOSITE_ENTRYPOINTS
                ]
        finally:
            _ci_guard_util.ACTION_DIR = original
        self.assertEqual(
            len(keys), len(set(keys)),
            f"two composite actions collided into one key: {sorted(keys)}",
        )
        self.assertIn(".github/actions/aws/deploy/action.yml", keys)
        self.assertIn(".github/actions/gcp/deploy/action.yml", keys)

    # --- L1: false ALARMS narrower than the command-position model needs ----

    def test_invocation_shapes_the_runner_really_executes(self):
        for text, want, label in (
            (f'"bash {self.T}"', True, "quoted run: value"),
            (f"'bash {self.T}'", True, "single-quoted value"),
            (f"bash -x {self.T}", True, "dash option run"),
            (f"{{ bash {self.T}; }}", True, "brace group"),
            (f"bash {self.T} || exit 1", True, "control"),
        ):
            with self.subTest(label=label):
                self.assertEqual(bool(invoked_shell_tests(text)), want)

    def test_over_crediting_shapes_stay_rejected(self):
        """The dangerous direction. Broadening the command-position set must not
        make a MENTION count — that was MEDIUM-2, and the quote-unaware residual
        must not widen either."""
        for text, label in (
            (f'echo "TEMPORARILY DISABLED: bash {self.T}"', "the MEDIUM-2 case"),
            (f"echo bash {self.T}", "bare word before bash"),
            (f'echo "do bash {self.T}"', "keyword inside a quoted string"),
            (f"timeout 30 bash {self.T}", "documented false alarm"),
        ):
            with self.subTest(label=label):
                self.assertFalse(bool(invoked_shell_tests(text)), label)


class TestExemptionVerdictIsNonVacuous(unittest.TestCase):
    """Mutation self-tests for the RUNS_ELSEWHERE rc-swallow rule.

    Anchored on `dashboard-control-smoke.yml`, whose steps name their tests in a
    `run:` directly. `cross-os-checks.yml` reaches its two through a matrix value
    and gets the same checks via `TestRunsElsewhereOwnershipIsNonVacuous`."""

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

    # --- round-2 review findings, on the real owner files ------------------

    def test_a_constant_job_gate_is_caught(self):
        """H1. `if` was a STEP swallow key and not a JOB one, though
        `test_job_level_continue_on_error_is_caught` says "one level out, the same
        defect". `if: false` on `cross-os-checks.yml`'s matrix job measured
        `61 passed` with both `*_live.sh` exemptions running nowhere on the
        platform they exist for."""
        owner = "cross-os-checks.yml"
        text = (LINT_YML.parent / owner).read_text(encoding="utf-8")
        job = next(
            j for j in top_level_jobs(text)
            if "matrix" in (job_block(text, j) or "")
        )
        mutant = apply_regex_mutation(
            text, rf"^  {re.escape(job)}:\n", f"  {job}:\n    if: false\n", flags=re.M
        )
        for name in ("test_check_macos_cis_security_live.sh",
                     "test_check_windows_kisa_security_live.sh"):
            with self.subTest(test=name):
                self.assertTrue(
                    exemption_swallow_problems(mutant, owner, name),
                    "a job switched off with `if: false` kept the exemption",
                )

    def test_a_real_path_gate_is_not_a_constant(self):
        """H1, the other direction, and the reason `if` cannot simply join
        `_SWALLOW_JOB_KEYS`: `dashboard-control-smoke.yml` legitimately carries a
        job-level `if: needs.changes.outputs.dashboard == 'true'`. A guard that
        reddens on the real file gets deleted (#414)."""
        text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")
        # Non-vacuity is asserted through the READER, not by looking for the
        # string in the raw file: a raw presence check would stay green with the
        # gate commented out, which is the inert shape
        # `test_ci_guard_assertion_scoping` exists to reject.
        job_key, _ = _enclosing_job_block(text, next(
            blk for blk in locate_exemption_steps(text, self.OWNER, self.TEST)[0]
        ))
        expr, gate_problems = job_gate_expression(text, job_key)
        self.assertEqual(gate_problems, [])
        self.assertIsNotNone(expr, "the owner job has no `if:` — fixture is stale")
        self.assertTrue(
            any(ref in expr for ref in _LIVE_GATE_REFS),
            f"the owner's job gate `{expr}` references none of {list(_LIVE_GATE_REFS)}, "
            "so this test is no longer exercising the live-gate direction",
        )
        self.assertEqual(exemption_swallow_problems(text, self.OWNER, self.TEST), [])

    def test_the_matrix_halves_must_share_a_job(self):
        """H2. `_matrix_keys_naming` and `step_blocks` were both whole-file, so
        the matrix entry and the step consuming it could sit in two unrelated jobs
        and still satisfy "both halves present" — measured at `61 passed` with the
        macOS entry parked in a second job."""
        owner = "cross-os-checks.yml"
        name = "test_check_macos_cis_security_live.sh"
        text = (LINT_YML.parent / owner).read_text(encoding="utf-8")
        entry = next(
            ln for ln in text.splitlines() if name in ln and ":" in ln
        )
        parked = (
            "\n  macos-checks-parked:\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      matrix:\n        include:\n"
            f"{entry}\n    steps:\n      - run: echo parked\n"
        )
        mutant = apply_mutation(text, entry + "\n", "") + parked
        self.assertTrue(
            exemption_swallow_problems(mutant, owner, name),
            "the two matrix halves were accepted from two different jobs",
        )

    def test_explicit_key_swallow_form_fails_closed(self):
        """M1a. `_keys_at` reads bare and quoted keys but cannot see
        `? continue-on-error` / `: true`, measured GREEN at both step and job
        level while PyYAML reported the key set."""
        text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")
        mutant = apply_mutation(
            text,
            "      - name: Run asset dashboard control-liveness smoke\n",
            "      - name: Run asset dashboard control-liveness smoke\n"
            "        ? continue-on-error\n        : true\n",
        )
        problems = exemption_swallow_problems(mutant, self.OWNER, self.TEST)
        self.assertTrue(problems)
        self.assertIn("explicit-key", problems[0])

    def test_a_decoy_job_makes_the_enclosing_job_ambiguous(self):
        """M1b. `_enclosing_job_block` matched the step's FIRST LINE anywhere in
        the file, so a second job with a byte-identical `- name:` line redirected
        the check — measured GREEN while PyYAML had
        `jobs.smoke.continue-on-error = True`. Ambiguity now fails closed rather
        than resolving to whichever job came first."""
        text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")
        step = (
            "      - name: Run asset dashboard control-liveness smoke\n"
            "        timeout-minutes: 5\n        env:\n"
            "          CHROME_BIN: /usr/bin/google-chrome\n"
            f"        run: bash scanner/tests/{self.TEST}\n"
        )
        # No `assertIn(step, text)` staleness check: it is the inert raw-presence
        # shape, and the `+ step` below fails loudly if the anchor drifts because
        # the decoy job would then carry a step the owner does not have.
        mutant = (
            text.rstrip("\n")
            + "\n\n  decoy:\n    runs-on: ubuntu-latest\n"
            "    continue-on-error: true\n    steps:\n" + step
        )
        self.assertTrue(
            exemption_swallow_problems(mutant, self.OWNER, self.TEST),
            "a decoy job with an identical step was silently accepted",
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

    def test_no_shell_test_hides_in_a_subdirectory(self):
        """A `test_*.sh` below `scanner/tests/` runs NOWHERE and is invisible here.

        `SHELL_TEST_GLOB` is non-recursive, and so is the kcov loop's
        `for sh in scanner/tests/test_*.sh` (and its `chmod +x` line). Planting
        `scanner/tests/unit/test_nested_thing.sh` — a script that exits 1 — left
        this guard at `47 passed` while nothing in CI ran it: not the fast path
        (explicit list), not the kcov backstop (flat glob), and not the denominator
        that would have demanded registration.

        WHY THIS AND NOT A RECURSIVE GLOB: making only this guard recursive would
        demand registration for a file the kcov backstop still cannot see, and
        making the kcov loop recursive too would SILENTLY CHANGE WHICH TESTS CI
        RUNS — every future nested script would join the coverage loop by side
        effect. Asserting the directory stays flat changes no CI behaviour, is
        green today (`scanner/tests/` has `fixtures/` and `__pycache__/` and zero
        nested `*.sh`), and leaves the recursion decision to whoever actually wants
        a subdirectory, with both globs to update.
        """
        nested = nested_shell_tests()
        self.assertEqual(
            nested, [],
            "these shell tests live BELOW `scanner/tests/`, where neither the "
            f"`{JOB}` explicit list nor the `scanner-shell-coverage` kcov glob "
            f"(`{SHELL_TEST_GLOB}`, non-recursive) can reach them, so they run "
            f"nowhere:\n" + "\n".join(f"  - {p}" for p in nested)
            + "\n\nMove them up to `scanner/tests/`, or make BOTH the kcov loop in "
            "lint.yml and this guard's globs recursive in the same change.",
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
        """The exemption must name a workflow that really INVOKES the test.

        It used to require only a mention outside the trigger block, which is the
        same mention-vs-invocation confusion the fast path was hardened against —
        and for `cross-os-checks.yml` the mention lives in a matrix VALUE, so
        rewriting the step that consumes it to `run: echo "skipping ${{ matrix.test
        }}"` left both `*_live.sh` tests running nowhere at `47 passed`. The
        invocation is now located for real (directly, or through the two documented
        halves of the matrix indirection), so a `paths:` mention, a `name:` mention
        and an `echo` all fail — the trigger-block subtraction this test used to
        need is gone with them, because a `paths:` entry is a sequence item and
        never an executed `run:` value.
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
                steps, problems = locate_exemption_steps(text, owner, test_name)
                self.assertEqual(problems, [], "; ".join(problems))
                self.assertTrue(
                    steps,
                    f"no step of {owner} invokes {test_name}, so that test runs "
                    f"nowhere. Register it in `{JOB}` or restore its step in "
                    f"{owner}.",
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

    def test_a_block_scalar_header_with_a_trailing_comment_still_registers(self):
        """`run: |  # note` is valid YAML — PyYAML reads the body — and the guard
        dropped it, returning the header `'|'` as the whole executed shell and
        reporting the step's test unregistered (`2 failed, 45 passed` on a real-file
        mutation, from an ordinary authoring style). A guard people have to fight
        gets weakened by its users rather than repaired (#414), and
        `test_ci_injection_surface` already handles this shape, so the header is
        comment-stripped before the block-scalar match."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: |  # slowest of the three\n"
            f"          bash scanner/tests/{self.TARGET}\n",
        )
        self.assertFalse(
            self._missing(mutant),
            "`run: |  # comment` must still collect its body — PyYAML does",
        )

    def test_a_mention_inside_an_executed_command_is_not_registration(self):
        """The step RUNS, and what it runs is an `echo`. The path is present in an
        executed `run:` value, which is all the bare-path matcher asked for:
        `47 passed`, with nothing executing the test."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: echo \"TEMPORARILY DISABLED: bash scanner/tests/"
            f"{self.TARGET}\"\n",
        )
        self.assertIn(self.TARGET, mutant, "fixture must keep the token in the file")
        self.assertTrue(self._missing(mutant))

    def test_a_block_scalar_of_another_key_is_not_registration(self):
        """A `run:`-shaped line inside a DIFFERENT key's block scalar. PyYAML reads
        this step's executed shell as `true`; the guard read the `env:` body and
        called the test registered at `47 passed`. The owning key is quoted here as
        well, since the consume-and-discard arm must not be bypassable by `"env":`.
        """
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Note about the score-to-grade test\n"
            '        "env":\n'
            "          NOTE: |\n"
            f"            run: bash scanner/tests/{self.TARGET}\n"
            "        run: true\n",
        )
        self.assertIn(self.TARGET, mutant, "fixture must keep the token in the file")
        self.assertTrue(self._missing(mutant))

    def test_the_pty_launcher_spelling_still_counts(self):
        """Direction, and a real spelling: `scanner-unit-tests` invokes
        `test_aws_sso_tty.sh` through `pty_run.py`. Narrowing a mention to an
        invocation must not reject the launcher forms actually in use, or the guard
        would false-alarm on the file it ships with."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: python3 scanner/tests/pty_run.py bash scanner/tests/"
            f"{self.TARGET}\n",
        )
        self.assertFalse(self._missing(mutant))

    def test_a_chained_invocation_still_counts(self):
        """Direction: `&&`/`;` are command positions, so a chained invocation in a
        block scalar registers. Pins that the command-position rule is not
        accidentally 'start of line only'."""
        mutant = apply_mutation(
            self.lint, self.step,
            "      - name: Run bash unit tests (print_summary score-to-grade)\n"
            "        run: |\n"
            f"          echo start && bash scanner/tests/{self.TARGET}\n",
        )
        self.assertFalse(self._missing(mutant))

    def test_nested_shell_test_detector_is_non_vacuous(self):
        """`nested_shell_tests()` is asserted to be EMPTY on the real tree, so it
        needs its own proof that it can be non-empty: a flat test must be ignored
        and a nested one reported."""
        original = globals()["REPO_ROOT"]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                flat = Path(tmp, SHELL_TEST_DIR)
                (flat / "unit").mkdir(parents=True)
                Path(flat, "test_flat.sh").write_text("exit 0\n", encoding="utf-8")
                Path(flat, "unit", "test_nested_thing.sh").write_text(
                    "exit 1\n", encoding="utf-8"
                )
                globals()["REPO_ROOT"] = Path(tmp)
                self.assertEqual(
                    nested_shell_tests(),
                    [f"{SHELL_TEST_DIR}/unit/test_nested_thing.sh"],
                )
        finally:
            globals()["REPO_ROOT"] = original

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
    standing between `RUNS_ELSEWHERE` and a parking lot for unrun tests.

    Anchored on `cross-os-checks.yml`, the MATRIX-indirection owner, so both halves
    of the indirection are driven. `dashboard-control-smoke.yml`, whose steps name
    their tests directly, is covered by `TestExemptionVerdictIsNonVacuous`."""

    OWNER = "cross-os-checks.yml"
    TEST = "test_check_macos_cis_security_live.sh"
    MATRIX_ENTRY = "            test: scanner/tests/test_check_macos_cis_security_live.sh\n"
    CONSUMER = "run: bash ${{ matrix.test }}"

    def setUp(self):
        self.text = (LINT_YML.parent / self.OWNER).read_text(encoding="utf-8")

    def _problems(self, text):
        return locate_exemption_steps(text, self.OWNER, self.TEST)[1]

    def test_control_owner_really_invokes_the_test(self):
        """Item 6: GREEN on the real file, and a located step — not an empty list
        of steps with an empty list of problems, which would read the same at the
        call sites and prove nothing."""
        steps, problems = locate_exemption_steps(self.text, self.OWNER, self.TEST)
        self.assertEqual(problems, [])
        self.assertTrue(steps, "no step located on the real file")

    def test_dropping_the_matrix_entry_is_caught(self):
        assert_disables(
            self._problems,
            self.text,
            apply_mutation(self.text, self.MATRIX_ENTRY, ""),
            "matrix value naming the test deleted",
        )

    def test_paths_only_mention_is_not_ownership(self):
        """POSITIVE CONTROL. The matrix entry is gone but the
        `on.pull_request.paths` mention remains, so the raw file still contains the
        name. A presence check over the file would pass here with the test running
        nowhere."""
        mutant = apply_mutation(self.text, self.MATRIX_ENTRY, "")
        self.assertIn(
            self.TEST, mutant,
            "fixture must leave the `paths:` mention in place, or it proves nothing",
        )
        self.assertIn(f"- 'scanner/tests/{self.TEST}'", mutant)
        self.assertTrue(self._problems(mutant))

    def test_a_consumer_that_only_interpolates_the_matrix_key_is_caught(self):
        """THE MEDIUM-1 bypass. The matrix entry is untouched and the step still
        runs and still mentions `${{ matrix.test }}` — it just no longer executes
        it. Under reference-only ownership this read `47 passed` with BOTH
        `*_live.sh` tests running nowhere in the repo."""
        assert_disables(
            self._problems,
            self.text,
            apply_mutation(
                self.text, self.CONSUMER, 'run: echo "skipping ${{ matrix.test }}"'
            ),
            "matrix consumer downgraded to an echo",
        )

    def test_deleting_the_consumer_step_is_caught(self):
        self.assertTrue(self._problems(apply_mutation(self.text, self.CONSUMER, "run: true")))

    def test_a_matrix_reached_test_gets_the_swallow_checks_too(self):
        """The other half of the asymmetry: `continue-on-error` on the step that
        consumes the matrix value. `exemption_swallow_problems` used to return `[]`
        for a MATRIX_INDIRECTION entry before it ever reached these checks, so the
        two cross-os entries had none of the protection the two
        dashboard-control-smoke entries had."""
        assert_disables(
            lambda t: exemption_swallow_problems(t, self.OWNER, self.TEST),
            self.text,
            apply_mutation(
                self.text,
                "      - name: Run OS-specific structural integration test\n",
                "      - name: Run OS-specific structural integration test\n"
                "        continue-on-error: true\n",
            ),
            "matrix consumer step swallows its rc",
        )

    def test_job_level_continue_on_error_on_the_matrix_owner_is_caught(self):
        self.assertTrue(
            exemption_swallow_problems(
                apply_mutation(
                    self.text,
                    "  live-os-checks:\n",
                    "  live-os-checks:\n    continue-on-error: true\n",
                ),
                self.OWNER,
                self.TEST,
            )
        )


if __name__ == "__main__":
    unittest.main()
