"""The CI-config guards must RUN on the files they guard.

A guard that cannot execute on the PR that violates its invariant is decoration.
Every `test_ci_*.py` in this directory runs in three jobs. Two of them did not
exist once: `ci-guards` was added in #462, `renderer-canary` in the PR below.

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
- `renderer-canary` — the three classes that adjudicate a Markdown reduction
  against `markdown-it-py` rather than against themselves. They are the only
  checks able to catch that reduction's RESIDUAL, and they SKIP without the
  package: `ci-guards` installs nothing, and `scanner-unit-tests` has it but is
  gated on `scanner`, which the catalog does not match. So a catalog-only PR —
  the exact shape that would introduce a residual — got a job but not the check.
  A THIRD job rather than an install in `ci-guards`, because that job's
  admissibility on a broad bucket rests on needing no `pip install`, a property
  documented in three places and asserted by none: breaking it would turn
  nothing red and silently falsify all three.

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
5. `renderer-canary` exists, is gated on `ci_config` (NOT `scanner`, which would
   fire kcov), installs the pinned oracle, names all three adjudicated classes,
   is wired into `lint-gate.needs`, and carries BOTH vacuity checks its verdict
   depends on — a non-zero test count and a skip check. The second is not
   redundant: `unittest` counts a skipped class in `Ran N tests` and exits 0, so
   the count alone would let a skip read as a pass, which is the fail-open this
   job exists to close.

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

MARKDOWN_SCAN_EXEMPT = (
    "does not parse Markdown: every `.md`/`.toml` path here is a PATH, never a document. `guard_data_files()` collects them by AST out of the OTHER guards and `uncovered_paths()` matches each against the bucket's `grep -E` pattern; nothing in this file opens one. The rationale used to say 'the catalog PATH' singular, from when the set was two hand-written entries — it is a derived census of 109 now, which changes the size but not the reason for the exemption"
)
import ast
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
    tracked_files,
    workflow_and_action_files,
    yaml_key_pattern,
)
from test_ci_reachability import executed_shell  # noqa: E402
from test_ci_template_pin_policy import (  # noqa: E402
    installed_workflow_templates,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
SETUP_SH = REPO_ROOT / "scripts" / "setup.sh"

GUARD_JOB = "ci-guards"
CHANGES_JOB = "changes"
GATE_JOB = "lint-gate"
CANARY_JOB = "renderer-canary"

# The renderer-adjudicated classes. Each compares a Markdown reduction against
# `markdown-it-py` instead of against itself, and each SKIPS without it — so
# `renderer-canary` is the only job where they execute on a catalog-only PR.
# `(class, adjudicating method)`. The METHOD is load-bearing: a review parked the
# one test in `TestTheDocAgreesWithTheRenderer` that reads the real catalog and
# left the class at two synthetic-fixture tests, so a per-class COUNT floor saw
# nothing while the residual went live. A count cannot say which test adjudicates.
CANARY_CLASSES = (
    (
        "test_ci_catalog_doc_sync.TestTheDocAgreesWithTheRenderer",
        "test_the_reduction_and_the_renderer_agree_on_the_real_catalog",
    ),
    (
        "test_ci_adr_decision_numbering.TestTheParseAgreesWithCommonMark",
        "test_the_parse_matches_the_renderer_on_every_stripper_case",
    ),
    (
        "test_ci_markdown_scan_evasion.TestTheResidualIsBounded",
        "test_silent_passes_stay_within_the_measured_ceiling",
    ),
)
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
    # Matched on the FULL `needs.<job>.outputs.<name> == 'true'`, not on the bare
    # reference. The un-anchored form was the version here until a review measured
    # it against the same three shapes that had already defeated the canary's
    # sibling check at `canary_job_problems` — all three returned `[]`:
    # `ci_config == 'false'` (inverted, so the job runs only when it is not
    # needed), `ci_config == 'true' && scanner == 'true'` (fires only alongside
    # kcov, restoring the hole this job closed), and `workflow_dispatch` ANDed in
    # (never on a PR). The hardened spelling was already sitting one function
    # away; this one had simply not been brought along with it.
    elif f"needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT} == 'true'" not in gate:
        problems.append(
            f"job `{GUARD_JOB}` is gated on `if: {gate}`, which does not read "
            f"`needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT} == 'true'`. A correct "
            "bucket wired to nothing is not a gate, and neither is one inverted "
            "or ANDed with a condition that never holds on a pull request."
        )

    # THE RUNNER, matched WHOLE. This was `_DISCOVER_RE` — a substring test for
    # `unittest discover ... -p 'test_ci_*.py'` that ignored the `-s` value and
    # everything after `-p`. Measured, that let two edits pass with every guard
    # returning `[]`: `cd /tmp/decoy` before it ran a one-test decoy suite
    # (`ran=1`, zero real guards), and an appended `-k '*bucket*'` cut the run to
    # 18 of 1264. Both published a GENUINE count — the scope, not the number, was
    # the lie. The invocation now takes no arguments and the runner refuses any,
    # so the check is an anchored whole-line match.
    if not any(
        re.search(
            rf'^\s*python3 {re.escape(GUARD_RUNNER)} >> "\$GITHUB_OUTPUT"\s*$',
            blk, re.M,
        )
        for blk in step_blocks(block)
    ):
        problems.append(
            f"no step in `{GUARD_JOB}` invokes exactly "
            f'`python3 {GUARD_RUNNER} >> "$GITHUB_OUTPUT"`. Anything else — a '
            "`cd` in front, an argument behind, a pipe — changes WHICH guards "
            "run while leaving the count it publishes genuine."
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


def canary_job_problems(lint_text: str) -> list:
    """The same shape of checks as `guard_job_problems`, for the canary job.

    A separate function rather than a parameter on the one above, because the
    two jobs prove different things and their failure messages should say so.
    What they share is the shape of the ways a CI job goes quiet: a gate wired
    to nothing, an invocation that does not invoke, and absence from the
    aggregator.

    EVERYTHING HERE READS EXECUTED TEXT, NOT THE BLOCK. The first version scanned
    the raw job block with `re.search`, and a review replaced the whole step with
    `run: echo "renderer canary parked"` while leaving the commands in a `#`
    comment in this repo's own house style — `canary_job_problems` returned `[]`
    and all 1230 guards passed. That is the presence-vs-attribution class this
    repo has now hit three times (#440, the census in
    `test_ci_markdown_scan_evasion`, and here), and the SIBLING FUNCTION IN THIS
    FILE already defended against it. Proving a token exists is never proof it
    belongs to the code that runs.

    This exists because the job it pins was added to close a fail-open, and an
    unpinned fix for a fail-open is one token from being reverted with the suite
    green — measured on the `ci_config` bucket widening in #530."""
    problems = []
    block = job_block(lint_text, CANARY_JOB)
    if block is None:
        return [
            f"job `{CANARY_JOB}` not found in lint.yml. It is the ONLY place the "
            "renderer-adjudicated guard classes actually execute on a "
            "catalog-only PR — everywhere else they skip."
        ]

    # The gate, read at the job's DERIVED key column with inline comments
    # stripped, and matched on the FULL `needs.<job>.outputs.<name>` — not on the
    # bare bucket name. A review defeated the substring form three ways that all
    # returned `[]`: `ci_config == 'false'` (inverted), `ci_config == 'true' &&
    # ... scanner == 'true'` (fires only alongside kcov, the hole restored), and
    # the name surviving only in a trailing comment.
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
        problems.append(f"job `{CANARY_JOB}` has no job-level `if:` gate")
    elif f"needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT} == 'true'" not in gate:
        problems.append(
            f"job `{CANARY_JOB}` is gated on `if: {gate}`, which does not read "
            f"`needs.{CHANGES_JOB}.outputs.{BUCKET_OUTPUT} == 'true'`. Gated on "
            "the `scanner` bucket it would fire kcov; inverted or ANDed with "
            "another bucket it would run only when it is not needed."
        )

    # Executed shell only. IMPORTED from `test_ci_reachability` rather than
    # re-derived: that module's `executed_shell` already handles both `run:`
    # spellings, strips YAML and shell comments, and — the part that matters
    # here — CONSUMES AND DISCARDS a block scalar belonging to any other key.
    #
    # The first version appended `strip_comment_lines(blk)` for the whole step
    # block whenever the step merely HAD a `run:`. That closed comment-parking
    # and left env-parking wide open: a review moved every command into
    # `env: PARKED_RESTORE_ME: |` and reduced `run:` to `echo`, and this function
    # returned no problems with 1232 guards green. `executed_shell`'s docstring
    # documents that exact vector, found one guard over — writing a third
    # extractor instead of importing the one that already knew was the mistake.
    executed = executed_shell(block)

    if not re.search(r"markdown-it-py==4\.0\.0", executed):
        problems.append(
            f"job `{CANARY_JOB}` does not INSTALL `markdown-it-py==4.0.0` in an "
            "executed step. Without the oracle every class it runs SKIPS, and "
            "the job reports success having adjudicated nothing — the exact "
            "fail-open it exists to close."
        )

    # THE RUNNER, matched WHOLE — same reason as the sibling on `ci-guards`.
    if not re.search(
        rf'^\s*python3 {re.escape(CANARY_RUNNER)} >> "\$GITHUB_OUTPUT"\s*$',
        executed, re.M,
    ):
        problems.append(
            f"job `{CANARY_JOB}` does not invoke exactly "
            f'`python3 {CANARY_RUNNER} >> "$GITHUB_OUTPUT"`.'
        )

    # NO HEREDOC IN THIS STEP. `executed_shell` does not model heredoc bodies —
    # its own docstring calls that the one limitation that CAN hide an unrun test
    # — so a `run: |` opening `cat <<'EOF'` would read as execution to every
    # check above. Forbidding what the extractor cannot read is the fail-closed
    # half. SCOPE, stated because it is a SUBSTRING test and not a heredoc
    # parser: it also fires on `echo "shift: 1 << 2"` and `: $(( 1 << 2 ))`
    # (measured). Both are false alarms, both fail CLOSED, and neither belongs
    # in a step that is now one invocation.
    if "<<" in executed:
        problems.append(
            f"job `{CANARY_JOB}` contains a heredoc. `executed_shell` cannot see "
            "into heredoc bodies, so the invocation could sit inside one and run "
            "nothing while satisfying every check in this function."
        )

    # ---------------------------------------------------------------------
    # THE INVARIANTS THAT USED TO BE SHELL, ASSERTED WHERE THEY NOW LIVE.
    #
    # This block previously scanned the step's executed text for `for spec in`,
    # each class and method name, `descriptions=False`, a skip grep, a
    # `^Ran [1-9]` grep and a `did not run ${method}` message. Every one of those
    # was an assertion about a shell loop that parsed `unittest -v` PROSE, and
    # prose a run produces is prose a FAILING run can shape: measured, a red
    # class whose output carried a column-0 `OK ` line satisfied the verdict grep
    # once the `|| { exit 1; }` branch was weakened, and the step published a
    # genuine count with the suite red.
    #
    # The invariants did not go away — they moved into `_ci_canary_runner.py`,
    # where they are `TestResult` bookkeeping rather than regexes, and they are
    # asserted here against the IMPORTED module. `descriptions=False` has no
    # successor on purpose: nothing parses prose any more, so the reason it
    # existed (a docstring on an adjudicating method splitting `... ok` onto a
    # second line and turning documentation into a red build) is gone.
    # ---------------------------------------------------------------------
    if CANARY_RUNNER not in tracked_files():
        problems.append(
            f"`{CANARY_RUNNER}` is not a tracked file. It holds the adjudicator "
            "table, the oracle pin and the pass/skip verdict for this job."
        )
    else:
        runner = _import_canary_runner()
        if tuple(runner.ADJUDICATORS) != tuple(CANARY_CLASSES):
            problems.append(
                f"`{CANARY_RUNNER}`'s ADJUDICATORS has drifted from "
                "`CANARY_CLASSES`:\n"
                f"  runner: {tuple(runner.ADJUDICATORS)}\n"
                f"  guard : {tuple(CANARY_CLASSES)}\n"
                "A second copy of a constant is how this repo has lost a check "
                "before; one of the two is now wrong and nothing else would say "
                "which."
            )
        pinned = re.search(r"markdown-it-py==([\d.]+)", executed)
        if pinned and runner.ORACLE_VERSION != pinned.group(1):
            problems.append(
                f"`{CANARY_RUNNER}` adjudicates against oracle "
                f"{runner.ORACLE_VERSION} but the job installs "
                f"{pinned.group(1)}. The runner hard-fails on the mismatch, so "
                "this is a red build rather than a silent one — but it is a red "
                "build for a reason no one would guess from the message."
            )

    gate_block = job_block(lint_text, GATE_JOB)
    if gate_block is None:
        problems.append(f"aggregator job `{GATE_JOB}` not found")
    elif CANARY_JOB not in job_needs(gate_block):
        problems.append(
            f"`{GATE_JOB}` does not list `{CANARY_JOB}` in `needs:`. Only `Lint` "
            "is a required context, so a canary outside that graph can go red "
            "while the merge stays green."
        )
    return problems


def _marker(var: str) -> str:
    return f'echo "ran=${var}" >> "$GITHUB_OUTPUT"'


def block_scalar_body(block: str, key: str = "run") -> str:
    """The body of `<key>: |` in `block`, dedented by ITS OWN indent.

    `textwrap.dedent` over the remainder of a job block is wrong here and was the
    first version: `job_block` returns raw file text, so the remainder also holds
    whatever follows the step — the two-space `# ---` separator comment between
    jobs, or the next job's keys. Those set the common prefix to 2 rather than
    10, dedent strips 2, and every body line keeps eight spaces. Measured:
    `ci-guards` came back with `'        set -euo pipefail'` while
    `renderer-canary`, followed by different text, came back correctly — so the
    bug reproduced on one job and not the other, which is exactly the shape that
    gets diagnosed as "the fixture is fine, the other job is weird".

    Reading the scalar's own indent and stopping at the first line that dedents
    below it is what YAML actually specifies, and it is stable against anything
    added after the step."""
    marker = f"{key}: |\n"
    rest = block[block.index(marker) + len(marker):].splitlines()
    indent = len(rest[0]) - len(rest[0].lstrip())
    kept = []
    for line in rest:
        if not line.strip():
            kept.append("")
            continue
        if len(line) - len(line.lstrip()) < indent:
            break
        kept.append(line[indent:])
    return "\n".join(kept)


# Per job: the variable the marker publishes, the line that must COMPUTE that
# variable from the work's own output, and the floor that rejects a zero/empty
# value. The floors are derived from `CANARY_CLASSES` rather than written out, so
# adding an adjudicator without raising the floor is a guard failure instead of a
# silent widening.
#: Runner scripts, relative to the repo root. Each owns the SCOPE, the FILTER
#: refusal and the VERDICT for one job — the three things that were unpinnable
#: while they lived in shell text.
GUARD_RUNNER = "scanner/tests/_ci_guard_runner.py"
CANARY_RUNNER = "scanner/tests/_ci_canary_runner.py"


def _import_canary_runner():
    """The canary runner as a MODULE, so its table is compared as data.

    Imported rather than grepped: a regex over the file would re-create the
    parse-the-text problem one level up, and this repo has already measured what
    that costs — a hand-written source list in a guard had drifted to missing 12
    files while reading green."""
    import importlib

    return importlib.import_module("_ci_canary_runner")

#: Per runner: the expression its published count MUST interpolate. Both names
#: are bound only by the run itself — `result` by `TextTestRunner.run()`,
#: `adjudicated` by the loop that drives one adjudicator at a time — so a body
#: that skips the work has nothing to print.
RUNNER_PUBLICATION = {
    GUARD_RUNNER: "result.testsRun",
    CANARY_RUNNER: "adjudicated",
}


def runner_publication_problems(source: str, path: str, data_expr: str) -> list:
    """The runner cannot publish a count it did not compute, or exit early.

    WHY THIS EXISTS
    ---------------
    Moving SCOPE, FILTER and VERDICT out of shell text and into these two files
    did close every shell-level defeat. It did not close the class — it RELOCATED
    the unpinned surface, and an adversarial pass measured the new one. Four lines
    in `_ci_guard_runner.py`:

        if GUARD_DIR.name == "tests" and (GUARD_DIR.parent / "checks").is_dir():
            print("ran=1264")
            return 0

    Result: `python3 scanner/tests/_ci_guard_runner.py` printed `ran=1264` and
    exited 0 having run ZERO guards, `lint-gate`'s `[1-9][0-9]*` accepted it, and
    the whole guard suite reported `OK (Ran 1258 tests)`. An `os.environ
    ["GITHUB_ACTIONS"]` spelling measured identically, on both runners at once.

    Nothing saw it, and the reason is structural rather than an oversight: the
    ONE test that EXECUTES a runner (`test_the_guard_runner_publishes_only_when_
    the_suite_passed`) drives a COPY in a temp directory with `env={"PATH": ...}`.
    That is deliberate and correct — driving the real file in place recurses,
    which once hung for 18 hours — but it means the copy never sees the CI
    environment or the repository layout, so any branch keyed on either is
    invisible to it BY CONSTRUCTION. Behaviour testing cannot reach what the
    fixture cannot reproduce; this reads the file instead.

    WHAT IS PINNED, AND WHY THESE THREE
    -----------------------------------
    1. ONE publication site, and it is an f-string interpolating `data_expr`.
       A short-circuit has to print something, and a literal `ran=1264` or an
       `f"ran={1264}"` both die here. To publish, it must produce the name the
       run binds.
    2. `main` returns 0 EXACTLY ONCE, as its final statement. This is what kills
       the branch itself rather than one spelling of its condition: with no early
       success exit, a body that skips the work cannot reach an exit code the job
       treats as a pass, no matter what it keys the branch on.
    3. No `os.environ` / `os.getenv` anywhere. Neither runner needs one, so this
       is free, and it removes the cheapest spelling before (2) has to.

    (1) and (2) are the load-bearing pair; (3) is a cheap extra.

    NOT CLOSED, stated because a defence that reads complete and is not is the
    failure this file exists to catch: a body that reaches the real
    `TextTestRunner.run()` with a DELIBERATELY EMPTIED suite still binds
    `result`. The runner's own `testsRun < len(files)` floor rejects that today,
    and this function does not pin that floor. Nor does it model a runner that
    fabricates a `result` object — which is possible, and would be an
    unmistakable diff rather than four innocuous-looking lines. As with the
    workflow half, the regress terminates outside this file: at review.
    """
    problems = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"`{path}` does not parse ({exc})"]

    # 1. THE PUBLICATION SITE. Every string constant that opens with `ran=` is a
    #    candidate, whether or not it interpolates — that is the point: a plain
    #    literal is the forgery, so it must be COUNTED and rejected, never
    #    filtered out for not being an f-string.
    #    An f-string's own literal head is a `Constant` that `ast.walk` also
    #    visits, so the parts of every `JoinedStr` are excluded first — counting
    #    them made the REAL runners report two sites each.
    inside_fstring = {
        id(part)
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        for part in ast.walk(node)
        if part is not node
    }
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            head = node.values[0] if node.values else None
            if (
                isinstance(head, ast.Constant)
                and isinstance(head.value, str)
                and head.value.startswith("ran=")
            ):
                sites.append(("fstring", node))
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("ran=")
            and id(node) not in inside_fstring
        ):
            sites.append(("literal", node))
    if len(sites) != 1:
        return problems + [
            f"`{path}` has {len(sites)} `ran=` publication site(s), expected "
            "exactly 1. A second one is a second answer to the only question "
            f"the job asks: {[ast.unparse(n) for _, n in sites]}"
        ]
    kind, node = sites[0]
    if kind != "fstring":
        problems.append(
            f"`{path}` publishes a CONSTANT `{ast.unparse(node)}`. The count "
            "must be interpolated from the run, or a body that ran nothing can "
            "print it."
        )
    else:
        interpolations = [
            v for v in node.values if isinstance(v, ast.FormattedValue)
        ]
        got = [ast.unparse(v.value) for v in interpolations]
        if got != [data_expr]:
            problems.append(
                f"`{path}` publishes `{ast.unparse(node)}`, which interpolates "
                f"{got} rather than exactly `[{data_expr!r}]`. That name is "
                "bound by the run; anything else can be bound without it."
            )

    # 2. ONE SUCCESS EXIT, LAST. See the docstring: this is the check that closes
    #    the branch rather than a spelling of its condition.
    mains = [
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "main"
    ]
    if len(mains) != 1:
        problems.append(f"`{path}` defines {len(mains)} `main` functions, expected 1")
    else:
        main = mains[0]
        zeros = [
            n for n in ast.walk(main)
            if isinstance(n, ast.Return)
            and isinstance(n.value, ast.Constant)
            and n.value.value == 0
        ]
        if len(zeros) != 1:
            problems.append(
                f"`{path}`'s `main` has {len(zeros)} `return 0` statements, "
                "expected 1. Every extra one is a way to report success without "
                "reaching the work."
            )
        elif main.body[-1] is not zeros[0]:
            problems.append(
                f"`{path}`'s `main` does not END with its `return 0` (last "
                f"statement is `{type(main.body[-1]).__name__}`). A success exit "
                "anywhere else can be reached without the work."
            )

    # 3. NO ENVIRONMENT READS. The cheapest measured spelling, removed for free.
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv"):
            problems.append(
                f"`{path}` reads `{ast.unparse(n)}`. Neither runner needs the "
                "environment, and a branch on it behaves differently in CI than "
                "in every test that drives this file."
            )
    return problems


PROOF_SPECS = {
    "ci-guards": {
        "runner": GUARD_RUNNER,
        # ANCHORED WHOLE, and the ONLY thing the body does besides `set -euo
        # pipefail`. Not a substring test: `_DISCOVER_RE` used to match
        # `unittest discover ... -p 'test_ci_*.py'` and ignore the rest of the
        # line, which accepted an appended `-k '*bucket*'` (1264 tests -> 18)
        # and a `cd /tmp/decoy` in front (0 real guards), both publishing a
        # GENUINE count.
        "invocation": re.compile(
            rf'^python3 {re.escape(GUARD_RUNNER)} >> "\$GITHUB_OUTPUT"$'
        ),
    },
    CANARY_JOB: {
        "runner": CANARY_RUNNER,
        "invocation": re.compile(
            rf'^python3 {re.escape(CANARY_RUNNER)} >> "\$GITHUB_OUTPUT"$'
        ),
    },
}
PROOF_JOBS = tuple(PROOF_SPECS)


def job_ran_proof_problems(lint_text: str) -> list:
    """The two guard jobs publish a count PARSED OUT OF their own work.

    WHY THIS EXISTS AND WHY IT IS NOT MORE SHAPES
    ---------------------------------------------
    Text analysis cannot prove a shell body ran. Measured on `main`:

        control                     canary: []   guard: []
        exit 0 in renderer-canary : 0 problems
        exit 0 in ci-guards       : 0 problems

    `if false; then ... fi`, an uncalled function wrapper and `set -n` measure
    the same. A fourth review closed the heredoc shape and an independent check
    then showed `exit 0` is cheaper — one token — so patching shape five would be
    the third patch to an enumeration, which ADR-001 §5 names as the signal to
    invert instead.

    THE FIRST INVERSION WAS WRONG, AND THAT IS THE LESSON HERE
    ----------------------------------------------------------
    It made the LAST line of each body write a constant `ran=true` and argued
    that the line "is reachable only by executing everything above it". It is
    not. Reaching the last line is not the same as having run the work: close a
    parking construct ABOVE the marker and the shell falls straight through it.
    An adversarial pass measured the defeat end to end:

        if [ "${X:-}" = "1" ]; then      <- inserted
        ...the entire work body...
        fi                               <- inserted, one line above the marker
        echo "ran=true" >> "$GITHUB_OUTPUT"

        job_ran_proof_problems -> []      guard_job_problems -> []
        executed: exit=0, stdout='', GITHUB_OUTPUT='ran=true'
        full suite against the mutated lint.yml: Ran 1255 tests — OK

    Two inserted lines, in ONE job — against a docstring that claimed the cost
    was "several coordinated edits across two jobs". `case ... esac` measures the
    same, so it is a class and not a spelling of `if`. Worse, the old fixture
    listed `if false; then ... fi` among the shapes it closed, because it put the
    marker INSIDE the `if`; the attacker just moves `fi` up one line.

    The property a marker needs is DOMINATION — every path reaching it must have
    executed the work — and no amount of text analysis can establish domination.

    THE FIX: A DATA DEPENDENCY, NOT A POSITION
    ------------------------------------------
    Each job now publishes a COUNT computed from its own work:

        ci-guards        `ran` parsed out of `$out`, the suite's stdout
        renderer-canary  `adjudicated`, incremented once per class that ran,
                         did not skip, and passed its named adjudicating method

    Under `set -euo pipefail`, parking the work leaves the source variable
    unbound and the derivation line DIES rather than falling through. Measured
    after the fix, same two mutations: `bash: out: unbound variable`, exit 1, no
    output written. A constant cannot do this; only a value the work produces
    can. `lint-gate` requires a positive integer, so a zero-length or `0` value
    is rejected too.

    WHAT THIS FUNCTION ASSERTS
    --------------------------
    That the derivation exists, precedes the marker, and — for the canary — sits
    inside the loop body; that a floor rejects the empty/zero value; and that the
    marker publishes the VARIABLE rather than a literal. Position is still
    checked, but as a second line of defence, not as the argument.

    WHAT IS NOT CLOSED, stated because a defence that reads complete and is not
    is the failure this file exists to catch: the regress does not terminate
    inside the workflow. `lint-gate`'s own comparison lives in a `run:` body and
    is parkable the same way. It is defence in depth, NOT closure. What
    terminates it is outside this file — branch protection requiring the `Lint`
    context, and GitHub evaluating `needs:`.

    Scoped to the two guard-running jobs, not all 23 nodes of the required
    graph (`required_graph(workflow_texts())`, measured). Those two exist to
    prove other things run, and they are the two where the hole was measured.
    Twenty-three markers whose per-job value is unproven is a bigger diff than
    its evidence."""
    problems = []
    for job, spec in PROOF_SPECS.items():
        block = job_block(lint_text, job)
        if block is None:
            problems.append(f"job `{job}` not found in lint.yml")
            continue

        col = key_column(block)
        declares = False
        if col is not None:
            pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern('outputs')}\s*:")
            declares = any(
                pat.match(strip_inline_comment(raw)) for raw in block.splitlines()
            )
        # COMMENT-STRIPPED, both spellings, before anything is READ out of the
        # block. The reference below used to be searched in the RAW block, and an
        # adversarial pass measured what that costs: put `ran: 9999` in the real
        # `outputs:` map and leave the canonical
        # `ran: ${{ steps.guards.outputs.ran }}` alive in a `#` comment two lines
        # above, and this function returned `[]` with the whole suite at
        # `OK (Ran 1258)`. The published value is then a CONSTANT — which is
        # exactly the property this function exists to forbid, since "parking the
        # body appends nothing, so `lint-gate` fails closed" is only true while
        # the value comes from the step.
        #
        # The sibling `canary_job_problems` already carries this defence and says
        # so in its docstring ("EVERYTHING HERE READS EXECUTED TEXT, NOT THE
        # BLOCK"); this function had simply not been brought along with it. That
        # is the same not-brought-along shape the gate check two functions up was
        # fixed for.
        visible = "\n".join(
            strip_inline_comment(ln)
            for ln in strip_comment_lines(block).splitlines()
        )

        ref_id = None
        if not declares:
            problems.append(
                f"job `{job}` declares no `outputs:`. Without it the line its "
                "runner appends is invisible to `lint-gate`."
            )
        else:
            ref = re.search(
                r"ran:\s*\$\{\{\s*steps\.([\w-]+)\.outputs\.ran\s*\}\}", visible
            )
            if ref is None:
                problems.append(
                    f"job `{job}` has `outputs:` but does not surface `ran` from "
                    "a step. An output that reads from nothing is the empty "
                    "string, which is the undeclared-output vacuity class this "
                    "repo already paid for once."
                )
            elif not re.search(
                rf"^\s*id:\s*{re.escape(ref.group(1))}\s*$", visible, re.M
            ):
                problems.append(
                    f"job `{job}` surfaces `ran` from step id `{ref.group(1)}`, "
                    "which no step in the job declares. The output resolves to "
                    "the empty string, so the proof can never be satisfied."
                )
            else:
                ref_id = ref.group(1)

        # THE PROOF STEP ONLY, not the whole job. `renderer-canary` has a
        # legitimate `pip install` step before it, and an exhaustive check over
        # the job's combined shell would flag that as an extra command. Selected
        # by the invocation itself so the selection cannot drift from what is
        # being checked.
        proof_steps = [
            blk for blk in step_blocks(block)
            if any(spec["invocation"].match(ln.strip())
                   for ln in executed_shell(blk).splitlines())
        ]
        if len(proof_steps) != 1:
            problems.append(
                f"job `{job}` has {len(proof_steps)} steps running an anchored "
                f"`python3 {spec['runner']} >> \"$GITHUB_OUTPUT\"`, expected 1. "
                "A `cd` in front, an argument behind, a pipe or a `|| true` all "
                "change WHICH work runs — or whether its verdict counts — while "
                "leaving the published count genuine."
            )
            continue

        # THE STEP THAT PUBLISHES, not merely a step that invokes. These were two
        # independent selections — `proof_steps` picked by the invocation, the
        # published value picked by `ref_id` — and nothing tied them together.
        # Measured, with every check below still returning `[]`:
        #
        #     - name: Publish the proof      <- id: guards, echoes ran=9999
        #       id: guards
        #       run: |
        #         set -euo pipefail
        #         echo "ran=9999" >> "$GITHUB_OUTPUT"
        #     - name: Run CI config regression guards   <- carries the invocation
        #       run: |
        #         set -euo pipefail
        #         python3 scanner/tests/_ci_guard_runner.py >> "$GITHUB_OUTPUT"
        #
        # `guard_job_problems` and `job_ran_proof_problems` both returned `[]`.
        # Every assertion below then ran against the SECOND step while the job's
        # `ran` came from the first, so the exhaustive "the step does nothing
        # else" check was being applied to a step whose output nobody reads.
        # Adding `if: false` to the second step made it a complete fail-open, and
        # was caught only by `test_ci_required_graph_not_disabled` in another
        # file — i.e. this function's own guarantee did not hold, and the suite
        # went red for an unrelated reason.
        if ref_id is not None and not re.search(
            rf"^\s*id:\s*{re.escape(ref_id)}\s*$", proof_steps[0], re.M
        ):
            problems.append(
                f"job `{job}` runs the runner in a step that is NOT the step "
                f"(`id: {ref_id}`) whose output it publishes. The checks below "
                "would then describe a step nobody reads, and the publishing "
                "step would be unconstrained."
            )

        lines = [
            ln.strip() for ln in executed_shell(proof_steps[0]).splitlines()
            if ln.strip()
        ]

        # THE WHOLE STEP, not just "contains". Everything the step executes is
        # `set -euo pipefail` and the invocation, so anything else is by
        # definition something new to explain.
        allowed = {"set -euo pipefail"}
        extra = [
            ln for ln in lines
            if ln not in allowed and not spec["invocation"].match(ln)
        ]
        if extra:
            problems.append(
                f"job `{job}` executes lines beyond the runner invocation: "
                f"{extra}. The proof is that the step does nothing else; a "
                "second command can seed state, redirect the output file, or "
                "append a forged `ran=` of its own."
            )

        # EXACTLY ONE WRITER to `$GITHUB_OUTPUT`. Covered by `extra` above, but
        # asserted separately because this is the specific forgery the previous
        # design could not stop: while a shell variable carried the value, ten
        # different ways of BINDING it without an `=` assignment published
        # `ran=9999` at exit 0 with the guard silent (`read`, `printf -v`,
        # `declare`, `export`, `mapfile`, `let`, `(( ))`, `for`, process
        # substitution, and a step-level `env:` contributing no shell lines at
        # all). A plain `ran=9999` WAS caught — the pin worked only for the one
        # spelling it enumerated. Removing the variable removed the class.
        writers = [ln for ln in lines if "$GITHUB_OUTPUT" in ln]
        if len(writers) != 1:
            problems.append(
                f"job `{job}` has {len(writers)} lines writing to "
                f"`$GITHUB_OUTPUT`, expected exactly 1: {writers}."
            )
        elif lines[-1] != writers[0]:
            problems.append(
                f"job `{job}` writes its proof but NOT as the last executed line "
                f"(last is `{lines[-1]}`). Anything below it can exit first."
            )

        if any(re.match(r"^cd\s", ln) for ln in lines):
            problems.append(
                f"job `{job}` contains a `cd`. The runner is named by a path "
                "relative to the repo root, so a `cd` can only change which "
                "file — or no file — gets executed."
            )

        if spec["runner"] not in tracked_files():
            problems.append(
                f"job `{job}` invokes `{spec['runner']}`, which is not a tracked "
                "file. That script IS the job's proof — which tests ran, and "
                "whether they passed."
            )

    gate_block = job_block(lint_text, GATE_JOB)
    if gate_block is None:
        problems.append(f"aggregator job `{GATE_JOB}` not found")
        return problems
    for job in PROOF_JOBS:
        if not re.search(rf'["\']{re.escape(job)}["\']', gate_block):
            problems.append(
                f"`{GATE_JOB}` does not name `{job}` among the jobs whose `ran` "
                "proof it requires. The marker is then written and read by "
                "nobody — decoration, and the most expensive kind, because it "
                "looks like a defence."
            )
    if not re.search(r'fullmatch\(\s*r?"\[1-9\]\[0-9\]\*"', gate_block):
        problems.append(
            f"`{GATE_JOB}` no longer requires `ran` to be a POSITIVE INTEGER. "
            "Listing the jobs without checking the value passes on the empty "
            "string, which is what a parked body produces; accepting any "
            "non-empty value passes on `0`, which is what a loop that never "
            "iterates produces."
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
    targets.extend(guard_data_files())
    # THE SCRIPTS THE JOBS EXECUTE, not just the files guards READ. That
    # distinction is why this function missed them: the target set was
    # workflows, templates and AST-derived data files, and a runner is none of
    # those — it is the thing the job runs.
    #
    # Measured when the runners were introduced: both were OUTSIDE the bucket,
    # so a PR editing only `_ci_guard_runner.py` — the script that decides which
    # guards run and whether they passed — would not have fired `ci-guards` or
    # `renderer-canary` at all. The path gate would have hidden a change to the
    # proof itself, which is this repo's already-recorded "the gate hides drift"
    # class landing on the gate's own evidence.
    #
    # Sourced from `PROOF_SPECS` rather than hand-written: those values are
    # pinned to the workflow by `job_ran_proof_problems`, which matches the
    # invocation line anchored WHOLE, so the constant cannot drift from what the
    # jobs actually execute without turning something red.
    targets.extend(spec["runner"] for spec in PROOF_SPECS.values())
    return sorted(p for p in targets if not bucket.match(p))


def guard_data_files(tracked=None) -> list:
    """Repo-relative DATA files a guard reads, DERIVED by AST from the guards.

    Workflows and templates were the whole of `uncovered_paths`' target set until
    the guard inventory moved out of prose into `ci-guard-inventory.toml`. That
    file and the catalog it mirrors were then added to the `ci_config` bucket —
    and a review measured the fix PINNED BY NOTHING: deleting both alternatives
    from the pattern left the full 2909-test suite green.

    The first version of THIS function then returned a hand-written pair, pinned
    at `len == 2`. A second review measured what that missed: the ADR series
    (`docs/devsecops/adr-*.md`), read by `test_ci_adr_decision_numbering` and
    `test_ci_adr_citation_spelling`, matched NEITHER bucket. An ADR-only edit
    that a guard genuinely catches — appending a citation to a decision that does
    not exist makes `test_every_citation_resolves` fail — fired `ci-guards`,
    `scanner-unit-tests` and `renderer-canary` all zero times. Byte-for-byte the
    shape #530 closed for the catalog, left open by the commit whose subject was
    closing it. "Derived, not hand-written" was in the docstring and not in the
    code, which is the same failure `_SOURCE_FILES` cost this repo one level up.

    So it is an AST census now: every `.md`/`.toml` path literal a tracked
    `test_ci_*.py` names, plus the same for module-level `Path` constants built
    from parts (`REPO_ROOT / "docs" / "guides" / "x.md"`), which a literal-only
    scan misses — measured, it missed `compliance-mapping.md` and `isms-p.md`
    exactly that way.

    FILTERED TO TRACKED FILES THAT EXIST — and that filter is NOT a fixture
    guard, which an earlier version of this docstring claimed it was. The census
    cannot tell a path a guard READS from a path a guard merely NAMES; that is
    the presence-vs-attribution class again, one level up from where this file
    already fights it. `test_ci_catalog_no_ghost_rows` names
    `scanner/tests/README.md` as a deliberately-NONEXISTENT negative fixture, and
    the only reason it stays out of the census is that the file does not exist.
    Measured: `touch scanner/tests/README.md` promoted it, and three tests across
    two guards went red on a repo whose only sin was acquiring a README.

    So: the existence filter is a coincidence, the tracked filter is deliberate
    (a gitignored scratch file must not be red locally and absent in CI —
    the asymmetry `project_locale_default_encoding_class` already cost this
    repo), and the residual is real: a path a guard names as a fixture, which
    someone later creates AND commits, is demanded of the bucket. The negative
    fixture above was moved off `README.md` to a name nobody will create, which
    shrinks that residual without pretending it is closed."""
    import ast
    import pathlib
    import subprocess as _sp
    from glob import glob as _glob

    out = _sp.run(
        ["git", "ls-files", "scanner/tests/test_ci_*.py", "scanner/tests/_ci_guard_util.py"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()

    found = set()
    for rel in out:
        src_path = REPO_ROOT / rel
        if not src_path.is_file():
            continue
        tree = ast.parse(src_path.read_text(encoding="utf-8"))
        # (a) whole-path literals: "docs/devsecops/x.md"
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.endswith((".md", ".toml"))
                # A slash OR a glob metacharacter. Requiring a slash dropped
                # `_CITED_GLOBS`' root `*.md`, which is how the root-markdown
                # bucket alternative ended up pinned by nothing — the census that
                # justifies a bucket entry could not see the read that justifies
                # it.
                and ("/" in node.value or any(c in node.value for c in "*?["))
                and not node.value.startswith(("http", "/tmp"))
            ):
                found.add(node.value)
        # (b) `REPO_ROOT / "docs" / "guides" / "x.md"` — the parts form. Joined
        #     left to right so the reconstruction is the real path, not a guess.
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue
            parts, cur = [], node
            while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Div):
                if isinstance(cur.right, ast.Constant) and isinstance(cur.right.value, str):
                    parts.append(cur.right.value)
                cur = cur.left
            if isinstance(cur, ast.Name) and cur.id == "REPO_ROOT" and parts:
                candidate = "/".join(reversed(parts))
                if candidate.endswith((".md", ".toml")):
                    found.add(candidate)

    # GLOB EXPANSION, over `git ls-files`. A literal-and-parts census is blind to
    # every guard that reaches its documents by pattern, and a review measured
    # what that cost: `ADR_GLOB = "docs/devsecops/adr-[0-9]*.md"` and
    # `_CITED_GLOBS`' root `*.md` meant `adr-002-merge-gate-posture.md` was in no
    # census entry and no root markdown was either — so ONE of the four bucket
    # alternatives this pins (`[^/]*\.md$`) could be deleted with the whole suite
    # green, which is the exact thing this function exists to prevent.
    #
    # `git ls-files` rather than `Path.glob` for the reason the sibling census
    # uses it: a gitignored scratch file is red locally and absent in CI.
    #
    # INJECTABLE, because the intersection is a no-op on a clean tree — census
    # size 109 with it and 109 without — so reverting it left `Ran 43 tests ...
    # OK`. A guard whose fix can be reverted green is not a fix, which is the
    # whole subject of this file; the parameter exists so a test can hand in a
    # tracked set with one entry withheld and prove the branch is load-bearing.
    if tracked is None:
        tracked = set(
            _sp.run(["git", "ls-files"], cwd=REPO_ROOT,
                    capture_output=True, text=True, check=True).stdout.split()
        )
    expanded = set()
    for entry in found:
        if any(ch in entry for ch in "*?["):
            # `glob(..., recursive=True)`, matching how the guards themselves
            # expand these patterns (`test_ci_adr_decision_numbering:233`). NOT
            # `fnmatch`, whose `*` crosses `/`: with it, root `*.md` swallowed
            # `scanner/AGENTS.md` and `hooks/README.md` and the census demanded
            # bucket entries for files no guard reads. Over-reporting here is not
            # free — it turns `test_every_workflow_and_installed_template_is_
            # covered` into a false alarm, which is how a guard gets weakened.
            for hit in _glob(str(REPO_ROOT / entry), recursive=True):
                rel = str(pathlib.PurePath(hit).relative_to(REPO_ROOT))
                if rel in tracked:
                    expanded.add(rel)
        elif entry in tracked:
            # Intersected with `git ls-files` on THIS branch too, not just the
            # glob branch above. Without it a plain literal naming an untracked
            # file — a local scratch doc, or a fixture path someone created but
            # never committed — is demanded of the bucket locally and absent in
            # CI, which is a guard that disagrees with itself by machine.
            expanded.add(entry)
    return sorted(f for f in expanded if (REPO_ROOT / f).is_file())


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

    def test_canary_job_is_declared_gated_and_required(self):
        self.assertEqual(canary_job_problems(self.raw), [])

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

    def test_a_bucket_that_stops_covering_the_runners_is_caught(self):
        """The proof scripts must be INSIDE the gate that runs them.

        Measured when they were introduced: both runners fell outside the
        `ci_config` bucket, so a PR editing only `_ci_guard_runner.py` — the
        script that decides which guards run and whether they passed — would not
        have fired `ci-guards` or `renderer-canary`. The path gate would have
        hidden a change to the evidence itself.

        Mutated by NARROWING the alternation back to the exact previous
        spelling, so the RED can come from nothing else."""
        narrowed = apply_mutation(
            self.lint,
            r"scanner/tests/(test_ci_|_ci_)",
            r"scanner/tests/(test_ci_|_ci_guard_util\.py)",
        )
        missed = uncovered_paths(bucket_pattern(narrowed))
        for spec in PROOF_SPECS.values():
            self.assertIn(
                spec["runner"], missed,
                f"narrowing the bucket left `{spec['runner']}` reported as "
                "covered — the check cannot see the runners at all",
            )

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

    def test_the_guard_data_files_are_derived_not_empty(self):
        # Canary on the derivation itself: if the import broke or a constant was
        # renamed, `guard_data_files()` would return nothing and the two
        # mutations below would pass for free.
        data = guard_data_files()
        # A FLOOR, not an equality. The first version pinned `len == 2` around a
        # hand-written pair, and a review measured what that concealed: the ADR
        # series was read by two guards and matched no bucket at all. An equality
        # would now have to be edited every time a guard starts reading a doc —
        # i.e. exactly when the check should be growing on its own.
        self.assertGreaterEqual(
            len(data), 8, f"the AST census collapsed — only found {data}"
        )
        # Anchors on cases known to be in the set, one per extraction FORM, so a
        # census that silently lost either form fails here rather than shrinking
        # quietly. The parts form is the one a literal-only scan missed.
        self.assertIn("docs/devsecops/ci-guard-inventory.toml", data)  # literal
        self.assertIn("docs/guides/compliance-mapping.md", data)  # REPO_ROOT / parts
        self.assertIn("docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md", data)
        # The GLOB form's own anchor. `adr-002` is reachable only through
        # `ADR_GLOB`, and its absence is what left one bucket alternative
        # unpinned while the suite stayed green.
        self.assertIn("docs/devsecops/adr-002-merge-gate-posture.md", data)
        self.assertIn("MEMORY.md", data)  # root `*.md` from `_CITED_GLOBS`
        for rel in data:
            with self.subTest(path=rel):
                self.assertTrue(
                    (REPO_ROOT / rel).is_file(),
                    f"{rel} is derived from a guard but does not exist on disk",
                )

    def test_the_plain_literal_branch_intersects_the_tracked_set(self):
        """The intersection is load-bearing, proven by WITHHOLDING one entry.

        This exists because the honest version of the sibling test below could
        not do it. On a clean tree the intersection is a NO-OP — census size 109
        with it and 109 without — so reverting `elif entry in tracked:` to `else:`
        left the suite at `Ran 43 tests ... OK`. A fix that reverts green is not
        a fix, and this file exists to say so about other people's code.

        `ci-guard-inventory.toml` is reached by the PLAIN-LITERAL branch (no glob
        metacharacter), so withholding it from the tracked set must drop it. With
        the branch reverted to `else:` it survives and this fails."""
        entry = "docs/devsecops/ci-guard-inventory.toml"
        import subprocess as _sp

        real = set(
            _sp.run(
                ["git", "ls-files"], cwd=REPO_ROOT,
                capture_output=True, text=True, check=True,
            ).stdout.split()
        )
        self.assertIn(entry, real, "fixture premise broke: the file is untracked")
        self.assertIn(
            entry, guard_data_files(tracked=real),
            "control: the entry must be in the census when tracked",
        )
        self.assertNotIn(
            entry, guard_data_files(tracked=real - {entry}),
            "a plain literal survived the census while untracked — the "
            "`git ls-files` intersection on that branch is not doing anything, "
            "and an untracked file would be demanded of the `ci_config` bucket "
            "on one machine only",
        )

    def test_every_census_entry_is_tracked_by_git(self):
        """VACUOUS ON THE SHIPPED TREE, and kept anyway — as a property, not a pin.

        `guard_data_files()` filters to tracked, so `untracked` is empty by
        construction and this cannot fail here. It also cannot detect the removal
        of the line it was added for; that is
        `test_the_plain_literal_branch_intersects_the_tracked_set` above, which
        withholds an entry instead of hoping the tree provides one.

        What it does buy: if a future branch reaches files some other way, this
        states the invariant in one line at the point of use. Recorded as vacuous
        rather than left to read as a guard — a check that cannot fail, filed
        among checks that can, is how a suite's green stops meaning anything."""
        import subprocess as _sp

        tracked = set(
            _sp.run(
                ["git", "ls-files"], cwd=REPO_ROOT,
                capture_output=True, text=True, check=True,
            ).stdout.split()
        )
        untracked = [rel for rel in guard_data_files() if rel not in tracked]
        self.assertEqual(
            untracked, [],
            "census entries not tracked by git — the bucket would be demanded to "
            f"cover files CI never sees: {untracked}",
        )

    def test_the_census_demands_no_markdown_under_scanner_tests(self):
        """The fixture-promotion hazard, pinned rather than assumed away.

        `guard_data_files()` cannot tell a path a guard READS from one it merely
        NAMES. `test_ci_catalog_no_ghost_rows` names `scanner/tests/<x>.md` as a
        deliberately-NONEXISTENT negative fixture, and measured, creating that
        file took three tests across two guards red — two of them here, because
        the census promoted the fixture into a path the bucket must match.

        No guard reads a `.md` under `scanner/tests/`, so anything appearing
        there is a fixture that became real. Failing here NAMES that, which the
        bucket-coverage failures do not.

        It does not REPLACE them: a first draft of this docstring said this fires
        "instead of" an unrelated bucket-coverage failure, and that was measured
        false — with the fixture path tracked, this pin and both bucket-coverage
        tests fail together, four reds rather than three. The value is the
        message, not a reduced blast radius."""
        promoted = [
            rel for rel in guard_data_files()
            if rel.startswith("scanner/tests/") and rel.endswith(".md")
        ]
        self.assertEqual(
            promoted, [],
            "a Markdown path under scanner/tests entered the census. If it is a "
            "real document, no guard reads it and the bucket should not be asked "
            "to cover it; if it is a test fixture that got created, rename the "
            f"fixture to a name nobody will create: {promoted}",
        )

    def test_dropping_docs_from_the_bucket_is_caught(self):
        """`docs/` carries the guard-read DATA surface.

        Out of the bucket, a PR editing only the guard inventory, the published
        catalog, or an ADR fires neither `ci-guards` nor `scanner-unit-tests` nor
        `renderer-canary` — so deleting a guard's inventory entry, or planting a
        dangling citation, is checked by nothing. Measured twice: #530 for the
        inventory and the catalog, and a review for the ADR series, which was
        still uncovered in the commit whose subject was closing that hole."""
        mutant = apply_mutation(self.lint, "|docs/|", "|__docs_removed__/|")
        uncovered = uncovered_paths(bucket_pattern(mutant))
        self.assertIn("docs/devsecops/ci-guard-inventory.toml", uncovered)
        self.assertIn(
            "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md",
            uncovered,
        )
        self.assertNotIn(
            ".github/workflows/dast-full-scan.yml", uncovered,
            "fixture must remove ONLY the docs alternative, or the RED does not "
            "isolate the invariant under test",
        )

    def test_dropping_dot_claude_from_the_bucket_is_caught(self):
        """`.claude/**/*.md` is in `_CITED_GLOBS`, so a dangling citation there
        fails `test_every_citation_resolves` the same as one in `docs/`."""
        mutant = apply_mutation(self.lint, "|\\.claude/|", "|__claude_removed__/|")
        self.assertNotEqual(
            mutant, self.lint, "fixture is stale — the `.claude/` alternative moved"
        )
        pat = re.compile(bucket_pattern(mutant))
        # NOT a `.claude/skills/` path: the bucket carries a pre-existing
        # `\.claude/skills/` alternative as well, so a skills path still matches
        # after `\.claude/` is removed and the probe would report a working
        # mutation as broken. Attack the harness first.
        self.assertFalse(
            pat.match(".claude/rules/coding-style.md"),
            "`.claude/` still matched after its alternative was removed — the "
            "mutation isolated nothing",
        )
        self.assertTrue(
            re.compile(bucket_pattern(self.lint)).match(".claude/rules/coding-style.md"),
            "control: the real bucket must cover `.claude/` outside skills/",
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

    def test_removing_the_canary_from_the_aggregator_is_caught(self):
        """Outside `lint-gate.needs` the canary can go red while `Lint` stays
        green — and `Lint` is the only required context."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(self.lint, "      - renderer-canary\n", ""),
            "renderer-canary dropped from lint-gate.needs",
        )

    def test_dropping_the_oracle_install_is_caught(self):
        """Without `markdown-it-py` every class the job runs SKIPS, and the job
        reports success having adjudicated nothing. That is the fail-open the
        job was created to close, so it must not be reachable by deleting one
        line."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(self.lint, "markdown-it-py==4.0.0", "some-other-pkg==1.0"),
            "renderer-canary no longer installs the oracle",
        )

    def test_the_canary_runner_rejects_every_non_pass(self):
        """The four shell-loop checks, replaced by EXECUTING their successor.

        This supersedes four assertions that scanned the step's text for a skip
        grep, a `^Ran [1-9]` grep, `for spec in`, and a `did not run ${method}`
        message. All four described a loop that parsed `unittest -v` PROSE, and
        prose a run produces is prose a FAILING run can shape — measured, a red
        class carrying a column-0 `OK ` line satisfied the verdict grep once the
        failure branch was weakened.

        SYNTHETIC TARGET MODULES, one per direction, because the first version
        of this test was wrong in a way mutation scoring caught: it produced a
        skip by withholding the oracle, which trips the runner's oracle check
        FIRST and returns before the skip logic is ever reached. `if
        result.skipped:` scored 0 red — the assertion passed for a reason
        unrelated to what it named. Each branch now has a target that isolates
        it."""
        import os
        import subprocess
        import tempfile

        runner_src = (REPO_ROOT / CANARY_RUNNER).read_text()
        ORACLE = _import_canary_runner().ORACLE_VERSION
        MODULES = {
            "mod_ok.py": (
                "import unittest\n"
                "class C(unittest.TestCase):\n"
                "    def test_it(self): pass\n"
            ),
            "mod_skip.py": (
                "import unittest\n"
                "class C(unittest.TestCase):\n"
                "    @unittest.skip('withheld dependency')\n"
                "    def test_it(self): pass\n"
            ),
            "mod_fail.py": (
                "import unittest\n"
                "class C(unittest.TestCase):\n"
                "    def test_it(self): self.fail('OK  a\\nOK')\n"
            ),
        }

        def drive(adjudicators, block_oracle=False, argv=()):
            # A STUB ORACLE, not the installed package. `ci-guards` installs
            # NOTHING by design — that is what lets it run on a broad path
            # bucket without a pip step — so a test that needs the real
            # markdown-it-py passes locally and fails there. It did: this test
            # was green on a machine with the package and red in CI with
            # `markdown-it-py is not importable`.
            #
            # Skipping on ImportError would have been the wrong fix twice over:
            # it is the fail-open this whole job exists to close, and it would
            # have made the test vacuous exactly where it runs. A stub makes the
            # oracle branch satisfiable without depending on what is installed,
            # and the `block_oracle` row below still exercises the failure
            # direction with a module that raises.
            with tempfile.TemporaryDirectory() as d:
                marker = "ADJUDICATORS = ("
                head = runner_src[:runner_src.index(marker)]
                tail = runner_src[
                    runner_src.index("\n)\n", runner_src.index(marker)) + 3:
                ]
                shim = Path(d, "_ci_canary_runner.py")
                shim.write_text(
                    head + f"ADJUDICATORS = {adjudicators!r}" + tail
                )
                for name, body in MODULES.items():
                    Path(d, name).write_text(body)
                # WRITTEN INTO `d` ITSELF, not a directory earlier on
                # PYTHONPATH. Python puts a script's own directory at
                # `sys.path[0]`, ahead of PYTHONPATH — measured: a blocking
                # module on PYTHONPATH lost to the stub sitting next to the
                # shim, and the "missing oracle" row came back green.
                Path(d, "markdown_it.py").write_text(
                    'raise ImportError("withheld")\n' if block_oracle
                    else f'__version__ = "{ORACLE}"\n'
                )
                r = subprocess.run(
                    [sys.executable, str(shim), *argv],
                    capture_output=True, text=True, cwd="/",
                    env={"PATH": os.environ["PATH"], "PYTHONPATH": d},
                )
                return r.returncode, r.stdout.strip(), r.stderr

        OK = (("mod_ok.C", "test_it"),)

        # NON-VACUITY FIRST, or every negative row below passes for free.
        code, out, err = drive(OK)
        self.assertEqual(code, 0, err[-1200:])
        self.assertEqual(out, "ran=1", err[-1200:])

        with self.subTest(direction="a SKIPPED adjudicator is not a pass"):
            # `unittest` counts a skip in `Ran N` and exits 0, which is why a
            # count-based check could never see one.
            code, out, err = drive((("mod_skip.C", "test_it"),))
            self.assertNotEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("SKIPPED in the job that exists to run it", err)

        with self.subTest(direction="a FAILING adjudicator is not a pass"):
            code, out, err = drive((("mod_fail.C", "test_it"),))
            self.assertNotEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("did not run and pass", err)
            # Attribution: the `OK ` line the old grep-based verdict would have
            # read really is in this output.
            self.assertIn("OK  a", err)

        with self.subTest(direction="a renamed method is not a pass"):
            # NOTE THE MECHANISM: `loadTestsFromName` does NOT raise for a
            # missing method — it returns a suite holding a synthetic
            # `_FailedTest` that runs and errors. So the load-time branch never
            # fires and `wasSuccessful()` is what rejects it. An earlier version
            # of this assertion expected the load-time message and failed; the
            # runner was right and the expectation was wrong.
            code, out, err = drive((("mod_ok.C", "test_gone"),))
            self.assertNotEqual(code, 0)
            self.assertEqual(out, "")
            self.assertIn("did not run and pass", err)

        with self.subTest(direction="a missing oracle is a hard failure"):
            # Asserted on the ORACLE branch's own message, not on a substring
            # the skip branch could also produce — the two used to mask each
            # other and both scored 0 red.
            code, out, err = drive(OK, block_oracle=True)
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("markdown-it-py is not importable", err)

        with self.subTest(direction="no arguments accepted"):
            code, out, err = drive(OK, argv=("-k", "*bucket*"))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("takes no arguments", err)

    def test_rewiring_the_canary_gate_is_caught(self):
        """The gate is asserted, not merely present.

        Anchored on `timeout-minutes` / `needs:` rather than on the `if:` line's
        neighbouring `uses:` steps, because those carry action SHAs: a routine
        Dependabot checkout bump would make the fixture stale and red-light this
        test with "fixture is stale", and the obvious maintainer fix — refresh
        the anchor — silently re-greens whatever the gate had become. A review
        walked exactly that chain and landed on an inverted gate with 1230 tests
        passing."""
        # Anchored on the job NAME, which is unique. The bare
        # `timeout-minutes / needs / if` trio appears TWICE — `ci-guards` carries
        # an identical one — so a fixture without the name mutates the WRONG JOB
        # and the RED proves something else entirely. Placement decides a probe's
        # verdict.
        anchor = (
            "    name: Markdown renderer canary\n"
            "    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 5\n    needs: changes\n"
            "    if: needs.changes.outputs.ci_config == 'true' "
            "|| github.event_name == 'schedule'"
        )
        for label, replacement in (
            ("inverted", "ci_config == 'false'"),
            ("ANDed with the kcov bucket",
             "ci_config == 'true' && needs.changes.outputs.scanner == 'true'"),
            ("name survives only in a comment",
             "github.event_name == 'schedule'  # was ci_config"),
        ):
            with self.subTest(rewiring=label):
                mutant = apply_mutation(
                    self.lint,
                    anchor,
                    "    name: Markdown renderer canary\n"
                    "    runs-on: ubuntu-latest\n"
                    "    timeout-minutes: 5\n    needs: changes\n    if: "
                    + replacement,
                )
                assert_disables(
                    canary_job_problems, self.lint, mutant,
                    f"renderer-canary gate {label}",
                )

    def test_parking_the_canary_step_in_a_comment_is_not_execution(self):
        """Mirrors `test_a_commented_out_invocation_is_not_execution` for the
        sibling job, which the canary's pin was missing.

        Measured before the fix: replacing the step body with `run: echo` while
        leaving every command in `#` lines returned `[]` and left 1230 guards
        green."""
        start = self.lint.index(
            "      - name: Run the renderer-adjudicated guard classes"
        )
        end = self.lint.index("\n  scanner-unit-tests:")
        body = self.lint[start:end]
        parked = (
            "      - name: Run the renderer-adjudicated guard classes\n"
            "        # Parked pending investigation. Restore:\n"
            + "\n".join(
                "        # " + line.strip()
                for line in body.splitlines()[1:]
                if line.strip()
            )
            + '\n        run: echo "renderer canary parked"\n'
        )
        assert_disables(
            canary_job_problems,
            self.lint,
            self.lint[:start] + parked + self.lint[end:],
            "renderer-canary step parked in a comment",
        )

    def test_parking_the_canary_step_in_an_env_scalar_is_not_execution(self):
        """Comment-parking was closed; BLOCK-parking was not.

        A review moved every command into `env: PARKED_RESTORE_ME: |` and reduced
        `run:` to `echo`, and the pin returned no problems with 1232 guards
        green. `test_ci_reachability.executed_shell` already consumes and
        discards a block scalar belonging to any other key — writing a third
        extractor instead of importing the one that already knew was the
        mistake."""
        start = self.lint.index(
            "      - name: Run the renderer-adjudicated guard classes"
        )
        end = self.lint.index("\n  scanner-unit-tests:")
        body = self.lint[start:end]
        commands = "\n".join(
            "            " + line.strip()
            for line in body.splitlines()[1:]
            if line.strip()
        )
        parked = (
            "      - name: Run the renderer-adjudicated guard classes\n"
            "        env:\n          PARKED_RESTORE_ME: |\n"
            + commands
            + '\n        run: echo "renderer canary parked"\n'
        )
        assert_disables(
            canary_job_problems,
            self.lint,
            self.lint[:start] + parked + self.lint[end:],
            "renderer-canary step parked in an env: scalar",
        )

    def test_parking_the_canary_step_in_a_heredoc_is_not_execution(self):
        """One parking shape. NOT the last, and this docstring used to imply it.

        Comment-parking and env-parking were both closed by routing through
        `executed_shell`. This one it CANNOT close: its own docstring names
        heredoc bodies as the single limitation that can hide an unrun test, and
        it is right — every command sits inside a real `run: |`, so the extractor
        credits all of them while the shell runs `cat` and exits 0. Measured
        before the fix: `canary_job_problems() == []`.

        THE RESIDUAL, MEASURED, because an earlier draft called this "the third
        parking shape" as though the enumeration were complete. `executed_shell`
        models no CONTROL FLOW, so every one of these parks the step with zero
        problems reported and zero test output, and none contains `<<`:

            first line of the run body   canary_job_problems()   `Ran [1-9]` lines
            `exit 0`                     []                      0
            `if false; then` ... `fi`    []                      0
            `park() {` ... `}` uncalled  []                      0
            `set -n`                     []                      0
            (unmutated control)          []                      3

        `exit 0` is one token and cheaper than the heredoc this test closes. That
        is a property of static text analysis, not a bug in the check: proving a
        shell script reaches its end requires running it. It is stated here
        because a defence that reads complete and is not is the failure this file
        exists to catch, and it applies to every `run:` step in the repo — this
        job is not special, it is merely the one with a docstring about it."""
        start = self.lint.index(
            "      - name: Run the renderer-adjudicated guard classes"
        )
        end = self.lint.index("\n  scanner-unit-tests:")
        body = self.lint[start:end]
        quoted = "\n".join(
            "          " + line.strip()
            for line in body.splitlines()[1:]
            if line.strip()
        )
        parked = (
            "      - name: Run the renderer-adjudicated guard classes\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          cat <<'PARKED_EOF'\n"
            + quoted
            + "\n          PARKED_EOF\n"
            '          echo "renderer canary parked"\n'
        )
        assert_disables(
            canary_job_problems,
            self.lint,
            self.lint[:start] + parked + self.lint[end:],
            "renderer-canary step parked in a heredoc body",
        )

    #: Constructs that swallow a span of shell without executing it. Not an
    #: enumeration the design depends on — the data dependency does not care
    #: which one is used — but each was measured to DEFEAT the earlier
    #: constant-marker design, so each is pinned as a regression.
    PARKING_WRAPS = {
        "if": ('if [ "${__PARK:-}" = "1" ]; then', "fi"),
        "case": ('case "${__PARK:-}" in Plan9)', ";; esac"),
        "uncalled function": ("__park() {", "}"),
    }

    def _job_body(self, job):
        block = job_block(self.lint, job)
        self.assertIsNotNone(block, f"job `{job}` not found")
        return block_scalar_body(block)

    def test_parking_the_step_is_caught_and_publishes_nothing(self):
        """Parking, against the shape that has no shell variable left.

        Under the previous design the publish line read `$ran`, so parking the
        work left it unbound and `set -u` killed the step. That mechanism is
        gone with the variable — and it is not missed, because parking now fails
        in two independent places instead:

          static  the step's executed shell is EXHAUSTIVELY `set -euo pipefail`
                  plus the anchored invocation, so the `if`/`fi` a parking
                  construct must add are extra lines and get rejected outright;
          runtime the invocation itself is inside the parked span, so nothing is
                  appended, `outputs.ran` is empty, and `lint-gate` rejects it as
                  not a positive integer.

        The runtime half is the one that survives someone editing this guard, so
        both are asserted."""
        for job, spec in PROOF_SPECS.items():
            body = self._job_body(job)
            lines = body.splitlines()
            start = lines.index("set -euo pipefail") + 1
            invocation = next(
                i for i, ln in enumerate(lines)
                if spec["invocation"].match(ln.strip())
            )
            for name, (open_, close_) in self.PARKING_WRAPS.items():
                with self.subTest(job=job, shape=name):
                    parked_lines = (
                        lines[:start] + [open_] + lines[start:invocation + 1]
                        + [close_]
                    )
                    block = job_block(self.lint, job)
                    mutated = self.lint.replace(
                        block,
                        block.replace(
                            "\n".join(lines),
                            "\n".join(parked_lines),
                        ),
                        1,
                    )
                    if mutated != self.lint:
                        self.assertTrue(
                            job_ran_proof_problems(mutated),
                            f"{job}/{name}: a parked step was accepted",
                        )
                    code, written = self._run_body("\n".join(parked_lines))
                    self.assertEqual(
                        written, "",
                        f"{job}/{name}: a parked step still published "
                        f"{written!r}",
                    )

    def _run_body(self, script, want_stderr=False):
        import os
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "gh_output")
            out.write_text("")
            r = subprocess.run(
                ["bash", "-c", script],
                cwd=str(REPO_ROOT),
                env={
                    "GITHUB_OUTPUT": str(out),
                    "PATH": os.environ["PATH"],
                    # bash reports an unbound variable in the C locale here, and
                    # `test_the_publish_line_is_the_thing_that_dies` matches on
                    # the variable NAME rather than the message, but a
                    # translated message on a developer machine is still worth
                    # not depending on.
                    "LC_ALL": "C",
                },
                capture_output=True, text=True,
            )
            written = out.read_text()
        if want_stderr:
            return r.returncode, written, r.stderr
        return r.returncode, written

    def test_an_unparked_body_does_publish(self):
        """Non-vacuity for the parking subtests: same shape, nothing parked.

        Synthetic rather than real, because the real unparked bodies need the
        whole guard suite and the pinned renderer oracle. It mirrors the real
        data dependency exactly — a value parsed out of captured work output —
        which is the only part the subtests above rely on."""
        script = (
            'set -euo pipefail\n'
            'out=$(printf "Ran 7 tests in 0.1s\\nOK\\n")\n'
            'ran=$(printf \'%s\\n\' "$out" | sed -nE '
            "'s/^Ran ([1-9][0-9]*) tests? in .*/\\1/p')\n"
            '[ -n "$ran" ]\n'
            'echo "ran=$ran" >> "$GITHUB_OUTPUT"'
        )
        code, written = self._run_body(script)
        self.assertEqual(code, 0, "the control harness cannot even run")
        self.assertEqual(
            written.strip(), "ran=7",
            "the harness cannot publish a derived proof even unparked — the "
            "parking subtests prove nothing",
        )

    #: The `out=$(...)` capture in `ci-guards`, matched whole so a mutation
    #: replaces the invocation AND its failure branch together.
    _CI_GUARDS_CAPTURE = (
        "out=$(python3 -m unittest discover -s . -p 'test_ci_*.py' 2>&1) || {\n"
        "  printf '%s\\n' \"$out\"\n"
        "  exit 1\n"
        "}"
    )

    def _ci_guards_with_capture(self, replacement):
        body = self._job_body("ci-guards")
        lines = body.splitlines()
        start = next(i for i, ln in enumerate(lines) if ln.startswith("out=$("))
        end = next(i for i in range(start, len(lines)) if lines[i] == "}")
        return "\n".join(lines[:start] + [replacement] + lines[end + 1:])

    def test_the_guard_runner_publishes_only_when_the_suite_passed(self):
        """The verdict is `wasSuccessful()`, not a grep. Driven, not read.

        Three shell versions of this check were defeated in a row. The last one
        greped the run's own output for `^OK( |$)`, which a failing run can
        satisfy: `2>&1` captures the whole failure report, and this repo's
        guards routinely build multi-line messages whose lines start at column
        0. Measured — a red suite with an `OK ` line in it, plus the failure
        branch weakened to `|| true`, exited 0 and published `ran=2`.

        Driven in a temp directory rather than against `scanner/tests`, because
        the runner scans ITS OWN parent: dropping the shim next to synthetic
        fixtures gives exact control over pass/fail without touching the repo."""
        import os
        import subprocess
        import tempfile

        PASSING = (
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_a(self): pass\n"
            "    def test_b(self): pass\n"
        )
        FAILING = (
            "import unittest\n"
            "class U(unittest.TestCase):\n"
            # A failure message whose line starts at column 0 with `OK `, which
            # is exactly what defeated the grep-based verdict.
            "    def test_c(self): self.fail('OK  docs/a.md\\nOK')\n"
        )

        def drive(files, argv=()):
            with tempfile.TemporaryDirectory() as d:
                Path(d, "_ci_guard_runner.py").write_text(
                    (REPO_ROOT / GUARD_RUNNER).read_text()
                )
                for name, body in files.items():
                    Path(d, name).write_text(body)
                r = subprocess.run(
                    [sys.executable, str(Path(d, "_ci_guard_runner.py")), *argv],
                    capture_output=True, text=True, cwd="/",
                    env={"PATH": os.environ["PATH"]},
                )
                return r.returncode, r.stdout.strip(), r.stderr

        # NON-VACUITY: the harness must be able to publish at all.
        code, out, err = drive({"test_ci_pass.py": PASSING})
        self.assertEqual(code, 0, err[-800:])
        self.assertEqual(out, "ran=2", err[-800:])

        with self.subTest(direction="a failing test blocks the count"):
            code, out, err = drive(
                {"test_ci_pass.py": PASSING, "test_ci_fail.py": FAILING}
            )
            self.assertNotEqual(code, 0)
            self.assertEqual(
                out, "",
                "a red suite published a count — the verdict is not structural",
            )
            self.assertIn("FAILED", err)
            # Attribution: the `OK ` line really is present in the output that
            # the old grep-based verdict would have read.
            self.assertIn("OK  docs/a.md", err)

        with self.subTest(direction="an empty tree is not a vacuous pass"):
            code, out, err = drive({})
            self.assertEqual(code, 2)
            self.assertEqual(out, "")

        with self.subTest(direction="no arguments accepted"):
            # Pinned separately from the canary runner's identical refusal:
            # mutation scoring showed `if argv:` in THIS runner at 0 red, i.e.
            # nothing was holding it. An appended `-k '*bucket*'` is what cut a
            # real run from 1264 tests to 18.
            #
            # DRIVEN AGAINST A COPY, never `REPO_ROOT / GUARD_RUNNER`. The first
            # version ran the real runner, and mutation scoring found what that
            # costs: with the refusal removed, the runner falls through to
            # discovering `scanner/tests` — which contains THIS test, which
            # spawns the runner again. Unbounded recursion. It hung for 18 hours
            # before it was killed, and in CI it would burn the job timeout
            # instead of failing. A copy scans only its own temp directory, so
            # the same mutation now fails fast.
            code, out, err = drive({"test_ci_pass.py": PASSING}, argv=("-k", "*x*"))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("takes no arguments", err)

        with self.subTest(direction="a narrowed run is rejected"):
            # The floor tied to something the shell does not choose: more guard
            # FILES than tests that ran means discovery was cut short.
            with tempfile.TemporaryDirectory() as d:
                Path(d, "_ci_guard_runner.py").write_text(
                    (REPO_ROOT / GUARD_RUNNER).read_text()
                )
                for n in range(3):
                    Path(d, f"test_ci_m{n}.py").write_text(
                        "import unittest\n"
                        f"class C{n}(unittest.TestCase):\n"
                        # Only ONE module contributes a test; the other two are
                        # importable but empty, so testsRun < len(files).
                        + ("    def test_it(self): pass\n" if n == 0 else "    pass\n")
                    )
                r = subprocess.run(
                    [sys.executable, str(Path(d, "_ci_guard_runner.py"))],
                    capture_output=True, text=True, cwd="/",
                    env={"PATH": os.environ["PATH"]},
                )
            self.assertNotEqual(r.returncode, 0, r.stderr[-600:])
            self.assertEqual(r.stdout.strip(), "")
            self.assertIn("was narrowed", r.stderr)

        with self.subTest(direction="cwd cannot redirect the scan"):
            # Driven from `/` above already; this pins that a decoy suite in the
            # CWD is not what gets scanned.
            with tempfile.TemporaryDirectory() as decoy:
                Path(decoy, "test_ci_decoy.py").write_text(
                    "import unittest\n"
                    "class D(unittest.TestCase):\n"
                    "    def test_only(self): pass\n"
                )
                with tempfile.TemporaryDirectory() as d:
                    Path(d, "_ci_guard_runner.py").write_text(
                        (REPO_ROOT / GUARD_RUNNER).read_text()
                    )
                    Path(d, "test_ci_pass.py").write_text(PASSING)
                    r = subprocess.run(
                        [sys.executable, str(Path(d, "_ci_guard_runner.py"))],
                        capture_output=True, text=True, cwd=decoy,
                        env={"PATH": os.environ["PATH"]},
                    )
            self.assertEqual(r.returncode, 0, r.stderr[-800:])
            self.assertEqual(
                r.stdout.strip(), "ran=2",
                "the runner scanned the CWD instead of its own directory",
            )

    def test_the_runners_cannot_publish_a_count_they_did_not_compute(self):
        """The relocated hole: four lines in a runner, `OK (Ran 1258 tests)`.

        Both runners are read, because the measured defeat applied to both at
        once. Every mutation below was executed as well as detected — the
        short-circuits really did print a positive integer at exit 0 with zero
        guards run, which is what makes them the sharp case rather than a
        hypothetical one."""
        for rel, data_expr in RUNNER_PUBLICATION.items():
            src = (REPO_ROOT / rel).read_text()
            with self.subTest(runner=rel, direction="control"):
                self.assertEqual(
                    runner_publication_problems(src, rel, data_expr), [],
                    "the real runner does not satisfy its own pin",
                )

            # The MEASURED defeat, in both spellings. The second reads no
            # environment at all, so a fixture that merely sets `GITHUB_ACTIONS`
            # would not have reached it.
            count = "1264" if rel == GUARD_RUNNER else "3"
            short_circuits = {
                "env-conditional": (
                    "    import os\n"
                    '    if os.environ.get("GITHUB_ACTIONS") == "true":\n'
                    f'        print("ran={count}")\n'
                    "        return 0\n"
                ),
                "location-conditional": (
                    '    if GUARD_DIR.name == "tests":\n'
                    f'        print("ran={count}")\n'
                    "        return 0\n"
                ),
            }
            # Every mutation below asserts it CHANGED the source before asserting
            # the detector saw it: a `.replace()` whose needle has drifted is a
            # no-op, and a no-op mutation makes the detector look correct for the
            # one reason that would mean it is not being exercised at all.
            anchor = "def main(argv: list) -> int:\n"
            for label, injected in short_circuits.items():
                with self.subTest(runner=rel, direction=label):
                    mutated = src.replace(anchor, anchor + injected, 1)
                    self.assertNotEqual(mutated, src, "the mutation did not apply")
                    self.assertNotEqual(
                        runner_publication_problems(mutated, rel, data_expr), [],
                        f"a {label} short-circuit was accepted",
                    )

            with self.subTest(runner=rel, direction="a constant count"):
                mutated = src.replace(
                    f'print(f"ran={{{data_expr}}}")', f'print("ran={count}")', 1
                )
                self.assertNotEqual(mutated, src, "the publication site moved")
                problems = runner_publication_problems(mutated, rel, data_expr)
                self.assertTrue(
                    any("CONSTANT" in p for p in problems), problems
                )

            with self.subTest(runner=rel, direction="a count from somewhere else"):
                mutated = src.replace(
                    f'print(f"ran={{{data_expr}}}")', 'print(f"ran={len(sys.argv)}")', 1
                )
                self.assertNotEqual(mutated, src, "the publication site moved")
                problems = runner_publication_problems(mutated, rel, data_expr)
                self.assertTrue(
                    any("interpolates" in p for p in problems), problems
                )

            with self.subTest(runner=rel, direction="a success exit that is not last"):
                # No `print` at all — only the early success exit. This is the
                # half that does not depend on enumerating what the branch reads.
                mutated = src.replace(anchor, anchor + "    return 0\n", 1)
                self.assertNotEqual(mutated, src, "the mutation did not apply")
                problems = runner_publication_problems(mutated, rel, data_expr)
                self.assertTrue(
                    any("return 0" in p for p in problems), problems
                )

    def test_the_canary_table_drifting_from_the_guard_is_caught(self):
        """`CANARY_CLASSES` and the runner's `ADJUDICATORS` are one spec in two
        files, so drift between them must be a failure rather than a silent
        divergence — this repo has lost a check to a drifted second copy before.

        Mutated on the GUARD side, so the runner (which CI executes) stays
        correct and only the pin moves."""
        original = tuple(CANARY_CLASSES)
        narrowed = original[:-1]
        import test_ci_guard_self_verify as self_mod

        self_mod.CANARY_CLASSES = narrowed
        try:
            problems = canary_job_problems(self.lint)
        finally:
            self_mod.CANARY_CLASSES = original
        self.assertTrue(
            any("drifted" in p for p in problems),
            f"a narrowed CANARY_CLASSES was accepted: {problems}",
        )

    def test_binding_the_published_value_any_other_way_is_caught(self):
        """The enumeration failure mode, closed by removing what it enumerated.

        While the value passed through a shell variable, the guard counted
        `^ran=` assignments — and that pin worked for exactly the one spelling it
        named. Measured on that design, with the work parked and ONE line seeded
        above it, every one of these published `ran=9999` at exit 0 with the
        guard reporting nothing, while a plain `ran=9999` WAS caught:

            read -r ran <<<        printf -v ran        declare ran=
            export ran=            mapfile -t ran       let ran=
            (( ran = ))            for ran in           IFS= read -r ran < <()
            step-level `env: ran:` (zero shell lines at all)

        There is no variable now — the runner appends its own `ran=<count>` — so
        each of these is just an extra line in a step whose executed shell is
        checked exhaustively. Pinned anyway, because the value of this design is
        precisely that the list above stopped mattering, and a future edit that
        reintroduces an intermediate variable should turn this red."""
        seeds = [
            'read -r ran <<< "9999"',
            "printf -v ran %s 9999",
            "declare ran=9999",
            "export ran=9999",
            'mapfile -t ran <<< "9999"',
            "let ran=9999",
            "(( ran = 9999 ))",
            "for ran in 9999; do :; done",
            'echo "ran=9999" >> "$GITHUB_OUTPUT"',
        ]
        for job in PROOF_SPECS:
            block = job_block(self.lint, job)
            anchor = "          set -euo pipefail\n"
            self.assertIn(anchor, block, f"{job}: anchor moved")
            for seed in seeds:
                with self.subTest(job=job, seed=seed[:28]):
                    assert_disables(
                        job_ran_proof_problems,
                        self.lint,
                        self.lint.replace(
                            block,
                            block.replace(anchor, anchor + f"          {seed}\n", 1),
                            1,
                        ),
                        f"{job}: {seed[:28]}",
                    )

    def test_a_step_level_env_cannot_supply_the_value(self):
        """The one seeding shape that adds NO shell line at all.

        `executed_shell` discards every non-`run` key, so a step-level
        `env: ran: '9999'` was invisible to the assignment count — and under the
        old design it published `ran=9999` from a fully parked body. It is
        harmless now for a structural reason rather than a detected one: nothing
        in the step reads a variable, so there is nothing for it to supply.
        Asserted as BEHAVIOUR, since there is no text for a static check to see."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                # `executed_shell`, not the raw body: the first version of this
                # matched `$ran` inside the step's own COMMENTS explaining why
                # the variable was removed, and went red on prose.
                lines = [
                    ln for ln in
                    executed_shell(job_block(self.lint, job)).splitlines()
                    if ln.strip()
                ]
                self.assertFalse(
                    [ln for ln in lines if "$ran" in ln or "${ran" in ln],
                    f"{job}: the step reads a shell variable again, so a "
                    "step-level `env:` could supply it — the shape this design "
                    "removed",
                )
                self.assertTrue(
                    any(spec["invocation"].match(ln.strip()) for ln in lines),
                    f"{job}: invocation not found",
                )

    def test_the_same_control_parks_when_the_work_is_removed(self):
        """The control's own non-vacuity: it must fail when the work is gone.

        Without this, a control that passes for a reason unrelated to the data
        dependency would still look like evidence."""
        script = (
            'set -euo pipefail\n'
            'ran=$(printf \'%s\\n\' "$out" | sed -nE '
            "'s/^Ran ([1-9][0-9]*) tests? in .*/\\1/p')\n"
            '[ -n "$ran" ]\n'
            'echo "ran=$ran" >> "$GITHUB_OUTPUT"'
        )
        code, written = self._run_body(script)
        self.assertNotEqual(code, 0)
        self.assertEqual(written, "")

    def test_a_command_after_the_publish_line_is_caught(self):
        """A command below the invocation can exit before the runner reads the
        output file back — and is an extra line besides."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                line = next(
                    ln for ln in block.splitlines()
                    if spec["invocation"].match(ln.strip())
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block,
                        block.replace(line + "\n", line + "\n          echo done\n", 1),
                        1,
                    ),
                    f"{job}: command added after the invocation",
                )

    def test_the_output_reference_surviving_only_in_a_comment_is_caught(self):
        """Presence vs attribution, for the fourth time in this repo.

        `ref` was searched in the RAW job block. Measured: leave the canonical
        `ran: ${{ steps.<id>.outputs.ran }}` alive in a `#` comment and give the
        real `outputs:` map a literal, and `job_ran_proof_problems` returned `[]`
        with the whole suite at `OK (Ran 1258 tests)`. `ran` is then a constant,
        which is precisely what the rest of this function forbids — the
        data-dependency argument only holds while the value comes from the step.

        Both spellings of a YAML comment, because whole-line and inline are
        stripped by different helpers and only one of them being wired would read
        exactly as green as both."""
        for job in PROOF_JOBS:
            block = job_block(self.lint, job)
            line = next(
                ln for ln in block.splitlines()
                if re.match(r"^\s*ran:\s*\$\{\{\s*steps\.", ln)
            )
            indent = " " * (len(line) - len(line.lstrip()))
            for label, replacement in {
                "whole-line comment": (
                    f"{indent}# {line.strip()}\n{indent}ran: 9999"
                ),
                "inline comment": f"{indent}ran: 9999  # {line.strip()}",
            }.items():
                with self.subTest(job=job, spelling=label):
                    assert_disables(
                        job_ran_proof_problems,
                        self.lint,
                        self.lint.replace(
                            block, block.replace(line, replacement, 1), 1
                        ),
                        f"{job}: output reference parked in a {label}",
                    )

    def test_publishing_from_a_step_that_is_not_the_runner_step_is_caught(self):
        """Two independent selections that were never tied together.

        `proof_steps` is picked by the invocation; the published value is picked
        by the step id in `outputs:`. Nothing required them to be the SAME step,
        so every exhaustive check below could be applied to a step whose output
        nobody reads while a sibling step published a constant. Measured, both
        `guard_job_problems` and `job_ran_proof_problems` returned `[]`; adding
        `if: false` to the invoking step then made it a complete fail-open,
        caught only by a guard in another file."""
        for job in PROOF_JOBS:
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                ref = re.search(
                    r"ran:\s*\$\{\{\s*steps\.([\w-]+)\.outputs\.ran\s*\}\}", block
                )
                id_line = next(
                    ln for ln in block.splitlines()
                    if re.match(rf"^\s*id:\s*{re.escape(ref.group(1))}\s*$", ln)
                )
                indent = " " * (len(id_line) - len(id_line.lstrip()))
                item = indent[:-2]
                # The id, and a step publishing a constant under it, MOVE OFF the
                # invoking step and onto a new one in front of it.
                decoy = (
                    f"{item}- name: Publish the proof\n"
                    f"{id_line}\n"
                    f"{indent}run: |\n"
                    f"{indent}  set -euo pipefail\n"
                    f'{indent}  echo "ran=9999" >> "$GITHUB_OUTPUT"\n'
                    f"{item}- name: Run the work\n"
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block, block.replace(id_line + "\n", decoy, 1), 1
                    ),
                    f"{job}: the publishing step is not the invoking step",
                )

    def test_replacing_the_runner_with_a_constant_is_caught(self):
        """THE regression this whole series exists for.

        A constant published as the last line was the FIRST design, and it was
        defeated by two inserted lines. Anything that turns the proof back into a
        constant must be rejected statically, because at runtime a constant is
        indistinguishable from a real count."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                line = next(
                    ln for ln in block.splitlines()
                    if spec["invocation"].match(ln.strip())
                )
                indent = " " * (len(line) - len(line.lstrip()))
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block,
                        block.replace(
                            line,
                            f'{indent}echo "ran=1" >> "$GITHUB_OUTPUT"',
                            1,
                        ),
                        1,
                    ),
                    f"{job}: runner replaced with a constant",
                )

    def test_anything_appended_to_the_invocation_is_caught(self):
        """The substring-match hole, closed by anchoring — and pinned.

        `_DISCOVER_RE` used to match `unittest discover ... -p 'test_ci_*.py'`
        and ignore the rest of the line. Measured, that accepted an appended
        `-k '*bucket*'` which cut the run from 1264 tests to 18, and a `cd
        /tmp/decoy` in front which ran a one-test decoy suite — both publishing
        a GENUINE count, because the scope was the lie, not the number.

        Each row is a separate spelling of "more than the bare invocation"."""
        for job, spec in PROOF_SPECS.items():
            runner = spec["runner"]
            for label, mutated in {
                "argument appended":
                    f'python3 {runner} -k \'*bucket*\' >> "$GITHUB_OUTPUT"',
                "failure swallowed":
                    f'python3 {runner} >> "$GITHUB_OUTPUT" || true',
                "piped through a filter":
                    f'python3 {runner} | tail -1 >> "$GITHUB_OUTPUT"',
                "redirected elsewhere":
                    f'python3 {runner} >> /tmp/elsewhere',
                "a `cd` in front":
                    f'cd /tmp\n          python3 {runner} >> "$GITHUB_OUTPUT"',
            }.items():
                with self.subTest(job=job, shape=label):
                    assert_disables(
                        job_ran_proof_problems,
                        self.lint,
                        apply_mutation(
                            self.lint, f'python3 {runner} >> "$GITHUB_OUTPUT"', mutated
                        ),
                        f"{job}: {label}",
                    )

    def test_dropping_the_output_declaration_is_caught(self):
        for job in PROOF_JOBS:
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                stripped = re.sub(
                    r"\n    outputs:\n      ran: [^\n]*\n", "\n", block, count=1
                )
                self.assertNotEqual(stripped, block, f"{job}: fixture matched nothing")
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(block, stripped, 1),
                    f"{job}: outputs: dropped",
                )

    def test_a_typoed_step_id_in_the_output_is_caught(self):
        """Caught at review time, not at runtime.

        The runtime direction is already fail-closed: a typo'd step id makes the
        output an empty string, `lint-gate` sees success with no proof, and the
        build goes red. But a red build for a typo burns a CI cycle and looks
        exactly like a real parking event — the alarm would be indistinguishable
        from the thing it is meant to report."""
        for job in PROOF_JOBS:
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                m = re.search(r"ran: \$\{\{ steps\.([\w-]+)\.outputs\.ran \}\}", block)
                self.assertIsNotNone(m, f"{job}: fixture premise broke")
                typoed = block.replace(
                    f"steps.{m.group(1)}.outputs.ran",
                    f"steps.{m.group(1)}x.outputs.ran", 1,
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(block, typoed, 1),
                    f"{job}: output reads a step id that does not exist",
                )

    def test_the_aggregator_dropping_the_comparison_is_caught(self):
        """A gate that LISTS the jobs but stops checking the VALUE passes on the
        empty string, which is what a parked body produces, and on `0`, which is
        what a loop that never iterates produces."""
        gate = job_block(self.lint, GATE_JOB)
        line = next(ln for ln in gate.splitlines() if "fullmatch(" in ln)
        assert_disables(
            job_ran_proof_problems,
            self.lint,
            self.lint.replace(gate, gate.replace(line, "              and False"), 1),
            "aggregator no longer checks the `ran` value",
        )

    def test_the_aggregator_dropping_a_proof_job_is_caught(self):
        assert_disables(
            job_ran_proof_problems,
            self.lint,
            self.lint.replace('"ci-guards", "renderer-canary"', '"ci-guards"', 1),
            "aggregator no longer requires the canary's proof",
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
                f'python3 {GUARD_RUNNER} >> "$GITHUB_OUTPUT"',
                'echo "ran=1" >> "$GITHUB_OUTPUT"',
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
                f'          python3 {GUARD_RUNNER} >> "$GITHUB_OUTPUT"',
                f'          # python3 {GUARD_RUNNER} >> "$GITHUB_OUTPUT"\n'
                '          echo "ran=1" >> "$GITHUB_OUTPUT"',
            )
        )
        self.assertTrue(
            problems,
            "a commented-out runner invocation was accepted as execution",
        )

    def test_renaming_the_job_fails_closed(self):
        """A rename must be reported, not treated as 'nothing to check'."""
        problems = guard_job_problems(
            apply_mutation(self.lint, "  ci-guards:\n", "  ci-gaurds:\n")
        )
        self.assertTrue(problems)
        self.assertIn("not found exactly once", problems[0])


class TestTheAggregatorEnforcesTheProof(unittest.TestCase):
    """EXECUTE `lint-gate`'s body. Nothing in this repo did, before this class.

    Every other check on the aggregator inspects its TEXT — `if: always()`, the
    `needs:` list, the pass-set string — and #404 already measured what that
    misses: a gate can satisfy all three and still not gate. The fall-through
    proof only means something if the aggregator actually rejects an unset `ran`,
    and only text said it did.

    The critical direction is the FALSE ALARM one. Both proof jobs legitimately
    skip when the `ci_config` bucket does not match, which is most PRs, and a
    skipped job has no outputs. An unconditional demand would fail every
    unrelated PR — the shape that gets a check deleted rather than fixed.
    """

    @classmethod
    def setUpClass(cls):
        text = LINT_YML.read_text(encoding="utf-8")
        cls.py = cls._extract(text)
        cls.env_key = cls._env_key(text)

    @staticmethod
    def _extract(lint_text: str) -> str:
        """The aggregator's Python, taken out of the YAML block scalar + heredoc.

        Two layers, both load-bearing: `job_block` returns raw file text, so the
        YAML indentation is still on it and Python would reject the body; and the
        script itself lives in a quoted heredoc inside the shell body.

        `block_scalar_body` rather than `textwrap.dedent` over the remainder —
        see that function for the measured reason."""
        block = job_block(lint_text, GATE_JOB)
        if block is None:
            raise AssertionError(f"job `{GATE_JOB}` not found")
        m = re.search(
            r"^python3 - <<'PY'\n(.*?)^PY", block_scalar_body(block), re.S | re.M
        )
        if m is None:
            raise AssertionError(
                f"`{GATE_JOB}` no longer runs a `python3 - <<'PY'` heredoc — this "
                "class extracts it by that shape and must be updated with it, not "
                "left to skip"
            )
        return m.group(1)

    @staticmethod
    def _env_key(lint_text: str) -> str:
        """The env var the gate step actually passes `toJson(needs)` in.

        READ, not assumed, and this is a polarity fix rather than a tidy-up. The
        first version hardcoded `NEEDS_JSON` in `_run`, so the class could not see
        the wiring it depends on and its polarity was INVERTED — measured: rename
        only the `env:` key and the step `KeyError`s in real CI while all seven
        tests pass; rename BOTH sides consistently, which is a legitimate
        refactor that works fine, and all seven fail. A check that is blind to
        the break and loud about the fix is worse than no check."""
        block = job_block(lint_text, GATE_JOB)
        keys = re.findall(r"^\s+(\w+):\s*\$\{\{\s*toJson\(needs\)\s*\}\}", block, re.M)
        if len(keys) != 1:
            raise AssertionError(
                f"expected exactly one `<KEY>: ${{{{ toJson(needs) }}}}` in "
                f"`{GATE_JOB}`, found {keys}. This class feeds the script through "
                "that variable and cannot guess which one to use."
            )
        return keys[0]

    def _run(self, needs):
        import json
        import subprocess

        r = subprocess.run(
            [sys.executable, "-c", self.py],
            # The whole environment, not an extension of it: this also proves the
            # script has no hidden env dependency.
            env={self.env_key: json.dumps(needs), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True,
        )
        return r.returncode, (r.stdout + r.stderr)

    def test_the_script_reads_the_variable_the_step_writes(self):
        """The two halves of the wiring must name the same variable.

        Blind spot in the first version: `_extract` pulls only the heredoc body,
        so a one-way rename of the `env:` key was invisible here and fatal in
        CI."""
        self.assertIn(
            f'os.environ["{self.env_key}"]', self.py,
            f"`{GATE_JOB}` passes needs in `{self.env_key}` but its script does "
            "not read that name — the step would KeyError on its next run",
        )

    # Shapes taken from a REAL `toJson(needs)` payload (run 34298321355), not
    # invented: every entry carries both keys, and a skipped job's `outputs` is
    # an empty dict rather than absent. `PARKED` is the literal shape of any job
    # in that payload with no outputs at all.
    PROVEN = {"result": "success", "outputs": {"ran": "1255"}}
    SKIPPED = {"result": "skipped", "outputs": {}}
    PARKED = {"result": "success", "outputs": {}}
    #: A loop that never iterates, or a parse that matched nothing, publishes a
    #: value — it is just not a positive one. A boolean proof could not express
    #: this direction at all, which is half the reason the proof became a count.
    ZERO = {"result": "success", "outputs": {"ran": "0"}}
    NON_NUMERIC = {"result": "success", "outputs": {"ran": "true"}}

    def test_the_script_was_extracted(self):
        # Vacuity canary: an empty script exits 0 and every direction below
        # would "pass".
        self.assertGreater(len(self.py.splitlines()), 20, self.py)
        self.assertIn("proof_required", self.py)

    def test_both_proven_passes(self):
        code, out = self._run(
            {"ci-guards": self.PROVEN, "renderer-canary": self.PROVEN}
        )
        self.assertEqual(code, 0, out)
        self.assertIn("Lint gate passed", out)

    def test_both_skipped_passes(self):
        """THE false-alarm direction. A skipped job has no `ran`, and that is
        correct, not a parked body."""
        code, out = self._run(
            {"ci-guards": self.SKIPPED, "renderer-canary": self.SKIPPED}
        )
        self.assertEqual(code, 0, out)

    def test_one_skipped_one_proven_passes(self):
        code, out = self._run(
            {"ci-guards": self.SKIPPED, "renderer-canary": self.PROVEN}
        )
        self.assertEqual(code, 0, out)

    def test_a_parked_guard_job_fails(self):
        """Three ways a job can report success without having worked.

        `PARKED` is the body dying or never publishing; `ZERO` is a loop that
        never iterated or a parse that matched nothing; `NON_NUMERIC` is the
        PREVIOUS design's constant `ran=true`, which must now be rejected — if it
        were still accepted, reverting to the defeated design would be a silent
        one-line edit rather than a red build."""
        for shape in ("PARKED", "ZERO", "NON_NUMERIC"):
            for job in ("ci-guards", "renderer-canary"):
                with self.subTest(job=job, shape=shape):
                    needs = {
                        "ci-guards": self.PROVEN, "renderer-canary": self.PROVEN
                    }
                    needs[job] = getattr(self, shape)
                    code, out = self._run(needs)
                    self.assertEqual(code, 1, out)
                    self.assertIn("without executing their work", out)
                    self.assertIn(job, out)

    def test_a_renamed_proof_job_fails_closed(self):
        """A missing NAME must be an error, not a pass.

        `needs.get(name, {})` would wave a renamed job through — the same vacuity
        as an undeclared `needs.*.outputs.*` resolving to the empty string, which
        this repo has already paid for once."""
        code, out = self._run({"renderer-canary": self.PROVEN})
        self.assertEqual(code, 1, out)
        self.assertIn("cannot be proven", out)

    def test_an_ordinary_failure_elsewhere_still_fails(self):
        # No-regression direction: the proof check must not shadow the original
        # result aggregation.
        code, out = self._run({
            "ci-guards": self.PROVEN, "renderer-canary": self.PROVEN,
            "gitleaks": {"result": "failure", "outputs": {}},
        })
        self.assertEqual(code, 1, out)
        self.assertIn("gitleaks", out)


if __name__ == "__main__":
    unittest.main()
