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

    if not re.search(r"grep\s+-qE\s+'\\\.\\\.\\\. skipped ", executed):
        problems.append(
            f"job `{CANARY_JOB}` lost its skip check. `unittest` counts a skipped "
            "class in `Ran N tests` and exits 0, so without this a skip reads as "
            "a pass."
        )

    if not re.search(r"\^Ran \[1-9\]", executed):
        problems.append(
            f"job `{CANARY_JOB}` lost its non-zero test-count check. `unittest` "
            "exits 0 on 'Ran 0 tests', so an emptied class would pass vacuously."
        )

    # The floors must be PER CLASS. A single aggregate check over the combined
    # output was the first version, and emptying one class — renaming its test
    # methods, which is what an ordinary refactor produces — left the other two
    # carrying the count while the residual went live.
    if "for spec in" not in executed:
        problems.append(
            f"job `{CANARY_JOB}` no longer loops per class. An aggregate "
            "`Ran [1-9]` over all three lets ONE adjudicator contribute zero "
            "tests while the others carry the count — measured, with the "
            "residual payload live and the job exiting 0."
        )

    for cls, method in CANARY_CLASSES:
        if cls not in executed:
            problems.append(
                f"job `{CANARY_JOB}` no longer RUNS `{cls}`. It skips in every "
                "other job, so dropping it here leaves it running nowhere."
            )
        if method not in executed:
            problems.append(
                f"job `{CANARY_JOB}` no longer names `{method}`, the one test in "
                f"`{cls}` that adjudicates real repository content against the "
                "renderer. Without the name the job floors on a COUNT, and a "
                "count cannot tell that the adjudicating test was parked."
            )

    # NO HEREDOC IN THIS STEP. `executed_shell` does not model heredoc bodies —
    # its own docstring says so and calls it the one limitation that CAN hide an
    # unrun test — so a `run: |` that opens `cat <<'EOF'` and quotes the whole
    # loop inside it reads to every check above as execution: measured,
    # `canary_job_problems() == []` with the step exiting 0 having adjudicated
    # nothing. Closing that in the shared extractor needs a heredoc state machine
    # across every guard that imports it; closing it HERE needs one line, because
    # this step has no heredoc by design (the install step's comment already
    # explains why an indented one would not even parse). Forbidding what the
    # extractor cannot read is the fail-closed half of the same fix.
    #
    # SCOPE, stated because the check is a SUBSTRING test and not a heredoc
    # parser: it also fires on `echo "shift: 1 << 2"` and `: $(( 1 << 2 ))`
    # (measured). Both are false alarms, both fail CLOSED, and neither shape
    # belongs in this step — acceptable, but it is a token check, not a grammar.
    # It does NOT close the parking class; `exit 0` as the first line parks the
    # step with no `<<` anywhere and this function still returns `[]`. See
    # `test_parking_the_canary_step_in_a_heredoc_is_not_execution` for the
    # measured residual.
    if "<<" in executed:
        problems.append(
            f"job `{CANARY_JOB}` contains a heredoc. `executed_shell` cannot see "
            "into heredoc bodies, so the loop could sit inside one, run nothing, "
            "and satisfy every check in this function. If a heredoc is genuinely "
            "needed, teach `executed_shell` to strip them FIRST."
        )

    # The runner must disable unittest's descriptions. See the step's own comment:
    # with them on, adding a docstring to an adjudicating method moves `... ok`
    # onto a second line and the by-name check below stops matching, turning
    # ordinary documentation into a red build.
    if "descriptions=False" not in executed:
        problems.append(
            f"job `{CANARY_JOB}` no longer runs with `descriptions=False`. Under "
            "`unittest -v` a docstring on an adjudicating method splits its "
            "result onto a second line and the per-method check fails on a "
            "passing suite — a false alarm, which is how a gate stops being read."
        )

    # The methods must be checked BY NAME in the step, not merely listed.
    if "did not run ${method}" not in executed:
        problems.append(
            f"job `{CANARY_JOB}` lost its per-method assertion. A per-class count "
            "floor passes with the adjudicating test parked — measured, with the "
            "residual live and a reader seeing 0 of 70 rows."
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
PROOF_SPECS = {
    "ci-guards": {
        "var": "ran",
        # `$ran` parsed out of `$out`, which holds the suite's own stdout.
        "derivation": re.compile(r'^ran=\$\(.*"\$out".*\)$'),
        "derivation_desc": 'a `ran=$(... "$out" ...)` parse of the suite output',
        "floor": '[ -n "$ran" ]',
        # `$out` is what the proof is computed FROM, so seeding it forges the
        # proof. Exactly one assignment, and `guard_job_problems` separately
        # requires that one to be the `unittest discover` invocation.
        "source": "out",
        "source_assignments": 1,
        # Two independent readings of the same run: a non-zero test count, and
        # the suite reporting OK. `Ran N` prints on failure too.
        "verdict": re.compile(r"^printf .*\| grep -qE '\^OK\( \|\$\)'$"),
    },
    CANARY_JOB: {
        "var": "adjudicated",
        "derivation": re.compile(r"^adjudicated=\$\(\(\s*adjudicated \+ 1\s*\)\)$"),
        "derivation_desc": "an `adjudicated=$((adjudicated + 1))` increment",
        "floor": f'[ "$adjudicated" -eq {len(CANARY_CLASSES)} ]',
        # The increment must sit INSIDE the loop body. Hoisted above `for` it is a
        # constant again, and below `done` it counts nothing.
        "inside_loop": True,
        # The counter is its own source: `adjudicated=0` to initialise and the
        # increment. A third assignment is a seeded value.
        "source": "adjudicated",
        "source_assignments": 2,
        "verdict": re.compile(r"^if ! printf .*\| grep -qE '\^OK\( \|\$\)'; then$"),
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
        marker = _marker(spec["var"])
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
        if not declares:
            problems.append(
                f"job `{job}` declares no `outputs:`. Without it the marker its "
                "body writes is invisible to `lint-gate`, and the job is back to "
                "being provable only by reading its text."
            )
        else:
            ref = re.search(
                r"ran:\s*\$\{\{\s*steps\.([\w-]+)\.outputs\.ran\s*\}\}", block
            )
            if ref is None:
                problems.append(
                    f"job `{job}` has `outputs:` but does not surface `ran` from a "
                    "step. An output that reads from nothing is the empty string, "
                    "which is the undeclared-output vacuity class this repo "
                    "already paid for once."
                )
            elif not re.search(
                rf"^\s*id:\s*{re.escape(ref.group(1))}\s*$", block, re.M
            ):
                # The runtime direction of this is already fail-closed — a typo'd
                # step id yields an empty output, `lint-gate` sees success with no
                # proof, and the build goes red. But red-at-runtime for a typo is
                # a wasted CI cycle and an alarm that looks like a real parking
                # event, so it is caught here instead, where the diff is.
                problems.append(
                    f"job `{job}` surfaces `ran` from step id "
                    f"`{ref.group(1)}`, which no step in the job declares. The "
                    "output resolves to the empty string, so the proof can never "
                    "be satisfied."
                )

        # `executed_shell` so a marker parked in a comment or an `env:` scalar
        # counts for nothing — the same routing the sibling pins use, for the
        # same two measured reasons.
        lines = [ln.strip() for ln in executed_shell(block).splitlines() if ln.strip()]
        if marker not in lines:
            problems.append(
                f"job `{job}` never writes `{marker}` in an executed step. The "
                "proof is that line; without it the job's `outputs.ran` is "
                "permanently empty and `lint-gate` fails closed — loudly, but it "
                "means the mechanism is gone."
            )
            continue
        at_marker = lines.index(marker)

        # THE DERIVATION. This is the check that survives a parking construct
        # closing above the marker: the published value has to be COMPUTED from
        # the work, so parking the work leaves its source unbound and `set -u`
        # kills the derivation instead of falling through it.
        derived = [i for i, ln in enumerate(lines) if spec["derivation"].match(ln)]
        if not derived:
            problems.append(
                f"job `{job}` publishes `ran` without {spec['derivation_desc']}. "
                "A constant proves only its own line — measured, wrapping the "
                "work in a never-taken `if` whose `fi` sits one line above the "
                "marker left every guard returning [], the whole suite green, "
                "and the step exiting 0 having run nothing."
            )
        elif min(derived) > at_marker:
            problems.append(
                f"job `{job}` computes its proof AFTER publishing it, so the "
                "published value cannot depend on the work."
            )
        elif spec.get("inside_loop"):
            # Hoisted above `for` the increment is a constant again; below `done`
            # it counts nothing. Both leave the marker looking derived.
            loop = [i for i, ln in enumerate(lines) if ln.startswith("for ")]
            done = [i for i, ln in enumerate(lines) if ln == "done"]
            if not loop or not done:
                problems.append(
                    f"job `{job}` no longer has the `for ... done` loop its "
                    "proof counts iterations of."
                )
            elif not any(loop[0] < i < done[0] for i in derived):
                problems.append(
                    f"job `{job}` increments its proof OUTSIDE the loop body. "
                    "Outside, it is incremented a fixed number of times "
                    "regardless of how many adjudicators actually ran."
                )

        # FORGERY. The data dependency stops a parked body only while the source
        # variable is UNBOUND. Seed it above the parked span and the derivation
        # runs on a lie: measured, `out="Ran 1 tests in 0.0s"` inserted above an
        # `if`-wrapped body published `ran=1` at exit 0 with every check returning
        # [], and `adjudicated=3` hoisted above the canary's loop published
        # `ran=3` the same way. That is a THIRD line for the attacker rather than
        # closure, and it is not domination — but a seeded value is an EXTRA
        # assignment, and counting assignments is something text CAN do.
        # Rewriting the one legitimate assignment instead removes the
        # `unittest discover` invocation, which `guard_job_problems` already
        # rejects.
        assigns = [
            ln for ln in lines
            if re.match(rf"^{re.escape(spec['source'])}=", ln)
        ]
        if len(assigns) != spec["source_assignments"]:
            problems.append(
                f"job `{job}` assigns `{spec['source']}` {len(assigns)} time(s), "
                f"expected {spec['source_assignments']}: {assigns}. An extra "
                "assignment is how a parked body forges a plausible proof — the "
                "derivation then reads a seeded value instead of the work."
            )

        if spec["verdict"] and not any(
            spec["verdict"].match(ln) for ln in lines
        ):
            problems.append(
                f"job `{job}` no longer requires its run to report `OK`. "
                "`unittest` prints `Ran N` on failure too, so with the exit-status "
                "branch weakened to `|| true` a genuinely FAILING suite publishes "
                "a genuine count and the job reports success — measured, with "
                "every other check in this function returning []."
            )

        if spec["floor"] not in lines:
            problems.append(
                f"job `{job}` lost its floor `{spec['floor']}`. Without it a "
                "derivation that produced nothing still publishes — the empty "
                "string for `ci-guards`, and for the canary a count that a "
                "never-iterating loop leaves at 0."
            )
        elif lines.index(spec["floor"]) > at_marker:
            problems.append(
                f"job `{job}` applies its floor after publishing, which is after "
                "the value has already been read."
            )

        # POSITION, still asserted — but as the second line of defence now, not
        # as the argument. A command below the marker can exit before the runner
        # reads the file back.
        if lines[-1] != marker:
            problems.append(
                f"job `{job}` writes its proof but NOT as its last executed line "
                f"(last is `{lines[-1]}`). Anything below it can exit first."
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

    def test_dropping_the_skip_check_is_caught(self):
        """`unittest` counts a skipped class in `Ran N tests` and exits 0, so
        the count check alone does not catch a skip."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(
                # RAW string: the workflow carries a shell-quoted ERE, so the
                # backslashes are literal in the file. Writing them as escapes in
                # a normal Python string produced a stale fixture twice, which
                # `assert_disables` correctly refused to score.
                self.lint,
                r"grep -qE '\.\.\. skipped |\(skipped='",
                "grep -qE '__removed__'",
            ),
            "renderer-canary lost its skip check",
        )

    def test_dropping_a_canary_class_is_caught(self):
        """Each class skips in every other job, so removing it here leaves it
        running nowhere at all."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "test_ci_markdown_scan_evasion.TestTheResidualIsBounded",
                "test_ci_markdown_scan_evasion.__removed__",
            ),
            "a renderer-adjudicated class dropped from the canary job",
        )

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

    def test_restoring_unittest_descriptions_is_caught(self):
        """The fail-CLOSED half: a false alarm is also a defect.

        `python3 -m unittest -v` cannot be told `descriptions=False`, and with
        descriptions on, a method that HAS a docstring prints `name (…)` and puts
        `... ok` on the NEXT line — so the by-name check stops matching and the
        job goes red because someone documented a test. Measured on
        `test_the_canary_fires_on_the_measured_residual_payload`, which already
        carries one; the three adjudicating methods do not, which is the only
        reason this is latent rather than live.

        Pinned because reverting to the shorter `-m unittest -v` spelling looks
        like a simplification and reintroduces it."""
        start = self.lint.index(
            "      - name: Run the renderer-adjudicated guard classes"
        )
        end = self.lint.index("\n  scanner-unit-tests:")
        body = self.lint[start:end]
        # Anchored on the RUNNER line, not on the token: the step's own comment
        # explains `descriptions=False` and therefore contains it, and matching
        # the token alone found two lines and would have mutated a comment —
        # scoring the fixture rather than the check. The same over-broad-anchor
        # slip the gate mutation already paid for once in this file.
        runner = [
            line for line in body.splitlines()
            if "descriptions=False" in line and line.lstrip().startswith("out=$(")
        ]
        self.assertEqual(
            len(runner),
            1,
            "expected exactly one runner line to mutate; the step changed shape",
        )
        reverted = body.replace(
            runner[0],
            '            out=$(python3 -m unittest -v "$cls" 2>&1) || {',
        )
        assert_disables(
            canary_job_problems,
            self.lint,
            self.lint[:start] + reverted + self.lint[end:],
            "renderer-canary reverted to `unittest -v` (descriptions on)",
        )

    # ------------------------------------------------------------------
    # THE EXECUTION PROOF. The static half of this is `job_ran_proof_problems`,
    # pinned by the mutations further down. The half below is the one that
    # actually carries the design, and it is NOT static: text cannot see control
    # flow, so parking the work with a construct that closes above the publish
    # line leaves every static check returning []. What stops it is that the
    # published value is COMPUTED from the work, so parking the work leaves its
    # source unbound and `set -u` kills the derivation.
    #
    # These run the REAL job bodies, parked. That is affordable precisely
    # because a parked body does no work: it dies on the unbound variable in
    # milliseconds. The unparked direction is the one that cannot be run here
    # (`ci-guards` would invoke the whole suite, and `renderer-canary` needs the
    # pinned oracle), so its non-vacuity is carried by the synthetic control.
    # ------------------------------------------------------------------

    #: Constructs that swallow a span of shell without executing it. Not an
    #: enumeration this design depends on — the data dependency does not care
    #: which one is used — but each was measured to DEFEAT the previous
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

    def test_parking_the_work_kills_the_publish_line_in_both_real_bodies(self):
        """The property the whole design rests on, measured on the real bodies.

        The previous design published a constant `ran=true` as the last line and
        argued that reaching the last line proved the body ran. It does not. An
        adversarial pass inserted two lines into `ci-guards` — a never-taken `if`
        opened after `set -euo pipefail` and its `fi` one line above the marker —
        and measured `job_ran_proof_problems() == []`, `guard_job_problems() ==
        []`, the full 1255-test suite `OK`, and the step exiting 0 with
        `ran=true` written and ZERO tests run. The old fixture had listed `if
        false; then ... fi` among the shapes it closed, but only because it put
        the marker INSIDE the `if`; moving `fi` up one line falls through it.

        The fix is a data dependency: `$ran` is parsed out of `$out`, and
        `$adjudicated` is incremented inside the loop. Park the work by ANY
        construct and the source variable is unbound at the publish line, so
        `set -u` ends the step instead of letting it fall through.

        Parked from just after `set -euo pipefail` to just before the publish
        line — the most that can be swallowed while leaving the proof intact,
        which is the strongest form of the attack."""
        for job, spec in PROOF_SPECS.items():
            body = self._job_body(job)
            lines = body.splitlines()
            start = lines.index("set -euo pipefail") + 1
            end = lines.index(_marker(spec["var"]))
            for name, (open_, close_) in self.PARKING_WRAPS.items():
                with self.subTest(job=job, shape=name):
                    parked = "\n".join(
                        lines[:start] + [open_] + lines[start:end] + [close_]
                        + lines[end:]
                    )
                    code, written = self._run_body(parked)
                    self.assertNotEqual(
                        code, 0,
                        f"{job}/{name}: the parked body EXITED 0 — the work never "
                        "ran and the step reported success",
                    )
                    self.assertNotIn(
                        "ran=", written,
                        f"{job}/{name}: the parked body still published a proof "
                        f"({written!r}) — the data dependency does not hold",
                    )

    def test_the_publish_line_is_the_thing_that_dies(self):
        """Attribution, not just failure.

        A parked body could exit non-zero for an unrelated reason and every
        subtest above would pass for the wrong reason. This pins the actual
        cause: bash naming the derivation's source variable as unbound."""
        for job, spec in PROOF_SPECS.items():
            body = self._job_body(job)
            lines = body.splitlines()
            start = lines.index("set -euo pipefail") + 1
            end = lines.index(_marker(spec["var"]))
            open_, close_ = self.PARKING_WRAPS["if"]
            parked = "\n".join(
                lines[:start] + [open_] + lines[start:end] + [close_] + lines[end:]
            )
            with self.subTest(job=job):
                _, _, stderr = self._run_body(parked, want_stderr=True)
                self.assertIn(
                    spec["var"], stderr,
                    f"{job}: parked body failed without naming `{spec['var']}` as "
                    f"unbound; stderr was {stderr!r}",
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

    def test_a_swallowed_suite_failure_does_not_publish(self):
        r"""A FAILING suite must not publish a count. Measured, not argued.

        `unittest` prints `Ran N` on failure exactly as it does on success, so
        weakening the capture's `|| { ...; exit 1; }` branch to `|| true` lets a
        red suite publish a genuine count and the job report success — worse than
        the parking class this design was built for, because parking runs nothing
        while this SWALLOWS real failures. Measured before the `^OK` check
        existed: `job_ran_proof_problems() == []` and `guard_job_problems() == []`
        with the suite red and the job green.

        The static guard still cannot see it (the OK check is textually present
        either way), so this direction is pinned by EXECUTION. Four rows, because
        the first version of this probe used `\\n` inside a non-raw Python string,
        printf emitted a literal backslash-n, the whole synthetic output collapsed
        onto one line, and every row went red for that reason instead of the one
        under test — the non-vacuity row is what caught it."""
        fail = r"""printf 'F\nRan 1253 tests in 16.8s\n\nFAILED (failures=1)\n'; exit 1"""
        ok = r"""printf 'Ran 1253 tests in 16.8s\n\nOK\n'"""
        cases = {
            # The attack.
            "failing + swallowed": (f"out=$({fail}) || true", False),
            # Same failure, branch intact — red for the ordinary reason.
            "failing + branch intact": (
                f'out=$({fail}) || {{\n  printf \'%s\\n\' "$out"\n  exit 1\n}}',
                False,
            ),
            # NON-VACUITY: the fixture path must be able to reach the publish
            # line at all, or the two rows above prove nothing.
            "passing": (f"out=$({ok})", True),
            # ATTRIBUTION: `|| true` alone must NOT be what makes it red, or the
            # first row is red for the wrong reason.
            "passing + swallowed": (f"out=$({ok}) || true", True),
        }
        for name, (capture, should_publish) in cases.items():
            with self.subTest(case=name):
                code, written = self._run_body(
                    self._ci_guards_with_capture(capture)
                )
                if should_publish:
                    self.assertEqual(code, 0, f"{name}: expected success")
                    self.assertEqual(written.strip(), "ran=1253", name)
                else:
                    self.assertNotEqual(code, 0, f"{name}: a red suite exited 0")
                    self.assertEqual(
                        written, "",
                        f"{name}: a red suite published {written!r}",
                    )

    def test_seeding_the_source_variable_is_caught(self):
        """FORGERY: the data dependency holds only while the source is unbound.

        Seed it above a parked span and the derivation runs on a lie — measured,
        `out="Ran 1 tests in 0.0s"` published `ran=1` at exit 0, and
        `adjudicated=3` hoisted above the canary's loop published `ran=3`, both
        with every check returning []. A seeded value is an EXTRA assignment, and
        counting assignments is something text CAN do."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                anchor = "          set -euo pipefail\n"
                self.assertIn(anchor, block, f"{job}: anchor moved")
                seeded = block.replace(
                    anchor,
                    anchor + f'          {spec["source"]}="forged"\n',
                    1,
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(block, seeded, 1),
                    f"{job}: source variable seeded with a forged value",
                )

    def test_dropping_the_ok_verdict_check_is_caught(self):
        """Without it, `Ran N` alone is the whole verdict — and it prints on
        failure too."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                line = next(
                    ln for ln in block.splitlines()
                    if spec["verdict"].match(ln.strip())
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block, block.replace(line + "\n", "", 1), 1
                    ),
                    f"{job}: `^OK` verdict check dropped",
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

    def test_hoisting_the_publish_line_above_the_work_is_caught(self):
        """Publishing before deriving.

        With the value hoisted, `$ran` is unbound where it is published, so this
        also fails closed at runtime — but statically it is the difference
        between a proof and a decoration, and it is caught where the diff is."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                marker_line = next(
                    ln for ln in block.splitlines()
                    if ln.strip() == _marker(spec["var"])
                )
                anchor = "          set -euo pipefail\n"
                self.assertIn(anchor, block, f"{job}: anchor moved")
                hoisted = block.replace(marker_line + "\n", "").replace(
                    anchor, anchor + marker_line + "\n", 1
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(block, hoisted, 1),
                    f"{job}: publish line hoisted above the derivation",
                )

    def test_a_command_after_the_publish_line_is_caught(self):
        """The position half, which survives as defence in depth.

        A command below the publish line can exit before the runner reads the
        file back. Any trailing command reopens that, so the check rejects all of
        them rather than trying to classify which are harmless."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                marker_line = next(
                    ln for ln in block.splitlines()
                    if ln.strip() == _marker(spec["var"])
                )
                trailing = block.replace(
                    marker_line + "\n", marker_line + "\n          echo done\n", 1
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(block, trailing, 1),
                    f"{job}: command added after the publish line",
                )

    def test_replacing_the_derivation_with_a_constant_is_caught(self):
        """THE regression this redesign exists for.

        A constant published on the last line was the previous design, and it was
        defeated by two inserted lines. Anything that turns the derivation back
        into a constant must be rejected statically, because at runtime a
        constant is indistinguishable from a real proof."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                derivation = next(
                    ln for ln in block.splitlines()
                    if spec["derivation"].match(ln.strip())
                )
                indent = " " * (len(derivation) - len(derivation.lstrip()))
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block,
                        block.replace(
                            derivation, f"{indent}{spec['var']}=1", 1
                        ),
                        1,
                    ),
                    f"{job}: derivation replaced with a constant",
                )

    def test_dropping_the_floor_is_caught(self):
        """A derivation that produced nothing still publishes without a floor.

        For `ci-guards` that is the empty string; for the canary it is `0`, which
        is what a loop that never iterates leaves behind. `lint-gate` rejects both
        as well — this is the static half of the same check."""
        for job, spec in PROOF_SPECS.items():
            with self.subTest(job=job):
                block = job_block(self.lint, job)
                floor = next(
                    ln for ln in block.splitlines() if ln.strip() == spec["floor"]
                )
                assert_disables(
                    job_ran_proof_problems,
                    self.lint,
                    self.lint.replace(
                        block, block.replace(floor + "\n", "", 1), 1
                    ),
                    f"{job}: floor dropped",
                )

    def test_moving_the_canary_increment_out_of_the_loop_is_caught(self):
        """Outside the loop it is incremented a fixed number of times.

        Hoisted above `for` or dropped below `done`, `$adjudicated` stops
        counting adjudicators and becomes a constant wearing a derivation's
        shape — which the runtime data dependency cannot tell apart, because the
        variable is still bound."""
        spec = PROOF_SPECS[CANARY_JOB]
        block = job_block(self.lint, CANARY_JOB)
        inc = next(
            ln for ln in block.splitlines() if spec["derivation"].match(ln.strip())
        )
        done = next(ln for ln in block.splitlines() if ln.strip() == "done")
        moved = block.replace(inc + "\n", "", 1).replace(
            done + "\n", done + "\n          " + inc.strip() + "\n", 1
        )
        self.assertNotEqual(moved, block, "fixture matched nothing")
        assert_disables(
            job_ran_proof_problems,
            self.lint,
            self.lint.replace(block, moved, 1),
            "canary increment moved below `done`",
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

    def test_dropping_the_per_method_assertion_is_caught(self):
        """A per-class COUNT floor passes with the adjudicating test parked.

        Measured: parking the one method in `TestTheDocAgreesWithTheRenderer`
        that reads the real catalog left the class at two synthetic-fixture
        tests, `Ran 3 tests / OK`, exit 0 — with the residual payload live and a
        reader seeing 0 of 70 guard rows."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(
                self.lint, 'did not run ${method}', 'did not run __removed__'
            ),
            "renderer-canary lost its per-method assertion",
        )

    def test_dropping_an_adjudicating_method_name_is_caught(self):
        """The class can stay in the loop while the method it must run does
        not — which is the shape a rename produces."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(
                self.lint,
                "test_the_reduction_and_the_renderer_agree_on_the_real_catalog",
                "__renamed_away__",
            ),
            "an adjudicating method name dropped from the canary loop",
        )

    def test_flattening_the_per_class_loop_is_caught(self):
        """An aggregate `Ran [1-9]` over the combined output lets ONE class
        contribute zero tests while the other two carry the count.

        Not hypothetical: emptying `TestTheDocAgreesWithTheRenderer` — renaming
        its test methods, which is what an ordinary refactor produces — printed
        "Ran 5 tests / OK" and exited 0 with the measured residual payload live
        in the catalog and a reader seeing 0 of 70 guard rows."""
        assert_disables(
            canary_job_problems,
            self.lint,
            apply_mutation(self.lint, "for spec in \\", "for _unused in \\"),
            "renderer-canary no longer loops per class",
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
