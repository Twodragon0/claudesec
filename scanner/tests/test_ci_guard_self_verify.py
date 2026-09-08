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


if __name__ == "__main__":
    unittest.main()
