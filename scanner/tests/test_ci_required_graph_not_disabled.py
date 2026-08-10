"""
No job in a REQUIRED check's dependency graph may be disabled by a runner key.

WHY THIS EXISTS
---------------
#404 proved the severity gate's shell body by EXECUTING it. That closed the
shell-level class completely and nothing can evade it — but execution is blind to
keys the RUNNER consumes, and #404 asserted those for exactly ONE step
(`Check for critical/high failures` in `security-scan.yml`).

The 2026-08-08 audit measured the rest of the surface:

    required contexts            ["Lint", "Security Scan Gate"]
    lint-gate                    15 dependencies + itself
    security-scan-gate            3 dependencies + itself
    protected before this guard   1 step

Every one of those jobs concludes `success` if a single `continue-on-error: true`
line is added at JOB level, and BOTH aggregators accept `success`/`skipped` from
every dependency. Reproduced on the real files:

- `security-scan-gate` + job-level `continue-on-error` — the required check itself
  concludes success no matter what its own `sys.exit(1)` does, and
  `test_gate_runs_always`, `test_gate_aggregates_required_needs` and
  `test_gate_passset_not_loosened` ALL stay green (they inspect `if: always()`,
  the `needs:` list and the pass-set string — none of which the mutation touches).
- `dependency-review` + job- or step-level `continue-on-error`, or step-level
  `if: false` — a HIGH/CRITICAL dependency advisory or a GPL/AGPL license
  violation stops blocking merges while `test_ci_gate_topology` (wired into
  `needs`) and `test_ci_required_jobs_exist` (job present) both stay green.

The generalisation is the point. Guarding the three sites the audit happened to
name would leave seventeen jobs of the same class open, so this walks the graph
from the codified required contexts and covers whatever is in it — including jobs
added later, which is the case a site list can never reach.

WHAT IS FORBIDDEN, AND WHAT DELIBERATELY IS NOT
-----------------------------------------------
FORBIDDEN — `continue-on-error` anywhere in the required graph, at job level or
step level. For a gating job there is no legitimate use: the key exists precisely
to make failure not count. Legitimate uses are ALLOWLISTED by
`(workflow, job, step)` so each one is a reviewed decision, not a blanket hole.

FORBIDDEN — a step-level `if:`, unless it is bare `always()` or is allowlisted.

The first version of this file did NOT check that, arguing conditional steps are
ordinary and a ban would be a false-alarm generator. That argument was wrong, and
wrong in a way that was measurable rather than debatable: it was sized against
every workflow in the repo, while the required graph holds 105 steps of which
exactly SEVEN carry an `if:` — five bare `always()`, two legitimate conditions.
At that size an allowlist is trivial, and the gap it left was real: `if: false`
on the sole step of a job that can fail (`Run gitleaks`, `Dependency Review`,
`pii-check`'s only step) leaves the job with nothing to fail on, so it concludes
`success` by DEFAULT — no job-level key needed. Measured on the real `lint.yml`:
step `continue-on-error` on `Run gitleaks` failed this guard; step `if: false` on
the same step passed it 14/14.

The direction is an ALLOWLIST of legitimate conditions, never a blocklist of
disable shapes. Enumerating ways to spell "false" is precisely what got defeated
three times over in #402/#404; `test_step_if_is_not_an_enumeration_of_false_spellings`
pins six conditions that are not literally `false` and must still be caught.
`always()` is exempt by MEANING (it forces the step to run even after a prior
failure, so it cannot disable) and only in its bare form — `always() && <expr>`
can disable, and is caught.

NOT forbidden — a JOB-level `if:`. Path gating is the repo's normal posture and
both aggregators treat `skipped` as passing by design.

FAIL-CLOSED
-----------
Anything that stops the graph being resolved — an unreadable protection script, a
required context that maps to no job, a job key that appears zero or many times —
is reported as a violation rather than skipped. A guard that silently resolves an
empty graph passes vacuously, which is the failure mode this whole file exists to
prevent; `test_graph_is_populated` is the canary.

stdlib-only, no PyYAML, no `scanner/lib` import, no network, no subprocess. Runs
under pytest and `python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SP 800-218 (SSDF) PO.3, PW.4.
"""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    WORKFLOW_DIR,
    explicit_key_lines,
    job_block,
    job_needs,
    keys_at_column,
    strip_inline_comment,
    top_level_jobs,
    workflow_and_action_files,
    yaml_key_pattern,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTECTION_SCRIPT = REPO_ROOT / "scripts" / "sync-repo-protection.sh"

# The key with no legitimate use in a gating job.
DISABLING_KEY = "continue-on-error"

# Runner-consumed keys that REDIRECT a step rather than skip it. A skipped step
# is what `if:`/`continue-on-error` produce; these produce a step that runs, and
# reports success, while doing something other than the check.
#
# Found 2026-08-10 by the audit rule this class's own retrospective added ("list
# the text an executed proof cannot see"), and proven on the real
# `security-scan.yml`: adding ONE line, `working-directory: docs`, to the
# `Check for critical/high failures` step left the ENTIRE suite green — 1945
# passed — while the required `Security Scan Gate` stopped blocking a CRITICAL.
# The mechanism is arithmetic, not exotic: the gate greps `scan-output.txt`
# relative to the cwd, `grep` on a missing file is swallowed by `|| true`, `CRITS`
# becomes the empty string, and `[ "" -gt 0 ]` errors out — but a failing `[` is a
# CONDITION, which `bash -e` deliberately does not treat as fatal. So the `exit 1`
# never runs and the step exits 0. Verified by execution:
#
#     cwd = repo root -> "Critical: 1" -> exit 1   (blocks)
#     cwd = docs/     -> "Critical: "  -> exit 0   (passes, silently)
#
# `shell:` is here for the same reason and is strictly worse: the custom-shell
# form is `shell: <command> ... {0}`, so `shell: cat {0}` PRINTS the gate script
# instead of running it and exits 0.
#
# #404's executed proof cannot see either key — it runs the `run:` body directly,
# in the test's own cwd, under its own interpreter. That is the whole point of
# the rule: execution moved the boundary of the proof, it did not remove one.
#
# Population, counted inside the guarded graph rather than across the repo (the
# ADR-001 "name the population" rule, which #407 itself got wrong): of 105 steps
# and 20 jobs in the required graph, `working-directory` appears 0 times,
# `shell` 0 times, and `defaults` 0 times at job OR workflow level. The feared
# false-alarm cost of forbidding them is an empty allowlist.
REDIRECT_KEYS = ("working-directory", "shell")

REDIRECT_KEYS_NOTE = (
    "`working-directory:` and `shell:` are consumed by the RUNNER, so a test that "
    "executes the `run:` body cannot observe them: the step still runs and still "
    "reports success while checking something else (a relocated cwd makes the "
    "gate's grep find no file, `CRITS` empty, and `[ \"\" -gt 0 ]` false, so its "
    "`exit 1` never fires)."
)

# Reviewed exceptions for REDIRECT_KEYS, `(workflow, job, step, key)`. Empty:
# no step in the required graph declares either key today.
ALLOWED_STEP_REDIRECT: frozenset = frozenset()

# Reviewed exceptions, `(workflow file, job key, step name)`. Each one is a step
# whose failure genuinely must not fail the build.
#
# Codecov upload: a third-party artifact upload, not an enforcement step. The
# coverage FLOOR is enforced separately and blockingly by the
# `Fail workflow on scanner unittest / coverage failure` step in the same job
# (and pinned by test_ci_coverage_thresholds.py), so a flaky upload cannot hide a
# coverage regression.
ALLOWED_STEP_EXCEPTIONS = frozenset(
    {
        ("lint.yml", "scanner-unit-tests", "Upload coverage to Codecov"),
    }
)

# `if:` on a step in the required graph.
#
# The first version of this guard did NOT check this key, on the reasoning that
# conditional steps are ordinary and forbidding them would be a false-alarm
# generator. That reasoning was WRONG, and wrong in a measurable way: it was
# sized against every workflow in the repo, but the required graph has 105 steps
# of which exactly SEVEN carry an `if:`. At that size an allowlist is trivial.
#
# It mattered, because the gap was real. `if: false` on the sole enforcement step
# of a job (`Run gitleaks`, `Dependency Review`, `pii-check`'s only step, ...)
# leaves the job with nothing that can fail, so it concludes `success` by
# default — no job-level key needed — and the aggregator accepts `success`.
# Measured on the real `lint.yml`: step-level `continue-on-error` on `Run
# gitleaks` FAILED this guard (4 tests); step-level `if: false` on the same step
# passed it 14/14 (2026-08-08 audit).
#
# Direction is an ALLOWLIST of legitimate conditions, not a blocklist of disable
# shapes. That is deliberate — ADR-001 §4: an enumeration of ways to write
# "false" (`false`, `${{ false }}`, `1 == 2`, `github.event_name == 'never'`, ...)
# is exactly the shape that got defeated three times over in #402/#404. Any new
# condition, however it is spelled, fails until a human reviews it.
#
# `always()` is exempt by MEANING rather than by listing: it forces the step to
# run even after a prior failure, so it cannot be a disable. Only the bare form
# is exempt — `always() && <expr>` can absolutely disable, so the one compound
# use is allowlisted explicitly below.
_IF_ALWAYS_RE = re.compile(r"""^\s*(?:\$\{\{\s*)?always\(\)\s*(?:\}\})?\s*$""")

ALLOWED_STEP_IF = frozenset(
    {
        # Build kcov only on a cache miss. Skipping it on a HIT is the point; the
        # coverage floor is enforced by a later unconditional step either way.
        ("lint.yml", "scanner-shell-coverage", "Build kcov v42 from source"),
        # The enforcement step itself. `always()` so it runs after the swallowed
        # pytest step (`set +e`), and the `!= '0'` arm is what makes it fail —
        # an unset output is also `!= '0'`, so it fails closed.
        (
            "lint.yml",
            "scanner-unit-tests",
            "Fail workflow on scanner unittest / coverage failure",
        ),
    }
)

# Jobs the required contexts are expected to resolve to. A canary, not the source
# of truth — the graph is walked from the protection script. If branch protection
# legitimately changes, this fails loudly and demands the change be acknowledged.
EXPECTED_ROOTS = {("lint.yml", "lint-gate"), ("security-scan.yml", "security-scan-gate")}


def desired_contexts(script_text: str):
    """The required status-check names codified in `sync-repo-protection.sh`.

    That script is the repo's source of truth for branch protection and is itself
    pinned against live drift by `test_ci_branch_protection_codified.py`, so
    reading it here keeps one source rather than a second hand-maintained list
    that could disagree with the real gate.
    """
    m = re.search(
        r"""^\s*DESIRED_CONTEXTS=(['"])(?P<json>\[.*?\])\1""",
        script_text,
        re.M,
    )
    if not m:
        return None
    try:
        value = json.loads(m.group("json"))
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, list) else None


def _job_display_name(block: str, job_key: str) -> str:
    """A job's rendered check name: its `name:` value, else the job key itself —
    which is what GitHub uses, and what branch protection matches on."""
    body = [ln for ln in block.splitlines()[1:] if ln.strip()]
    if not body:
        return job_key
    col = min(len(ln) - len(ln.lstrip()) for ln in body)
    pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern('name')}\s*:\s*(.+?)\s*$")
    for raw in block.splitlines()[1:]:
        m = pat.match(strip_inline_comment(raw))
        if m:
            return m.group(1).strip("\"'")
    return job_key


def _workflow_files():
    """Workflow files only — composite actions have no `jobs:` map."""
    return [Path(p) for p in workflow_and_action_files() if Path(p).parent == WORKFLOW_DIR]


def workflow_texts() -> dict:
    """`{filename: text}` for every workflow on disk."""
    return {p.name: p.read_text(encoding="utf-8") for p in _workflow_files()}


def required_graph(texts: dict):
    """`(jobs, problems)` — every `(file, job_key)` reachable from a required
    context through `needs:`, plus fail-closed problems found on the way.

    Takes the workflow texts as a PARAMETER rather than reading disk, so the
    mutation self-tests exercise this exact function on a mutated copy instead of
    a parallel re-implementation. An earlier draft did keep a second in-memory
    copy — which is precisely the "two copies, and the next fix reaches only one"
    shape this repo has been bitten by; the self-tests would then have proved
    something about a function that does not guard the repo.
    """
    problems = []
    if not PROTECTION_SCRIPT.is_file():
        return set(), [f"{PROTECTION_SCRIPT} not found — cannot resolve required checks"]
    contexts = desired_contexts(PROTECTION_SCRIPT.read_text(encoding="utf-8"))
    if not contexts:
        return set(), ["could not parse DESIRED_CONTEXTS from the protection script"]

    # display name -> [(file, job_key)] across every workflow
    index = {}
    for fname, text in sorted(texts.items()):
        for key in top_level_jobs(text):
            block = job_block(text, key)
            if block is None:
                problems.append(
                    f"{fname}: job {key!r} does not resolve to exactly one block "
                    "— refusing to guess which one CI runs"
                )
                continue
            index.setdefault(_job_display_name(block, key), []).append((fname, key))

    roots = []
    for ctx in contexts:
        hits = index.get(ctx, [])
        if len(hits) != 1:
            problems.append(
                f"required check {ctx!r} resolves to {len(hits)} jobs {hits} — a "
                "required context that maps to no job means this guard is walking "
                "an empty graph and passing vacuously"
            )
            continue
        roots.append(hits[0])

    seen, stack = set(), list(roots)
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        fname, key = node
        block = job_block(texts[fname], key)
        if block is None:
            problems.append(f"{fname}: dependency {key!r} does not resolve to one block")
            continue
        for dep in job_needs(block):
            if (fname, dep) not in seen:
                stack.append((fname, dep))
    return seen, problems


def _steps_of(block: str):
    """`(step_name, key_column, step_block)` for each step of a job block.

    The step key column is DERIVED from each `- ` item, never assumed: dedenting
    a whole `steps:` list by 2 is valid YAML and would walk every step key out
    from under a fixed anchor (the shape that defeated #404's first draft)."""
    lines = block.splitlines()
    body = [ln for ln in lines[1:] if ln.strip()]
    if not body:
        return []
    job_col = min(len(ln) - len(ln.lstrip()) for ln in body)
    steps_re = re.compile(rf"^ {{{job_col}}}{yaml_key_pattern('steps')}\s*:\s*$")
    start = next(
        (i for i, ln in enumerate(lines) if steps_re.match(strip_inline_comment(ln))),
        None,
    )
    if start is None:
        return []
    out = []
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        m = re.match(r"^(\s*-\s+)(.*)$", line)
        # A block sequence may legally sit at its parent key's OWN indent, so a
        # `- ` item at exactly `job_col` is still one of `steps:`' items — not the
        # end of the list. Breaking on `indent <= job_col` skipped every step of a
        # dedented (but perfectly valid) `steps:` list, and the guard reported
        # clean on a workflow whose steps it had never looked at. Caught by
        # `test_dedented_steps_are_still_checked` while writing this file, which
        # is the same shape that defeated #404's first workflow-level draft.
        if indent < job_col or (indent == job_col and not m):
            break
        if not m:
            continue
        dash_col = indent
        key_col = len(m.group(1))
        item = [line]
        for nxt in lines[i + 1:]:
            if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= dash_col:
                break
            item.append(nxt)
        chunk = "\n".join(item)
        name_m = re.match(
            rf"^\s*-\s+{yaml_key_pattern('name')}\s*:\s*(.+?)\s*$",
            strip_inline_comment(line),
        )
        out.append((name_m.group(1).strip("\"'") if name_m else "", key_col, chunk))
    return out


def _declares(block: str, col: int, key: str) -> bool:
    """Whether `key` is declared at `col` in `block`, ordinary or explicit form.

    The `? key` / `: value` explicit form yields the same mapping key while the
    substring `key:` never appears anywhere, so no line matcher can reach it —
    it is unscannable, not merely unmatched, and is treated as present
    (fail closed, the `unscannable_*` tripwire pattern, ADR-001 §4)."""
    return key in keys_at_column(block, col) or bool(explicit_key_lines(block, key))


def _key_value(block: str, col: int, key: str):
    """The scalar value of `key` at `col`, or None if absent/unreadable.

    None means "present but not readable as a plain scalar" is NOT distinguished
    from absent here — callers pair this with `_declares`, so an unreadable value
    on a declared key is reported rather than skipped."""
    pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern(key)}\s*:\s*(.+?)\s*$")
    for raw in block.splitlines():
        m = pat.match(strip_inline_comment(raw))
        if m:
            return m.group(1).strip("\"'")
    return None


def graph_violations(texts: dict = None):
    """Every way a required check can be neutered by a runner-consumed key.

    `texts` defaults to the real workflows; the mutation self-tests pass a
    mutated copy so nothing is ever written into `.github/`."""
    if texts is None:
        texts = workflow_texts()
    jobs, problems = required_graph(texts)
    out = list(problems)
    for fname in sorted({f for f, _ in jobs}):
        # WORKFLOW-level `defaults:` reaches every job in the file at once — the
        # quietest form of the redirect class, and one no job- or step-level scan
        # would ever look at.
        if _declares(texts[fname], 0, "defaults"):
            out.append(
                f"{fname}: workflow-level `defaults:` — `defaults.run.working-directory` "
                "and `defaults.run.shell` change how EVERY step in this file runs, "
                f"including the required check's. See {REDIRECT_KEYS_NOTE}"
            )
    for fname, key in sorted(jobs):
        block = job_block(texts[fname], key)
        if block is None:
            out.append(f"{fname}: job {key!r} no longer resolves to one block")
            continue
        body = [ln for ln in block.splitlines()[1:] if ln.strip()]
        job_col = min((len(ln) - len(ln.lstrip()) for ln in body), default=4)
        if _declares(block, job_col, "defaults"):
            out.append(
                f"{fname}: job {key!r} sets job-level `defaults:` — "
                f"`defaults.run.working-directory`/`shell` redirect every step in the "
                f"job. See {REDIRECT_KEYS_NOTE}"
            )
        for rkey in REDIRECT_KEYS:
            if _declares(block, job_col, rkey):
                out.append(
                    f"{fname}: job {key!r} sets job-level `{rkey}`. "
                    f"See {REDIRECT_KEYS_NOTE}"
                )
        if _declares(block, job_col, DISABLING_KEY):
            out.append(
                f"{fname}: job {key!r} sets job-level `{DISABLING_KEY}` — the whole "
                "job concludes `success` regardless of what it does, and the "
                "aggregator accepts `success`, so this required check stops blocking"
            )
        for step_name, key_col, chunk in _steps_of(block):
            if _declares(chunk, key_col, DISABLING_KEY) and (
                fname,
                key,
                step_name,
            ) not in ALLOWED_STEP_EXCEPTIONS:
                out.append(
                    f"{fname}: job {key!r} step {step_name!r} sets `{DISABLING_KEY}` — "
                    "the runner discards its exit code. If the step genuinely must not "
                    "fail the build, add it to ALLOWED_STEP_EXCEPTIONS with a rationale"
                )
            for rkey in REDIRECT_KEYS:
                if _declares(chunk, key_col, rkey) and (
                    fname,
                    key,
                    step_name,
                    rkey,
                ) not in ALLOWED_STEP_REDIRECT:
                    out.append(
                        f"{fname}: job {key!r} step {step_name!r} sets `{rkey}`. "
                        f"See {REDIRECT_KEYS_NOTE} If this step genuinely needs it, "
                        "add it to ALLOWED_STEP_REDIRECT with a rationale"
                    )
            if not _declares(chunk, key_col, "if"):
                continue
            if (fname, key, step_name) in ALLOWED_STEP_IF:
                continue
            value = _key_value(chunk, key_col, "if")
            if value is not None and _IF_ALWAYS_RE.match(value):
                continue  # `always()` forces the step to run; it cannot disable
            out.append(
                f"{fname}: job {key!r} step {step_name!r} is conditional "
                f"(`if: {value}`). A condition on a step in a REQUIRED check's "
                "graph can stop it running, and a job whose only failing step is "
                "skipped concludes `success` by default. If this condition is "
                "legitimate, add it to ALLOWED_STEP_IF with a rationale — the "
                "allowlist is the review moment, and is deliberately not a list "
                "of ways to spell `false`"
            )
    return sorted(out)


class TestRequiredGraphNotDisabled(unittest.TestCase):
    def test_graph_is_populated(self):
        """Canary. An empty or shrunken graph would pass every check below
        vacuously, which is precisely how a guard goes quietly dead."""
        jobs, problems = required_graph(workflow_texts())
        self.assertEqual(problems, [], f"required graph could not be resolved: {problems}")
        self.assertTrue(
            EXPECTED_ROOTS <= jobs,
            f"the codified required contexts no longer resolve to {EXPECTED_ROOTS} "
            f"(got {sorted(jobs)}). If branch protection changed, that is a decision "
            "to acknowledge here, not to absorb silently.",
        )
        self.assertGreaterEqual(
            len(jobs),
            18,
            f"the required graph collapsed to {len(jobs)} jobs — measured at 20 on "
            "2026-08-08. A sudden shrink means dependencies were dropped from an "
            "aggregator's `needs:`, which is itself the bug this class covers.",
        )

    def test_no_runner_key_disables_a_required_job(self):
        violations = graph_violations()
        self.assertEqual(
            violations,
            [],
            "a job in a REQUIRED check's dependency graph can no longer fail the "
            "build:\n  " + "\n  ".join(violations),
        )

    def test_allowlist_has_no_stale_entries(self):
        """A stale exception is an unexplained hole. Fails once the step stops
        setting the key, so each allowlist keeps meaning what it says."""
        stale = []
        for label, entries, key in (
            ("ALLOWED_STEP_EXCEPTIONS", ALLOWED_STEP_EXCEPTIONS, DISABLING_KEY),
            ("ALLOWED_STEP_IF", ALLOWED_STEP_IF, "if"),
        ):
            for fname, job, step_name in sorted(entries):
                text = (WORKFLOW_DIR / fname).read_text(encoding="utf-8")
                block = job_block(text, job)
                if block is None:
                    stale.append(f"{label}: {fname}:{job} (job not found)")
                    continue
                hit = [
                    chunk
                    for name, col, chunk in _steps_of(block)
                    if name == step_name and _declares(chunk, col, key)
                ]
                if not hit:
                    stale.append(f"{label}: {fname}:{job}:{step_name}")
        self.assertEqual(
            stale, [], "stale allowlist entries (step fixed or moved): " + str(stale)
        )


class TestGraphViolationDetector(unittest.TestCase):
    """Mutation self-tests. Each case is a shape the 2026-08-08 audit reproduced
    on the real workflows; a guard with no mutation self-test is an untested
    control (ADR-001 §4)."""

    def setUp(self):
        self.lint = (WORKFLOW_DIR / "lint.yml").read_text(encoding="utf-8")
        self.scan = (WORKFLOW_DIR / "security-scan.yml").read_text(encoding="utf-8")

    def _violations_with(self, fname, mutant):
        """`graph_violations()` as if `fname` held `mutant`, without touching disk.

        Calls the REAL function with substituted text — not a parallel copy — so
        every mutation below exercises the code that actually guards the repo."""
        texts = workflow_texts()
        self.assertNotEqual(mutant, texts[fname], "mutation did not apply — the test is vacuous")
        texts[fname] = mutant
        return graph_violations(texts)

    def test_job_level_on_the_required_check_itself_is_caught(self):
        m = self.scan.replace(
            "  security-scan-gate:\n", "  security-scan-gate:\n    continue-on-error: true\n", 1
        )
        hits = self._violations_with("security-scan.yml", m)
        self.assertTrue(
            [h for h in hits if "security-scan-gate" in h], f"not caught: {hits}"
        )

    def test_job_level_on_lint_gate_is_caught(self):
        m = self.lint.replace("  lint-gate:\n", "  lint-gate:\n    continue-on-error: true\n", 1)
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "lint-gate" in h], f"not caught: {hits}")

    def test_job_level_on_a_dependency_is_caught(self):
        m = self.lint.replace(
            "  dependency-review:\n", "  dependency-review:\n    continue-on-error: true\n", 1
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "dependency-review" in h], f"not caught: {hits}")

    def test_step_level_on_a_dependency_is_caught(self):
        m = re.sub(
            r"(?m)^(( *)- name: Dependency Review)$",
            r"\1\n\2  continue-on-error: true",
            self.lint,
            count=1,
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "Dependency Review" in h], f"not caught: {hits}")

    # --- REDIRECT keys: the step RUNS and reports success, checking something
    # --- else. The 2026-08-10 finding; see REDIRECT_KEYS for the executed proof.

    def test_step_working_directory_on_the_gate_is_caught(self):
        # THE finding, on the real gate step: one line, whole suite green (1945
        # passed), required check no longer blocks a CRITICAL.
        m = self.scan.replace(
            "      - name: Check for critical/high failures\n        run: |\n",
            "      - name: Check for critical/high failures\n"
            "        working-directory: docs\n        run: |\n",
            1,
        )
        hits = self._violations_with("security-scan.yml", m)
        self.assertTrue(
            [h for h in hits if "working-directory" in h and "critical/high" in h],
            f"not caught: {hits}",
        )

    def test_step_shell_on_the_gate_is_caught(self):
        # `shell: cat {0}` prints the script instead of running it and exits 0 —
        # strictly worse than the cwd redirect, and equally invisible to a test
        # that executes the `run:` body itself.
        m = self.scan.replace(
            "      - name: Check for critical/high failures\n        run: |\n",
            "      - name: Check for critical/high failures\n"
            "        shell: cat {0}\n        run: |\n",
            1,
        )
        hits = self._violations_with("security-scan.yml", m)
        self.assertTrue([h for h in hits if "shell" in h], f"not caught: {hits}")

    def test_step_redirect_on_a_dependency_is_caught(self):
        m = re.sub(
            r"(?m)^(( *)- name: Dependency Review)$",
            r"\1\n\2  working-directory: docs",
            self.lint,
            count=1,
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue(
            [h for h in hits if "Dependency Review" in h and "working-directory" in h],
            f"not caught: {hits}",
        )

    def test_job_level_defaults_is_caught(self):
        # `defaults.run.working-directory` at JOB level redirects every step in
        # the job at once — no per-step edit to notice in review.
        m = self.scan.replace(
            "  security-scan-gate:\n",
            "  security-scan-gate:\n    defaults:\n      run:\n"
            "        working-directory: docs\n",
            1,
        )
        hits = self._violations_with("security-scan.yml", m)
        self.assertTrue([h for h in hits if "defaults" in h], f"not caught: {hits}")

    def test_workflow_level_defaults_is_caught(self):
        # The quietest form: one top-level block redirects EVERY job in the file,
        # and neither a job scan nor a step scan would ever look at column 0.
        m = self.scan.replace(
            "jobs:\n", "defaults:\n  run:\n    working-directory: docs\njobs:\n", 1
        )
        hits = self._violations_with("security-scan.yml", m)
        self.assertTrue(
            [h for h in hits if "workflow-level `defaults:`" in h], f"not caught: {hits}"
        )

    def test_quoted_and_explicit_redirect_spellings_are_caught(self):
        # `"working-directory":` is the same key to any YAML parser, and the
        # `? working-directory` explicit form makes the substring vanish entirely
        # — the shapes that defeated eight guards in #391/#393/#394.
        for inject in (
            '        "working-directory": docs\n',
            "        ? working-directory\n        : docs\n",
        ):
            with self.subTest(spelling=inject.strip()):
                m = self.scan.replace(
                    "      - name: Check for critical/high failures\n        run: |\n",
                    "      - name: Check for critical/high failures\n"
                    + inject
                    + "        run: |\n",
                    1,
                )
                hits = self._violations_with("security-scan.yml", m)
                self.assertTrue(
                    [h for h in hits if "working-directory" in h], f"not caught: {hits}"
                )

    def test_redirect_keys_quiet_on_the_real_workflows(self):
        # No-false-alarm direction, and the reason ALLOWED_STEP_REDIRECT is
        # empty: nothing in the required graph declares either key today.
        hits = [h for h in graph_violations() if "working-directory" in h or "shell" in h]
        self.assertEqual(hits, [])

    def test_quoted_key_spelling_is_caught(self):
        m = self.lint.replace(
            "  dependency-review:\n", '  dependency-review:\n    "continue-on-error": true\n', 1
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "dependency-review" in h], f"not caught: {hits}")

    def test_explicit_key_form_is_caught(self):
        m = self.lint.replace(
            "  dependency-review:\n",
            "  dependency-review:\n    ? continue-on-error\n    : true\n",
            1,
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "dependency-review" in h], f"not caught: {hits}")

    def _gitleaks_step_with(self, key_line):
        """The real lint.yml with `key_line` added to the `Run gitleaks` step —
        the sole step in that job that can fail."""
        return re.sub(
            r"(?m)^(( *)- name: Run gitleaks)$",
            lambda m: f"{m.group(1)}\n{m.group(2)}  {key_line}",
            self.lint,
            count=1,
        )

    def test_step_if_false_on_the_sole_enforcement_step_is_caught(self):
        """The gap the first version of this guard had, measured on the real file.

        Skipping the only step that can fail leaves the job with zero failures,
        so it concludes `success` by default — no job-level key needed — and the
        aggregator accepts `success`."""
        # The mutant is bound to a local before being scanned, rather than nested
        # as `scan(build(text))`. `test_ci_strip_before_match`'s detector B reads
        # that nesting as `strip_x(extract_y(text))` — a real defect shape when
        # the inner call NARROWS a haystack. It does not here (this builder ADDS
        # text, and the scanner strips comments per line internally), but the
        # detector cannot tell a builder from an extractor, and un-nesting is
        # cheaper and safer than teaching it a new category or spending an
        # allowlist entry on a false positive. Do not re-nest these.
        mutant = self._gitleaks_step_with("if: false")
        hits = self._violations_with("lint.yml", mutant)
        self.assertTrue([h for h in hits if "Run gitleaks" in h], f"not caught: {hits}")

    def test_step_if_is_not_an_enumeration_of_false_spellings(self):
        """The allowlist direction is the whole point (ADR-001 §4).

        A blocklist of ways to write "false" is the shape that got defeated three
        times over in #402/#404. None of these are `false` literally, and every
        one must still be caught, because the rule is "not on the allowlist", not
        "looks disabled"."""
        for cond in (
            "${{ false }}",
            "github.event_name == 'never'",
            "${{ 1 == 2 }}",
            "${{ !always() }}",
            "always() && false",  # the `always()` exemption is BARE-form only
            "${{ github.actor == 'nobody-at-all' }}",
        ):
            with self.subTest(cond=cond):
                mutant = self._gitleaks_step_with(f"if: {cond}")
                hits = self._violations_with("lint.yml", mutant)
                self.assertTrue(
                    [h for h in hits if "Run gitleaks" in h], f"not caught: {cond} -> {hits}"
                )

    def test_step_if_explicit_key_form_is_caught(self):
        m = re.sub(
            r"(?m)^(( *)- name: Run gitleaks)$",
            lambda m: f"{m.group(1)}\n{m.group(2)}  ? if\n{m.group(2)}  : false",
            self.lint,
            count=1,
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "Run gitleaks" in h], f"not caught: {hits}")

    def test_bare_always_is_not_a_false_alarm(self):
        """`always()` forces the step to run even after a prior failure, so it
        cannot be a disable. Exempt by MEANING, not by being on a list."""
        for cond in ("always()", "${{ always() }}"):
            with self.subTest(cond=cond):
                mutant = self._gitleaks_step_with(f"if: {cond}")
                self.assertEqual(
                    self._violations_with("lint.yml", mutant),
                    [],
                    f"{cond} was wrongly reported as a disable",
                )

    def test_dedented_steps_are_still_checked(self):
        """A block sequence may sit at its parent key's own indent, so dedenting
        a whole `steps:` list is valid YAML and a cosmetic diff — and it moves
        every step key off any fixed anchor. The shape that defeated #404's first
        workflow-level draft."""
        block = job_block(self.lint, "dependency-review")
        dedented = "\n".join(
            ln[2:] if ln.startswith("      ") else ln for ln in block.splitlines()
        )
        m = self.lint.replace(block, dedented, 1)
        m = re.sub(
            r"(?m)^(( *)- name: Dependency Review)$",
            r"\1\n\2  continue-on-error: true",
            m,
            count=1,
        )
        hits = self._violations_with("lint.yml", m)
        self.assertTrue([h for h in hits if "Dependency Review" in h], f"not caught: {hits}")

    def test_unmutated_workflows_are_clean(self):
        self.assertEqual(graph_violations(), [])

    def test_commented_key_is_not_a_false_alarm(self):
        m = self.lint.replace(
            "  dependency-review:\n", "  dependency-review:\n    # continue-on-error: true\n", 1
        )
        self.assertEqual(
            self._violations_with("lint.yml", m),
            [],
            "a `#`-commented key is inert and must not trip the guard",
        )

    def test_dropping_a_required_context_fails_closed(self):
        """A context that maps to no job would leave an empty graph — every check
        below it green, protecting nothing."""
        text = PROTECTION_SCRIPT.read_text(encoding="utf-8")
        self.assertIsNotNone(desired_contexts(text))
        self.assertIsNone(
            desired_contexts(text.replace("DESIRED_CONTEXTS=", "OTHER_CONTEXTS=", 1)),
            "an unparseable protection script must be reported, not treated as "
            "'no required checks'",
        )


class TestHarnessUsesTheRealFunction(unittest.TestCase):
    def test_substituted_texts_match_disk(self):
        """`graph_violations(workflow_texts())` and `graph_violations()` must be
        the same call. If the harness ever drifts into a parallel copy again, the
        mutation self-tests would prove something about a function that does not
        guard the repo."""
        self.assertEqual(graph_violations(workflow_texts()), graph_violations())
        self.assertEqual(graph_violations(), [])


if __name__ == "__main__":
    unittest.main()
