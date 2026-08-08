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

NOT forbidden — a step-level `if:`. Conditional steps are ordinary and there are
hundreds; forbidding them across twenty jobs would be a false-alarm generator
that gets the guard disabled within a week. #404 forbids `if:` on the ONE step
where the condition is never legitimate (the severity gate). That asymmetry is
deliberate: this guard covers the key with no legitimate use across a wide
surface, #404 covers a narrow surface exhaustively.

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


def graph_violations(texts: dict = None):
    """Every way a required check can be neutered by a runner-consumed key.

    `texts` defaults to the real workflows; the mutation self-tests pass a
    mutated copy so nothing is ever written into `.github/`."""
    if texts is None:
        texts = workflow_texts()
    jobs, problems = required_graph(texts)
    out = list(problems)
    for fname, key in sorted(jobs):
        block = job_block(texts[fname], key)
        if block is None:
            out.append(f"{fname}: job {key!r} no longer resolves to one block")
            continue
        body = [ln for ln in block.splitlines()[1:] if ln.strip()]
        job_col = min((len(ln) - len(ln.lstrip()) for ln in body), default=4)
        if _declares(block, job_col, DISABLING_KEY):
            out.append(
                f"{fname}: job {key!r} sets job-level `{DISABLING_KEY}` — the whole "
                "job concludes `success` regardless of what it does, and the "
                "aggregator accepts `success`, so this required check stops blocking"
            )
        for step_name, key_col, chunk in _steps_of(block):
            if not _declares(chunk, key_col, DISABLING_KEY):
                continue
            if (fname, key, step_name) in ALLOWED_STEP_EXCEPTIONS:
                continue
            out.append(
                f"{fname}: job {key!r} step {step_name!r} sets `{DISABLING_KEY}` — "
                "the runner discards its exit code. If the step genuinely must not "
                "fail the build, add it to ALLOWED_STEP_EXCEPTIONS with a rationale"
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
        setting the key, so the allowlist keeps meaning what it says."""
        stale = []
        for fname, job, step_name in sorted(ALLOWED_STEP_EXCEPTIONS):
            text = (WORKFLOW_DIR / fname).read_text(encoding="utf-8")
            block = job_block(text, job)
            if block is None:
                stale.append(f"{fname}:{job} (job not found)")
                continue
            hit = [
                chunk
                for name, col, chunk in _steps_of(block)
                if name == step_name and _declares(chunk, col, DISABLING_KEY)
            ]
            if not hit:
                stale.append(f"{fname}:{job}:{step_name}")
        self.assertEqual(
            stale, [], "stale ALLOWED_STEP_EXCEPTIONS entries (step fixed or moved): " + str(stale)
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
