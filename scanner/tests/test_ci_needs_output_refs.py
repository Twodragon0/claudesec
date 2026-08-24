"""Regression guard: every `needs.<job>.outputs.<name>` reference in a workflow
must RESOLVE, and every `github.<prop>` in an `if:` must be a real context
property.

THE INVARIANT, and why a typo here is worse than a syntax error: GitHub does not
fail an expression that names something nonexistent. `needs.changes.outputs.pythonn`
evaluates to the empty string, so `if: needs.changes.outputs.pythonn == 'true'`
is permanently false, the job is permanently `skipped` — and `lint-gate` counts
`skipped` as a pass (`result not in ("success", "skipped")`). The check reports
GREEN forever while enforcing nothing. There is no `neutral` conclusion for a job
and no warning anywhere: a one-character edit silently deletes a required gate.

THREE WAYS THE SAME EXPRESSION GOES SILENTLY EMPTY, all checked here:
  1. the OUTPUT name is not declared by the producing job's `outputs:` map,
  2. the JOB name is not a top-level job in the same workflow,
  3. the referencing job does not list the producing job in its own `needs:` —
     `needs.changes` is only populated for jobs that actually depend on `changes`.
Plus the neighbouring shape in the same expressions: a mistyped `github.<prop>`
(`github.event_nam == 'schedule'`) makes that arm of the `||` dead.

THE INCIDENT: this repo has already paid for this class twice, from the other
direction. `lint.yml` has no `schedule:` trigger, so the `|| github.event_name ==
'schedule'` arm was DEAD in seven jobs — `npm-audit` ran on nothing for ~7 weeks
and 117 commits, and `dast-full-scan`'s nightly was silently `skipped` ~42 nights
(#396/#397). Both were no-op jobs reading green. Nothing then pinned the
expressions themselves, so the successor typo would repeat it: measured
2026-08-24 on this branch, mutating `outputs.shell` -> `outputs.shel` and
`github.event_name` -> `github.event_nam` in `lint.yml` each left all 918
existing CI guards GREEN.

DIRECTION: presence/equality — the reference set must resolve EXACTLY. Adding a
real output and referencing it stays green; any rename, typo, or removal on
either side trips. There is no ratchet to be lenient about.

KNOWN LIMITS, by direction:
- `steps.<id>.outputs.<name>` is NOT checked (false negative, deliberate). Step
  outputs are written at runtime into `$GITHUB_OUTPUT` by shell, often through a
  variable, so there is no static declaration to compare against. Only the
  `needs.` half has one.
- A job that calls a reusable workflow (job-level `uses:`) takes its outputs from
  the callee, which this guard does not follow, so such a job would be a FALSE
  ALARM. There are zero job-level `uses:` in this repo today (verified
  2026-08-24); if one lands, exempt it here rather than dropping the check.
- `github.<prop>` is validated ONLY inside `if:` values (false negative,
  deliberate). Elsewhere `github.` collides with prose and code that is not an
  expression at all — `github.com`/`github.io` in URLs, and `github.rest.*`
  inside `actions/github-script` bodies, which is the JS Octokit client rather
  than the Actions context. Scoping by context beats trying to tell those apart
  by token shape.
- `github.event.<anything>` is skipped: the webhook payload is not a fixed
  schema, so there is no list to check it against.

stdlib-only (regex + the shared column primitives, no PyYAML — it is absent from
requirements-ci.txt). No `scanner/lib` import, so this does not touch the 99%
coverage gate. Passes under both pytest and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    block_ends_at,
    job_needs,
    key_column,
    key_line,
    keys_at_column,
    strip_comment_lines,
    top_level_jobs,
    job_block,
    workflow_and_action_files,
)

# `needs.<job>.outputs.<name>`. Job and output names use the YAML-key charset
# GitHub allows, so a typo is a DIFFERENT name rather than a non-match — which is
# the whole point: the reference still parses, it just resolves to nothing.
_NEEDS_OUT_RE = re.compile(r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)")

# A single-segment `github.<prop>`. `(?![.\w])` stops it from swallowing
# `github.event.pull_request` as the property `event` — that nested form is
# excluded on purpose (see KNOWN LIMITS), and matching only the terminal segment
# would be the wrong grammar.
_GITHUB_PROP_RE = re.compile(r"github\.([A-Za-z_][A-Za-z0-9_]*)(?![.\w])")

# The documented `github` context properties.
# https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
#
# Enumerating the VALID set is directional on purpose: a property GitHub adds
# later is REPORTED (a false alarm someone resolves by adding one line here),
# never silently accepted. The opposite shape — enumerating known-bad names —
# cannot catch a typo nobody predicted, which is the only thing worth catching.
_GITHUB_CONTEXT_PROPS = frozenset(
    {
        "action", "action_path", "action_ref", "action_repository", "action_status",
        "actor", "actor_id", "api_url", "base_ref", "env", "event", "event_name",
        "event_path", "graphql_url", "head_ref", "job", "path", "ref", "ref_name",
        "ref_protected", "ref_type", "repository", "repository_id",
        "repository_owner", "repository_owner_id", "repositoryUrl",
        "retention_days", "run_attempt", "run_id", "run_number", "secret_source",
        "server_url", "sha", "token", "triggering_actor", "workflow",
        "workflow_ref", "workflow_sha", "workspace",
    }
)


def declared_outputs(block: str) -> set:
    """The output names a job block declares under its own `outputs:` map.

    Column-derived at both levels rather than anchored at a fixed indent: the job
    body's column comes from `key_column`, and the `outputs:` sub-block's own
    column comes from `key_column` again. A `steps:` list dedented to its parent's
    indent is valid YAML and a cosmetic diff, and it walks every key out from
    under a `^\\s{6}` anchor with the suite green (`keys_at_column`'s lesson).

    Only a key at EXACTLY the job's column counts as the job's `outputs:` — a
    step whose `with:` happens to contain an `outputs` input sits deeper and must
    not contribute names.
    """
    col = key_column(block)
    if col is None:
        return set()
    lines = block.splitlines()
    for i, raw in enumerate(lines):
        parsed = key_line(raw)
        if not parsed or parsed[0] != col or parsed[1] != "outputs":
            continue
        sub = [raw]
        for later in lines[i + 1:]:
            if block_ends_at(later, col):
                break
            sub.append(later)
        sub_block = "\n".join(sub)
        sub_col = key_column(sub_block)
        return set(keys_at_column(sub_block, sub_col)) if sub_col is not None else set()
    return set()


def _referencing_job(text: str, offset: int, jobs: list):
    """The top-level job whose block contains character `offset`, or None.

    Needed for check 3: whether the reference is legal depends on WHICH job makes
    it. Derived by locating each job's block in the document rather than tracking
    indent while scanning, so a reference inside a block scalar is attributed to
    the same job the runner would attribute it to.
    """
    for job in jobs:
        block = job_block(text, job)
        if not block:
            continue
        start = text.find(block)
        if start != -1 and start <= offset < start + len(block):
            return job
    return None


def unresolved_needs_refs(text: str) -> list:
    """Every `needs.<job>.outputs.<name>` in `text` that cannot resolve.

    Comment lines are stripped first: a reference inside a comment is not live, so
    validating it would be a false alarm. That direction is safe — a commented-out
    reference also cannot satisfy anything here, because this function only ever
    ADDS findings.
    """
    scan = strip_comment_lines(text)
    jobs = top_level_jobs(scan)
    if not jobs:
        return []
    outputs = {j: declared_outputs(job_block(scan, j) or "") for j in jobs}
    findings = []
    for m in _NEEDS_OUT_RE.finditer(scan):
        job, name = m.group(1), m.group(2)
        if job not in jobs:
            findings.append(
                f"needs.{job}.outputs.{name}: no top-level job named '{job}' "
                f"(jobs: {', '.join(sorted(jobs))})"
            )
            continue
        if name not in outputs[job]:
            findings.append(
                f"needs.{job}.outputs.{name}: job '{job}' declares no output "
                f"'{name}' (declares: {', '.join(sorted(outputs[job])) or 'none'})"
            )
            continue
        src = _referencing_job(scan, m.start(), jobs)
        if src is not None and src != job and job not in job_needs(job_block(scan, src) or ""):
            findings.append(
                f"needs.{job}.outputs.{name}: job '{src}' reads it but does not "
                f"list '{job}' in its own needs:, so the value is always empty"
            )
    return findings


def unknown_github_props(text: str) -> list:
    """Every `github.<prop>` inside an `if:` value that is not a real context
    property. Scoped to `if:` values — see the module docstring's KNOWN LIMITS."""
    findings = []
    for raw in strip_comment_lines(text).splitlines():
        parsed = key_line(raw)
        if not parsed or parsed[1] != "if":
            continue
        for m in _GITHUB_PROP_RE.finditer(parsed[2]):
            if m.group(1) not in _GITHUB_CONTEXT_PROPS:
                findings.append(
                    f"github.{m.group(1)}: not a documented github context "
                    f"property, so this expression is always empty -> "
                    f"{parsed[2].strip()}"
                )
    return findings


class TestNeedsOutputRefsResolve(unittest.TestCase):
    """The invariant, on the real workflow and action files."""

    @classmethod
    def setUpClass(cls):
        cls.files = [Path(p) for p in workflow_and_action_files()]

    def test_workflow_files_found(self):
        """Canary: a moved or renamed tree must fail loudly, not vacuously.

        Without this, an empty file list satisfies every "for each file" assertion
        below and the guard reports OK having checked nothing.
        """
        self.assertGreater(len(self.files), 5, "workflow/action files not found")

    def test_at_least_one_needs_output_reference_exists(self):
        """Canary for the DETECTOR, not the tree: if the regex ever stops matching
        the shape this repo actually writes, every assertion below passes on an
        empty finding set. Measured 2026-08-24: 14 references across 4 workflows.
        """
        total = sum(
            len(_NEEDS_OUT_RE.findall(strip_comment_lines(p.read_text(encoding="utf-8"))))
            for p in self.files
        )
        self.assertGreaterEqual(
            total, 10, "no needs.<job>.outputs.<name> references found to check"
        )

    def test_every_needs_output_reference_resolves(self):
        bad = {}
        for path in self.files:
            found = unresolved_needs_refs(path.read_text(encoding="utf-8"))
            if found:
                bad[path.name] = found
        self.assertEqual(
            bad,
            {},
            "unresolvable needs.<job>.outputs.<name> reference(s). GitHub does "
            "NOT fail on these — the expression yields '', so the job is "
            "permanently skipped and lint-gate reads skipped as a pass:\n"
            + "\n".join(
                f"  {f}: {v}" for f, vs in sorted(bad.items()) for v in vs
            ),
        )

    def test_every_github_context_property_in_an_if_is_real(self):
        bad = {}
        for path in self.files:
            found = unknown_github_props(path.read_text(encoding="utf-8"))
            if found:
                bad[path.name] = found
        self.assertEqual(
            bad,
            {},
            "unknown github context property in an if: expression — that arm is "
            "always false. If GitHub has added the property, add it to "
            "_GITHUB_CONTEXT_PROPS:\n"
            + "\n".join(
                f"  {f}: {v}" for f, vs in sorted(bad.items()) for v in vs
            ),
        )


class TestUnresolvedRefDetector(unittest.TestCase):
    """Mutation self-tests. Each case is the real defect shape, applied to a
    string — never to a file on disk. `assert_disables` pins BOTH directions
    (clean text clean, mutant reported) so a detector that fires on everything
    cannot pass either.
    """

    CLEAN = """\
name: probe
on:
  pull_request:
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      python: ${{ steps.detect.outputs.python }}
      shell: ${{ steps.detect.outputs.shell }}
    steps:
      - id: detect
        run: echo "python=true" >> "$GITHUB_OUTPUT"
  python-lint:
    needs: changes
    if: needs.changes.outputs.python == 'true' || github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - run: ruff check .
"""

    def test_clean_probe_has_no_findings(self):
        """Positive control. Every mutation case below is meaningless unless the
        unmutated fixture is genuinely clean."""
        self.assertEqual(unresolved_needs_refs(self.CLEAN), [])
        self.assertEqual(unknown_github_props(self.CLEAN), [])

    def test_typo_in_output_name_is_reported(self):
        assert_disables(
            unresolved_needs_refs,
            self.CLEAN,
            apply_mutation(self.CLEAN, "outputs.python == 'true'", "outputs.pythonn == 'true'"),
            "output-name typo",
        )

    def test_typo_in_job_name_is_reported(self):
        assert_disables(
            unresolved_needs_refs,
            self.CLEAN,
            apply_mutation(self.CLEAN, "if: needs.changes.outputs", "if: needs.chagnes.outputs"),
            "job-name typo",
        )

    def test_removing_the_output_declaration_is_reported(self):
        """The other side of the same edit: the reference is untouched and the
        DECLARATION goes away. A guard that only re-read the reference would miss
        this, which is the direction that actually happens during a refactor."""
        assert_disables(
            unresolved_needs_refs,
            self.CLEAN,
            apply_mutation(self.CLEAN, "      python: ${{ steps.detect.outputs.python }}\n", ""),
            "declaration removed",
        )

    def test_missing_needs_edge_is_reported(self):
        """Check 3: the name resolves but the referencing job never depends on the
        producer, so `needs.changes` is not populated for it."""
        assert_disables(
            unresolved_needs_refs,
            self.CLEAN,
            apply_mutation(self.CLEAN, "    needs: changes\n", ""),
            "needs edge removed",
        )

    def test_typo_in_github_context_property_is_reported(self):
        assert_disables(
            unknown_github_props,
            self.CLEAN,
            apply_mutation(self.CLEAN, "github.event_name", "github.event_nam"),
            "github context typo",
        )

    def test_commented_out_reference_is_not_reported(self):
        """False-alarm direction: a reference that only survives in a comment is
        not live, so it must not be validated. Uses a name that WOULD be reported
        if the comment were read as code."""
        mutant = self.CLEAN.replace(
            "      - run: ruff check .",
            "      # legacy: needs.changes.outputs.gone\n      - run: ruff check .",
        )
        self.assertNotEqual(mutant, self.CLEAN, "fixture stale")
        self.assertEqual(unresolved_needs_refs(mutant), [])

    def test_nested_event_payload_is_not_reported(self):
        """`github.event.pull_request.head.sha` must not be read as the property
        `event.pull_request` nor as the bare property `event` being unknown."""
        mutant = apply_mutation(
            self.CLEAN,
            "github.event_name == 'schedule'",
            "github.event.pull_request.draft == false",
        )
        self.assertEqual(unknown_github_props(mutant), [])

    def test_step_outputs_are_not_validated(self):
        """`steps.<id>.outputs.<name>` has no static declaration to check, and the
        fixture's own `outputs:` map is built from exactly that shape. If this
        ever starts reporting, the regex has stopped anchoring on `needs.`."""
        mutant = apply_mutation(
            self.CLEAN, "steps.detect.outputs.shell", "steps.detect.outputs.anything"
        )
        self.assertEqual(unresolved_needs_refs(mutant), [])

    def test_quoted_job_key_is_still_resolved(self):
        """#391/#393's quoted-key class: a `"python-lint":` job must not become
        invisible, which would drop check 3 for every reference inside it."""
        mutant = apply_mutation(self.CLEAN, "  python-lint:", '  "python-lint":')
        self.assertEqual(unresolved_needs_refs(mutant), [])
        assert_disables(
            unresolved_needs_refs,
            mutant,
            apply_mutation(mutant, "outputs.python == 'true'", "outputs.nope == 'true'"),
            "quoted job key + output typo",
        )

    def test_outputs_key_nested_in_a_step_does_not_declare_job_outputs(self):
        """A `with: outputs:` input sits deeper than the job's column and must not
        supply names — otherwise a step input silently satisfies the invariant."""
        mutant = apply_mutation(
            self.CLEAN,
            "      - run: ruff check .",
            "      - uses: some/action@sha\n        with:\n          outputs:\n            nope: 1",
        )
        assert_disables(
            unresolved_needs_refs,
            mutant,
            apply_mutation(mutant, "outputs.python == 'true'", "outputs.nope == 'true'"),
            "step-level outputs must not count",
        )


if __name__ == "__main__":
    unittest.main()
