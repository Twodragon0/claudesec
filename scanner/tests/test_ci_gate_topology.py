"""
Regression guards for the CI *enforcement topology* in `.github/workflows/`.

Two invariants, both load-bearing for merge safety:

1. **Action SHA pinning** — every `uses:` across all workflow files must pin a
   40-hex commit SHA, not a mutable tag/branch (OWASP A08, supply-chain). A
   Dependabot or human edit reintroducing a tag pin is a security regression.

2. **`lint-gate.needs` completeness** — `main` branch protection requires only
   the `Lint` check (the `lint-gate` job's display name) plus `Security Scan
   Gate`. Any job NOT wired into `lint-gate.needs` is therefore invisible to
   branch protection: it can go red without blocking a merge. This is the exact
   silent-bypass class flagged in project memory (paths-ignore vs branch
   protection, #186). This guard asserts every lint.yml job is either in
   `lint-gate.needs` or in a small, documented allowlist of intentionally
   ungated jobs — so a NEWLY added job that someone forgets to wire in trips it.

stdlib-only (regex/line scanning, no PyYAML — the CI `scanner-unit-tests` job
does not install it). No network, no subprocess. Passes under pytest (the CI
runner) and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    explicit_key_lines,
    job_block,
    job_needs,
    required_aggregators,
    strip_inline_comment as _strip_comment,
    top_level_jobs,
    workflow_and_action_files,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
LINT_YML = WORKFLOW_DIR / "lint.yml"

# Jobs in lint.yml intentionally NOT funnelled through the lint-gate aggregator.
# Keep this list TINY and justify every entry — it is the escape hatch the guard
# exists to police.
#
# - lint-gate: the aggregator itself (cannot depend on itself).
#
# (workflow-fork-guard was previously allowlisted, but is now wired into
# lint-gate.needs so its OWASP A08 fork-guard audit is merge-blocking — it is
# therefore correctly NO LONGER allowlisted.)
# Jobs deliberately not wired into their workflow's aggregator `needs:`, keyed by
# `(workflow file, job key)`.
#
# Keyed by FILE as well as name since 2026-08-10. A flat name set was fine while
# this guard only ever read `lint.yml`, but the moment it covers both required
# workflows a bare `"lint-gate"` would also exempt a same-named job in
# `security-scan.yml` — an allowlist that silently widens as files are added.
#
# Each aggregator exempts itself: a job cannot be in its own `needs:`.
UNGATED_JOBS_ALLOWLIST = {
    ("lint.yml", "lint-gate"),
    ("security-scan.yml", "security-scan-gate"),
}


# `uses:` bare OR quoted. A quoted key resolves identically for any YAML parser,
# and an adversarial sweep proved `- "uses": actions/checkout@main` slipped past
# the SHA-pin scan with the whole suite green. See `yaml_key_pattern`.
_USES_RE = re.compile(rf"""\s*-?\s*{yaml_key_pattern('uses')}:\s*([^\s#'"]+)""")


class TestActionShaPinning(unittest.TestCase):
    def test_every_uses_is_sha_pinned(self):
        # Workflows AND composite actions, both extensions — a composite
        # `action.yml` carries `steps[].uses` and was never globbed here, so a
        # tag pin there defeated OWASP A08 with the guard green.
        workflow_files = workflow_and_action_files()
        self.assertTrue(
            workflow_files,
            f"No workflow files found under {WORKFLOW_DIR} — path assumption broke",
        )
        self.assertTrue(
            [p for p in workflow_files if "/actions/" in p],
            "No composite `action.yml` matched — this repo has two; if they were "
            "intentionally removed, drop this canary in the same commit rather "
            "than leaving them silently unscanned.",
        )
        violations = []
        for path in workflow_files:
            for lineno, raw in enumerate(
                Path(path).read_text(encoding="utf-8").splitlines(), start=1
            ):
                m = _USES_RE.match(_strip_comment(raw))
                if not m:
                    continue
                ref = m.group(1)
                # Local composite actions and docker refs are not SHA-pinnable.
                if ref.startswith("./") or ref.startswith("docker://"):
                    continue
                if not re.search(r"@[0-9a-f]{40}$", ref):
                    violations.append(f"{Path(path).name}:{lineno}: {ref}")
        self.assertEqual(
            violations,
            [],
            "Non-SHA-pinned `uses:` found (use a 40-hex commit SHA, not a tag):\n"
            + "\n".join(violations),
        )

    def test_no_explicit_key_uses_or_jobs(self):
        # `? uses` / `: actions/checkout@main` declares the same key while the
        # substring `uses:` never appears, so the SHA-pin scan above cannot see the
        # value at all. Same for `? jobs`, which would hide the entire job map from
        # the gating check. Fail closed on the shape (ADR-001 §4).
        offenders = []
        for path in workflow_and_action_files():
            text = Path(path).read_text(encoding="utf-8")
            for ln in explicit_key_lines(text, "uses", "jobs", "needs"):
                offenders.append(f"{Path(path).name}:  {ln}")
        self.assertEqual(
            offenders,
            [],
            "A `uses:`/`jobs:`/`needs:` key declared with YAML's explicit-key form "
            "(`? key` on one line, `: value` on the next). The literal `key:` never "
            "appears, so neither the SHA-pin scan nor the gate-completeness scan can "
            "read it. Use the ordinary `key: value` form:\n  " + "\n  ".join(offenders),
        )


def required_workflow_texts():
    """`{filename: text}` for every workflow file (both extensions)."""
    return {
        Path(p).name: Path(p).read_text(encoding="utf-8")
        for p in workflow_and_action_files()
        if "/workflows/" in p
    }


def ungated_jobs():
    """`(violations, aggregators)` — jobs in a REQUIRED workflow that no required
    aggregator depends on, so they can fail without blocking a merge.

    Scoped to EVERY workflow that hosts a required aggregator, resolved from the
    codified `DESIRED_CONTEXTS`, not to a hardcoded `lint.yml`. That hardcoding
    was a real gap, measured 2026-08-10: a job added to `security-scan.yml` and
    left out of `security-scan-gate.needs` was invisible to the whole suite
    (1952 passed) even though this document claims the topology guards catch
    exactly that class. `lint.yml` was covered; the second required workflow
    never was.

    Same lesson as #407 and fixed the same way — derive the scope from the
    required contexts instead of naming one file, so a third required workflow
    is covered on the day it appears rather than after the next audit."""
    texts = required_workflow_texts()
    aggregators, problems = required_aggregators(texts)
    out = list(problems)
    for fname, gate in sorted(aggregators.items()):
        block = job_block(texts[fname], gate)
        if block is None:
            out.append(f"{fname}: aggregator {gate!r} does not resolve to one block")
            continue
        needs = set(job_needs(block))
        if not needs:
            out.append(f"{fname}: {gate}.needs parsed empty — the scan below is vacuous")
            continue
        for job in set(top_level_jobs(texts[fname])) - needs:
            if (fname, job) in UNGATED_JOBS_ALLOWLIST:
                continue
            out.append(
                f"{fname}: job {job!r} is not in {gate}.needs and is not "
                "allowlisted — it would NOT block a merge if it fails. Wire it "
                "into the aggregator, or (if intentionally ungated) add "
                f"('{fname}', '{job}') to UNGATED_JOBS_ALLOWLIST with a rationale"
            )
    return sorted(out), aggregators


class TestRequiredWorkflowGateCompleteness(unittest.TestCase):
    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_aggregators_resolve(self):
        # Vacuity canary. An empty aggregator map makes every check below pass
        # for free — the shape a guard dies in without anyone noticing.
        _, aggregators = ungated_jobs()
        self.assertEqual(
            aggregators,
            {"lint.yml": "lint-gate", "security-scan.yml": "security-scan-gate"},
            "the codified required contexts no longer resolve to the two known "
            "aggregators. If branch protection changed, acknowledge it here.",
        )

    def test_every_job_is_gated_or_allowlisted(self):
        violations, _ = ungated_jobs()
        self.assertEqual(violations, [], "\n  " + "\n  ".join(violations))

    def test_allowlist_has_no_stale_entries(self):
        # An allowlist entry that no longer names a real job (or that has since
        # been added to needs) is dead config — fail so it gets cleaned up.
        texts = required_workflow_texts()
        aggregators, _ = required_aggregators(texts)
        stale = []
        for fname, job in sorted(UNGATED_JOBS_ALLOWLIST):
            if fname not in texts or job not in set(top_level_jobs(texts[fname])):
                stale.append(f"{fname}:{job} (no such job)")
                continue
            gate = aggregators.get(fname)
            if gate and job != gate:
                block = job_block(texts[fname], gate)
                if block is not None and job in set(job_needs(block)):
                    stale.append(f"{fname}:{job} (now in {gate}.needs)")
        self.assertEqual(
            stale,
            [],
            "Stale UNGATED_JOBS_ALLOWLIST entries: " + ", ".join(stale),
        )


class TestLycheeVersionPin(unittest.TestCase):
    """`lint.yml` must keep `lycheeVersion: v0.23.0`.

    This is an INTENTIONAL upgrade block (equality, not a floor). lychee v0.24.x
    nests the binary inside a `lychee-<triple>/` subdirectory, but the pinned
    lychee-action installer expects it at the tarball ROOT and fails with
    `install: cannot stat '.../lychee-download/lychee'` — link-check breaks before
    any link is checked. PR #204 bumped to v0.24.2 and regressed exactly this;
    reverted in #210. Upstream lychee-action itself still defaults to v0.23.0.

    To bump intentionally: first verify the action's install path end-to-end
    (binary at the tarball root for the version), then update both lint.yml and
    PINNED_LYCHEE_VERSION here in the same PR.
    """

    PINNED_LYCHEE_VERSION = "v0.23.0"

    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_lychee_version_pinned(self):
        matches = re.findall(r"^\s*lycheeVersion:\s*(\S+)\s*$", self.text, re.MULTILINE)
        self.assertTrue(
            matches,
            "No `lycheeVersion:` found in lint.yml — the link-check binary pin was "
            "removed (it must stay pinned; see this test's docstring).",
        )
        for got in matches:
            self.assertEqual(
                got,
                self.PINNED_LYCHEE_VERSION,
                f"lycheeVersion is {got}, expected {self.PINNED_LYCHEE_VERSION}. "
                "v0.24.x nests the binary in a subdir the pinned lychee-action "
                "installer can't find (breaks link-check). If bumping is truly "
                "intended, verify the action install path end-to-end and update "
                "PINNED_LYCHEE_VERSION in this test.",
            )


class TestKeyQuotingAndEnumerationMutation(unittest.TestCase):
    """Non-vacuity for the 2026-08-06 sweep fixes: each detector must FIRE on the
    quoted / explicit-key / composite-action form that previously slipped past."""

    def test_uses_matcher_reads_quoted_key(self):
        for line in (
            '      - "uses": actions/checkout@main',
            "      - 'uses': actions/checkout@v4",
            "      - uses: actions/checkout@v4",
        ):
            with self.subTest(line=line.strip()):
                m = _USES_RE.match(_strip_comment(line))
                self.assertIsNotNone(
                    m,
                    "Mutation FAILED: a quoted `uses` key hid the action ref from "
                    "the SHA-pin scan — standard YAML key quoting evades OWASP A08.",
                )
                self.assertTrue(
                    m.group(1).startswith("actions/checkout@"),
                    f"captured the wrong ref: {m.group(1)!r}",
                )

    def test_uses_matcher_does_not_widen_to_other_keys(self):
        # The alternation must not swallow neighbouring keys — `with:`/`name:` are
        # not action refs, and flagging them would be noise that gets the guard
        # deleted rather than fixed.
        for line in ("      - name: uses something", '        with: {"uses": x}'):
            with self.subTest(line=line.strip()):
                self.assertIsNone(
                    _USES_RE.match(_strip_comment(line)),
                    "False positive: the quoted-uses pattern matched a non-`uses` key.",
                )

    def test_explicit_key_tripwire_fires(self):
        wf = "\n".join(
            ["jobs:", "  j:", "    steps:", "      - ? uses", "        : actions/checkout@main"]
        )
        self.assertTrue(
            explicit_key_lines(wf, "uses", "jobs", "needs"),
            "tripwire FAILED: `? uses` / `: ref` was not flagged, and the SHA-pin "
            "scan cannot read that value.",
        )
        self.assertEqual(
            explicit_key_lines("jobs:\n  j:\n    steps:\n      - uses: a@" + "0" * 40, "uses"),
            [],
            "tripwire false-positive on an ordinary `uses:` line.",
        )

    def test_composite_actions_are_enumerated(self):
        found = workflow_and_action_files()
        self.assertTrue(
            [p for p in found if "/actions/" in p and p.endswith(("action.yml", "action.yaml"))],
            "Mutation FAILED: composite `action.yml` files are not enumerated, so a "
            "tag-pinned `uses:` there evades the SHA-pin scan (verified green before "
            "this fix).",
        )

    def test_top_level_jobs_reads_quoted_job_key(self):
        wf = "\n".join(
            ["jobs:", "  build:", "    runs-on: x", '  "rogue":', "    runs-on: y"]
        )
        self.assertEqual(
            top_level_jobs(wf),
            ["build", "rogue"],
            "Mutation FAILED: a quoted job key is invisible to `top_level_jobs`, so "
            "an ungated job is hidden from BOTH branch protection and this guard.",
        )

    def test_quoted_sibling_job_terminates_the_aggregator_needs(self):
        # A quoted sibling job key must still end the aggregator's block, or that
        # job's `needs:` items get slurped into the aggregator's list and satisfy
        # the completeness check for dependencies it does not have.
        #
        # Kept after the hand-rolled `_lint_gate_needs` was replaced by the shared
        # `job_block`/`job_needs`: the point of a replacement is that the hardening
        # survives it, and the only way to know is to re-run the case that proved
        # it. Verified equal on the real lint.yml (15 identical entries) before the
        # swap.
        wf = "\n".join(
            [
                "jobs:",
                "  lint-gate:",
                "    needs:",
                "      - changes",
                '  "other":',
                "    needs:",
                "      - smuggled",
            ]
        )
        self.assertEqual(
            job_needs(job_block(wf, "lint-gate")),
            ["changes"],
            "Mutation FAILED: a quoted sibling job key did not terminate the "
            "aggregator scan, so a foreign `needs:` entry was attributed to it.",
        )

    def test_ungated_job_in_each_required_workflow_is_caught(self):
        # THE 2026-08-10 finding, both halves. Before this fix the security-scan
        # half was invisible: a rogue job there left the whole suite green
        # (1952 passed) while it could fail forever without blocking a merge.
        texts = required_workflow_texts()
        rogue = (
            "  rogue-enforcement:\n"
            "    name: Rogue enforcement job\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: x\n"
            "        run: exit 1\n"
        )
        for fname in ("lint.yml", "security-scan.yml"):
            with self.subTest(workflow=fname):
                mutated = dict(texts)
                mutated[fname] = apply_mutation(
                    texts[fname], "jobs:\n", "jobs:\n" + rogue
                )
                aggregators, _ = required_aggregators(mutated)
                gate = aggregators[fname]
                needs = set(job_needs(job_block(mutated[fname], gate)))
                self.assertNotIn(
                    "rogue-enforcement",
                    needs,
                    "fixture error: the rogue job must NOT be in the aggregator's "
                    "needs, or this proves nothing",
                )
                self.assertIn(
                    "rogue-enforcement",
                    set(top_level_jobs(mutated[fname])) - needs,
                    f"not caught: an ungated job in {fname} was not detected",
                )

    def test_allowlist_is_file_scoped(self):
        # A flat name allowlist would let `lint-gate` exempt a same-named job in
        # any other required workflow. Keyed by file, it cannot.
        self.assertTrue(
            all(isinstance(e, tuple) and len(e) == 2 for e in UNGATED_JOBS_ALLOWLIST),
            "UNGATED_JOBS_ALLOWLIST entries must be (workflow, job) pairs",
        )
        self.assertNotIn(("security-scan.yml", "lint-gate"), UNGATED_JOBS_ALLOWLIST)


if __name__ == "__main__":
    unittest.main()
