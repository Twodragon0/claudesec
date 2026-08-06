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
    explicit_key_lines,
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
UNGATED_JOBS_ALLOWLIST = {"lint-gate"}


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


class TestLintGateNeedsCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def _lint_gate_needs(self):
        needs, in_gate, in_needs = [], False, False
        for raw in self.text.splitlines():
            if re.match(rf"^  {yaml_key_pattern('lint-gate')}:\s*$", raw):
                in_gate = True
                continue
            if in_gate:
                # Leaving the lint-gate block (next top-level job) ends the scan.
                # The sibling job key is matched bare OR quoted: a quoted
                # `"other-job":` would not terminate the scan, so that job's
                # `needs:` items would be slurped into lint-gate's list and could
                # satisfy the completeness check for jobs lint-gate does not
                # actually depend on.
                if re.match(
                    r"""^  (?:"[^"]+"|'[^']+'|[A-Za-z0-9_-]+):\s*$""", raw
                ) and not re.match(r"^    ", raw):
                    break
                if re.match(r"^    needs:\s*$", raw):
                    in_needs = True
                    continue
                if in_needs:
                    item = re.match(r"^      -\s*([A-Za-z0-9_-]+)\s*$", raw)
                    if item:
                        needs.append(item.group(1))
                    elif re.match(r"^    [A-Za-z]", raw):  # next key under lint-gate
                        in_needs = False
        return needs

    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_every_job_is_gated_or_allowlisted(self):
        jobs = set(top_level_jobs(self.text))
        needs = set(self._lint_gate_needs())
        self.assertIn("changes", jobs, "job parsing broke — 'changes' not found")
        self.assertTrue(needs, "lint-gate.needs parsing broke — empty needs list")

        ungated = jobs - needs - UNGATED_JOBS_ALLOWLIST
        self.assertEqual(
            ungated,
            set(),
            "Job(s) not wired into lint-gate.needs and not allowlisted — they "
            "would NOT block a merge if they fail:\n  "
            + ", ".join(sorted(ungated))
            + "\nAdd each to lint-gate.needs, or (if intentionally ungated) to "
            "UNGATED_JOBS_ALLOWLIST in this test with a justification.",
        )

    def test_allowlist_has_no_stale_entries(self):
        # An allowlist entry that no longer names a real job (or that has since
        # been added to needs) is dead config — fail so it gets cleaned up.
        jobs = set(top_level_jobs(self.text))
        needs = set(self._lint_gate_needs())
        stale = {
            j
            for j in UNGATED_JOBS_ALLOWLIST
            if j not in jobs or (j in needs and j != "lint-gate")
        }
        self.assertEqual(
            stale,
            set(),
            "Stale UNGATED_JOBS_ALLOWLIST entries (job removed, or now in "
            "lint-gate.needs): " + ", ".join(sorted(stale)),
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

    def test_quoted_sibling_job_terminates_lint_gate_needs(self):
        # A quoted sibling job key must still end the lint-gate block, or that
        # job's `needs:` items get slurped into lint-gate's list and satisfy the
        # completeness check for dependencies lint-gate does not have.
        case = TestLintGateNeedsCompleteness("test_lint_yml_exists")
        case.text = "\n".join(
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
            case._lint_gate_needs(),
            ["changes"],
            "Mutation FAILED: a quoted sibling job key did not terminate the "
            "lint-gate scan, so a foreign `needs:` entry was attributed to it.",
        )


if __name__ == "__main__":
    unittest.main()
