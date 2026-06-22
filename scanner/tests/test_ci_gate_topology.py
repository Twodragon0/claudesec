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
from glob import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    strip_inline_comment as _strip_comment,
    top_level_jobs,
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


class TestActionShaPinning(unittest.TestCase):
    def test_every_uses_is_sha_pinned(self):
        workflow_files = sorted(glob(str(WORKFLOW_DIR / "*.yml")))
        self.assertTrue(
            workflow_files,
            f"No workflow files found under {WORKFLOW_DIR} — path assumption broke",
        )
        violations = []
        for path in workflow_files:
            for lineno, raw in enumerate(
                Path(path).read_text(encoding="utf-8").splitlines(), start=1
            ):
                m = re.match(r"\s*-?\s*uses:\s*([^\s#]+)", _strip_comment(raw))
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


class TestLintGateNeedsCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def _lint_gate_needs(self):
        needs, in_gate, in_needs = [], False, False
        for raw in self.text.splitlines():
            if re.match(r"^  lint-gate:\s*$", raw):
                in_gate = True
                continue
            if in_gate:
                # leaving the lint-gate block (next top-level job) ends the scan
                if re.match(r"^  [A-Za-z0-9_-]+:\s*$", raw) and not re.match(
                    r"^    ", raw
                ):
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


if __name__ == "__main__":
    unittest.main()
