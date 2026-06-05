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
import unittest
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
LINT_YML = WORKFLOW_DIR / "lint.yml"

# Jobs in lint.yml intentionally NOT funnelled through the lint-gate aggregator.
# Keep this list TINY and justify every entry — it is the escape hatch the guard
# exists to police.
#
# - lint-gate: the aggregator itself (cannot depend on itself).
# - workflow-fork-guard: a standalone pull_request_target fork-guard audit. NOTE:
#   it is currently neither in lint-gate.needs nor a required status check, so a
#   red result does not block merges. This is flagged for review (see the PR that
#   added this test); if it should gate merges, add it to lint-gate.needs and
#   delete it from this allowlist.
UNGATED_JOBS_ALLOWLIST = {"lint-gate", "workflow-fork-guard"}


def _strip_comment(line: str) -> str:
    # Drop an inline "  # ..." comment without tripping on '#' inside a token.
    return re.sub(r"\s+#.*$", "", line)


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

    def _top_level_jobs(self):
        jobs, in_jobs = [], False
        for raw in self.text.splitlines():
            if re.match(r"^jobs:\s*$", raw):
                in_jobs = True
                continue
            if in_jobs:
                if re.match(r"^\S", raw):  # dedent back to a top-level key
                    break
                m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", _strip_comment(raw))
                if m:
                    jobs.append(m.group(1))
        return jobs

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
        jobs = set(self._top_level_jobs())
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
        jobs = set(self._top_level_jobs())
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


if __name__ == "__main__":
    unittest.main()
