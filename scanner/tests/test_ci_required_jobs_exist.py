"""
Regression guard: security/enforcement jobs in `.github/workflows/lint.yml`
must keep EXISTING.

`test_ci_gate_topology.py` proves that every job that *exists* in lint.yml is
wired into the `lint-gate` aggregator (so it blocks merges). But that check is
satisfied by the set of jobs that happen to be present: deleting a job entirely
shrinks `jobs` and the topology assertion stays green. So a refactor or a botched
merge-conflict resolution that DROPS a whole security job would silently disable
that control while CI stays green — exactly the silent-weakening class these
guards exist to catch (cf. project memory: "CI enforces secret hygiene with the
gitleaks job and the pii-check job"; workflow-fork-guard was made merge-blocking
in #203).

This guard asserts a documented set of load-bearing jobs is still PRESENT:

- `gitleaks`             — secret scanning (OWASP A07/secret hygiene)
- `pii-check`            — PII leakage scan
- `dependency-review`   — supply-chain gate (OWASP A08)
- `workflow-fork-guard` — `pull_request_target` fork guard (OWASP A08), #203
- `scanner-unit-tests`  — runs the entire `test_ci_*.py` guard suite; if this job
                          is dropped, NONE of the CI config guards execute
- `scanner-shell-coverage` — kcov bash coverage floor enforcement

Semantics are PRESENCE: removing any of these trips the guard. If a job is
intentionally renamed/retired, update REQUIRED_LINT_JOBS here in the same PR and
justify it. (Whether each present job is merge-blocking is the separate concern
of test_ci_gate_topology.py — NOT duplicated here.)

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

# Load-bearing security/enforcement jobs whose silent deletion would disable a
# control without any visible CI failure. Keep each entry justified (see module
# docstring). Edit ONLY in the same PR that intentionally renames/retires a job.
REQUIRED_LINT_JOBS = frozenset(
    {
        "gitleaks",
        "pii-check",
        "dependency-review",
        "workflow-fork-guard",
        "scanner-unit-tests",
        "scanner-shell-coverage",
    }
)


def _strip_comment(line: str) -> str:
    return re.sub(r"\s+#.*$", "", line)


class TestRequiredLintJobsExist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def _top_level_jobs(self):
        """Return the set of 2-space-indented job keys under `jobs:`."""
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
        return set(jobs)

    def test_lint_yml_exists(self):
        self.assertTrue(
            LINT_YML.is_file(),
            f"CI workflow not found at {LINT_YML} — path assumption broke",
        )

    def test_parser_canary(self):
        # If the job parser breaks, fail loudly here rather than vacuously
        # "finding" the required jobs missing (or present).
        jobs = self._top_level_jobs()
        self.assertIn(
            "lint-gate", jobs, "job parsing broke — 'lint-gate' aggregator not found"
        )

    def test_required_security_jobs_present(self):
        jobs = self._top_level_jobs()
        missing = REQUIRED_LINT_JOBS - jobs
        self.assertEqual(
            missing,
            set(),
            "Required security/enforcement job(s) missing from lint.yml — a "
            "control was deleted and CI would stay green:\n  "
            + ", ".join(sorted(missing))
            + "\nRestore the job(s), or (if intentionally retired) update "
            "REQUIRED_LINT_JOBS in this test with a justification.",
        )


if __name__ == "__main__":
    unittest.main()
