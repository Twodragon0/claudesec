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

MUTATION SELF-TESTS
-------------------
A presence guard is the easiest kind to hold vacuously: `REQUIRED - jobs` is
empty both when every job is there and when the parser silently returns
everything. `test_parser_canary` covers only the second half, and only for one
key. `TestRequiredJobsDetectorMutation` therefore deletes each required job from
the REAL `lint.yml` text, one at a time, and asserts THAT job is the one
reported — so the check is proven to bite on the exact file it protects, not on
a synthetic fixture whose indentation might not match. It also pins the two
no-false-alarm directions (an unrelated extra job, a required job written with a
quoted key) that a stricter parser would break.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import job_block, top_level_jobs  # noqa: E402

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


def missing_required_jobs(text: str) -> set:
    """The required `lint.yml` jobs absent from `text`; empty when all present."""
    return REQUIRED_LINT_JOBS - set(top_level_jobs(text))


class TestRequiredLintJobsExist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""

    def test_lint_yml_exists(self):
        self.assertTrue(
            LINT_YML.is_file(),
            f"CI workflow not found at {LINT_YML} — path assumption broke",
        )

    def test_parser_canary(self):
        # If the job parser breaks, fail loudly here rather than vacuously
        # "finding" the required jobs missing (or present).
        jobs = set(top_level_jobs(self.text))
        self.assertIn(
            "lint-gate", jobs, "job parsing broke — 'lint-gate' aggregator not found"
        )

    def test_required_security_jobs_present(self):
        missing = missing_required_jobs(self.text)
        self.assertEqual(
            missing,
            set(),
            "Required security/enforcement job(s) missing from lint.yml — a "
            "control was deleted and CI would stay green:\n  "
            + ", ".join(sorted(missing))
            + "\nRestore the job(s), or (if intentionally retired) update "
            "REQUIRED_LINT_JOBS in this test with a justification.",
        )


class TestRequiredJobsDetectorMutation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LINT_YML.read_text(encoding="utf-8")

    def _without(self, job: str) -> str:
        """The real `lint.yml` with `job`'s whole block deleted — the shape a
        botched merge-conflict resolution leaves behind."""
        block = job_block(self.text, job)
        self.assertIsNotNone(
            block, f"could not isolate the `{job}` job block in the real lint.yml"
        )
        mutated = self.text.replace(block, "", 1)
        self.assertNotEqual(mutated, self.text, f"deleting `{job}` changed nothing")
        return mutated

    def test_each_required_job_is_individually_detected(self):
        # One job at a time: deleting `gitleaks` must report `gitleaks` and
        # nothing else. A detector keyed on the wrong job — or one that reports
        # the whole required set whenever anything is off — fails here.
        for job in sorted(REQUIRED_LINT_JOBS):
            with self.subTest(deleted=job):
                self.assertEqual(missing_required_jobs(self._without(job)), {job})

    def test_quiet_on_the_real_file(self):
        self.assertEqual(missing_required_jobs(self.text), set())

    def test_quiet_when_an_unrelated_job_is_added(self):
        # No-false-alarm: the direction is PRESENCE of a required set, never an
        # equality against the full job list, so adding a job is fine.
        mutated = self.text.replace(
            "jobs:\n", "jobs:\n  brand-new-helper:\n    runs-on: ubuntu-latest\n", 1
        )
        self.assertEqual(missing_required_jobs(mutated), set())

    def test_quiet_on_a_quoted_job_key(self):
        # `"gitleaks":` is the same key to any YAML parser. A bare-only job
        # matcher would report the job missing and send someone chasing a
        # control that is actually there — the false-alarm twin of the quoted-key
        # blindness that hit eight guards in #391/#393/#394.
        mutated = self.text.replace("\n  gitleaks:\n", '\n  "gitleaks":\n', 1)
        self.assertNotEqual(mutated, self.text, "quoted-key fixture did not apply")
        self.assertEqual(missing_required_jobs(mutated), set())

    def test_fires_on_a_job_demoted_to_a_comment(self):
        # Commenting a job out disables it exactly as deleting it does, and the
        # substring `gitleaks:` still appears in the file — so a raw-text
        # presence check would read green here.
        mutated = self.text.replace("\n  gitleaks:\n", "\n  # gitleaks:\n", 1)
        self.assertNotEqual(mutated, self.text, "comment fixture did not apply")
        self.assertEqual(missing_required_jobs(mutated), {"gitleaks"})


if __name__ == "__main__":
    unittest.main()
