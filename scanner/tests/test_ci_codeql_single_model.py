"""
Regression guard: ClaudeSec keeps a SINGLE CodeQL model.

Project policy (CLAUDE.md / git-workflow rules): "Single CodeQL model:
repository default setup only — do not add a duplicate repo-level CodeQL
workflow file." GitHub's default setup runs CodeQL *analysis* without any
in-repo workflow; adding a workflow that runs CodeQL analysis creates a second,
conflicting model (duplicate runs, divergent config, wasted minutes).

A repo-level CodeQL ANALYSIS necessarily invokes the `github/codeql-action/init`
and/or `github/codeql-action/analyze` actions. This guard asserts NO workflow
file uses either.

IMPORTANT — `upload-sarif` is intentionally ALLOWED: `dast-full-scan.yml` uses
`github/codeql-action/upload-sarif` to publish ZAP/DAST SARIF results to the
Security tab. That is a third-party-result upload, not a CodeQL analysis, so it
does NOT create a duplicate model. The guard must match only `init`/`analyze`.

Semantics: PRESENCE-of-violation (the analysis actions must be ABSENT). If you
ever intentionally move from default setup to a workflow-based CodeQL model,
delete this guard in the same PR and document the decision.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib.
"""

import re
import unittest
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# CodeQL *analysis* sub-actions that constitute a repo-level model. `upload-sarif`
# is deliberately excluded — it only publishes third-party SARIF.
ANALYSIS_ACTION_RE = re.compile(
    r"uses:\s*github/codeql-action/(init|analyze)(?:[/@]|\s|$)"
)


def _strip_comment(line: str) -> str:
    return re.sub(r"\s+#.*$", "", line)


class TestCodeqlSingleModel(unittest.TestCase):
    def test_workflow_dir_exists(self):
        self.assertTrue(
            WORKFLOW_DIR.is_dir(),
            f"Workflow dir not found at {WORKFLOW_DIR} — path assumption broke",
        )

    def test_no_repo_level_codeql_analysis(self):
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
                if ANALYSIS_ACTION_RE.search(_strip_comment(raw)):
                    violations.append(f"{Path(path).name}:{lineno}: {raw.strip()}")
        self.assertEqual(
            violations,
            [],
            "Repo-level CodeQL analysis (init/analyze) found — this duplicates "
            "the repository default-setup CodeQL model (CLAUDE.md: single CodeQL "
            "model only). Remove the workflow, or if intentionally switching to a "
            "workflow-based model, delete this guard in the same PR:\n  "
            + "\n  ".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
