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
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    explicit_key_lines,
    strip_inline_comment as _strip_comment,
    workflow_and_action_files,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# CodeQL *analysis* sub-actions that constitute a repo-level model. `upload-sarif`
# is deliberately excluded — it only publishes third-party SARIF.
# The `uses:` key is read bare OR quoted — `"uses": github/codeql-action/init@…`
# resolves identically and slipped past the bare-only regex, letting a second
# CodeQL model in with this guard green (2026-08-06 sweep). See yaml_key_pattern.
ANALYSIS_ACTION_RE = re.compile(
    rf"{yaml_key_pattern('uses')}:\s*[\"']?github/codeql-action/(init|analyze)"
    r"(?:[/@]|\s|$)"
)


class TestCodeqlSingleModel(unittest.TestCase):
    def test_workflow_dir_exists(self):
        self.assertTrue(
            WORKFLOW_DIR.is_dir(),
            f"Workflow dir not found at {WORKFLOW_DIR} — path assumption broke",
        )

    def test_no_repo_level_codeql_analysis(self):
        # Workflows in BOTH extensions plus composite actions: a `codeql.yaml`
        # or a composite `action.yml` invoking `codeql-action/init` is just as
        # much a second model, and neither was enumerated before.
        workflow_files = workflow_and_action_files()
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


class TestCodeqlMatcherMutation(unittest.TestCase):
    """Non-vacuity for the 2026-08-06 sweep fix: a quoted `uses:` key and the
    explicit-key form must not smuggle a second CodeQL model past this guard."""

    def test_fires_on_quoted_uses_key(self):
        sha = "0" * 40
        for line in (
            f'      - "uses": github/codeql-action/init@{sha}',
            f"      - 'uses': github/codeql-action/analyze@{sha}",
            f"      - uses: github/codeql-action/init@{sha}",
        ):
            with self.subTest(line=line.strip()):
                self.assertTrue(
                    ANALYSIS_ACTION_RE.search(_strip_comment(line)),
                    "Mutation FAILED: a quoted `uses` key hid a CodeQL analysis "
                    "action, so a duplicate repo-level model would pass.",
                )

    def test_quiet_on_upload_sarif_and_comments(self):
        sha = "0" * 40
        for line in (
            f"      - uses: github/codeql-action/upload-sarif@{sha}",
            f"      # - uses: github/codeql-action/init@{sha}",
        ):
            with self.subTest(line=line.strip()):
                self.assertFalse(
                    ANALYSIS_ACTION_RE.search(_strip_comment(line)),
                    "False positive: `upload-sarif` (third-party SARIF publishing, "
                    "not analysis) or a commented-out line was flagged.",
                )

    def test_enumeration_covers_yaml_and_composite_actions(self):
        found = workflow_and_action_files()
        self.assertTrue(
            [p for p in found if "/actions/" in p],
            "Mutation FAILED: composite actions are not enumerated, so a "
            "`codeql-action/init` inside one would be invisible here.",
        )

    def test_tripwire_flags_explicit_uses_key(self):
        wf = "\n".join(
            ["jobs:", "  j:", "    steps:", "      - ? uses", "        : github/codeql-action/init@x"]
        )
        self.assertTrue(
            explicit_key_lines(wf, "uses"),
            "tripwire FAILED: `? uses` / `: codeql-action/init` was not flagged, and "
            "the analysis-action scan cannot read that value.",
        )


if __name__ == "__main__":
    unittest.main()
