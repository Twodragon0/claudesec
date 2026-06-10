"""
Regression guards for the npm release workflow `.github/workflows/npm-publish.yml`.

Two supply-chain invariants, both silently weakenable:

1. **SLSA provenance** — every `npm publish` invocation must pass `--provenance`.
   This is the whole point of the workflow (OIDC trusted-publisher + SLSA
   attestation). Dropping `--provenance` still publishes successfully, so the
   regression is invisible: packages ship WITHOUT attestation and nobody sees a
   failure. Plausible incident: a "fix the failing publish" commit removes the
   flag. (OWASP A08 Software & Data Integrity Failures; SLSA provenance.)

2. **Least-privilege default token** — the workflow-level `permissions:` block
   must stay `contents: read`. Broadening it (e.g. `write-all`) silently grants
   the release workflow extra scope across all jobs. The `publish` job legitimately
   ADDS `id-token: write` at the JOB level (required for OIDC provenance); this
   guard inspects only the top-level block, so that job-level grant is not flagged.

Semantics: PRESENCE for the flag; the permissions block must contain
`contents: read` and no `write` grant. If you intentionally change either, update
this guard in the same PR and justify it.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib.

Scope note: action SHA-pinning for this file is already covered by
test_ci_gate_topology.py (it globs all workflows) — NOT duplicated here.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
NPM_PUBLISH = REPO_ROOT / ".github" / "workflows" / "npm-publish.yml"


def _strip_comment(line: str) -> str:
    return re.sub(r"\s+#.*$", "", line)


class TestNpmPublishProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            NPM_PUBLISH.read_text(encoding="utf-8") if NPM_PUBLISH.is_file() else ""
        )

    def test_npm_publish_yml_exists(self):
        self.assertTrue(NPM_PUBLISH.is_file(), f"{NPM_PUBLISH} not found")

    def test_every_npm_publish_has_provenance(self):
        # Match `npm publish ...` run lines (ignore inline comments). Both the
        # dry-run and the real publish step must carry --provenance.
        publish_lines = [
            line.strip()
            for line in self.text.splitlines()
            if re.search(r"\bnpm\s+publish\b", _strip_comment(line))
        ]
        self.assertTrue(
            publish_lines,
            "No `npm publish` invocation found in npm-publish.yml — the publish "
            "step was removed or renamed.",
        )
        missing = [ln for ln in publish_lines if "--provenance" not in ln]
        self.assertEqual(
            missing,
            [],
            "`npm publish` without `--provenance` (packages would ship without "
            "SLSA attestation, silently):\n  " + "\n  ".join(missing),
        )


class TestNpmPublishLeastPrivilege(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            NPM_PUBLISH.read_text(encoding="utf-8") if NPM_PUBLISH.is_file() else ""
        )

    def _top_level_permissions_block(self):
        # Capture the WORKFLOW-level `permissions:` block: from a column-0
        # `permissions:` header to the next column-0 top-level key (jobs:, etc.).
        # Job-level permissions live under `jobs:` and are NOT captured here.
        out, in_perms = [], False
        for raw in self.text.splitlines():
            if re.match(r"^permissions:\s*$", raw):
                in_perms = True
                continue
            if in_perms:
                if re.match(r"^\S", raw):  # dedent to next top-level key
                    break
                out.append(raw)
        return "\n".join(out)

    def test_top_level_permissions_is_least_privilege(self):
        block = self._top_level_permissions_block()
        self.assertTrue(
            block.strip(),
            "No workflow-level `permissions:` block found in npm-publish.yml — the "
            "least-privilege default was removed (GITHUB_TOKEN would fall back to "
            "broad default scopes).",
        )
        self.assertRegex(
            block,
            r"^\s*contents:\s*read\s*$",
            "Workflow-level permissions must keep `contents: read`.",
        )
        write_grants = [
            ln.strip()
            for ln in block.splitlines()
            if re.search(r":\s*write\b", _strip_comment(ln))
        ]
        self.assertEqual(
            write_grants,
            [],
            "Workflow-level `permissions:` was broadened with a write grant "
            "(least-privilege regression — keep it `contents: read`; job-level "
            "`id-token: write` belongs under the publish job, not here):\n  "
            + "\n  ".join(write_grants),
        )


if __name__ == "__main__":
    unittest.main()
