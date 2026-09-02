"""
Regression guard: no `if:` condition may reference the `secrets` context.

WHY THIS IS NOT A STYLE RULE
---------------------------
`secrets` is not an available context in ANY `if:` — step level or job level.
GitHub rejects the file with `Unrecognized named-value: 'secrets'`, and at JOB
level that rejection takes the WHOLE workflow with it.

Measured 2026-09-02 with actionlint 1.7.12 on `templates/security-scan-suite.yml`:

    :70:13: context "secrets" is not allowed here.
      available contexts are "github", "inputs", "needs", "vars".

One `if:` on an *optional* Datadog job meant `codeql`, `semgrep`, `trivy`,
`gitleaks` and both `osv_scanner` jobs never ran either — a whole security suite
dark, shipped to adopters under a "copy it deliberately" header.
`templates/prowler.yml:96` carried the same expression at step level.

WHY `templates/` IS IN SCOPE AND WHY THAT IS THE POINT
------------------------------------------------------
`_ci_guard_util.workflow_and_action_files()` covers `.github/workflows/` plus
composite actions — NOT `templates/`. That is the #415/#417 class: `templates/`
ships executable workflows to other repositories and no guard read them, so a
defect there is invisible here AND propagates. This guard enumerates both trees
from `git ls-files` (never a filesystem walk — a gitignored local file would make
it red locally and green in CI, [[project-locale-default-encoding-class]]) and
keeps only files that actually declare `jobs:`, which is how a workflow is
distinguished from the `templates/*.example.yml` config files.

DIRECTION: forbidden-token presence. Any occurrence trips. A FORBIDDEN-token scan
can only over-report, which is a false alarm rather than a bypass (ADR-001 §1's
exemption) — but comments are stripped anyway, because the fix for this very
defect QUOTES the broken line in an explanatory comment and an unstripped scan
would flag the documentation.

The correct spellings, both used by the fix:
  - step level: map the secret into job `env:`, then test `env.X != ''`
  - job level:  `env` is not allowed there either, so gate the STEPS instead, or
    gate the job on `vars.*` / a `needs.<job>.outputs.*` flag.

stdlib-only (`re`, `subprocess`, `pathlib`) — no PyYAML.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF PO.3.
"""

import re
import subprocess
import unittest
from pathlib import Path

from _ci_guard_util import key_line, strip_comment_lines

REPO_ROOT = Path(__file__).resolve().parents[2]

# Trees whose YAML GitHub Actions executes — here, or in an adopter's repo.
WORKFLOW_PREFIXES = (".github/workflows/", "templates/")

_SECRETS_RE = re.compile(r"\bsecrets\s*\.")


def workflow_files():
    """Tracked `*.yml`/`*.yaml` under the workflow trees that declare `jobs:`.

    `git ls-files` rather than a filesystem walk, and the `jobs:` filter rather
    than a hand-written name list — both because a hand-maintained enumeration
    is the thing that silently stops covering new files
    ([[feedback-enumerate-with-ast]], #501)."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.yml", "*.yaml"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    files = []
    for rel in filter(None, out.split("\0")):
        if not rel.startswith(WORKFLOW_PREFIXES):
            continue
        path = REPO_ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            # Unreadable is a FINDING, not a skip — surfaced by returning it so
            # the caller's scan raises rather than quietly covering one less file.
            files.append((rel, ""))
            continue
        if re.search(r"(?m)^jobs\s*:\s*$", text):
            files.append((rel, text))
    return sorted(files)


def secrets_in_if(text):
    """Every `if:` whose expression mentions `secrets.`, as (line_no, line).

    Handles the block/folded forms (`if: >-` and friends) by consuming the more
    deeply indented continuation lines, so an expression wrapped onto the next
    line is not invisible to a single-line scan."""
    findings = []
    lines = strip_comment_lines(text).splitlines()
    i = 0
    while i < len(lines):
        parsed = key_line(lines[i])
        if not parsed or parsed[1] != "if":
            i += 1
            continue
        col, _, rest = parsed
        expr, start = rest, i
        if rest.strip().startswith((">", "|")):
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= col:
                    break
                expr += "\n" + nxt
                j += 1
            i = j
        else:
            i += 1
        if _SECRETS_RE.search(expr):
            findings.append((start + 1, lines[start].strip()))
    return findings


class TestScanIsNotVacuous(unittest.TestCase):
    """Canaries. Every assertion below passes trivially on an empty file list."""

    def test_enough_workflow_files_are_found(self):
        files = workflow_files()
        self.assertGreaterEqual(
            len(files),
            15,
            "the workflow enumeration collapsed — a `git ls-files` or `jobs:` "
            f"assumption broke. Found {len(files)}: "
            f"{[rel for rel, _ in files]}",
        )

    def test_both_trees_are_covered(self):
        rels = [rel for rel, _ in workflow_files()]
        for prefix in WORKFLOW_PREFIXES:
            self.assertTrue(
                any(r.startswith(prefix) for r in rels),
                f"no workflow files found under {prefix!r}. `templates/` being "
                "empty here is the #415/#417 gap this guard exists to close.",
            )

    def test_every_file_is_readable(self):
        empty = [rel for rel, text in workflow_files() if not text]
        self.assertEqual(
            empty, [], f"workflow file(s) could not be decoded: {empty}"
        )

    def test_the_detector_finds_a_planted_reference(self):
        planted = (
            "jobs:\n"
            "  a:\n"
            "    if: ${{ secrets.TOKEN != '' }}\n"
            "    steps:\n"
            "      - run: true\n"
        )
        self.assertTrue(
            secrets_in_if(planted),
            "the detector missed a plain job-level `secrets` reference — every "
            "clean result below would be void",
        )

    def test_the_detector_ignores_legitimate_secrets_use(self):
        """`secrets` in `with:`/`env:` is CORRECT and must not be flagged."""
        fine = (
            "jobs:\n"
            "  a:\n"
            "    env:\n"
            "      TOKEN: ${{ secrets.TOKEN }}\n"
            "    steps:\n"
            "      - uses: some/action@v1\n"
            "        with:\n"
            "          token: ${{ secrets.TOKEN }}\n"
            "        if: ${{ env.TOKEN != '' }}\n"
        )
        self.assertEqual(secrets_in_if(fine), [])


class TestNoSecretsInIf(unittest.TestCase):
    def test_no_workflow_conditions_reference_secrets(self):
        violations = []
        for rel, text in workflow_files():
            for line_no, line in secrets_in_if(text):
                violations.append(f"{rel}:{line_no}: {line}")
        self.assertEqual(
            violations,
            [],
            "`secrets` is not an available context in ANY `if:`. GitHub rejects "
            "the file with `Unrecognized named-value: 'secrets'`, and at JOB "
            "level that kills the WHOLE workflow — every other job in it too.\n  "
            + "\n  ".join(violations)
            + "\nFix: map the secret into job `env:` and test `env.X != ''` in a "
            "STEP `if:`. A JOB `if:` allows neither `secrets` nor `env`, so "
            "gate its steps instead, or use `vars.*` / "
            "`needs.<job>.outputs.*`.",
        )


class TestGuardIsNonVacuousOnRealFiles(unittest.TestCase):
    """The mutation drives the REAL detector against a REAL file (#504)."""

    def test_reintroducing_the_defect_is_caught(self):
        target = "templates/security-scan-suite.yml"
        text = (REPO_ROOT / target).read_text(encoding="utf-8")
        anchor = "    if: ${{ env.DD_API_KEY != '' && env.DD_APP_KEY != '' }}"
        # The fix moved the gate to the steps, so mutate the step-level spelling
        # back to `secrets` wherever it now lives.
        mutant, n = re.subn(
            r"if: \$\{\{ env\.DD_API_KEY != '' && env\.DD_APP_KEY != '' \}\}",
            "if: ${{ secrets.DD_API_KEY != '' && secrets.DD_APP_KEY != '' }}",
            text,
            count=1,
        )
        self.assertEqual(
            n, 1, f"mutation fixture is stale: no `env.DD_*` `if:` in {target} "
            f"(looked for a line like {anchor.strip()!r})"
        )
        self.assertTrue(
            secrets_in_if(mutant),
            "the detector did NOT fire on the reintroduced defect — check that "
            "possibility FIRST, before assuming the guard has a gap",
        )

    def test_a_commented_out_reference_is_not_flagged(self):
        """The fix's own comment QUOTES the broken line; it must not trip."""
        text = (REPO_ROOT / "templates/security-scan-suite.yml").read_text(
            encoding="utf-8"
        )
        # Line-anchored to a COMMENT line on purpose, not `assertIn` over the raw
        # text: that is what I actually mean (the reference must live in a
        # comment), and a raw whole-file presence check is the inert-assertion
        # shape `test_ci_guard_assertion_scoping.py` rejects — it caught this
        # exact line on the first draft.
        self.assertRegex(
            text,
            r"(?m)^\s*#.*secrets\.DD_API_KEY",
            "expected the explanatory comment to quote the broken expression on "
            "a comment line — if it no longer does, this test proves nothing "
            "about comment stripping and should be updated or dropped",
        )
        self.assertEqual(
            secrets_in_if(text),
            [],
            "a `#`-commented `if:` example was flagged as a real violation",
        )


if __name__ == "__main__":
    unittest.main()
