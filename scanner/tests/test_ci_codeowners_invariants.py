"""
Regression guard: `.github/CODEOWNERS` must keep every security-sensitive path
pattern owned by at least one code owner (`@...`).

Background
----------
`main` branch protection uses `require_code_owner_reviews=true`. If a future
edit accidentally removes a pattern line (e.g. drops `Dockerfile*` or
`scanner/`) or leaves it with no owner, those paths would merge with NO
human code-owner review — a silent security regression with no visible build
failure. This guard locks that topology in.

The required-pattern set below was derived from `.github/CODEOWNERS` as it
stands at the time of authoring (PR test/ci-codeowners-invariants). Each entry
covers a security-sensitive surface:

  *                      — global default; if removed, ALL paths lose fallback ownership
  .github/workflows/     — CI pipeline; supply-chain attack surface (OWASP A08)
  .github/CODEOWNERS     — the file that enforces this very protection
  hooks/                 — Claude Code security hooks (least-privilege entrypoints)
  scanner/               — the scanner that runs in CI; a backdoor here is a supply-chain issue
  scripts/               — automation scripts with broad filesystem access
  templates/             — user-facing config templates; must be audited before release
  Dockerfile*            — container image; any change affects the runtime attack surface
  docker-compose*.yml    — service composition; port/mount changes affect attack surface

Mutation self-test
------------------
The `TestCodeownersInvariantsMutation` class constructs synthetic CODEOWNERS
strings and verifies:
- a string MISSING `Dockerfile*` is detected as failing
- a string with an OWNER-LESS pattern entry is detected as failing
- the real on-disk CODEOWNERS does NOT trigger either failure

stdlib-only (no PyYAML, no third-party deps). No network, no subprocess.
Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
CODEOWNERS = REPO_ROOT / ".github" / "CODEOWNERS"

# Security-sensitive path patterns that MUST be present in CODEOWNERS and MUST
# have at least one non-empty owner.  Raising or expanding this set is always
# allowed — do NOT remove entries without a documented rationale and a PR that
# revises the set here.
REQUIRED_PATTERNS = {
    "*",
    ".github/workflows/",
    ".github/CODEOWNERS",
    "hooks/",
    "scanner/",
    "scripts/",
    "templates/",
    "Dockerfile*",
    "docker-compose*.yml",
}

# Regex for a valid owner token: @handle or @org/team
_OWNER_RE = re.compile(r"@\S+")


def _parse_codeowners(text: str) -> dict:
    """Return {pattern: [owners]} for every non-comment, non-blank line."""
    result = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        pattern = parts[0]
        owners = [p for p in parts[1:] if _OWNER_RE.match(p)]
        result[pattern] = owners
    return result


def _missing_or_ownerless(text: str) -> list:
    """Return a list of problem descriptions for REQUIRED_PATTERNS violations."""
    entries = _parse_codeowners(text)
    problems = []
    for pattern in sorted(REQUIRED_PATTERNS):
        if pattern not in entries:
            problems.append(f"MISSING pattern: {pattern!r}")
        elif not entries[pattern]:
            problems.append(f"NO OWNER for pattern: {pattern!r}")
    return problems


class TestCodeownersInvariants(unittest.TestCase):
    """Guards that the on-disk CODEOWNERS satisfies all required-pattern invariants."""

    @classmethod
    def setUpClass(cls):
        cls.text = CODEOWNERS.read_text(encoding="utf-8") if CODEOWNERS.is_file() else ""

    def test_codeowners_file_exists(self):
        self.assertTrue(
            CODEOWNERS.is_file(),
            f".github/CODEOWNERS not found at {CODEOWNERS} — "
            "the file that enforces code-owner review for security-sensitive paths "
            "has been deleted.",
        )

    def test_all_required_patterns_present_and_owned(self):
        problems = _missing_or_ownerless(self.text)
        self.assertEqual(
            problems,
            [],
            "CODEOWNERS is missing required security-sensitive patterns or has "
            "owner-less entries.  Any of these allows the affected paths to merge "
            "without human code-owner review (require_code_owner_reviews=true "
            "only fires when a pattern matches AND has an owner):\n  "
            + "\n  ".join(problems)
            + "\n\nAdd the missing patterns back, or (if intentionally removing "
            "one) update REQUIRED_PATTERNS in this test with a justification.",
        )

    def test_global_default_owner_is_set(self):
        """The `*` pattern is special: it must have at least one owner."""
        entries = _parse_codeowners(self.text)
        self.assertIn("*", entries, "Global default pattern `*` is missing from CODEOWNERS")
        self.assertTrue(
            entries["*"],
            "Global default pattern `*` has no owner — all unmatched paths would "
            "have NO code-owner review requirement.",
        )


class TestCodeownersInvariantsMutation(unittest.TestCase):
    """Mutation self-tests: verify the detector fires on known-bad inputs
    and stays quiet on the known-good real file."""

    # Minimal valid CODEOWNERS (all required patterns, each with an owner)
    _GOOD = "\n".join(
        [
            "# comment",
            "* @Twodragon0",
            ".github/workflows/ @Twodragon0",
            ".github/CODEOWNERS @Twodragon0",
            "hooks/ @Twodragon0",
            "scanner/ @Twodragon0",
            "scripts/ @Twodragon0",
            "templates/ @Twodragon0",
            "Dockerfile* @Twodragon0",
            "docker-compose*.yml @Twodragon0",
        ]
    )

    def test_good_codeowners_has_no_problems(self):
        problems = _missing_or_ownerless(self._GOOD)
        self.assertEqual(
            problems,
            [],
            "Mutation self-test BROKEN: a known-good CODEOWNERS string triggered "
            "false positives:\n  " + "\n  ".join(problems),
        )

    def test_missing_dockerfile_pattern_is_detected(self):
        """Remove the Dockerfile* line — guard must fire."""
        mutant = "\n".join(
            line for line in self._GOOD.splitlines() if not line.startswith("Dockerfile*")
        )
        problems = _missing_or_ownerless(mutant)
        self.assertTrue(
            any("Dockerfile*" in p for p in problems),
            "Mutation self-test FAILED: removing 'Dockerfile*' from CODEOWNERS was "
            "NOT detected.  The guard is broken.",
        )

    def test_ownerless_pattern_is_detected(self):
        """Keep scanner/ but strip its owner — guard must fire."""
        mutant = self._GOOD.replace("scanner/ @Twodragon0", "scanner/")
        problems = _missing_or_ownerless(mutant)
        self.assertTrue(
            any("scanner/" in p for p in problems),
            "Mutation self-test FAILED: an owner-less 'scanner/' entry was NOT "
            "detected.  The guard is broken.",
        )

    def test_real_codeowners_has_no_problems(self):
        """The on-disk CODEOWNERS must pass cleanly (mirrors the live guard)."""
        if not CODEOWNERS.is_file():
            self.skipTest("CODEOWNERS not found — covered by TestCodeownersInvariants")
        text = CODEOWNERS.read_text(encoding="utf-8")
        problems = _missing_or_ownerless(text)
        self.assertEqual(
            problems,
            [],
            "The real .github/CODEOWNERS failed the mutation self-test validator:\n  "
            + "\n  ".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
