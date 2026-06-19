"""
Regression guard: `.github/dependabot.yml` keeps its dependency-update coverage
and the load-bearing alpine version freeze.

Background
----------
Dependabot is ClaudeSec's supply-chain freshness control: it opens the PRs that
keep actions, npm, pip, and Docker base images current (OWASP CICD-SEC-3
Dependency Chain Abuse; NIST SSDF SP 800-218 PW.4). This guard protects two
things that would silently regress coverage if removed:

  1. **Ecosystem coverage** — all four ecosystems must stay declared:
     `github-actions`, `npm`, `pip`, `docker`. Deleting one stops that surface
     from ever receiving update PRs, so it quietly rots (no build failure — the
     scheduler just goes silent for that ecosystem).
  2. **Alpine version freeze** — the `docker` ecosystem must keep its `ignore`
     entry holding `alpine` on its current minor line by excluding
     `version-update:semver-minor` AND `version-update:semver-major`.
     This is incident-backed: an alpine minor bump changes the bundled Python
     (3.24 ships py3.14), and prowler 3.11.3 pins pydantic v1 which cannot run on
     py>3.12, so `prowler -v` crashes with a pydantic ConfigError. PR #220 proved
     the alpine 3.20->3.24 build is green but prowler is broken at runtime.
     Removing the freeze would let Dependabot propose the breaking bump; digest /
     patch rebuilds of 3.20 still flow.

This is DISTINCT from `test_ci_dependabot_automerge.py`, which guards the
`dependabot-auto-merge.yml` *workflow* (the pull_request_target auto-arm safety).
This guard protects the `.github/dependabot.yml` *config* (what gets updated).

Direction: presence (each ecosystem / freeze token must exist). Adding ecosystems
or tightening the freeze stays green; dropping coverage or loosening the freeze
trips the guard.

Mutation self-test
------------------
`TestDependabotConfigGuardMutation` builds a synthetic known-good config,
confirms it passes, then verifies each invariant is detected when removed, and
that the real on-disk config passes cleanly.

stdlib-only (no PyYAML — not in requirements-ci.txt). Substring checks. No
`scanner/lib` import (does not touch the 99% coverage gate). No network, no
subprocess. Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"

# Shared guard primitive (comment-stripping). Import as a top-level module so it
# resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import non_comment_lines  # noqa: E402

# Each ecosystem must stay declared, else that surface stops getting update PRs.
REQUIRED_ECOSYSTEMS = (
    'package-ecosystem: "github-actions"',
    'package-ecosystem: "npm"',
    'package-ecosystem: "pip"',
    'package-ecosystem: "docker"',
)

# The alpine freeze: holding alpine on its current minor line. All three tokens
# must be present (the dependency-name plus BOTH excluded update-types).
ALPINE_FREEZE_TOKENS = {
    "alpine_dependency": 'dependency-name: "alpine"',
    "freeze_minor": "version-update:semver-minor",
    "freeze_major": "version-update:semver-major",
}

# Schema sanity.
SCHEMA_VERSION = "version: 2"

# Co-location window (lines): the alpine dependency-name and BOTH excluded
# update-types must appear within this many lines of each other, i.e. inside one
# `ignore:` block — not scattered across unrelated blocks (sec-review DC-3).
FREEZE_WINDOW = 6


def _alpine_freeze_colocated(lines: list) -> bool:
    """True if an `alpine` dependency-name line is followed, within FREEZE_WINDOW
    lines, by BOTH excluded update-types (DC-3: the freeze must be one block)."""
    for i, line in enumerate(lines):
        if ALPINE_FREEZE_TOKENS["alpine_dependency"] in line:
            window = "\n".join(lines[i : i + FREEZE_WINDOW + 1])
            if (
                ALPINE_FREEZE_TOKENS["freeze_minor"] in window
                and ALPINE_FREEZE_TOKENS["freeze_major"] in window
            ):
                return True
    return False


def config_violations(text: str) -> list:
    lines = non_comment_lines(text)
    scan = "\n".join(lines)
    problems = []
    if SCHEMA_VERSION not in scan:
        problems.append(f"MISSING dependabot schema marker: {SCHEMA_VERSION!r}")
    for eco in REQUIRED_ECOSYSTEMS:
        if eco not in scan:
            problems.append(f"MISSING ecosystem coverage: {eco!r}")
    for name, tok in sorted(ALPINE_FREEZE_TOKENS.items()):
        if tok not in scan:
            problems.append(f"MISSING alpine-freeze token [{name}]: {tok!r}")
    # DC-3: all three freeze tokens present but NOT co-located in one ignore
    # block means the alpine freeze was moved/split and is no longer effective.
    if (
        all(tok in scan for tok in ALPINE_FREEZE_TOKENS.values())
        and not _alpine_freeze_colocated(lines)
    ):
        problems.append(
            "DC-3: alpine-freeze tokens are present but not co-located in a single "
            f"ignore block (within {FREEZE_WINDOW} lines) — the freeze may have "
            "been split across unrelated blocks and is no longer effective."
        )
    return problems


class TestDependabotConfigGuard(unittest.TestCase):
    """Guards the on-disk .github/dependabot.yml config."""

    @classmethod
    def setUpClass(cls):
        cls.text = DEPENDABOT.read_text(encoding="utf-8") if DEPENDABOT.is_file() else ""

    def test_config_exists(self):
        self.assertTrue(
            DEPENDABOT.is_file(),
            f"{DEPENDABOT} not found — Dependabot dependency-update coverage has "
            "been deleted or moved.",
        )

    def test_all_ecosystems_present(self):
        missing = [eco for eco in REQUIRED_ECOSYSTEMS if eco not in self.text]
        self.assertEqual(
            missing, [],
            "dependabot.yml dropped ecosystem coverage: "
            + ", ".join(missing)
            + " — that surface stops receiving update PRs and silently rots. "
            "Restore the entry, or update REQUIRED_ECOSYSTEMS with a rationale.",
        )

    def test_alpine_freeze_intact(self):
        missing = [
            f"{name}={tok!r}"
            for name, tok in sorted(ALPINE_FREEZE_TOKENS.items())
            if tok not in self.text
        ]
        self.assertEqual(
            missing, [],
            "The alpine version freeze weakened (missing: "
            + ", ".join(missing)
            + "). Without holding alpine on its current minor line, Dependabot "
            "could propose a bump that ships py3.14 and breaks prowler "
            "(pydantic v1, incident #220). Restore the ignore entry or update the "
            "guard once prowler supports py3.13+.",
        )

    def test_all_invariants_hold(self):
        problems = config_violations(self.text)
        self.assertEqual(
            problems, [],
            "dependabot.yml lost a supply-chain coverage/freeze invariant:\n  "
            + "\n  ".join(problems),
        )


class TestDependabotConfigGuardMutation(unittest.TestCase):
    """Mutation self-tests: the detector must fire on known-bad inputs and stay
    quiet on the known-good real config."""

    _GOOD = "\n".join(
        [
            "version: 2",
            "updates:",
            '  - package-ecosystem: "github-actions"',
            '  - package-ecosystem: "npm"',
            '  - package-ecosystem: "pip"',
            '  - package-ecosystem: "docker"',
            "    ignore:",
            '      - dependency-name: "alpine"',
            "        update-types:",
            '          - "version-update:semver-minor"',
            '          - "version-update:semver-major"',
        ]
    )

    def test_good_config_passes(self):
        self.assertEqual(
            config_violations(self._GOOD), [],
            "Mutation self-test BROKEN: a known-good config reported violations:\n  "
            + "\n  ".join(config_violations(self._GOOD)),
        )

    def test_dropping_an_ecosystem_is_detected(self):
        mutant = self._GOOD.replace('  - package-ecosystem: "docker"\n', "")
        self.assertTrue(
            any("docker" in p for p in config_violations(mutant)),
            "Mutation FAILED: dropping the docker ecosystem was NOT detected.",
        )

    def test_dropping_pip_is_detected(self):
        mutant = self._GOOD.replace('  - package-ecosystem: "pip"\n', "")
        self.assertTrue(
            any('"pip"' in p for p in config_violations(mutant)),
            "Mutation FAILED: dropping the pip ecosystem was NOT detected.",
        )

    def test_loosening_alpine_minor_freeze_is_detected(self):
        mutant = self._GOOD.replace(
            '          - "version-update:semver-minor"\n', ""
        )
        self.assertTrue(
            any("freeze_minor" in p for p in config_violations(mutant)),
            "Mutation FAILED: removing the semver-minor alpine freeze was NOT "
            "detected.",
        )

    def test_loosening_alpine_major_freeze_is_detected(self):
        # No trailing newline: semver-major is the last line of _GOOD.
        mutant = self._GOOD.replace(
            '          - "version-update:semver-major"', ""
        )
        self.assertTrue(
            any("freeze_major" in p for p in config_violations(mutant)),
            "Mutation FAILED: removing the semver-major alpine freeze was NOT "
            "detected.",
        )

    def test_removing_alpine_dependency_is_detected(self):
        mutant = self._GOOD.replace('      - dependency-name: "alpine"\n', "")
        self.assertTrue(
            any("alpine_dependency" in p for p in config_violations(mutant)),
            "Mutation FAILED: removing the alpine ignore entry was NOT detected.",
        )

    def test_commented_out_ecosystem_is_detected(self):
        # DC-2: an ecosystem present only in a comment must NOT satisfy the check.
        mutant = self._GOOD.replace(
            '  - package-ecosystem: "docker"',
            '  # - package-ecosystem: "docker"  (removed)',
        )
        self.assertTrue(
            any('"docker"' in p for p in config_violations(mutant)),
            "Mutation FAILED (DC-2): a commented-out docker ecosystem was NOT "
            "detected.",
        )

    def test_commented_alpine_freeze_is_detected(self):
        # DC-1: the freeze surviving only in a comment must NOT satisfy the check.
        mutant = self._GOOD.replace(
            '      - dependency-name: "alpine"',
            '      # - dependency-name: "alpine"  (freeze removed)',
        )
        self.assertTrue(
            any("alpine_dependency" in p for p in config_violations(mutant)),
            "Mutation FAILED (DC-1): a commented-out alpine freeze was NOT detected.",
        )

    def test_non_colocated_alpine_freeze_is_detected(self):
        # DC-3: alpine dependency-name in one block, the semver tokens in an
        # unrelated block far away — all three tokens present, freeze ineffective.
        mutant = "\n".join(
            [
                "version: 2",
                "updates:",
                '  - package-ecosystem: "github-actions"',
                '  - package-ecosystem: "npm"',
                '  - package-ecosystem: "pip"',
                '  - package-ecosystem: "docker"',
                "    ignore:",
                '      - dependency-name: "alpine"',
                "        update-types: []",
                "        # padding to push the semver tokens out of the window",
                "        a: 1",
                "        b: 2",
                "        c: 3",
                "        d: 4",
                "        e: 5",
                '      - dependency-name: "some-other-pkg"',
                "        update-types:",
                '          - "version-update:semver-minor"',
                '          - "version-update:semver-major"',
            ]
        )
        self.assertTrue(
            any("DC-3" in p for p in config_violations(mutant)),
            "Mutation FAILED (DC-3): a non-co-located (split) alpine freeze was "
            "NOT detected.",
        )

    def test_real_config_clean(self):
        if not DEPENDABOT.is_file():
            self.skipTest("config not found — covered by TestDependabotConfigGuard")
        problems = config_violations(DEPENDABOT.read_text(encoding="utf-8"))
        self.assertEqual(
            problems, [],
            "The real .github/dependabot.yml failed the invariant validator:\n  "
            + "\n  ".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
