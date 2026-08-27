"""
Guard: `.gitleaks.toml` must EXTEND gitleaks' built-in ruleset, not replace it.

THE INCIDENT THIS CODIFIES (2026-08-26)
---------------------------------------
Defining `[[rules]]` in a gitleaks config makes gitleaks use ONLY those rules
unless the config also says `[extend] useDefault = true`. This config had ten
custom PII/vendor rules and no `[extend]` block, so the repository's primary
secret scanner had gitleaks' entire built-in ruleset (~170 rules) switched off.

Measured with `gitleaks dir` 8.30.1 on throwaway fixtures under $TMPDIR, values
fake and shapes NON-canonical — the AWS documentation example key
(`AKIA` + `IOSFODNN7EXAMPLE`) is allowlisted by scanners, and using it made the
first version of this measurement read "gitleaks misses everything", which was
the fixture's fault and not gitleaks':

    fixture                         default rules   config BEFORE   config AFTER
    AWS access key (AKIA + 16)        detected         MISSED         detected
    GitHub PAT (ghp_ + 36)            detected         MISSED         detected
    OPENSSH private key block         detected         MISSED         detected

So `Run gitleaks` was a required-adjacent job reporting green over a corpus it
was not really scanning for secrets. Restoring the defaults produced ZERO new
findings on the tracked tree (`git archive HEAD` export, which is what CI's
fresh checkout sees), so nothing was being suppressed for a reason.

WHY A GUARD
-----------
The failure mode is invisible by construction: the job runs, exits 0, and the
config looks deliberate — a list of rules with a maintained allowlist. Nothing
about a green `Run gitleaks` distinguishes "scanned and found nothing" from
"scanned with 6% of the rules". OWASP CICD-SEC-7 (Insecure System
Configuration); NIST SSDF (SP 800-218) PW.4.

DIRECTION
---------
- `useDefault` is asserted EXACTLY true — this is a boolean control, not a floor.
- The custom rule set is asserted as a FLOOR (`>=`) plus a spot-check of ids, so
  adding rules stays green while "fixing" a future finding by deleting the custom
  PII rules trips it. Both halves matter: the incident is a config that has one
  and not the other.
- The workflow must still pass `--config .gitleaks.toml`, or this file is inert
  regardless of what it says.
- The workflow must scan a RELATIVE root. Anchoring the allowlist made the scan
  root load-bearing: gitleaks reports each finding's path as the scan root joined
  with the relative path, so `^`-anchored entries only match when that root is
  `.`. Measured 2026-08-26 against a `git archive HEAD` export, same config:

      gitleaks dir .                    -> 0 findings   (what lint.yml does)
      gitleaks dir /tmp/gl-499-verify   -> 5 findings   (^ never matches)

  The five are the three files the allowlist names on purpose
  (`docs/guides/zscaler-zia-datadog.md` and two `scanner/tests/` fixtures), so an
  absolute root fails LOUD rather than silently un-suppressing — the opposite
  direction from the incident above. Pinned anyway: fail-loud still costs a red
  required-adjacent job and a re-read of the allowlist to diagnose, and the
  coupling is invisible from either file alone.

Parsed with `tomllib` (stdlib since 3.11; CI runs 3.11.16) rather than scanned
with regex. That is deliberate per ADR-001 §5 — model the grammar, do not proxy
it. It also means comments cannot satisfy any assertion here, so no
comment-stripping primitive is needed: a `#`-commented `useDefault = true` simply
is not in the parsed document. A regex version of this guard would have been
satisfiable by the very comment block that explains the incident.

stdlib-only (`tomllib`, `re`, `pathlib`, `unittest`). No PyYAML, no network, no
`scanner/lib` import. Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import re
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    non_comment_lines,
    strip_comment_lines,
    strip_inline_comment_sh,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

# Floor, not an equality: the config carried 10 custom rules when this guard was
# written and adding more is always fine.
MIN_CUSTOM_RULES = 10

# A few ids that must survive, so "fix the finding by deleting the rule" trips.
REQUIRED_RULE_IDS = frozenset(
    {
        "hardcoded-macos-user-path",
        "aws-account-id",
        "zscaler-credentials",
    }
)

# Scan roots under which the `^`-anchored allowlist entries still match. gitleaks
# joins this root onto each reported path, so anything else (an absolute path,
# `$GITHUB_WORKSPACE`, `"${{ github.workspace }}"`) breaks every `^` anchor at
# once. `.` is what lint.yml uses; `./` is the same directory spelled differently.
RELATIVE_SCAN_ROOTS = frozenset({".", "./"})


def gitleaks_scan_roots(yaml_text: str) -> list:
    """Every scan-root argument passed to `gitleaks dir` in `yaml_text`.

    Comment-stripped in BOTH forms before matching. `lint.yml` explains the
    subcommand in prose — "`gitleaks dir` is the v8.20+ replacement for the legacy
    `detect --no-git`" — so a whole-line-comment-only scan would read that
    sentence as an invocation. The shell-aware inline stripper covers the other
    half: these lines live inside a `run:` block, where bash starts a comment
    after a metacharacter with no intervening space.

    `finditer`, not `search`: a second `gitleaks dir` added elsewhere in the file
    must be checked too, not shadowed by the first one passing.
    """
    active = "\n".join(
        strip_inline_comment_sh(line) for line in non_comment_lines(yaml_text)
    )
    return [m.group(1) for m in re.finditer(r"gitleaks\s+dir\s+(\S+)", active)]


def absolute_scan_roots(yaml_text: str) -> list:
    """The `gitleaks dir` roots that would defeat the anchored allowlist."""
    return sorted(r for r in gitleaks_scan_roots(yaml_text) if r not in RELATIVE_SCAN_ROOTS)


class TestGitleaksExtendsDefaultRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (
            GITLEAKS_CONFIG.read_text(encoding="utf-8")
            if GITLEAKS_CONFIG.is_file()
            else ""
        )
        cls.doc = tomllib.loads(cls.raw) if cls.raw else {}

    def test_config_exists(self):
        self.assertTrue(
            GITLEAKS_CONFIG.is_file(),
            f"{GITLEAKS_CONFIG} not found — the `Run gitleaks` job passes "
            "`--config .gitleaks.toml`, so a missing file changes what CI scans.",
        )

    def test_config_parses(self):
        self.assertTrue(
            self.doc,
            ".gitleaks.toml did not parse into a non-empty document; gitleaks "
            "would fail or fall back, and every other assertion here is vacuous.",
        )

    def test_default_ruleset_is_extended(self):
        self.assertIs(
            self.doc.get("extend", {}).get("useDefault"),
            True,
            "`.gitleaks.toml` no longer sets `[extend] useDefault = true`. "
            "Defining `[[rules]]` without it makes gitleaks use ONLY the rules in "
            "this file and DROP its ~170 built-in rules — measured 2026-08-26, "
            "that state let an AWS access key, a GitHub PAT and an OPENSSH "
            "private key all pass `Run gitleaks` while the job reported green. "
            "If the custom rules are ever the only ones wanted, say so in the "
            "config and update this guard with the reason.",
        )

    def test_custom_rules_survive(self):
        rules = self.doc.get("rules", [])
        self.assertGreaterEqual(
            len(rules),
            MIN_CUSTOM_RULES,
            f"custom rule count dropped to {len(rules)} (floor "
            f"{MIN_CUSTOM_RULES}). These cover PII and vendor credentials the "
            "default ruleset does not; extending the defaults does not replace "
            "them. If a rule is genuinely obsolete, lower the floor here and say "
            "which and why.",
        )
        ids = {r.get("id") for r in rules}
        missing = sorted(REQUIRED_RULE_IDS - ids)
        self.assertEqual(
            missing,
            [],
            f"custom gitleaks rules removed: {missing}. Deleting a rule is the "
            "cheap way to make its finding go away; do that only with a stated "
            "reason and update REQUIRED_RULE_IDS in this guard.",
        )

    def test_allowlist_paths_are_anchored(self):
        r"""Every `[allowlist] paths` entry must be anchored.

        gitleaks matches these as UNANCHORED substrings of the path, so an entry
        naming a directory exempts every path that merely CONTAINS it. Measured
        2026-08-26 by planting a real-shaped GitHub PAT (fake value) against the
        pre-fix list: `docs/` also exempted `internal-docs/` and `prodocs/`,
        `templates/` also exempted `scanner/templates/`, and `README\.md`
        matched `myREADME.md` mid-string.

        Harmless while the default ruleset was off — nothing was detected to
        suppress — and load-bearing the moment `useDefault` turned it back on,
        which is why this lands with that change rather than after it.

        Direction: every entry anchored. Adding an exemption is fine; adding an
        unanchored one is not.
        """
        paths = self.doc.get("allowlist", {}).get("paths", [])
        self.assertTrue(paths, "`[allowlist] paths` is empty or missing")
        unanchored = [p for p in paths if not p.startswith(("^", "(^|/)"))]
        self.assertEqual(
            unanchored,
            [],
            "unanchored gitleaks allowlist path(s): "
            f"{unanchored}\n"
            "gitleaks substring-matches these, so each one also exempts every "
            "path that CONTAINS it. Anchor with `^` for a repo-root path or "
            "`(^|/)` for something that may appear at any depth.",
        )

    def test_workflow_still_passes_the_config(self):
        """Without `--config .gitleaks.toml` in the job, this file is inert.

        Scanned comment-stripped so the explanatory comments in `lint.yml` — which
        do mention the flag — cannot satisfy it.
        """
        if not LINT_YML.is_file():
            self.skipTest(f"{LINT_YML} not found")
        active = strip_comment_lines(LINT_YML.read_text(encoding="utf-8"))
        self.assertRegex(
            active,
            r"--config\s+\.gitleaks\.toml",
            "the `Run gitleaks` job no longer passes `--config .gitleaks.toml`, "
            "so neither the custom rules nor the allowlist in that file apply. "
            "Note the direction: dropping the flag RESTORES the default ruleset "
            "but LOSES the custom PII rules and the allowlist, so it is a "
            "different scan, not a stricter one.",
        )

    def test_workflow_scans_a_relative_root(self):
        """`gitleaks dir <root>` must use a relative root, or the `^` anchors die.

        See DIRECTION in the module docstring for the measurement. Two assertions,
        because either alone is vacuous: the root must EXIST (deleting the command
        leaves nothing non-relative to complain about) and it must be relative.
        """
        if not LINT_YML.is_file():
            self.skipTest(f"{LINT_YML} not found")
        raw = LINT_YML.read_text(encoding="utf-8")
        roots = gitleaks_scan_roots(raw)
        self.assertTrue(
            roots,
            "no `gitleaks dir <root>` invocation found in lint.yml outside of "
            "comments. Either the secret scan was removed, or it moved to a "
            "subcommand this guard does not know about (`gitleaks git`, which "
            "scans history and reports paths differently). Update this guard "
            "together with whatever replaced it.",
        )
        self.assertEqual(
            absolute_scan_roots(raw),
            [],
            f"`gitleaks dir` scan root(s) {absolute_scan_roots(raw)} are not "
            "relative. gitleaks joins the scan root onto every reported path, so "
            "the `^`-anchored `[allowlist] paths` in .gitleaks.toml stop matching "
            "and the three files that carry example credentials on purpose start "
            "failing CI (5 findings, measured 2026-08-26). Either keep the root "
            "`.` or re-anchor the allowlist to match the new root — the two are "
            "one decision, not two.",
        )


class TestGitleaksRulesetMutation(unittest.TestCase):
    """Mutation self-tests: the assertions must fail on the pre-fix config.

    Operates on parsed copies, never on the real file.
    """

    def _judge(self, doc):
        """Return the list of invariants that FAIL for `doc`."""
        failures = []
        if doc.get("extend", {}).get("useDefault") is not True:
            failures.append("useDefault")
        if len(doc.get("rules", [])) < MIN_CUSTOM_RULES:
            failures.append("rule-count")
        if REQUIRED_RULE_IDS - {r.get("id") for r in doc.get("rules", [])}:
            failures.append("rule-ids")
        return failures

    def test_real_config_passes_the_judge(self):
        doc = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(
            self._judge(doc),
            [],
            "MUTATION SELF-TEST BROKEN: the real .gitleaks.toml fails the judge, "
            "so the mutants below prove nothing.",
        )

    def test_pre_fix_shape_is_detected(self):
        """The exact shape the incident had: custom rules, no `[extend]`."""
        raw = GITLEAKS_CONFIG.read_text(encoding="utf-8")
        mutant = re.sub(
            r"(?m)^\[extend\]\s*\nuseDefault\s*=\s*true\s*\n", "", raw, count=1
        )
        self.assertNotEqual(
            mutant, raw, "mutation fixture is stale: the `[extend]` block moved"
        )
        self.assertIn(
            "useDefault",
            self._judge(tomllib.loads(mutant)),
            "MUTATION SELF-TEST FAILED: removing `[extend] useDefault = true` was "
            "NOT detected — the guard would not have caught the incident it exists "
            "for.",
        )

    def test_commented_out_extend_is_detected(self):
        """A `#`-commented `useDefault` must not satisfy the check.

        This is why the guard parses instead of matching text: the config's own
        comment block explains the incident and names the key, so a regex looking
        for `useDefault` would be satisfied by the explanation of why it matters.
        """
        raw = GITLEAKS_CONFIG.read_text(encoding="utf-8")
        mutant = re.sub(
            r"(?m)^\[extend\]\s*\nuseDefault\s*=\s*true\s*$",
            "# [extend]\n# useDefault = true",
            raw,
            count=1,
        )
        self.assertNotEqual(
            mutant, raw, "mutation fixture is stale: the `[extend]` block moved"
        )
        self.assertIn("useDefault", mutant, "fixture should still contain the token")
        self.assertIn(
            "useDefault",
            self._judge(tomllib.loads(mutant)),
            "MUTATION SELF-TEST FAILED: a commented-out `[extend]` block satisfied "
            "the check.",
        )

    def test_false_value_is_detected(self):
        raw = GITLEAKS_CONFIG.read_text(encoding="utf-8")
        mutant = raw.replace("useDefault = true", "useDefault = false", 1)
        self.assertNotEqual(mutant, raw, "mutation fixture is stale")
        self.assertIn(
            "useDefault",
            self._judge(tomllib.loads(mutant)),
            "MUTATION SELF-TEST FAILED: `useDefault = false` satisfied the check.",
        )

    def test_unanchored_allowlist_path_is_detected(self):
        raw = GITLEAKS_CONFIG.read_text(encoding="utf-8")
        mutant = raw.replace("\'\'\'^docs/guides/", "\'\'\'docs/guides/", 1)
        self.assertNotEqual(
            mutant, raw, "mutation fixture is stale: the anchored docs entry moved"
        )
        doc = tomllib.loads(mutant)
        paths = doc.get("allowlist", {}).get("paths", [])
        unanchored = [p for p in paths if not p.startswith(("^", "(^|/)"))]
        self.assertNotEqual(
            unanchored,
            [],
            "MUTATION SELF-TEST FAILED: an unanchored allowlist path was NOT "
            "detected.",
        )

    def test_deleting_custom_rules_is_detected(self):
        doc = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))
        stripped = dict(doc)
        stripped["rules"] = []
        failures = self._judge(stripped)
        self.assertIn("rule-count", failures)
        self.assertIn("rule-ids", failures)


class TestGitleaksScanRootMutation(unittest.TestCase):
    """Mutation self-tests for the scan-root detector. Parsed copies only."""

    @classmethod
    def setUpClass(cls):
        if not LINT_YML.is_file():
            raise unittest.SkipTest(f"{LINT_YML} not found")
        cls.clean = LINT_YML.read_text(encoding="utf-8")

    def test_absolute_root_is_detected(self):
        """`$GITHUB_WORKSPACE` is the realistic way this regresses.

        Someone hardening the checkout, or reusing the step in a composite action
        where `.` is not the repo root, reaches for the workspace variable. It is
        absolute at runtime, so every `^` anchor stops matching — the mutant
        genuinely disables the control, it does not merely change bytes.
        """
        mutant = apply_mutation(
            self.clean, "gitleaks dir . \\", 'gitleaks dir "$GITHUB_WORKSPACE" \\'
        )
        found = assert_disables(
            absolute_scan_roots, self.clean, mutant, label="absolute scan root"
        )
        self.assertEqual(found, ['"$GITHUB_WORKSPACE"'])

    def test_second_invocation_is_not_shadowed(self):
        """A bad root added ALONGSIDE the good one must still be caught.

        `re.search` would stop at the compliant first match and report clean.
        """
        mutant = apply_mutation(
            self.clean,
            "gitleaks dir . \\",
            "gitleaks dir . \\\n            --redact\n          gitleaks dir /srv/checkout \\",
        )
        found = assert_disables(
            absolute_scan_roots, self.clean, mutant, label="second invocation"
        )
        self.assertEqual(found, ["/srv/checkout"])

    def test_commented_invocation_does_not_satisfy_the_presence_check(self):
        """A `gitleaks dir` living only in a comment must not count as one.

        lint.yml's own prose names the subcommand, so this is the comment-evasion
        class biting the presence half rather than the anchor half.
        """
        self.assertEqual(
            gitleaks_scan_roots(
                "      # `gitleaks dir` is the v8.20+ replacement\n"
                "      run: echo no-scan-here\n"
            ),
            [],
            "a commented-out `gitleaks dir` satisfied the presence check, so "
            "deleting the real scan would read green.",
        )

    def test_inline_shell_comment_does_not_satisfy_the_presence_check(self):
        """`;#gitleaks dir .` never runs; the shell-aware stripper must drop it."""
        self.assertEqual(
            gitleaks_scan_roots("        run: |\n          true;#gitleaks dir .\n"),
            [],
            "an inline bash comment satisfied the presence check.",
        )

    def test_detector_sees_the_real_invocation(self):
        """Anti-tautology: the detector must actually find lint.yml's root.

        Without this, a `gitleaks_scan_roots` that returned `[]` for everything
        would pass every case above and the clean half of both mutation tests.
        """
        self.assertEqual(gitleaks_scan_roots(self.clean), ["."])


if __name__ == "__main__":
    unittest.main()
