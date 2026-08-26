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
from _ci_guard_util import strip_comment_lines  # noqa: E402

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

    def test_deleting_custom_rules_is_detected(self):
        doc = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))
        stripped = dict(doc)
        stripped["rules"] = []
        failures = self._judge(stripped)
        self.assertIn("rule-count", failures)
        self.assertIn("rule-ids", failures)


if __name__ == "__main__":
    unittest.main()
