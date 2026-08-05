"""
Regression guard: every marketplace plugin skill maps to a real CLI subcommand.

`.claude-plugin/marketplace.json` exposes the plugin's slash commands as
`skills[]`, each carrying a `command` like `npx claudesec <sub>`. When the plugin
is installed, invoking the skill shells out to that command. If a skill's `<sub>`
does not exist as a dispatch arm in `bin/claudesec-cli.sh` (the `claudesec` npm
bin), the slash command silently fails for every user with a "usage" fallback —
a published-surface break that no other check catches (the marketplace manifest
and the CLI live in separate files with no compile-time link).

This guards a two-way parity for the user-facing surface:

1. **Every marketplace skill resolves to a CLI subcommand.** Each `skills[].command`
   must be `npx claudesec <sub>` where `<sub>` is a real `case` arm in the CLI.
   Adding a skill that points at a non-existent (or typo'd) subcommand trips this.

2. **The `prowler` and `compliance` arms stay wired (issue #20).** These two were
   added as thin aliases over the scanner (`scan -c prowler` /
   `scan --compliance`); deleting either CLI arm while leaving its skill in the
   manifest would re-introduce exactly the silent break above. Pinned explicitly
   so a future CLI refactor cannot drop them unnoticed.

`marketplace.json` is JSON (stdlib `json`); the CLI is parsed with a regex over
its `case` arms — no PyYAML (absent from requirements-ci.txt), no network, no
subprocess. Does not import scanner/lib, so it never moves the coverage gate.
Passes under pytest (the CI runner) and `python3 -m unittest`.

OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control).
NIST SP 800-218 (SSDF) — PW.4.
"""

import json
import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
MARKETPLACE = REPO_ROOT / ".claude-plugin" / "marketplace.json"
CLI = REPO_ROOT / "bin" / "claudesec-cli.sh"

# Subcommands that MUST stay wired in the CLI (the #20 additions, plus the
# original trio). Each must be both a CLI arm AND present so the manifest skill
# resolves.
REQUIRED_SUBCOMMANDS = ("scan", "prowler", "compliance", "dashboard", "setup")


def cli_case_arms(text):
    """Subcommands dispatched by `bin/claudesec-cli.sh`.

    The CLI is a single `case "${1:-help}" in ... esac`. Each arm header looks
    like `  scan)` / `  help|--help|-h|*)`. We collect every bare-word token
    that precedes a `)` at an arm header, so `help|--help|-h|*` contributes
    `help` (flags and the `*` catch-all are not valid subcommand names and are
    ignored). Trailing inline `#` comments are irrelevant here (arm headers have
    none), but we still anchor to the start-of-line indented `word)` form so a
    `)` inside a string/body cannot be mistaken for an arm.

    Order matters: bash `case` is FIRST-MATCH-WINS, so any arm placed AFTER the
    `*` catch-all is unreachable dead code even though it is textually present.
    We collect only up to (and including) the top-level catch-all arm, so a real
    subcommand demoted below `*)` is correctly seen as NOT dispatched.

    Arms are scoped by `case`/`esac` nesting DEPTH (the top-level case is depth 1),
    NOT by indentation. bash decides arm membership by nesting, not indent, so an
    indent heuristic is bypassable: a top-level `*)` indented deeper than the first
    arm would be skipped by an indent filter, letting a subcommand demoted below it
    be wrongly counted as dispatched (ADR-001 §4 — model the grammar, not a proxy).
    """
    arms = set()
    depth = 0  # `case … in` opens a level; `esac` closes it. Top-level case == 1.
    for raw in text.splitlines():
        s = raw.strip()
        if re.match(r"^case\b.*\bin\b\s*(#.*)?$", s):
            depth += 1
            continue
        if re.match(r"^esac\b", s):
            depth -= 1
            continue
        if depth != 1:  # arms of a nested case are not CLI subcommands
            continue
        m = re.match(r"^\s{2,}([A-Za-z0-9_|*-]+)\)\s*$", raw)
        if not m:
            continue
        toks = m.group(1).split("|")
        for tok in toks:
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", tok):
                arms.add(tok)
        if "*" in toks:  # top-level catch-all: nothing after it is reachable
            break
    return arms


class TestPluginSkillsCliParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
        cls.cli_text = CLI.read_text(encoding="utf-8")
        cls.arms = cli_case_arms(cls.cli_text)
        cls.skills = cls.manifest["plugins"][0]["skills"]

    def test_files_exist(self):
        self.assertTrue(MARKETPLACE.is_file(), f"missing {MARKETPLACE}")
        self.assertTrue(CLI.is_file(), f"missing {CLI}")

    def test_cli_arms_parsed(self):
        # Canary: if the regex finds nothing, the parse broke — fail loudly
        # rather than vacuously passing the parity check below.
        self.assertTrue(self.arms, "no CLI case arms parsed — regex/path broke")

    def test_every_skill_resolves_to_cli_subcommand(self):
        for skill in self.skills:
            cmd = skill.get("command", "")
            with self.subTest(skill=skill.get("name"), command=cmd):
                m = re.fullmatch(r"npx claudesec (\S+)", cmd.strip())
                self.assertIsNotNone(
                    m,
                    f"skill {skill.get('name')!r} command {cmd!r} is not "
                    "'npx claudesec <sub>' — parity cannot be verified",
                )
                sub = m.group(1)
                self.assertIn(
                    sub,
                    self.arms,
                    f"skill {skill.get('name')!r} points at 'claudesec {sub}', "
                    "which has no dispatch arm in bin/claudesec-cli.sh — the "
                    "slash command would silently fall through to usage",
                )

    def test_required_subcommands_present(self):
        for sub in REQUIRED_SUBCOMMANDS:
            with self.subTest(subcommand=sub):
                self.assertIn(
                    sub,
                    self.arms,
                    f"CLI subcommand {sub!r} disappeared from bin/claudesec-cli.sh "
                    "— a published marketplace skill depends on it (issue #20)",
                )


class TestCliCaseArmsParserSelfTest(unittest.TestCase):
    """Mutation self-test for the first-match-wins parse of `cli_case_arms`."""

    _GOOD = (
        'case "${1:-help}" in\n'
        "  scan)\n    do_scan ;;\n"
        "  prowler)\n    do_prowler ;;\n"
        "  help|--help|-h|*)\n    usage ;;\n"
        "esac\n"
    )
    # `prowler)` demoted BELOW the `*)` catch-all: `claudesec prowler` would fall
    # through to usage — textually present but unreachable dead code.
    _ORDER_BLIND = (
        'case "${1:-help}" in\n'
        "  scan)\n    do_scan ;;\n"
        "  help|--help|-h|*)\n    usage ;;\n"
        "  prowler)\n    do_prowler ;;\n"
        "esac\n"
    )
    # Top-level `*)` catch-all indented DEEPER than the first arm. bash ignores
    # indentation — this IS a top-level catch-all (no nested `case` opened it), so
    # `prowler)` below it is unreachable. An indent-scoping parser skips the `*)`
    # (indent != base) and never breaks, wrongly collecting the dead `prowler`.
    _ORDER_BLIND_DEEP = (
        'case "${1:-help}" in\n'
        "  scan)\n    do_scan ;;\n"
        "    help|--help|-h|*)\n    usage ;;\n"   # 4-space indent, still top-level
        "  prowler)\n    do_prowler ;;\n"          # dead: bash matched `*)` first
        "esac\n"
    )
    # A nested case with its own BARE `*)` (on its own line, so it matches the
    # arm-header regex) must NOT end top-level collection early. This exercises the
    # case/esac depth scoping: the nested `*)` is at depth 2 and must be ignored.
    _NESTED = (
        'case "${1:-help}" in\n'
        "  scan)\n"
        '    case "$2" in\n'
        "      fast)\n        f ;;\n"
        "      *)\n        s ;;\n"                 # nested BARE catch-all (depth 2)
        "    esac\n    ;;\n"
        "  prowler)\n    do_prowler ;;\n"
        "  help|--help|-h|*)\n    usage ;;\n"
        "esac\n"
    )

    def test_good_collects_reachable_arms(self):
        self.assertEqual(cli_case_arms(self._GOOD), {"scan", "prowler", "help"})

    def test_arm_after_catch_all_is_unreachable(self):
        arms = cli_case_arms(self._ORDER_BLIND)
        self.assertNotIn(
            "prowler", arms,
            "Order-blind parse: `prowler)` placed AFTER the `*)` catch-all is "
            "unreachable but was collected — parity would pass on a dead arm.",
        )
        self.assertEqual(arms, {"scan", "help"})

    def test_deeper_indented_catch_all_still_ends_collection(self):
        # bash matches `*)` first regardless of indent, so `prowler)` after a
        # deeper-indented top-level `*)` is dead. An indent-scoping parser misses
        # this; case/esac depth scoping catches it.
        arms = cli_case_arms(self._ORDER_BLIND_DEEP)
        self.assertNotIn(
            "prowler", arms,
            "Order-blind (deeper-indent): a top-level `*)` indented deeper than the "
            "first arm still ends collection — `prowler)` below it is unreachable.",
        )
        self.assertEqual(arms, {"scan", "help"})

    def test_nested_case_default_does_not_truncate_top_level(self):
        # The nested BARE `*)` is at case-depth 2; top-level `prowler)` stays
        # reachable. A parser that breaks on ANY `*)` would lose `prowler` here.
        self.assertEqual(cli_case_arms(self._NESTED), {"scan", "prowler", "help"})


if __name__ == "__main__":
    unittest.main()
