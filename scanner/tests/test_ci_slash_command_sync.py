r"""
Regression guard: the slash commands README advertises must be the ones that
exist in `.claude/commands/`.

THE DRIFT WAS REAL AND UNGUARDED, measured 2026-09-21 on `main`. README's
`Claude Code slash commands` block listed seven names. Four of them —
`/prowler`, `/compliance`, `/audit`, `/team-scan` — had no definition anywhere
in the repo, and five that DO exist (`/compliance-check`, `/hotfix`,
`/new-guide`, `/pipeline-review`, `/scanner-feature`) were unlisted. A reader
following the README typed four commands that do not exist and never learned
about five that do.

`/prowler` and `/compliance` were the interesting pair: `grep` found both in
`package.json`, which reads at a glance like a definition. They are npm
KEYWORDS. The CLI does have `npx claudesec prowler`, so the names are real —
just not as slash commands, which is exactly the confusion a list under the
heading "Claude Code slash commands" creates.

DIRECTION: EQUALITY, and the FILESYSTEM is authoritative. A command file is the
thing Claude Code actually loads; the README restates it. So adding a command
without listing it fails, and listing one that does not exist fails. Neither
direction is the "safe" one — an unlisted command is invisible, and a listed
non-existent one is a broken instruction.

WHY THE MARKDOWN REDUCTION IS USED DIFFERENTLY HERE
`rendered_markdown` removes fenced code among its four evasions, and this list
LIVES in a fence — reducing before searching would delete the subject and make
every run read as "block missing". So the two steps are split, and each gets the
text it can actually judge:

  - the section MARKER is checked against the reduced text, so a heading hidden
    in a closed comment or after an unterminated `<!--` cannot silently take the
    whole block out of scope;
  - the command names are then read from the RAW fence, because that is where
    they are and a browser shows them there.

Checking the marker against raw text instead would let someone comment out the
whole section and keep this guard green over invisible content. Checking the
names against reduced text would find nothing, ever.

SCOPE: bounded to the one section (ADR-001 §2). `/scan` also appears in the
`Options` block as `npx claudesec scan`, and command-looking tokens appear in
prose elsewhere; an unscoped search would collect those and report phantom
commands.

CONSTRAINTS (same as every guard in this directory)
---------------------------------------------------
stdlib-only (`re` + `pathlib` + the shared helpers). No PyYAML, no network, no
subprocess beyond the shared `tracked_files`. Does not import `scanner/lib`, so
it does not move the measured coverage gate. Passes under pytest and under
`python3 -m unittest`.

The command set comes from `tracked_files()`, never a filesystem glob: an
untracked local `.claude/commands/scratch.md` is not what CI builds from, and
scanning the disk would make the verdict depend on the machine
([[project-locale-default-encoding-class]]).

REACHABILITY: a PR adding a command touches `.claude/commands/**` and a PR
editing the list touches `README.md`; `[^/]*\.md$` puts the latter in the
`ci_config` bucket (`ci-guards`), and pytest runs this from the `scanner`
bucket. Verified against `lint.yml` rather than assumed.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF (SP 800-218) PO.3.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    apply_mutation,
    rendered_markdown,
    tracked_files,
)

README = REPO_ROOT / "README.md"
COMMANDS_PREFIX = ".claude/commands/"

#: The heading that opens the advertised list. Bold text rather than an ATX
#: heading, which is how the README writes it — pinned as a literal so a
#: rewording is a deliberate edit here and not a silently empty scope.
SECTION_MARKER = "**Claude Code slash commands**"

#: A line inside the block that advertises a command: `/name` at the start,
#: optionally followed by a `#` description.
_ADVERTISED_RE = re.compile(r"^/([a-z][a-z0-9-]*)\s*(?:#.*)?$", re.MULTILINE)


def command_files(paths=None) -> set:
    """Every slash command that exists, by name, from the git index."""
    return {
        Path(rel).stem
        for rel in (paths if paths is not None else tracked_files())
        if rel.startswith(COMMANDS_PREFIX) and rel.endswith(".md")
    }


def advertised_block(text: str):
    """The RAW fenced block under `SECTION_MARKER`, or None if not visible.

    Returns None when the marker is not present in the REDUCED text — i.e. when
    a reader would not see the section at all — so a commented-out heading fails
    loudly here instead of quietly narrowing the scope to nothing.
    """
    if SECTION_MARKER not in rendered_markdown(text):
        return None
    start = text.find(SECTION_MARKER)
    if start == -1:
        return None
    fence = re.search(r"^```[^\n]*\n(.*?)^```", text[start:], re.S | re.M)
    return fence.group(1) if fence else None


def advertised_commands(text: str) -> set:
    block = advertised_block(text)
    return set() if block is None else set(_ADVERTISED_RE.findall(block))


class TestInputsAreLocatable(unittest.TestCase):
    """Canaries. Every assertion below is vacuous on an empty set."""

    def test_readme_exists(self):
        self.assertTrue(README.is_file(), f"{README} not found")

    def test_the_section_is_still_findable(self):
        self.assertIsNotNone(
            advertised_block(README.read_text(encoding="utf-8")),
            f"the {SECTION_MARKER!r} section or its code fence is gone — if it "
            "was renamed, update SECTION_MARKER in the same commit; until then "
            "this guard is scoped to nothing.",
        )

    def test_at_least_one_command_exists_on_disk(self):
        self.assertGreater(
            len(command_files()), 0,
            f"no tracked `{COMMANDS_PREFIX}*.md` found — the enumeration "
            "collapsed, and the equality below would pass on two empty sets.",
        )


class TestReadmeMatchesTheCommandsOnDisk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = README.read_text(encoding="utf-8")

    def test_every_advertised_command_exists(self):
        missing = sorted(advertised_commands(self.text) - command_files())
        self.assertEqual(
            [], missing,
            "README advertises slash command(s) with no file in "
            f"`{COMMANDS_PREFIX}`, so a reader who types them gets nothing:\n  "
            + "\n  ".join("/" + m for m in missing)
            + "\nAdd the command file, or drop it from the list. If it is a CLI "
            "subcommand rather than a slash command, say so in prose instead — "
            "that mix-up is what this guard was written for.",
        )

    def test_every_command_on_disk_is_advertised(self):
        unlisted = sorted(command_files() - advertised_commands(self.text))
        self.assertEqual(
            [], unlisted,
            "command file(s) exist that README never mentions, so nobody "
            f"discovers them:\n  " + "\n  ".join("/" + m for m in unlisted)
            + f"\nAdd them to the {SECTION_MARKER!r} block.",
        )


class TestGuardIsNonVacuous(unittest.TestCase):
    """Mutations drive the REAL extractor against the REAL README (#504)."""

    @classmethod
    def setUpClass(cls):
        cls.text = README.read_text(encoding="utf-8")
        cls.real = advertised_commands(cls.text)

    def test_the_extractor_finds_the_live_list(self):
        """Positive control. Without it every absence below is satisfiable by
        an extractor that returns nothing at all."""
        self.assertGreaterEqual(
            len(self.real), 4,
            f"the extractor found {sorted(self.real)} — too few to be the real "
            "list, so the mutation cases beneath prove nothing",
        )

    def test_advertising_a_nonexistent_command_is_caught(self):
        mutant = apply_mutation(self.text, "/scan ", "/not-a-real-command ")
        found = advertised_commands(mutant) - command_files()
        self.assertIn("not-a-real-command", found)

    def test_deleting_a_line_makes_its_command_unlisted(self):
        line = [
            m for m in self.text.splitlines() if m.startswith("/security-review")
        ]
        self.assertEqual(1, len(line), "fixture stale: expected one such line")
        mutant = apply_mutation(self.text, line[0] + "\n", "")
        self.assertIn(
            "security-review", command_files() - advertised_commands(mutant)
        )

    def test_a_commented_out_section_fails_rather_than_scoping_to_nothing(self):
        """The shape the split reduction exists for.

        Wrapping the heading in an HTML comment removes the section from what a
        reader sees. A guard that located the marker in RAW text would carry on
        happily against invisible content; this must report the block as gone.
        """
        mutant = apply_mutation(
            self.text, SECTION_MARKER, f"<!-- {SECTION_MARKER} -->"
        )
        self.assertIsNone(advertised_block(mutant))
        self.assertEqual(set(), advertised_commands(mutant))

    def test_an_unterminated_comment_opener_also_hides_it(self):
        mutant = apply_mutation(
            self.text, SECTION_MARKER, f"<!--\n{SECTION_MARKER}"
        )
        self.assertIsNone(advertised_block(mutant))

    def test_prose_outside_the_block_is_not_collected(self):
        """SCOPE. `npx claudesec scan` and other command-shaped text live
        elsewhere in this README; collecting them would invent commands."""
        mutant = apply_mutation(
            self.text,
            "Dashboard serves at",
            "/phantom-command\n\nDashboard serves at",
        )
        self.assertNotIn("phantom-command", advertised_commands(mutant))


if __name__ == "__main__":
    unittest.main()
