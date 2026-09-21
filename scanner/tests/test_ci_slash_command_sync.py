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

WHY THE MARKDOWN REDUCTION IS BUILT BY HAND HERE
`rendered_markdown` removes fenced code among its four evasions, and this list
LIVES in a fence — reducing with it would delete the subject and make every run
read as "block missing". So this composes the two COMMENT primitives only:

    truncate_at_unclosed_html_comment(strip_html_comments(text))

Comments removed, fences kept. That is the reduction whose blind spot is not
this guard's subject.

A FIRST VERSION OF THIS GUARD WAS DEFEATED HERE, and the fix is the reason the
composition looks like this. It checked only the MARKER against
`rendered_markdown` and then read the names from RAW text. The marker is not the
subject, so hiding the FENCE while leaving the bold marker visible passed the
check and still returned all eight names. Measured on the real README against
the repo's browser oracle (markdown -> HTML -> consume comments; a containment
check over the HTML string says "visible" for both of these and is the mistake
that oracle exists to prevent):

    case                                       guard  /scanner-feature seen
    CLEAN (control)                                8  True
    unterminated `<!--` between marker and fence   8  False   <- FALSE GREEN
    fence wrapped in a closed `<!-- -->`           8  False   <- FALSE GREEN

Both assertions passed in both rows. Reducing the whole region instead — marker
AND fence together — is what closes it, because the subject is now inside what
gets reduced.

THE FENCE MUST OPEN IMMEDIATELY AFTER THE MARKER (blank lines aside). The first
version took "the next fence anywhere below", so deleting the intended fence
silently picked up the `Options` block further down and the canary that exists
to catch exactly that edit went on passing. Today those lines start with `npx`
so nothing was collected, but any later fence containing a `/name` line would
have been read as an advertised command.

RESIDUALS, both in the OVER-STRIP direction — a loud "block missing" failure,
never a silent pass. Enumerated because an unexplained disagreement between this
guard and a renderer is the thing the next audit has to re-derive:

  - a `<!--` written as SAMPLE CODE inside a fence above this section truncates
    the document here, because fences are deliberately not blanked first. The
    README has 28 fences of which 0 contain `<!--` (measured 2026-09-21).
  - commenting out the MARKER alone leaves the fence rendering, so a reader
    still sees the list while this reports it gone. Correct behaviour rather
    than a defect: without the heading there is nothing that identifies WHICH
    fence is the command list, and guessing is how the first version came to
    adopt the `Options` block.

Everything else agrees with the renderer, checked shape by shape:

    case                                      guard  reader sees list
    CLEAN (control)                               8  True
    unterminated `<!--` before the fence          0  False
    fence wrapped in a closed `<!-- -->`          0  False
    intended fence deleted                        0  False
    tilde fence instead of backticks              8  True

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
    strip_html_comments,
    tracked_files,
    truncate_at_unclosed_html_comment,
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


#: A fence opener, either flavour. `~~~` is accepted because a tilde fence
#: renders identically and a matcher that knew only backticks would skip past
#: one to some later block rather than read it.
_FENCE_OPEN_RE = re.compile(r"^(`{3,}|~{3,})[^\n]*$")


def comment_reduced(text: str) -> str:
    """`text` with HTML comments removed and FENCES LEFT INTACT.

    Not `rendered_markdown`: that blanks fenced code, which is where this
    guard's subject lives. See the module docstring for why the subject has to
    be inside whatever gets reduced.
    """
    return truncate_at_unclosed_html_comment(strip_html_comments(text))


def advertised_block(text: str):
    """The fenced block under `SECTION_MARKER`, or None if a reader loses it.

    Everything happens on the REDUCED text — marker AND fence — so a comment
    that swallows either one fails closed here rather than yielding names
    nobody can see.
    """
    reduced = comment_reduced(text)
    # Exactly one, not "at least one": `str.find` takes the first occurrence
    # while a presence check is satisfied by any, and those need not be the
    # same one. A duplicate marker is a document bug either way.
    if reduced.count(SECTION_MARKER) != 1:
        return None
    lines = reduced[reduced.index(SECTION_MARKER):].splitlines()
    i = 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines):
        return None
    opener = _FENCE_OPEN_RE.match(lines[i])
    if not opener:
        return None
    closer = opener.group(1)[0] * 3
    body = []
    for line in lines[i + 1:]:
        if line.startswith(closer):
            return "\n".join(body)
        body.append(line)
    return None  # unterminated fence: not a block a reader gets either


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

    def test_every_command_name_can_legally_be_advertised(self):
        """A filename the advertising pattern cannot express makes
        `test_every_command_on_disk_is_advertised` UNSATISFIABLE, and its
        message then tells the reader to do something impossible.

        `_ADVERTISED_RE` rejects uppercase, `_` and a digit-first name, so
        `Team_Scan.md` would be reported as unlisted forever — no README line
        can produce it. Fail here instead, where the fix is "rename the file".
        """
        inexpressible = sorted(
            n for n in command_files() if not _ADVERTISED_RE.fullmatch("/" + n)
        )
        self.assertEqual(
            [], inexpressible,
            "command file name(s) cannot be written as an advertised command "
            f"(`{_ADVERTISED_RE.pattern}`): {inexpressible}. Rename the file to "
            "lowercase-with-hyphens; do NOT widen the pattern without checking "
            "what else it would then collect from prose.",
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

    def test_deleting_the_fence_does_not_silently_adopt_a_LATER_one(self):
        """SCOPE, and the case the first version of this guard got wrong.

        Taking "the next fence anywhere below the marker" meant deleting the
        intended fence picked up the `Options` block instead, and the canary
        written to catch exactly that edit kept passing. It collected nothing
        only because those lines happen to start with `npx`; a `/name` line in
        any later fence would have been read as an advertised command.

        Both halves are asserted — that the block is reported GONE, and that a
        planted command in a later fence is not adopted — because the first is
        satisfiable by an extractor that broke for an unrelated reason.
        """
        start = self.text.index(SECTION_MARKER)
        fence_open = self.text.index("```", start)
        fence_close = self.text.index("```", fence_open + 3) + 3
        without_fence = self.text[:fence_open] + self.text[fence_close:]
        self.assertIsNone(advertised_block(without_fence))

        planted = apply_mutation(
            without_fence,
            "npx claudesec scan                      # Scan only",
            "/phantom-command                        # not a real command",
        )
        self.assertNotIn("phantom-command", advertised_commands(planted))

    def test_hiding_the_FENCE_is_caught_even_though_the_marker_survives(self):
        """The shape that defeated the first version of this guard.

        The marker is not the subject. Measured against the repo's browser
        oracle, both mutants below make the list invisible to a reader while
        the bold marker still renders — and the original, which reduced only
        the marker, returned all eight names and passed both assertions.
        """
        start = self.text.index(SECTION_MARKER)
        fence_open = self.text.index("```", start)
        fence_close = self.text.index("```", fence_open + 3) + 3

        between = (
            self.text[:fence_open] + "<!-- retiring this list\n" + self.text[fence_open:]
        )
        wrapped = (
            self.text[:fence_open]
            + "<!--\n"
            + self.text[fence_open:fence_close]
            + "\n-->"
            + self.text[fence_close:]
        )
        for label, mutant in (
            ("unterminated opener between marker and fence", between),
            ("fence wrapped in a closed comment", wrapped),
        ):
            with self.subTest(label):
                self.assertIn(
                    SECTION_MARKER, mutant,
                    "fixture stale: the marker must SURVIVE, or this tests the "
                    "old marker check rather than the new one",
                )
                self.assertEqual(
                    set(), advertised_commands(mutant),
                    f"{label}: the fence is hidden from a reader but its names "
                    "were still collected",
                )


if __name__ == "__main__":
    unittest.main()
