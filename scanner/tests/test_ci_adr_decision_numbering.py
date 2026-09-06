"""
Guard: every ADR's Decision numbers are STABLE, because the repo cites them by
number and a number is all a citation carries.

WHY THIS IS A CI INVARIANT AND NOT A STYLE PREFERENCE
-----------------------------------------------------
Guard docstrings, the catalog, the retrospectives and the authoring skill all cite
rules as `ADR-001 §N`. Inserting a decision in the middle of that list silently
re-points every citation at the wrong rule — no file changes, no test fails, and
the next reader is told a different thing than the author meant.

It already happened. On 2026-08-11 a sweep found **26** `ADR-001 §4` citations of
which **23 meant §5** ("Prefer a grammar-complete rule"), quoting its text
verbatim — "prefer a rule complete by construction over an incomplete
reassembler", "a third patch to an enumeration is a redesign signal", "model the
grammar, not a proxy". §4 is the mutation-self-test decision, and exactly two
citations meant it. The most plausible history is an item inserted above it, which
is the operation this guard now forces into the open.

"Into the open", not "blocks": the pin is one-sided. Renumbering the ADR while
reordering `DECISIONS_BY_ADR` in the SAME commit passes the whole suite (measured 2026-08-12
by in-memory mutation; the one-sided control — ADR renumbered, the pin untouched
— correctly fails `test_numbers_map_to_the_same_decisions`). The guarantee is that a
renumber cannot be a silent one-line edit: it must arrive as a lockstep diff through
this file, where a reviewer sees it. An APPEND without its `DECISIONS_BY_ADR` line does fail
outright, because `test_no_extra_or_missing_decisions` is a set equality.

The fix for that drift was to correct the citations, not to renumber the ADR back:
renumbering to satisfy one rule's citations would have broken §1/§2/§3/§6's.

WHY IT COVERS THE WHOLE SERIES AND NOT JUST ADR-001
---------------------------------------------------
It was written for ADR-001 because that was the only ADR. ADR-002 landed on
2026-09-04 with **zero** citations (measured on `378d09d`), which is the only
moment when widening this guard costs nothing: every future `ADR-002 §N` is born
inside the scan instead of being retro-fitted into it. The whole reason ADR-001
needed this guard is that its citations were counted for the first time at 81,
after the drift had already happened.

So the ADR set is DISCOVERED from `docs/devsecops/adr-[0-9]*.md` rather than
listed here, and an ADR on disk with no `DECISIONS_BY_ADR` entry FAILS. That is
the #501 lesson applied one level up: a hand-written source list drifts silently,
so the list of files is derived and only the PIN is hand-written.

TWO DECISION FORMS, AND WHY THE PARSE REFUSES AMBIGUITY
-------------------------------------------------------
ADR-001 writes its decisions as a numbered list (`1. **Title.**`); ADR-002 writes
them as headings (`### §N — Title`). Both are read, but an ADR that produces
items in BOTH forms parses to nothing and fails the vacuity canary rather than
silently picking one — a decision list read through the wrong matcher is a pin
over the wrong strings, which is worse than no pin. `## ` terminates the section
scan and `### ` does not, so a heading-form decision cannot escape the section.

The canary is PER ADR. A single repo-wide "did anything parse" check would let a
renamed heading in ADR-002 pass on ADR-001's nine items, which is exactly the
vacuity shape this suite exists to refuse.

`_CITE_RE` below matches only the `ADR-NNN §N` spelling — for ADR-001, 64 of the 81 live citations
on `d55c506`. The other 17 use `ADR §N`, `ADR-001 Decision N`, a bare `Decision N`,
or the tail of a `§N/§M` chain. The 2026-08-12 vintage sweep found all five citations
still carrying a pre-renumbering number in that remainder: four invisible outright,
and one (`ci-config-regression-guards.md:324`, `ADR-001 §1/§3`) on a line this scan
DOES match — it resolved the `§1` and never saw the `/§3`, so a chained citation
hides its tail from the only scanner that reads these. Widening the regex is not the
fix (a bare `Decision N` is unquotably common in prose); writing new citations in
the canonical anchored form, and spelling a pair out with the prefix REPEATED, is.
See "On citing this ADR".

DIRECTION
---------
PIN (`==`) on the mapping `number -> title`. Any of these fails:

- inserting a decision anywhere but the end (every later number shifts);
- renumbering, reordering, or deleting a decision;
- retitling one (the title is how a reader confirms a citation resolves, so a
  retitle is exactly as confusing as a renumber and gets the same review);
- a citation to a number that does not exist in the ADR it NAMES (so a number
  valid in one ADR still dangles when cited against another).

APPENDING is allowed and costs one line here. That is the point: it is a review
moment, not a silent re-pointing of sixty citations. When you append, add the entry
to `DECISIONS_BY_ADR` in the same commit.

Titles are matched by PREFIX, so rewording the body of a decision — or the tail of
a long title — does not trip this. Only the identity of the rule does.

stdlib-only, no PyYAML, no `scanner/lib` import. Passes under pytest and
`python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration) — the documented policy behind
the guards is part of the configuration.
"""

import re
import sys
import unittest
from glob import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    strip_code_fences,
    strip_html_blocks,
    strip_html_comments,
    truncate_at_unclosed_html_comment,
)

# The ADR series. `adr-index.md` is deliberately NOT matched: an index cites ADRs,
# it does not define decisions.
#
# The glob is DELIBERATELY wider than the convention: it matches any digit run,
# so an off-convention id is DISCOVERED and then fails
# `test_every_adr_id_is_three_digits` by name. Narrowing the glob to `[0-9][0-9]`
# `[0-9]` instead would make the same file invisible, which is the failure this
# whole discovery step exists to prevent. An earlier version of this comment
# claimed the glob 'covers adr-tools' 4-digit ids too' — it covers them for
# DISCOVERY only, and `_CITE_RE` can never see a 4-digit citation, so such an ADR
# would be pinned and permanently uncitable. Review walked that through; the
# guard now rejects it rather than advertising support for it.
ADR_GLOB = "docs/devsecops/adr-[0-9]*.md"

# No trailing hyphen. Written `adr-(\d+)-` it required a slug after the id, so
# `adr-005.md` and `adr-005_thing.md` matched the GLOB, failed this regex, and
# were dropped from the series in silence — an ADR whose numbers were then
# unpinned and unscanned while every test stayed green. Found by review, not by
# the suite, which is why `test_the_glob_and_the_id_regex_agree` now pins the two
# against each other: a derived list is only derived if nothing filters it
# invisibly afterwards (#501).
_ADR_FILE_RE = re.compile(r"adr-(\d+)")

# `adr id -> {number -> title prefix}`, pinned. Prefix match: reword the tail
# freely, but the rule a number denotes may not change without this line changing
# with it. An ADR on disk that is missing here fails `test_every_adr_is_pinned`,
# so adding ADR-003 costs one block and is a review moment.
DECISIONS_BY_ADR = {
    "001": {
        1: "Route every presence/regex check through the shared comment-stripping",
        2: "Scope the haystack before choosing a matcher.",
        3: "Two-pass adversarial review for any substring/parse guard before merge.",
        4: "Every detector ships a non-vacuous mutation self-test.",
        5: "Prefer a grammar-complete rule over enumerating forms.",
        6: "Run a periodic comprehensive adversarial audit",
        7: "The meta-guards are in audit scope, and are audited FIRST.",
        8: "Audit whether each guard RUNS, not only whether its logic is right.",
        9: "Route every BLOCK COLLECTOR through the shared block primitives",
    },
    "002": {
        1: "The base gate is two required contexts, strict mode, and",
        2: "`required_approving_review_count` stays 0 while exactly one account",
        3: "`require_code_owner_reviews` is ON, and this reverses",
        4: "`dismiss_stale_reviews` is false, and that is load-bearing",
        5: "The auto-arm surface is `pip`, patch/minor, with a known non-empty",
        6: "The hard-excludes are a control, and a control is proven by execution",
    },
}

# ADR-001 stays addressable by name: the spelling guard's real-file mutation test
# and several of its fixtures are specifically about it, and naming it there beats
# indexing into the dict at every call site.
#
# There is deliberately NO `DECISIONS` alias for `DECISIONS_BY_ADR["001"]`. The
# first draft kept one "for back-compat" and nothing read it, so the docstrings
# and the catalog went on routing readers to a dead name while every failure
# message named the live one.
ADR_REL = "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
ADR = REPO_ROOT / ADR_REL

# Form 1 (ADR-001): a numbered list item whose first line opens with `**`. The
# Context section also uses a numbered list, so items are collected only from the
# Decision section.
_ITEM_RE = re.compile(r"^(\d+)\.\s+\*\*(.+?)(?:\*\*|$)")

# Form 2 (ADR-002): a `### §N — Title` heading. `##` is excluded because it
# terminates the Decision section; the dash class covers em, en and hyphen.
_SECTION_RE = re.compile(r"^#{3,6}\s*§(\d+)\s*[—–-]\s*(.+?)\s*$")

_FORMS = (("list", _ITEM_RE), ("section", _SECTION_RE))

# The canonical citation spelling, now over the whole series. Group 1 is the ADR
# id, group 2 the decision number — a citation resolves against ITS OWN ADR, so a
# number that exists in one ADR is still dangling when cited against another.
#
# No DANGLING example citation is written in this file, deliberately — resolvable
# ones are written freely above, and stating the rule as 'no literal citation'
# was itself false in the file that said it. The first draft of this comment
# spelled a non-existent decision out and `test_every_citation_resolves` failed on
# it immediately: a guard's own prose is inside the population it scans, which is
# the same discipline `test_this_guard_declares_no_citations_of_its_own` enforces
# one file over.
_CITE_RE = re.compile(r"ADR-(\d{3}) §(\d+)")

# Where citations live. Kept broad on purpose: a dangling `§10` in any of these is
# as wrong as one in a guard.
_CITED_GLOBS = (
    "scanner/**/*.py",
    "docs/**/*.md",
    ".claude/**/*.md",
    "*.md",
)


def in_nested_checkout(path, root) -> bool:
    """True when `path` lives inside a git checkout nested under `root`.

    A linked worktree marks its root with a `.git` FILE (`gitdir: ...`), a
    vendored clone with a `.git` DIRECTORY — `Path.exists()` covers both. The
    walk stops at `root` itself, so the repo's own `.git` never matches.
    """
    root = Path(root)
    node = Path(path).parent
    while node != root and root in node.parents:
        if (node / ".git").exists():
            return True
        node = node.parent
    return False


def cited_paths() -> list:
    """Absolute paths of every file the citation scan reads — this repo's files only.

    `.claude/**/*.md` reaches into `.claude/worktrees/<id>/`, where the agent
    worktrees live. Those are gitignored checkouts of OTHER branches: scanning
    them made both ADR guards report citation errors for files the current
    commit does not contain, and the failure appeared ONLY on a developer's
    machine because a CI checkout has no worktrees. A guard that fails for a
    reason the tree cannot cause is a guard people learn to ignore.

    The rule is structural rather than a `.claude/worktrees/` path literal, so a
    checkout nested anywhere — a vendored clone, a worktree relocated by
    `OMC_STATE_DIR` — is excluded by construction (ADR-001 §5).

    Both guards enumerate through here. Sharing only the glob TUPLE was not
    enough: the two `glob()` loops were separate code, which is exactly where an
    exclusion added to one would fail to reach the other.
    """
    out = set()
    for pattern in _CITED_GLOBS:
        for path in glob(str(REPO_ROOT / pattern), recursive=True):
            if not in_nested_checkout(path, REPO_ROOT):
                out.add(path)
    return sorted(out)


def decision_section(text: str) -> str:
    """The text between the `## Decision` heading and the next `##` heading,
    with HTML comments and fenced code blocks blanked out first.

    THE STRIP IS THE CONTROL, not tidiness. Scanning raw text here UNDER-reports,
    which is the opposite of the spelling guard's situation: there a raw scan can
    only over-report (a false alarm a baseline line settles), so it deliberately
    reads raw. Here a decision "retired" by wrapping it in `<!-- -->` or in a
    fence still parsed, so the whole list looked intact and
    `test_no_extra_or_missing_decisions` passed — the exact deletion this guard's
    docstring promises to catch, going through green. Measured on a real edit to
    ADR-002 that removed a decision both ways: 92 passed, both times.

    The UNCLOSED opener needs its own step, and it must come LAST. The shared
    comment stripper deliberately leaves an unterminated `<!--` intact — right
    for a presence check, a silent pass here: an unclosed opener hides everything
    below it in the rendered document (measured on ADR-002: three decisions and
    the whole Consequences section) while this parse still saw every one of them,
    one character away from the closed form above.

    But truncating BEFORE fences are stripped is wrong in the other direction: a
    `<!--` shown as sample code inside a fence is not an HTML block to CommonMark,
    and truncating on it deleted decisions that render fine. Both orderings were
    adjudicated against `markdown-it-py` rather than argued, and the sequence
    below — closed comments, fences, then the unclosed opener — is the only one
    that matches the renderer on every case measured.

    The terminator is `^## ` OR END OF TEXT. With `^## ` alone, truncating at an
    unclosed opener also removed the `## Consequences` that ends the section, so
    the whole parse went empty and the failure read "nothing parsed" instead of
    naming the decisions that vanished. Both fail, but only one says what broke.

    Routed through `_ci_guard_util`'s block primitives rather than re-implemented
    (ADR-001 §9), and comment-stripped before matching (ADR-001 §1)."""
    clean = truncate_at_unclosed_html_comment(
        strip_html_blocks(strip_code_fences(strip_html_comments(text)))
    )
    m = re.search(r"^## Decision\s*$(.*?)(?=^## |\Z)", clean, re.M | re.S)
    return m.group(1) if m else ""


def decision_forms(text: str) -> dict:
    """`{form name: {number: title}}` for every form that produced items.

    Only column-0 items count in either form: a nested `1.` inside a decision's
    own body is indented, and a `9.` quoted in prose is not at the start of a
    line. An ADR normally populates exactly one key."""
    out = {}
    for name, pattern in _FORMS:
        items = {}
        for line in decision_section(text).splitlines():
            m = pattern.match(line)
            if m:
                items.setdefault(int(m.group(1)), m.group(2).strip())
        if items:
            out[name] = items
    return out


def parsed_decisions(text: str) -> dict:
    """`{number: title}` for the Decision list, or `{}` when the form is ambiguous.

    Refusing to choose is the point: an ADR whose Decision section produces items
    under BOTH matchers has no single numbering to pin, and picking one silently
    would pin the wrong strings. `{}` trips the per-ADR vacuity canary, so the
    ambiguity surfaces as a failure rather than as a green over half a list."""
    forms = decision_forms(text)
    return next(iter(forms.values())) if len(forms) == 1 else {}


def citation_numbers() -> dict:
    """`{(adr id, number): [file:line, ...]}` for every `ADR-NNN §N` in the repo."""
    out = {}
    for path in cited_paths():
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _CITE_RE.finditer(line):
                rel = p.relative_to(REPO_ROOT)
                key = (m.group(1), int(m.group(2)))
                out.setdefault(key, []).append(f"{rel}:{lineno}")
    return out


def adr_glob_paths() -> list:
    """Repo-relative paths of every `ADR_GLOB` match, nested checkouts excluded.

    Separate from `adr_files()` so the two can be COMPARED. The id regex used to
    be able to drop a glob match silently, and a discovery step that can lose a
    file without saying so is the failure `adr_files`'s own docstring claims it
    prevents."""
    return sorted(
        str(Path(path).relative_to(REPO_ROOT))
        for path in glob(str(REPO_ROOT / ADR_GLOB))
        if not in_nested_checkout(path, REPO_ROOT)
    )


def adr_files() -> dict:
    """`{adr id: relpath}` for every ADR on disk, nested checkouts excluded.

    Derived, not listed: a hand-written file list is the drift `_SOURCE_FILES`
    already demonstrated (#501), one level up from the pin it feeds."""
    out = {}
    for rel in adr_glob_paths():
        m = _ADR_FILE_RE.match(Path(rel).name)
        if m:
            out[m.group(1)] = rel
    return out


class TestAdrDecisionNumbering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.on_disk = adr_files()
        cls.text = {
            adr_id: (REPO_ROOT / rel).read_text(encoding="utf-8")
            for adr_id, rel in cls.on_disk.items()
        }
        cls.found = {
            adr_id: parsed_decisions(text) for adr_id, text in cls.text.items()
        }

    def test_adr_exists(self):
        self.assertTrue(ADR.is_file(), f"{ADR_REL} not found — path assumption broke")

    def test_the_series_is_discovered(self):
        # Canary for the glob itself: if it stops matching, every per-ADR loop
        # below iterates over nothing and passes for free.
        self.assertIn(
            "001",
            self.on_disk,
            f"`{ADR_GLOB}` matched no ADR-001 — the series glob broke: "
            f"{self.on_disk}",
        )

    def test_the_glob_and_the_id_regex_agree(self):
        # The fail-closed hinge of the whole discovery step, and the one the
        # first draft did NOT have: `test_every_adr_is_pinned` compares the
        # pinned set against `adr_files()`, so a file the ID REGEX dropped is
        # absent from BOTH sides and the comparison passes. Reviewed into
        # existence after `adr-005.md` (no slug after the id) was measured
        # invisible while all 90 tests stayed green.
        #
        # Equality of counts also catches a COLLISION — two files yielding the
        # same id, where the dict would keep one and lose the other just as
        # quietly.
        paths = adr_glob_paths()
        found = adr_files()
        self.assertEqual(
            len(found),
            len(paths),
            "the ADR glob and the id regex disagree: every "
            f"`{ADR_GLOB}` match must yield exactly one id, and two matches must "
            "not share one. matched: "
            f"{paths}, keyed: {found}",
        )

    def test_every_adr_id_is_three_digits(self):
        # `adr-index.md` documents the id as a zero-padded 3-digit number, and
        # `_CITE_RE` can only see exactly that. An `adr-0004-*.md` is therefore
        # DISCOVERABLE but permanently UNCITABLE: it would pin under the key
        # `0004`, while a citation written with three digits keys `004` and
        # dangles forever, and one written with four is invisible to the citation
        # scan entirely. Three id spellings in one system, and no test connected
        # them until review walked it through.
        #
        # (Written without a literal example on purpose. The first draft spelled
        # both citations out and `test_every_citation_resolves` failed on them —
        # the third time in this change that a guard caught its author's prose.)
        #
        # Failing here rather than normalising: the convention is the repo's, not
        # this guard's, so a file that breaks it should be renamed. Guard B's
        # four-digit tests are about DETECTING a four-digit CITATION as a
        # mis-spelling, which is the same position stated from the other side.
        bad = {i: rel for i, rel in self.on_disk.items() if not re.fullmatch(r"\d{3}", i)}
        self.assertEqual(
            bad,
            {},
            "ADR filenames must carry a zero-padded THREE-digit id, per "
            "`docs/devsecops/adr-index.md`, because that is the only id shape a "
            f"citation can be written in and be seen. Rename: {bad}",
        )

    def test_every_adr_is_pinned(self):
        # Fail-closed in the direction that matters: a NEW ADR is unpinned until
        # someone adds it here, so its numbers cannot start being cited outside
        # the scan. The reverse (a pinned id with no file) is a deleted ADR, which
        # is equally a review moment.
        self.assertEqual(
            sorted(self.on_disk),
            sorted(DECISIONS_BY_ADR),
            "the ADR series on disk and the pinned set disagree. Add the new "
            f"ADR's `{{number: title}}` block to DECISIONS_BY_ADR in the same "
            f"commit. on disk: {sorted(self.on_disk)}, pinned: "
            f"{sorted(DECISIONS_BY_ADR)}",
        )

    def test_decision_section_is_parsed(self):
        # Vacuity canary, PER ADR: a repo-wide "something parsed" would let a
        # renamed heading in one ADR ride on another's items, which is how a guard
        # over a renamed heading goes quietly inert.
        for adr_id, found in self.found.items():
            with self.subTest(adr=adr_id):
                self.assertTrue(
                    found,
                    f"no decisions parsed from ADR-{adr_id}'s `## Decision` "
                    "section — the heading or the item format changed, or the "
                    "section produced items in BOTH supported forms (see "
                    "`test_each_adr_uses_exactly_one_form`). Fix the parse; do "
                    "NOT leave this guard scanning nothing.",
                )

    def test_each_adr_uses_exactly_one_form(self):
        # Separated from the canary above so an ambiguous section reports as
        # ambiguity rather than as "nothing parsed".
        for adr_id, text in self.text.items():
            forms = decision_forms(text)
            with self.subTest(adr=adr_id):
                self.assertEqual(
                    len(forms),
                    1,
                    f"ADR-{adr_id}'s Decision section produced items in "
                    f"{len(forms)} forms, not 1, so there is no single numbering "
                    "to pin (0 = the format changed; 2 = the section mixes a "
                    "numbered list with `### §N` headings). Forms: "
                    f"{ {k: sorted(v) for k, v in forms.items()} }",
                )

    def test_numbers_map_to_the_same_decisions(self):
        for adr_id, want_all in DECISIONS_BY_ADR.items():
            found = self.found.get(adr_id, {})
            wrong = {
                n: (found.get(n), want)
                for n, want in want_all.items()
                if not (found.get(n) or "").startswith(want)
            }
            with self.subTest(adr=adr_id):
                self.assertEqual(
                    wrong,
                    {},
                    f"an ADR-{adr_id} Decision number now denotes a DIFFERENT "
                    "rule. Citations carry only the number, so inserting or "
                    "reordering an item silently re-points all of them (this is "
                    "how 23 citations came to say §4 when they meant §5). APPEND "
                    "instead, and add the new number here in the same commit. "
                    f"number -> (found, expected): {wrong}",
                )

    def test_no_extra_or_missing_decisions(self):
        for adr_id, want_all in DECISIONS_BY_ADR.items():
            with self.subTest(adr=adr_id):
                self.assertEqual(
                    sorted(self.found.get(adr_id, {})),
                    sorted(want_all),
                    f"ADR-{adr_id}'s Decision list gained or lost an item. "
                    "Appending is fine — add it to DECISIONS_BY_ADR here. "
                    "Anything else re-points existing citations.",
                )

    def test_every_citation_resolves(self):
        dangling = {
            key: refs
            for key, refs in citation_numbers().items()
            if key[1] not in DECISIONS_BY_ADR.get(key[0], {})
        }
        self.assertEqual(
            dangling,
            {},
            "a citation points at a decision number that does not exist in the "
            f"ADR it names: {dangling}",
        )

    def test_citations_are_found_at_all(self):
        # Second canary: if the globs stop matching, `test_every_citation_resolves`
        # passes vacuously.
        cites = citation_numbers()
        self.assertTrue(cites, "no `ADR-NNN §N` citations found — the globs broke")
        self.assertGreaterEqual(
            sum(len(v) for v in cites.values()),
            40,
            "citation count collapsed — the scan is no longer reading the guards "
            f"and docs: {({k: len(v) for k, v in cites.items()})}",
        )


class TestParserBehaviour(unittest.TestCase):
    """Mutation self-tests for the parse itself, on synthetic text."""

    _ADR = (
        "## Context\n\n1. **Something in Context.** Ignored.\n\n"
        "## Decision\n\n"
        "1. **First rule.** body\n\n"
        "2. **Second rule.** body\n"
        "   1. **A nested item.** must not be collected\n\n"
        "## Consequences\n\n3. **Not a decision.** after the section\n"
    )

    def test_only_the_decision_section_is_read(self):
        got = parsed_decisions(self._ADR)
        self.assertEqual(got, {1: "First rule.", 2: "Second rule."})

    def test_a_nested_item_is_not_collected(self):
        # It would overwrite decision 1 with a sub-point and make the pin compare
        # the wrong string — the guard would then demand a "fix" to a correct ADR.
        self.assertNotIn("nested", parsed_decisions(self._ADR)[1])

    def test_an_inserted_decision_is_caught(self):
        mutant = self._ADR.replace(
            "1. **First rule.** body\n",
            "1. **Inserted rule.** body\n\n2. **First rule.** body\n",
        ).replace("\n2. **Second rule.**", "\n3. **Second rule.**")
        got = parsed_decisions(mutant)
        self.assertNotEqual(
            got.get(1), "First rule.",
            "an inserted item did not shift the numbering in the parse, so the pin "
            "could not notice the shift",
        )

    def test_a_reworded_body_is_not_caught(self):
        # Direction: only the rule's IDENTITY is pinned, so prose edits stay green.
        mutant = self._ADR.replace("1. **First rule.** body", "1. **First rule.** rewritten body")
        self.assertEqual(parsed_decisions(mutant)[1], "First rule.")


class TestSectionFormParserBehaviour(unittest.TestCase):
    """The same mutation self-tests for ADR-002's `### §N — Title` form.

    Written out rather than parameterised with the list-form class: the two
    matchers have different failure modes (a heading cannot be nested, a list item
    cannot be out-levelled), so a shared harness would assert the union of what
    neither needs."""

    _ADR = (
        "## Context\n\n### §9 — A heading in Context.\n\n"
        "## Decision\n\n"
        "### §1 — First rule\n\nbody\n\n"
        "### §2 — Second rule\n\nbody\n\n"
        "## Consequences\n\n### §3 — Not a decision\n"
    )

    def test_only_the_decision_section_is_read(self):
        self.assertEqual(
            parsed_decisions(self._ADR), {1: "First rule", 2: "Second rule"}
        )

    def test_every_dash_spelling_is_read(self):
        # em, en and hyphen: an ADR author's editor decides this, not the guard.
        for dash in ("—", "–", "-"):
            text = self._ADR.replace("§1 —", f"§1 {dash}")
            self.assertEqual(parsed_decisions(text)[1], "First rule", dash)

    def test_a_two_hash_heading_is_not_a_decision(self):
        # `## ` ends the Decision section, so a decision written at `##` would
        # truncate the scan instead of joining it. Pinned so the level matters.
        text = self._ADR.replace("### §2 —", "## §2 —")
        self.assertNotIn(2, parsed_decisions(text))

    def test_an_inserted_decision_is_caught(self):
        mutant = self._ADR.replace(
            "### §1 — First rule", "### §1 — Inserted rule\n\n### §2 — First rule"
        ).replace("\n### §2 — Second rule", "\n### §3 — Second rule")
        self.assertNotEqual(
            parsed_decisions(mutant).get(1),
            "First rule",
            "an inserted heading did not shift the numbering in the parse",
        )

    def test_a_reworded_body_is_not_caught(self):
        mutant = self._ADR.replace("### §1 — First rule\n\nbody", "### §1 — First rule\n\nrewritten")
        self.assertEqual(parsed_decisions(mutant)[1], "First rule")


class TestRetiringADecisionInPlaceIsCaught(unittest.TestCase):
    """Commenting a decision out, or fencing it, must read as a DELETION.

    Found by adversarial review, not by this suite: `decision_forms` matched
    line by line, so a decision wrapped in `<!-- -->` or in a code fence stayed
    in the parsed list while disappearing from the rendered document. The pin,
    the set-equality check and the citation resolver all went on asserting it
    existed. Measured on a real ADR-002 edit removing a decision both ways:
    92 passed, both times.
    """

    _FENCE = "`" * 3
    ALIVE = "### §1 — Alpha\n\nbody\n\n### §2 — Beta\n\nbody\n\n### §3 — Gamma\n\nbody\n\n"
    BETA = "### §2 — Beta\n\nbody\n"

    def _parse(self, body: str) -> list:
        # The wrapping is assembled into a LOCAL and parsed from there, rather
        # than written as `parsed_decisions(self._section(body))`. That nested
        # shape is what `test_ci_strip_before_match` reads as `strip-after-extract`
        # — a stripper wrapped around a local extractor — and it flagged all six
        # of these. Here the inner call is a fixture constructor and not an
        # extractor, so it is a false positive of that meta-guard; removing the
        # SHAPE is still the right answer, because growing that guard's
        # exception list to admit a test helper would weaken it for the real
        # sites it exists to catch.
        text = "## Decision\n\n" + body + "\n## Consequences\n\nx\n"
        return sorted(parsed_decisions(text))

    def test_the_intact_fixture_parses_all_three(self):
        # Non-vacuity: without this, every assertion below could pass because the
        # fixture never parsed at all.
        self.assertEqual(self._parse(self.ALIVE), [1, 2, 3])

    def test_an_html_commented_decision_is_gone(self):
        body = self.ALIVE.replace(self.BETA, "<!--\n### §2 — Beta\n\nretired\n-->\n")
        self.assertEqual(self._parse(body), [1, 3])

    def test_a_fenced_decision_is_gone(self):
        body = self.ALIVE.replace(
            self.BETA, f"{self._FENCE}markdown\n### §2 — Beta\n{self._FENCE}\n"
        )
        self.assertEqual(self._parse(body), [1, 3])

    def test_a_tilde_fence_is_stripped_too(self):
        # Same grammar, other fence character. Enumerating only backticks would
        # leave the identical evasion one keystroke away (ADR-001 §5).
        body = self.ALIVE.replace(self.BETA, "~~~\n### §2 — Beta\n~~~\n")
        self.assertEqual(self._parse(body), [1, 3])

    def test_a_list_form_item_is_covered_by_the_same_strip(self):
        # The other decision form. The strip runs before the matchers, so both
        # get it — asserted rather than assumed, since a per-form strip is
        # exactly where one would have been forgotten.
        body = "1. **Alpha.** b\n<!--\n2. **Beta.** b\n-->\n3. **Gamma.** b\n"
        self.assertEqual(self._parse(body), [1, 3])

    def test_an_UNCLOSED_comment_is_caught_too(self):
        # One character away from the closed case above, and strictly worse: an
        # unterminated `<!--` hides everything BELOW it in the rendered document,
        # so §2 and §3 both vanish from the ADR a reader sees. Without the
        # truncation step all three stayed parsed — a silent pass.
        #
        # §1 SURVIVES, and that is the correct answer rather than a leak: it sits
        # above the opener and the renderer still shows it. An earlier version of
        # this assertion expected `[]`, which the section regex produced only
        # because truncating also removed the `## Consequences` that terminated
        # the section — a right failure for a wrong reason, and a message that
        # said "nothing parsed" instead of naming what vanished.
        body = self.ALIVE.replace(self.BETA, "<!-- RETIRED\n### §2 — Beta\n\nbody\n")
        self.assertEqual(self._parse(body), [1])

    def test_an_unclosed_comment_ABOVE_the_list_empties_it(self):
        # The same defect at the top of the section: everything is hidden, so the
        # parse must be empty and the per-ADR vacuity canary must fire. Asserted
        # separately because "one decision lost" and "all of them lost" reach
        # different assertions.
        self.assertEqual(self._parse("<!-- RETIRED\n" + self.ALIVE), [])

    def test_an_unclosed_opener_INSIDE_a_fence_is_not_an_html_block(self):
        # The order the strippers run in is itself attackable, and getting it
        # wrong cost a real divergence: with the truncation applied BEFORE fences
        # were stripped, a `<!--` shown as sample code inside a fence read as an
        # HTML-block opener and deleted decisions that render perfectly well.
        # CommonMark says the fenced code block wins. Over-strip is a loud
        # failure rather than a silent pass, but a guard that fails on a
        # legitimate document is a guard people delete.
        body = self.ALIVE.replace(
            self.BETA,
            f"{self._FENCE}\n<!-- sample opener\n{self._FENCE}\n\n### §2 — Beta\n\nbody\n",
        )
        self.assertEqual(self._parse(body), [1, 2, 3])

    def test_a_fence_marker_inside_a_comment_does_not_reopen_the_document(self):
        # The mirror case: a fence opener living only inside a closed comment is
        # removed with it, so it cannot leave an unbalanced fence behind that
        # would blank the rest of the section.
        body = self.ALIVE.replace(
            self.BETA, f"<!--\n{self._FENCE}\nretired\n-->\n\n### §2 — Beta\n\nbody\n"
        )
        self.assertEqual(self._parse(body), [1, 2, 3])

    def test_a_real_code_example_does_not_delete_the_decision_owning_it(self):
        # The false-positive boundary: an ADR decision whose BODY contains a
        # fenced example must keep its own heading. Only the fence CONTENT is
        # blanked, not the surrounding document.
        body = self.ALIVE.replace(
            self.BETA,
            f"### §2 — Beta\n\n{self._FENCE}bash\nrm -rf /tmp/x\n{self._FENCE}\n",
        )
        self.assertEqual(self._parse(body), [1, 2, 3])


class TestTheParseAgreesWithCommonMark(unittest.TestCase):
    """The strip order is adjudicated against a real renderer, not argued.

    Two orderings were each defensible in prose and each wrong on one case, so
    the claim "this is what CommonMark renders" is checked by rendering. `<h3>`
    ELEMENTS, not a substring search: an HTML block passes its source through
    verbatim, so `"§2" in html` is true even when a reader sees nothing — the
    first version of this probe made exactly that mistake and reported the
    unclosed-opener case as agreeing when it did not.

    SKIPPED, not failed, when `markdown-it-py` is absent: it is not a dependency
    of this suite, and the cases below are also pinned individually above without
    it. This class is the cross-check, not the coverage.
    """

    _F = "`" * 3
    A = "### §1 — Alpha\n\nbody\n\n"
    B = "### §2 — Beta\n\nbody\n\n"

    @classmethod
    def setUpClass(cls):
        try:
            from markdown_it import MarkdownIt
        except ImportError:  # pragma: no cover - depends on the local env
            # `from None`: a missing optional dependency is a CONDITION, not an
            # error being handled, so chaining would print a traceback that reads
            # like a failure. Required by the repo's ruff config (B904).
            raise unittest.SkipTest("markdown-it-py not installed") from None
        cls.md = MarkdownIt("commonmark")

    def _rendered_ids(self, src: str) -> list:
        return sorted(int(n) for n in re.findall(r"<h3>§(\d+)", self.md.render(src)))

    def test_the_parse_matches_the_renderer_on_every_stripper_case(self):
        cases = {
            "control": self.A + self.B,
            "closed comment": self.A + "<!-- note -->\n\n" + self.B,
            "closed fence": self.A + f"{self._F}\nx\n{self._F}\n\n" + self.B,
            "unclosed opener inside a fence":
                self.A + f"{self._F}\n<!-- sample\n{self._F}\n\n" + self.B,
            "fence marker inside a closed comment":
                self.A + f"<!--\n{self._F}\nretired\n-->\n\n" + self.B,
            "genuine unclosed opener": self.A + "<!-- RETIRED\n" + self.B,
            # Each of the four below was a measured SILENT PASS — the renderer
            # hid the decision and the parse kept it — found by adversarial
            # review after the comment and fence cases were already fixed. Three
            # strippers, three directions, same evasion.
            "html block, no blank line":
                self.A + "<div>\n### §2 — Beta\n</div>\n\n",
            "html block, other tag":
                self.A + "<table>\n### §2 — Beta\n</table>\n\n",
            "html block WITH a blank line (not a block)":
                self.A + "<div>\n\n### §2 — Beta\n\n</div>\n\n",
            "backtick in a backtick fence info string":
                self.A + f"{self._F}a`b\nx\n{self._F}\n\n" + self.B,
            # And this one was an OVER-strip that made a correct document fail.
            "unclosed opener in an inline code span":
                self.A + "see `<!--` in prose\n\n" + self.B,
        }
        for label, body in cases.items():
            src = "## Decision\n\n" + body + "\n## Consequences\n\nx\n"
            with self.subTest(case=label):
                self.assertEqual(
                    sorted(parsed_decisions(src)),
                    self._rendered_ids(src),
                    f"{label}: the parse and the renderer disagree about which "
                    "decisions a reader can see",
                )

    def test_the_named_over_strip_limits_are_still_over_strip(self):
        # What the composition gets WRONG, kept executable so a future red is
        # read as the known limit rather than as a real deletion. The direction
        # is what makes it acceptable: the parse sees FEWER decisions than the
        # renderer, so the failure is loud. A silent pass in this list would be a
        # defect; a disagreement in this direction is a documented cost.
        cases = {
            # The comment opens inside a fence and closes outside it. Fences are
            # stripped after closed comments, so the opener survives the comment
            # pass and the fence pass blanks only the fenced part.
            "opener in a fence, closer outside":
                self.A + f"{self._F}\n<!-- x\n{self._F}\n-->\n\n" + self.B,
        }
        for label, body in cases.items():
            src = "## Decision\n\n" + body + "\n## Consequences\n\nx\n"
            parsed, rendered = sorted(parsed_decisions(src)), self._rendered_ids(src)
            with self.subTest(case=label):
                self.assertNotEqual(
                    parsed, rendered, f"{label} now AGREES — good, move it above"
                )
                self.assertLess(
                    set(parsed),
                    set(rendered),
                    f"{label}: the parse sees MORE than the renderer, which is a "
                    "silent pass, not the documented over-strip",
                )

    def test_the_renderer_probe_is_not_vacuous(self):
        # Without this, a `_rendered_ids` that always returned [] would make the
        # comparison above pass on any parse that also returned [].
        src = "## Decision\n\n" + self.A + self.B + "\n## Consequences\n\nx\n"
        self.assertEqual(self._rendered_ids(src), [1, 2])


class TestFormAmbiguityIsRefused(unittest.TestCase):
    """A Decision section that parses under both matchers must yield nothing.

    Silently preferring one would pin half a list against the wrong strings and
    read green, which is the failure this whole suite is written against."""

    _MIXED = (
        "## Decision\n\n"
        "1. **A list rule.** body\n\n"
        "### §1 — A heading rule\n\n"
        "## Consequences\n"
    )

    def test_both_forms_are_seen(self):
        # Non-vacuity for the test below: without this, `parsed_decisions`
        # returning `{}` could just mean neither matcher fired.
        self.assertEqual(sorted(decision_forms(self._MIXED)), ["list", "section"])

    def test_an_ambiguous_section_parses_to_nothing(self):
        self.assertEqual(parsed_decisions(self._MIXED), {})

    def test_either_form_alone_still_parses(self):
        # The control: refusing ambiguity must not break the unambiguous cases.
        for drop, keep in (
            ("### §1 — A heading rule\n\n", "A list rule."),
            ("1. **A list rule.** body\n\n", "A heading rule"),
        ):
            self.assertEqual(parsed_decisions(self._MIXED.replace(drop, ""))[1], keep)


if __name__ == "__main__":
    unittest.main()
