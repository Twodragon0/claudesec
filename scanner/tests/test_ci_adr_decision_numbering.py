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
reordering `DECISIONS` in the SAME commit passes all ten tests (measured 2026-08-12
by in-memory mutation; the one-sided control — ADR renumbered, `DECISIONS` untouched
— correctly fails `test_numbers_map_to_the_same_decisions`). The guarantee is that a
renumber cannot be a silent one-line edit: it must arrive as a lockstep diff through
this file, where a reviewer sees it. An APPEND without its `DECISIONS` line does fail
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
fix (a bare `Decision N` is unquotably common in prose); writing new citations as
`ADR-001 §N`, and spelling two out as `§1 and §4`, is. See "On citing this ADR".

DIRECTION
---------
PIN (`==`) on the mapping `number -> title`. Any of these fails:

- inserting a decision anywhere but the end (every later number shifts);
- renumbering, reordering, or deleting a decision;
- retitling one (the title is how a reader confirms a citation resolves, so a
  retitle is exactly as confusing as a renumber and gets the same review);
- a citation to a number that does not exist (`§10` today).

APPENDING is allowed and costs one line here. That is the point: it is a review
moment, not a silent re-pointing of sixty citations. When you append, add the entry
to `DECISIONS` in the same commit.

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
from _ci_guard_util import REPO_ROOT  # noqa: E402

# The ADR series. `adr-index.md` is deliberately NOT matched: an index cites ADRs,
# it does not define decisions. `[0-9]*` covers adr-tools' 4-digit ids too.
ADR_GLOB = "docs/devsecops/adr-[0-9]*.md"
_ADR_FILE_RE = re.compile(r"adr-(\d+)-")

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
ADR_REL = "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
ADR = REPO_ROOT / ADR_REL
DECISIONS = DECISIONS_BY_ADR["001"]

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
# No literal citation is written in this file, deliberately. The first draft of
# this comment spelled that example out and `test_every_citation_resolves` failed
# on it immediately: a guard's own prose is inside the population it scans, which
# is the same discipline `test_this_guard_declares_no_citations_of_its_own`
# enforces one file over.
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
    """The text between the `## Decision` heading and the next `##` heading."""
    m = re.search(r"^## Decision\s*$(.*?)^## ", text, re.M | re.S)
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


def adr_files() -> dict:
    """`{adr id: relpath}` for every ADR on disk, nested checkouts excluded.

    Derived, not listed: a hand-written file list is the drift `_SOURCE_FILES`
    already demonstrated (#501), one level up from the pin it feeds."""
    out = {}
    for path in glob(str(REPO_ROOT / ADR_GLOB)):
        if in_nested_checkout(path, REPO_ROOT):
            continue
        p = Path(path)
        m = _ADR_FILE_RE.match(p.name)
        if m:
            out[m.group(1)] = str(p.relative_to(REPO_ROOT))
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
