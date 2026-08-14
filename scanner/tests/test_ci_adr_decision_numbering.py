"""
Guard: ADR-001's Decision numbers are STABLE, because 81 places cite them.

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

`_CITE_RE` below matches only the `ADR-001 §N` spelling — 64 of the 81 live citations
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

ADR_REL = "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
ADR = REPO_ROOT / ADR_REL

# `number -> title prefix`, pinned. Prefix match: reword the tail freely, but the
# rule a number denotes may not change without this line changing with it.
DECISIONS = {
    1: "Route every presence/regex check through the shared comment-stripping",
    2: "Scope the haystack before choosing a matcher.",
    3: "Two-pass adversarial review for any substring/parse guard before merge.",
    4: "Every detector ships a non-vacuous mutation self-test.",
    5: "Prefer a grammar-complete rule over enumerating forms.",
    6: "Run a periodic comprehensive adversarial audit",
    7: "The meta-guards are in audit scope, and are audited FIRST.",
    8: "Audit whether each guard RUNS, not only whether its logic is right.",
    9: "Route every BLOCK COLLECTOR through the shared block primitives",
}

# A numbered list item whose first line opens with `**`. The Context section also
# uses a numbered list, so items are collected only from the Decision section.
_ITEM_RE = re.compile(r"^(\d+)\.\s+\*\*(.+?)(?:\*\*|$)")

_CITE_RE = re.compile(r"ADR-001 §(\d+)")

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


def parsed_decisions(text: str) -> dict:
    """`{number: title}` for the Decision list, comment- and nesting-safe.

    Only column-0 numbered items count: a nested `1.` inside a decision's own body
    is indented, and a `9.` quoted in prose is not at the start of a line."""
    out = {}
    for line in decision_section(text).splitlines():
        m = _ITEM_RE.match(line)
        if m:
            out.setdefault(int(m.group(1)), m.group(2).strip())
    return out


def citation_numbers() -> dict:
    """`{number: [file:line, ...]}` for every `ADR-001 §N` in the repo."""
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
                out.setdefault(int(m.group(1)), []).append(f"{rel}:{lineno}")
    return out


class TestAdrDecisionNumbering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = ADR.read_text(encoding="utf-8") if ADR.is_file() else ""
        cls.found = parsed_decisions(cls.text)

    def test_adr_exists(self):
        self.assertTrue(ADR.is_file(), f"{ADR_REL} not found — path assumption broke")

    def test_decision_section_is_parsed(self):
        # Vacuity canary: an empty parse would make every assertion below pass for
        # free, which is how a guard over a renamed heading goes quietly inert.
        self.assertTrue(
            self.found,
            "no numbered decisions parsed from the `## Decision` section — the "
            "heading or the list format changed. Fix the parse; do NOT leave this "
            "guard scanning nothing.",
        )

    def test_numbers_map_to_the_same_decisions(self):
        wrong = {
            n: (self.found.get(n), want)
            for n, want in DECISIONS.items()
            if not (self.found.get(n) or "").startswith(want)
        }
        self.assertEqual(
            wrong,
            {},
            "an ADR-001 Decision number now denotes a DIFFERENT rule. 81 places "
            "cite these numbers, so inserting or reordering an item silently "
            "re-points all of them (this is how 23 citations came to say §4 when "
            "they meant §5). APPEND instead, and add the new number here in the "
            f"same commit. number -> (found, expected): {wrong}",
        )

    def test_no_extra_or_missing_decisions(self):
        self.assertEqual(
            sorted(self.found),
            sorted(DECISIONS),
            "the Decision list gained or lost an item. Appending is fine — add it "
            "to DECISIONS here. Anything else re-points existing citations.",
        )

    def test_every_citation_resolves(self):
        dangling = {
            n: refs for n, refs in citation_numbers().items() if n not in DECISIONS
        }
        self.assertEqual(
            dangling,
            {},
            "a citation points at a decision number that does not exist: "
            f"{dangling}",
        )

    def test_citations_are_found_at_all(self):
        # Second canary: if the globs stop matching, `test_every_citation_resolves`
        # passes vacuously.
        cites = citation_numbers()
        self.assertTrue(cites, "no `ADR-001 §N` citations found — the globs broke")
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


if __name__ == "__main__":
    unittest.main()
