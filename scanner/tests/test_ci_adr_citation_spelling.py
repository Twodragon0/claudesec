r"""
Guard: a NEW citation of an ADR-001 decision must use the canonical spelling, so
the population stays inside the regex `test_ci_adr_decision_numbering.py` scans.

WHY THIS IS A CI INVARIANT AND NOT A STYLE PREFERENCE
-----------------------------------------------------
`test_ci_adr_decision_numbering.py` is the control that keeps sixty-odd citations
pointing at the rule their author meant. Its `_CITE_RE` matches ONE spelling. The
2026-08-12 vintage sweep (#434) counted the population for the first time and
found it written five ways: 64 of 81 in the canonical form, 17 in four others that
the scanner cannot see — and **all five** citations still carrying a
pre-renumbering number were in that invisible 17. The blind spot was not
incidental; it is why they survived three sweeps (#423, #426/#430) that each read
every match the scanner produced.

One of the five is the sharpest case: `ci-config-regression-guards.md:324` wrote a
CHAIN. That line was match #8 of 69 in a plain scan, so the sweeps read it,
resolved its head correctly, and never saw the tail. An invisible token on a
visible line reads exactly like a triaged one.

Widening `_CITE_RE` is not the fix — a bare `Decision <N>` is unquotably common in
prose, so a wider regex buys false positives instead of coverage. Narrowing what
gets WRITTEN is. This guard is that narrowing.

FORBIDDEN SPELLINGS, by slug
----------------------------
- `mis-anchored` — the anchor is not exactly `ADR-001` plus ONE SPACE plus a
  DIGIT after the section mark, which is precisely what `_CITE_RE` requires. #434
  enumerated ONE instance of this (`ADR §<N>`, the `-001` dropped); written to that
  one spelling the guard left four evasions, and written with an exemption one
  character short of `_CITE_RE`'s own pattern it left a whole further family —
  `§§<N>`, the ordinary plural-sections form, among them. This is therefore a RULE,
  not an enumeration (ADR-001 §5) — see the pattern's comment, and the tests under
  `TestSpellingDetector` that pin each shape AND the false-positive boundary. (No
  count here on purpose: an earlier draft of the catalog row miscounted them, in a
  PR about a miscounted population.)
- `adr001-decision` — the word form instead of the mark, `ADR` and `Decision` both
  case-insensitive, id required.
- `anchored-chain` — `ADR-001 §<N>/§<M>`: head visible, tail invisible. Cite the
  pair by REPEATING the prefix (`ADR-001 §<N> and ADR-001 §<M>`), which is the only
  form `_CITE_RE` fully sees — measured 2026-08-12: it returns ONE number for the
  chain and for the un-repeated pair alike, and two only for the repeated form
  (the transcript is in the catalog's backlog). So the ADR's original "write them
  out" advice was a half-fix, corrected there in this PR. The un-repeated pair is
  nevertheless NOT flagged here, and that is a deliberate false negative. Measured
  on `b382641`, the tree this decision was taken against: THREE live instances of
  "a canonical citation with a bare `§<M>` later on the same line", by the pattern
  `ADR-001 §\d+(?![\d/])(?:(?!ADR-001)[^\n])*?§\d+`, and all three are drift notes
  quoting a number as DATA (*"26 `ADR-001 §4` citations of which 23 meant §5"*). So
  a rule wide enough to catch the pair would over-report on precisely the prose that
  documents this class.

  That count is anchored to a commit because THIS PR moved it: the same pattern
  gives 3 on `b382641`, 6 on `6c9a387` and 7 on `dc3a959` — writing about the class
  creates instances of it. The cost argument is unaffected (the four added are this
  PR's own prose about drift notes, the same category), but a bare "three" would be
  unreproducible within a week, which is the failure this PR exists to stop. Named
  as a test rather than left as an unremarked green, and in the catalog's backlog.
- `bare-decision` — `Decision <N>` in a file outside the `docs/devsecops/adr-NNN`
  series. Deliberately the narrowest class of the four; both proposed widenings
  were measured to cost live false positives and are rejected in its comment.

The `mis-anchored` rule earned itself immediately: it found a LIVE citation in
`test_ci_strip_before_match.py` that no census had ever seen, because a line wrap
put `ADR-001` at the end of one line and its `§<N>` at the start of the next. The
spelling was canonical; only the wrap made it invisible. Reflowed in this PR
rather than grandfathered — restoring visibility costs nothing there. Exactly one
such site exists repo-wide (measured), so the population is 82, not 81.

A bare `§<N>` with no `ADR-001` anchor is deliberately NOT flagged. It is not a
citation the scanner could ever see in any spelling, it is overwhelmingly
set-enumeration prose about a cohort ("the §2/§3 citations"), and `§<N>` is also
how this repo cites NIST SP 800-61r2, ISO 27035, RFC 8259 and the `kcov-debug`
skill's own sections — 275 `§`-shaped hits repo-wide, most of them nothing to do
with this ADR. Flagging them would be sprawl, and a guard people have to fight
gets weakened rather than repaired (#414).

THE ADR'S OWN CROSS-REFERENCES
------------------------------
The ADR writes `Decision <N>` about its own list ("Decision <N> says bound the
haystack"). That is correct prose, not a citation: it sits beside the list it
names, and the numbering guard reads that list DIRECTLY rather than through
`_CITE_RE`, so nothing is hidden from anything. Demanding `ADR-001 §<N>` inside
`adr-001-....md` would be absurd. So `bare-decision` is exempt for one class over
one GLOB — `docs/devsecops/adr-[0-9]*.md` — and for no other class.

The glob, not the single path the first draft hardcoded: `adr-index.md` documents
`adr-NNN` as a sequential series and instructs that a changed decision be recorded
as a NEW ADR, so the first `adr-002` would have failed this guard on its own
legitimate self-cross-references. The index itself is NOT exempt — it cites ADRs
rather than defining decisions.

That exemption is NARROW, and the baseline below proves it: the ADR does carry
`mis-anchored` and `anchored-chain` entries, because its drift tables quote the old
spelling of a corrected citation as DATA. A new one of those in the ADR still
fails. #434 recorded that the previous exclusion rule had been stated too
narrowly to reproduce its own count; this one is stated as code, and
`TestAdrExemptionIsNarrow` pins both directions of it.

DIRECTION / SEMANTICS
---------------------
Regression-pin over a KNOWN baseline, the shape of
`test_ci_guard_assertion_scoping.py` and `test_ci_strip_before_match.py`: the
detected set must EQUAL `GRANDFATHERED`. A new non-canonical citation fails, and a
canonicalized site's stale entry fails. Unlike those two, this baseline cannot be
empty: #434 deliberately left correct citations in a non-canonical spelling alone
rather than churning twelve sites for spelling, and churn is the wrong trade for a
permanent doc.

The precise limit of set equality, because an earlier draft of this docstring
overstated it as "the allowlist cannot outlive its justification": equality is over
the SET, so any edit that leaves the set unchanged is invisible. Two measured
counterexamples — canonicalize one of the retrospective's two `ADR §<N>` sites
while adding a new one elsewhere in the same file, and the `|#1`/`|#2` pair is
reproduced exactly; or swap two grandfathered numbers within one file (below).
What equality does guarantee is that the baseline cannot grow, or hold an entry for
a site that no longer produces it, without a diff through this file.

What makes a non-empty baseline maintainable is the KEY, which carries no line
number and no surrounding prose:

    <repo-relative path>|<slug>|<number(s)>|#<ordinal>

- **No line number.** Line numbers rot on every reflow, and a baseline that
  demands an update for an unrelated paragraph edit is a baseline that gets
  bulk-regenerated instead of read.
- **The NUMBER is in the key**, so this cannot degrade into a per-file count. A
  count of 4 hides `Decision <N>` being edited to `Decision <M>` entirely; here the
  key changes, so a ONE-WAY retarget is a new entry and fails
  (`test_a_number_swap_changes_the_key`). Stated exactly, because the first draft
  claimed more: a PAIRWISE swap — two of the skill's word-form citations trading
  numbers — leaves the key set byte-identical and passes, with both citations now
  wrong. Set membership catches a retarget; it cannot catch a permutation. That is
  a strictly smaller hole than a count, which hides both.
- **The ordinal** (per file+slug+numbers) keeps a second identical occurrence from
  collapsing into the first. Two `ADR §<N>`s in one file are two entries.
- **The whole number sequence** for a chain, so retargeting a tail is visible too.
- **The slug, not the matched text**, so this file contains no instance of any
  spelling it forbids — no self-exemption is needed, and
  `test_this_guard_declares_no_citations_of_its_own` keeps it that way. The
  docstring above writes `<N>` for the same reason, and the test fixtures are
  ASSEMBLED from parts (`_misanchored(4)`) rather than written literally — the same
  discipline this repo already uses for credential-shaped fixtures, which the
  repository ruleset blocks even in tests. That test has now caught this file three
  times: 28 keys in the first draft, 6 after the mis-anchored rule widened, and 6
  more after the review fixes. All fixtures and comments, none of them exemptions.

Removal direction: canonicalizing a grandfathered site is welcome and costs one
line here. It is a one-sided pin the other way — the baseline can only shrink
through a diff a reviewer sees.

SCOPE
-----
The scanned globs are IMPORTED from `test_ci_adr_decision_numbering` rather than
restated, because the invariant is defined relative to that scanner's population:
two lists is where they drift apart. Widening one widens both.

Measured 2026-08-12 on b382641: zero occurrences of any forbidden spelling in the
255 tracked files those globs do NOT cover, so nothing is being missed today. If a
citation ever lands in a `.sh` or a workflow, BOTH guards are blind to it — a
shared limitation with a single fix, which is the point of sharing the constant.

`test_population_is_scanned`'s `>= 40` is a VACUITY canary and NOT the control.
Measured on `dc3a959`: canonical citations total 98, and dropping the `scanner/**`
glob leaves exactly 40 — so the threshold is inert for every single-glob drop, and
raising it would only move the inertness. The real control in that test is the two
`assertIn`s, which name the ADR itself and this guard's own file: either glob going
missing fails them by name. Read the `>= 40` as "the scan returned something", and
nothing more.

NOT CLAIMED
-----------
This does not stop a citation from naming the wrong decision; reading the quoted
text is what does that. What it does is keep every future citation inside the one
scanner that reads them, so the next sweep's matches ARE its population.

stdlib-only, no PyYAML, no `scanner/lib` import (so it never moves the 99%
coverage gate), no network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`.

This docstring is RAW — it carries an `r` prefix — because it quotes regexes. It was not, and the
consequence was the exact failure this guard exists to prevent, one level up: the
`[^\n]` inside the reproducible pattern above was interpreted as a real newline, so
the pattern a reader saw was TRUNCATED, and `\d` raised a SyntaxWarning that the two
AST meta-guards surfaced on every pytest run. A quoted pattern that does not
round-trip is not evidence. Keep the `r`.

OWASP CICD-SEC-7 (Insecure System Configuration) — the documented policy behind
the guards is part of the configuration; NIST SP 800-218 (SSDF) PO.3, PW.4.
"""

import re
import sys
import unittest
from fnmatch import fnmatch
from glob import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    apply_mutation,
    assert_disables,
)
from test_ci_adr_decision_numbering import ADR_REL, _CITED_GLOBS  # noqa: E402

THIS_REL = "scanner/tests/test_ci_adr_citation_spelling.py"

# One more `§<digits>` hop in a chain.
#
# The separator is a CLASS, not the single literal `/` the first draft used: all of
# `§1, §3` · `§1–§3` · `§1-§3` · `§1 & §3` · `§1+§3` · `§1; §3` · `§1|§3` yield
# `['1']` from `_CITE_RE` and were invisible here, which is an enumeration in the
# very file that invokes ADR-001 §5. The `§` on the tail is optional ONLY after
# `/` (where `§1/3` is an idiomatic abbreviation) and REQUIRED after every other
# separator, because `§5, 2026-08-12` would otherwise key as a chain to decision
# 2026 — a real shape in this repo's tables.
#
# `[ \t]` and not `\s`: a hop that could span a newline turns an unrelated `/ §6`
# on the next line into a chain tail. Pinned by
# `test_a_chain_hop_does_not_cross_a_newline`.
_CHAIN_SEP = r"(?:/[ \t]*§?|[,;&+|~–—-][ \t]*§)"
_CHAIN_HOP = rf"(?:[ \t]*{_CHAIN_SEP}\d+)"

# The ADR's own identifier after the `ADR` token: a separator plus a zero-padded 1,
# so `-001`, ` 001` and adr-tools' 4-digit `-0001` all read as the id.
#
# The separator class EXCLUDES `§` deliberately. With a plain `\W` there, the
# `ADR §<N>/§<M>` in the 2026-08 retrospective parsed as id=`ADR §<N>` and keyed as a
# `mis-anchored|2` rather than `|1/2` — the id matcher ate the first decision
# number. Caught by re-measuring the live hit set after the widening, not by
# review; see the harness discipline in ADR-001 §4.
_ADR_ID = r"(?:[^\w§]{1,2}0*1)?"

# The joint between the anchor and what follows it: up to three non-word chars on
# the same line, OR a line wrap with any indent and an optional continuation
# marker, OR a Markdown link suffix (`[ADR-001](path)`), which the repo already
# writes in four places.
#
# The wrap branch is unbounded on indent on purpose. Bounded at `\W{0,3}` it
# covered 0/1/2-space and `> ` continuations but NOT a 4- or 8-space Python
# docstring continuation — the single most common wrap shape in this suite, and
# the exact place the one live wrap site was found. Re-derived with an unbounded
# gap over all tracked files: still exactly one site, so widening costs nothing.
_JOINT = r"(?:\](?:\([^)\s]*\))?)?(?:\W{0,3}|[ \t]*\n[ \t]*(?:[#>*+-][ \t]*)*)"

# Slug -> pattern. Group 1 is the head number, group 2 the (possibly empty) chain
# tail. There is no masking pass and so no stripper to attack: the `mis-anchored`
# class excludes the canonical anchor with a lookahead, and `bare-decision`
# excludes the `ADR-001 ` prefix its own class owns. The one residual overlap is
# an over-report: a LOWERCASE word form (`adr-001 Decision <N>`) is claimed by both
# `adr001-decision` and `bare-decision`, because the latter's lookbehind is
# case-sensitive. Two keys on a line that is forbidden either way — a false alarm,
# never a miss.
FORBIDDEN = (
    # `ADR-001 §<N>/§<M>` — the head is canonical, so the line is VISIBLE to
    # `_CITE_RE` while the tail is not. Requires at least one hop, so plain
    # `ADR-001 §1` and a pair with the prefix repeated are untouched.
    ("anchored-chain", re.compile(rf"ADR-001 §(\d+)((?:{_CHAIN_HOP})+)")),
    # The word form. `ADR` and `Decision` are both case-insensitive, and the
    # joint between them and the number is `\W{0,3}`, so a lower-case word form and
    # a parenthesised number are both covered. The id is REQUIRED here, which keeps
    # slug honest; a bare `ADR Decision <N>` with no id is a named limit below.
    (
        "adr001-decision",
        re.compile(
            rf"(?<![-\w])(?i:ADR)[^\w§]{{1,2}}0*1[ \t]*(?i:Decisions?)\W{{0,3}}"
            rf"(\d+)((?:{_CHAIN_HOP})*)"
        ),
    ),
    # The ANCHOR is not exactly `ADR-001` plus one space before the section mark.
    #
    # A rule, not an enumeration (ADR-001 §5). #434 catalogued one instance of
    # this class — the `-001` simply dropped — and writing the guard as that one
    # spelling left evasions invisible to BOTH `_CITE_RE` and the matcher: a
    # U+2011 hyphen, a missing hyphen (`ADR 001 §<N>`), a backticked prefix
    # (`` `ADR-001` §<N> ``), lower case (the #379 lesson — a case-sensitive
    # matcher missed GitHub's own `macOS-14`), a parenthesised `the ADR (§<N>)`, a
    # Markdown link, adr-tools' 4-digit id, and every wrap shape above.
    #
    # THE LOOKAHEAD MUST REQUIRE A DIGIT. Written `(?!ADR-001 §)` it exempted a
    # SUPERSET of what `_CITE_RE` matches — that regex needs `ADR-001 §\d+`, so the
    # whole family `ADR-001 §<non-digit>…<digit>` was invisible to both, including
    # `§§4`, which is the ordinary way to write plural sections. Found by an
    # independent pass, not by the live-population measurement: "same hits, no new
    # false positives" can only ever measure spellings that already exist, which is
    # #434's own finding turned on this guard. `§\W{0,3}` closes the spaced and
    # marked-up variants of the same family.
    #
    # The negative lookahead is case-SENSITIVE while `ADR` is not, which is the
    # whole point: a lower-case canonical form is invisible to `_CITE_RE` and must
    # be flagged, so only the exactly-canonical anchor may be exempt. `(?i:...)`
    # is a SCOPED inline flag (Python 3.6+), verified on 3.11 — the version the
    # `scanner-unit-tests` job runs — precisely so no global `re.IGNORECASE` can
    # weaken the lookahead.
    #
    # False-positive boundary, stated completely: `\W{0,3}` cannot cross a WORD
    # character, so `in the ADR, see §4` does not match — that shape belongs to the
    # documented same-line gap instead. It CAN cross a paragraph break, though,
    # because a blank line is two non-word characters: `see the ADR.\n\n§4 of NIST`
    # keys as `mis-anchored|4`. Zero live instances on `dc3a959`, over-report
    # direction, and pinned as a known false positive rather than left for a reader
    # to trip over. Narrowing it would mean dropping `\n` from the joint, which is
    # exactly what hid the one live wrap site.
    (
        "mis-anchored",
        re.compile(
            rf"(?<![-\w])(?!ADR-001 §\d)(?i:ADR){_ADR_ID}{_JOINT}"
            rf"§\W{{0,3}}(\d+)((?:{_CHAIN_HOP})*)"
        ),
    ),
    # A bare `Decision` + number, outside the ADRs. The lookbehind is fixed-width
    # and exact, so the uppercase word form is claimed only by its own class.
    #
    # This class is DELIBERATELY the narrowest of the four — capital `D`, exactly
    # one space, no marked-up joint — because it has no `ADR` anchor to disambiguate
    # it from ordinary prose. The widening offered in review was measured and
    # REJECTED, and the measurement also located the blame precisely. Variants, each
    # counted as NEW hits over the shipped pattern, ADR series exempt:
    #
    #     variant                                    b382641   dc3a959
    #     joint `\W{0,3}` + bound `\d{1,2}`               +4       +11
    #     joint `\W{0,3}` only                            +4       +11
    #     bound `\d{1,2}` only                             0         0
    #
    # So the JOINT is the whole cost and the bound is free — but also pointless,
    # since without the joint there is nothing for it to bound. Every one of those
    # hits is this catalog writing `**Decision (2026-08-12): no guard.**`, which the
    # widened joint parses as decision 20.
    #
    # An earlier version of this comment said "SIX", which reproduces at no
    # committed state: it was measured mid-edit on an uncommitted tree. Third
    # unreproducible numeral this round, in a PR about miscounted populations —
    # hence the table with commits in it.
    #
    # Named limits, all measured at zero live instances on `dc3a959`: lower-case
    # `decision <N>`, `Decision #<N>`, `Decision-<N>`, and `Decision <4-digit year>`
    # as a false positive that fails loudly rather than silently.
    ("bare-decision", re.compile(r"(?<!ADR-001 )\bDecisions? (\d+)()")),
)

# Slug -> path GLOBS where that slug is not a violation. See "THE ADR'S OWN
# CROSS-REFERENCES": one class, one directory of definition sites.
#
# A GLOB, not the single `ADR_REL` path the first draft hardcoded. `adr-index.md`
# documents `adr-NNN` as a sequential series and instructs that a changed decision
# be recorded as a NEW ADR, so the first `adr-002` would have failed this guard on
# its own legitimate self-cross-references. `adr-[0-9]*` covers 3- and 4-digit ids
# and deliberately does NOT cover `adr-index.md`: an index cites ADRs, it does not
# define decisions, so a bare `Decision <N>` there is a citation like any other.
EXEMPT_PATH_GLOBS = {"bare-decision": ("docs/devsecops/adr-[0-9]*.md",)}

# Correct citations in a non-canonical spelling, present when this guard landed.
# #434 left them alone on purpose: they resolve to the right decision, and
# churning twelve sites in permanent docs for spelling is the worse trade. New
# ones must be canonical.
#
# The two `mis-anchored` entries in the ADR and both `anchored-chain` entries are
# drift notes QUOTING a corrected citation's old spelling as data — which is
# exactly why the ADR is not blanket-exempt.
#
# To retire an entry: canonicalize the site and delete the line (the stale-entry
# test will tell you if you forget). To add one: you almost certainly should not —
# write the canonical form instead. The exception is another drift note that must
# reproduce a non-canonical spelling verbatim; say so in the PR.
GRANDFATHERED = frozenset(
    {
        # The authoring skill's four, written `5a35454` in the word form.
        ".claude/skills/ci-config-guard-claudesec/SKILL.md|adr001-decision|1|#1",
        ".claude/skills/ci-config-guard-claudesec/SKILL.md|adr001-decision|3|#1",
        ".claude/skills/ci-config-guard-claudesec/SKILL.md|adr001-decision|4|#1",
        ".claude/skills/ci-config-guard-claudesec/SKILL.md|adr001-decision|5|#1",
        # The ADR's own drift tables, quoting the old spelling of a fixed site.
        "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
        "|mis-anchored|3|#1",
        "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
        "|mis-anchored|4|#1",
        "docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md"
        "|anchored-chain|1/3|#1",
        # The numbering guard's docstring, naming the chain that hid a tail.
        "scanner/tests/test_ci_adr_decision_numbering.py|anchored-chain|1/3|#1",
        # The catalog backlog's measured `_CITE_RE` transcript, added by the same
        # PR as this guard: the three-row comparison IS the evidence, so the chain
        # row has to be reproduced verbatim. The documented escape hatch,
        # exercised once on its own PR — the ADR prose and this guard's docstring
        # were reworded to avoid a second and third copy instead.
        "docs/devsecops/ci-config-regression-guards.md|anchored-chain|1/4|#1",
        # The 2026-08 cycle retrospective's Korean prose: two live citations of
        # decision 9, and the chain the #434 review named as the counterexample to
        # "don't chain" — grandfathered rather than churned, under the
        # `mis-anchored` class it actually falls in.
        "docs/reports/guard-audit-cycle-2026-08-retrospective.md|mis-anchored|1/2|#1",
        "docs/reports/guard-audit-cycle-2026-08-retrospective.md|mis-anchored|9|#1",
        "docs/reports/guard-audit-cycle-2026-08-retrospective.md|mis-anchored|9|#2",
    }
)

_CANONICAL_RE = re.compile(r"ADR-001 §\d+")


def _numbers(head: str, chain: str) -> str:
    """`'1'` / `'1/3'` — every decision number in one match, separator- and
    whitespace-normalized so `§1 / §3` and `§1/3` key identically to `§1/§3`."""
    return "/".join([head] + re.findall(r"\d+", chain or ""))


def spelling_findings(text: str, relpath: str) -> list:
    """Sorted baseline keys for every forbidden ADR-001 citation spelling in
    `text`, attributed to `relpath`.

    RAW text on purpose. The consumer this protects (`_CITE_RE` in
    `test_ci_adr_decision_numbering`) reads raw text, so scanning anything narrower
    would measure a different population than the one the invariant is about. And
    this is a FORBIDDEN-token scan, the direction ADR-001 §2 exempts: over raw text
    it can only over-report, which is a false alarm a baseline line settles — never
    a silent bypass. A citation parked in an HTML comment still counts, because
    `_CITE_RE` would still have counted it."""
    seen = {}
    out = []
    for slug, pattern in FORBIDDEN:
        if any(fnmatch(relpath, g) for g in EXEMPT_PATH_GLOBS.get(slug, ())):
            continue
        for m in pattern.finditer(text):
            base = f"{relpath}|{slug}|{_numbers(m.group(1), m.group(2))}"
            seen[base] = seen.get(base, 0) + 1
            out.append(f"{base}|#{seen[base]}")
    return sorted(out)


def scanned_files() -> list:
    """`(relpath, text)` for every file the numbering guard's citation scan reads,
    sorted and de-duplicated (the globs overlap: `*.md` and `docs/**/*.md`)."""
    paths = set()
    for pattern in _CITED_GLOBS:
        paths.update(glob(str(REPO_ROOT / pattern), recursive=True))
    out = []
    for path in sorted(paths):
        p = Path(path)
        try:
            out.append((str(p.relative_to(REPO_ROOT)), p.read_text(encoding="utf-8")))
        except (UnicodeDecodeError, OSError):
            continue
    return out


def scan_population() -> list:
    """Every forbidden-spelling key in the cited population, sorted."""
    out = []
    for relpath, text in scanned_files():
        out.extend(spelling_findings(text, relpath))
    return sorted(out)


class TestAdrCitationSpelling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = scanned_files()
        cls.found = set(scan_population())

    def test_population_is_scanned(self):
        # Vacuity canary. The two `assertIn`s below are the actual control — they
        # name a file from two different globs, so either glob disappearing fails by
        # name. The `>= 40` only says "the scan returned something": canonical is 98
        # on `dc3a959` and dropping the `scanner/**` glob leaves exactly 40, so the
        # threshold is inert for a single-glob drop and is not a floor.
        rels = [rel for rel, _ in self.files]
        self.assertTrue(rels, "no files matched the imported citation globs")
        self.assertIn(ADR_REL, rels, f"{ADR_REL} dropped out of the scanned globs")
        self.assertIn(THIS_REL, rels, "this guard file is not in its own scan")
        canonical = sum(len(_CANONICAL_RE.findall(t)) for _, t in self.files)
        self.assertGreaterEqual(
            canonical,
            40,
            "canonical citation count collapsed — the scan is no longer reading "
            f"the guards and docs (found {canonical})",
        )

    def test_no_new_non_canonical_citation(self):
        new = sorted(self.found - GRANDFATHERED)
        self.assertEqual(
            new,
            [],
            "Non-canonical ADR-001 citation spelling(s):\n  "
            + "\n  ".join(new)
            + "\n\nUse the canonical form. It is the only spelling matched by "
            "`_CITE_RE` in test_ci_adr_decision_numbering.py, which is the scan "
            "every renumbering sweep uses as its population — a citation it "
            "cannot see is a citation no sweep audits (#434: all five surviving "
            "pre-renumbering errors were in the invisible 17).\n"
            "  mis-anchored    -> the anchor must be exactly `ADR-001 ` (right "
            "hyphen, right case, nothing between it and the mark, same line).\n"
            "  adr001-decision -> use the section mark, not the word.\n"
            "  anchored-chain  -> REPEAT the prefix before the second number; a "
            "chain hides its tail from the scan while the head keeps the line "
            "looking triaged, and un-chaining alone does not fix that (the scan "
            "anchors on the prefix, so it needs one per number).\n"
            "  bare-decision   -> name the ADR (the ADR file itself is exempt, "
            "since it is the definition site).\n"
            "If a doc must reproduce a non-canonical spelling VERBATIM as data "
            "about a past drift, add its key to GRANDFATHERED and say so in the PR.",
        )

    def test_grandfather_baseline_has_no_stale_entries(self):
        stale = sorted(GRANDFATHERED - self.found)
        self.assertEqual(
            stale,
            [],
            "Stale GRANDFATHERED entries (site canonicalized, renumbered, or "
            "removed):\n  "
            + "\n  ".join(stale)
            + "\n\nDelete them. A stale allowlist entry is a standing permission "
            "to re-introduce exactly that spelling at exactly that site.",
        )

    def test_this_guard_declares_no_citations_of_its_own(self):
        # The baseline is keyed by SLUG and number, and the docstring writes `<N>`,
        # so this file instantiates none of the spellings it forbids. Without that
        # discipline the guard would need to exempt itself — a hole in the one file
        # nobody would think to check.
        text = dict(self.files).get(THIS_REL, "")
        self.assertTrue(text, "could not read this guard's own source")
        self.assertEqual(
            spelling_findings(text, THIS_REL),
            [],
            "this guard now contains a literal instance of a spelling it forbids "
            "— write `<N>` in prose and keep the baseline keyed by slug, rather "
            "than exempting this file",
        )


# --- fixture spellings, ASSEMBLED -------------------------------------------
#
# Every fixture below is built from parts so that this file's own source holds no
# literal instance of a forbidden spelling. The escape keeps even the section mark
# out of the source, and each f-string interpolates the number, so the anchor and
# the digit are never adjacent in the bytes on disk. Without this the guard would
# have to exempt itself, and a self-exempt guard is un-scanned by the one check
# that would notice a real citation parked in it.
_S = "§"  # §


def _canon(*nums) -> str:
    """The canonical form, one or two decisions (`... and ...`) — the encouraged
    spelling, and the negative control for every assertion below."""
    return " and ".join(f"ADR-001 {_S}{n}" for n in nums)


def _misanchored(*nums) -> str:
    """The `-001`-dropped instance of `mis-anchored` — #434's enumerated one, and
    the shape of all five live sites. The other shapes that class now covers (bad
    hyphen, missing hyphen, intervening markup, wrong case) are written inline in
    their own tests, since each one IS the thing under test."""
    return "ADR " + "/".join(f"{_S}{n}" for n in nums)


def _word(n) -> str:
    """The `adr001-decision` word form."""
    return f"ADR-001 Decision {n}"


def _word_joint(joint, n, word="Decision") -> str:
    """The word form with an arbitrary joint between the word and the number, and
    an arbitrary spelling of the word itself. Assembled, so no literal instance of
    any of these shapes exists in this file."""
    return f"ADR-001 {word}{joint}{n}"


def _chain(*nums) -> str:
    """The `anchored-chain` spelling: a canonical head, an invisible tail."""
    return "ADR-001 " + "/".join(f"{_S}{n}" for n in nums)


def _bare(n, plural: bool = False) -> str:
    """The `bare-decision` spelling."""
    return f"Decision{'s' if plural else ''} {n}"


class TestSpellingDetector(unittest.TestCase):
    """Mutation self-tests on synthetic text. Every forbidden class must produce a
    key and every allowed form must produce none: the on-disk baseline is
    non-empty, so a detector that fired on nothing would still satisfy the pin
    above by accident."""

    OTHER = "docs/x.md"

    def _keys(self, text, relpath=None):
        return spelling_findings(text, relpath or self.OTHER)

    def _slugs(self, text, relpath=None):
        return [k.split("|")[1] for k in self._keys(text, relpath)]

    # --- the four forbidden classes fire ---------------------------------------

    def test_adr_without_001_is_detected(self):
        self.assertEqual(
            self._keys(f"see {_misanchored(4)} for this"),
            [f"{self.OTHER}|mis-anchored|4|#1"],
        )

    def test_word_form_decision_is_detected(self):
        self.assertEqual(
            self._keys(f"per {_word(3)}, review twice"),
            [f"{self.OTHER}|adr001-decision|3|#1"],
        )

    def test_anchored_chain_is_detected(self):
        self.assertEqual(
            self._keys(f"({_chain(1, 3)})"),
            [f"{self.OTHER}|anchored-chain|1/3|#1"],
        )

    def test_bare_decision_outside_the_adr_is_detected(self):
        self.assertEqual(
            self._keys(f"{_bare(5)} says model the grammar"),
            [f"{self.OTHER}|bare-decision|5|#1"],
        )

    def test_plural_decisions_is_detected(self):
        self.assertEqual(
            self._slugs(f"{_bare(4, plural=True)} and 6 in action"), ["bare-decision"]
        )

    # --- the mis-anchored RULE, not an enumeration -----------------------------
    #
    # Each of these was measured invisible to `_CITE_RE` **and** to the first
    # draft's `ADR §<N>`-only matcher. They are the reason this class is a rule.

    def test_a_non_ascii_hyphen_in_the_anchor_is_detected(self):
        # U+2011 NON-BREAKING HYPHEN — a copy-paste artefact, not an attack.
        self.assertEqual(
            self._slugs(f"ADR‑001 {_S}4 applies"), ["mis-anchored"]
        )

    def test_a_missing_hyphen_in_the_anchor_is_detected(self):
        self.assertEqual(self._slugs(f"ADR 001 {_S}4"), ["mis-anchored"])

    def test_markup_between_the_anchor_and_the_mark_is_detected(self):
        # A backticked prefix renders identically and is invisible to the scan.
        self.assertEqual(self._slugs(f"`ADR-001` {_S}4"), ["mis-anchored"])

    def test_a_lower_case_anchor_is_detected(self):
        # The #379 lesson: `_CITE_RE` is case-sensitive, so this is invisible.
        self.assertEqual(self._slugs(f"adr-001 {_S}4"), ["mis-anchored"])
        self.assertEqual(self._slugs(f"Adr-001 {_S}4"), ["mis-anchored"])

    def test_a_parenthesised_section_after_the_anchor_is_detected(self):
        self.assertEqual(self._slugs(f"the ADR ({_S}4)"), ["mis-anchored"])

    def test_a_lower_case_chain_keys_the_whole_sequence(self):
        # The lower-case chain falls to `mis-anchored` (the chain class requires
        # the exact canonical head), and must still record both numbers.
        self.assertEqual(
            self._keys(f"adr-001 {_S}1/{_S}3"),
            [f"{self.OTHER}|mis-anchored|1/3|#1"],
        )

    def test_a_paragraph_break_IS_crossed_a_known_false_positive(self):
        # Named, not hidden: a blank line is two non-word characters, so the joint
        # spans it. Over-report direction, zero live instances on `dc3a959`. The only
        # way to narrow it is to drop `\n` from the joint, which is what hid the one
        # live wrap site this rule was widened to find.
        self.assertEqual(
            self._slugs(f"see the ADR.\n\n{_S}4 of NIST SP 800-218"),
            ["mis-anchored"],
            "the paragraph-break false positive is gone — good; remove it from the "
            "boundary comment and from here",
        )

    def test_prose_that_merely_mentions_the_adr_is_not_flagged(self):
        # The false-positive boundary of the rule: `\W{0,3}` cannot cross a word
        # character, so an ADR mention and a later section mark are not joined.
        # (That shape is the documented same-line gap, not this class.)
        self.assertEqual(self._keys(f"in the ADR, see {_S}4"), [])
        self.assertEqual(self._keys(f"the ADR mandates {_S}4 here"), [])

    # --- the allowed forms do NOT fire (positive control for the absence) ------

    def test_canonical_citation_is_not_flagged(self):
        # The whole point: the form the guard steers people toward must pass.
        self.assertEqual(self._keys(f"the rule ({_canon(5)}) applies"), [])

    def test_the_repeated_prefix_pair_is_not_flagged(self):
        # The form that actually keeps BOTH numbers inside `_CITE_RE`.
        self.assertEqual(self._keys(_canon(1, 4)), [])

    def test_the_un_repeated_pair_is_a_KNOWN_false_negative(self):
        # Deliberate, and named as such so nobody reads its green as coverage:
        # `_CITE_RE` sees only the first number here, exactly as with a chain. It
        # is permitted because the only live instances of this shape are drift
        # notes quoting a number as data, which a wider rule would over-report.
        self.assertEqual(self._keys(f"ADR-001 {_S}1 and {_S}4"), [])

    def test_canonical_does_not_leak_into_the_mis_anchored_class(self):
        # The canonical form contains `ADR` and a section mark; only a SPACE after
        # `ADR` may match, and there a `-` follows.
        self.assertNotIn("mis-anchored", self._slugs(_canon(4)))

    def test_canonical_does_not_leak_into_the_bare_decision_class(self):
        # The fixed-width lookbehind is what keeps the word form in one class.
        self.assertEqual(self._slugs(_word(3)), ["adr001-decision"])

    def test_a_bare_section_mark_is_not_a_citation(self):
        # Other standards and this repo's own skills use the section mark;
        # flagging them would be sprawl, and none of them is visible to
        # `_CITE_RE` in any spelling.
        for text in (
            "NIST SP 800-61r2 §3.1 / ISO 27035-2 §6",
            "RFC 8259 §7. Handles backslash",
            "path unstable — see §2",
            "the §2/§3 citations were classified",
        ):
            self.assertEqual(self._keys(text), [], text)

    def test_a_word_ending_in_adr_is_not_a_citation(self):
        self.assertEqual(self._keys("MYADR §1"), [])

    # --- the KEY is what makes the baseline trustworthy ------------------------

    def test_a_number_swap_changes_the_key(self):
        # The failure mode a per-file COUNT would hide: same file, same spelling,
        # different decision. Retargeting a grandfathered citation must read as a
        # new entry, not as "still 1 occurrence".
        self.assertNotEqual(
            self._keys(_misanchored(4)),
            self._keys(_misanchored(5)),
            "editing the decision number left the baseline key unchanged, so a "
            "silent retarget of a grandfathered site would pass",
        )

    def test_a_chain_tail_swap_changes_the_key(self):
        self.assertNotEqual(self._keys(_chain(1, 3)), self._keys(_chain(1, 5)))

    def test_a_PAIRWISE_swap_is_a_KNOWN_hole_in_set_equality(self):
        # The precise limit of the baseline, made executable so the docstring
        # cannot drift back to claiming more. Two grandfathered citations in one
        # file trading numbers leave the key SET identical — both are now wrong and
        # nothing fails. A one-way retarget is caught (test above); a permutation is
        # not. Set membership cannot distinguish them, and a per-file count would
        # hide both, which is why the key is still the better choice.
        before = self._keys(f"{_word(1)} then {_word(5)}")
        after = self._keys(f"{_word(5)} then {_word(1)}")
        self.assertEqual(
            sorted(set(before)),
            sorted(set(after)),
            "a pairwise swap now changes the key set — good; update the "
            "'known hole' paragraph in the module docstring",
        )

    def test_a_duplicate_occurrence_is_a_second_key(self):
        # Set semantics would collapse the two, so adding a spelling to a file
        # that already has that exact one would be invisible.
        self.assertEqual(
            self._keys(f"{_misanchored(9)} here\nand {_misanchored(9)} there"),
            [f"{self.OTHER}|mis-anchored|9|#1", f"{self.OTHER}|mis-anchored|9|#2"],
        )

    def test_the_key_carries_no_line_number(self):
        # Reflow-immunity, stated as a test rather than as a promise: the same
        # citation moved down the file keys identically.
        top = self._keys(f"{_misanchored(4)}\n\nfiller\n")
        bottom = self._keys(f"filler\n\n\n\n{_misanchored(4)}\n")
        self.assertEqual(top, bottom)

    def test_chain_separator_whitespace_is_normalized(self):
        base = self._keys(_chain(1, 3))
        for spelling in (f"ADR-001 {_S}1 / {_S}3", f"ADR-001 {_S}1/3"):
            self.assertEqual(self._keys(spelling), base, spelling)

    def test_a_multi_hop_chain_records_every_number(self):
        self.assertEqual(
            self._keys(_chain(1, 3, 5)),
            [f"{self.OTHER}|anchored-chain|1/3/5|#1"],
        )

    # --- HIGH-1: the lookahead must require a DIGIT, not just the mark ----------
    #
    # `_CITE_RE` needs `ADR-001 §\d+`. An exemption for the shorter `ADR-001 §`
    # exempted a SUPERSET, so this whole family was invisible to both matchers.
    # `§§<N>` is the ordinary way to write plural sections.

    def test_the_plural_section_mark_is_detected(self):
        for text in (f"ADR-001 {_S}{_S}4", f"ADR-001 {_S}{_S}4-5"):
            self.assertEqual(self._slugs(text), ["mis-anchored"], text)

    def test_a_gap_or_markup_between_the_mark_and_the_number_is_detected(self):
        for text in (
            f"ADR-001 {_S} 4",
            f"ADR-001 {_S}`4`",
            f"ADR-001 {_S}**4**",
            f"ADR-001 {_S}(4)",
            f"ADR-001 {_S}-4",
        ):
            self.assertEqual(self._slugs(text), ["mis-anchored"], text)

    def test_the_canonical_form_is_still_the_only_exemption(self):
        # The control for the family above: exactly `ADR-001 §<digit>` is exempt,
        # and nothing shorter. If this ever fails the guard has become a false-alarm
        # machine on the encouraged spelling.
        self.assertEqual(self._keys(_canon(4)), [])

    # --- M-2: the chain separator is a class ------------------------------------

    def test_every_chain_separator_is_detected(self):
        for sep in (",", "–", "-", " & ", "+", "; ", "|"):
            text = f"ADR-001 {_S}1{sep}{_S}3"
            self.assertEqual(
                self._keys(text),
                [f"{self.OTHER}|anchored-chain|1/3|#1"],
                f"separator {sep!r} not read as a chain",
            )

    def test_a_number_after_a_comma_is_not_a_chain_tail(self):
        # The false-positive boundary of the separator class: a date following a
        # citation must not key as a chain to decision 2026. This is why every
        # separator except `/` requires the tail's section mark.
        self.assertEqual(self._keys(f"ADR-001 {_S}5, 2026-08-12"), [])

    def test_a_chain_hop_does_not_cross_a_newline(self):
        # Pins the documented `[ \t]`-not-`\s` choice.
        #
        # The first version of this test was VACUOUS and the review's N-2 was right:
        # its fixture read `ADR-001 §5 applies\n/ §6`, where the word "applies"
        # blocks the hop before the newline is ever reached, so swapping `[ \t]` for
        # `\s` left it green. The citation has to END the line for the newline to be
        # the only thing the separator class decides. Verified: with `\s` restored
        # this assertion goes RED.
        self.assertEqual(
            self._keys(f"ADR-001 {_S}5\n/ {_S}6"),
            [],
            "a `/ §N` on the NEXT line was read as a chain tail",
        )

    def test_named_chain_and_anchor_misses(self):
        # The cost of the newline bound above plus two more true misses, named here
        # rather than left for a reader to rediscover. All invisible to `_CITE_RE`
        # too, and all measured at zero live instances on `dc3a959`.
        #
        # The previous version of this test re-asserted the newline fixture from the
        # test above verbatim — two names, one assertion, so the second proved
        # nothing new (review NIT).
        cases = {
            # a genuinely WRAPPED chain: head canonical so nothing fires, tail
            # unanchored. The price of not letting a hop cross a newline.
            "wrapped chain": f"ADR-001 {_S}5\n/ {_S}6",
            # a doubled separator is not a hop
            "doubled separator": f"ADR-001 {_S}1//{_S}3",
            # the anchor AFTER the mark — the reverse word order
            "trailing anchor": f"{_S}4 of ADR-001",
        }
        for label, text in cases.items():
            self.assertEqual(self._keys(text), [], f"{label} is now covered — good, "
                             "but move it out of the named-misses list")

    # --- M-1 / L-3: the wrap and link shapes -----------------------------------

    def test_every_wrap_indent_is_detected(self):
        # A 4- or 8-space continuation is the commonest wrap in this suite, and is
        # exactly where the one live site was found.
        for indent in ("", " ", "  ", "   ", "    ", "        ", "\t", "  - ", "# "):
            text = f"ADR-001\n{indent}{_S}4"
            self.assertEqual(self._slugs(text), ["mis-anchored"], repr(text))

    def test_a_markdown_link_around_the_anchor_is_detected(self):
        # The repo already writes the link form in four places.
        self.assertEqual(
            self._slugs(f"[ADR-001](../devsecops/x.md) {_S}4"), ["mis-anchored"]
        )

    def test_a_four_digit_adr_id_is_detected(self):
        # adr-tools' convention; `_CITE_RE` sees nothing.
        self.assertEqual(self._slugs(f"ADR-0001 {_S}4"), ["mis-anchored"])

    def test_a_chain_after_a_mis_anchored_head_keys_the_whole_sequence(self):
        # Regression pin for the id matcher eating the first number: with a plain
        # `\W` separator in the id, this keyed `|2` instead of `|1/2`.
        self.assertEqual(
            self._keys(_misanchored(1, 2)),
            [f"{self.OTHER}|mis-anchored|1/2|#1"],
        )

    # --- L-2 / L-1: what the tail classes do and do not cover ------------------

    def test_a_lower_case_word_form_is_detected(self):
        self.assertIn("adr001-decision", self._slugs(f"per {_word(4).lower()}"))

    def test_the_word_form_joint_is_not_a_single_space(self):
        # The gap the second pass found: L-2 widened this class's joint from one
        # literal space to `\W{0,3}`, and NOTHING asserted it. Reverting the joint
        # left all 54 tests green while these six shapes lost coverage — the same
        # "widened but unpinned" shape as HIGH-1, one class over.
        for label, joint, word in (
            ("parenthesised", "(", "Decision"),
            ("hyphenated", "-", "Decision"),
            ("bold", " **", "Decision"),
            ("double space", "  ", "Decision"),
            ("colon, lower case", ": ", "decision"),
            ("plural with a hash", " #", "Decisions"),
        ):
            text = _word_joint(joint, 4, word)
            self.assertEqual(
                self._slugs(text),
                ["adr001-decision"],
                f"{label} joint ({text!r}) not read as the word form",
            )

    def test_named_tail_limits_are_still_uncovered(self):
        # Not a wish list: an executable record of what the narrowest class does
        # NOT see, so the next audit does not have to re-derive it. All measured at
        # zero live instances on `dc3a959`. Widening `bare-decision` to reach these
        # was measured to cost live false positives — see the per-commit variant
        # table in that pattern's comment for the numbers.
        for text in (f"{_bare(4)[:-2]}#4", f"{_bare(4)[:-2]}-4", _bare(4).lower()):
            self.assertEqual(self._keys(text), [], f"{text!r} is now covered — "
                             "good, but update the named limits in the docstring")


class TestAdrExemptionIsNarrow(unittest.TestCase):
    """The one exemption, pinned in BOTH directions. Stated as tests because #434
    found the previous exclusion rule written too narrowly in prose to reproduce
    its own count."""

    _XREF = f"{_bare(2)} says bound the haystack; see also {_bare(4, True)} and 6."
    _DATA = f"| skill:71 | {_misanchored(4)} | now the grammar rule |"

    def test_the_adr_may_cross_reference_its_own_items(self):
        self.assertEqual(spelling_findings(self._XREF, ADR_REL), [])

    def test_the_same_text_outside_the_adr_is_flagged(self):
        # Without this, "exempt" could silently mean "unimplemented".
        self.assertEqual(
            [k.split("|")[1] for k in spelling_findings(self._XREF, "docs/x.md")],
            ["bare-decision", "bare-decision"],
        )

    def test_the_adr_is_not_exempt_from_the_other_classes(self):
        self.assertEqual(
            spelling_findings(self._DATA, ADR_REL),
            [f"{ADR_REL}|mis-anchored|4|#1"],
            "the ADR became blanket-exempt; only its own bare cross-references "
            "are prose, and its drift tables are grandfathered one line at a "
            "time so a NEW one is still a review moment",
        )

    def test_exactly_one_class_and_one_glob_are_exempt(self):
        self.assertEqual(
            {k: sorted(v) for k, v in EXEMPT_PATH_GLOBS.items()},
            {"bare-decision": ["docs/devsecops/adr-[0-9]*.md"]},
        )
        # The glob must actually cover the ADR the numbering guard reads, so the
        # exemption is not silently pointing at nothing.
        self.assertTrue(
            any(fnmatch(ADR_REL, g) for g in EXEMPT_PATH_GLOBS["bare-decision"]),
            f"the exempt glob no longer matches {ADR_REL}",
        )

    def test_a_future_adr_may_cross_reference_its_own_items(self):
        # `adr-index.md` documents `adr-NNN` as a sequential series and says to
        # record a changed decision as a NEW ADR, so the first `adr-002` must not
        # fail this guard on its own prose. The hardcoded single path did.
        for rel in (
            "docs/devsecops/adr-002-something.md",
            "docs/devsecops/adr-0007-four-digit.md",
        ):
            self.assertEqual(spelling_findings(self._XREF, rel), [], rel)

    def test_the_exemption_does_not_leak_past_the_adr_series(self):
        # Non-vacuity for the GLOB form specifically: an index (which cites ADRs
        # rather than defining decisions) and a same-named file in another
        # directory are both still scanned.
        for rel in (
            "docs/devsecops/adr-index.md",
            "docs/reports/adr-002-retrospective.md",
            "scanner/tests/test_ci_adr_002.py",
        ):
            self.assertEqual(
                [k.split("|")[1] for k in spelling_findings(self._XREF, rel)],
                ["bare-decision", "bare-decision"],
                f"the exempt glob wrongly covers {rel}",
            )


class TestRealFileMutation(unittest.TestCase):
    """Non-vacuity against real on-disk text: the detector must be quiet on the
    file as committed and fire on a canonical citation degraded to each forbidden
    spelling. Synthetic fixtures alone cannot show that the real population is
    clean AND that the guard would notice the regression in it."""

    # A file with canonical citations and zero grandfathered entries, so "quiet on
    # clean" is a real measurement rather than a baseline subtraction. (The catalog
    # would NOT do: it now carries the one entry this PR added.)
    TARGET_REL = "docs/reports/adr-001-q3-audit-retrospective.md"

    @classmethod
    def setUpClass(cls):
        cls.clean = (REPO_ROOT / cls.TARGET_REL).read_text(encoding="utf-8")

    def _detector(self, text):
        return sorted(set(spelling_findings(text, self.TARGET_REL)) - GRANDFATHERED)

    # That decision is cited exactly once in the target, so this anchor is
    # unambiguous — `apply_mutation` would rewrite every occurrence otherwise, and
    # the count assertion below is what keeps the fixture honest as the file grows.
    ANCHOR = _canon(5)

    def test_target_has_canonical_citations_to_degrade(self):
        # Fixture canary: with no canonical citation present, every mutation below
        # would be stale and `apply_mutation` would be the only thing failing.
        self.assertEqual(self.clean.count(self.ANCHOR), 1)
        self.assertEqual(self._detector(self.clean), [])

    def test_each_degradation_of_a_real_citation_is_caught(self):
        cases = {
            "mis-anchored": _misanchored(5),
            "adr001-decision": _word(5),
            "anchored-chain": _chain(5, 9),
            "bare-decision": _bare(5),
        }
        for slug, new in cases.items():
            with self.subTest(slug=slug):
                mutant = apply_mutation(self.clean, self.ANCHOR, new)
                found = assert_disables(self._detector, self.clean, mutant, label=slug)
                self.assertEqual(
                    [k.split("|")[1] for k in found],
                    [slug],
                    f"the mutant was caught, but not as {slug}: {found}",
                )

    def test_a_canonical_addition_to_a_real_file_stays_quiet(self):
        # The inverse control. An absence assertion is worth nothing unless the
        # same harness can be shown to produce a finding (it is, above) and unless
        # adding the ENCOURAGED form produces none.
        added = apply_mutation(self.clean, self.ANCHOR, _canon(5, 1))
        self.assertEqual(self._detector(added), [])


class TestScopeIsSharedWithTheNumberingGuard(unittest.TestCase):
    def test_globs_come_from_the_numbering_guard(self):
        # Single source: the population this guard polices IS that guard's scan.
        # A second hand-maintained glob list is where the two would drift apart.
        import test_ci_adr_decision_numbering as numbering

        self.assertIs(_CITED_GLOBS, numbering._CITED_GLOBS)
        self.assertTrue(_CITED_GLOBS, "the shared glob tuple is empty")

    def test_adr_rel_comes_from_the_numbering_guard(self):
        import test_ci_adr_decision_numbering as numbering

        self.assertEqual(ADR_REL, numbering.ADR_REL)
        self.assertTrue((REPO_ROOT / ADR_REL).is_file(), f"{ADR_REL} not on disk")


if __name__ == "__main__":
    unittest.main()
