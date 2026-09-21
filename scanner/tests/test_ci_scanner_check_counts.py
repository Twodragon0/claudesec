r"""
Regression guard: README's `Scanner Categories` table states the number of
checks each category actually implements, and the Scanner CLI paragraph states
the real total.

WHY THIS GUARD EXISTS
---------------------
The table drifted silently. Measured on `origin/main` at the time of writing,
three of eleven rows were wrong and one carried a hedge instead of a number:

    infra           16 stated, 18 implemented
    access-control   6 stated, 10 implemented
    saas            33 stated, 49 implemented
    network         "5+" stated, 10 implemented

and the prose said `~120+ checks` against a real 198. Nothing failed, because
nothing compared them. A README count is the first number a reader trusts and
the last one anybody re-measures, so the drift direction that matters is the
flattering one: `saas` understated by 16 checks reads as modesty, while the same
mechanism would let a row claim checks that do not exist.

DIRECTION: EQUALITY, code-authoritative.
    Adding a check without updating README fails. Editing a README number
    without adding checks fails. Adding a category directory with no README row
    fails. Deleting a row fails. There is no direction in which a stated number
    and the tree may disagree.

WHY THE CODE IS THE SINGLE SOURCE AND README IS THE DERIVATIVE (direction 1)
----------------------------------------------------------------------------
The catalog guards went the other way — they moved their inventory into
`ci-guard-inventory.toml` so that no Markdown sits between a guard and its
invariant (ADR-001 §5; `test_ci_catalog_completeness`'s docstring). That was
right THERE because the authority was the prose: the inventory existed only in
the document, so a row hidden from readers let a guard certify coverage that no
reader could see.

Here the authority is already the tree. `scanner/checks/<category>/` and the
check IDs inside it are the fact; README restates it. Introducing a TOML
inventory (direction 2) would add a third copy of a number that the code already
states unambiguously, and the code→inventory comparison it buys is one this
guard gets directly from the filesystem. So: no new artifact.

That inversion also flips most of the Markdown scan-evasion class from a silent
pass into a loud failure. A README row hidden in a closed comment, a code fence,
an HTML block, or after an unterminated `<!--` is REMOVED by `rendered_markdown`
— so this guard sees a missing row and fails, where the catalog guards would
have seen a row that is not there. Fail-closed is the default here, not the
exception.

THE RESIDUAL, STATED HONESTLY
-----------------------------
`rendered_markdown` is a stdlib reduction of four enumerated constructs, not a
CommonMark implementation, and it carries a MEASURED residual of 14 shapes where
it keeps a row a browser does not show (pinned as a ceiling by
`test_ci_markdown_scan_evasion.TestTheResidualIsBounded`). In those shapes this
guard reads a correct table that a reader receives as nothing — green while the
published table is invisible. Every set comparison computed FROM the reduction
necessarily agrees with itself, so no amount of comparing here can catch it.

`TestTheTableAgreesWithTheRenderer` is that hole closed rather than declared, by
adjudicating the real README against `markdown-it-py` instead of against the
reduction — the same move `test_ci_catalog_doc_sync` made for the catalog. It
skips without the oracle so the package-free `ci-guards` job stays package-free,
and it is registered in `_ci_canary_runner.ADJUDICATORS` (pinned equal to
`test_ci_guard_self_verify.CANARY_CLASSES`) so the `renderer-canary` job runs it
with the pinned oracle installed. Do not move or rename that class without
updating both tuples.

What is left after that is the ordinary scope of any count: this measures check
IDs EMITTED by `pass`/`fail`/`warn`/`skip` call sites, which is what the scanner
can report, not what it executes on a given run. A check that is implemented but
unreachable still counts. That is the same denominator the README sentence
means, and narrowing it would need a runtime, not a better regex.

WHY ID PREFIX IS NOT THE UNIT — the directory is
------------------------------------------------
The obvious implementation maps README categories to ID prefixes (`infra`→INFRA,
`code`→CODE-INJ|CODE-SEC|CODE-SAST, …). That needs a hand-written prefix→
category table inside this guard, which is precisely the drift this file exists
to stop, one level up — and it has already been measured wrong here: an
enumeration of `SAAS`, `SAAS-API` and `SAAS-ZIA` misses `AUDIT-001`
(`scanner/checks/saas/audit-points.sh`), understating `saas` by one.

`scanner/checks/<category>/` needs no table: the directory names ARE the
category names the README table keys on, and every ID lives in exactly one of
them. ADR-001 §5 — prefer a rule complete by the grammar over an enumeration.
`test_the_categories_partition_every_id` pins the property that makes this sound
(the per-directory counts sum to the repo-wide unique count), so an ID emitted
outside `scanner/checks/*/`, or double-counted across two directories, fails
here rather than quietly skewing a row.

ROWS WHOSE UNIT IS NOT CHECKS
-----------------------------
`prowler` states `16 providers`, not a check count, and is exempt BY NAME in
`UNIT_EXEMPT` with its reason and its real authority. It is not skipped
silently: `test_exempt_rows_are_present_and_still_not_counts` asserts the row
exists and still does not state a bare number, so deleting the row, or quietly
converting it to a check count, fails here.

CONSTRAINTS (same as every guard in this directory)
---------------------------------------------------
stdlib-only on the default path (`re` + `pathlib` + the shared reduction; no
PyYAML, no `tomllib` need). No network, no subprocess. Does not import
`scanner/lib`, so it never moves the measured coverage gate. Passes under pytest
(the `scanner-unit-tests` runner) and `python3 -m unittest` (the package-free
`ci-guards` runner).

REACHABILITY: both entry points are covered by existing diff buckets, verified
against `lint.yml` rather than assumed. A PR adding a check touches
`scanner/checks/**`, which matches the `scanner` bucket (`^(scanner/|…)`) and
runs this under pytest. A PR editing only the README touches `README.md`, which
matches the `ci_config` bucket (`[^/]*\.md$`) and runs this under `ci-guards`.
Neither path needs a new `lint.yml` entry.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    rendered_markdown,
    strip_inline_comment_sh,
)

CHECKS_DIR = REPO_ROOT / "scanner" / "checks"
README = REPO_ROOT / "README.md"

#: Category rows whose `Checks` cell is deliberately NOT a check count, with the
#: unit it actually states and where that number's authority lives. Named here
#: rather than skipped inside a loop so the exemption is visible to a reviewer
#: and so the two tests below can assert the row is still there and still not a
#: count — an exemption that silently covers a deleted row protects nothing.
UNIT_EXEMPT = {
    "prowler": (
        "the cell states `16 providers` — Prowler PROVIDERS, not checks. The "
        "integration emits 17 unique literal IDs: `PROWLER-001` plus one "
        "`PROWLER-<provider>-001` for each of the 16 providers. So the row "
        "would be wrong either way — 16 is not the check count, and the check "
        "count is not what the cell means. The 16 is already guarded at its "
        "real source: `test_ci_provider_labels_sync` pins `PROVIDER_LABELS` at "
        "exactly 16 entries and pins the bash mirror equal to it. "
        "An earlier version of this note said 14 provider IDs and read the "
        "16-vs-14 gap as a real shortfall in the integration. That gap was an "
        "artifact of a too-narrow extraction pattern, which could not see "
        "`PROWLER-K8S-001` or `PROWLER-M365-001` because of the digits inside "
        "their middle segment. The providers and the IDs agree at 16."
    ),
}

#: The categories that MUST exist, as a literal floor.
#:
#: Every other comparison in this file derives both sides from the tree, which
#: makes them all blind in exactly one direction: delete
#: `scanner/checks/<category>/` AND its README row AND adjust the total, and
#: every set relation is satisfied by the smaller tree. MEASURED on this guard
#: before this constant existed — removing `scanner/checks/saas/` (49 checks),
#: its row, and retotalling to `10 categories (144 checks)` left all 19 tests
#: GREEN. That is a silent loss of a quarter of the scanner's coverage, and no
#: amount of internal consistency notices it, because consistency is the thing
#: the deletion preserved.
#:
#: So the floor is a LITERAL and deliberately not derived. Adding a category
#: does NOT require touching this list — the filesystem comparisons handle the
#: additive direction — but REMOVING one fails until a human deletes the name
#: here. That is the point: a reviewable one-line edit that says "we dropped
#: saas" is fine; losing it to a refactor is not. Counts are absent on purpose,
#: since those legitimately move on every PR while the names do not.
KNOWN_CATEGORIES = frozenset({
    "access-control",
    "ai",
    "cicd",
    "cloud",
    "code",
    "infra",
    "macos",
    "network",
    "prowler",
    "saas",
    "windows",
})

#: A LITERAL check ID: the first argument to one of the four result helpers.
#:
#: SCOPE, stated first because the previous version of this comment overclaimed
#: and the claim was false. What is counted is the number of check IDs WRITTEN
#: AS LITERALS. Three call sites assemble the ID at runtime —
#: `warn "${check_id_prefix}-000"`, `pass "${check_id_prefix}-001"`,
#: `fail "${check_id_prefix}-001"` in `scanner/checks/prowler/integration.sh` —
#: and no literal scan of any kind can see what those expand to, because the
#: value does not exist until the shell runs. They are excluded and DECLARED, in
#: `_RUNTIME_ASSEMBLED` below, not silently dropped.
#:
#: The comment this replaces said a sweep "found every call site matches this
#: shape and none constructs the ID from a variable, so the extraction is
#: complete rather than best-effort". Both halves were wrong, and the way they
#: were wrong is worth recording: the sweep was
#: `git grep -hoE '\b(pass|fail|...)'`, and `\b` is not supported by git grep's
#: ERE engine, so it matched ZERO lines. Piping zero lines into a `grep -v`
#: filter prints nothing, and nothing was read as "no non-conforming shapes".
#: A vacuous measurement with no canary on its own denominator — exactly what
#: ADR-001 §4 means by proving the harness can produce a RED before trusting a
#: green. The correct sweep returns 666 lines and 200 distinct first arguments.
#:
#: The pattern is also WIDER than the one it replaces, which missed five real
#: IDs: `[A-Z]+(-[A-Z]+)?-[0-9]+` required a numeric tail and at most one
#: hyphenated middle, so `TRIVY-CRIT`, `TRIVY-HIGH`, `TRIVY-MED` (no numeric
#: tail) and `PROWLER-K8S-001`, `PROWLER-M365-001` (digits inside a middle
#: segment) were invisible. That understated `network` as 7 against 10,
#: `prowler` as 15 against 17, and the total as 193 against 198.
_ID_CALL = re.compile(r'(?:pass|fail|warn|skip) +"([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)"')

#: EVERY literal first argument to the four helpers, whatever its shape. The
#: denominator for `test_the_extraction_sees_every_call_site`, which is the
#: canary on `_ID_CALL`'s own coverage.
_ANY_CALL = re.compile(r'(?:pass|fail|warn|skip) +"([^"]*)"')

#: A first argument that is assembled at runtime rather than written out.
#: Matched at the START, so `${prefix}-001` is recognised while a literal that
#: merely contains a `$` later is not quietly excused.
_RUNTIME_ASSEMBLED = re.compile(r"^\$[{(]?[A-Za-z_]")

#: A `Scanner Categories` row: `| \`<category>\` | <cell> | <covers> |`.
#:
#: The category is captured SEPARATELY from the count, and the count group is
#: `[^|]*`, which matches EMPTY. Deliberate, and it is the property an
#: inverse-mutation pass has to check: a matcher that gathered rows by "there is
#: a number here" would drop a row whose number was deleted at the EXTRACTION
#: step, so the assertion about numbers would never see the one edit it exists
#: to catch. Rows are gathered by category NAME and the cell is read afterwards,
#: which is what makes `stated_count` returning None a detectable state rather
#: than an invisible one.
_ROW = re.compile(
    r"^\|\s*`([a-z][a-z-]*)`\s*\|([^|]*)\|[^|]*\|\s*$", re.MULTILINE
)

#: The heading the category table lives under. The haystack is SCOPED to this
#: section before `_ROW` runs (ADR-001 §2 — bound the haystack, then match).
#:
#: A MEASURED false positive, not a hypothetical. Unscoped, `_ROW` matches any
#: three-column row in the README whose first cell is a backticked lowercase
#: word. Adding an ordinary options table elsewhere in the file —
#: `| \`verbose\` | 0 | chatty |` — made the guard report `verbose` as a
#: category with no directory. It passed only because no such table happened to
#: exist yet, in a 1000-line README full of tables. A false positive is not a
#: harmless over-report: it fails a PR that did nothing wrong, which is how a
#: guard comes to be deleted.
_SECTION = "### Scanner Categories"

#: The `Scanner CLI` sentence's total. `(\d+) checks` inside the parenthesis,
#: anchored on the category count so a number elsewhere in the prose cannot
#: satisfy it.
_TOTAL = re.compile(r"across\s+(\d+)\s+categories\s+\((\d+)\s+checks\)")


def category_dirs():
    """`scanner/checks/*/` directory names — the category vocabulary.

    The filesystem rather than a literal list, for the reason in the header: a
    hand-written list of categories inside the guard that checks the README's
    hand-written list of categories is two copies of the same claim and no
    authority over either."""
    return sorted(p.name for p in CHECKS_DIR.iterdir() if p.is_dir())


def active_shell(text: str) -> str:
    """`text` with bash comments removed, line by line.

    ADR-001 §1: a token surviving only in a comment must never satisfy an
    invariant — and here it would not merely satisfy one, it would INFLATE a
    count. `scanner/checks/network/scan-tools.sh:48` already carries
    `# warn "command substitution: 1 unterminated here-document" at source
    time.`, a documentation line whose text is shaped exactly like a live call.
    It happens not to match `_ID_CALL` today, so it changes no number; the
    exposure is that widening the pattern is what makes such a line countable,
    and the widening is the other half of this change.

    `strip_inline_comment_sh`, not `strip_inline_comment`: these are shell
    files, where `#` opens a comment after a metacharacter with no intervening
    space, and the shared helper is quote-aware so a `#` inside a message string
    survives."""
    return "\n".join(strip_inline_comment_sh(l) for l in text.splitlines())


def first_args(path: Path):
    """`(all literal first arguments, those counted as IDs)` under `path`.

    Both from the same comment-stripped text, so the canary and the count can
    never disagree about their denominator."""
    every, ids = set(), set()
    for f in sorted(path.rglob("*")):
        if not f.is_file():
            continue
        text = active_shell(f.read_text(encoding="utf-8", errors="replace"))
        every.update(_ANY_CALL.findall(text))
        ids.update(_ID_CALL.findall(text))
    return every, ids


def ids_in(path: Path):
    """The set of unique LITERAL check IDs emitted anywhere under `path`.

    A SET, because an ID is emitted from several call sites — one per verdict
    branch — and the README states how many checks exist, not how many ways each
    can end."""
    return first_args(path)[1]


def code_counts():
    """`{category: number of unique check IDs}` from the tree."""
    return {name: len(ids_in(CHECKS_DIR / name)) for name in category_dirs()}


def category_section(text):
    """The `### Scanner Categories` section only, as a READER sees it.

    ORDER: reduce, THEN slice. Not interchangeable. `rendered_markdown` runs on
    the whole document first so that an unterminated `<!--` ABOVE the heading
    swallows the heading too and this returns nothing — which is the behaviour
    `test_ci_markdown_scan_evasion.test_no_detector_sees_a_row_under_a_hidden_ANCHOR`
    exists to demand. Slicing first and reducing the slice would find the
    heading in raw text and so never notice that a reader lost it.

    Bounded by the next heading at level 1-3, so a new `####` subsection inside
    the table's section does not truncate it while a sibling `###` does."""
    reduced = rendered_markdown(text)
    start = reduced.find(_SECTION)
    if start == -1:
        return ""
    rest = reduced[start + len(_SECTION):]
    nxt = re.search(r"(?m)^#{1,3} ", rest)
    return rest[: nxt.start()] if nxt else rest


def doc_rows(text):
    """`{category: cell text}` from the README's category table, as a READER
    sees it.

    Scoped to the table's own section and reduced before the match — see
    `category_section` for the ordering constraint, and `_SECTION` for the
    measured false positive that the scoping closes."""
    return {m.group(1): m.group(2).strip() for m in _ROW.finditer(category_section(text))}


def stated_count(cell):
    """The integer a `Checks` cell states, or None if it states no bare number.

    `None` is a verdict, not an error: it is what makes `5+`, `16 providers` and
    an empty cell all fail the count comparison rather than parse to something
    convenient. `int(cell)` on the whole stripped cell — deliberately not a
    `\\d+` search, which would read `16` out of `16 providers` and silently turn
    a providers row into a checks row."""
    try:
        return int(cell)
    except ValueError:
        return None


class TestTheMeasurementIsSound(unittest.TestCase):
    """Canaries. Every comparison below is a set or dict relation, and each one
    passes vacuously if its operands are empty — the failure mode ADR-001 §4
    calls out and the reason these run first."""

    def test_the_checks_tree_is_where_this_thinks_it_is(self):
        self.assertTrue(
            CHECKS_DIR.is_dir(),
            f"{CHECKS_DIR} is not a directory — the path assumption broke and "
            "every count below would be zero",
        )

    def test_categories_are_found(self):
        self.assertTrue(category_dirs(), f"no category directories under {CHECKS_DIR}")

    def test_every_category_emits_at_least_one_id(self):
        # A category whose IDs the pattern cannot see would report 0 and demand
        # a README edit to `0`, which is the one wrong answer this guard could
        # talk someone into making.
        empty = sorted(c for c, n in code_counts().items() if n == 0)
        self.assertEqual(
            empty,
            [],
            f"category directories emit no recognisable check ID: {empty}. "
            "Either they are empty, or the IDs are written in a shape "
            "`_ID_CALL` does not match — fix the pattern, do not write 0 into "
            "the README.",
        )

    def test_the_extraction_sees_every_call_site(self):
        """The canary on `_ID_CALL`'s own coverage — the axis that had NO
        detector, and the one that let five real IDs go uncounted.

        The comment on `_ID_CALL` used to claim `partition_every_id` covered
        this. It does not, and the claim is self-contradicting: an ID the
        pattern cannot see is missing from BOTH operands, so `sum(per-dir) ==
        len(repo-wide)` still holds. Verified — that test passed while
        `TRIVY-CRIT`, `TRIVY-HIGH`, `TRIVY-MED`, `PROWLER-K8S-001` and
        `PROWLER-M365-001` were all invisible.

        So this compares against a genuinely different denominator: EVERY
        literal first argument to the four helpers, whatever its shape. Each one
        must either be counted as an ID or be a declared runtime assembly.
        Anything else is a shape the extraction cannot see, and it fails here
        naming the offender rather than quietly lowering a number.

        LIMIT, because this does not close infinitely and should not read as if
        it did: `_ANY_CALL` is itself a pattern. It is complete over `<helper>
        "<literal>"` by the shell grammar, which is the whole call syntax in
        use, so the residual is not "a cleverer literal" — it is a call whose
        HELPER NAME changes (caught by `test_every_category_emits_at_least_one_id`
        driving a category to zero) or an ID assembled at runtime, which is
        unreachable by construction and declared below."""
        every, ids = first_args(CHECKS_DIR)
        self.assertTrue(every, "no helper call sites found at all — sweep broke")
        unseen = sorted(
            a for a in every - ids if not _RUNTIME_ASSEMBLED.match(a)
        )
        self.assertEqual(
            unseen,
            [],
            "first argument(s) to pass/fail/warn/skip that `_ID_CALL` does not "
            f"recognise as a check ID: {unseen}. Each is a check the counts do "
            "not include, so every README number is understated by the ones in "
            "this list. Widen `_ID_CALL`, or — if the string genuinely is not a "
            "check ID — say so here rather than leaving it to be rediscovered.",
        )

    def test_runtime_assembled_ids_are_declared_not_silent(self):
        """The honest residual, asserted so it stays visible and stays small.

        `${check_id_prefix}-001` cannot be resolved by any literal scan; the
        value does not exist until the shell runs. Excluding it is the only
        option, so the thing worth guarding is that the exclusion is a KNOWN,
        BOUNDED set rather than a growing quiet one. If a fourth runtime call
        site appears, this fails and a human decides whether the counts are
        still meaningful."""
        every, ids = first_args(CHECKS_DIR)
        runtime = sorted(a for a in every - ids if _RUNTIME_ASSEMBLED.match(a))
        self.assertEqual(
            runtime,
            ["${check_id_prefix}-000", "${check_id_prefix}-001"],
            f"the set of runtime-assembled check IDs changed: {runtime}. These "
            "are invisible to every literal scan, so they are excluded from the "
            "counts and the README understates the scanner by however many they "
            "expand to at run time. A change here means re-deciding whether a "
            "literal count is still the right denominator.",
        )

    def test_the_categories_partition_every_id(self):
        """The per-directory counts sum to the repo-wide unique count.

        This is what makes the directory the sound unit rather than merely a
        convenient one. It fails if an ID is emitted from two different category
        directories (double-counted, so two rows are inflated and the total is
        wrong) or from `scanner/checks/` itself outside any category (counted in
        no row at all, so the total silently disagrees with the rows). Either
        one would leave the per-row assertions green while the total lied."""
        counts = code_counts()
        every = ids_in(CHECKS_DIR)
        self.assertEqual(
            sum(counts.values()),
            len(every),
            "check IDs are not partitioned by category directory: the rows sum "
            f"to {sum(counts.values())} but {len(every)} unique IDs exist under "
            f"{CHECKS_DIR}. An ID shared between two categories, or emitted "
            "outside `scanner/checks/<category>/`, breaks the per-row counts.",
        )

    def test_no_known_category_has_silently_disappeared(self):
        """The floor. The one direction every derived comparison is blind to.

        See `KNOWN_CATEGORIES` for the measurement: without this, deleting a
        category directory together with its README row and the total left all
        19 tests green while 49 checks left the product. Asserted against BOTH
        sides, because a category can be lost from the tree (coverage gone) or
        from the published table (coverage undocumented) independently."""
        dirs = set(code_counts())
        rows = set(doc_rows(README.read_text(encoding="utf-8")))
        gone_from_tree = sorted(KNOWN_CATEGORIES - dirs)
        gone_from_doc = sorted(KNOWN_CATEGORIES - rows)
        self.assertEqual(
            gone_from_tree,
            [],
            f"category directory has disappeared: {gone_from_tree}. Every other "
            "check here compares the tree against the README, so both agree on "
            "a tree that lost a whole category. If the removal is intentional, "
            "delete the name from `KNOWN_CATEGORIES` in the same commit — that "
            "edit is the review moment this floor exists to force.",
        )
        self.assertEqual(
            gone_from_doc,
            [],
            f"category no longer has a README row: {gone_from_doc}. The checks "
            "may still exist while nothing documents them.",
        )

    def test_the_floor_does_not_block_a_new_category(self):
        # The floor must be a FLOOR. If it were an equality, adding a category
        # would fail here instead of failing the README comparison with a
        # useful message — and the fix would be to edit this list, which is
        # exactly the two-copies-of-one-claim shape the header rejects.
        self.assertTrue(
            KNOWN_CATEGORIES <= set(code_counts()),
            "`KNOWN_CATEGORIES` names a category with no directory — it is a "
            "floor, so it must be a SUBSET of what exists",
        )

    def test_the_readme_table_is_found(self):
        rows = doc_rows(README.read_text(encoding="utf-8"))
        self.assertTrue(
            rows,
            "no `Scanner Categories` rows parsed out of README.md. Either the "
            "table was restructured, or it is hidden from readers by a comment, "
            "a fence or an HTML block — `rendered_markdown` removes all three.",
        )


class TestTheReadmeTableMatchesTheTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = doc_rows(README.read_text(encoding="utf-8"))
        cls.counts = code_counts()

    def test_every_category_has_a_row(self):
        missing = sorted(set(self.counts) - set(self.rows))
        self.assertEqual(
            missing,
            [],
            f"category directory with no README row: {missing}. A new category "
            "under `scanner/checks/` must be added to the `Scanner Categories` "
            "table in the same commit.",
        )

    def test_no_row_names_a_category_that_does_not_exist(self):
        extra = sorted(set(self.rows) - set(self.counts))
        self.assertEqual(
            extra,
            [],
            f"README row(s) for categories with no directory: {extra}. Either "
            f"the category was deleted and the row outlived it, or the row's "
            "first column does not match the directory name.",
        )

    def test_each_row_states_the_implemented_count(self):
        wrong = {}
        for category, count in sorted(self.counts.items()):
            if category in UNIT_EXEMPT or category not in self.rows:
                continue
            stated = stated_count(self.rows[category])
            if stated != count:
                wrong[category] = (self.rows[category], count)
        self.assertEqual(
            wrong,
            {},
            "README states a check count the tree does not implement "
            "{category: (stated, measured)}: "
            f"{wrong}. The tree is authoritative — edit the README, and note "
            "that a cell stating anything other than a bare integer (`5+`, "
            "`~20`) reads as no count at all and lands here.",
        )

    def test_the_total_matches_the_sum_of_the_rows(self):
        text = rendered_markdown(README.read_text(encoding="utf-8"))
        match = _TOTAL.search(text)
        self.assertIsNotNone(
            match,
            "the `Scanner CLI` paragraph no longer states "
            "`across N categories (M checks)`. That sentence is the first count "
            "a reader meets, so it is asserted rather than left to prose.",
        )
        categories, total = int(match.group(1)), int(match.group(2))
        self.assertEqual(
            categories,
            len(self.counts),
            f"the prose says {categories} categories; {len(self.counts)} "
            f"directories exist under {CHECKS_DIR}",
        )
        self.assertEqual(
            total,
            sum(self.counts.values()),
            f"the prose says {total} checks; the tree implements "
            f"{sum(self.counts.values())}. This total counts EVERY category "
            "including `prowler`, whose ROW states providers — the row's "
            "exemption is about the unit in that cell, not about whether its "
            "checks exist.",
        )

    def test_exempt_rows_are_present_and_still_not_counts(self):
        """An exemption must keep having a subject.

        Two ways `UNIT_EXEMPT` could come to excuse nothing, both silent without
        this: the row is deleted (and the count assertion above skips a row that
        is not there), or the cell is quietly changed to a bare integer (and the
        assertion above skips a number nobody checks). Neither is caught by the
        equality tests, because both operands are derived from the same skip."""
        for category, why in sorted(UNIT_EXEMPT.items()):
            with self.subTest(category=category):
                self.assertIn(
                    category,
                    self.rows,
                    f"`{category}` is exempt from the count comparison but has "
                    f"no README row. Drop the `UNIT_EXEMPT` entry, or restore "
                    f"the row. Reason on file: {why}",
                )
                self.assertIsNone(
                    stated_count(self.rows[category]),
                    f"`{category}`'s cell now states a bare number "
                    f"({self.rows[category]!r}), so it is no longer the "
                    "different-unit row `UNIT_EXEMPT` excuses. Remove the "
                    "exemption so the count is actually checked, or restore the "
                    "unit to the cell.",
                )

    def test_the_exemption_is_not_a_blanket(self):
        # An exemption for a category that does not exist is dead text, and one
        # that grew to cover every row would disable this guard while leaving
        # every test name in place.
        unknown = sorted(set(UNIT_EXEMPT) - set(self.counts))
        self.assertEqual(
            unknown, [], f"`UNIT_EXEMPT` names non-existent categories: {unknown}"
        )
        self.assertLess(
            len(UNIT_EXEMPT),
            len(self.counts),
            "every category is exempt — the count comparison now asserts "
            "nothing while reading green",
        )


class TestTheDetectorIsNotInert(unittest.TestCase):
    """Mutation self-tests on the real functions (ADR-001 §4).

    Synthetic documents and synthetic trees only — nothing here writes to the
    repository, and each case drives the SAME function the assertions above use,
    so a rename or a reordering fails here rather than leaving a surrogate
    green."""

    @staticmethod
    def doc(*rows):
        """A synthetic README carrying `rows` inside the real section heading.

        The heading is not decoration: `doc_rows` is section-SCOPED, so a
        fixture without it exercises the empty-section path and would make every
        `assertNotIn` below pass for the wrong reason."""
        return f"# R\n\n{_SECTION}\n\n" + "\n".join(rows) + "\n"

    def test_a_wrong_number_is_detected(self):
        rows = doc_rows(self.doc("| `infra` | 16 | Docker |"))
        self.assertEqual(stated_count(rows["infra"]), 16)
        self.assertNotEqual(
            stated_count(rows["infra"]), 18, "the comparison is a real inequality"
        )

    def test_a_row_with_the_number_deleted_is_still_EXTRACTED(self):
        """The pre-filtering trap, pinned.

        If `_ROW` required a number, deleting one would remove the row at the
        extraction step and `test_each_row_states_the_implemented_count` would
        never see the edit it exists to catch — the guard would be vacuous in
        precisely its headline direction. The row must survive extraction and
        the CELL must read as no count."""
        for cell in (" ", " several ", " ~18 "):
            with self.subTest(cell=cell):
                rows = doc_rows(self.doc(f"| `infra` |{cell}| Docker |"))
                self.assertIn(
                    "infra", rows, "the row vanished at extraction, not at the "
                    "assertion — the matcher pre-filters on the asserted value"
                )
                self.assertIsNone(stated_count(rows["infra"]))

    def test_rows_outside_the_section_are_not_categories(self):
        """The measured false positive, pinned.

        An unrelated three-column table with a backticked lowercase first cell
        is ordinary README content and must not be read as a category row."""
        other = "| `verbose` | 0 | chatty |"
        self.assertEqual(doc_rows(f"# R\n\n## Options\n\n{other}\n"), {})
        both = (
            f"# R\n\n## Options\n\n{other}\n\n{_SECTION}\n\n"
            "| `infra` | 18 | Docker |\n"
        )
        self.assertEqual(doc_rows(both), {"infra": "18"})

    def test_the_section_ends_at_the_next_heading(self):
        # A row belonging to a LATER section must not be absorbed, or a table
        # added below would inject phantom categories.
        doc = (
            f"# R\n\n{_SECTION}\n\n| `infra` | 18 | Docker |\n\n"
            "## Project Structure\n\n| `ghost` | 3 | nope |\n"
        )
        self.assertEqual(doc_rows(doc), {"infra": "18"})

    def test_a_missing_section_yields_no_rows(self):
        # Fail-closed: if the heading is renamed, every category reads as
        # missing (a loud failure) rather than the table reading as correct.
        self.assertEqual(doc_rows("# R\n\n| `infra` | 18 | Docker |\n"), {})

    def test_a_hedge_is_not_a_count(self):
        # `5+` and `~20` read as a number to a human and to a `\d+` search. They
        # must read as NO count here, or a row can dodge the comparison by
        # adding one character.
        for cell in ("5+", "~20", "16 providers", "", "—", "18 "):
            with self.subTest(cell=cell):
                got = stated_count(cell)
                self.assertTrue(
                    got is None or cell.strip().isdigit(),
                    f"{cell!r} parsed as the count {got}",
                )
        self.assertIsNone(stated_count("5+"))
        self.assertIsNone(stated_count("16 providers"))
        self.assertEqual(stated_count("18 "), 18)

    def test_a_row_hidden_from_readers_is_not_a_row(self):
        # The fail-closed direction this guard depends on. A row the reader
        # cannot see must read as MISSING (which fails
        # `test_every_category_has_a_row`), never as present-and-correct.
        row = "| `infra` | 18 | Docker |"
        self.assertIn("infra", doc_rows(self.doc(row)))
        for label, body in (
            ("closed-comment", f"<!--\n{row}\n-->"),
            ("code-fence", f"```\n{row}\n```"),
            ("html-block", f"<div>\n{row}\n</div>"),
            ("unclosed-comment", f"<!-- retiring this\n{row}"),
        ):
            with self.subTest(vector=label, position="around-row"):
                self.assertNotIn("infra", doc_rows(self.doc(body)))
        # The vector ABOVE the anchor, which is the stronger case: it hides the
        # heading too, so a detector that sliced the section out of RAW text
        # before reducing would still find the row. That is the ordering
        # `category_section` pins.
        hidden_anchor = (
            f"# R\n\n<!-- retiring the whole section\n\n{_SECTION}\n\n{row}\n"
        )
        self.assertEqual(
            doc_rows(hidden_anchor),
            {},
            "a row under an anchor an unterminated opener already swallowed was "
            "still read — the reduction is running after the slice, not before",
        )

    def test_the_id_pattern_requires_a_helper_call(self):
        # An ID in prose, in a comment, or in a variable assignment is not an
        # emitted check. Without this the count would inflate on documentation.
        self.assertEqual(_ID_CALL.findall('pass "INFRA-001" "x"'), ["INFRA-001"])
        self.assertEqual(_ID_CALL.findall('fail "SAAS-API-012" "x"'), ["SAAS-API-012"])
        self.assertEqual(_ID_CALL.findall('# see INFRA-001 for context'), [])
        self.assertEqual(_ID_CALL.findall('_id="INFRA-001"'), [])

    def test_the_id_pattern_sees_the_five_it_used_to_miss(self):
        """Regression pin on the widening, by ID rather than by count.

        A count assertion would have gone green again the moment the numbers
        were edited to match a still-broken pattern. These are the five real
        IDs `[A-Z]+(-[A-Z]+)?-[0-9]+` could not see, in the two shapes that
        defeated it: no numeric tail, and digits inside a middle segment."""
        for line, want in (
            ('fail "TRIVY-CRIT" "x"', ["TRIVY-CRIT"]),
            ('fail "TRIVY-HIGH" "x"', ["TRIVY-HIGH"]),
            ('warn "TRIVY-MED" "x"', ["TRIVY-MED"]),
            ('skip "PROWLER-K8S-001" "x"', ["PROWLER-K8S-001"]),
            ('skip "PROWLER-M365-001" "x"', ["PROWLER-M365-001"]),
        ):
            with self.subTest(line=line):
                self.assertEqual(_ID_CALL.findall(line), want)

    def test_a_comment_cannot_inflate_a_count(self):
        """ADR-001 §1, and it is a live exposure rather than a hypothetical.

        `scanner/checks/network/scan-tools.sh:48` carries a `# warn "..."`
        documentation line. It does not match `_ID_CALL` today, but the widened
        pattern is what makes such a line countable, so the stripping and the
        widening belong in the same change."""
        live = 'warn "NET-001" "real"\n'
        self.assertEqual(_ID_CALL.findall(active_shell(live)), ["NET-001"])
        for commented in (
            '# warn "NET-999" "documentation"\n',
            '    # warn "NET-999" "indented"\n',
            'echo ok ;# warn "NET-999" "after a metacharacter"\n',
        ):
            with self.subTest(line=commented.strip()):
                self.assertEqual(_ID_CALL.findall(active_shell(commented)), [])

    def test_a_runtime_assembled_id_is_recognised_as_such(self):
        # It must be classified, not counted and not left unclassified — both of
        # the other two outcomes would be wrong in opposite directions.
        for arg in ("${check_id_prefix}-001", "$prefix-001", "${x}"):
            with self.subTest(arg=arg):
                self.assertTrue(_RUNTIME_ASSEMBLED.match(arg))
        for arg in ("INFRA-001", "TRIVY-CRIT", "PROWLER-M365-001"):
            with self.subTest(arg=arg):
                self.assertIsNone(_RUNTIME_ASSEMBLED.match(arg))

    def test_the_row_pattern_needs_three_columns(self):
        # The README holds many tables. A two-column or four-column table with a
        # backticked first cell must not be read as a category row.
        self.assertEqual(doc_rows(self.doc("| `infra` | 18 |")), {})
        self.assertEqual(doc_rows(self.doc("| `infra` | 18 | a | b |")), {})
        self.assertEqual(doc_rows(self.doc("| `infra` | 18 | a |")), {"infra": "18"})


class TestTheTableAgreesWithTheRenderer(unittest.TestCase):
    """The only class here that can catch the RESIDUAL rather than the four
    enumerated vectors.

    Everything above is computed from `rendered_markdown`, so it agrees with
    itself by construction: a residual shape is BY DEFINITION one where the
    reduction and a browser disagree, which means the reduction still finds the
    row and every comparison over it passes. `test_ci_markdown_scan_evasion`
    pins that residual at 14 measured shapes; this class is the reason that
    number is not also this guard's blind spot.

    Registered in `_ci_canary_runner.ADJUDICATORS` (pinned equal to
    `test_ci_guard_self_verify.CANARY_CLASSES`), so the `renderer-canary` job
    runs it BY NAME with the pinned oracle installed. It SKIPS without
    `markdown-it-py`, which keeps the package-free `ci-guards` job package-free
    and is exactly the fail-open the runner exists to close — hence the
    registration rather than trusting a local green."""

    @classmethod
    def setUpClass(cls):
        try:
            from markdown_it import MarkdownIt
        except ImportError:  # pragma: no cover - depends on the local env
            raise unittest.SkipTest("markdown-it-py not installed") from None
        cls.md = MarkdownIt("commonmark")
        cls.text = README.read_text(encoding="utf-8")

    def _reader_sees(self, text):
        """Category rows a BROWSER displays.

        markdown -> HTML -> consume HTML comments. The second step is the
        load-bearing one: markdown-it passes raw HTML through, so an unbalanced
        `<!--` is emitted verbatim and the browser comments out the rest of the
        page. Testing containment in the rendered STRING would report a row as
        visible when no reader receives it."""
        out = self.md.render(text)
        out = re.sub(r"<!--.*?-->", "", out, flags=re.DOTALL)
        opener = out.find("<!--")
        if opener != -1:
            out = out[:opener]
        # Matched as TEXT, not as table markup, and that is deliberate. The
        # `commonmark` preset implements CommonMark, where pipe tables are not a
        # construct — the table renders as one paragraph with the pipes intact
        # and only the backticks resolved to `<code>`. An earlier version looked
        # for `<td><code>…</code></td>` and found nothing, which made
        # `_reader_sees` return the empty set for every input: the comparison
        # below would then have "agreed" on any document, the exact vacuity
        # `test_the_oracle_is_not_vacuous` exists to refuse. Same oracle and
        # same reasoning as `test_ci_catalog_doc_sync`, which matches its guard
        # paths out of rendered text for this reason.
        return set(
            re.findall(r"\|\s*<code>([a-z][a-z-]*)</code>\s*\|[^|\n]*\|[^|\n]*\|", out)
        )

    def test_the_oracle_is_not_vacuous(self):
        # Without this, a `_reader_sees` that always returned everything would
        # make the comparison below pass on any document at all.
        table = (
            f"{_SECTION}\n\n| Category | Checks | Covers |\n|---|---|---|\n"
            "| `infra` | 18 | Docker |\n"
        )
        self.assertEqual(self._reader_sees(table), {"infra"})
        self.assertEqual(self._reader_sees(f"<!-- open\n{table}"), set())

    def test_the_reduction_and_the_renderer_agree_on_the_real_readme(self):
        reduced = set(doc_rows(self.text))
        rendered = self._reader_sees(self.text)
        self.assertEqual(
            reduced - rendered,
            set(),
            "the reduction credits README with category row(s) a READER cannot "
            f"see: {sorted(reduced - rendered)}. This is the residual, not a "
            "drift — look for a stray unmatched backtick or an HTML block "
            "around a comment opener above the `Scanner Categories` table.",
        )

    def test_the_canary_fires_on_the_measured_residual_payload(self):
        """Non-vacuity, using the shape that defeats a reduction-only check.

        Without this the class above could be inert and read green. The opener
        sits ABOVE the table, which is the whole mechanism — an unbalanced
        `<!--` hides everything BELOW it, so a fixture that puts the row first
        proves nothing."""
        table = (
            f"{_SECTION}\n\n| Category | Checks | Covers |\n|---|---|---|\n"
            "| `infra` | 18 | Docker |\n"
        )
        # A stray unmatched backtick makes `rendered_markdown`'s code-span
        # masking swallow the real opener, so the reduction keeps the row while
        # the browser stops rendering at it.
        payload = "A ` stray backtick\n\n<!-- retiring this\n\n" + table
        self.assertIn(
            "infra",
            doc_rows(payload),
            "the reduction no longer keeps this row — the residual payload has "
            "stopped reproducing and this canary is measuring nothing",
        )
        self.assertEqual(
            self._reader_sees(payload),
            set(),
            "the renderer still shows the row, so this fixture is not a "
            "residual shape and the class below it proves nothing",
        )


if __name__ == "__main__":
    unittest.main()
