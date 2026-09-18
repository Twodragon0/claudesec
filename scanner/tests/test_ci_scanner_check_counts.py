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
    network         "5+" stated, 7 implemented

and the prose said `~120+ checks` against a real 193. Nothing failed, because
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
from _ci_guard_util import REPO_ROOT, rendered_markdown  # noqa: E402

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
        "integration emits 15 unique IDs (`PROWLER-001` plus 14 "
        "`PROWLER-<provider>-001`), which is a different number of a different "
        "thing, so asserting the check count here would demand a wrong edit. "
        "The 16 is already guarded at its real source: "
        "`test_ci_provider_labels_sync` pins `PROVIDER_LABELS` at exactly 16 "
        "entries and pins the bash mirror equal to it."
    ),
}

#: A check ID as the scanner emits it: the first argument to one of the four
#: result helpers. A repo-wide sweep found every `pass|fail|warn|skip "…"` call
#: site in `scanner/checks/**` matches this shape and none constructs the ID
#: from a variable, so the extraction is complete rather than best-effort. If
#: that stops being true, `test_the_categories_partition_every_id` is what
#: notices: an ID the pattern cannot see is an ID missing from both sides.
_ID_CALL = re.compile(r'\b(?:pass|fail|warn|skip) +"([A-Z]+(?:-[A-Z]+)?-[0-9]+)"')

#: A `Scanner Categories` row: `| \`<category>\` | <cell> | <covers> |`. The
#: category is backticked in the published table, which is also what keeps this
#: from matching the many other tables in the README — none of them puts a
#: backticked single word in column one followed by exactly two more columns.
_ROW = re.compile(
    r"^\|\s*`([a-z][a-z-]*)`\s*\|([^|]*)\|[^|]*\|\s*$", re.MULTILINE
)

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


def ids_in(path: Path):
    """The set of unique check IDs emitted anywhere under `path`.

    A SET, because an ID is emitted from several call sites — one per verdict
    branch — and the README states how many checks exist, not how many ways each
    can end."""
    found = set()
    for f in sorted(path.rglob("*")):
        if not f.is_file():
            continue
        found.update(_ID_CALL.findall(f.read_text(encoding="utf-8", errors="replace")))
    return found


def code_counts():
    """`{category: number of unique check IDs}` from the tree."""
    return {name: len(ids_in(CHECKS_DIR / name)) for name in category_dirs()}


def doc_rows(text):
    """`{category: cell text}` from the README's category table, as a READER
    sees it.

    Reduced by `rendered_markdown` BEFORE the search, not after — a row hidden
    in a comment, a fence or an HTML block, or one sitting below an unterminated
    `<!--`, renders as nothing and must not satisfy a comparison here. Reducing
    after the search would leave the four enumerated vectors wide open while
    keeping every token a static check looks for; that exact shape is what
    `test_ci_markdown_scan_evasion.test_no_detector_sees_a_row_under_a_hidden_ANCHOR`
    exists to catch, and this function is registered there."""
    return {m.group(1): m.group(2).strip() for m in _ROW.finditer(rendered_markdown(text))}


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

    def test_a_wrong_number_is_detected(self):
        rows = doc_rows("| `infra` | 16 | Docker |\n")
        self.assertEqual(stated_count(rows["infra"]), 16)
        self.assertNotEqual(
            stated_count(rows["infra"]), 18, "the comparison is a real inequality"
        )

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
        self.assertIn("infra", doc_rows(f"{row}\n"))
        for doc in (
            f"<!--\n{row}\n-->\n",
            f"```\n{row}\n```\n",
            f"<div>\n{row}\n</div>\n",
            f"<!-- retiring this\n{row}\n",
        ):
            with self.subTest(doc=doc.splitlines()[0]):
                self.assertNotIn("infra", doc_rows(doc))

    def test_the_id_pattern_requires_a_helper_call(self):
        # An ID in prose, in a comment, or in a variable assignment is not an
        # emitted check. Without this the count would inflate on documentation.
        self.assertEqual(_ID_CALL.findall('pass "INFRA-001" "x"'), ["INFRA-001"])
        self.assertEqual(_ID_CALL.findall('fail "SAAS-API-012" "x"'), ["SAAS-API-012"])
        self.assertEqual(_ID_CALL.findall('# see INFRA-001 for context'), [])
        self.assertEqual(_ID_CALL.findall('_id="INFRA-001"'), [])

    def test_the_row_pattern_needs_three_columns(self):
        # The README holds many tables. A two-column or four-column table with a
        # backticked first cell must not be read as a category row.
        self.assertEqual(doc_rows("| `infra` | 18 |\n"), {})
        self.assertEqual(doc_rows("| `infra` | 18 | a | b |\n"), {})
        self.assertEqual(doc_rows("| `infra` | 18 | a |\n"), {"infra": "18"})


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
            "| Category | Checks | Covers |\n|---|---|---|\n"
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
            "| Category | Checks | Covers |\n|---|---|---|\n"
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
