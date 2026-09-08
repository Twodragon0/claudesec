"""
Regression guard: the PUBLISHED catalog `docs/devsecops/ci-config-regression-guards.md`
must present the same inventory that `docs/devsecops/ci-guard-inventory.toml`
records.

WHY THIS GUARD EXISTS, AND WHY IT IS DELIBERATELY WEAKER THAN THE THREE IT
REPLACED HALF OF
    `test_ci_catalog_completeness`, `test_ci_catalog_no_ghost_rows` and
    `test_ci_collector_table_completeness` used to read the prose as a database.
    That put the whole Markdown scan-evasion class between each guard and the
    invariant it asserts: a row hidden in a closed comment, a code fence, an HTML
    block, or after an unterminated comment opener renders as nothing a reader
    can act on, while a raw substring scan still finds it. #528 and #529 patched
    the reduction twice and the second still left a MEASURED 14 silent-pass
    shapes, because the divergence is two-layer — markdown -> HTML -> browser —
    and a stdlib regex cannot model it. ADR-001 §5 says to invert rather than
    patch an enumeration a third time.

    So the three guards moved to the TOML and now have no Markdown in their
    paths. This guard is the one remaining prose reader, and it still carries
    that residual. The difference is the FAILURE MODE, which is the whole point
    of the split:

      before  a hidden row -> a guard certifies coverage that the published
              inventory does not show. Silent, and about the guard suite.
      after   a hidden row -> documentation drift, and the guard suite's own
              inventory is unaffected.

    An earlier draft of this paragraph said the drift is "loudly reported here".
    A review measured that FALSE for the residual specifically, and the
    correction matters more than the claim did. The four ENUMERATED vectors are
    reported loudly (the vector class below). The RESIDUAL is not, and cannot be
    by any set comparison in this file: a residual shape is by definition one
    where the reduction and a browser disagree, so every comparison computed
    from the reduction agrees with itself. Four inserted lines on the real
    catalog left a reader seeing ZERO of 70 guard rows with 68 guard tests
    green. `TestTheDocAgreesWithTheRenderer` is that hole closed, by
    adjudicating against `markdown-it-py` rather than against the reduction.

    To actually degrade the guard inventory you must now also edit the TOML, and
    that fails `test_ci_catalog_completeness`'s on-disk comparison outright.

WHAT MOVED HERE, COUNTED HONESTLY
    Nine self-tests genuinely moved from those three guards, one of them WIDENED
    (it replaces an assertion of the opposite property), plus four written NEW
    here and one new control. An earlier draft of this docstring claimed all
    fourteen were "deleted from the three converted guards" and labelled four
    with origins that do not exist — an AST diff of test-method names between
    `origin/main` and this commit shows ZERO tests were deleted from
    `test_ci_markdown_scan_evasion`, and neither the fence nor the HTML-block
    nor the fenced-`#`-comment case ever had a test in the two guards they were
    attributed to. Those vectors were fixed in the shared reduction and pinned
    in `test_ci_markdown_scan_evasion`'s vector matrix, never per-consumer.

    The labels are the whole mechanism by which a later auditor answers "did
    coverage survive the refactor?", so a wrong one is worse than none: an
    auditor who trusts it stops looking. Each case below now says `moved`,
    `WIDENED`, or `NEW in this PR — not a move`.

    Two named canaries from the old guards are gone rather than moved, and
    where their property lives now:
      `test_section_is_found` (collector guard) — a renamed heading is still
        caught, by `test_the_collector_enumeration_matches` reporting every
        module as missing. Only the message quality degrades.
      `test_unclosed_comment_marker_does_not_blank_the_catalog` — asserted the
        document is NOT blanked by a stray opener; subsumed by
        `test_row_after_an_unterminated_opener_is_not_documented`, which
        asserts the stronger, opposite-direction property.

Set EQUALITY in both directions, so the doc may neither omit an inventory entry
nor present one the inventory does not have.

WHERE THE RENDERER CLASS ACTUALLY RUNS
    `TestTheDocAgreesWithTheRenderer` needs `markdown-it-py`, so it skips in the
    package-free `ci-guards` job. It used to run only under
    `scanner-unit-tests`, whose `scanner` bucket a catalog-only PR does not
    match — so the residual canary did NOT fire on the very PR shape that would
    introduce a residual. That gap is CLOSED: the `renderer-canary` job runs this
    class (and the two other renderer-adjudicated classes) on the `ci_config`
    bucket, which now covers `docs/`, with a per-class non-zero-test floor and a
    skip check, and is wired into `lint-gate.needs`. Do not re-open it by moving
    this class or renaming it without updating
    `test_ci_guard_self_verify.CANARY_CLASSES`, which pins the list.

stdlib-only for everything except that one class (`tomllib` + the shared
reduction; no PyYAML). No network, no subprocess.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    GUARD_INVENTORY,
    REPO_ROOT,
    guard_inventory,
    rendered_markdown,
)

CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"
CATALOG = REPO_ROOT / CATALOG_REL
INVENTORY_REL = "docs/devsecops/ci-guard-inventory.toml"
SECTION_TITLE = "Block-collector enumeration"
CATALOG_SECTION_TITLE = "Catalog"

_GUARD_PATH_RE = re.compile(r"scanner/tests/(test_ci_[A-Za-z0-9_]+\.py)")
_MODULE_RE = re.compile(r"\b(test_ci_[A-Za-z0-9_]+|_ci_guard_util)\b")


def catalog_section(catalog_text: str) -> str:
    """The `## Catalog` section, up to the next heading of the same level."""
    m = re.search(
        rf"^#+\s*{re.escape(CATALOG_SECTION_TITLE)}\s*$(.*?)(?=^#+\s|\Z)",
        rendered_markdown(catalog_text),
        re.M | re.S,
    )
    return m.group(1) if m else ""


def documented_rows(catalog_text: str) -> list:
    """First-cell guard names, one entry per `|`-row of the `## Catalog` table.

    A LIST, not a set, and scoped to the section and to the row's FIRST CELL.
    The first version scanned the whole reduced document for the path pattern
    and de-duplicated, which a review defeated four ways without any Markdown
    trickery at all: deleting a row and adding one prose sentence naming the
    path; moving the row to a `## Retired` section as a pipe-less one-liner;
    and listing a guard twice with contradictory verdicts. Each read GREEN
    against the real inventory.

    The invariant is "each guard has a row in the published Catalog table whose
    first cell names it", so that is what this returns. A path merely MENTIONED
    somewhere in the document is not a row, and two rows for one guard are two
    entries.

    ACCEPTED LIMIT, stated rather than left to be rediscovered: a row whose
    first cell is right and whose other cells are emptied (`| path | | | |`)
    still counts. Presence of a row is the contract; judging whether a verdict
    is substantive is not something this can check, and pretending otherwise
    would be the enumeration trap again."""
    out = []
    for line in catalog_section(catalog_text).splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) > 1:
            out.extend(_GUARD_PATH_RE.findall(cells[1]))
    return out


def documented_guards(catalog_text: str) -> set:
    """Guard file names the catalog's Catalog table PRESENTS to a reader."""
    return set(documented_rows(catalog_text))


def collector_section(catalog_text: str) -> str:
    """The block-collector enumeration section, up to the next heading.

    Matched on the TITLE rather than a fixed heading level, so promoting or
    demoting the section does not silently empty this check. Reduced first, which
    also keeps an ordinary `# shell comment` inside a fenced example from
    matching the `^#+\\s` terminator and ending the section early — a defect
    measured in #529, where every row below such a fence went unread."""
    m = re.search(
        rf"^#+\s*{re.escape(SECTION_TITLE)}.*?$(.*?)(?=^#+\s|\Z)",
        rendered_markdown(catalog_text),
        re.M | re.S,
    )
    return m.group(1) if m else ""


def documented_collectors(catalog_text: str) -> set:
    """Modules named in the enumeration table's rows.

    Reads the whole row, not only its first cell: a verdict routinely names the
    file whose collector it compares against, and a row is a row wherever the
    name sits. Normalises the three spellings the table uses — `test_ci_x.py`,
    `test_ci_x.collector_fn`, and the bare `test_ci_x` — to one key."""
    out = set()
    for line in collector_section(catalog_text).splitlines():
        if not line.lstrip().startswith("|"):
            continue
        out |= {f"{m}.py" for m in _MODULE_RE.findall(line)}
    return out


class TestCatalogDocMatchesInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CATALOG.read_text(encoding="utf-8") if CATALOG.is_file() else ""
        inv = guard_inventory()
        cls.inv_guards = set(inv["catalog"]["guards"])
        cls.inv_collectors = set(inv["block_collectors"]["modules"])
        cls.doc_guards = documented_guards(cls.text)
        cls.doc_collectors = documented_collectors(cls.text)

    def test_both_sources_exist(self):
        self.assertTrue(CATALOG.is_file(), f"{CATALOG_REL} not found — path broke")
        self.assertTrue(
            GUARD_INVENTORY.is_file(), f"{INVENTORY_REL} not found — path broke"
        )

    def test_the_doc_scan_is_not_vacuous(self):
        # Without this, a reduction that blanked the whole document would make
        # both set comparisons below report "the doc omits everything" — loud,
        # but for a reason that has nothing to do with drift. A floor near the
        # real count says which of the two it is.
        self.assertGreater(
            len(self.doc_guards),
            50,
            f"only {len(self.doc_guards)} guard paths are visible in "
            f"{CATALOG_REL}. Before hunting drift, check whether the Markdown "
            "reduction ate the document — that has happened twice",
        )

    def test_the_doc_omits_no_inventory_entry(self):
        missing = sorted(self.inv_guards - self.doc_guards)
        self.assertEqual(
            missing,
            [],
            f"{INVENTORY_REL} lists guard(s) the published catalog does not "
            f"show a reader:\n  " + ", ".join(missing) + "\n"
            "Add a Catalog table row (Guard | Protects | Key assertions | "
            "Landed). If the row IS in the file, it is hidden from a reader — "
            "check for a comment, fence, or HTML block around it.",
        )

    def test_the_doc_shows_nothing_the_inventory_lacks(self):
        extra = sorted(self.doc_guards - self.inv_guards)
        self.assertEqual(
            extra,
            [],
            f"the published catalog shows guard(s) absent from {INVENTORY_REL}:"
            f"\n  " + ", ".join(extra) + "\n"
            "Either add them to `[catalog].guards` or remove the rows. A row "
            "with no inventory entry is not covered by the on-disk checks.",
        )

    def test_the_collector_enumeration_matches(self):
        self.assertEqual(
            self.doc_collectors,
            self.inv_collectors,
            "the published 'Block-collector enumeration' table and "
            f"`[block_collectors].modules` in {INVENTORY_REL} disagree.\n"
            f"  only in the doc: {sorted(self.doc_collectors - self.inv_collectors)}\n"
            f"  only in the TOML: {sorted(self.inv_collectors - self.doc_collectors)}",
        )


class TestTheDocAgreesWithTheRenderer(unittest.TestCase):
    """The only check here that can catch the RESIDUAL, not just the four
    enumerated vectors.

    Why the rest of this file cannot: a residual shape is BY DEFINITION one
    where `rendered_markdown` and a browser disagree, so the reduction always
    still finds the row. Every set comparison above is computed from the
    reduction, which means it agrees with itself. A review demonstrated the
    consequence on the real catalog with four inserted lines — a stray unmatched
    backtick, a real `<!--` opener, a closing backtick — after which the
    reduction saw all 70 guard paths, a CommonMark render showed a reader ZERO,
    `Block-collector enumeration` was invisible, and 68 guard tests passed.

    The earlier docstring claimed a hidden row is "loudly reported here". It was
    not. This class is that claim made true, by adjudicating against the
    renderer instead of against the same reduction.

    SKIPPED without `markdown-it-py`, so the package-free `ci-guards` job stays
    package-free. The `renderer-canary` job is where this class actually runs in
    CI: it installs the pinned oracle and is gated on `ci_config`, so it fires on
    a catalog-only PR without touching the `scanner` bucket that would fire kcov.
    The earlier note here said the check ran only under `scanner-unit-tests` and
    called that a KNOWN GAP; that was true when written and is not now."""

    @classmethod
    def setUpClass(cls):
        try:
            from markdown_it import MarkdownIt
        except ImportError:  # pragma: no cover - depends on the local env
            raise unittest.SkipTest("markdown-it-py not installed") from None
        cls.md = MarkdownIt("commonmark")
        cls.text = CATALOG.read_text(encoding="utf-8") if CATALOG.is_file() else ""

    def _reader_sees(self, text: str) -> set:
        """Guard paths a BROWSER displays.

        markdown -> HTML -> consume HTML comments. The second step is the one
        that matters and the one a first attempt at this got wrong: markdown-it
        passes raw HTML through, so an unbalanced `<!--` is emitted verbatim and
        the browser comments out the rest of the page. Containment in the
        rendered STRING therefore reports a row as visible when no reader sees
        it."""
        out = self.md.render(text)
        out = re.sub(r"<!--.*?-->", "", out, flags=re.DOTALL)
        opener = out.find("<!--")
        if opener != -1:
            out = out[:opener]
        return set(_GUARD_PATH_RE.findall(out))

    def test_the_oracle_is_not_vacuous(self):
        # Without this, a `_reader_sees` that always returned everything would
        # make the comparison below pass on any document.
        row = "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |"
        self.assertEqual(self._reader_sees(f"{row}\n"), {"test_ci_alpha.py"})
        self.assertEqual(self._reader_sees(f"<!-- open\n{row}\n"), set())

    def test_the_reduction_and_the_renderer_agree_on_the_real_catalog(self):
        reduced = documented_guards(self.text)
        rendered = self._reader_sees(self.text)
        self.assertEqual(
            reduced - rendered,
            set(),
            "the reduction credits the catalog with guard row(s) a READER cannot "
            f"see: {sorted(reduced - rendered)}. This is the residual, not a "
            "drift — look for a stray unmatched backtick or an HTML block "
            "around a comment opener near those rows.",
        )

    def test_the_canary_fires_on_the_measured_residual_payload(self):
        """Non-vacuity, using the exact shape a review defeated the old check
        with. Without this the class above could be inert and read green."""
        row = "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |"
        # The payload sits ABOVE the row, which is the whole mechanism: the
        # unbalanced opener hides everything BELOW it. A first draft of this
        # fixture put the row first and the canary read green — the ordering is
        # not incidental.
        doc = (
            "# CI Config Regression Guards\n\n"
            "A stray tick ` here.\n\n<!-- parking\n`\n\n"
            f"## Catalog\n\n{row}\n"
        )
        reduced, rendered = documented_guards(doc), self._reader_sees(doc)
        self.assertEqual(reduced, {"test_ci_alpha.py"})
        self.assertEqual(
            rendered,
            set(),
            "the payload no longer hides the row from a reader — if the "
            "reduction was fixed, re-measure the residual and update the "
            "ceiling in test_ci_markdown_scan_evasion",
        )


class TestDocScanRejectsHiddenRows(unittest.TestCase):
    """The Markdown vectors at the one consumer that still reads prose.

    Every case names its provenance — `moved`, `WIDENED`, or `NEW in this PR`.
    The moved ones are the assertions that made the old guards trustworthy
    about prose, and they still have a subject — this guard —
    so they keep running rather than being deleted alongside the code they used
    to test."""

    _A = "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |"
    _B = "| `scanner/tests/test_ci_beta.py` | b | b | #2 |"

    @staticmethod
    def _doc(body: str) -> str:
        """`body` inside a real `## Catalog` section.

        The fixtures used to be bare rows, which passed only because
        `documented_guards` scanned the whole document. Once it was scoped to the
        section — the fix for a review finding that a prose sentence naming a
        deleted guard satisfied the old check — every one of those fixtures went
        red, correctly: they were not exercising a Catalog table at all."""
        return f"# CI Config Regression Guards\n\n## Catalog\n\n{body}\n"

    def test_visible_rows_are_found(self):
        # Control. Without it every "hidden" assertion below could pass on a
        # scanner that finds nothing at all.
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n{self._B}\n")),
            {"test_ci_alpha.py", "test_ci_beta.py"},
        )

    def test_row_in_a_closed_comment_is_not_documented(self):
        # from test_ci_catalog_completeness
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n<!-- {self._B} -->\n")),
            {"test_ci_alpha.py"},
        )

    def test_row_in_a_multiline_comment_is_not_documented(self):
        # from test_ci_catalog_completeness
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n<!--\nparked:\n{self._B}\n-->\n")),
            {"test_ci_alpha.py"},
        )

    def test_row_in_a_code_fence_is_not_documented(self):
        # NEW in this PR — not a move. `test_ci_catalog_completeness` never had
        # a fence test; #529 fixed the fence vector in the shared reduction and
        # pinned it in `test_ci_markdown_scan_evasion`'s vector matrix, never
        # per-consumer. Added here because this guard is now the consumer.
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n```\n{self._B}\n```\n")),
            {"test_ci_alpha.py"},
        )

    def test_row_in_an_html_block_is_not_documented(self):
        # NEW in this PR — not a move, same reason as the fence case above.
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n<div>\n{self._B}\n</div>\n")),
            {"test_ci_alpha.py"},
        )

    def test_row_after_an_unterminated_opener_is_not_documented(self):
        # WIDENED from `test_ci_catalog_completeness`'s
        # `test_unclosed_comment_marker_does_not_blank_the_catalog`, which
        # asserted the OPPOSITE property — that the document is not blanked.
        # This subsumes it: a browser stops rendering at the opener, so
        # everything below is invisible and must not count as documented.
        self.assertEqual(
            documented_guards(self._doc(f"{self._A}\n<!-- retiring\n{self._B}\n")),
            {"test_ci_alpha.py"},
        )

    def test_a_backticked_opener_is_not_an_opener(self):
        # NEW in this PR — not a move. NO test was deleted from
        # `test_ci_markdown_scan_evasion`; its
        # `test_a_backticked_opener_is_not_a_comment` is still live there and
        # covers the primitive. This is the same property at THIS consumer.
        self.assertEqual(
            documented_guards(self._doc(f"See `<!--` in prose.\n\n{self._A}\n{self._B}\n")),
            {"test_ci_alpha.py", "test_ci_beta.py"},
        )

    def test_a_commented_ghost_does_not_mask_a_live_row(self):
        # from test_ci_catalog_no_ghost_rows
        text = self._doc(f"<!-- {self._B} old -->\n{self._B}\n")
        self.assertEqual(documented_guards(text), {"test_ci_beta.py"})

    def test_a_prose_mention_is_not_a_row(self):
        # NEW in this PR. A review deleted a real row and added ONE prose
        # sentence naming the path; the whole-document scan counted it and the
        # check read GREEN against the real inventory. Scoping to the row's
        # first cell is what closes it.
        text = self._doc(
            f"{self._A}\n\nSee `scanner/tests/test_ci_beta.py` for the details.\n"
        )
        self.assertEqual(documented_guards(text), {"test_ci_alpha.py"})

    def test_a_pipeless_one_liner_in_another_section_is_not_a_row(self):
        # NEW in this PR. Same review: the row moved to a `## Retired` section
        # as a bare line. Two reasons it must not count — no pipes, and outside
        # the Catalog section.
        text = (
            "# CI Config Regression Guards\n\n## Catalog\n\n"
            f"{self._A}\n\n## Retired\n\n`scanner/tests/test_ci_beta.py`\n"
        )
        self.assertEqual(documented_guards(text), {"test_ci_alpha.py"})

    def test_a_row_in_another_section_is_not_a_catalog_row(self):
        # NEW in this PR. The pipes alone are not enough; the section is
        # load-bearing, or a table anywhere in the document would satisfy the
        # Catalog inventory.
        text = (
            "# CI Config Regression Guards\n\n## Catalog\n\n"
            f"{self._A}\n\n## Retired\n\n{self._B}\n"
        )
        self.assertEqual(documented_guards(text), {"test_ci_alpha.py"})

    def test_a_duplicate_row_is_two_entries(self):
        # NEW in this PR. A review listed one guard TWICE with contradictory
        # verdicts and the de-duplicating set hid it. `documented_rows` returns
        # a list so the duplication is visible to a caller that cares.
        text = self._doc(f"{self._A}\n{self._A}\n{self._B}\n")
        rows = documented_rows(text)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows.count("test_ci_alpha.py"), 2)

    def test_a_gutted_row_still_counts_as_a_row(self):
        # The ACCEPTED LIMIT, asserted so it is a decision rather than a
        # discovery. Presence of a row is the contract; whether its verdict says
        # anything is not something a path scan can judge.
        text = self._doc("| `scanner/tests/test_ci_alpha.py` | | | |\n")
        self.assertEqual(documented_guards(text), {"test_ci_alpha.py"})

    def test_the_prose_glob_is_not_read_as_a_path(self):
        # from test_ci_catalog_no_ghost_rows. `*` is not a filename character,
        # so the catalog's own prose glob must not become an entry.
        self.assertEqual(
            documented_guards(self._doc("see `scanner/tests/test_ci_*.py` for all")), set()
        )

    def test_duplicate_citations_collapse(self):
        # from test_ci_catalog_no_ghost_rows
        self.assertEqual(documented_guards(self._doc(f"{self._A}\nagain {self._A}\n")), {
            "test_ci_alpha.py"
        })

    def test_a_collector_row_is_read_from_anywhere_in_the_line(self):
        # from test_ci_collector_table_completeness
        md = (
            f"## {SECTION_TITLE} (2026-08-11)\n\n"
            "| Collector | Reads | Verdict |\n|---|---|---|\n"
            "| `_ci_guard_util.job_block` | mapping | FIXED |\n"
            "| something | mapping | matches `test_ci_drift_watch_not_silent` |\n"
            "\n## Next section\n"
        )
        self.assertEqual(
            documented_collectors(md),
            {"_ci_guard_util.py", "test_ci_drift_watch_not_silent.py"},
        )

    def test_the_collector_section_ends_at_the_next_heading(self):
        # from test_ci_collector_table_completeness
        md = (
            f"## {SECTION_TITLE}\n\n| `test_ci_a.py` | x | y |\n"
            "\n## Other\n\n| `test_ci_b.py` | x | y |\n"
        )
        self.assertEqual(documented_collectors(md), {"test_ci_a.py"})

    def test_a_renamed_collector_section_yields_nothing(self):
        # from test_ci_collector_table_completeness — the shape the vacuity
        # canary in the class above exists for.
        self.assertEqual(
            collector_section("## Something else\n\n| `test_ci_a.py` |\n"), ""
        )

    def test_a_fenced_hash_comment_does_not_end_the_collector_section(self):
        # NEW in this PR — not a move. The defect was real and measured in #529
        # (the section terminator matched a shell comment inside a fenced
        # example, so every row below went unread), but it was fixed in the
        # reduction and never had a test in
        # `test_ci_collector_table_completeness`. It gets one here.
        md = (
            f"## {SECTION_TITLE}\n\n"
            "```bash\n# an ordinary shell comment\necho hi\n```\n\n"
            "| `test_ci_a.py` | x | y |\n"
        )
        self.assertEqual(documented_collectors(md), {"test_ci_a.py"})


if __name__ == "__main__":
    unittest.main()
