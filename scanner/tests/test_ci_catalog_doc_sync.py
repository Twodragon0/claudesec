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
      after   a hidden row -> the doc and the TOML disagree, or they agree while
              the doc renders badly. Documentation drift, loudly reported here,
              and the guard suite's own inventory is unaffected.

    To actually degrade the guard inventory you must now also edit the TOML, and
    that fails `test_ci_catalog_completeness`'s on-disk comparison outright.

WHAT MOVED HERE
    The Markdown-vector self-tests deleted from those three guards, because
    "the tests went away with the code" is how a refactor loses coverage without
    anyone deciding to. Each is marked below with the guard it came from.

Set EQUALITY in both directions, so the doc may neither omit an inventory entry
nor present one the inventory does not have.

stdlib-only (`tomllib` + the shared reduction; no PyYAML). No network, no
subprocess.

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

_GUARD_PATH_RE = re.compile(r"scanner/tests/(test_ci_[A-Za-z0-9_]+\.py)")
_MODULE_RE = re.compile(r"\b(test_ci_[A-Za-z0-9_]+|_ci_guard_util)\b")


def documented_guards(catalog_text: str) -> set:
    """Guard file names the catalog PRESENTS to a reader."""
    return set(_GUARD_PATH_RE.findall(rendered_markdown(catalog_text)))


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


class TestDocScanRejectsHiddenRows(unittest.TestCase):
    """The Markdown vectors, moved here from the three converted guards.

    Every case names its origin. These are the assertions that made the old
    guards trustworthy about prose, and they still have a subject — this guard —
    so they keep running rather than being deleted alongside the code they used
    to test."""

    _A = "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |"
    _B = "| `scanner/tests/test_ci_beta.py` | b | b | #2 |"

    def test_visible_rows_are_found(self):
        # Control. Without it every "hidden" assertion below could pass on a
        # scanner that finds nothing at all.
        self.assertEqual(
            documented_guards(f"{self._A}\n{self._B}\n"),
            {"test_ci_alpha.py", "test_ci_beta.py"},
        )

    def test_row_in_a_closed_comment_is_not_documented(self):
        # from test_ci_catalog_completeness
        self.assertEqual(
            documented_guards(f"{self._A}\n<!-- {self._B} -->\n"),
            {"test_ci_alpha.py"},
        )

    def test_row_in_a_multiline_comment_is_not_documented(self):
        # from test_ci_catalog_completeness
        self.assertEqual(
            documented_guards(f"{self._A}\n<!--\nparked:\n{self._B}\n-->\n"),
            {"test_ci_alpha.py"},
        )

    def test_row_in_a_code_fence_is_not_documented(self):
        # from test_ci_catalog_completeness (#529)
        self.assertEqual(
            documented_guards(f"{self._A}\n```\n{self._B}\n```\n"),
            {"test_ci_alpha.py"},
        )

    def test_row_in_an_html_block_is_not_documented(self):
        # from test_ci_catalog_completeness (#529)
        self.assertEqual(
            documented_guards(f"{self._A}\n<div>\n{self._B}\n</div>\n"),
            {"test_ci_alpha.py"},
        )

    def test_row_after_an_unterminated_opener_is_not_documented(self):
        # from test_ci_catalog_completeness (#529). A browser stops rendering at
        # the opener, so everything below it is invisible.
        self.assertEqual(
            documented_guards(f"{self._A}\n<!-- retiring\n{self._B}\n"),
            {"test_ci_alpha.py"},
        )

    def test_a_backticked_opener_is_not_an_opener(self):
        # from test_ci_markdown_scan_evasion (#529). Prose that spells the token
        # in backticks is ordinary documentation and must not eat the rows below.
        self.assertEqual(
            documented_guards(f"See `<!--` in prose.\n\n{self._A}\n{self._B}\n"),
            {"test_ci_alpha.py", "test_ci_beta.py"},
        )

    def test_a_commented_ghost_does_not_mask_a_live_row(self):
        # from test_ci_catalog_no_ghost_rows
        text = f"<!-- {self._B} old -->\n{self._B}\n"
        self.assertEqual(documented_guards(text), {"test_ci_beta.py"})

    def test_the_prose_glob_is_not_read_as_a_path(self):
        # from test_ci_catalog_no_ghost_rows. `*` is not a filename character,
        # so the catalog's own prose glob must not become an entry.
        self.assertEqual(
            documented_guards("see `scanner/tests/test_ci_*.py` for all"), set()
        )

    def test_duplicate_citations_collapse(self):
        # from test_ci_catalog_no_ghost_rows
        self.assertEqual(documented_guards(f"{self._A}\nagain {self._A}\n"), {
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
        # from test_ci_collector_table_completeness (#529). The measured defect:
        # `^#+\s` matched a shell comment inside a fenced example, so every row
        # below it went unread.
        md = (
            f"## {SECTION_TITLE}\n\n"
            "```bash\n# an ordinary shell comment\necho hi\n```\n\n"
            "| `test_ci_a.py` | x | y |\n"
        )
        self.assertEqual(documented_collectors(md), {"test_ci_a.py"})


if __name__ == "__main__":
    unittest.main()
