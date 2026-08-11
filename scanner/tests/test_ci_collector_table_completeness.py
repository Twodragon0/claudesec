"""
Meta-guard: every indentation-based BLOCK COLLECTOR in the guard suite has a
verdict row in the catalog's block-collector enumeration table.

WHY
---
#419 found the same defect in five collectors at once — a `#` comment line ending a
block it does not end, hiding every key after it (three live bypasses, two of them
on a required check). The fix that scales is not the five patches; it is the
ENUMERATION, because the next collector added is the next one nobody looked at.

The enumeration was written down in `docs/devsecops/ci-config-regression-guards.md`
("Block-collector enumeration"), which immediately raises the failure this repo has
already paid for twice: a table that nothing checks goes stale. #411 re-triaged a
backlog listing seven solved problems as open; #413 found an "already guarded"
verdict that had gone false. A hand-maintained list of parsers is exactly that
shape.

So the list is DERIVED from the source and diffed against the table.

WHAT COUNTS AS A COLLECTOR
--------------------------
A file that computes an indentation width (`len(s) - len(s.lstrip())`, including the
tab-expanded form). That is deliberately broader than "has a bug": a collector is
anything that reasons about indentation, and the verdict for most of them is
"correct as-is". Over-reporting costs one table row; under-reporting is a parser
nobody audited.

DIRECTION
---------
COMPLETENESS, one way. Every detected file must have a row. EXTRA rows are allowed
and expected — the table also records collectors that are immune by construction
(`test_ci_drift_watch_not_silent` strips comments before splitting;
`test_ci_npm_publish` was converted to the shared `block_ends_at` and no longer does
its own indent math), and deleting those rows would lose the verdict that made them
safe. Asserting the reverse direction would demand deleting exactly the rows worth
keeping.

Not checked: the CONTENT of a verdict. "Is this collector correct?" is not
mechanizable — that is what the audit is for. This guard only guarantees the audit
had the full list in front of it.

stdlib-only, no PyYAML, no `scanner/lib` import. Passes under pytest and
`python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration); NIST SP 800-218 (SSDF) PO.3.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import REPO_ROOT  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent
CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"
CATALOG = REPO_ROOT / CATALOG_REL
SECTION_TITLE = "Block-collector enumeration"

# `len(x) - len(x.lstrip())` and the tab-expanded `len(e) - len(e.lstrip())` form.
# The same name on both sides, so an unrelated subtraction of two lengths is not
# mistaken for an indent measurement.
_INDENT_RE = re.compile(
    r"len\(\s*([A-Za-z_][\w\.\[\]]*)\s*\)\s*-\s*len\(\s*\1\.lstrip\(\)\s*\)"
)

# This file itself carries the indent shape as a REGEX LITERAL, not as code, so it
# matches its own detector. Excluded by name rather than by trying to tell a pattern
# string from an expression — the latter is a parser, which is the thing this whole
# class of bug is about. If a real collector is ever added here, this line has to go
# with it.
_SELF = "test_ci_collector_table_completeness.py"


def scanned_files() -> list:
    """The guard suite plus the shared primitives module, sorted."""
    return sorted(TESTS_DIR.glob("test_ci_*.py")) + [TESTS_DIR / "_ci_guard_util.py"]


def collector_files(paths=None) -> set:
    """File names that reason about indentation, i.e. that collect a block."""
    out = set()
    for path in paths or scanned_files():
        p = Path(path)
        if not p.is_file():
            continue
        if p.name == _SELF:
            continue
        if _INDENT_RE.search(p.read_text(encoding="utf-8")):
            out.add(p.name)
    return out


def table_section(catalog_text: str) -> str:
    """The block-collector enumeration section, up to the next `##` heading.

    Matched on the TITLE rather than a fixed heading level, so promoting or
    demoting the section does not silently empty this guard."""
    m = re.search(
        rf"^#+\s*{re.escape(SECTION_TITLE)}.*?$(.*?)(?=^#+\s|\Z)",
        catalog_text,
        re.M | re.S,
    )
    return m.group(1) if m else ""


def table_files(catalog_text: str) -> set:
    """File names named in the enumeration table's rows.

    Reads the whole row, not only its first cell: a verdict routinely names the
    file whose collector it compares against (`test_ci_drift_watch_not_silent`
    appears as the pattern the others now match), and a row is a row wherever the
    name sits."""
    out = set()
    for line in table_section(catalog_text).splitlines():
        if not line.lstrip().startswith("|"):
            continue
        # Match the MODULE identifier and normalise, so all three spellings the
        # table actually uses resolve to one key: `test_ci_x.py`,
        # `test_ci_x.collector_fn`, and the bare `test_ci_x`. Anchoring on `.py`
        # alone missed the last two, which is how the first version of this guard
        # reported a documented collector as unlisted.
        out |= {
            f"{m}.py"
            for m in re.findall(r"\b(test_ci_[A-Za-z0-9_]+|_ci_guard_util)\b", line)
        }
    return out


class TestCollectorTableCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = CATALOG.read_text(encoding="utf-8") if CATALOG.is_file() else ""
        cls.detected = collector_files()
        cls.listed = table_files(cls.catalog)

    def test_catalog_exists(self):
        self.assertTrue(CATALOG.is_file(), f"{CATALOG_REL} not found — path broke")

    def test_section_is_found(self):
        # Vacuity canary #1: no section means an empty `listed` set, which would
        # report every collector as missing (loud) — but a section that parses to
        # nothing while the file still contains the title would be silent.
        self.assertTrue(
            table_section(self.catalog).strip(),
            f"the {SECTION_TITLE!r} section is missing or empty in {CATALOG_REL}. "
            "If it was intentionally removed, delete this guard in the same commit "
            "rather than leaving the enumeration unchecked.",
        )

    def test_detection_finds_the_known_collectors(self):
        # Vacuity canary #2: if the indent regex stops matching, `detected` empties
        # and completeness passes for free.
        self.assertGreaterEqual(
            len(self.detected),
            5,
            "the collector detector found almost nothing — the indent-measurement "
            f"shape changed. Fix the pattern; do NOT ship it blind. Found: "
            f"{sorted(self.detected)}",
        )
        for expected in (
            "test_ci_security_gate_behaviour.py",
            "test_ci_required_graph_not_disabled.py",
            "_ci_guard_util.py",
        ):
            self.assertIn(
                expected,
                self.detected,
                f"{expected} is known to collect blocks but was not detected",
            )

    def test_every_collector_file_has_a_verdict_row(self):
        missing = sorted(self.detected - self.listed)
        self.assertEqual(
            missing,
            [],
            "block collector(s) with no verdict row in the catalog's "
            f"{SECTION_TITLE!r} table:\n  " + "\n  ".join(missing) + "\n"
            "Add a row saying what the collector reads (mapping or scalar) and why "
            "it is safe. #419 found the same defect in five collectors at once "
            "because nobody had the list; a collector that is not on the list is "
            "one the next audit will not look at.",
        )

    def test_extra_rows_are_allowed(self):
        # Direction, asserted rather than assumed: the table legitimately records
        # collectors that do no indent math of their own — immune by construction,
        # or converted to the shared primitive. Failing on those would demand
        # deleting the rows most worth keeping.
        extra = self.listed - self.detected
        self.assertTrue(
            extra,
            "no extra rows at all. Not a failure in itself, but the table used to "
            "carry verdicts for collectors with no indent math (drift-watch's "
            "strip-then-split, npm-publish after conversion to `block_ends_at`) — "
            "if those rows were dropped, the reasons that made them safe went with "
            "them.",
        )


class TestDetectorBehaviour(unittest.TestCase):
    """Mutation self-tests, on synthetic text — no real file is touched."""

    def test_indent_measurement_is_detected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "test_ci_fake.py")
            p.write_text("def f(l):\n    return len(l) - len(l.lstrip())\n")
            self.assertEqual(collector_files([p]), {"test_ci_fake.py"})

    def test_tab_expanded_form_is_detected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "test_ci_fake.py")
            p.write_text("def f(s):\n    e = s.expandtabs(8)\n    return len(e) - len(e.lstrip())\n")
            self.assertEqual(
                collector_files([p]),
                {"test_ci_fake.py"},
                "the tab-expanded indent form was missed — that is how "
                "`test_ci_injection_surface` measures indentation",
            )

    def test_unrelated_length_subtraction_is_not_detected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "test_ci_fake.py")
            p.write_text("def f(a, b):\n    return len(a) - len(b.lstrip())\n")
            self.assertEqual(
                collector_files([p]), set(),
                "two DIFFERENT names is not an indent measurement; flagging it "
                "would make the guard noise",
            )

    def test_a_row_is_read_from_anywhere_in_the_line(self):
        md = (
            "## Block-collector enumeration (2026-08-11)\n\n"
            "| Collector | Reads | Verdict |\n|---|---|---|\n"
            "| `_ci_guard_util.job_block` | mapping | FIXED |\n"
            "| something | mapping | matches `test_ci_drift_watch_not_silent` |\n"
            "\n## Next section\n"
        )
        self.assertEqual(
            table_files(md),
            {"_ci_guard_util.py", "test_ci_drift_watch_not_silent.py"},
        )

    def test_section_ends_at_the_next_heading(self):
        md = (
            "## Block-collector enumeration\n\n| `test_ci_a.py` | x | y |\n"
            "\n## Other\n\n| `test_ci_b.py` | x | y |\n"
        )
        self.assertEqual(table_files(md), {"test_ci_a.py"})

    def test_a_renamed_section_yields_nothing(self):
        # The shape the canary above exists for.
        self.assertEqual(table_section("## Something else\n\n| `test_ci_a.py` |\n"), "")


if __name__ == "__main__":
    unittest.main()
