"""
Regression guard: every `scanner/tests/test_ci_*.py` guard must be DOCUMENTED in
the catalog `docs/devsecops/ci-config-regression-guards.md`.

The catalog is the single source of truth for ClaudeSec's CI config regression
guard inventory: it records what each guard protects, its key assertions, and the
PR that landed it. A new guard added to `scanner/tests/` without a catalog row is
a silent documentation drift — the guard runs, but the inventory no longer
reflects reality, and the next engineer reading the catalog believes coverage is
complete when it is not. This guard makes that drift fail loudly and reviewably,
the same discipline the rest of the suite applies to CI YAML.

Semantics are PRESENCE: each guard file's repo-relative path (`scanner/tests/
test_ci_<name>.py`) must appear verbatim in the catalog text. Adding a guard
without listing it trips this; removing a guard file (and its row) stays green.
This guard documents ITSELF in the catalog too, so the invariant is uniform
across all `test_ci_*.py` files.

stdlib-only (Path glob + substring scan, no PyYAML — absent from
requirements-ci.txt). No network, no subprocess. Passes under pytest (the CI
runner) and `python3 -m unittest`. Does not import scanner/lib, so it never moves
the measured coverage gate.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_html_comments  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scanner" / "tests"
CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"
CATALOG = REPO_ROOT / CATALOG_REL


def missing_rows(catalog_text: str, guard_names) -> list:
    """Guard file names with no row in `catalog_text`, HTML-comment-stripped.

    Stripping `<!-- ... -->` first is load-bearing: Markdown has no `#` comment,
    so an HTML comment is the escape hatch. A row parked in one renders as
    nothing — the published inventory silently loses the guard — while a raw
    substring scan still finds the path and reports green. That is the Markdown
    form of the comment-evasion class the rest of the suite defends against."""
    active = strip_html_comments(catalog_text)
    return [name for name in guard_names if f"scanner/tests/{name}" not in active]


class TestCiCatalogCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog_text = (
            CATALOG.read_text(encoding="utf-8") if CATALOG.is_file() else ""
        )
        cls.guard_files = sorted(p.name for p in TESTS_DIR.glob("test_ci_*.py"))

    def test_catalog_exists(self):
        self.assertTrue(
            CATALOG.is_file(),
            f"CI guard catalog not found at {CATALOG} — path assumption broke",
        )

    def test_guard_files_found(self):
        # Canary: if the glob finds nothing, the path is wrong — fail loudly
        # rather than vacuously passing the completeness check below.
        self.assertTrue(
            self.guard_files,
            f"no test_ci_*.py guards found under {TESTS_DIR} — glob/path broke",
        )

    def test_every_guard_listed_in_catalog(self):
        missing = missing_rows(self.catalog_text, self.guard_files)
        self.assertEqual(
            missing,
            [],
            "CI config regression guard(s) missing from the catalog "
            f"({CATALOG_REL}):\n  "
            + ", ".join(missing)
            + "\nAdd a Catalog table row (Guard | Protects | Key assertions | "
            "Landed) for each new guard so the inventory stays the single source "
            "of truth.",
        )



class TestCatalogCompletenessDetector(unittest.TestCase):
    """Mutation self-tests — the guard shipped without any, so a parser
    regression would have gone unnoticed (Class 2 backlog item)."""

    _NAMES = ["test_ci_alpha.py", "test_ci_beta.py"]
    _ROWS = (
        "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |\n"
        "| `scanner/tests/test_ci_beta.py` | b | b | #2 |\n"
    )

    def test_documented_guards_are_not_missing(self):
        self.assertEqual(missing_rows(self._ROWS, self._NAMES), [])

    def test_undocumented_guard_is_detected(self):
        self.assertEqual(
            missing_rows(self._ROWS, self._NAMES + ["test_ci_gamma.py"]),
            ["test_ci_gamma.py"],
            "A guard with no catalog row was NOT detected.",
        )

    def test_row_parked_in_an_html_comment_does_not_count(self):
        mutant = self._ROWS.replace(
            "| `scanner/tests/test_ci_beta.py` | b | b | #2 |",
            "<!-- | `scanner/tests/test_ci_beta.py` | b | b | #2 | -->",
        )
        self.assertEqual(
            missing_rows(mutant, self._NAMES),
            ["test_ci_beta.py"],
            "A row hidden inside an HTML comment satisfied the presence check — "
            "the rendered inventory drops the guard while the check reads green.",
        )

    def test_multiline_html_comment_is_stripped(self):
        mutant = (
            "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |\n"
            "<!--\nparked for later:\n"
            "| `scanner/tests/test_ci_beta.py` | b | b | #2 |\n-->\n"
        )
        self.assertEqual(missing_rows(mutant, self._NAMES), ["test_ci_beta.py"])

    def test_unclosed_comment_marker_does_not_blank_the_catalog(self):
        # Degrades to no-strip rather than eating the document, which would make
        # every guard look undocumented at once.
        mutant = self._ROWS + "<!-- note without a closer\n"
        self.assertEqual(missing_rows(mutant, self._NAMES), [])

    def test_empty_catalog_reports_every_guard(self):
        self.assertEqual(missing_rows("", self._NAMES), self._NAMES)


if __name__ == "__main__":
    unittest.main()
