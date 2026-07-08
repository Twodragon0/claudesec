"""
Regression guard: `scanner/lib/diagram-gen.py` MUST single-source its security
architecture domains and compliance frameworks from the canonical modules —
never re-declare inline copies that can drift.

Background
----------
diagram-gen.py previously carried an inline `ARCH_DOMAINS` list (only 6 of the
canonical 8 domains, name+icon only) and an inline `frameworks` string list
(6 of 11 frameworks, with stale/mis-versioned names like "ISO 27001" instead of
"ISO 27001:2022"). Both silently drifted from `dashboard_arch.ARCH_DOMAINS` and
`dashboard_compliance.COMPLIANCE_FRAMEWORKS`, so the generated architecture
diagram showed an outdated domain/framework set — the same drift bug-class as
the removed `dashboard_compliance` inline `COMPLIANCE_CONTROL_MAP` fallback.

The fix imports both from the canonical modules and removes the inline copies:

    from dashboard_arch import ARCH_DOMAINS
    from dashboard_compliance import COMPLIANCE_FRAMEWORKS
    ...
    frameworks = [f["name"] for f in COMPLIANCE_FRAMEWORKS]

This guard asserts the single-sourcing holds so a future edit cannot silently
reintroduce a divergent inline copy.

Detection strategy
------------------
1. Source-level (comment-stripped): diagram-gen.py must contain the two
   canonical imports, must NOT reassign `ARCH_DOMAINS = [...]`, and must derive
   frameworks via `[f["name"] for f in COMPLIANCE_FRAMEWORKS]` (no inline list
   of framework name string literals).
2. Functional (importlib load, since the filename has a hyphen): the loaded
   module's `ARCH_DOMAINS` must be the *same object* as
   `dashboard_arch.ARCH_DOMAINS` — proof it is imported, not copied.
Includes a mutation self-test verifying the source detector fires on a
synthetic inline `ARCH_DOMAINS = [` reassignment.

stdlib-only: no PyYAML, no third-party deps. Runs under pytest (CI) and
`python3 -m unittest`. No network, no subprocess.
"""

import importlib.util
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_DIR = REPO_ROOT / "scanner" / "lib"
DIAGRAM_GEN = LIB_DIR / "diagram-gen.py"
CLAUDESEC = REPO_ROOT / "scanner" / "claudesec"

# The canonical bash scan-category array (single source of truth).
_BASH_ALL_CATEGORIES_RE = re.compile(
    r"readonly\s+-a\s+CLAUDESEC_ALL_CATEGORIES=\((.*?)\)", re.DOTALL
)
# The old inline form we forbid re-introducing: a literal category list on a
# lowercase `categories=(` assignment instead of expanding the canonical array.
# Case-sensitive, so it does NOT match the uppercase CLAUDESEC_ALL_CATEGORIES decl.
_BASH_INLINE_CATEGORIES_RE = re.compile(r"categories=\(\s*infra\s+ai\s+network")

# An inline reassignment of the canonical list (the drift we forbid).
_INLINE_ARCH_RE = re.compile(r"^\s*ARCH_DOMAINS\s*=\s*\[", re.MULTILINE)
# A hand-rolled frameworks list of string literals (the old inline copy).
_INLINE_FRAMEWORKS_RE = re.compile(
    r"frameworks\s*=\s*\[\s*[\"']", re.MULTILINE
)
_IMPORT_ARCH_RE = re.compile(
    r"^\s*from\s+dashboard_arch\s+import\s+.*\bARCH_DOMAINS\b", re.MULTILINE
)
_IMPORT_FRAMEWORKS_RE = re.compile(
    r"^\s*from\s+dashboard_compliance\s+import\s+.*\bCOMPLIANCE_FRAMEWORKS\b",
    re.MULTILINE,
)
_DERIVE_FRAMEWORKS_RE = re.compile(
    r"frameworks\s*=\s*\[\s*f\[[\"']name[\"']\]\s+for\s+f\s+in\s+COMPLIANCE_FRAMEWORKS\s*\]"
)


def _load_diagram_gen():
    """Load diagram-gen.py (hyphenated filename) via importlib."""
    # diagram-gen.py inserts its own dir on sys.path for sibling imports.
    spec = importlib.util.spec_from_file_location("diagram_gen_sync", DIAGRAM_GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bash_all_categories():
    """Parse CLAUDESEC_ALL_CATEGORIES=( ... ) from scanner/claudesec -> list."""
    m = _BASH_ALL_CATEGORIES_RE.search(CLAUDESEC.read_text(encoding="utf-8"))
    return m.group(1).split() if m else None


class TestDiagramGenCanonicalSync(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = DIAGRAM_GEN.read_text(encoding="utf-8")
        cls.stripped = strip_comment_lines(cls.src)

    def test_imports_canonical_arch_domains(self):
        self.assertRegex(
            self.stripped,
            _IMPORT_ARCH_RE,
            "diagram-gen.py must `from dashboard_arch import ARCH_DOMAINS`",
        )

    def test_imports_canonical_frameworks(self):
        self.assertRegex(
            self.stripped,
            _IMPORT_FRAMEWORKS_RE,
            "diagram-gen.py must `from dashboard_compliance import COMPLIANCE_FRAMEWORKS`",
        )

    def test_no_inline_arch_domains_reassignment(self):
        self.assertIsNone(
            _INLINE_ARCH_RE.search(self.stripped),
            "diagram-gen.py must NOT redefine ARCH_DOMAINS inline (import it)",
        )

    def test_frameworks_derived_from_canonical(self):
        self.assertRegex(
            self.stripped,
            _DERIVE_FRAMEWORKS_RE,
            "frameworks must derive from COMPLIANCE_FRAMEWORKS, not an inline list",
        )

    def test_no_inline_frameworks_string_list(self):
        self.assertIsNone(
            _INLINE_FRAMEWORKS_RE.search(self.stripped),
            "diagram-gen.py must NOT hardcode a frameworks string list",
        )

    def test_arch_domains_is_same_object_as_canonical(self):
        mod = _load_diagram_gen()
        sys.path.insert(0, str(LIB_DIR))
        import dashboard_arch  # noqa: E402

        self.assertIs(
            mod.ARCH_DOMAINS,
            dashboard_arch.ARCH_DOMAINS,
            "diagram-gen ARCH_DOMAINS must be the canonical object, not a copy",
        )

    def test_mutation_self_test_detects_inline_reassignment(self):
        """The detector must fire on a synthetic inline reassignment."""
        bad = 'import os\nARCH_DOMAINS = [\n    {"name": "X", "icon": "?"},\n]\n'
        self.assertIsNotNone(
            _INLINE_ARCH_RE.search(strip_comment_lines(bad)),
            "detector should flag an inline ARCH_DOMAINS reassignment",
        )

    # -- CATEGORIES single-source parity (bash <-> diagram-gen) ---------------

    def test_categories_mirror_bash_canonical_order(self):
        bash_cats = _bash_all_categories()
        self.assertIsNotNone(
            bash_cats,
            "CLAUDESEC_ALL_CATEGORIES array not found in scanner/claudesec",
        )
        mod = _load_diagram_gen()
        self.assertEqual(
            mod.CATEGORIES,
            bash_cats,
            "diagram-gen CATEGORIES must exactly mirror scanner/claudesec "
            "CLAUDESEC_ALL_CATEGORIES — same members AND order, since the "
            "CATEGORIES[:8]/[:7] diagram-label slices depend on order",
        )

    def test_bash_category_list_is_single_sourced(self):
        stripped = strip_comment_lines(CLAUDESEC.read_text(encoding="utf-8"))
        self.assertIsNone(
            _BASH_INLINE_CATEGORIES_RE.search(stripped),
            "scanner/claudesec must expand CLAUDESEC_ALL_CATEGORIES, not inline "
            "the category list on a lowercase categories=(...) assignment",
        )

    def test_categories_parity_self_test_detects_reorder(self):
        """Sanity: a reordered copy must not compare equal to the bash source."""
        bash_cats = _bash_all_categories()
        self.assertNotEqual(bash_cats, list(reversed(bash_cats)))


if __name__ == "__main__":
    unittest.main()
