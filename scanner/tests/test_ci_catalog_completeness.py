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

import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scanner" / "tests"
CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"
CATALOG = REPO_ROOT / CATALOG_REL


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
        missing = [
            name
            for name in self.guard_files
            if f"scanner/tests/{name}" not in self.catalog_text
        ]
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


if __name__ == "__main__":
    unittest.main()
