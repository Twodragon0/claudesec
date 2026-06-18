"""
Regression guard: every `scanner/tests/test_ci_*.py` path CITED in the catalog
`docs/devsecops/ci-config-regression-guards.md` must EXIST on disk.

This is the reverse of `test_ci_catalog_completeness.py`. That guard catches a
guard file added without a catalog row (under-documentation); this one catches
the opposite — a "ghost" catalog row that names a guard which was renamed or
deleted without updating the catalog. A ghost row makes the inventory OVERstate
coverage: a reader trusts that protection exists when the file behind it is gone.

Together the two guards make the catalog and the on-disk guard suite a verified
1:1 mapping. Same risk class as the rest of the suite — OWASP CICD-SEC-1
(Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.

Semantics are EXISTENCE: each concrete `scanner/tests/test_ci_<name>.py` path in
the catalog must resolve to a real file. The glob `scanner/tests/test_ci_*.py`
(used in prose) is intentionally skipped — `*` is not a filename character, so
the path regex never matches it.

stdlib-only (regex + Path.is_file, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"
CATALOG = REPO_ROOT / CATALOG_REL

# Concrete guard paths only; `*` is not matched, so the prose glob
# `scanner/tests/test_ci_*.py` is skipped by construction.
CITED_PATH_RE = re.compile(r"scanner/tests/test_ci_[A-Za-z0-9_]+\.py")


class TestCiCatalogNoGhostRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = CATALOG.read_text(encoding="utf-8") if CATALOG.is_file() else ""
        cls.cited = sorted(set(CITED_PATH_RE.findall(text)))

    def test_catalog_exists(self):
        self.assertTrue(
            CATALOG.is_file(),
            f"CI guard catalog not found at {CATALOG} — path assumption broke",
        )

    def test_paths_cited(self):
        # Canary: the catalog must cite at least one concrete guard path. If the
        # regex stops matching, fail loudly rather than vacuously passing.
        self.assertTrue(
            self.cited,
            f"no scanner/tests/test_ci_*.py paths found in {CATALOG_REL} — "
            "regex/format drift",
        )

    def test_every_cited_path_exists(self):
        ghosts = [rel for rel in self.cited if not (REPO_ROOT / rel).is_file()]
        self.assertEqual(
            ghosts,
            [],
            f"Catalog ({CATALOG_REL}) cites guard file(s) that no longer exist "
            "on disk:\n  "
            + ", ".join(ghosts)
            + "\nA renamed/deleted guard left a ghost row — the inventory now "
            "overstates coverage. Update or remove the Catalog row.",
        )


if __name__ == "__main__":
    unittest.main()
