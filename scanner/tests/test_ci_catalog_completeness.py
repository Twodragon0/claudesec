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

Semantics are PRESENCE: each guard file's name must appear in the INVENTORY,
`docs/devsecops/ci-guard-inventory.toml`. Adding a guard without listing it trips
this; removing a guard file (and its entry) stays green. This guard lists ITSELF,
so the invariant is uniform across all `test_ci_*.py` files.

**The inventory is a TOML file and not the published Markdown, as of this
change.** Reading the prose put the entire Markdown scan-evasion class between
this guard and its invariant: a row hidden in a closed comment, a code fence, an
HTML block, or after an unterminated comment opener renders as nothing a reader
can act on while a raw substring scan still finds it. #528 and #529 patched the
reduction and the second still left a measured 14 silent-pass shapes, because the
divergence is two-layer (markdown -> HTML -> browser) and a stdlib regex cannot
model it. ADR-001 §5 says to invert instead of patching an enumeration a third
time, so the comparison moved off prose entirely: **there is now no Markdown
anywhere in this guard's path**, and the residual cannot reach it.

The doc is still checked, deliberately more weakly, by
`test_ci_catalog_doc_sync.py` — the only remaining reader of the prose. Its
failure mode is documentation drift rather than a guard certifying an inventory
that does not exist, and degrading the published catalog now ALSO requires
editing the inventory, which fails the on-disk comparison here outright.

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
from _ci_guard_util import GUARD_INVENTORY, guard_inventory  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scanner" / "tests"
INVENTORY_REL = "docs/devsecops/ci-guard-inventory.toml"


def missing_rows(inventory_guards, guard_names) -> list:
    """Guard file names absent from `inventory_guards`.

    A set difference over a parsed TOML list — no text scanning, no reduction, no
    renderer. That is the whole point of the change: the previous version took a
    substring over reduced Markdown, which made every defect in the reduction a
    defect in this invariant. The signature takes the inventory list rather than
    document text so a caller cannot accidentally hand it prose again."""
    listed = set(inventory_guards)
    return [name for name in guard_names if name not in listed]


class TestCiCatalogCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = guard_inventory()["catalog"]["guards"]
        cls.guard_files = sorted(p.name for p in TESTS_DIR.glob("test_ci_*.py"))

    def test_inventory_exists(self):
        self.assertTrue(
            GUARD_INVENTORY.is_file(),
            f"guard inventory not found at {GUARD_INVENTORY} — path assumption broke",
        )

    def test_guard_files_found(self):
        # Canary: if the glob finds nothing, the path is wrong — fail loudly
        # rather than vacuously passing the completeness check below.
        self.assertTrue(
            self.guard_files,
            f"no test_ci_*.py guards found under {TESTS_DIR} — glob/path broke",
        )

    def test_inventory_is_not_empty(self):
        # The second half of the same canary, on the other operand. An empty
        # inventory would make the difference below equal every guard on disk
        # and fail loudly — but an inventory with ONE entry would not, so pin a
        # floor near the real count rather than mere non-emptiness.
        self.assertGreater(
            len(self.inventory),
            50,
            f"inventory holds only {len(self.inventory)} entries — it is "
            "supposed to list every guard, so this is a parse or path failure, "
            "not a small repo",
        )

    def test_inventory_is_sorted_and_unique(self):
        # A duplicate would hide a typo (one right entry, one wrong) and an
        # unsorted list makes every addition a merge conflict.
        self.assertEqual(
            self.inventory,
            sorted(set(self.inventory)),
            "inventory `catalog.guards` must be sorted and free of duplicates",
        )

    def test_every_guard_listed_in_inventory(self):
        missing = missing_rows(self.inventory, self.guard_files)
        self.assertEqual(
            missing,
            [],
            "CI config regression guard(s) missing from the inventory "
            f"({INVENTORY_REL}):\n  "
            + ", ".join(missing)
            + f"\nAdd each to `[catalog].guards` in {INVENTORY_REL}, and add a "
            "Catalog table row (Guard | Protects | Key assertions | Landed) to "
            "docs/devsecops/ci-config-regression-guards.md in the same commit — "
            "test_ci_catalog_doc_sync.py checks the second half.",
        )



class TestCatalogCompletenessDetector(unittest.TestCase):
    """Mutation self-tests for the detector.

    Rewritten when the comparison moved from prose to TOML. The old cases drove
    `missing_rows` with Markdown — a row in a closed comment, a multi-line
    comment, an unterminated opener — and every one of them is now meaningless
    here: this function never sees a document. Those vectors did not disappear,
    they MOVED, and they are asserted in `test_ci_catalog_doc_sync.py` against
    the one remaining reader of the prose. Deleting them outright would have
    dropped the coverage on the floor; that is the trap in a refactor like this."""

    _NAMES = ["test_ci_alpha.py", "test_ci_beta.py"]
    _LISTED = ["test_ci_alpha.py", "test_ci_beta.py"]

    def test_listed_guards_are_not_missing(self):
        self.assertEqual(missing_rows(self._LISTED, self._NAMES), [])

    def test_unlisted_guard_is_detected(self):
        self.assertEqual(
            missing_rows(self._LISTED, self._NAMES + ["test_ci_gamma.py"]),
            ["test_ci_gamma.py"],
            "a guard with no inventory entry was NOT detected",
        )

    def test_empty_inventory_reports_every_guard(self):
        self.assertEqual(missing_rows([], self._NAMES), self._NAMES)

    def test_order_is_reported_by_disk_not_inventory(self):
        # The result names what to ADD, so it follows the on-disk argument. If
        # it followed the inventory the message would omit exactly the entries
        # that are missing from it.
        self.assertEqual(
            missing_rows(["test_ci_beta.py"], ["test_ci_zeta.py", "test_ci_alpha.py"]),
            ["test_ci_zeta.py", "test_ci_alpha.py"],
        )

    def test_a_substring_match_does_not_satisfy_the_check(self):
        # The old prose version matched `scanner/tests/<name>` as a SUBSTRING, so
        # a longer path containing the shorter name counted as listing it. Set
        # membership does not, and pinning that keeps a future "optimisation"
        # back to substring matching from silently reintroducing it.
        self.assertEqual(
            missing_rows(["test_ci_alpha_extended.py"], ["test_ci_alpha.py"]),
            ["test_ci_alpha.py"],
            "a different, longer file name satisfied the presence check",
        )

    def test_prose_is_not_accepted_as_an_inventory(self):
        # Guards against the caller mistake the new signature exists to prevent:
        # handing this function catalog TEXT. A string is iterable, so without
        # this it would silently compare against its CHARACTERS and report every
        # guard as missing — loud, but for the wrong reason and confusing.
        catalog_text = "| `scanner/tests/test_ci_alpha.py` | a | a | #1 |\n"
        self.assertEqual(
            missing_rows(catalog_text, self._NAMES),
            self._NAMES,
            "prose was accepted as an inventory rather than reporting everything "
            "missing — check the call site, not this assertion",
        )


if __name__ == "__main__":
    unittest.main()
