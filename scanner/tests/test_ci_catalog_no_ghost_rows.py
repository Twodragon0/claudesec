"""
Regression guard: every guard NAMED in the inventory
`docs/devsecops/ci-guard-inventory.toml` must EXIST on disk.

This is the reverse of `test_ci_catalog_completeness.py`. That guard catches a
guard file added without an inventory entry (under-documentation); this one
catches the opposite — a "ghost" entry naming a guard which was renamed or
deleted without updating the inventory. A ghost entry makes the inventory
OVERstate coverage: a reader trusts that protection exists when the file behind
it is gone.

Together the two guards make the inventory and the on-disk guard suite a verified
1:1 mapping. Same risk class as the rest of the suite — OWASP CICD-SEC-1
(Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.

Semantics are EXISTENCE: each guard named in the INVENTORY,
`docs/devsecops/ci-guard-inventory.toml`, must resolve to a real file.

**The inventory is a TOML file and not the published Markdown, as of this
change.** Reading the prose made this guard's verdict depend on the Markdown
reduction, whose residual was measured at 14 silent-pass shapes and cannot be
closed by a stdlib regex (the divergence is markdown -> HTML -> browser, two
layers). ADR-001 §5 says to invert rather than patch an enumeration a third
time, so the comparison is now a set of names against `Path.is_file` with **no
Markdown in the path at all**. The prose glob problem disappears with it: an
inventory holds names, never globs, so there is nothing to skip.

stdlib-only (`tomllib` + `Path.is_file`; no PyYAML, absent from
requirements-ci.txt). No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import GUARD_INVENTORY, guard_inventory  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_REL = "docs/devsecops/ci-guard-inventory.toml"


def listed_paths(inventory_guards) -> list:
    """Repo-relative guard paths named in the inventory, sorted.

    The inventory stores bare file NAMES; the `scanner/tests/` prefix is applied
    here so the rest of this guard, and its failure message, still speak in
    repo-relative paths a reader can paste into an editor."""
    return sorted(f"scanner/tests/{name}" for name in inventory_guards)


def ghost_rows(inventory_guards, repo_root: Path) -> list:
    """Inventory entries with no file on disk."""
    return [
        rel for rel in listed_paths(inventory_guards) if not (repo_root / rel).is_file()
    ]


class TestCiCatalogNoGhostRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = guard_inventory()["catalog"]["guards"]
        cls.listed = listed_paths(cls.inventory)

    def test_inventory_exists(self):
        self.assertTrue(
            GUARD_INVENTORY.is_file(),
            f"guard inventory not found at {GUARD_INVENTORY} — path assumption broke",
        )

    def test_paths_listed(self):
        # Canary: an empty inventory makes "no ghosts" trivially true. A floor
        # near the real count rather than mere non-emptiness, because a
        # one-entry inventory would also pass a non-empty check.
        self.assertGreater(
            len(self.listed),
            50,
            f"inventory holds only {len(self.listed)} entries — parse or path "
            f"failure in {INVENTORY_REL}, not a small repo",
        )

    def test_every_listed_collector_exists(self):
        """The other list in the same file, which had no existence check.

        A review measured `"test_ci_zzz_never_existed.py"` in
        `[block_collectors].modules` plus a matching doc row passing everything:
        `test_ci_collector_table_completeness` only asserts detected-minus-listed
        (extras are legitimate — see its `test_extra_rows_are_allowed`), so a
        ghost collector was nobody's business. Not a regression, since the old
        prose table had no existence check either, but a free asymmetry to close
        inside the one file that already does existence checking."""
        modules = guard_inventory()["block_collectors"]["modules"]
        ghosts = [
            m
            for m in modules
            if not (REPO_ROOT / "scanner" / "tests" / m).is_file()
        ]
        self.assertEqual(
            ghosts,
            [],
            f"`[block_collectors].modules` in {INVENTORY_REL} names module(s) "
            "with no file under scanner/tests:\n  " + ", ".join(ghosts),
        )

    def test_every_listed_path_exists(self):
        ghosts = [rel for rel in self.listed if not (REPO_ROOT / rel).is_file()]
        self.assertEqual(
            ghosts,
            [],
            f"Inventory ({INVENTORY_REL}) names guard file(s) that no longer "
            "exist on disk:\n  "
            + ", ".join(ghosts)
            + "\nA renamed/deleted guard left a ghost entry — the inventory now "
            "overstates coverage. Update or remove it, and its catalog row.",
        )



class TestGhostRowDetector(unittest.TestCase):
    """Mutation self-tests for the detector.

    Rewritten when the comparison moved from prose to TOML. The old cases fed
    `ghost_rows` catalog text — a commented-out ghost that must NOT be reported,
    a commented ghost that must not mask a live one, a prose glob that is not a
    path, duplicate citations collapsing. None of those can happen to a parsed
    list of names, and all of them were about the Markdown reduction rather than
    about ghost detection. They MOVED to `test_ci_catalog_doc_sync.py`, which is
    where prose is still read; they were not dropped."""

    _REAL = "test_ci_catalog_no_ghost_rows.py"   # this file
    _GHOST = "test_ci_definitely_not_a_real_guard.py"

    def test_real_entry_is_not_a_ghost(self):
        self.assertEqual(ghost_rows([self._REAL], REPO_ROOT), [])

    def test_deleted_guard_entry_is_detected(self):
        self.assertEqual(
            ghost_rows([self._GHOST], REPO_ROOT),
            [f"scanner/tests/{self._GHOST}"],
            "an inventory entry naming a nonexistent guard file was NOT "
            "detected — the inventory would overstate coverage",
        )

    def test_empty_inventory_has_no_ghosts(self):
        # Vacuously true by construction, which is exactly why the class above
        # pins a count floor on the REAL inventory rather than relying on this.
        self.assertEqual(ghost_rows([], REPO_ROOT), [])

    def test_a_ghost_is_reported_alongside_real_entries(self):
        # The live one must not mask the ghost, the property the old
        # commented-ghost case was really about.
        self.assertEqual(
            ghost_rows([self._REAL, self._GHOST], REPO_ROOT),
            [f"scanner/tests/{self._GHOST}"],
        )

    def test_paths_are_repo_relative_and_sorted(self):
        self.assertEqual(
            listed_paths(["test_ci_zeta.py", "test_ci_alpha.py"]),
            ["scanner/tests/test_ci_alpha.py", "scanner/tests/test_ci_zeta.py"],
        )

    def test_existence_is_checked_under_scanner_tests_not_the_repo_root(self):
        # The prefix is load-bearing. `SECURITY.md` exists at the repo root and
        # NOT under scanner/tests, so if the prefix were ever dropped this entry
        # would resolve and a ghost would look real — a verdict that depends on
        # which directory the name happens to match.
        #
        # `README.md` was the original choice and it was a landmine: this file
        # names `scanner/tests/<that>.md` as a path literal, and
        # `test_ci_guard_self_verify.guard_data_files()` collects `.md` path
        # literals out of the guards by AST. Measured — creating
        # `scanner/tests/README.md`, which is a perfectly ordinary thing to do,
        # took THREE tests across TWO guards red: this one (the fixture stopped
        # being a ghost) and two bucket-coverage assertions (the census promoted
        # the fixture into a path the `ci_config` bucket must match). A negative
        # fixture whose whole premise is "this file does not exist" must not name
        # a file anyone would plausibly create. `scanner/tests/SECURITY.md` is
        # such a name; the census residual is documented where it lives, in
        # `guard_data_files()`.
        #
        # THE RENAME IS PROBABILITY MITIGATION, NOT CLOSURE, and measurement says
        # so plainly: `SECURITY.md` inherits the landmine in full, and committing
        # one now costs FOUR reds where `README.md` cost three — the original
        # three plus `test_the_census_demands_no_markdown_under_scanner_tests`,
        # which was added to name the cause. The trade is deliberate: a louder,
        # self-explaining failure on a path nobody will take, instead of a quiet
        # one on a path someone might. Closing it properly means teaching the
        # census to tell a path a guard READS from one it merely NAMES, which is
        # attribution, and this repo has not found a static way to do that.
        self.assertEqual(
            ghost_rows(["SECURITY.md"], REPO_ROOT),
            ["scanner/tests/SECURITY.md"],
            "existence was checked somewhere other than scanner/tests",
        )


if __name__ == "__main__":
    unittest.main()
