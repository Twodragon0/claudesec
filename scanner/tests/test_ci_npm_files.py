"""
Regression guard for the npm package payload (`package.json` "files" allowlist).

Three silently-weakenable packaging invariants, all proven by an actual incident
(the published tarball had ballooned to ~43 MB / 536 files before #261):

1. **`docs/` must NOT be in `files[]`.** It is not read at runtime — the scanner
   only *writes* `$SCAN_DIR/docs/architecture` into the user's project. Listing
   `docs/` ships the whole tree, including two `.pptx` seminar templates totalling
   ~38 MB. Re-adding `docs/` (e.g. "ship the docs with the CLI") silently re-bloats
   every install with no test failure.

2. **Operator-only scripts must stay excluded** via negated `files[]` patterns.
   `scripts/` is shipped wholesale (the CLI needs `setup.sh`, `run-*.sh`, etc.),
   so the company-internal helpers (cost-xlsx / license / PC-sheet trackers and
   Google-Sheets auth) are removed with `!scripts/<name>` negations. Dropping a
   negation re-publishes internal operational tooling to the public registry —
   an information-exposure regression that no other check catches.
   (`.npmignore` CANNOT express this: paths under a dir listed in `files[]` take
   precedence over `.npmignore`, confirmed empirically via `npm publish --dry-run`.)

3. **`CHANGELOG.md` must stay in `files[]`** so the release notes ship with the
   package (npm would include it by default, but the repo convention is to list
   README/LICENSE/CHANGELOG explicitly; dropping it here is a quiet drift).

`package.json` is JSON, so this guard parses it with the stdlib `json` module —
no PyYAML (absent from requirements-ci.txt). No network, no subprocess, does not
import scanner/lib. Passes under pytest and `python3 -m unittest`.
"""

import fnmatch
import json
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_JSON = REPO_ROOT / "package.json"

# Operator-only scripts that must NOT ship to the public npm package.
# Each must be present as a negated pattern in files[].
EXCLUDED_SCRIPTS = (
    "scripts/sync-cost-xlsx.py",
    "scripts/update-license-active-accounts.py",
    "scripts/update-pc-sheet.py",
    "scripts/full-asset-sync.py",
    "scripts/gsheet-auth.py",
    "scripts/gsheet-auth-setup.py",
)


def _normalize(entry: str) -> str:
    return entry.strip().rstrip("/")


def _pattern_matches(pattern: str, path: str) -> bool:
    """Does a (positive, already-normalized) `files[]` pattern cover `path`?
    A bare dir/file (`scripts`) covers itself and everything under it; globs
    (`scripts/*`, `docs/**`) match via fnmatch (npm globs are not slash-aware,
    matching fnmatch's behaviour closely enough for this guard)."""
    return path == pattern or path.startswith(pattern + "/") or fnmatch.fnmatch(path, pattern)


def _is_shipped(files: list, path: str) -> bool:
    """Resolve whether `path` ends up in the tarball. npm applies `files[]` in
    order with negations removing matches, so the LAST matching entry wins —
    a positive pattern re-added AFTER its `!negation` re-ships the path. Order-
    aware, unlike a set-membership check (the audit's order-blind finding)."""
    shipped = False
    for entry in files:
        e = entry.strip()
        neg = e.startswith("!")
        if _pattern_matches(_normalize(e[1:] if neg else e), path):
            shipped = not neg
    return shipped


class TestNpmFilesAllowlist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exists = PACKAGE_JSON.is_file()
        cls.files = []
        if cls.exists:
            data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
            cls.files = list(data.get("files", []))

    def test_package_json_exists(self):
        self.assertTrue(self.exists, f"{PACKAGE_JSON} not found")

    def test_has_files_allowlist(self):
        self.assertTrue(
            self.files,
            'package.json has no "files" allowlist — every working-tree file '
            "(scan reports, .pptx, __pycache__) would be eligible for publish.",
        )

    def test_docs_not_shipped(self):
        # Any positive entry that pulls in docs/ — `docs`, `docs/`, `docs/*`,
        # `docs/**`, or a `docs/<subdir>` — all re-ship the tree (glob-family,
        # not just the two enumerated forms the audit found bypassable).
        offenders = [
            e
            for e in self.files
            if not e.lstrip().startswith("!")
            and (_normalize(e) == "docs" or _normalize(e).startswith("docs/"))
        ]
        self.assertEqual(
            offenders,
            [],
            "`docs/` is back in package.json files[] — this re-ships ~38 MB of "
            ".pptx seminar templates that are not used at runtime (incident #261). "
            f"Offending entries: {offenders}",
        )

    def test_operator_scripts_excluded(self):
        # Order-aware: a `!scripts/x` negation only holds if no LATER positive
        # pattern re-includes it (npm files[] is last-match-wins).
        shipped = [s for s in EXCLUDED_SCRIPTS if _is_shipped(self.files, s)]
        self.assertEqual(
            shipped,
            [],
            "Operator-only scripts would publish to the public npm registry "
            "(information exposure) — either their `!scripts/...` negation is "
            "missing, or a later positive `files[]` pattern re-includes them "
            "(order-blind bypass). Re-exclude:\n  " + "\n  ".join(shipped),
        )

    def test_scripts_dir_still_shipped(self):
        # The negations only matter if scripts/ is actually included.
        normalized = {_normalize(e) for e in self.files}
        self.assertIn(
            "scripts",
            normalized,
            "`scripts/` dropped from files[] — the CLI's setup/run helpers would "
            "stop shipping, and the operator-script negations become meaningless.",
        )

    def test_changelog_shipped(self):
        normalized = {_normalize(e) for e in self.files}
        self.assertIn(
            "CHANGELOG.md",
            normalized,
            "CHANGELOG.md dropped from files[] — release notes stop shipping with "
            "the package (repo convention lists README/LICENSE/CHANGELOG).",
        )


class TestNpmFilesResolverSelfTest(unittest.TestCase):
    """Mutation self-tests for the glob-family / order-aware resolution."""

    def test_docs_recursive_glob_is_flagged(self):
        # `docs/**` shipped the tree but the old `in ("docs","docs/*")` check
        # missed it (audit finding). It must now count as a docs offender.
        for form in ("docs", "docs/", "docs/*", "docs/**", "docs/architecture"):
            self.assertTrue(
                _normalize(form) == "docs" or _normalize(form).startswith("docs/"),
                f"docs form {form!r} not recognised as shipping docs/",
            )

    def test_negation_then_positive_reships(self):
        # `!scripts/x` followed by a later positive `scripts/x` re-ships it
        # (last-match-wins). The order-blind set check missed this.
        files = ["scripts", "!scripts/gsheet-auth.py", "scripts/gsheet-auth.py"]
        self.assertTrue(
            _is_shipped(files, "scripts/gsheet-auth.py"),
            "resolver is order-blind: a positive pattern after the negation must "
            "re-ship the path.",
        )

    def test_negation_last_excludes(self):
        # The real, correct order: dir include then negation → excluded.
        files = ["scripts", "!scripts/gsheet-auth.py"]
        self.assertFalse(
            _is_shipped(files, "scripts/gsheet-auth.py"),
            "a `!scripts/x` negation after the `scripts` include must exclude it.",
        )


if __name__ == "__main__":
    unittest.main()
