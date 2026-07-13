"""
Regression guard: no NEW unreachable (dead) top-level function accumulates in the
coverage-measured `scanner/lib` SUT files.

Why this guard exists
---------------------
The bash coverage floor (kcov, `scanner-shell-coverage`) measures *"was this line
executed by a test"* — NOT *"is this function reachable from the scanner"*. A
function that is called only by its own unit test therefore stays fully "covered"
while being dead code: it inflates the file, misleads readers, and survives every
existing gate. That exact class was cleaned up in the dead-code removal PR
(compute_trend, load_scan_history, the _html_findings_rows builders, html_escape,
api_key_found, compliance_map) — nothing prevented the next one from creeping in.

What it checks
--------------
For every TOP-LEVEL function defined in the four kcov SUT files, the guard looks
for at least one reference in the PRODUCTION corpus — the scanner entrypoint
(`scanner/claudesec`), the check scripts (`scanner/checks/**`, sourced and run at
scan time), and the library itself (`scanner/lib/**`, so a helper called only by
another lib function still counts). Whole-line `#` comments are stripped first
(a name in a comment is not a call) and the function's own definition line is not
counted as a reference. A function with ZERO production references is reachable
only from tests (or nowhere) — i.e. dead.

Regression-pin, not a big-bang cleanup
--------------------------------------
Three functions are currently dead and are recorded in `KNOWN_UNREFERENCED` as
documented removal-candidates (surfaced by this guard, deferred to a follow-up
because one cascades into `output_prowler.sh` + several test files):
  - `_prowler_dashboard_summary`  — leftover of the removed bash-HTML dashboard
    path (the Python `dashboard-gen.py` renders this now); sole caller of the
    `_prowler_dashboard_summary_provider_label` perf mirror.
  - `count_files`                 — dead sibling of the live `files_contain`.
  - `datadog_validate_api_key`    — superseded by `scanner/lib/datadog.sh` (#334).

The guard asserts the computed dead set EQUALS this baseline, so:
  * a NEW dead top-level function fails the guard (it is not in the baseline);
  * removing/​wiring-up a baselined function ALSO fails until it is dropped from
    `KNOWN_UNREFERENCED` — keeping the allowlist honest and the backlog visible.

Detection is conservative: a name appearing anywhere in production (even inside a
string) counts as referenced, so the guard only ever UNDER-reports dead code —
it will not false-positive and block a legitimately-reachable function, including
one invoked by dynamic dispatch that also names it elsewhere.

stdlib-only (no PyYAML). No `scanner/lib` import (does not touch the 99% coverage
gate). No network, no subprocess. Runs under pytest (the CI runner) and
`python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

# The four kcov-measured SUT libs (mirrors the scanner-shell-coverage
# --include-pattern). Network-I/O libs (datadog.sh) and the claudesec entrypoint
# are intentionally NOT measured and NOT scanned as definition sources here.
SUT_FILES = [
    "scanner/lib/checks.sh",
    "scanner/lib/checks_credentials.sh",
    "scanner/lib/output.sh",
    "scanner/lib/output_prowler.sh",
]

# Documented dead top-level functions (referenced only by tests). Removal
# candidates; drop each from this set in the PR that deletes it.
KNOWN_UNREFERENCED = {
    "_prowler_dashboard_summary",
    "count_files",
    "datadog_validate_api_key",
}

# Shared guard primitive (whole-line comment stripping). Import as a top-level
# module so it resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# A TOP-LEVEL bash function definition: `name() {` or `function name {`, at
# column 0 (no leading whitespace — nested functions are implementation details
# always referenced by their enclosing function).
DEF_RE = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")


def top_level_funcs(text: str) -> set:
    """Names of top-level function definitions in one file's text."""
    names = set()
    for line in text.splitlines():
        m = DEF_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def _referenced(name: str, corpus_texts: dict) -> bool:
    """True if `name` appears as a whole word anywhere in the production corpus,
    on any line that is not that function's own definition line."""
    word = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])")
    for text in corpus_texts.values():
        for line in text.splitlines():
            if not word.search(line):
                continue
            m = DEF_RE.match(line)
            if m and m.group(1) == name:
                continue  # the definition itself is not a reference
            return True
    return False


def compute_unreferenced(sut_texts: dict, corpus_texts: dict) -> set:
    """The set of top-level SUT function names with no production reference."""
    defined = set()
    for text in sut_texts.values():
        defined |= top_level_funcs(text)
    return {name for name in defined if not _referenced(name, corpus_texts)}


def _production_corpus() -> dict:
    """Comment-stripped text of every production file a lib function could be
    called from: the entrypoint, the check scripts, and the library itself."""
    files = [REPO_ROOT / "scanner" / "claudesec"]
    files += sorted((REPO_ROOT / "scanner" / "checks").rglob("*.sh"))
    files += sorted((REPO_ROOT / "scanner" / "lib").rglob("*.sh"))
    corpus = {}
    for f in files:
        if f.is_file():
            corpus[str(f)] = strip_comment_lines(f.read_text(encoding="utf-8"))
    return corpus


class TestScannerLibReachability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sut_texts = {}
        cls.missing = []
        for rel in SUT_FILES:
            p = REPO_ROOT / rel
            if p.is_file():
                cls.sut_texts[rel] = p.read_text(encoding="utf-8")
            else:
                cls.missing.append(rel)
        cls.corpus = _production_corpus()

    def test_sut_files_exist(self):
        self.assertEqual(
            self.missing, [],
            f"SUT lib file(s) not found: {self.missing} — a rename/move broke the "
            "reachability guard's definition source. Update SUT_FILES.",
        )

    def test_functions_found(self):
        # Canary: if parsing finds nothing, the regex/paths broke — fail loudly
        # rather than vacuously passing with an empty dead set.
        defined = set()
        for text in self.sut_texts.values():
            defined |= top_level_funcs(text)
        self.assertGreater(
            len(defined), 20,
            "Parsed suspiciously few top-level functions from the SUT files — "
            "the definition regex or file paths likely broke.",
        )

    def test_corpus_nonempty(self):
        self.assertTrue(
            self.corpus, "Production corpus is empty — check-script/entrypoint "
            "globbing broke; the guard would false-flag every function as dead.",
        )

    def test_no_new_dead_function(self):
        dead = compute_unreferenced(self.sut_texts, self.corpus)
        new_dead = dead - KNOWN_UNREFERENCED
        self.assertEqual(
            new_dead, set(),
            "NEW dead top-level function(s) in scanner/lib (defined but referenced "
            f"only by tests / nowhere in production): {sorted(new_dead)}. Either "
            "wire the function into the scanner, delete it (with its unit test), or "
            "— if intentionally kept — add it to KNOWN_UNREFERENCED with a reason.",
        )

    def test_no_stale_allowlist_entry(self):
        dead = compute_unreferenced(self.sut_texts, self.corpus)
        stale = KNOWN_UNREFERENCED - dead
        self.assertEqual(
            stale, set(),
            f"KNOWN_UNREFERENCED lists function(s) that are no longer dead: "
            f"{sorted(stale)} (removed, or now referenced in production). Drop them "
            "from KNOWN_UNREFERENCED so the baseline stays honest.",
        )


class TestReachabilityMutation(unittest.TestCase):
    """Synthetic fixtures prove the detector fires on a dead function and stays
    quiet on a reachable one — independent of the live tree."""

    _SUT = {
        "lib.sh": "\n".join([
            "live_entry() {",
            "  helper_used",
            "}",
            "helper_used() {",
            "  echo hi",
            "}",
            "dead_fn() {",
            "  echo bye",
            "}",
        ])
    }

    def test_reachable_helper_not_flagged(self):
        # live_entry referenced by entrypoint; helper_used referenced by live_entry.
        corpus = {
            "claudesec": "main() { live_entry; }",
            "lib.sh": self._SUT["lib.sh"],
        }
        dead = compute_unreferenced(self._SUT, corpus)
        self.assertNotIn("helper_used", dead)
        self.assertNotIn("live_entry", dead)

    def test_dead_function_flagged(self):
        corpus = {
            "claudesec": "main() { live_entry; }",
            "lib.sh": self._SUT["lib.sh"],
        }
        dead = compute_unreferenced(self._SUT, corpus)
        self.assertIn("dead_fn", dead)

    def test_comment_reference_does_not_rescue(self):
        # A commented-out call must NOT count as a production reference.
        corpus = {
            "claudesec": "main() { live_entry; }\n# dead_fn is old, do not call",
            "lib.sh": self._SUT["lib.sh"],
        }
        dead = compute_unreferenced(
            self._SUT, {k: strip_comment_lines(v) for k, v in corpus.items()}
        )
        self.assertIn("dead_fn", dead)

    def test_substring_is_not_a_reference(self):
        # `dead_fn_extended` must not satisfy a reference to `dead_fn`.
        corpus = {
            "claudesec": "main() { live_entry; dead_fn_extended; }",
            "lib.sh": self._SUT["lib.sh"],
        }
        dead = compute_unreferenced(self._SUT, corpus)
        self.assertIn("dead_fn", dead)


if __name__ == "__main__":
    unittest.main()
