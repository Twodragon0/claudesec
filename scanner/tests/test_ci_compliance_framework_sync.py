r"""
Regression guard: README's `Frameworks Scored in the Compliance Report` table
names every framework `COMPLIANCE_CONTROL_MAP` scores, and states each one's
real control / N-A / scored counts.

WHY THIS GUARD EXISTS
---------------------
A framework shipped and the README never learned about it. Measured on
`origin/main` at the time of writing, `scanner/lib/compliance-map.py` held eight
frameworks and README mentioned `CMMC` **zero** times and `800-171` zero times,
while `CMMC 2.0 Level 2` had 14 controls in the map, a dedicated test
(`test_cmmc_native_map.py`), and a section of its own in
`docs/guides/compliance-mapping.md`. Three of the other seven — `PCI-DSS
v4.0.1`, `NIST 800-53 Rev5`, `KISA ISMS Simple` — were absent from the framework
table too.

This is the third instance of one class in three cycles. #561 found README
stating check counts the tree did not implement; #567 found README advertising
four slash commands that do not exist while omitting five that do. Each got a
guard. The compliance-framework surface was the one left unguarded, so it
drifted next.

The direction that matters here is the *silent* one. A missing row does not
read as missing — the table looks complete, because a reader has nothing to
compare it against. So a capability the project paid to build stays invisible,
and the number a reader would quote in an audit conversation comes from a table
that never claimed to be exhaustive and was not.

WHY A SECOND TABLE INSTEAD OF FIXING THE FIRST ONE
--------------------------------------------------
README's older `Supported Frameworks` table is NOT wrong, and equating it with
the map would make this guard wrong. It is deliberately wider: `OWASP Top 10`
and `OWASP LLM Top 10` are check categories, and `ISO 42001` and `NIST CSF` have
guides, but none of the four is a key in `COMPLIANCE_CONTROL_MAP` and none is
scored. A `map == that table` assertion would demand four rows be deleted that a
reader is right to see.

So the claim is split, and this guard binds to the narrow one only: what the
compliance report scores. That also removes the name-normalisation problem. The
rows carry the map key VERBATIM in a code span (`SOC 2 (TSC)`, not `SOC 2`;
`ISO 27001:2022`, not a `Framework | Version` pair), so the comparison is exact
string equality against `COMPLIANCE_CONTROL_MAP.keys()` — no fuzzy matching that
could silently accept a renamed framework. Display names are load-bearing
elsewhere in this repo (a native compliance match is framework-level, so a typo
marks every control FAIL), which is one more reason not to compare a prettified
label.

NOT A DUPLICATE of `test_ci_compliance_doc_table.py`, which pins the SOC 2 series
KEYWORD lists in `docs/guides/compliance-mapping.md`. Different document,
different subject: that one checks one framework's detection tokens, this one
checks which frameworks exist at all and how many controls each scores. Neither
would catch the other's drift.

DIRECTION: EQUALITY, code-authoritative.
    Adding a framework to the map without adding a row fails. Adding a row for a
    framework the map does not hold fails. Renaming a map key without updating
    the row fails. Editing a count fails. The map is the fact; README restates
    it.

WHY THE MAP IS READ WITH `ast`, NOT IMPORTED
--------------------------------------------
`ast.literal_eval` on the `COMPLIANCE_CONTROL_MAP` assignment gives the same
data with no import of `scanner/lib`, so this guard never moves the measured
coverage gate, and it runs unchanged in the package-free `ci-guards` runner. It
also cannot be satisfied by a module that merely defines the name at runtime:
the assignment must be a literal, and `test_the_map_is_a_literal_this_can_read`
fails loudly rather than skipping if that ever stops being true. A guard that
degrades to a skip when its subject moves is the vacuous pass this directory
exists to prevent.

WHY THE READER'S VIEW, NOT THE RAW TEXT
----------------------------------------
The rows are read out of `rendered_markdown(README)`, so a row hidden from
readers is hidden from this guard too and fails as a MISSING row — a closed
`<!-- -->`, a code fence, an HTML block, or an unterminated `<!--` above it all
remove it. The subject here is the table CELLS, and cells survive that
reduction while all four concealments do not, which is the property #567's
guard got wrong by reducing a section marker and then reading its subject from
raw text. The section slice is bounded at the next heading for the same reason
that guard's canary needed bounding: an unbounded search adopts whatever table
comes next and reports it as the subject.

CONSTRAINTS (same as every guard in this directory)
---------------------------------------------------
stdlib-only (`ast` + `re` + `pathlib` + the shared reduction; no PyYAML, no
`tomllib`). No network, no subprocess. Does not import `scanner/lib`. Passes
under pytest (the `scanner-unit-tests` runner) and `python3 -m unittest` (the
package-free `ci-guards` runner).

REACHABILITY: both entry points are covered by existing diff buckets, verified
against `lint.yml` rather than assumed. A PR editing the map touches
`scanner/lib/compliance-map.py`, which matches the `scanner` bucket
(`^(scanner/|…)`, line 127) and runs this under pytest. A PR editing only the
README touches `README.md`, which matches the `ci_config` bucket
(`…|[^/]*\.md$|…`, line 157) and runs this under `ci-guards`. Editing this file
matches `ci_config` too (`scanner/tests/(test_ci_|_ci_)`). No new `lint.yml`
entry is needed.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import ast
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    rendered_markdown,
)

README = REPO_ROOT / "README.md"
MAP_SOURCE = REPO_ROOT / "scanner" / "lib" / "compliance-map.py"

#: The name assigned in `MAP_SOURCE` that this guard treats as the fact.
MAP_NAME = "COMPLIANCE_CONTROL_MAP"

#: The README heading whose table restates it. Matched on the rendered text, so
#: a heading commented out or fenced away does not satisfy it.
SECTION_HEADING = "Frameworks Scored in the Compliance Report"

#: `| `key` | total | n/a | scored |` — the key MUST be backticked, so a row
#: cannot be satisfied by prose that happens to name a framework, and the three
#: cells MUST be bare integers, so a hedge (`~14`, `14+`) is not a count.
ROW = re.compile(
    r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$"
)


def map_frameworks() -> dict:
    """`{framework: (total, na, scored)}` measured from the map's source.

    Parsed, never imported. `assessable: False` is what the dashboard renders as
    N/A, so `scored` is the denominator of that framework's percentage — which
    is the number a published standard's control total (ISO 27001's 93, CMMC's
    110) does NOT reconcile with, and the confusion this column exists to end.
    """
    tree = ast.parse(MAP_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == MAP_NAME for t in node.targets
        ):
            continue
        data = ast.literal_eval(node.value)
        out = {}
        for framework, controls in data.items():
            na = sum(
                1
                for c in controls
                if isinstance(c, dict) and c.get("assessable") is False
            )
            out[framework] = (len(controls), na, len(controls) - na)
        return out
    return {}


def doc_rows(text: str) -> dict:
    """`{framework: (total, na, scored)}` from README, as a READER sees it.

    ORDER: reduce, THEN slice. Not interchangeable — slicing raw text and
    reducing after would let a concealed heading still bound a visible table,
    which is the split that made #567's guard green on a README whose list no
    reader could see.
    """
    reduced = rendered_markdown(text)
    lines = reduced.splitlines()

    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and SECTION_HEADING in line:
            start = i + 1
            break
    if start is None:
        return {}

    rows = {}
    for line in lines[start:]:
        # Bounded at the next heading of ANY level: an unbounded scan would run
        # on into `## Security Coverage Map` and beyond, and report whatever
        # table it found there as this section's.
        if line.lstrip().startswith("#"):
            break
        m = ROW.match(line.rstrip())
        if m:
            rows[m.group(1)] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
    return rows


class TheSubjectsAreWhereThisThinksTheyAre(unittest.TestCase):
    """Canaries. Each one fails loudly where a wrong answer would read as pass."""

    def test_the_map_source_exists(self):
        self.assertTrue(
            MAP_SOURCE.is_file(),
            f"{MAP_SOURCE} is missing. An earlier attempt at this measurement "
            "died on `scanner/compliance-map.py`, which does not exist — the "
            "map lives under `scanner/lib/`. If it moved, move this constant.",
        )

    def test_the_map_is_a_literal_this_can_read(self):
        frameworks = map_frameworks()
        self.assertTrue(
            frameworks,
            f"no `{MAP_NAME}` literal parsed out of {MAP_SOURCE.name}. Either "
            "it was renamed, or it is no longer a literal dict and "
            "`ast.literal_eval` can no longer read it. Do NOT relax this into "
            "a skip: an empty map compares equal to an empty README table, so "
            "every assertion below would pass while checking nothing.",
        )

    def test_every_framework_declares_controls(self):
        # A framework whose list is empty would make its row `0 | 0 | 0`, which
        # is the one wrong answer the comparison below cannot distinguish from
        # agreement.
        empty = sorted(k for k, v in map_frameworks().items() if v[0] == 0)
        self.assertEqual(
            empty,
            [],
            f"framework(s) in {MAP_NAME} with no controls: {empty}. A zero-row "
            "framework agrees with a zero-row README and proves nothing.",
        )

    def test_the_readme_table_is_found(self):
        rows = doc_rows(README.read_text(encoding="utf-8"))
        self.assertTrue(
            rows,
            f"no `{SECTION_HEADING}` rows parsed out of README.md. Either the "
            "heading changed, the table's shape changed, or the section is "
            "hidden from readers inside a comment, a fence, or an HTML block — "
            "`rendered_markdown` removes all three, so this guard sees exactly "
            "what a reader sees.",
        )


class TheTableMatchesTheMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = doc_rows(README.read_text(encoding="utf-8"))
        cls.frameworks = map_frameworks()

    def test_every_scored_framework_has_a_row(self):
        missing = sorted(set(self.frameworks) - set(self.rows))
        self.assertEqual(
            missing,
            [],
            f"framework(s) scored by {MAP_NAME} with no README row: {missing}. "
            "This is the drift the guard was written for — `CMMC 2.0 Level 2` "
            "shipped with 14 controls, a test and a guide section while README "
            "named it zero times. Add a row with the map key verbatim in a "
            "code span.",
        )

    def test_no_row_names_a_framework_that_is_not_scored(self):
        extra = sorted(set(self.rows) - set(self.frameworks))
        self.assertEqual(
            extra,
            [],
            f"README row(s) for framework(s) absent from {MAP_NAME}: {extra}. "
            "Either the map key was renamed and the row was not, or the row "
            "belongs in the wider `Supported Frameworks` table above — that "
            "one is allowed to list frameworks the report does not score.",
        )

    def test_each_row_states_the_measured_counts(self):
        wrong = {
            k: {"README": self.rows[k], "map": self.frameworks[k]}
            for k in sorted(set(self.rows) & set(self.frameworks))
            if self.rows[k] != self.frameworks[k]
        }
        self.assertEqual(
            wrong,
            {},
            "README states control counts the map does not hold "
            f"(framework: README vs measured, as `(total, n/a, scored)`): "
            f"{wrong}. The map is authoritative — edit the README.",
        )

    def test_each_row_is_internally_consistent(self):
        # Cheap, and catches the transcription slip the comparison above would
        # report as three separate wrong numbers without saying why.
        broken = {
            k: v for k, v in self.rows.items() if v[0] != v[1] + v[2]
        }
        self.assertEqual(
            broken,
            {},
            f"README row(s) where total != n/a + scored: {broken}.",
        )


if __name__ == "__main__":
    unittest.main()
