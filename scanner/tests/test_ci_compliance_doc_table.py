"""
Regression guard: the SOC 2 table in the compliance guide matches the source.

THE INCIDENTS THIS EXISTS FOR
-----------------------------
`docs/guides/compliance-mapping.md` publishes the keyword list of each SOC 2
series as operator-facing reference. Nothing tied it to
`COMPLIANCE_CONTROL_MAP`, and it rotted three separate ways at once — every one
of the nine rows was wrong when this guard was written (measured 2026-08-18):

* `sso` on CC6 and `vulnerability` on CC3 are the PRE-#447/#452 spellings. Those
  PRs narrowed them to `_sso` and `vulnerab` precisely because `sso` matches
  "associated" and `vulnerability` missed "vulnerabilities". The doc kept
  advertising the forms that were removed for being wrong.
* `default` on CC5 is asserted ABSENT by a sibling guard —
  `test_ci_compliance_keyword_guard.py::test_cc5_does_not_carry_default`, whose
  docstring measured it recovering 0 of CC5's 21 missed checks while newly
  lighting 158 corpus-wide. The doc published a token CI rejects outright, so an
  operator reading the guide would re-propose it.
* `sast` on CC8 never existed in the source at all (removed for `sast` inside
  "disaster"), `branch_protection` was listed under CC6 when it belongs only to
  CC8, and CC1/CC2/CC9 rendered `—` while all three carry real keywords.

None of that changes runtime behaviour. It is worse than a behaviour bug in one
respect: a security guide that names false-positive-prone tokens as live is
actively misleading, and a docs-accuracy pass had already re-copied the stale
values once (the rename of the column header in that same pass did not check
them).

WHAT IS PINNED, AND IN WHICH DIRECTION
--------------------------------------
Equality, both ways: the doc's keyword column must equal
`COMPLIANCE_CONTROL_MAP["SOC 2 (TSC)"]` exactly, in order. Any edit to either
side trips the guard. That is deliberate — a one-directional "doc ⊆ source"
check would let the doc silently drop tokens, which is how CC1/CC2/CC9 came to
read `—`.

The native-check COUNTS in the same table are NOT pinned here and cannot be:
they are a property of the installed Prowler package, and no test in
`scanner/tests/` reads real Prowler data (CI does not install it).
`test_native_provider_scope.py` pins the mechanism; the counts are a measured
figure carrying their Prowler version, like the rest of this repo's
measurements.

stdlib-only (importlib to load the hyphenated module, regex for the table). No
PyYAML, no network, no subprocess. Importing compliance-map.py is fine — it is
already in the measured `scanner/lib` coverage set, so this guard does not move
the 99% floor. Runs under pytest (the CI runner) and `python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration): documentation that misstates
which detection tokens are live degrades every decision made from it.
"""

import importlib.util
import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDE = REPO_ROOT / "docs" / "guides" / "compliance-mapping.md"
COMPLIANCE_MAP_PATH = REPO_ROOT / "scanner" / "lib" / "compliance-map.py"

_spec = importlib.util.spec_from_file_location(
    "compliance_map_doc_table_guard", str(COMPLIANCE_MAP_PATH)
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP

FRAMEWORK = "SOC 2 (TSC)"

# A row of the SOC 2 series table:
#   | CC6 Logical and physical ... | PASS/FAIL | 136 | mfa, two_factor, ... |
# Anchored at line start so a `CC6` mentioned in prose cannot be read as a row.
_ROW = re.compile(
    r"^\|\s*(CC\d)\b[^|]*\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$", re.MULTILINE
)


def parse_doc_rows(text):
    """`{control: [keyword, ...]}` from the guide's SOC 2 series table.

    Tokens are rendered in backticks — `_sso` and `_approval` start with an
    underscore, which markdownlint reads as an emphasis marker in bare text
    (MD037) — so the backticks are stripped here rather than compared.

    An em dash in the keyword cell means "no keywords" and yields `[]`, so a row
    that drops its list is a detectable difference rather than a parse failure.
    """
    rows = {}
    for match in _ROW.finditer(text):
        control = match.group(1)
        cell = match.group(4).strip()
        if cell in ("", "—", "-"):
            rows[control] = []
        else:
            rows[control] = [
                tok.strip().strip("`") for tok in cell.split(",") if tok.strip()
            ]
    return rows


def source_rows():
    return {
        ctrl["control"]: list(ctrl["checks"])
        for ctrl in COMPLIANCE_CONTROL_MAP[FRAMEWORK]
    }


class TestSoc2DocTableMatchesSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = GUIDE.read_text(encoding="utf-8") if GUIDE.is_file() else ""
        cls.doc = parse_doc_rows(cls.text)
        cls.src = source_rows()

    def test_guide_exists(self):
        self.assertTrue(GUIDE.is_file(), f"{GUIDE} not found")

    def test_the_table_was_actually_found(self):
        """Canary. Without this the equality tests below pass vacuously the day
        the table is reformatted or moved — the exact way a guard reads green
        while guarding nothing."""
        self.assertEqual(
            sorted(self.doc),
            [f"CC{n}" for n in range(1, 10)],
            "Could not parse nine CC rows out of the SOC 2 table in "
            f"{GUIDE.name}. If the table moved or changed shape, update _ROW.",
        )

    def test_source_still_has_nine_series(self):
        self.assertEqual(sorted(self.src), [f"CC{n}" for n in range(1, 10)])

    def test_every_series_keyword_list_matches_exactly(self):
        for control in sorted(self.src):
            with self.subTest(control=control):
                self.assertEqual(
                    self.doc.get(control),
                    self.src[control],
                    f"{GUIDE.name}'s {control} row disagrees with "
                    f"COMPLIANCE_CONTROL_MAP[{FRAMEWORK!r}]. Copy the list from "
                    "the source; do not edit the doc alone.",
                )

    def test_no_documented_token_is_absent_from_the_source(self):
        """The specific rot this guard was written for. `sso`, `vulnerability`,
        `sast` and `default` were all published as live while the source had
        narrowed or deleted them."""
        every_source_token = {tok for toks in self.src.values() for tok in toks}
        for control, tokens in sorted(self.doc.items()):
            for token in tokens:
                with self.subTest(control=control, token=token):
                    self.assertIn(
                        token,
                        every_source_token,
                        f"{GUIDE.name} documents {token!r} on {control}, but no "
                        "SOC 2 control carries it. It was probably narrowed or "
                        "removed — see test_ci_compliance_keyword_guard.py.",
                    )

    def test_cc5_default_stays_out_of_the_doc_too(self):
        """A sibling guard keeps `default` out of the source; this keeps the
        guide from advertising it back in. Pinned by name because it is the one
        token the doc published that CI actively rejects."""
        self.assertNotIn("default", self.doc.get("CC5", []))


class TestParserIsNotVacuous(unittest.TestCase):
    """Attack the extractor, not just the assertion.

    A row regex that silently matches nothing turns every equality test above
    into a tautology, so the parser gets its own positive and negative cases.
    """

    TABLE = (
        "| Series | Status source | Native checks | Keyword fallback |\n"
        "|--------|---------------|---------------|------------------|\n"
        "| CC1 Control environment | **N/A** (governance) | 30 | `alpha`, `beta` |\n"
        "| CC9 Risk mitigation | **N/A** | 1 (gcp only) | — |\n"
    )

    def test_parses_a_keyword_row(self):
        self.assertEqual(parse_doc_rows(self.TABLE)["CC1"], ["alpha", "beta"])

    def test_a_leading_underscore_token_survives_backtick_stripping(self):
        """`_sso` and `_approval` are why the tokens are backticked at all —
        bare, markdownlint reads the underscore as an emphasis marker."""
        row = "| CC6 Access | PASS/FAIL | 136 | `mfa`, `_sso`, `_approval` |\n"
        self.assertEqual(parse_doc_rows(row)["CC6"], ["mfa", "_sso", "_approval"])

    def test_an_em_dash_cell_is_an_empty_list_not_a_missing_row(self):
        parsed = parse_doc_rows(self.TABLE)
        self.assertIn("CC9", parsed)
        self.assertEqual(parsed["CC9"], [])

    def test_prose_mentioning_a_series_is_not_read_as_a_row(self):
        prose = "CC6 is decided by keywords | sometimes | maybe | nope |\n"
        self.assertEqual(parse_doc_rows(prose), {})

    def test_a_changed_token_is_visible_to_the_parser(self):
        mutated = self.TABLE.replace("`alpha`, `beta`", "`alpha`, `gamma`")
        self.assertNotEqual(mutated, self.TABLE, "mutation fixture is stale")
        self.assertEqual(parse_doc_rows(mutated)["CC1"], ["alpha", "gamma"])

    def test_the_real_guide_is_not_parsed_as_empty(self):
        self.assertTrue(parse_doc_rows(GUIDE.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
