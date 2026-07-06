"""
Functional guard: short compliance keywords still POSITIVELY match.

Background
----------
`test_ci_compliance_keyword_guard.py` is a STATIC guard: it only asserts that
compliance keywords have no substring false-positive collisions with benign
words. It does not prove the keywords still do their job — a future edit
could accidentally drop or mangle a short acronym keyword (cve, iam, kms,
mfa, pii, ssl, ssn, sso, tls, vpc, xss) from `COMPLIANCE_CONTROL_MAP` without
any test catching the resulting false negative (a control that should FAIL
silently stays PASS).

This test closes that gap: for each short acronym keyword, it builds a
synthetic finding whose text contains the keyword (`map_compliance` uses a
plain `kw in text` substring match), runs it through `map_compliance()`, and
asserts every control that lists the keyword in its `checks` list flips to
`"FAIL"`.

The finding's `compliance` field is set to `{}` so `_match_prowler_compliance`
(the native-match path) cannot contribute a FAIL — only the keyword substring
match in `map_compliance()` is under test.

stdlib-only (importlib to load the hyphenated `compliance-map.py` module, same
approach as `test_compliance_map.py` / `test_ci_compliance_keyword_guard.py`).
No network, no on-disk fixtures.

OWASP CICD-SEC-7 (Insecure System Configuration) — a false negative here means
a real compliance gap is silently reported as PASS.
"""

import importlib.util
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
COMPLIANCE_MAP_PATH = REPO_ROOT / "scanner" / "lib" / "compliance-map.py"

_spec = importlib.util.spec_from_file_location(
    "compliance_map_positive", str(COMPLIANCE_MAP_PATH)
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP
map_compliance = _mod.map_compliance

# Short (<=3 char) acronym keywords documented in #307's guard as intentional
# and exempt from the "no short keywords" heuristic.
SHORT_KEYWORDS = ["cve", "iam", "kms", "mfa", "pii", "ssl", "ssn", "sso", "tls", "vpc", "xss"]


def _controls_with_keyword(keyword):
    """List of (framework, control_id) whose checks list contains `keyword`."""
    hits = []
    for framework, controls in COMPLIANCE_CONTROL_MAP.items():
        for ctrl in controls:
            if keyword in ctrl["checks"]:
                hits.append((framework, ctrl["control"]))
    return hits


def _make_finding_for_keyword(keyword):
    """A synthetic finding whose text contains `keyword` as a whole word."""
    return {
        "check": "test_check",
        "title": f"Synthetic finding containing {keyword} keyword",
        "message": f"This finding text mentions {keyword} as a standalone token.",
        "compliance": {},
    }


class TestShortKeywordsHaveControls(unittest.TestCase):
    """Sanity: every short keyword in SHORT_KEYWORDS actually appears in the
    map. If a keyword was removed entirely, this fires before the positive-
    match assertion would (which would otherwise vacuously pass with an empty
    control list)."""

    def test_each_short_keyword_maps_to_at_least_one_control(self):
        for keyword in SHORT_KEYWORDS:
            with self.subTest(keyword=keyword):
                hits = _controls_with_keyword(keyword)
                self.assertGreater(
                    len(hits),
                    0,
                    f"keyword {keyword!r} does not appear in any control's "
                    "checks list — either it was removed from the map, or "
                    "SHORT_KEYWORDS is stale.",
                )


class TestShortKeywordsPositivelyMatch(unittest.TestCase):
    """Each short acronym keyword must still trigger FAIL on every control
    that lists it, when a finding's text contains that keyword."""

    def test_short_keywords_trigger_fail_on_all_their_controls(self):
        for keyword in SHORT_KEYWORDS:
            expected_controls = _controls_with_keyword(keyword)
            with self.subTest(keyword=keyword):
                self.assertGreater(
                    len(expected_controls),
                    0,
                    f"keyword {keyword!r} maps to no controls — cannot assert "
                    "a positive match (see TestShortKeywordsHaveControls).",
                )
                finding = _make_finding_for_keyword(keyword)
                result = map_compliance([finding])
                for framework, control_id in expected_controls:
                    controls_by_id = {c["control"]: c for c in result[framework]}
                    ctrl = controls_by_id[control_id]
                    with self.subTest(framework=framework, control=control_id):
                        self.assertEqual(
                            ctrl["status"],
                            "FAIL",
                            f"keyword {keyword!r} did NOT trigger FAIL on "
                            f"{framework}/{control_id} (checks={ctrl['checks']!r}) "
                            "— this is a false negative: the keyword no longer "
                            "matches its own finding text.",
                        )
                        self.assertGreaterEqual(ctrl["count"], 1)


if __name__ == "__main__":
    unittest.main()
