"""
Regression guard for the Lighthouse Performance gate (`lighthouserc.json`).

`lighthouse.yml` audits the live GitHub Pages deployment and asserts on the
Lighthouse categories declared in `lighthouserc.json`. Issue #19 added a hard
**Performance >= 0.90** gate alongside the pre-existing SEO and Accessibility
gates (live baseline 0.93 cold / 1.00 warm CDN, measured 2026-06). Silently
dropping the Performance assertion, downgrading it from `error` to `warn`, or
lowering its `minScore` floor below 0.90 would let a dashboard performance
regression deploy with no visible failure — exactly the drift the rest of the
`test_ci_*.py` suite guards against.

Two invariants, both silently weakenable:

1. **Each gated category keeps an `error`-level floor `>= 0.90`.** The three
   categories — `performance`, `seo`, `accessibility` — must each be present
   with severity `error` (not `warn`/`off`) and `minScore >= 0.9`. Direction is
   a floor (`>=`): ratcheting a threshold UP stays green; loosening it DOWN, or
   demoting the severity, trips this guard.

2. **`numberOfRuns >= 3`.** lhci asserts on the MEDIAN run, so a single run makes
   a hard Performance gate flaky (cold first paint vs. warm CDN cache swing the
   score). Reverting to `numberOfRuns: 1` re-introduces that flakiness; this
   guard pins the variance-damping floor.

`lighthouserc.json` is JSON, so this guard parses it with the stdlib `json`
module — no PyYAML (absent from requirements-ci.txt). No network, no subprocess,
does not import scanner/lib (so it never moves the measured coverage gate).
Passes under pytest (the CI runner) and `python3 -m unittest`.

OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control).
NIST SP 800-218 (SSDF) — PW.4.
"""

import json
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LIGHTHOUSERC = REPO_ROOT / "lighthouserc.json"

# Categories that MUST stay hard-gated at a >= 0.90 floor.
GATED_CATEGORIES = ("performance", "seo", "accessibility")

MIN_SCORE_FLOOR = 0.9
MIN_RUNS_FLOOR = 3


class TestLighthousePerfGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(LIGHTHOUSERC.read_text(encoding="utf-8"))
        cls.ci = cls.config.get("ci", {})
        cls.assertions = cls.ci.get("assert", {}).get("assertions", {})

    def test_lighthouserc_exists(self):
        self.assertTrue(
            LIGHTHOUSERC.is_file(),
            f"lighthouserc.json not found at {LIGHTHOUSERC} — path assumption broke",
        )

    def test_each_category_gated_at_floor(self):
        for cat in GATED_CATEGORIES:
            key = f"categories:{cat}"
            with self.subTest(category=cat):
                self.assertIn(
                    key,
                    self.assertions,
                    f"{key} assertion missing — {cat} regressions would deploy silently",
                )
                rule = self.assertions[key]
                # lhci shorthand form: ["error", { "minScore": 0.9 }]
                self.assertIsInstance(
                    rule, list, f"{key} must use the [severity, opts] array form"
                )
                self.assertEqual(
                    rule[0],
                    "error",
                    f"{key} severity must be 'error' (a hard gate), not '{rule[0]}'",
                )
                min_score = rule[1].get("minScore") if len(rule) > 1 else None
                self.assertIsNotNone(
                    min_score, f"{key} must declare a minScore floor"
                )
                self.assertGreaterEqual(
                    min_score,
                    MIN_SCORE_FLOOR,
                    f"{key} minScore {min_score} fell below the {MIN_SCORE_FLOOR} floor",
                )

    def test_number_of_runs_damps_variance(self):
        runs = self.ci.get("collect", {}).get("numberOfRuns")
        self.assertIsNotNone(
            runs, "collect.numberOfRuns missing — median-of-N variance damping lost"
        )
        self.assertGreaterEqual(
            runs,
            MIN_RUNS_FLOOR,
            f"numberOfRuns {runs} < {MIN_RUNS_FLOOR}: a single run makes the hard "
            "Performance gate flaky (cold vs. warm CDN swing)",
        )


if __name__ == "__main__":
    unittest.main()
