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

MUTATION SELF-TESTS
-------------------
The checks are expressed as a `gate_violations(config)` detector rather than
assertions written straight against the real file, so each weakening can be
proven to be caught: a demoted severity, a lowered `minScore`, a deleted
category, the un-shorthand `{"minScore": ...}` object form (which has no
severity at all and therefore no hard gate), and `numberOfRuns: 1`. Assertions
that only ever see a PASSING config cannot be distinguished from assertions that
never run — the ADR-001 §2 inert-assertion class this repo has hit before.

Being a detector also removes a real fragility of the earlier shape: it read
`rule[1]["minScore"]` unconditionally, so a malformed rule raised
`AttributeError`/`IndexError` instead of reporting a violation. Malformed is now
reported as a violation like any other — the gate is not enforcing either way.

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


def category_violations(config: dict) -> list:
    """Reasons `config`'s category gates are weaker than the documented floor.

    Every branch REPORTS rather than raises: a rule of the wrong shape is a gate
    that is not enforcing, which is the same finding as a lowered floor and must
    read as one, not as a test error."""
    assertions = config.get("ci", {}).get("assert", {}).get("assertions", {})
    out = []
    for cat in GATED_CATEGORIES:
        key = f"categories:{cat}"
        if key not in assertions:
            out.append(f"{key} assertion missing — {cat} regressions deploy silently")
            continue
        rule = assertions[key]
        # Require the explicit lhci `[severity, opts]` array form. A bare options
        # object (`{"minScore": 0.9}`) states a threshold but never states
        # `error`, so whether it blocks the build depends on an lhci default this
        # repo has not pinned — and a gate whose severity is implicit is not a
        # gate we can assert on. Requiring the explicit form makes the intent
        # readable in the config itself.
        if not isinstance(rule, list) or not rule:
            out.append(
                f"{key} must use the [severity, opts] array form (got "
                f"{type(rule).__name__}) — without an explicit severity the "
                "assertion is not a hard gate"
            )
            continue
        if rule[0] != "error":
            out.append(f"{key} severity must be 'error' (a hard gate), not {rule[0]!r}")
        opts = rule[1] if len(rule) > 1 else None
        min_score = opts.get("minScore") if isinstance(opts, dict) else None
        if not isinstance(min_score, (int, float)):
            out.append(f"{key} must declare a numeric minScore floor")
        elif min_score < MIN_SCORE_FLOOR:
            out.append(f"{key} minScore {min_score} fell below the {MIN_SCORE_FLOOR} floor")
    return out


def runs_violations(config: dict) -> list:
    """Reasons `config` no longer damps Lighthouse run-to-run variance."""
    runs = config.get("ci", {}).get("collect", {}).get("numberOfRuns")
    if not isinstance(runs, int):
        return ["collect.numberOfRuns missing — median-of-N variance damping lost"]
    if runs < MIN_RUNS_FLOOR:
        return [
            f"numberOfRuns {runs} < {MIN_RUNS_FLOOR}: a single run makes the hard "
            "Performance gate flaky (cold vs. warm CDN swing)"
        ]
    return []


class TestLighthousePerfGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Read defensively so a missing file surfaces as the explicit
        # `test_lighthouserc_exists` failure below rather than a setUpClass
        # error that masks it.
        cls.config = (
            json.loads(LIGHTHOUSERC.read_text(encoding="utf-8"))
            if LIGHTHOUSERC.is_file()
            else {}
        )

    def test_lighthouserc_exists(self):
        self.assertTrue(
            LIGHTHOUSERC.is_file(),
            f"lighthouserc.json not found at {LIGHTHOUSERC} — path assumption broke",
        )

    def test_each_category_gated_at_floor(self):
        self.assertEqual(category_violations(self.config), [])

    def test_number_of_runs_damps_variance(self):
        self.assertEqual(runs_violations(self.config), [])


def _cfg(assertions=None, runs=3):
    return {
        "ci": {
            "collect": {"numberOfRuns": runs},
            "assert": {
                "assertions": assertions
                if assertions is not None
                else {
                    f"categories:{c}": ["error", {"minScore": 0.9}]
                    for c in GATED_CATEGORIES
                }
            },
        }
    }


class TestLighthouseGateMutation(unittest.TestCase):
    """Mutation self-tests. Every assertion above compares against `[]`, which a
    detector that always returned `[]` would also satisfy — these prove it does
    not."""

    def test_quiet_on_the_real_config(self):
        real = json.loads(LIGHTHOUSERC.read_text(encoding="utf-8"))
        self.assertEqual(category_violations(real), [])
        self.assertEqual(runs_violations(real), [])

    def test_fires_on_each_category_deleted(self):
        for cat in GATED_CATEGORIES:
            with self.subTest(deleted=cat):
                a = {
                    f"categories:{c}": ["error", {"minScore": 0.9}]
                    for c in GATED_CATEGORIES
                    if c != cat
                }
                out = category_violations(_cfg(a))
                self.assertEqual(len(out), 1)
                self.assertIn(f"categories:{cat}", out[0])

    def test_fires_on_severity_demoted_to_warn(self):
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:performance"] = ["warn", {"minScore": 0.9}]
        self.assertTrue(category_violations(_cfg(a)))

    def test_fires_on_severity_off(self):
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:seo"] = ["off", {"minScore": 0.9}]
        self.assertTrue(category_violations(_cfg(a)))

    def test_fires_on_lowered_min_score(self):
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:performance"] = ["error", {"minScore": 0.5}]
        out = category_violations(_cfg(a))
        self.assertEqual(len(out), 1)
        self.assertIn("0.5", out[0])

    def test_fires_on_bare_object_form_with_no_severity(self):
        # The shape that reads most like a hard gate without stating one: the
        # threshold is right there, but `error` is nowhere, so the severity falls
        # to an lhci default this repo does not pin.
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:accessibility"] = {"minScore": 0.9}
        out = category_violations(_cfg(a))
        self.assertEqual(len(out), 1)
        self.assertIn("array form", out[0])

    def test_fires_on_missing_min_score(self):
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:performance"] = ["error"]
        self.assertTrue(category_violations(_cfg(a)))

    def test_malformed_rule_is_reported_not_raised(self):
        # The pre-refactor shape indexed into `rule[1]` and would raise here,
        # turning a real finding into a confusing test ERROR.
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:seo"] = ["error", "0.9"]
        self.assertTrue(category_violations(_cfg(a)))

    def test_quiet_on_ratcheted_up_floors(self):
        # No-false-alarm direction: the semantics are a FLOOR, so raising a
        # threshold must stay green.
        a = {f"categories:{c}": ["error", {"minScore": 1.0}] for c in GATED_CATEGORIES}
        self.assertEqual(category_violations(_cfg(a)), [])

    def test_quiet_on_extra_ungated_assertion(self):
        a = {f"categories:{c}": ["error", {"minScore": 0.9}] for c in GATED_CATEGORIES}
        a["categories:best-practices"] = ["warn", {"minScore": 0.5}]
        self.assertEqual(category_violations(_cfg(a)), [])

    def test_fires_on_single_run(self):
        self.assertTrue(runs_violations(_cfg(runs=1)))

    def test_fires_on_missing_number_of_runs(self):
        self.assertTrue(runs_violations({"ci": {"collect": {}}}))

    def test_runs_quiet_on_more_than_the_floor(self):
        self.assertEqual(runs_violations(_cfg(runs=5)), [])


if __name__ == "__main__":
    unittest.main()
