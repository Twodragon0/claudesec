"""
Regression guard: compliance-map keyword lists stay free of over-broad
substring-false-positive tokens.

Background
----------
`map_compliance()` (scanner/lib/compliance-map.py) marks a control FAIL when any
Prowler finding's `"{check} {title} {message}".lower()` CONTAINS any of the
control's `checks` keywords — a plain substring match. Short/generic keywords
substring-match unrelated findings and produce false-positive FAILs: a bare
`policy` matches network/IAM/bucket "policy"; `port` matches
support/report/transport/export; `node` matches nodejs/node_modules; `endpoint`
matches VPC/API/S3 "endpoint"; `transfer` (in a PII cross-border control)
matches "S3 Transfer"/"DataSync". A review removed each over-broad token while
keeping >=2 intent-carrying keywords per affected control, so detection is
preserved (no new false-negatives).

Why not a naive "min length" rule
---------------------------------
A "min 4-char keyword" guard would be WRONG: `port` and `node` are exactly 4
chars (it would MISS them) while it would flag ~11 legitimate 3-char security
acronyms (cve, iam, kms, mfa, pii, ssl, ssn, sso, tls, vpc, xss). This guard is
two-part instead:

1. **Regression pins** — assert the specific removed tokens stay removed from the
   specific controls, and that every edited control still has >=2 checks (a
   future edit cannot silently gut a control down to one over-broad keyword).
2. **Substring-collision guard** — assert NO keyword anywhere in the map is a
   PROPER substring of any word in a curated list of benign, Prowler-adjacent
   words. A keyword equal to a benign word is the intended match (e.g. control
   2.6.3 legitimately keys on `session`, 2.10.5 on `transfer`) and is NOT a
   collision; only a shorter keyword hiding inside a longer benign word (`port`
   in `transport`) is. Verified empirically: of the 12 short (<=3 char) tokens,
   NONE is a proper substring of any benign word, so the ALLOWLIST is empty.

Direction: absence-of-token (removed tokens stay removed) + non-emptiness
(edited controls keep >=2 checks) + no-proper-substring-collision. Re-adding a
removed over-broad token, or introducing any new keyword that is a proper
substring of a benign word, trips this guard. A mutation self-test injects a fake
`"port"` keyword and asserts the collision detector fires.

stdlib-only (importlib to load the hyphenated module). No PyYAML, no network, no
subprocess. Importing compliance-map.py is fine — it is already in the measured
`scanner/lib` coverage set, so this guard does not move the 99% floor. Runs under
pytest (the CI runner) and `python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration) — a silently over-broad
compliance mapping degrades the accuracy of the security posture report.
"""

import importlib.util
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
COMPLIANCE_MAP_PATH = REPO_ROOT / "scanner" / "lib" / "compliance-map.py"

_spec = importlib.util.spec_from_file_location(
    "compliance_map_guard", str(COMPLIANCE_MAP_PATH)
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP


# ── Curated benign, Prowler-adjacent words. A compliance keyword must never be a
# PROPER substring of any of these (that is the false-positive class this guard
# targets). `endpoint`/`session`/`transfer` appear here as the "vpc endpoint" /
# "login session" / "s3 transfer" senses — some are also legitimate keywords, so
# the detector compares by PROPER substring (keyword != word) to leave the
# intended equal-match alone. ──
BENIGN_WORDS = [
    "support",
    "report",
    "transport",
    "export",
    "session",
    "nodejs",
    "node_modules",
    "apigateway",
    "capital",
    "software",
    "endpoint",  # e.g. "vpc endpoint"
    "dialog",
    "login",
    "transfer",  # e.g. "s3 transfer"
]

# Intentional short acronyms that are ALLOWED to be a proper substring of a
# benign word, each with a justification. Verified empirically to be EMPTY: none
# of {cve,iam,kms,mfa,pii,ssl,ssn,sso,tls,vpc,xss} is a proper substring of any
# BENIGN_WORDS entry. Kept as an explicit hook so a future benign-word addition
# that legitimately collides has a documented place to be recorded.
ALLOWLIST = {
    # token: reason  (currently none needed)
}


def _checks_of(framework: str, control: str) -> list:
    """The `checks` keyword list for a given framework/control id."""
    for ctrl in COMPLIANCE_CONTROL_MAP.get(framework, []):
        if ctrl["control"] == control:
            return ctrl["checks"]
    raise AssertionError(f"control not found: {framework!r} / {control!r}")


def _all_keywords() -> set:
    kws = set()
    for controls in COMPLIANCE_CONTROL_MAP.values():
        for ctrl in controls:
            kws.update(ctrl["checks"])
    return kws


def _collisions(keywords) -> list:
    """(keyword, benign_word) pairs where keyword is a PROPER substring of a
    benign word and is not allowlisted. Proper => keyword != benign_word, so a
    keyword that EQUALS a benign word (the intended match) is not flagged."""
    hits = []
    for kw in sorted(keywords):
        if kw in ALLOWLIST:
            continue
        for word in BENIGN_WORDS:
            if kw != word and kw in word:
                hits.append((kw, word))
    return hits


# The exact per-control removals this PR made (framework, control, removed_token).
REMOVED_TOKENS = [
    ("KISA ISMS-P", "1.1.1", "policy"),
    ("KISA ISMS-P", "2.1.1", "policy"),
    ("KISA ISMS Simple", "S-1.1", "policy"),
    ("KISA ISMS Simple", "S-2.1", "policy"),
    ("KISA ISMS-P", "2.6.3", "api"),
    ("KISA ISMS-P", "2.7.2", "hsm"),
    ("KISA ISMS-P", "2.10.1", "waf"),
    ("KISA ISMS-P", "2.10.1", "endpoint"),
    ("KISA ISMS-P", "2.10.8", "endpoint"),
    ("KISA ISMS-P", "2.10.8", "edr"),
    ("KISA ISMS-P", "3.3.4", "transfer"),
    ("CIS Benchmarks", "CIS-4.1", "port"),
    ("CIS Benchmarks", "CIS-K8s-4.1", "node"),
]

# Controls this PR edited — each must still carry >=2 intent-carrying keywords.
EDITED_CONTROLS = sorted({(fw, ctrl) for fw, ctrl, _ in REMOVED_TOKENS})


class TestComplianceKeywordRegressionPins(unittest.TestCase):
    def test_removed_tokens_stay_removed(self):
        for framework, control, token in REMOVED_TOKENS:
            with self.subTest(framework=framework, control=control, token=token):
                checks = _checks_of(framework, control)
                self.assertNotIn(
                    token,
                    checks,
                    f"over-broad token {token!r} was re-added to "
                    f"{framework}/{control} (checks={checks!r}) — it substring-"
                    "matches unrelated findings and re-introduces false-positive "
                    "FAILs. Remove it again.",
                )

    def test_edited_controls_keep_at_least_two_checks(self):
        for framework, control in EDITED_CONTROLS:
            with self.subTest(framework=framework, control=control):
                checks = _checks_of(framework, control)
                self.assertGreaterEqual(
                    len(checks),
                    2,
                    f"{framework}/{control} was gutted to {checks!r} — an edited "
                    "control must keep >=2 intent-carrying keywords so detection "
                    "is not lost.",
                )


class TestComplianceKeywordCollision(unittest.TestCase):
    def test_no_keyword_is_proper_substring_of_benign_word(self):
        hits = _collisions(_all_keywords())
        self.assertEqual(
            hits,
            [],
            "compliance keyword(s) are a PROPER substring of a benign Prowler-"
            "adjacent word and will substring-false-positive:\n  "
            + "\n  ".join(f"{kw!r} inside {word!r}" for kw, word in hits)
            + "\nDrop the over-broad token, or (if legitimately intentional) add "
            "it to ALLOWLIST with a justification.",
        )

    def test_allowlist_entries_are_actually_needed(self):
        # An allowlist entry that does not actually collide is stale cruft — it
        # would mask a future real collision on the same token. Keep the
        # allowlist minimal and honest.
        kws = _all_keywords()
        for token in ALLOWLIST:
            collides = any(token != w and token in w for w in BENIGN_WORDS)
            in_map = token in kws
            with self.subTest(token=token):
                self.assertTrue(
                    collides and in_map,
                    f"ALLOWLIST token {token!r} is stale — it is not a keyword in "
                    "the map and/or does not collide with any benign word. Remove "
                    "it.",
                )

    def test_mutation_detector_fires_on_injected_collision(self):
        # Self-test: inject a fake over-broad `"port"` keyword (a proper substring
        # of "transport"/"support"/"report"/"export") and confirm the collision
        # detector catches it. Proves the guard is non-vacuous.
        mutated = _all_keywords() | {"port"}
        hits = _collisions(mutated)
        self.assertTrue(
            any(kw == "port" for kw, _ in hits),
            "Mutation FAILED: injecting a fake 'port' keyword did NOT trip the "
            "collision detector — the guard is vacuous.",
        )

    def test_mutation_equal_match_is_not_flagged(self):
        # A keyword EQUAL to a benign word (e.g. an intended `session` match) is
        # NOT a proper-substring collision and must stay unflagged, else the guard
        # would forbid the legitimate keys 2.6.3/`session` and 2.10.5/`transfer`.
        hits = _collisions({"session", "transfer", "endpoint"})
        self.assertEqual(
            hits,
            [],
            "False positive: a keyword equal to a benign word was flagged as a "
            "collision — the detector must compare by PROPER substring only.",
        )


if __name__ == "__main__":
    unittest.main()
