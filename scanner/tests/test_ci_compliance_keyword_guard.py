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
    # Added 2026-08-14 after an adversarial pass against the REAL Prowler 5.38
    # check catalog found both of these live in the map, past this guard:
    #   `sso`  inside "a-sso-ciated"  — 70 of 74 corpus hits were this, not SSO
    #                                   ("subnet has a network security group
    #                                   associated" scored as an access control)
    #   `sast` inside "di-sast-er"    — 3 of 3 corpus hits were backup/DR checks
    #                                   ("drs_job_exist") scored as secure coding
    # The detector was already correct; its word list simply did not contain the
    # two words that mattered. A curated list is only as good as its curation —
    # extend it whenever a real corpus turns up a new collision.
    "associated",
    "disaster",
    # 2026-08-18: `review` is embedded in Vercel "preview deployment" checks —
    # 4 of its 51 corpus hits. Far smaller than sso/associated (70/74), and
    # `review` is still carrying real signal, so this is registered to keep the
    # token honest rather than to force its removal: if someone later shortens
    # `review`, the collision surfaces instead of quietly widening.
    "preview",
]

# Intentional short acronyms that are ALLOWED to be a proper substring of a
# benign word, each with a justification. Verified empirically to be EMPTY: none
# of {cve,iam,kms,mfa,pii,ssl,ssn,sso,tls,vpc,xss} is a proper substring of any
# BENIGN_WORDS entry. Kept as an explicit hook so a future benign-word addition
# that legitimately collides has a documented place to be recorded.
ALLOWLIST = {
    # `review` is a proper substring of "preview", but only 4 of its 51 real
    # corpus hits are Vercel preview-deployment checks — 8%, against 70/74 for
    # `sso`/"associated" and 308/316 for `change`. It carries real
    # code-review signal for KISA 2.9.1 / S-2.9, so removing it would cost more
    # than the noise it admits. Recorded here rather than dropped, which is what
    # this hook exists for; `preview` stays in BENIGN_WORDS so that shortening
    # `review` to anything narrower surfaces the collision instead of widening
    # it quietly.
    "review": "8% collision with 'preview' (4/51), measured 2026-08-18; "
    "the other 47 hits are genuine code-review signal",
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
    # Retargeted 2.10.8 -> 2.10.9. These two pin `endpoint`/`edr` out of the
    # MALWARE control, which moved to its standard id when 2.10.8 was corrected
    # to 패치관리. Left on 2.10.8 the pins went vacuous — they asserted absence
    # from a control the tokens had never been on, and re-adding `edr` (24/24
    # corpus hits unrelated) to the malware control passed the whole file.
    # The collision detector cannot catch either: `endpoint` equals a BENIGN
    # word rather than being a proper substring of one, so the pin IS the guard.
    ("KISA ISMS-P", "2.10.9", "endpoint"),
    ("KISA ISMS-P", "2.10.9", "edr"),
    ("KISA ISMS-P", "3.3.4", "transfer"),
    ("CIS Benchmarks", "CIS-4.1", "port"),
    ("CIS Benchmarks", "CIS-K8s-4.1", "node"),
    # 2026-08-14 sweep: `sso` -> `_sso` (keeps team_saml_sso_enforced,
    # entra_seamless_sso_disabled, sagemaker_domain_sso_configured; drops
    # "associated"), `sast` dropped outright (no real check id contains it;
    # every affected control keeps code_scanning / injection / vulnerability).
    ("ISO 27001:2022", "A.8.5", "sso"),
    ("KISA ISMS-P", "2.5.3", "sso"),
    ("KISA ISMS-P", "2.6.2", "sso"),
    ("KISA ISMS Simple", "S-2.4", "sso"),
    ("PCI-DSS v4.0.1", "Req 8", "sso"),
    ("NIST 800-53 Rev5", "IA-2", "sso"),
    ("CIS Benchmarks", "CIS-K8s-ArgoCD", "sso"),
    # 2026-08-14, SECOND class — over-broad WHOLE WORDS. These are correctly
    # spelled, correctly meaning English words that are simply too common in
    # Prowler's risk narratives. The collision detector below CANNOT catch them:
    # it looks for a keyword hidden INSIDE a differently-spelled benign word
    # (`sso` in "associated"), and these are not hidden — they are the word.
    # Only corpus measurement finds this class, so the pins are the guard.
    #   change    316 hits, 308 (97.5%) unrelated ("X changed" config drift)
    #   forensic   73 hits, essentially all generic "logging enabled" hygiene
    #   edr        24 hits, 24 of them onedrive/sharepoint/requestedregion
    #   endpoint   ~40-53% VPC/private-endpoint checks read as malware evidence
    #   health     29 hits, all ELB/ASG/K8s health CHECKS, no health DATA
    ("KISA ISMS-P", "2.9.1", "change"),
    ("KISA ISMS Simple", "S-2.9", "change"),
    ("KISA ISMS-P", "2.11.5", "forensic"),
    ("KISA ISMS Simple", "S-2.13", "edr"),
    ("KISA ISMS Simple", "S-2.13", "endpoint"),
    ("KISA ISMS-P", "3.1.4", "health"),
    # Zero real-corpus hits anywhere in 1561 checks — they were never carrying
    # the change-management signal their control's action text implies.
    ("KISA ISMS-P", "2.9.1", "require_approval"),
    ("KISA ISMS-P", "2.9.1", "pull_request"),
    ("KISA ISMS Simple", "S-2.9", "require_approval"),
    ("KISA ISMS Simple", "S-2.9", "pull_request"),
    ("ISO 27001:2022", "A.8.28", "sast"),
    ("KISA ISMS-P", "2.8.4", "sast"),
    ("KISA ISMS Simple", "S-2.8", "sast"),
    ("PCI-DSS v4.0.1", "Req 6", "sast"),
    ("NIST 800-53 Rev5", "RA-5", "sast"),
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


class TestMeasuredRejections(unittest.TestCase):
    """Two edits proposed by review and rejected on measurement, 2026-08-14.

    Both look obviously right on inspection — CC5's own action text says "enforce
    secure defaults", and CC4 is a monitoring criterion with no `alert` token —
    which is exactly why they need a pin rather than a comment. Measured against
    Prowler 5.38's real catalog using Prowler's own soc2_{aws,azure,gcp}.json as
    ground truth:

      CC5 + `default`  recovers 0 of its 21 missed checks and newly lights 158
                       corpus-wide. The token's 169 hits are real; none are CC5's.
      CC4 + `alert`    recovers 3 of 24 (85.7% -> 75.0% miss) while taking CC4's
                       corpus matches 137 -> 182 and its overlap with CC7 from
                       38% -> 52% of CC4.

    Re-adding either is allowed — but only with a fresh measurement, which is
    what this failing test forces someone to do.
    """

    def test_cc5_does_not_carry_default(self):
        checks = _checks_of("SOC 2 (TSC)", "CC5")
        self.assertNotIn("default", checks)
        self.assertNotIn("_default_", checks)

    def test_cc4_does_not_carry_alert(self):
        self.assertNotIn("alert", _checks_of("SOC 2 (TSC)", "CC4"))

    def test_cc7_still_owns_alert(self):
        # The rejection is about CC4, not about the token. CC7 is where alerting
        # belongs, and dropping it there would be a real detection loss.
        self.assertIn("alert", _checks_of("SOC 2 (TSC)", "CC7"))


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

    def test_mutation_detector_fires_on_the_two_real_2026_collisions(self):
        # Non-vacuity for the words added in the 2026-08-14 sweep specifically.
        # Without this, deleting "associated"/"disaster" from BENIGN_WORDS would
        # silently re-open the exact hole the sweep closed and every assertion
        # above would still pass.
        for token, word in (("sso", "associated"), ("sast", "disaster")):
            with self.subTest(token=token):
                hits = _collisions(_all_keywords() | {token})
                self.assertIn(
                    (token, word),
                    hits,
                    f"Mutation FAILED: re-injecting {token!r} did not collide with "
                    f"{word!r} — {word!r} is missing from BENIGN_WORDS and the "
                    "guard is blind to a collision that was live in the map.",
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
