"""
Regression guard: KISA ISMS-P control ids in the scanner agree with the repo's
own ISMS-P reference table.

THE INCIDENT THIS EXISTS FOR
----------------------------
`compliance-map.py` carried four KISA control ids labelled with the wrong
requirement, and had done since the table was written. #451 made it
consequential by attaching Prowler's requirement->check data to those ids, so
203 real checks were scored against controls that name a different requirement:

    id       compliance-map.py said     the requirement actually is
    2.6.1    접근권한 관리                 네트워크 접근 (Network access)      106 checks
    2.9.3    로그 및 접근기록 관리 (Logging)  백업 및 복구관리 (Backup/recovery)   24 checks
    2.9.4    백업 관리 (Backup)           로그 및 접속기록 관리 (Logging)       59 checks
    2.10.8   악성코드 통제 (Malware)        패치관리 (Patch management)         14 checks

This is the failure `prowler_native_map.py` refused to ship CIS over — "attach
real checks to the WRONG controls silently" — except it was already live, in a
framework nobody re-checked. It also produced two false conclusions that were
written down and cited for weeks: `docs/plans/compliance-native-mapping-and-cmmc.md`
reported "2.9.4 백업·복구 scored 0/58" and "2.10.8 악성코드 0/14" as the clearest
evidence that keyword matching cannot reproduce Prowler's intent. Both zeros
were arithmetic against the wrong requirement. After relabelling, at Prowler
5.30.1: 2.9.3 0/24 -> 20/24, 2.9.4 0/59 -> 41/59, 2.10.8 0/14 -> 14/14,
2.6.1 21/106 -> 44/106, and framework agreement 31.4% -> 49.6% (16 shared ids
before, 19 after — 2.5.5/2.5.6 were added to re-home the access-rights coverage
that correcting 2.6.1 would otherwise have dropped, and 2.10.9 restored).

ISO 27001 A.8.2 carried the same defect — labelled "Access control", which is
A.5.15, when Annex A.8.2 is "Privileged access rights" (58 native checks). It is
corrected in the same change but NOT covered by this guard: there is no in-repo
ISO reference table to compare against.

WHY THIS IS CHECKABLE WITHOUT PROWLER
--------------------------------------
The repo already contains the correct numbering, in `docs/compliance/isms-p.md`
— a hand-written reference table that disagreed with the scanner for the whole
period. No external source, no network, and no Prowler install is needed: the
two in-repo artifacts simply have to agree. (They also both agree with Prowler,
which is how the drift was found, but that is not what this guard tests.)

Direction: equality on the ids the guide and the scanner share. Renaming a
control in either file without the other trips it.

SCOPE, stated because it is a real limit: this compares `name` only. Swapping
two controls' `checks` (or `desc`/`action`, both of which are rendered to
operators) while leaving the names correct is NOT caught — verified by mutation.
For the NATIVE path the label is the load-bearing field, since that is what
decides which requirement Prowler's checks are reported against, so the guard
covers the incident it was written for; the keyword-path equivalent is
`test_ci_compliance_keyword_guard.py`. Ids present in only one file
are not compared — the guide lists all 100+ ISMS-P requirements while the
scanner maps a technical subset, and requiring parity there would force the
scanner to grow controls it has no signal for.

stdlib-only (importlib for the hyphenated module, regex for the guide's tables).
No PyYAML, no network, no subprocess. Importing compliance-map.py is fine — it
is already in the measured `scanner/lib` coverage set. Runs under pytest and
`python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration): a compliance report that
scores the right evidence against the wrong requirement is wrong in a way no
severity count reveals.
"""

import importlib.util
import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDE = REPO_ROOT / "docs" / "compliance" / "isms-p.md"
COMPLIANCE_MAP_PATH = REPO_ROOT / "scanner" / "lib" / "compliance-map.py"

_spec = importlib.util.spec_from_file_location(
    "compliance_map_kisa_alignment", str(COMPLIANCE_MAP_PATH)
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
COMPLIANCE_CONTROL_MAP = _mod.COMPLIANCE_CONTROL_MAP

FRAMEWORK = "KISA ISMS-P"

# Label errors this guard found but did NOT fix, with the reason.
#
# All three are keyword-only: Prowler maps no check to any of them, so unlike
# the four that were corrected, nothing is currently being scored against the
# wrong requirement — and per-finding routing (the open Phase 1 in
# docs/plans/compliance-status-model.md) does not change that, because it only
# reroutes findings for controls that HAVE a native mapping. Fixing them means
# renumbering ids rather than relabelling in place, which is a content-modelling
# decision, not a measurement one. Deferred deliberately, pinned so it cannot be
# forgotten: this dict must SHRINK, and any new entry is a fresh drift.
#
#   id      compliance-map.py     the requirement is        evidence
#   2.8.4   시큐어 코딩             시험 데이터 보안             guide + Prowler "Test Data Security"
#   2.8.6   시험과 운영 환경 분리      운영환경 이관               guide + Prowler "Transition to Operational Environment"
#                                (시험과 운영 환경 분리 is 2.8.3)
#
# 2.11.5 was a third entry here and is now FIXED: the scanner said 사고 분석 및
# 공유 and the guide said 사고 대응 훈련 및 개선 (which is 2.11.4) — both wrong
# against Prowler's "Incident Response and Recovery". Both were corrected.
KNOWN_DIVERGENCE = {"2.8.4", "2.8.6"}

# `| 2.9.3 | 백업 및 복구 관리 | 백업 정책, 복구 시험 |` — id in column 1, the
# Korean requirement title in column 2. Anchored at line start so prose cannot
# be read as a row.
_GUIDE_ROW = re.compile(r"^\|\s*(\d+\.\d+\.\d+)\s*\|\s*([^|]+?)\s*\|", re.MULTILINE)

# The scanner writes "백업 및 복구관리 (Backup and recovery management)"; the guide
# writes "백업 및 복구 관리". Compare on the Korean part with spaces removed —
# enough to catch a swapped requirement, loose enough not to police wording.
_PARENTHETICAL = re.compile(r"\s*\([^)]*\)\s*$")


def _normalize(title):
    return _PARENTHETICAL.sub("", title).replace(" ", "").strip()


def guide_titles():
    text = GUIDE.read_text(encoding="utf-8") if GUIDE.is_file() else ""
    out = {}
    for cid, title in _GUIDE_ROW.findall(text):
        out.setdefault(cid, _normalize(title))
    return out


def scanner_titles():
    return {
        c["control"]: _normalize(c["name"])
        for c in COMPLIANCE_CONTROL_MAP[FRAMEWORK]
        if re.fullmatch(r"\d+\.\d+\.\d+", c["control"])
    }


class TestKisaControlAlignment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guide = guide_titles()
        cls.scanner = scanner_titles()
        cls.shared = sorted(set(cls.guide) & set(cls.scanner))

    def test_guide_exists(self):
        self.assertTrue(GUIDE.is_file(), f"{GUIDE} not found")

    def test_the_guide_tables_were_actually_parsed(self):
        """Canary. A reformatted guide would otherwise make every comparison
        below pass vacuously — the exact way a guard reads green while guarding
        nothing."""
        self.assertGreaterEqual(
            len(self.guide),
            50,
            f"Parsed only {len(self.guide)} numbered rows out of {GUIDE.name}; "
            "the reference tables moved or changed shape. Update _GUIDE_ROW.",
        )

    def test_enough_controls_are_actually_compared(self):
        self.assertGreaterEqual(
            len(self.shared),
            35,
            "Too few shared ids to be a meaningful check. The floor is close to the "
            "actual count on purpose: with wide headroom, renumbering a control "
            "to an id absent from the guide drops it from the comparison "
            "silently.",
        )

    def test_the_four_realigned_controls_are_compared(self):
        """These are the ids the guard exists for; if any drops out of the
        comparison the guard has stopped covering its own incident."""
        for cid in ("2.6.1", "2.9.3", "2.9.4", "2.10.8"):
            with self.subTest(control=cid):
                self.assertIn(cid, self.shared)

    def test_known_divergences_are_still_divergent(self):
        """A stale entry masks a real regression on the same id, so an entry
        that has been fixed must be removed from the set."""
        for cid in sorted(KNOWN_DIVERGENCE):
            with self.subTest(control=cid):
                self.assertIn(cid, self.shared, f"{cid} left the comparison")
                self.assertNotEqual(
                    self.scanner[cid],
                    self.guide[cid],
                    f"KISA {cid} now agrees with {GUIDE.name} — drop it from "
                    "KNOWN_DIVERGENCE.",
                )

    def test_every_shared_control_names_the_same_requirement(self):
        for cid in self.shared:
            if cid in KNOWN_DIVERGENCE:
                continue
            with self.subTest(control=cid):
                self.assertEqual(
                    self.scanner[cid],
                    self.guide[cid],
                    f"KISA {cid} is '{self.scanner[cid]}' in compliance-map.py but "
                    f"'{self.guide[cid]}' in {GUIDE.name}. One of them names the "
                    "wrong requirement — check KISA ISMS-P 2023 before deciding "
                    "which, and remember Prowler's file is a third opinion.",
                )

    def test_the_swapped_pair_stays_unswapped(self):
        """A named pin on the specific drift, so a future edit that re-swaps
        them fails with the history rather than a generic mismatch."""
        self.assertIn("백업", self.scanner["2.9.3"])
        self.assertIn("로그", self.scanner["2.9.4"])
        self.assertIn("네트워크", self.scanner["2.6.1"])
        self.assertIn("패치", self.scanner["2.10.8"])
        self.assertIn("악성코드", self.scanner["2.10.9"])


class TestParserIsNotVacuous(unittest.TestCase):
    """Attack the extractor before trusting the assertions."""

    TABLE = (
        "| 항목 | 명칭 | 설명 |\n"
        "|------|------|------|\n"
        "| 2.9.3 | 백업 및 복구 관리 | 백업 정책, 복구 시험 |\n"
        "| 2.9.4 | 로그 및 접속기록 관리 | 로그 저장, 보호, 검토 |\n"
    )

    def test_parses_id_and_title(self):
        rows = _GUIDE_ROW.findall(self.TABLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(_normalize(rows[0][1]), "백업및복구관리")

    def test_prose_mentioning_an_id_is_not_read_as_a_row(self):
        self.assertEqual(_GUIDE_ROW.findall("see 2.9.3 | not a row |\n"), [])

    def test_normalize_ignores_spacing_and_the_english_gloss(self):
        self.assertEqual(
            _normalize("백업 및 복구관리 (Backup and recovery management)"),
            _normalize("백업 및 복구 관리"),
        )

    def test_normalize_still_separates_different_requirements(self):
        self.assertNotEqual(_normalize("백업 관리"), _normalize("로그 및 접속기록 관리"))

    def test_a_swap_is_visible_to_the_comparison(self):
        swapped = self.TABLE.replace("백업 및 복구 관리", "TMP").replace(
            "로그 및 접속기록 관리", "백업 및 복구 관리"
        ).replace("TMP", "로그 및 접속기록 관리")
        self.assertNotEqual(swapped, self.TABLE, "mutation fixture is stale")
        rows = dict(_GUIDE_ROW.findall(swapped))
        self.assertEqual(_normalize(rows["2.9.3"]), "로그및접속기록관리")

    def test_the_real_guide_is_not_parsed_as_empty(self):
        self.assertTrue(guide_titles())


if __name__ == "__main__":
    unittest.main()
