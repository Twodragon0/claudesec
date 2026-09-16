"""
Regression guard: the published catalog must not RESTATE a version this repo
pins. It may refer to the pin; it may not spell it.

THE DEFECT THIS EXISTS FOR, MEASURED. #550 re-adjudicated the renderer oracle
from markdown-it-py 4.0.0 to 4.2.0 and moved the version everywhere it is
consumed. `docs/devsecops/ci-config-regression-guards.md` went on asserting, in
the present tense, that the canary job "installs `markdown-it-py==<old>`" — false
the moment that PR merged, and caught by nothing: `test_ci_catalog_doc_sync.py`
compares guard NAMES, and no other reader of the doc looks at versions at all.
#551 removed the claim rather than updating it, and this guard keeps it removed.

SCOPE IS DELIBERATELY ONE SPELLING, AND THAT IS A LIMIT, NOT AN OVERSIGHT.
Only `<pkg>==<version>` for a package this repo itself pins in a
`requirements*.txt`. The catalog also restates eight `vX.Y.Z` tags, and those are
LEFT ALONE on purpose: they are incident narrative, and one of them
(`a STALE # v4.2.2 comment on a v7.0.0 SHA`) quotes a wrong version DELIBERATELY,
because that is what the incident was. Banning that spelling too would forbid
prose the catalog needs, and a parity check — "every version named here must
match reality" — fails on exactly that line and then needs an exemption list,
which is the enumeration ladder ADR-001 §5 says to stop climbing. Measured when
this landed: all eight were accurate (shellcheck 0.11.0, lychee v0.23.0,
checkout v7.0.1), so the narrative form is not currently drifting.

WHY A RAW SCAN IS RIGHT HERE, WHEN IT IS WRONG NEXT DOOR. Sibling guards moved
OFF the Markdown prose because a row hidden in a comment or a code fence renders
as nothing while a substring scan still finds it — a silent PASS. The direction
is reversed for an ABSENCE assertion: over-finding text that does not render
produces a false FAILURE, which is loud and fixable, never a guard certifying
something it did not check. So this one reads the file raw, and a pin smuggled
into an HTML comment trips it.

SEVERITY IS DOCUMENTATION, NOT A GATE. Nothing executes the catalog. A stale
version in prose misleads a reader; it does not turn a check green. That is why
the guard is cheap and narrow rather than a general doc-vs-reality oracle.

stdlib-only (`git ls-files` via subprocess, `re`, `Path`). Does not import
scanner/lib, so it never moves the measured coverage gate.

OWASP CICD-SEC-1 (Insufficient Flow Control) / NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

MARKDOWN_SCAN_EXEMPT = (
    "Reads the catalog RAW, and that is the correct direction for this "
    "assertion. The reduction exists because a row hidden in a comment or a "
    "code fence renders as nothing while a substring scan still finds it — a "
    "silent PASS for a PRESENCE check. This is an ABSENCE check: over-finding "
    "text a browser would drop produces a false FAILURE, which is loud and "
    "fixable, never a guard certifying something it did not check. Reducing "
    "first would do the opposite of protecting the invariant — it would let a "
    "restated pin be smuggled into an HTML comment and pass. Pinned by "
    "test_a_pin_smuggled_into_an_html_comment_is_still_caught."
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_REL = "docs/devsecops/ci-config-regression-guards.md"

# `name==1.2` / `name==1.2.3`, optionally inside backticks. Deliberately NOT
# anchored to a line start: the point is that the literal appears at all.
_PIN_RE = re.compile(r"([A-Za-z0-9_.\-]+)==(\d+\.\d+(?:\.\d+)?)")


def pinned_packages() -> set:
    """Package names this repo pins, from every TRACKED `requirements*.txt`.

    `git ls-files` rather than a filesystem glob, and rather than a hand-written
    list. Both alternatives have failed in this suite: a gitignored file makes a
    filesystem scan disagree with CI, and a hand list drifted to missing twelve
    entries before anyone noticed (#501).
    """
    tracked = subprocess.run(
        ["git", "ls-files", "requirements*.txt"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    names = set()
    for rel in tracked:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        names |= {m.group(1).lower() for m in re.finditer(r"^([A-Za-z0-9_.\-]+)==", text, re.M)}
    return names


def restated_pins(doc_text: str, pinned: set) -> list:
    """`line N: <pkg>==<ver>` for every pin the doc spells out.

    A package NOT pinned here is ignored: the catalog legitimately narrates
    versions of things this repo does not own, and a ban on those would be a
    ban on describing the outside world.
    """
    found = []
    for n, line in enumerate(doc_text.splitlines(), 1):
        for m in _PIN_RE.finditer(line):
            if m.group(1).lower() in pinned:
                found.append(f"line {n}: {m.group(0)}")
    return found


class TestCatalogDoesNotRestatePins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = (REPO_ROOT / CATALOG_REL).read_text(encoding="utf-8")
        cls.pinned = pinned_packages()

    def test_the_package_list_is_not_empty(self):
        """Without this the ban below is vacuous by accident rather than by
        the catalog being clean — an empty `pinned` set matches nothing and
        reports success having checked nothing, the fail-open shape this suite
        keeps finding."""
        self.assertGreater(
            len(self.pinned),
            5,
            "no pinned packages were read from requirements*.txt — the ban "
            "would pass by matching nothing",
        )

    def test_the_catalog_does_not_spell_a_pin_it_could_refer_to(self):
        offenders = restated_pins(self.doc, self.pinned)
        self.assertEqual(
            offenders,
            [],
            f"{CATALOG_REL} spells out a version this repo pins:\n  "
            + "\n  ".join(offenders)
            + "\n\nRefer to the pin instead of restating it (\"the pinned "
            "`markdown-it-py` oracle\"), or, if the version is load-bearing to "
            "an incident you are narrating, attribute it to when it was "
            "measured. A restated pin has no parity check and goes stale "
            "silently — #550 left one behind for exactly one commit.",
        )


class TestTheBanIsNonVacuous(unittest.TestCase):
    """A ban that currently matches nothing proves nothing about its detector.

    Measured when this landed: the catalog had ZERO `<pkg>==<ver>` literals, so
    the assertion above passes on an empty haystack. These plant the defect back
    and require it to be caught.
    """

    def setUp(self):
        self.doc = (REPO_ROOT / CATALOG_REL).read_text(encoding="utf-8")
        self.pinned = pinned_packages()

    def test_the_exact_defect_that_shipped_is_caught(self):
        pkg = sorted(self.pinned)[0]
        planted = self.doc + f"\n\nIt installs `{pkg}==9.9.9` (1s, one dependency).\n"
        self.assertTrue(
            restated_pins(planted, self.pinned),
            "re-planting a restated pin was NOT caught — the detector cannot "
            "see the shape it exists for",
        )

    def test_a_pin_smuggled_into_an_html_comment_is_still_caught(self):
        """The sibling guards read RENDERED markdown because a comment-hidden
        row is a silent pass there. For an absence assertion the direction
        flips: hidden text must still trip, or the ban is evaded by indenting
        the claim into something a browser drops."""
        pkg = sorted(self.pinned)[0]
        planted = self.doc + f"\n\n<!-- was `{pkg}==9.9.9` -->\n"
        self.assertTrue(
            restated_pins(planted, self.pinned),
            "a pin inside an HTML comment escaped the ban",
        )

    def test_narrative_version_tags_are_not_flagged(self):
        """The eight `vX.Y.Z` mentions the catalog needs must stay legal,
        including the one that quotes a WRONG version on purpose."""
        # ISOLATED from the real document on purpose. Appending to it would
        # couple this to the catalog being clean: measured, planting one
        # offender upstream turned ONE failure into three, two of them here
        # and both misleading about what broke.
        planted = (
            "It updated the SHA but left a STALE `# v4.2.2` comment on a "
            "`v7.0.0` SHA.\n"
        )
        self.assertEqual(
            restated_pins(planted, self.pinned),
            [],
            "narrative version tags were flagged — this ban is one spelling "
            "wide on purpose",
        )

    def test_a_package_this_repo_does_not_pin_is_not_flagged(self):
        planted = "Upstream ships `not-a-package-we-pin==1.2.3`.\n"
        self.assertEqual(
            restated_pins(planted, self.pinned),
            [],
            "a version this repo does not own was flagged — the catalog is "
            "allowed to describe the outside world",
        )


if __name__ == "__main__":
    unittest.main()
