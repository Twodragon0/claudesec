"""
Regression guard: prowler is installed from an EXACT version pin in `Dockerfile`,
never an unpinned/floating spec.

Background
----------
The ClaudeSec image installs the prowler CLI so the prowler/cloud scanner
categories can run. prowler's resolvable version depends on the base image's
Python: on alpine 3.20 (py3.12) an UNPINNED `pip install prowler` resolves to a
modern release, but on a newer Python (py3.13/3.14) pip silently backtracks to
ancient prowler 3.11.3 (pydantic v1) instead of failing fast — which then
crashes at runtime (`prowler -v` → pydantic ConfigError). PR #237 fixed this by
pinning prowler explicitly; the Dockerfile comment documents the lockstep
relationship with the alpine freeze (#220).

The load-bearing invariant is therefore: **prowler must be installed via an
exact `==` pin (through the `PROWLER_VERSION` build arg), never as a bare
unpinned `prowler` spec.** Silent removal of the pin would re-introduce the #237
drift with no build failure. This complements:
  - `test_ci_dependabot_config.py` — locks the alpine MINOR freeze policy.
  - `test_ci_prowler_provider_guard_ordering.py` — locks the runtime provider
    skip ordering.

Direction: presence of an exact `==` pin + a concrete `PROWLER_VERSION` value;
absence of any unpinned `pip install ... prowler` spec. A legitimate version
bump (`5.30.1` → `5.31.0`) stays green — the guard pins the *pinning*, not a
specific number — but un-pinning trips it. (The exact number is asserted to be
present and version-shaped so a blank/placeholder arg cannot pass.)

Mutation self-test
------------------
`TestProwlerVersionPinnedMutation` builds synthetic known-good/known-bad
Dockerfile snippets and confirms the detector fires on the un-pinned forms and
stays quiet on the pinned form and the real on-disk Dockerfile.

stdlib-only (no PyYAML). Regex/substring scanning. No `scanner/lib` import (does
not touch the 99% coverage gate). No network, no subprocess. Runs under pytest
(the CI runner) and `python3 -m unittest`.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

# `ARG PROWLER_VERSION=<x.y.z>` — the pin value must be version-shaped, not blank
# or a placeholder. Matches e.g. ARG PROWLER_VERSION=5.30.1
ARG_PIN_RE = re.compile(r"^\s*ARG\s+PROWLER_VERSION=(\d+\.\d+(?:\.\d+)?)\s*$", re.MULTILINE)

# Any ARG PROWLER_VERSION assignment (incl. blank / non-version), to catch a
# second override that bash/Docker last-wins resolves (sec-review Finding 3).
ARG_ANY_RE = re.compile(r"^\s*ARG\s+PROWLER_VERSION=(\S*)", re.MULTILINE)

# The install must use the pinned form: prowler==${PROWLER_VERSION} (or an
# inline ==<version>). We match a `prowler==` immediately followed by either the
# build arg or a literal version.
PINNED_INSTALL_RE = re.compile(r"prowler==(?:\$\{PROWLER_VERSION\}|\d+\.\d+)")

# Any `pip install ... prowler` where the prowler token is NOT followed by `==`
# (i.e. unpinned / floating). This is the #237 regression we forbid. The span is
# bounded to a single shell command (`[^&;|]`) so that — after continuation lines
# are joined — it does not run past the install into a later `&& ... prowler/...`
# path or `sed ... from prowler\.providers` reference (which would false-positive).
UNPINNED_INSTALL_RE = re.compile(
    r"pip install[^&;|\n]*?(?<![=\w])prowler(?!==)(?![=\w/.-])"
)


def _active_text(text: str) -> str:
    """The Dockerfile's *active* instructions: whole-line `#` comments dropped
    (so a token in a comment can't satisfy a check — Finding 2/6), and backslash
    line-continuations joined onto one line (so a `RUN pip install \\` that wraps
    `prowler` onto the next line is still seen — Finding 1, CRITICAL)."""
    no_comments = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    return no_comments.replace("\\\n", " ")


def violations(text: str) -> list:
    active = _active_text(text)
    problems = []
    all_args = ARG_ANY_RE.findall(active)
    version_args = ARG_PIN_RE.findall(active)
    if not all_args:
        problems.append(
            "MISSING exact ARG PROWLER_VERSION=<x.y.z> pin (unpinned prowler "
            "re-introduces the #237 py3.13 backtrack-to-3.11.3 crash)."
        )
    elif len(version_args) != len(all_args):
        problems.append(
            "Finding 3: an ARG PROWLER_VERSION assignment is blank or "
            "non-version-shaped — a second override (Docker last-wins) would make "
            "the build resolve an unpinned prowler when no --build-arg is passed."
        )
    if not PINNED_INSTALL_RE.search(active):
        problems.append(
            "MISSING pinned install form prowler==${PROWLER_VERSION} (or "
            "prowler==<version>)."
        )
    if UNPINNED_INSTALL_RE.search(active):
        problems.append(
            "FORBIDDEN unpinned `pip install ... prowler` spec found — prowler "
            "must always be installed with an exact == pin."
        )
    return problems


class TestProwlerVersionPinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(encoding="utf-8") if DOCKERFILE.is_file() else ""

    def test_dockerfile_exists(self):
        self.assertTrue(
            DOCKERFILE.is_file(),
            f"{DOCKERFILE} not found — the prowler install (and its pin) moved or "
            "was deleted.",
        )

    def test_arg_pin_present_and_version_shaped(self):
        active = _active_text(self.text)
        self.assertRegex(
            active, ARG_PIN_RE,
            "ARG PROWLER_VERSION=<x.y.z> not found or not version-shaped — prowler "
            "would be unpinned and could silently backtrack to 3.11.3 on a newer "
            "Python (incident #237). Restore the exact pin.",
        )
        self.assertEqual(
            len(ARG_ANY_RE.findall(active)), len(ARG_PIN_RE.findall(active)),
            "A blank/non-version ARG PROWLER_VERSION override is present "
            "(sec-review Finding 3) — the last-wins value would be unpinned.",
        )

    def test_install_uses_pinned_form(self):
        self.assertRegex(
            _active_text(self.text), PINNED_INSTALL_RE,
            "The prowler install no longer uses the prowler==${PROWLER_VERSION} "
            "pinned form.",
        )

    def test_no_unpinned_install(self):
        self.assertNotRegex(
            _active_text(self.text), UNPINNED_INSTALL_RE,
            "An unpinned `pip install ... prowler` spec is present — that is the "
            "exact #237 regression. Pin it with ==${PROWLER_VERSION}.",
        )

    def test_all_invariants_hold(self):
        problems = violations(self.text)
        self.assertEqual(
            problems, [],
            "Dockerfile weakened the prowler version pin:\n  " + "\n  ".join(problems),
        )


class TestProwlerVersionPinnedMutation(unittest.TestCase):
    _GOOD = "\n".join(
        [
            "ARG PROWLER_VERSION=5.30.1",
            'RUN pip install --no-cache-dir --break-system-packages "prowler==${PROWLER_VERSION}" \\',
            "    && find /install -type d -name tests -exec rm -rf {} +",
        ]
    )

    def test_good_passes(self):
        self.assertEqual(violations(self._GOOD), [])

    def test_removing_arg_pin_is_detected(self):
        mutant = self._GOOD.replace("ARG PROWLER_VERSION=5.30.1\n", "")
        self.assertTrue(
            any("ARG PROWLER_VERSION" in p for p in violations(mutant)),
            "Mutation FAILED: removing the ARG pin was NOT detected.",
        )

    def test_blank_arg_pin_is_detected(self):
        mutant = self._GOOD.replace("ARG PROWLER_VERSION=5.30.1", "ARG PROWLER_VERSION=")
        self.assertTrue(
            any("ARG PROWLER_VERSION" in p for p in violations(mutant)),
            "Mutation FAILED: a blank/placeholder ARG pin was NOT detected.",
        )

    def test_unpinned_install_is_detected(self):
        mutant = self._GOOD.replace('"prowler==${PROWLER_VERSION}"', "prowler")
        problems = violations(mutant)
        self.assertTrue(
            any("unpinned" in p.lower() for p in problems),
            "Mutation FAILED: an unpinned `pip install ... prowler` was NOT "
            "detected.\n  " + "\n  ".join(problems),
        )

    def test_continuation_unpinned_is_detected(self):
        # Finding 1 (CRITICAL): a `RUN pip install \` that wraps `prowler` onto
        # the next line must still be caught as unpinned.
        mutant = "ARG PROWLER_VERSION=5.30.1\nRUN pip install \\\n    prowler\n"
        self.assertTrue(
            any("unpinned" in p.lower() for p in violations(mutant)),
            "Mutation FAILED (Finding 1): a multi-line continuation unpinned "
            "prowler install was NOT detected.",
        )

    def test_comment_pin_with_active_continuation_unpinned_is_detected(self):
        # Finding 2 (HIGH): a commented-out pin must not satisfy the pinned-form
        # check while the active (wrapped) install is unpinned.
        mutant = (
            "ARG PROWLER_VERSION=5.30.1\n"
            "# old: RUN pip install 'prowler==${PROWLER_VERSION}'\n"
            "RUN pip install \\\n    prowler\n"
        )
        self.assertTrue(
            any("unpinned" in p.lower() for p in violations(mutant)),
            "Mutation FAILED (Finding 2): a commented pin masking an active "
            "unpinned install was NOT detected.",
        )

    def test_duplicate_blank_arg_override_is_detected(self):
        # Finding 3 (HIGH): a second blank ARG PROWLER_VERSION= (last-wins) override.
        mutant = (
            "ARG PROWLER_VERSION=5.30.1\n"
            "ARG PROWLER_VERSION=\n"
            'RUN pip install "prowler==${PROWLER_VERSION}"\n'
        )
        self.assertTrue(
            any("Finding 3" in p for p in violations(mutant)),
            "Mutation FAILED (Finding 3): a blank duplicate ARG PROWLER_VERSION "
            "override was NOT detected.",
        )

    def test_real_dockerfile_clean(self):
        if not DOCKERFILE.is_file():
            self.skipTest("Dockerfile not found — covered by TestProwlerVersionPinned")
        self.assertEqual(
            violations(DOCKERFILE.read_text(encoding="utf-8")), [],
            "The real Dockerfile failed the prowler-pin validator.",
        )


if __name__ == "__main__":
    unittest.main()
