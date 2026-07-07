"""
Regression guard: Trivy is installed from an EXACT version pin in `Dockerfile`
and its downloaded binary is checksum-verified — never a floating tag or an
integrity-free download.

Background
----------
The ClaudeSec image installs the Trivy CLI (used by the network checks) by
`curl`-downloading a prebuilt release asset. Unlike prowler (a `pip` package
Dependabot can bump) and the base image (a `FROM` digest Dependabot tracks),
Trivy is fetched via a hardcoded `ARG TRIVY_VERSION` + `curl`, which Dependabot's
`docker` ecosystem cannot see — so it can silently go stale or miss a CVE fix
with no automated signal, and a careless edit could drop the checksum step or
switch to a `/releases/latest/` floating tag (a supply-chain regression).

The load-bearing invariants are therefore:
  1. Trivy is pinned via an exact, version-shaped `ARG TRIVY_VERSION=<x.y.z>`
     (no blank / non-version value, no second last-wins override).
  2. The download URL references the pinned tag `v${TRIVY_VERSION}` — never a
     floating `/releases/latest/`.
  3. The downloaded asset is integrity-checked (`sha256sum -c`) against the
     upstream checksums file.

A legitimate version bump (`0.69.3` -> `0.70.0`) stays green — the guard pins the
*pinning + integrity check*, not a specific number. Mirrors
`test_ci_prowler_version_pinned.py`.

stdlib-only (no PyYAML). Regex/substring scanning. No `scanner/lib` import (does
not touch the 99% coverage gate). No network, no subprocess. Runs under pytest
(the CI runner) and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"

# Shared guard primitives (comment-stripping, continuation-joining). Import as a
# top-level module so it resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import join_continuations, strip_comment_lines  # noqa: E402

# `ARG TRIVY_VERSION=<x.y.z>` — the pin value must be version-shaped, not blank
# or a placeholder. Matches e.g. ARG TRIVY_VERSION=0.69.3
ARG_PIN_RE = re.compile(r"^\s*ARG\s+TRIVY_VERSION=(\d+\.\d+(?:\.\d+)?)\s*$", re.MULTILINE)

# Any ARG TRIVY_VERSION assignment (incl. blank / non-version), to catch a second
# override that Docker last-wins resolves.
ARG_ANY_RE = re.compile(r"^\s*ARG\s+TRIVY_VERSION=(\S*)", re.MULTILINE)

# The download must reference the pinned release tag v${TRIVY_VERSION}.
PINNED_DOWNLOAD_RE = re.compile(r"trivy/releases/download/v\$\{TRIVY_VERSION\}/")

# A floating `/releases/latest/` trivy download — the regression we forbid.
FLOATING_DOWNLOAD_RE = re.compile(r"trivy/releases/latest/")

# The downloaded asset must be checksum-verified.
CHECKSUM_VERIFY_RE = re.compile(r"sha256sum\s+-c")


def _active_text(text: str) -> str:
    """The Dockerfile's *active* instructions: whole-line `#` comments dropped and
    backslash line-continuations joined onto one line (so a wrapped `RUN` that
    spreads the download/checksum across lines is still seen as one command)."""
    return join_continuations(strip_comment_lines(text))


def violations(text: str) -> list:
    active = _active_text(text)
    problems = []
    all_args = ARG_ANY_RE.findall(active)
    version_args = ARG_PIN_RE.findall(active)
    if not all_args:
        problems.append(
            "MISSING exact ARG TRIVY_VERSION=<x.y.z> pin (an unpinned/floating "
            "Trivy can go stale or miss a CVE fix with no Dependabot signal)."
        )
    elif len(version_args) != len(all_args):
        problems.append(
            "An ARG TRIVY_VERSION assignment is blank or non-version-shaped — a "
            "second override (Docker last-wins) would make the build unpinned."
        )
    if not PINNED_DOWNLOAD_RE.search(active):
        problems.append(
            "MISSING pinned download form trivy/releases/download/v${TRIVY_VERSION}/."
        )
    if FLOATING_DOWNLOAD_RE.search(active):
        problems.append(
            "FORBIDDEN floating trivy/releases/latest/ download — pin the tag with "
            "v${TRIVY_VERSION}."
        )
    if not CHECKSUM_VERIFY_RE.search(active):
        problems.append(
            "MISSING checksum verification (sha256sum -c) for the downloaded Trivy "
            "binary — the download must be integrity-checked."
        )
    return problems


class TestTrivyVersionPinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(encoding="utf-8") if DOCKERFILE.is_file() else ""

    def test_dockerfile_exists(self):
        self.assertTrue(
            DOCKERFILE.is_file(),
            f"{DOCKERFILE} not found — the Trivy install (and its pin) moved or "
            "was deleted.",
        )

    def test_arg_pin_present_and_version_shaped(self):
        active = _active_text(self.text)
        self.assertRegex(
            active, ARG_PIN_RE,
            "ARG TRIVY_VERSION=<x.y.z> not found or not version-shaped — Trivy "
            "would be unpinned. Restore the exact pin.",
        )
        self.assertEqual(
            len(ARG_ANY_RE.findall(active)), len(ARG_PIN_RE.findall(active)),
            "A blank/non-version ARG TRIVY_VERSION override is present — the "
            "last-wins value would be unpinned.",
        )

    def test_download_uses_pinned_tag(self):
        self.assertRegex(
            _active_text(self.text), PINNED_DOWNLOAD_RE,
            "The Trivy download no longer references the pinned v${TRIVY_VERSION} tag.",
        )

    def test_no_floating_latest_download(self):
        self.assertNotRegex(
            _active_text(self.text), FLOATING_DOWNLOAD_RE,
            "A floating trivy/releases/latest/ download is present — pin the tag.",
        )

    def test_download_is_checksum_verified(self):
        self.assertRegex(
            _active_text(self.text), CHECKSUM_VERIFY_RE,
            "The Trivy binary download is no longer checksum-verified (sha256sum -c).",
        )

    def test_all_invariants_hold(self):
        problems = violations(self.text)
        self.assertEqual(
            problems, [],
            "Dockerfile weakened the Trivy pin / integrity check:\n  "
            + "\n  ".join(problems),
        )


class TestTrivyVersionPinnedMutation(unittest.TestCase):
    _GOOD = "\n".join(
        [
            "ARG TRIVY_VERSION=0.69.3",
            "RUN set -eux; \\",
            '    trivy_file="trivy_${TRIVY_VERSION}_${asset_arch}.tar.gz"; \\',
            '    curl -fsSL -o "/tmp/${trivy_file}" \\',
            '      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_file}"; \\',
            "    cd /tmp && grep \"${trivy_file}\" trivy_checksums.txt | sha256sum -c -",
        ]
    )

    def test_good_passes(self):
        self.assertEqual(violations(self._GOOD), [])

    def test_removing_arg_pin_is_detected(self):
        mutant = self._GOOD.replace("ARG TRIVY_VERSION=0.69.3\n", "")
        self.assertTrue(
            any("ARG TRIVY_VERSION" in p for p in violations(mutant)),
            "Mutation FAILED: removing the ARG pin was NOT detected.",
        )

    def test_blank_arg_pin_is_detected(self):
        mutant = self._GOOD.replace("ARG TRIVY_VERSION=0.69.3", "ARG TRIVY_VERSION=")
        self.assertTrue(
            any("blank or non-version" in p for p in violations(mutant)),
            "Mutation FAILED: a blank ARG pin was NOT detected.",
        )

    def test_floating_latest_is_detected(self):
        mutant = self._GOOD.replace(
            "trivy/releases/download/v${TRIVY_VERSION}/", "trivy/releases/latest/"
        )
        self.assertTrue(
            any("floating" in p or "pinned download" in p for p in violations(mutant)),
            "Mutation FAILED: a floating /releases/latest/ download was NOT detected.",
        )

    def test_removing_checksum_is_detected(self):
        mutant = self._GOOD.replace("| sha256sum -c -", "")
        self.assertTrue(
            any("checksum" in p for p in violations(mutant)),
            "Mutation FAILED: dropping the sha256sum -c check was NOT detected.",
        )


if __name__ == "__main__":
    unittest.main()
