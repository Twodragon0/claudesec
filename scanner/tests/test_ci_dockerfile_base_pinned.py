"""
Regression guard: container base images stay supply-chain pinned, and the
prowler image stays held on the pinned alpine minor (the py3.12 line) and
stays Python-version agnostic.

Background
----------
Two invariants protect the ClaudeSec images (OWASP Top 10:2021 A08 — Software
and Data Integrity Failures; NIST SSDF SP 800-218 PW.4):

  1. **Digest-pinned bases** — every `FROM` in `Dockerfile` and `Dockerfile.nginx`
     must carry an `@sha256:` digest, so a moving tag cannot swap the base image
     out from under a "reproducible" build.
  2. **alpine MINOR freeze + version-agnostic resolution** — in the prowler
     `Dockerfile`, every `FROM alpine:` must stay on `PINNED_ALPINE_MINOR`
     (currently 3.23, the LAST minor on the py3.12 line) with an `@sha256:`
     digest. The next minor, 3.24, ships py3.14 — outside prowler's `<3.14`
     range — so pip backtracks to prowler 3.11.3 / pydantic v1 and the scanner
     crashes at runtime (#220/#237). And the build must resolve
     site-packages with the version-agnostic `find ... -name 'python3.*'` glob
     (#234) rather than a hardcoded `python3.12/site-packages` path — a hardcoded
     path would break the build the moment the base Python changes, defeating the
     graceful-bump design.

`Dockerfile.nginx` uses a *different* base (`nginx:*-alpine`), so the alpine
minor freeze applies only to the prowler `Dockerfile`; the digest-pin invariant
applies to both. This guard complements `test_ci_dependabot_config.py` (which
locks the *freeze policy* in `dependabot.yml`) by locking the *actual image* a
manual edit could still bump.

Direction: alpine minor `== PINNED_ALPINE_MINOR` (any other minor trips); digest
pin = presence of `@sha256:`; version-agnostic = presence of the `python3.*` glob
+ absence of a hardcoded `python3.<n>/site-packages` path. Bumping the pin is a
deliberate act: change the ONE constant, having first re-measured the new minor's
Python against prowler's `requires_python` and rebuilt the image. Every fixture
below derives from that constant, so the mutation tests keep exercising the guard
after a bump instead of going vacuous.

Mutation self-test
------------------
`TestDockerfileBasePinnedMutation` builds synthetic snippets and confirms the
detector fires on an un-digest-pinned FROM, a bumped alpine minor, and a
hardcoded python3.N path, and stays quiet on the known-good form and the real
on-disk Dockerfiles.

stdlib-only (no PyYAML). Regex/line scanning. No `scanner/lib` import (does not
touch the 99% coverage gate). No network, no subprocess. Runs under pytest (the
CI runner) and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERFILE_NGINX = REPO_ROOT / "Dockerfile.nginx"

# Shared guard primitive (comment-stripping). Import as a top-level module so it
# resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines, strip_inline_comment  # noqa: E402

# A `FROM [--flag=...]... <image>[ AS stage]` line. Group 1 = the image ref.
# The `(?:--\S+\s+)*` prefix skips build flags like `--platform=$BUILDPLATFORM`
# so a multi-arch FROM is still inspected, not silently dropped (sec-review F5).
FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+\S+)?\s*$", re.MULTILINE | re.IGNORECASE
)

# Version-agnostic site-packages resolution (#234).
VERSION_AGNOSTIC_RE = re.compile(r"-name\s+'python3\.\*'")
# A hardcoded python minor in a site-packages path — the regression #234 removed.
HARDCODED_PY_PATH_RE = re.compile(r"python3\.\d+/site-packages")


def from_refs(text: str) -> list:
    # Strip whole-line AND trailing-inline `#` comments before matching. FROM_RE
    # anchors the image ref at line-end (`\s*$`), so a `FROM img@sha256:x # note`
    # line would otherwise fail to match and be SILENTLY DROPPED from both the
    # digest and alpine-freeze checks (comment-evasion false-negative — F-4).
    active = "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )
    return FROM_RE.findall(active)


def digest_violations(text: str, label: str) -> list:
    """Every FROM must be @sha256: digest pinned."""
    problems = []
    refs = from_refs(text)
    if not refs:
        problems.append(f"[{label}] no FROM line found — Dockerfile moved or emptied.")
    for ref in refs:
        if "@sha256:" not in ref:
            problems.append(
                f"[{label}] FROM {ref!r} is not digest-pinned (@sha256:) — a moving "
                "tag could swap the base image (OWASP A08)."
            )
    return problems


# The alpine minor the prowler image is pinned to. ONE constant, because the
# previous version of this guard spelled "3.20" in twenty places including its own
# mutation fixtures, so a legitimate bump meant a twenty-line diff and an easy
# miss — the enumeration-as-control shape ADR-001 §5 warns about.
#
# 3.23 is the LAST minor on the py3.12 line. Measured 2026-08-24 by installing
# python3 in each image: 3.20 -> 3.12.13, 3.21/3.22/3.23 -> 3.12.14,
# 3.24 -> 3.14.7. alpine skips py3.13 entirely, and prowler 5.39.1 requires
# `<3.14,>=3.10`, so 3.24 is out of range and the freeze stays.
#
# Bumping this constant is the deliberate act. Re-MEASURE the new minor's Python
# against prowler's `requires_python` first — `docker run --rm alpine:<v> sh -c
# 'apk add --no-cache python3 >/dev/null 2>&1; python3 --version'` — and build the
# image, because #220 was green at build time and broken at runtime.
PINNED_ALPINE_MINOR = "3.23"


def alpine_freeze_violations(text: str) -> list:
    """Every alpine FROM in the prowler Dockerfile must stay on the pinned minor."""
    expected = f"alpine:{PINNED_ALPINE_MINOR}@sha256:"
    problems = []
    for ref in from_refs(text):
        if ref.startswith("alpine:") or ref.startswith("alpine@"):
            if not ref.startswith(expected):
                problems.append(
                    f"FROM {ref!r} drifted off the alpine:{PINNED_ALPINE_MINOR} "
                    "(py3.12) line. The next minor (3.24) ships py3.14, which is "
                    "outside prowler's `<3.14` range: pip backtracks to prowler "
                    "3.11.3 (pydantic v1) and the scanner crashes at runtime "
                    "(#220 built green and was broken). If the bump is intended, "
                    "re-measure the new minor's Python and update "
                    "PINNED_ALPINE_MINOR in this guard."
                )
    return problems


def version_agnostic_violations(text: str) -> list:
    problems = []
    active = strip_comment_lines(text)
    if not VERSION_AGNOSTIC_RE.search(active):
        problems.append(
            "version-agnostic site-packages resolution (find ... -name "
            "'python3.*') is gone — restore it so an alpine base bump does not "
            "break the build (#234)."
        )
    if HARDCODED_PY_PATH_RE.search(active):
        problems.append(
            "a hardcoded pythonX.Y/site-packages path was re-introduced — this is "
            "the #234 regression; use the version-agnostic glob instead."
        )
    return problems


class TestDockerfileBasePinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = DOCKERFILE.read_text(encoding="utf-8") if DOCKERFILE.is_file() else ""
        cls.nginx = (
            DOCKERFILE_NGINX.read_text(encoding="utf-8")
            if DOCKERFILE_NGINX.is_file()
            else ""
        )

    def test_dockerfile_exists(self):
        self.assertTrue(DOCKERFILE.is_file(), f"{DOCKERFILE} not found.")

    def test_dockerfile_nginx_exists(self):
        self.assertTrue(DOCKERFILE_NGINX.is_file(), f"{DOCKERFILE_NGINX} not found.")

    def test_all_from_lines_digest_pinned(self):
        problems = digest_violations(self.df, "Dockerfile") + digest_violations(
            self.nginx, "Dockerfile.nginx"
        )
        self.assertEqual(
            problems, [],
            "A base image lost its digest pin:\n  " + "\n  ".join(problems),
        )

    def test_alpine_minor_frozen_at_320(self):
        problems = alpine_freeze_violations(self.df)
        self.assertEqual(
            problems, [],
            "The prowler Dockerfile alpine base drifted:\n  " + "\n  ".join(problems),
        )

    def test_version_agnostic_site_resolution(self):
        problems = version_agnostic_violations(self.df)
        self.assertEqual(
            problems, [],
            "The prowler Dockerfile lost its version-agnostic site resolution:\n  "
            + "\n  ".join(problems),
        )


class TestDockerfileBasePinnedMutation(unittest.TestCase):
    # Derived from PINNED_ALPINE_MINOR, never spelled. A fixture that hardcodes
    # the minor silently stops exercising the guard the day the pin moves: the
    # mutants below flip "the pinned minor" to "some other minor", and if the
    # fixture is already on some other minor then `_GOOD` itself is a violation
    # and every assertion here becomes vacuous.
    _PINNED_FROM = f"FROM alpine:{PINNED_ALPINE_MINOR}@sha256:deadbeef AS builder"
    _OFF_MINOR = "3.24" if PINNED_ALPINE_MINOR != "3.24" else "3.20"
    _GOOD = "\n".join(
        [
            _PINNED_FROM,
            "ARG PROWLER_VERSION=5.39.1",
            "RUN SITE=\"$(find /install/lib -maxdepth 1 -type d -name 'python3.*' | head -n1)/site-packages\"",
            f"FROM alpine:{PINNED_ALPINE_MINOR}@sha256:deadbeef",
        ]
    )
    _GOOD_NGINX = "FROM nginx:1.31-alpine@sha256:cafef00d"

    def test_good_passes(self):
        self.assertEqual(digest_violations(self._GOOD, "df"), [])
        self.assertEqual(digest_violations(self._GOOD_NGINX, "nginx"), [])
        self.assertEqual(alpine_freeze_violations(self._GOOD), [])
        self.assertEqual(version_agnostic_violations(self._GOOD), [])

    def test_untagged_digest_is_detected(self):
        mutant = self._GOOD.replace(
            self._PINNED_FROM, f"FROM alpine:{PINNED_ALPINE_MINOR} AS builder"
        )
        self.assertTrue(
            any("not digest-pinned" in p for p in digest_violations(mutant, "df")),
            "Mutation FAILED: a FROM without @sha256: digest was NOT detected.",
        )

    def test_alpine_minor_bump_is_detected(self):
        mutant = self._GOOD.replace(
            self._PINNED_FROM,
            f"FROM alpine:{self._OFF_MINOR}@sha256:deadbeef AS builder",
        )
        self.assertTrue(
            any(PINNED_ALPINE_MINOR in p for p in alpine_freeze_violations(mutant)),
            f"Mutation FAILED: an alpine minor bump "
            f"({PINNED_ALPINE_MINOR} -> {self._OFF_MINOR}) was NOT detected.",
        )

    def test_alpine_bump_on_commented_from_line_is_detected(self):
        # F-4 (comment-evasion): a trailing inline comment on a FROM line must not
        # make it slip past the freeze check (FROM_RE anchors the ref at line-end).
        mutant = self._GOOD.replace(
            self._PINNED_FROM,
            f"FROM alpine:{self._OFF_MINOR}@sha256:deadbeef AS builder  # interim bump",
        )
        self.assertTrue(
            any(PINNED_ALPINE_MINOR in p for p in alpine_freeze_violations(mutant)),
            "Mutation FAILED (F-4): an alpine bump on a FROM line with a trailing "
            "inline comment was silently dropped (not inspected).",
        )

    def test_undigested_from_with_trailing_comment_is_detected(self):
        mutant = self._GOOD.replace(
            self._PINNED_FROM,
            f"FROM alpine:{PINNED_ALPINE_MINOR} AS builder  # no digest",
        )
        self.assertTrue(
            any("not digest-pinned" in p for p in digest_violations(mutant, "df")),
            "Mutation FAILED (F-4): an un-digested FROM with a trailing comment "
            "was silently dropped.",
        )

    def test_hardcoded_python_path_is_detected(self):
        mutant = self._GOOD.replace(
            "find /install/lib -maxdepth 1 -type d -name 'python3.*' | head -n1)/site-packages",
            "echo /install/lib/python3.12/site-packages",
        )
        self.assertTrue(
            any("hardcoded" in p for p in version_agnostic_violations(mutant)),
            "Mutation FAILED: a hardcoded python3.12/site-packages path was NOT "
            "detected.",
        )

    def test_platform_flag_from_is_still_inspected(self):
        # Finding 5: a `FROM --platform=... alpine:3.24@...` must NOT be silently
        # dropped — the alpine minor bump still has to be caught.
        mutant = (
            f"FROM --platform=$BUILDPLATFORM alpine:{self._OFF_MINOR}"
            "@sha256:deadbeef AS builder"
        )
        self.assertTrue(
            any(PINNED_ALPINE_MINOR in p for p in alpine_freeze_violations(mutant)),
            "Mutation FAILED (Finding 5): a `FROM --platform=...` alpine minor bump "
            "was silently dropped by FROM_RE instead of being inspected.",
        )

    def test_platform_flag_undigested_from_is_detected(self):
        # Finding 5: digest check must also see through a --platform flag.
        mutant = f"FROM --platform=linux/amd64 alpine:{PINNED_ALPINE_MINOR} AS builder"
        self.assertTrue(
            any("not digest-pinned" in p for p in digest_violations(mutant, "df")),
            "Mutation FAILED (Finding 5): an un-digested `FROM --platform=...` was "
            "NOT detected.",
        )

    def test_comment_hardcoded_py_path_does_not_false_positive(self):
        # Finding 6: a comment mentioning python3.12/site-packages must not trip
        # the hardcoded-path check.
        good_with_comment = (
            "# do not hardcode python3.12/site-packages here\n" + self._GOOD
        )
        self.assertEqual(
            version_agnostic_violations(good_with_comment), [],
            "False positive (Finding 6): a comment mentioning a hardcoded "
            "python3.N/site-packages path tripped the guard.",
        )

    def test_real_dockerfiles_clean(self):
        if DOCKERFILE.is_file():
            df = DOCKERFILE.read_text(encoding="utf-8")
            self.assertEqual(digest_violations(df, "Dockerfile"), [])
            self.assertEqual(alpine_freeze_violations(df), [])
            self.assertEqual(version_agnostic_violations(df), [])
        if DOCKERFILE_NGINX.is_file():
            self.assertEqual(
                digest_violations(DOCKERFILE_NGINX.read_text(encoding="utf-8"), "Dockerfile.nginx"),
                [],
            )


if __name__ == "__main__":
    unittest.main()
