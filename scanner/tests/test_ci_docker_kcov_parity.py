"""
Regression guard: the local Docker kcov harness (`scripts/verify-shell-coverage-docker.sh`)
stays in sync with the CI `scanner-shell-coverage` job in `.github/workflows/lint.yml`.

Background
----------
`verify-shell-coverage-docker.sh` exists to reproduce the CI bash-coverage gate
locally (kcov is Linux/ptrace-only, so macOS devs run it in a container). Its
whole value is being CI-exact: it declares `INCLUDE=`, `EXCLUDE=`, and `FLOOR=`
that MUST match the `--include-pattern` / `--exclude-pattern` and coverage
threshold the CI job uses. When they drift, the local harness silently measures
a different set of files (or floor) than CI, so a dev can see "PASS locally" for
a change CI then rejects — or, worse, the harness's lax patterns pass a change
that craters real CI coverage.

This drift has already happened: PR #336 found the local `INCLUDE` was missing
`checks_credentials.sh` (present in CI since the credentials split), and had to
add `test_run_category_checks.sh` to `EXCLUDE` in BOTH places at once. Nothing
prevented the next divergence — this guard does.

The load-bearing invariants:
  1. The docker script's `INCLUDE` == CI's `--include-pattern` (as a set).
  2. The docker script's `EXCLUDE` == CI's `--exclude-pattern` (as a set).
  3. The docker script's `FLOOR` == CI's enforced coverage threshold.
  4. CI's own tty and non-tty kcov invocations use identical include/exclude
     patterns (a single canonical value to compare against).
  5. Both builds pass a CMake policy floor >= 3.5, regardless of flag order.
  6. Both builds verify the same SHA-256 before extracting kcov v42.
  7. CI uses the v3 cache, excluding binaries built from unverified source.

A legitimate coordinated change (e.g. splitting a new lib file and adding its
pattern to both files) stays green — the guard pins *equality of the two
sources*, not any specific pattern list.

stdlib-only (no PyYAML). Regex/substring scanning. No `scanner/lib` import (does
not touch the 99% coverage gate). No network, no subprocess. Runs under pytest
(the CI runner) and `python3 -m unittest`.
"""

import re
import shlex
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
DOCKER_SH = REPO_ROOT / "scripts" / "verify-shell-coverage-docker.sh"
DOCKERFILE = REPO_ROOT / "scripts" / "docker" / "shell-coverage.Dockerfile"

# Shared guard primitive (whole-line comment stripping). Import as a top-level
# module so it resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# CI kcov invocation flags (any number of occurrences; tty + non-tty).
CI_INCLUDE_RE = re.compile(r"--include-pattern=(\S+)")
CI_EXCLUDE_RE = re.compile(r"--exclude-pattern=(\S+)")
# CI enforced floor: `threshold = 90.0` in the Python enforce step.
CI_FLOOR_RE = re.compile(r"^\s*threshold\s*=\s*(\d+(?:\.\d+)?)\s*$", re.MULTILINE)

# Docker harness declarations: INCLUDE="...", EXCLUDE="...", FLOOR="...".
DOCKER_INCLUDE_RE = re.compile(r'^INCLUDE="([^"]*)"', re.MULTILINE)
DOCKER_EXCLUDE_RE = re.compile(r'^EXCLUDE="([^"]*)"', re.MULTILINE)
DOCKER_FLOOR_RE = re.compile(r'^FLOOR="([^"]*)"', re.MULTILINE)


def _pattern_set(csv: str) -> set:
    """Parse a comma-separated kcov pattern list into a set (order/dupes ignored),
    stripping a trailing backslash line-continuation and whitespace."""
    csv = csv.rstrip("\\").strip()
    return {p.strip() for p in csv.split(",") if p.strip()}


def _unique(values: list):
    """If every element of `values` is equal, return that element; else return
    the list of distinct values (a divergence to report). Empty -> None."""
    distinct = sorted(set(values))
    if not distinct:
        return None
    if len(distinct) == 1:
        return distinct[0]
    return distinct


def _as_float(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _build_violations(lint: str, dockerfile: str) -> list:
    """Check active build commands, without reading files or running tools."""
    problems = []
    step = re.search(
        r"^      - name: Build kcov v42 from source\n(.*?)(?=^      - name:|\Z)",
        lint, re.MULTILINE | re.DOTALL,
    )
    build = step.group(1) if step else ""
    if not step:
        problems.append("CI kcov build step missing or renamed: expected Build kcov v42 from source.")
    if not re.search(r"key: kcov-v42-.*-noble-v3$", lint, re.MULTILINE):
        problems.append("CI kcov cache must use v3 to discard unverified binaries.")
    if "refs/tags/v42.tar.gz" not in build or "cd kcov-42" not in build:
        problems.append("CI kcov source must remain pinned to v42.")
    if not re.search(r"^ARG KCOV_VERSION=42$", dockerfile, re.MULTILINE):
        problems.append("Docker kcov source must remain pinned to v42.")

    hashes = []
    for label, text in (("CI", build), ("Docker", dockerfile)):
        # Join shell continuations, then inspect only actual cmake commands.
        joined = re.sub(r"\\\n\s*", " ", text)
        commands = re.findall(r"(?:^|[;\n])\s*cmake\s+([^;\n]+)", joined)
        floors = []
        for command in commands:
            tokens = shlex.split(command)
            values = [t.split("=", 1)[1] for t in tokens
                      if t.startswith("-DCMAKE_POLICY_VERSION_MINIMUM=")]
            floors.extend(values)
        if not floors or any(
            not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value)
            or tuple(map(int, value.split("."))) < (3, 5)
            for value in floors
        ) or len(floors) != len(commands):
            problems.append(f"{label} cmake command must set CMAKE_POLICY_VERSION_MINIMUM >= 3.5.")
        pin = re.search(r"(?:^|\n)\s*(?:ARG )?KCOV_SHA256=([0-9a-f]{64})\s*(?:\n|$)", text)
        hashes.append(pin.group(1) if pin else None)
        if not pin:
            problems.append(f"{label} must declare a 64-digit KCOV_SHA256 pin.")
        # The checked file must be the downloaded file, and extraction follows verification.
        download = re.search(r"curl [^;\n]*-o kcov\.tar\.gz [^;\n]*refs/tags/", joined)
        verify = re.search(r'echo "\$\{KCOV_SHA256\}  kcov\.tar\.gz" \| sha256sum -c -', joined)
        extract = re.search(r"tar xzf kcov\.tar\.gz", joined)
        if not (download and verify and extract
                and download.start() < verify.start() < extract.start()):
            problems.append(f"{label} must download, sha256sum -c, then extract kcov.tar.gz.")
    if all(hashes) and hashes[0] != hashes[1]:
        problems.append("KCOV_SHA256 drift: CI and Docker pins must match.")
    return problems


def violations(lint_text: str, docker_text: str, dockerfile_text: str) -> list:
    """Every way the two sources disagree. Empty list == in sync."""
    problems = []
    lint = strip_comment_lines(lint_text)
    docker = strip_comment_lines(docker_text)

    problems.extend(_build_violations(lint, strip_comment_lines(dockerfile_text)))

    # --- CI side: collect every include/exclude occurrence, require consistency.
    ci_includes = CI_INCLUDE_RE.findall(lint)
    ci_excludes = CI_EXCLUDE_RE.findall(lint)
    if not ci_includes:
        problems.append(
            "CI lint.yml has no --include-pattern= (the scanner-shell-coverage "
            "kcov invocation moved or was removed) — cannot verify parity."
        )
    if not ci_excludes:
        problems.append(
            "CI lint.yml has no --exclude-pattern= (the scanner-shell-coverage "
            "kcov invocation moved or was removed) — cannot verify parity."
        )

    ci_inc = _unique([",".join(sorted(_pattern_set(v))) for v in ci_includes])
    ci_exc = _unique([",".join(sorted(_pattern_set(v))) for v in ci_excludes])
    if isinstance(ci_inc, list):
        problems.append(
            "CI lint.yml's kcov --include-pattern differs between invocations "
            f"(tty vs non-tty): {ci_inc}. They must be identical."
        )
    if isinstance(ci_exc, list):
        problems.append(
            "CI lint.yml's kcov --exclude-pattern differs between invocations "
            f"(tty vs non-tty): {ci_exc}. They must be identical."
        )

    ci_floor_m = CI_FLOOR_RE.search(lint)
    ci_floor = _as_float(ci_floor_m.group(1)) if ci_floor_m else None
    if ci_floor is None:
        problems.append(
            "CI lint.yml has no `threshold = <float>` coverage floor — the "
            "enforce step moved or was removed; cannot verify FLOOR parity."
        )

    # --- Docker side.
    d_inc_m = DOCKER_INCLUDE_RE.search(docker)
    d_exc_m = DOCKER_EXCLUDE_RE.search(docker)
    d_floor_m = DOCKER_FLOOR_RE.search(docker)
    if not d_inc_m:
        problems.append('verify-shell-coverage-docker.sh has no INCLUDE="..." declaration.')
    if not d_exc_m:
        problems.append('verify-shell-coverage-docker.sh has no EXCLUDE="..." declaration.')
    if not d_floor_m:
        problems.append('verify-shell-coverage-docker.sh has no FLOOR="..." declaration.')

    # --- Compare (only when both sides parsed).
    if ci_includes and d_inc_m and not isinstance(ci_inc, list):
        ci_set = _pattern_set(ci_includes[0])
        d_set = _pattern_set(d_inc_m.group(1))
        if ci_set != d_set:
            problems.append(
                "INCLUDE drift: docker harness "
                f"{sorted(d_set)} != CI --include-pattern {sorted(ci_set)}. "
                "Sync scripts/verify-shell-coverage-docker.sh to lint.yml."
            )
    if ci_excludes and d_exc_m and not isinstance(ci_exc, list):
        ci_set = _pattern_set(ci_excludes[0])
        d_set = _pattern_set(d_exc_m.group(1))
        if ci_set != d_set:
            problems.append(
                "EXCLUDE drift: docker harness "
                f"{sorted(d_set)} != CI --exclude-pattern {sorted(ci_set)}. "
                "Sync scripts/verify-shell-coverage-docker.sh to lint.yml."
            )
    if ci_floor is not None and d_floor_m:
        d_floor = _as_float(d_floor_m.group(1))
        if d_floor is None or d_floor != ci_floor:
            problems.append(
                f"FLOOR drift: docker harness FLOOR={d_floor_m.group(1)!r} != "
                f"CI threshold {ci_floor}. Sync the local floor to CI."
            )
    return problems


class TestDockerKcovParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lint = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        cls.docker = DOCKER_SH.read_text(encoding="utf-8") if DOCKER_SH.is_file() else ""

    def test_sources_exist(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found.")
        self.assertTrue(DOCKER_SH.is_file(), f"{DOCKER_SH} not found.")

    def test_in_sync(self):
        problems = violations(self.lint, self.docker, self.dockerfile)
        self.assertEqual(
            problems, [],
            "Local Docker kcov harness has drifted from CI (lint.yml):\n  "
            + "\n  ".join(problems),
        )


class TestDockerKcovParityMutation(unittest.TestCase):
    """Two minimal in-sync fixtures + mutations, so the guard is proven to FAIL
    on each drift class (not just pass on the live, already-synced files)."""

    _LINT = "\n".join(
        [
            "            if [[ \"$name\" == *_tty ]]; then",
            "              kcov --include-pattern=checks.sh,output.sh \\",
            "                --exclude-pattern=api-checks.sh,test_x.sh \\",
            "                \"kcov-out/$name\" \"$sh\"",
            "            else",
            "              kcov --include-pattern=checks.sh,output.sh \\",
            "                --exclude-pattern=api-checks.sh,test_x.sh \\",
            "                \"kcov-out/$name\" \"$sh\"",
            "            fi",
            "          threshold = 90.0",
        ]
    )
    _DOCKER = "\n".join(
        [
            'INCLUDE="checks.sh,output.sh"',
            'EXCLUDE="api-checks.sh,test_x.sh"',
            'FLOOR="90.0"',
        ]
    )

    _LINT += "\n" + "\n".join([
        "          key: kcov-v42-Linux-X64-noble-v3",
        "      - name: Build kcov v42 from source",
        "        run: |",
        "          KCOV_SHA256=" + "a" * 64,
        "          curl -fsSL -o kcov.tar.gz https://github.com/SimonKagstrom/kcov/archive/refs/tags/v42.tar.gz",
        '          echo "${KCOV_SHA256}  kcov.tar.gz" | sha256sum -c -',
        "          tar xzf kcov.tar.gz",
        "          cd kcov-42",
        "          cmake -DCMAKE_INSTALL_PREFIX=/tmp/kcov -DCMAKE_POLICY_VERSION_MINIMUM=3.5 ..",
    ])
    _DOCKERFILE = "\n".join([
        "ARG KCOV_VERSION=42",
        "ARG KCOV_SHA256=" + "a" * 64,
        "RUN set -eux; "
        'curl -fsSL -o kcov.tar.gz https://github.com/SimonKagstrom/kcov/archive/refs/tags/v${KCOV_VERSION}.tar.gz; '
        'echo "${KCOV_SHA256}  kcov.tar.gz" | sha256sum -c -; '
        "tar xzf kcov.tar.gz; "
        "cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_INSTALL_PREFIX=/usr/local ..",
    ])

    def test_build_mutations_fail(self):
        for label, lint, dockerfile, message in [
            ("missing flag", self._LINT.replace("-DCMAKE_POLICY_VERSION_MINIMUM=3.5", ""), self._DOCKERFILE, "CI cmake"),
            ("comment only", self._LINT.replace("-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "") + "\n# cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 ..", self._DOCKERFILE, "CI cmake"),
            ("renamed step", self._LINT.replace("Build kcov v42 from source", "Build renamed"), self._DOCKERFILE, "missing or renamed"),
            ("low floor", self._LINT.replace("MINIMUM=3.5", "MINIMUM=3.4"), self._DOCKERFILE, "CI cmake"),
            ("invalid floor", self._LINT.replace("MINIMUM=3.5", "MINIMUM=bad"), self._DOCKERFILE, "CI cmake"),
            ("docker missing flag", self._LINT, self._DOCKERFILE.replace("-DCMAKE_POLICY_VERSION_MINIMUM=3.5", ""), "Docker cmake"),
            ("hash drift", self._LINT, self._DOCKERFILE.replace("a" * 64, "b" * 64), "KCOV_SHA256 drift"),
            ("missing hash", self._LINT.replace("a" * 64, ""), self._DOCKERFILE, "64-digit"),
            ("comment hash", self._LINT, self._DOCKERFILE.replace("ARG KCOV_SHA256", "# ARG KCOV_SHA256"), "64-digit"),
            ("old cache", self._LINT.replace("noble-v3", "noble-v2"), self._DOCKERFILE, "cache"),
        ]:
            with self.subTest(label=label):
                self.assertTrue(any(message in p for p in violations(lint, self._DOCKER, dockerfile)))

    def test_verification_required_before_extraction(self):
        for target in ("CI", "Docker"):
            for old, new in [
                ("sha256sum -c -", "true"),
                ("-o kcov.tar.gz", "-o other.tar.gz"),
                ("tar xzf kcov.tar.gz", "tar xzf other.tar.gz"),
                ('echo "${KCOV_SHA256}  kcov.tar.gz" | sha256sum -c -',
                 'tar xzf kcov.tar.gz; echo "${KCOV_SHA256}  kcov.tar.gz" | sha256sum -c -'),
            ]:
                with self.subTest(target=target, mutation=new):
                    lint = self._LINT.replace(old, new) if target == "CI" else self._LINT
                    dockerfile = self._DOCKERFILE.replace(old, new) if target == "Docker" else self._DOCKERFILE
                    self.assertTrue(any(target + " must download" in p
                                        for p in violations(lint, self._DOCKER, dockerfile)))

    def test_reordered_flags_and_higher_policy_floor_pass(self):
        lint = self._LINT.replace(
            "-DCMAKE_INSTALL_PREFIX=/tmp/kcov -DCMAKE_POLICY_VERSION_MINIMUM=3.5",
            "-DCMAKE_POLICY_VERSION_MINIMUM=3.10 -DCMAKE_INSTALL_PREFIX=/tmp/kcov",
        )
        dockerfile = self._DOCKERFILE.replace("MINIMUM=3.5", "MINIMUM=4.0")
        self.assertEqual(violations(lint, self._DOCKER, dockerfile), [])

    def test_good_passes(self):
        self.assertEqual(violations(self._LINT, self._DOCKER, self._DOCKERFILE), [])

    def test_order_and_dupes_ignored(self):
        docker = 'INCLUDE="output.sh,checks.sh,checks.sh"\nEXCLUDE="test_x.sh,api-checks.sh"\nFLOOR="90.0"'
        self.assertEqual(violations(self._LINT, docker, self._DOCKERFILE), [])

    def test_include_drift_detected(self):
        docker = self._DOCKER.replace('INCLUDE="checks.sh,output.sh"', 'INCLUDE="checks.sh"')
        self.assertTrue(
            any("INCLUDE drift" in p for p in violations(self._LINT, docker, self._DOCKERFILE)),
            "Mutation FAILED: a missing INCLUDE pattern was NOT detected.",
        )

    def test_exclude_drift_detected(self):
        docker = self._DOCKER.replace("test_x.sh", "")
        self.assertTrue(
            any("EXCLUDE drift" in p for p in violations(self._LINT, docker, self._DOCKERFILE)),
            "Mutation FAILED: a missing EXCLUDE pattern was NOT detected.",
        )

    def test_floor_drift_detected(self):
        docker = self._DOCKER.replace('FLOOR="90.0"', 'FLOOR="85.0"')
        self.assertTrue(
            any("FLOOR drift" in p for p in violations(self._LINT, docker, self._DOCKERFILE)),
            "Mutation FAILED: a floor mismatch was NOT detected.",
        )

    def test_ci_internal_inconsistency_detected(self):
        # tty invocation includes an extra pattern the non-tty one lacks.
        lint = self._LINT.replace(
            "--include-pattern=checks.sh,output.sh \\\n                --exclude-pattern=api-checks.sh,test_x.sh",
            "--include-pattern=checks.sh,output.sh,extra.sh \\\n                --exclude-pattern=api-checks.sh,test_x.sh",
            1,
        )
        self.assertTrue(
            any("differs between invocations" in p for p in violations(lint, self._DOCKER, self._DOCKERFILE)),
            "Mutation FAILED: divergent tty/non-tty CI patterns were NOT detected.",
        )

    def test_comment_only_pattern_does_not_satisfy(self):
        # A pattern that appears ONLY in a comment must not count as CI's real value.
        docker = (
            "# --include-pattern=checks.sh,output.sh (doc only)\n"
            'INCLUDE="checks.sh"\n'
            'EXCLUDE="api-checks.sh,test_x.sh"\n'
            'FLOOR="90.0"'
        )
        self.assertTrue(
            any("INCLUDE drift" in p for p in violations(self._LINT, docker, self._DOCKERFILE)),
            "Mutation FAILED: a comment-only pattern was treated as the real value.",
        )


if __name__ == "__main__":
    unittest.main()
