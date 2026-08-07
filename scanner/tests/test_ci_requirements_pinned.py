"""
Regression guard: every requirement in every root `requirements*.txt` must carry
an exact `==` pin.

WHY
---
Measured on this repo (`GET /repos/{owner}/{repo}/dependency-graph/compare`,
2026-08-07), the two manifests were blind to DIFFERENT degrees, and the
difference is the point:

- `requirements-scripts.txt` (unconstrained) recorded `version: ""` for all five
  packages — nothing for an advisory to match. Its history confirms the effect:
  two commits total, never once touched by Dependabot.
- `requirements-ci.txt` (`>=` floors) recorded the RANGE — `Pillow >= 12.3.0` —
  and Dependabot did bump it (#141, #236, #272, #321). It was not blind, it was
  weaker. The repository SBOM still carried it as a bare `pkg:pypi/pillow` with
  no `@version` (ten of eleven pypi entries were versionless, against
  `pkg:pypi/pyyaml@6.0.3`), so anything consuming the SBOM rather than the
  manifest saw no version.

The second reason applies to both, and `requirements-fork-guard.txt` already
documents it for the `pyyaml>=6.0,<7` range it replaced: a floating range is
resolved at job time, so a release published between two runs enters CI with no
review. The `pip-audit` job is path-gated on `requirements.*\\.txt`, so drift
that does not touch the file is not audited AT THE MOMENT IT HAPPENS — it waits
for the weekly `schedule:` arm added in #394.

Pinning costs nothing here: `.github/dependabot.yml` runs the `pip` ecosystem on
`/` weekly with a `pip-deps` group, so upgrades arrive as one reviewable PR.

SEMANTICS
---------
PIN, not floor. Every logical requirement line must carry an exact `==<version>`
specifier. `>=`, `~=`, `<=`, `!=`, a bare package name, a `${VAR}`-templated
version, a PEP 508 direct reference (`pkg @ https://...`), and `-r`/`-c`/`-e`
indirection all trip the guard. Changing a pinned version stays green — that
reviewable diff is the point.

KNOWN LIMITS, each with its DIRECTION
-------------------------------------
- **`--require-hashes` and direct references are rejected (false POSITIVE).**
  Both are *stronger* than `==`, and hash-pinning is a posture this repo
  explicitly considered and declined (`requirements-fork-guard.txt`, "WHY NOT
  --require-hashes"). If either is adopted this guard must be extended first —
  it fails loudly rather than silently accepting, which is the correct way round.
- **Only ROOT-level `requirements*.txt` is discovered (false NEGATIVE, bounded).**
  A repo-wide `rglob` was tried and reverted: it red-lit developer machines on
  untracked `build/`, `scratch/`, and non-standard venv directories, and these
  guards may not shell out to `git ls-files` (stdlib-only, no subprocess). The
  gap that actually mattered — a manifest CI installs but nothing checks — is
  closed directly instead, by `test_workflow_installed_manifests_are_checked`:
  every `-r <path>` in `.github/workflows/**` must resolve to a file this guard
  reads. A nested manifest no workflow installs is also outside
  `.github/dependabot.yml`'s `directory: "/"` scope, so introducing one requires
  a dependabot change, which `test_ci_dependabot_config.py` sees.

An earlier revision of this guard was defeated five ways in adversarial review
(comment-continuation deletion, base64 `==` padding in a URL, `--extra-index-url`
with `==` in the query, VCS refs, `${VAR}` versions). Each is a `test_bypass_*`
self-test below; treat the parser as attackable and land the PoC before the fix.

stdlib-only (Path glob + line scanning, no PyYAML — absent from
requirements-ci.txt). No network, no subprocess. Passes under pytest (the CI
runner) and `python3 -m unittest`. Does not import scanner/lib, so it never
moves the measured coverage gate.

OWASP CICD-SEC-3 (Dependency Chain Abuse) / CICD-SEC-7 (Insecure System
Configuration); NIST SSDF (SP 800-218) PW.4, PO.3.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    strip_inline_comment,
    workflow_and_action_files,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

# The root manifests in scope. Asserted as an EQUALITY, not a subset: a new
# root-level requirements file fails until it is listed here, forcing a
# deliberate decision instead of silently joining — or skipping — the invariant.
EXPECTED_MANIFESTS = {
    "requirements-ci.txt",
    "requirements-fork-guard.txt",
    "requirements-scripts.txt",
}

# pip options that cannot introduce an unpinned or unreviewed dependency, so they
# are not requirements and are skipped. Enumerating the SAFE set is deliberate
# and directional: an option not listed here is REPORTED (a false alarm someone
# resolves), never silently accepted. The dangerous ones — `-r`/`-c`/`-e`, which
# defer pinning elsewhere, and `--index-url`/`--extra-index-url`/`--find-links`,
# which add a resolution source (the dependency-confusion primitive) — are
# therefore covered without having to be enumerated.
_INERT_OPTIONS = frozenset(
    {
        "--require-hashes",
        "--only-binary",
        "--no-binary",
        "--prefer-binary",
        "--no-index",
    }
)

# An exact-version specifier. The version must be a real token, so
# `--extra-index-url https://h.test/simple?t=YQ==` — which ends in `==` with
# nothing after it — does NOT match. `${VAR}` versions are rejected separately.
_PIN_RE = re.compile(r"==\s*(?P<v>[^\s,;#]+)")

# `pip install ... -r <path>` inside a workflow.
_INSTALL_R_RE = re.compile(r"-r\s+(?P<p>[^\s'\"]*requirements[\w.-]*\.txt)")


def requirements_files() -> list:
    """The root-level `requirements*.txt` manifests (see KNOWN LIMITS)."""
    return sorted(REPO_ROOT.glob("requirements*.txt"))


def join_requirement_continuations(text: str) -> str:
    """Join `\\`-continuations the way pip does — a COMMENT line never continues.

    pip's `req_file.join_lines()` skips the continuation when the physical line
    matches its `COMMENT_RE`. A naive `text.replace("\\\\\\n", " ")` does not, so
    a prose comment ending in a backslash ABSORBS the next line and the
    requirement on it vanishes from the scan. That defeated the first version of
    this guard (`# see docs \\` + `pytest>=9.1.1` reported clean while pip
    installed a live floating floor), and is why this is not the shared
    `join_continuations` helper: shell and Dockerfile continuations have no such
    exemption, so giving the shared helper one would be wrong for them.

    `rstrip()` before the backslash test also makes CRLF files behave.
    """
    out, pending = [], ""
    for raw in text.splitlines():
        line = pending + raw
        pending = ""
        stripped = line.rstrip()
        if stripped.endswith("\\") and not line.lstrip().startswith("#"):
            pending = stripped[:-1] + " "
            continue
        out.append(line)
    if pending:
        out.append(pending)
    return "\n".join(out)


def logical_requirement_lines(text: str) -> list:
    """The requirement lines of a requirements file, comment- and marker-free.

    Continuations are joined pip-faithfully, then whole-line and trailing
    `# ...` comments are removed (pip needs whitespace before an inline `#`,
    exactly `strip_inline_comment`'s boundary), then the PEP 508 environment
    marker after `;` is dropped so a marker's own `==` cannot stand in for a
    missing version pin.
    """
    lines = []
    for raw in join_requirement_continuations(text).splitlines():
        line = strip_inline_comment(raw).strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(";", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def is_exactly_pinned(line: str) -> bool:
    """Whether one logical requirement line carries an exact `==<version>` pin."""
    if line.startswith("-"):
        # An option, not a requirement. Only the inert ones are accepted.
        return line.split("=", 1)[0].split()[0] in _INERT_OPTIONS
    if "@" in line:
        # PEP 508 direct reference (`pkg @ https://…`, `pkg @ git+https://…@ref`).
        # It carries no version specifier, and any `==` in it belongs to the URL
        # — base64 padding in a signed query string is the ordinary case.
        return False
    m = _PIN_RE.search(line)
    # `pytest==${PYTEST_VER}` is expanded by pip from the job environment, which
    # is precisely the unreviewed-CI-input failure this guard exists to prevent.
    return bool(m) and "$" not in m.group("v")


def unpinned_requirements(text: str) -> list:
    """Logical requirement lines in `text` that carry no exact `==` pin."""
    return [ln for ln in logical_requirement_lines(text) if not is_exactly_pinned(ln)]


def workflow_installed_manifests() -> dict:
    """`{workflow path: [requirements paths it installs]}`, from `-r <path>`.

    Closes the discovery gap left by scanning only the repo root: a manifest CI
    actually installs must be one this guard reads, wherever it lives. Whole-line
    and trailing comments are dropped first, so a commented-out legacy install
    does not create a phantom requirement.
    """
    found = {}
    # workflow_and_action_files() yields str paths (glob), not Path.
    for wf in (Path(p) for p in workflow_and_action_files()):
        hits = []
        for raw in wf.read_text(encoding="utf-8").splitlines():
            if raw.lstrip().startswith("#"):
                continue
            hits.extend(
                m.group("p") for m in _INSTALL_R_RE.finditer(strip_inline_comment(raw))
            )
        if hits:
            found[str(wf.relative_to(REPO_ROOT))] = sorted(set(hits))
    return found


class TestCiRequirementsPinned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = requirements_files()

    def test_requirements_files_found(self):
        # Canary: a vacuous pass if the glob or repo-root assumption breaks.
        self.assertTrue(
            self.files,
            f"no requirements*.txt found under {REPO_ROOT} — glob/path broke",
        )

    def test_manifest_set_is_exactly_the_expected_one(self):
        self.assertEqual(
            {p.name for p in self.files},
            EXPECTED_MANIFESTS,
            "the set of root requirements manifests changed. Adding one is fine "
            "— list it in EXPECTED_MANIFESTS so the addition is reviewed rather "
            "than silently joining or skipping the pin invariant.",
        )

    def test_every_requirement_is_exactly_pinned(self):
        offenders = {}
        for path in self.files:
            bad = unpinned_requirements(path.read_text(encoding="utf-8"))
            if bad:
                offenders[str(path.relative_to(REPO_ROOT))] = bad
        self.assertEqual(
            offenders,
            {},
            "requirement(s) without an exact `==` pin:\n"
            + "\n".join(
                f"  {rel}: {', '.join(bad)}" for rel, bad in sorted(offenders.items())
            )
            + "\nPin the version. An unconstrained requirement is recorded by "
            "GitHub's dependency graph with an EMPTY version, and even a `>=` "
            "floor leaves the SBOM purl versionless; a floating range also lets "
            "an unreviewed release into CI between audits. The `pip` ecosystem "
            "in .github/dependabot.yml raises upgrades as PRs, so a pin is a "
            "reviewable diff, not a maintenance burden.",
        )

    def test_workflow_installed_manifests_are_checked(self):
        checked = {p.resolve() for p in self.files}
        unchecked = {}
        for wf, paths in workflow_installed_manifests().items():
            missing = [p for p in paths if (REPO_ROOT / p).resolve() not in checked]
            if missing:
                unchecked[wf] = missing
        self.assertEqual(
            unchecked,
            {},
            "workflow(s) install a requirements file this guard never reads, so "
            "its pins are unenforced:\n"
            + "\n".join(
                f"  {wf}: {', '.join(ps)}" for wf, ps in sorted(unchecked.items())
            )
            + "\nMove it to the repo root (where the dependency graph and "
            'dependabot\'s `directory: "/"` also see it) and list it in '
            "EXPECTED_MANIFESTS.",
        )


class TestUnpinnedRequirementDetector(unittest.TestCase):
    """Mutation self-tests. Every `test_bypass_*` case is a PoC from adversarial
    review that the first version of this parser reported as clean."""

    def test_exact_pin_is_accepted(self):
        self.assertEqual(unpinned_requirements("pytest==9.1.1\n"), [])

    def test_floor_is_rejected(self):
        self.assertEqual(unpinned_requirements("pytest>=9.1.1\n"), ["pytest>=9.1.1"])

    def test_bare_package_is_rejected(self):
        self.assertEqual(unpinned_requirements("gspread\n"), ["gspread"])

    def test_compatible_release_is_rejected(self):
        self.assertEqual(unpinned_requirements("pytest~=9.1\n"), ["pytest~=9.1"])

    def test_exclusion_is_rejected(self):
        # `!=` contains `=` but is not a pin — a substring check for `=` alone
        # would have accepted it.
        self.assertEqual(unpinned_requirements("pytest!=9.1.1\n"), ["pytest!=9.1.1"])

    def test_requirement_indirection_is_rejected(self):
        self.assertEqual(unpinned_requirements("-r extra.txt\n"), ["-r extra.txt"])

    def test_constraint_indirection_is_rejected(self):
        self.assertEqual(
            unpinned_requirements("-c constraints.txt\n"), ["-c constraints.txt"]
        )

    def test_editable_install_is_rejected(self):
        self.assertEqual(unpinned_requirements("-e .\n"), ["-e ."])

    def test_comment_lines_and_blanks_are_ignored(self):
        text = "# pytest>=9.1.1 (prose about the old floor)\n\n   \npytest==9.1.1\n"
        self.assertEqual(unpinned_requirements(text), [])

    def test_extras_with_pin_are_accepted(self):
        self.assertEqual(unpinned_requirements("celery[redis]==5.4.0\n"), [])

    def test_pinned_package_with_marker_is_accepted(self):
        self.assertEqual(
            unpinned_requirements('gspread==6.2.1; python_version=="3.13"\n'), []
        )

    def test_hash_continuation_is_joined_before_judging(self):
        text = "pytest==9.1.1 \\\n    --hash=sha256:abc\n"
        self.assertEqual(unpinned_requirements(text), [])

    def test_crlf_continuation_is_joined(self):
        # `rstrip()` before the backslash test — otherwise `\r` hides it and the
        # `--hash` continuation is reported as a bare unpinned line.
        self.assertEqual(
            unpinned_requirements("pytest==9.1.1 \\\r\n  --hash=sha256:a\r\n"), []
        )

    def test_inert_options_are_accepted(self):
        for opt in ("--require-hashes", "--only-binary=:all:", "--no-index"):
            self.assertEqual(unpinned_requirements(opt + "\npytest==9.1.1\n"), [], opt)

    def test_multiple_offenders_are_all_reported(self):
        text = "pytest==9.1.1\ngspread\nrequests>=2.34.2\n"
        self.assertEqual(unpinned_requirements(text), ["gspread", "requests>=2.34.2"])

    # ── PoCs that defeated the first version of this parser ──────────────────

    def test_bypass_inline_comment_cannot_supply_the_pin(self):
        self.assertEqual(unpinned_requirements("gspread  # ==6.2.1\n"), ["gspread"])

    def test_bypass_environment_marker_cannot_supply_the_pin(self):
        # `python_version=="3.13"` contains `==` while the package is unpinned.
        self.assertEqual(
            unpinned_requirements('gspread; python_version=="3.13"\n'), ["gspread"]
        )

    def test_bypass_comment_ending_in_backslash_does_not_eat_the_next_line(self):
        # pip does NOT continue a comment line, so `pytest>=9.1.1` here is a live
        # floating floor. A naive `\\\n` -> ' ' join deleted it from the scan.
        text = "# upgrades arrive via Dependabot, see \\\npytest>=9.1.1\n"
        self.assertEqual(unpinned_requirements(text), ["pytest>=9.1.1"])

    def test_bypass_base64_padding_in_direct_reference(self):
        # `sig=YWJjZA==` is ordinary SAS/HMAC query padding, not a version pin.
        line = "requests @ https://h.test/dl?sig=YWJjZA=="
        self.assertEqual(unpinned_requirements(line + "\n"), [line])

    def test_bypass_vcs_direct_reference(self):
        line = "requests @ git+https://github.com/e/r@main#s==1"
        self.assertEqual(unpinned_requirements(line + "\n"), [line])

    def test_bypass_extra_index_url_with_equals_in_query(self):
        # Adding a resolution source is a dependency-confusion primitive; the
        # `==` in the query string must not read as a pin.
        line = "--extra-index-url https://h.test/simple?t=YQ=="
        self.assertEqual(unpinned_requirements(line + "\n"), [line])

    def test_bypass_index_url_is_reported(self):
        line = "--index-url https://h.test/simple"
        self.assertEqual(unpinned_requirements(line + "\n"), [line])

    def test_bypass_environment_variable_version(self):
        # pip expands `${VAR}`, handing version choice to the job environment.
        self.assertEqual(
            unpinned_requirements("pytest==${PYTEST_VER}\n"), ["pytest==${PYTEST_VER}"]
        )

    def test_unknown_option_is_reported_not_silently_accepted(self):
        # Direction check on the SAFE-set enumeration: an option nobody thought
        # about must fail loudly rather than pass.
        self.assertEqual(
            unpinned_requirements("--some-future-flag x\n"), ["--some-future-flag x"]
        )


class TestWorkflowManifestScan(unittest.TestCase):
    def test_at_least_one_workflow_installs_a_manifest(self):
        # Canary: if the `-r` scan finds nothing, the cross-check above is
        # vacuous and could not notice an unchecked manifest.
        self.assertTrue(
            workflow_installed_manifests(),
            "no `-r <requirements>` install found in any workflow — the "
            "workflow/manifest cross-check has become vacuous",
        )

    def test_commented_out_install_is_not_picked_up(self):
        for raw in (
            "        # pip install -r legacy/requirements.txt",
            "        pip install -q pytest  # -r legacy/requirements.txt",
        ):
            line = raw if raw.lstrip().startswith("#") else strip_inline_comment(raw)
            hits = [] if raw.lstrip().startswith("#") else _INSTALL_R_RE.findall(line)
            self.assertEqual(hits, [], raw)


if __name__ == "__main__":
    unittest.main()
