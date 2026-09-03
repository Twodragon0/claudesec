"""
Regression guard: a `templates/` workflow must not ship a dependency the adopter
cannot satisfy.

`templates/` is the one directory whose contents run in OTHER people's
repositories. A defect here is invisible in this repo's CI — the file never
executes — and it propagates. That is the #415/#417 class, and it is why
`workflow_and_action_files()` (which covers `.github/workflows/` plus composite
actions, NOT `templates/`) is not enough on its own.

TWO INVARIANTS, both found 2026-09-03.

1. **`uses: ./…` must resolve in the ADOPTER's repo, not just ours.**
   `templates/prowler.yml` and `templates/security-scan-suite.yml` reference
   `./.github/actions/token-expiry-gate` and `./.github/actions/datadog-ci-collect`.
   `uses: ./…` resolves inside the repository running the workflow, so an
   adopter without those paths gets `Can't find 'action.yml'` immediately.
   Both headers say *"NOT installed by scripts/setup.sh; copy it deliberately"*,
   which makes hand-copying the documented path — and copying the workflow alone
   is not enough. `setup.sh` does provision all three paths (it `mkdir -p`s both
   action directories and copies `scripts/token-expiry-gate.py`), so the
   invariant is: **every local-action ref in a template is a path the installer
   actually provisions.** Add a ref without adding it to the installer and this
   fails.

2. **`vars.` names cannot start with `GITHUB_`.** GitHub rejects configuration
   variables with that prefix, so `${{ vars.GITHUB_TOKEN_EXPIRES_AT }}` was
   permanently the empty string — a shipped knob that could never work. It was
   harmless only by accident: `scripts/token-expiry-gate.py`'s
   `PROVIDER_ENV_KEYS["github"]` is the alias tuple
   `("GH_TOKEN_EXPIRES_AT", "GITHUB_TOKEN_EXPIRES_AT")` and `resolve_expiry_env`
   returns the FIRST non-empty, so the settable sibling one line above already
   fed the same provider. The aliases in the script and the action's inputs are
   NOT the defect and stay — an env var or secret of that name is legal; only a
   `vars.` reference is not.

Direction: (1) existence + installer coverage; (2) forbidden-token presence. A
forbidden-token scan can only over-report (ADR-001 §1's exemption), but comments
are stripped anyway so the prose explaining the removal cannot trip it.

stdlib-only (`re`, `subprocess`, `pathlib`) — no PyYAML, no `scanner/lib` import.

OWASP CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-3 (Dependency Chain
Abuse); NIST SSDF PO.3.
"""

import re
import subprocess
import unittest
from pathlib import Path

from _ci_guard_util import strip_comment_lines

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "templates"
INSTALLER = REPO_ROOT / "scripts" / "setup.sh"

# `uses: ./<path>` — a LOCAL action reference, resolved in the running repo.
_LOCAL_USES_RE = re.compile(r"^\s*uses:\s*\./(?P<path>[^\s#]+)", re.M)
# A `vars.` reference whose name starts with GITHUB_ (case-insensitive, as the
# GitHub restriction is).
_GITHUB_VAR_RE = re.compile(r"vars\.GITHUB_[A-Z0-9_]*", re.I)


def workflow_like_files():
    """Tracked `*.yml`/`*.yaml` under `templates/` and `.github/workflows/`.

    `git ls-files`, never a filesystem walk: a gitignored local file would make
    this red locally and green in CI
    ([[project-locale-default-encoding-class]])."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.yml", "*.yaml"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return sorted(
        rel for rel in filter(None, out.split("\0"))
        if rel.startswith((".github/workflows/", "templates/"))
    )


def local_action_refs(text):
    """Every `uses: ./<path>` in `text`, comment-stripped."""
    return sorted(set(_LOCAL_USES_RE.findall(strip_comment_lines(text))))


def github_prefixed_vars(text):
    """Every `vars.GITHUB_*` reference in `text`, comment-stripped."""
    return sorted(set(_GITHUB_VAR_RE.findall(strip_comment_lines(text))))


def provisioning_problems(rel, text, installer):
    """Local-action refs in `text` that an adopter could not satisfy.

    A pure function so the mutation self-test can drive the SAME code the real
    assertion runs, rather than a re-implementation of it (#504)."""
    problems = []
    for ref in local_action_refs(text):
        # An action DIRECTORY is referenced; Actions resolves `action.yml`
        # (or `.yaml`) inside it. A direct file path is accepted too.
        candidates = (
            REPO_ROOT / ref / "action.yml",
            REPO_ROOT / ref / "action.yaml",
            REPO_ROOT / ref,
        )
        if not any(c.is_file() for c in candidates):
            problems.append(f"{rel}: `uses: ./{ref}` does not exist here")
        elif ref not in installer:
            problems.append(
                f"{rel}: `uses: ./{ref}` is never copied by {INSTALLER.name}"
            )
    return problems


class TestInputsAreLocatable(unittest.TestCase):
    """Canaries. Both assertions below are vacuous on an empty file list."""

    def test_installer_exists(self):
        self.assertTrue(INSTALLER.is_file(), f"{INSTALLER} not found")

    def test_templates_are_found(self):
        templates = [f for f in workflow_like_files() if f.startswith("templates/")]
        self.assertGreaterEqual(
            len(templates), 5,
            f"the template enumeration collapsed — found {templates}",
        )

    def test_at_least_one_local_action_ref_exists_to_check(self):
        """If this hits zero the invariant-1 test below proves nothing."""
        total = sum(
            len(local_action_refs((REPO_ROOT / f).read_text(encoding="utf-8")))
            for f in workflow_like_files() if f.startswith("templates/")
        )
        self.assertGreater(
            total, 0,
            "no `uses: ./…` refs found in templates/. If they were all removed "
            "deliberately, drop this guard; otherwise the matcher broke.",
        )

    def test_the_forbidden_var_detector_fires(self):
        self.assertEqual(
            github_prefixed_vars("x: ${{ vars.GITHUB_TOKEN_EXPIRES_AT || '' }}"),
            ["vars.GITHUB_TOKEN_EXPIRES_AT"],
        )

    def test_the_forbidden_var_detector_ignores_legitimate_names(self):
        """`vars.GH_*` and the `github` CONTEXT are both fine."""
        self.assertEqual(
            github_prefixed_vars(
                "a: ${{ vars.GH_TOKEN_EXPIRES_AT }}\n"
                "b: ${{ github.run_id }}\n"
                "c: ${{ secrets.GITHUB_TOKEN }}\n"
            ),
            [],
        )


class TestLocalActionRefsAreProvisioned(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = INSTALLER.read_text(encoding="utf-8")

    def test_every_template_local_action_exists_and_is_installed(self):
        problems = []
        for rel in workflow_like_files():
            if not rel.startswith("templates/"):
                continue
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            problems += provisioning_problems(rel, text, self.installer)
        self.assertEqual(
            problems, [],
            "template(s) reference a local action the adopter will not have. "
            "`uses: ./…` resolves in THEIR repo, so a missing path fails the run "
            "with `Can't find 'action.yml'` — and these templates document "
            "hand-copying as the adoption path.\n  " + "\n  ".join(problems)
            + "\nFix: copy the path in scripts/setup.sh (with its `mkdir -p`), "
            "or stop referencing it from the template.",
        )


class TestNoGithubPrefixedVars(unittest.TestCase):
    def test_no_workflow_references_a_github_prefixed_var(self):
        violations = []
        for rel in workflow_like_files():
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            for hit in github_prefixed_vars(text):
                violations.append(f"{rel}: {hit}")
        self.assertEqual(
            violations, [],
            "GitHub rejects configuration variables whose name starts with "
            "`GITHUB_`, so these references are permanently the empty string — a "
            "shipped knob that cannot work.\n  " + "\n  ".join(violations)
            + "\nUse an unprefixed name (`vars.GH_…`). Note this forbids only "
            "`vars.`: `secrets.GITHUB_TOKEN` and the `github` context are legal, "
            "and so is an `env:` var of that name.",
        )


class TestGuardIsNonVacuous(unittest.TestCase):
    """Mutations drive the REAL detectors against REAL files (#504)."""

    def test_reintroducing_the_dead_knob_is_caught(self):
        target = TEMPLATE_DIR / "prowler.yml"
        text = target.read_text(encoding="utf-8")
        anchor = "          gh-token-expires-at: ${{ vars.GH_TOKEN_EXPIRES_AT || '' }}\n"
        self.assertEqual(
            text.count(anchor), 1,
            f"mutation fixture is stale: anchor not found once in {target.name}",
        )
        mutant = text.replace(
            anchor,
            anchor + "          github-token-expires-at: ${{ vars.GITHUB_TOKEN_EXPIRES_AT || '' }}\n",
            1,
        )
        self.assertEqual(
            github_prefixed_vars(mutant), ["vars.GITHUB_TOKEN_EXPIRES_AT"],
            "the detector did NOT fire on the reintroduced knob — check that "
            "possibility FIRST before assuming a gap",
        )

    def test_an_uninstalled_local_action_is_caught(self):
        """Drives `provisioning_problems`, the function the real assertion uses.

        Two synthetic refs because the two halves fail for different reasons and
        a single case cannot tell them apart: one path EXISTS here but is not in
        the installer, the other does not exist at all. Synthetic on purpose —
        every ref on disk today is installed, which is what the real test
        asserts, so the mutant has to introduce the violation."""
        installer = INSTALLER.read_text(encoding="utf-8")

        existing_but_uninstalled = "scanner/lib"          # a real dir, no action.yml
        missing_entirely = ".github/actions/not-a-real-action"
        self.assertNotIn(existing_but_uninstalled, installer,
                         "fixture stale: the installer now mentions this path")

        for ref, expect in ((existing_but_uninstalled, "does not exist here"),
                            (missing_entirely, "does not exist here")):
            found = provisioning_problems(
                "templates/fake.yml", f"      uses: ./{ref}\n", installer
            )
            self.assertEqual(len(found), 1, f"{ref}: expected one problem, got {found}")
            self.assertIn(expect, found[0], f"{ref}: wrong reason -> {found[0]}")

        # And the installer-coverage half specifically: a path that DOES resolve
        # to an action file but is absent from the installer.
        real_action = ".github/actions/token-expiry-gate"
        self.assertTrue((REPO_ROOT / real_action / "action.yml").is_file())
        found = provisioning_problems(
            "templates/fake.yml", f"      uses: ./{real_action}\n",
            "installer that copies nothing",
        )
        self.assertEqual(len(found), 1, f"expected one problem, got {found}")
        self.assertIn("is never copied by", found[0])

    def test_todays_templates_pass_both_invariants(self):
        """Negative control. Without it the mutations above prove nothing."""
        for rel in workflow_like_files():
            text = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertEqual(
                github_prefixed_vars(text), [], f"{rel} already violates"
            )


if __name__ == "__main__":
    unittest.main()
