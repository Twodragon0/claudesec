"""
Guard: the workflow templates ClaudeSec INSTALLS into other people's repositories
are SHA-pinned to the same refs this repo runs; the ones it only illustrates say
out loud that they are not.

THE DECISION THIS CODIFIES (2026-08-11)
---------------------------------------
#415 brought `templates/` under the injection scan and deliberately left one
question open: the templates carry ~30 tag-pinned `uses:` refs while this repo
enforces 40-hex SHA pins on its own workflows. Widening the shared
`workflow_and_action_files()` enumerator would have settled it as a side effect
of a scanning change, which is the wrong way to decide a policy with a real
maintenance cost. Decided deliberately now, and the answer is neither
all-SHA nor all-tag, because the two halves of `templates/` are not the same
artifact:

- **INSTALLED** (`scripts/setup.sh` copies them into `$TARGET_DIR/.github/
  workflows/`): `codeql.yml`, `dependency-review.yml`. These become live
  workflows in someone else's repo, running with their token, without them
  choosing a single line. A mutable tag there is a supply-chain exposure WE
  created — a tag is repointable at attacker code (the 2025 `tj-actions/
  changed-files` compromise is the canonical case), so these are SHA-pinned.
- **EXAMPLE** (`prowler.yml`, `sbom.yml`, `scorecard.yml`,
  `security-scan-suite.yml`): documented copy-me starting points. They stay
  tag-pinned and carry a note telling the reader to pin before adopting.

The asymmetry is not aesthetic, it is about who can keep a pin FRESH. Dependabot's
`github-actions` ecosystem scans `.github/workflows/` (and `.github/actions/`),
never an arbitrary directory, so nothing bumps a SHA sitting in `templates/`. The
evidence is in the repo's own history: `templates/codeql.yml` and
`templates/dependency-review.yml` carried a hand-written
`actions/checkout@b4ffde65…  # v4.1.1` while this repo's workflows moved to
`# v7.0.1` — **three major versions of silent rot**, shipped to every user of
`setup.sh`. A stale pin presented as security advice is worse than a visible tag.

So the installed half is pinned to the SHA THIS REPO ALREADY RUNS for the same
action, and `test_installed_template_pins_match_ours` fails when the two drift.
That makes our own Dependabot the upstream freshness signal (it bumps
`.github/workflows/`, this guard then demands the templates follow), and the
user's own Dependabot is the downstream one: `setup.sh` installs
`templates/dependabot.yml` (whose `github-actions` ecosystem bumps SHA pins and
their `# vX.Y.Z` comments) unless the repo already has a config, in which case
they already have an updater. Either way the pins keep moving after install, and
no pin in this repo depends on a human remembering.

The example half gets no pin it cannot keep: those actions (`aquasecurity/
trivy-action`, `anchore/*`, `sigstore/cosign-installer`, `ossf/scorecard-action`,
`gitleaks/gitleaks-action`, `aws-actions/configure-aws-credentials`, …) are not
run by this repo at all, so there is no signal to mirror and a SHA there would
rot exactly like the checkout pin did.

The two composite actions `setup.sh` also installs
(`.github/actions/{datadog-ci-collect,token-expiry-gate}/action.yml`) need
nothing here — they live under `.github/actions/`, so
`test_ci_gate_topology.test_every_uses_is_sha_pinned` already covers them.

DIRECTION
---------
Pins are exact (`==`): reintroducing a tag in an installed template, or letting
its SHA diverge from ours, trips this. The example half is a presence check on
the note. The INSTALLED SET IS DERIVED from `scripts/setup.sh`, not listed here —
a third template added to that copy list is covered the day it lands rather than
after the next audit (the generalisation lesson from #407/#413), and a
`setup.sh` this guard can no longer parse fails the canary loudly instead of
scanning an empty set.

OWASP CICD-SEC-3 (Dependency Chain Abuse); NIST SSDF (SP 800-218) PW.4.
"""

import re
import sys
import unittest
from glob import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    REPO_ROOT,
    apply_mutation,
    assert_disables,
    explicit_key_lines,
    join_continuations,
    non_comment_lines,
    uses_refs,
    workflow_and_action_files,
)

TEMPLATE_DIR = REPO_ROOT / "templates"
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup.sh"

# The sentence every EXAMPLE template must carry. Checked as a substring so the
# surrounding wording can be edited freely; if this phrase is reworded, update it
# here in the same commit.
EXAMPLE_PIN_NOTE = "Pin each to a 40-hex commit SHA when you adopt it"

# `owner/repo[/subpath]@ref` — the subpath is dropped when identifying the action
# REPO, because `github/codeql-action/init` and `.../upload-sarif` are one
# repository at one commit, which is what makes the parity check possible at all.
_REF_RE = re.compile(r"^(?P<repo>[^@/\s]+/[^@/\s]+)(?P<sub>/[^@\s]*)?@(?P<ref>\S+)$")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# `cp "$CLAUDESEC_DIR/templates/<name>" "$TARGET_DIR/.github/workflows/"`
_INSTALL_RE = re.compile(
    r"""cp\s+(?:-\S+\s+)*["']?\$\{?CLAUDESEC_DIR\}?/templates/(?P<name>[A-Za-z0-9._-]+)["']?"""
    r"""\s+["']?\$\{?TARGET_DIR\}?/\.github/workflows/?["']?"""
)


def installed_workflow_templates(setup_text: str) -> list:
    """Template file names `scripts/setup.sh` copies into a target repo's
    `.github/workflows/`, sorted.

    Derived rather than listed so the policy follows the installer. Comment lines
    are dropped first — a commented-out `cp` installs nothing, and treating it as
    if it did would demand pins on a file nobody ships — and backslash
    continuations are joined, so a wrapped `cp` is still one command."""
    text = join_continuations("\n".join(non_comment_lines(setup_text)))
    return sorted({m.group("name") for m in _INSTALL_RE.finditer(text)})


def _pinnable(ref: str) -> bool:
    """Local composite actions and docker images cannot carry a commit SHA."""
    return not (ref.startswith("./") or ref.startswith("docker://"))


def unpinned_uses(text: str) -> list:
    """Every `uses:` in `text` that is not pinned to a 40-hex commit SHA.

    Fails CLOSED on the `? uses` explicit-key form: it declares the same mapping
    key while the substring `uses:` never appears, so no line matcher can reach
    the value (ADR-001 §5, the shape that defeated eight guards in the 2026-08-06
    sweep)."""
    out = []
    for lineno, ref in uses_refs(text):
        if not _pinnable(ref):
            continue
        m = _REF_RE.match(ref)
        if not m or not _SHA_RE.match(m.group("ref")):
            out.append(f"line {lineno}: {ref}")
    out += [
        f"unscannable `? uses` explicit-key form: {ln}"
        for ln in explicit_key_lines(text, "uses")
    ]
    return out


def our_action_shas() -> dict:
    """`{owner/repo: {sha, ...}}` for every action this repo's own workflows and
    composite actions run. The upstream freshness signal Dependabot maintains."""
    out = {}
    for path in workflow_and_action_files():
        for _, ref in uses_refs(Path(path).read_text(encoding="utf-8")):
            m = _REF_RE.match(ref)
            if m and _SHA_RE.match(m.group("ref")):
                out.setdefault(m.group("repo"), set()).add(m.group("ref"))
    return out


def pin_drift(text: str, ours: dict) -> list:
    """Reasons an installed template's pins no longer match what this repo runs.

    Only actions present in BOTH are compared — an action the template uses and
    we do not has no signal to mirror, and inventing one would be a pin nobody
    can keep fresh (the whole reason the example half stays tag-pinned).

    Reports our own inconsistency too: if this repo runs two different SHAs for
    one action repo, there is no single ref for the template to mirror and the
    check refuses to pick one."""
    out = []
    for lineno, ref in uses_refs(text):
        m = _REF_RE.match(ref) if _pinnable(ref) else None
        if not m:
            continue
        repo, sha = m.group("repo"), m.group("ref")
        mine = ours.get(repo)
        if not mine:
            continue
        if len(mine) > 1:
            out.append(
                f"line {lineno}: this repo runs {repo} at {len(mine)} different SHAs "
                f"({sorted(mine)}) — make them consistent; the template cannot mirror both"
            )
        elif sha not in mine:
            out.append(
                f"line {lineno}: {repo} pinned at {sha} but this repo runs "
                f"{sorted(mine)[0]} — an installed template must mirror the ref "
                "Dependabot keeps fresh here"
            )
    return out


def missing_example_note(text: str) -> list:
    """Non-empty when `text` ships a tag-pinned `uses:` without the note telling
    the reader to pin it before adopting."""
    tag_pinned = [f"line {n}: {r}" for n, r in uses_refs(text) if _pinnable(r)
                  and not (_REF_RE.match(r) and _SHA_RE.match(_REF_RE.match(r).group("ref")))]
    if tag_pinned and EXAMPLE_PIN_NOTE not in text:
        return tag_pinned
    return []


def _template_files() -> list:
    out = []
    for pattern in ("*.yml", "*.yaml"):
        out += glob(str(TEMPLATE_DIR / pattern))
    return sorted(out)


class TestTemplatePinPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup_text = (
            SETUP_SCRIPT.read_text(encoding="utf-8") if SETUP_SCRIPT.is_file() else ""
        )
        cls.installed = installed_workflow_templates(cls.setup_text)
        cls.templates = {Path(p).name: Path(p).read_text(encoding="utf-8") for p in _template_files()}

    def test_setup_script_exists(self):
        self.assertTrue(SETUP_SCRIPT.is_file(), f"{SETUP_SCRIPT} not found — path assumption broke")

    def test_installed_set_is_derived_and_non_empty(self):
        # Vacuity canary. If `setup.sh` stops matching (renamed variables, a loop
        # instead of `cp`), this guard would scan NOTHING and pass for free. Fail
        # loudly and re-derive the parse by hand instead.
        self.assertTrue(
            self.installed,
            f"no `cp .../templates/X {SETUP_SCRIPT.name} -> .github/workflows/` lines "
            "parsed — the installer changed shape, so this guard is scanning an "
            "empty set. Re-derive `_INSTALL_RE`; do NOT leave it silently vacuous.",
        )
        for name in self.installed:
            self.assertIn(
                name, self.templates,
                f"setup.sh installs templates/{name} but no such template exists",
            )

    def test_installed_templates_are_sha_pinned(self):
        violations = []
        for name in self.installed:
            violations += [f"{name} {v}" for v in unpinned_uses(self.templates[name])]
        self.assertEqual(
            violations,
            [],
            "an INSTALLED template carries a non-SHA `uses:`. setup.sh copies these "
            "into a user's .github/workflows/, so a mutable tag is a supply-chain "
            "exposure we shipped them (OWASP CICD-SEC-3):\n  " + "\n  ".join(violations),
        )

    def test_installed_template_pins_match_ours(self):
        ours = our_action_shas()
        self.assertTrue(ours, "no SHA-pinned actions found in this repo — path assumption broke")
        drift = []
        for name in self.installed:
            drift += [f"{name} {d}" for d in pin_drift(self.templates[name], ours)]
        self.assertEqual(
            drift,
            [],
            "an installed template's pin no longer matches the ref this repo runs. "
            "Dependabot cannot see templates/, so this parity IS the freshness "
            "mechanism — `templates/codeql.yml` sat three major versions behind on "
            "actions/checkout before it existed:\n  " + "\n  ".join(drift),
        )

    def test_example_templates_declare_they_are_not_pinned(self):
        missing = []
        for name, text in self.templates.items():
            if name in self.installed:
                continue
            hits = missing_example_note(text)
            if hits:
                missing.append(f"{name}: {len(hits)} tag-pinned uses, no pin note")
        self.assertEqual(
            missing,
            [],
            "an EXAMPLE template ships tag-pinned `uses:` refs without telling the "
            f"reader to pin them. Add the note containing {EXAMPLE_PIN_NOTE!r}, or "
            "SHA-pin the file:\n  " + "\n  ".join(missing),
        )

    def test_the_policy_split_is_real(self):
        # Both halves must be non-empty, or one of the two rules above is
        # asserting over nothing while reading as if it enforced the policy.
        examples = [n for n in self.templates if n not in self.installed and uses_refs(self.templates[n])]
        self.assertTrue(self.installed, "no installed templates — see the canary above")
        self.assertTrue(
            examples,
            "no example templates with `uses:` refs — `test_example_templates_"
            "declare_they_are_not_pinned` is vacuous; delete it or fix the glob",
        )


class TestPinPolicyDetectors(unittest.TestCase):
    """Mutation self-tests. Every mutation is applied to a COPY held in memory;
    `templates/` and `scripts/setup.sh` are never written to."""

    @classmethod
    def setUpClass(cls):
        cls.setup_text = SETUP_SCRIPT.read_text(encoding="utf-8")
        cls.installed_name = installed_workflow_templates(cls.setup_text)[0]
        cls.installed_text = (TEMPLATE_DIR / cls.installed_name).read_text(encoding="utf-8")
        cls.example_text = (TEMPLATE_DIR / "scorecard.yml").read_text(encoding="utf-8")
        cls.ours = our_action_shas()

    def _first_sha_ref(self):
        for _, ref in uses_refs(self.installed_text):
            m = _REF_RE.match(ref)
            if m and _SHA_RE.match(m.group("ref")):
                return ref
        raise AssertionError("no SHA-pinned ref in the installed template to mutate")

    def test_a_tag_reintroduced_is_caught(self):
        ref = self._first_sha_ref()
        repo = _REF_RE.match(ref).group("repo")
        assert_disables(
            unpinned_uses,
            self.installed_text,
            apply_mutation(self.installed_text, ref, f"{repo}@v4"),
            "tag reintroduced in an installed template",
        )

    def test_a_quoted_key_does_not_hide_a_tag(self):
        # `- "uses": x` resolves identically to the bare form (#391/#393/#394).
        ref = self._first_sha_ref()
        repo = _REF_RE.match(ref).group("repo")
        assert_disables(
            unpinned_uses,
            self.installed_text,
            apply_mutation(self.installed_text, f"uses: {ref}", f'"uses": {repo}@main'),
            "quoted `uses:` key hiding a branch ref",
        )

    def test_a_quoted_value_does_not_hide_a_tag(self):
        # `uses: "actions/checkout@v4"` is ordinary YAML. A matcher whose value
        # class excludes the quote character reads no ref at all and reports
        # clean — an absence that looks exactly like compliance.
        ref = self._first_sha_ref()
        repo = _REF_RE.match(ref).group("repo")
        assert_disables(
            unpinned_uses,
            self.installed_text,
            apply_mutation(self.installed_text, f"uses: {ref}", f'uses: "{repo}@v4"'),
            "quoted VALUE hiding a tag ref",
        )

    def test_the_explicit_key_form_fails_closed(self):
        ref = self._first_sha_ref()
        repo = _REF_RE.match(ref).group("repo")
        assert_disables(
            unpinned_uses,
            self.installed_text,
            apply_mutation(
                self.installed_text, f"uses: {ref}", f"? uses\n        : {repo}@main"
            ),
            "`? uses` explicit-key form is unscannable, so it must fail closed",
        )

    def test_a_tag_surviving_only_in_a_comment_is_not_flagged(self):
        # Direction: the guard must not fire on prose. A commented example ref is
        # documentation, not an executed step.
        mutant = apply_mutation(
            self.installed_text,
            "jobs:",
            "# example only: uses: actions/checkout@v4\njobs:",
        )
        self.assertEqual(unpinned_uses(mutant), [])

    def test_pin_drift_from_our_own_ref_is_caught(self):
        ref = self._first_sha_ref()
        m = _REF_RE.match(ref)
        stale = "0" * 40
        assert_disables(
            lambda t: pin_drift(t, self.ours),
            self.installed_text,
            apply_mutation(self.installed_text, ref, f"{m.group('repo')}{m.group('sub') or ''}@{stale}"),
            "installed template pinned to a SHA this repo does not run",
        )

    def test_drift_ignores_actions_this_repo_does_not_run(self):
        # An action with no upstream signal must not be compared against
        # nothing — that is the false alarm that would push us into inventing
        # pins we cannot keep fresh.
        self.assertEqual(
            pin_drift("      - uses: some/unused-action@" + "a" * 40 + "\n", self.ours), []
        )

    def test_example_note_removal_is_caught(self):
        assert_disables(
            missing_example_note,
            self.example_text,
            apply_mutation(self.example_text, EXAMPLE_PIN_NOTE, "Pin it, maybe"),
            "the EXAMPLE pin note was reworded away",
        )

    def test_a_new_installed_template_is_picked_up_automatically(self):
        # The generalisation this guard is built on: adding a template to the
        # installer's copy list enrols it in the SHA rule with no edit here.
        mutant = apply_mutation(
            self.setup_text,
            'cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"',
            'cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"\n'
            'cp "$CLAUDESEC_DIR/templates/scorecard.yml" "$TARGET_DIR/.github/workflows/"',
        )
        self.assertIn("scorecard.yml", installed_workflow_templates(mutant))
        # …and it would immediately fail the SHA rule, which is the point.
        self.assertNotEqual(unpinned_uses(self.example_text), [])

    def test_a_commented_out_install_is_not_counted(self):
        mutant = apply_mutation(
            self.setup_text,
            'cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"',
            '# cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"',
        )
        self.assertNotIn("codeql.yml", installed_workflow_templates(mutant))

    def test_a_wrapped_install_command_is_still_counted(self):
        # A `cp` split over a backslash continuation is one command; a per-line
        # scan would miss it and silently drop the file from the policy.
        wrapped = (
            'cp "$CLAUDESEC_DIR/templates/wrapped.yml" \\\n'
            '  "$TARGET_DIR/.github/workflows/"\n'
        )
        self.assertEqual(installed_workflow_templates(wrapped), ["wrapped.yml"])


if __name__ == "__main__":
    unittest.main()
