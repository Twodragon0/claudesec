"""
Regression guard: the npm CLI self-upgrade in the two OIDC/provenance workflows
must PIN the trusted-publishing floor (>= 11.5.1), never a bare `npm@latest`.

WHY THIS GUARD EXISTS
---------------------
OIDC tokenless `npm publish --provenance` requires **npm >= 11.5.1**, but Node 22
(the pinned runtime) bundles npm 10.x — so both workflows self-upgrade npm before
they need it:

- `.github/workflows/npm-publish.yml`    — the publish (needs npm for OIDC).
- `.github/workflows/provenance-verify.yml` — the published-artifact monitor
  (needs npm for `npm audit signatures` + provenance verification).

`npm install -g npm@latest` *happens* to satisfy the floor today, but it makes
the requirement INVISIBLE: nothing in the config states that 11.5.1 is the line
below which OIDC trusted publishing breaks. Dependabot cannot help here — the
npm CLI is a runner binary installed by a shell command, not a `package.json`
dependency, so there is no manifest surface for it to bump or flag. The floor is
therefore made explicit (`npm@'>=11.5.1'`) and asserted here: the version-shaped
pin is the visible record of the OIDC requirement, and this guard fails loudly if
a future edit drops it back to `@latest` (silently losing the documented floor).

DIRECTION
---------
Floor pin: the upgrade line must reference the `11.5.1` floor and must NOT be a
bare `npm@latest`. Removing the explicit version / reverting to `@latest` trips
it, and so does pinning BELOW the floor.

Ratcheting the floor UP is a PAIRED EDIT, not a free pass: `FLOOR` here is the
documented record of the OIDC requirement, so bumping the workflow to
`npm@'>=12.0.0'` without bumping `FLOOR` fails. That is deliberate — the version
in the workflow and the version this guard claims is required must never drift
apart silently, and the paired diff is the reviewable artifact. (An earlier
docstring claimed ratcheting up "stays green"; it never did — `assertIn(FLOOR)`
cannot see `>=12.0.0`. The behaviour was right and the documentation was wrong.)

COMMENT EVASION (ADR-001 §1)
----------------------------
The floor token is matched on the line with its trailing shell comment STRIPPED,
not on the raw line. Whole-line `#` stripping alone was not enough and the gap
was live: `npm install -g npm@'>=10.0.0'  # OIDC floor is 11.5.1` is not
`npm@latest` and does contain `11.5.1`, so the pin could be dropped a full major
below the OIDC floor with this guard green — the publish would then fail at
runtime with no config-level warning. Stripping happens BEFORE matching (the
ordering `test_ci_strip_before_match.py` enforces), so an upgrade command that
survives only inside a comment cannot satisfy the canary either.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.

OWASP A08 (Software & Data Integrity Failures); NIST SSDF (SP 800-218) PW.4.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import non_comment_lines, strip_inline_comment_sh  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Workflows whose npm self-upgrade gates an OIDC / provenance operation.
OIDC_WORKFLOWS = ("npm-publish.yml", "provenance-verify.yml")

# Documented OIDC trusted-publishing floor (npm-publish.yml header).
FLOOR = "11.5.1"

# A global npm self-upgrade: `npm install -g npm...` / `npm i -g npm`.
_UPGRADE_RE = re.compile(r"\bnpm\s+(?:install|i)\s+-g\s+npm\b")


def _upgrade_lines(text: str) -> list:
    """npm self-upgrade run lines, COMMENT-FREE: whole-line `#` comments are
    dropped and each surviving line has its trailing shell comment removed
    BEFORE the upgrade pattern is matched.

    Both directions of the ordering matter. Stripping first means a commented-out
    `# npm install -g npm@'>=11.5.1'` cannot satisfy the canary. Returning the
    stripped line means a floor quoted only in a trailing comment cannot satisfy
    the pin check — the live false negative documented in the module header.

    The SHELL stripper (not the YAML/whitespace one) is correct here: these are
    `run:` command lines, and bash starts a comment after `;`/`&&` with no
    intervening space (`npm i -g npm@latest;#>=11.5.1`)."""
    return [
        stripped
        for stripped in (strip_inline_comment_sh(ln) for ln in non_comment_lines(text))
        if _UPGRADE_RE.search(stripped)
    ]


def floor_violations(text: str) -> list:
    """Reasons `text`'s npm self-upgrade fails to pin the OIDC floor; empty when
    it is pinned correctly.

    Fails CLOSED on absence: a workflow with no self-upgrade line at all is a
    violation, not a vacuous pass — that is the shape a renamed or deleted step
    takes, and it is exactly as broken as `@latest` (Node 22 ships npm 10.x)."""
    lines = _upgrade_lines(text)
    if not lines:
        return [
            "no `npm install -g npm` self-upgrade line found — Node 22 ships "
            "npm 10.x, which cannot do OIDC trusted publishing / provenance "
            f"verification (needs >= {FLOOR})"
        ]
    out = []
    for ln in lines:
        if re.search(r"npm@latest\b", ln):
            out.append(
                "npm self-upgrade uses `npm@latest`, which hides the OIDC "
                f"trusted-publishing floor. Pin it explicitly (`npm@'>={FLOOR}'`) "
                "so the requirement is visible + guarded — Dependabot cannot "
                f"track the runner npm binary: {ln.strip()}"
            )
        elif FLOOR not in ln:
            out.append(
                f"npm self-upgrade does not reference the OIDC floor `{FLOOR}`. "
                "The pin is the visible record that OIDC trusted publishing "
                f"breaks below npm {FLOOR}; keep `npm@'>={FLOOR}'`, and if you "
                "ratchet the floor up, update FLOOR in this guard in the same "
                f"PR: {ln.strip()}"
            )
    return out


class TestNpmOidcFloor(unittest.TestCase):
    def _text(self, name: str) -> str:
        path = WORKFLOWS_DIR / name
        self.assertTrue(path.is_file(), f"{path} not found")
        return path.read_text(encoding="utf-8")

    def test_each_oidc_workflow_has_an_upgrade_line(self):
        # Canary: if the upgrade step is renamed/removed, the pin assertions below
        # would pass vacuously. Fail loudly instead.
        for name in OIDC_WORKFLOWS:
            with self.subTest(workflow=name):
                self.assertTrue(
                    _upgrade_lines(self._text(name)),
                    f"{name}: no `npm install -g npm` self-upgrade line found — "
                    "Node 22 ships npm 10.x, which cannot do OIDC trusted "
                    "publishing / provenance verification (needs >= 11.5.1).",
                )

    def test_upgrade_pins_the_floor_not_latest(self):
        for name in OIDC_WORKFLOWS:
            with self.subTest(workflow=name):
                self.assertEqual(
                    floor_violations(self._text(name)),
                    [],
                    f"{name}: OIDC floor pin weakened.",
                )


class TestFloorDetectorMutation(unittest.TestCase):
    """Mutation self-tests: the detector must FIRE on each way the pin can be
    weakened, and stay QUIET on the real form. Without these, every assertion
    above only ever sees a passing workflow — a detector that returned `[]`
    unconditionally would look identical."""

    REAL = "        run: npm install -g npm@'>=11.5.1'\n"

    def test_quiet_on_the_real_pin(self):
        self.assertEqual(floor_violations(self.REAL), [])

    def test_fires_on_latest(self):
        out = floor_violations("        run: npm install -g npm@latest\n")
        self.assertTrue(out)
        self.assertIn("npm@latest", out[0])

    def test_fires_on_short_install_form(self):
        # `npm i -g npm@latest` is the same command; the matcher must see it.
        self.assertTrue(floor_violations("        run: npm i -g npm@latest\n"))

    def test_fires_on_pin_lowered_below_the_floor(self):
        self.assertTrue(floor_violations("        run: npm install -g npm@'>=10.0.0'\n"))

    def test_fires_when_the_upgrade_step_is_removed(self):
        # Fail-closed direction: no upgrade line at all is a violation, so a
        # renamed/deleted step cannot make the pin checks pass vacuously.
        self.assertTrue(floor_violations("jobs:\n  publish:\n    steps: []\n"))

    def test_trailing_comment_cannot_satisfy_the_floor(self):
        # THE live false negative this hardening closes: the pin is a full major
        # below the OIDC floor, but the floor string survives in the comment.
        # A whole-line-only stripper reported this clean.
        mutant = "        run: npm install -g npm@'>=10.0.0'  # OIDC floor is 11.5.1\n"
        self.assertTrue(
            floor_violations(mutant),
            "a floor quoted only in a trailing comment must not satisfy the pin",
        )

    def test_metachar_adjacent_comment_cannot_satisfy_the_floor(self):
        # bash needs no space before `#` after a command separator, so the
        # whitespace-only stripper misses this one too.
        mutant = "        run: npm install -g npm@latest;#>=11.5.1\n"
        self.assertTrue(floor_violations(mutant))

    def test_commented_out_upgrade_line_does_not_satisfy_the_canary(self):
        # Strip-before-match: the only `npm install -g npm` in this text is
        # inside a comment, so the detector must report the ABSENCE, not accept
        # the commented floor.
        mutant = "        # run: npm install -g npm@'>=11.5.1'\n        run: npm ci\n"
        out = floor_violations(mutant)
        self.assertTrue(out)
        self.assertIn("no `npm install -g npm`", out[0])

    def test_hash_inside_the_pin_is_not_treated_as_a_comment(self):
        # No-false-alarm direction for the stripper: a `#` that is not at a bash
        # word boundary must survive, so a legitimate line is never truncated
        # into a phantom violation.
        self.assertEqual(
            floor_violations("        run: npm install -g npm@'>=11.5.1' --tag=x#y\n"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
