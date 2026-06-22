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
bare `npm@latest`. Ratcheting the floor UP (e.g. a future `>=12.0.0`) stays green;
removing the explicit version / reverting to `@latest` trips it.

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
from _ci_guard_util import non_comment_lines  # noqa: E402

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
    """npm self-upgrade run lines, with whole-line `#` comments dropped so a
    floor mentioned only in prose can never satisfy the pin check."""
    return [ln for ln in non_comment_lines(text) if _UPGRADE_RE.search(ln)]


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
            text = self._text(name)
            for ln in _upgrade_lines(text):
                with self.subTest(workflow=name, line=ln.strip()):
                    self.assertNotRegex(
                        ln,
                        r"npm@latest\b",
                        f"{name}: npm self-upgrade uses `npm@latest`, which hides "
                        "the OIDC trusted-publishing floor. Pin it explicitly "
                        f"(`npm@'>={FLOOR}'`) so the requirement is visible + "
                        "guarded — Dependabot cannot track the runner npm binary.",
                    )
                    self.assertIn(
                        FLOOR,
                        ln,
                        f"{name}: npm self-upgrade does not reference the OIDC "
                        f"floor `{FLOOR}`. The pin is the visible record that "
                        "OIDC trusted publishing breaks below npm 11.5.1; keep "
                        f"`npm@'>={FLOOR}'` (ratcheting the floor up is fine).",
                    )


if __name__ == "__main__":
    unittest.main()
