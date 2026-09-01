"""
Regression guard: the nightly DAST tracker's ISSUE BODY must keep being rewritten
from the newest run.

WHAT THIS PROTECTS, AND WHY IT IS NOT COSMETIC
----------------------------------------------
`zaproxy/action-full-scan` opens one issue titled by its `issue_title:` input and
on every later run APPENDS a comment carrying only the delta ("New Alerts" /
"Resolved Alerts"). It never rewrites the body. So the body is a frozen snapshot
of the first run that found anything — and the body is what a reader sees first.

Measured on issue #498: the body, dated 2026-08-26, listed `CSP: style-src
unsafe-inline` plus missing COEP/COOP/CORP as live, while that same issue's
2026-08-28 comment reported all four under "Resolved Alerts" — #500 had fixed
them on 08-27. Four days of already-fixed MEDIUM findings presented as current.

That is the mirror of the class the rest of this suite guards. Green-while-
defeated hides a real problem behind a reassuring surface; RED-WHILE-FIXED hides
a real all-clear behind an alarming one. Both cost the same thing: a reader who
learns the surface is unreliable stops reading it. A tracker that cries wolf gets
muted, and a muted DAST tracker is how the nightly went 42 nights unwatched
(#399/#497).

`dast-full-scan.yml`'s "Refresh ZAP tracker body" step replaces the body every
run. Every assertion below pins a way that step can go silently inert — each one
produces no error, no red job, and no visible change, which is why none of them
would be caught by the workflow simply running.

SEMANTICS, and the discipline they follow
-----------------------------------------
Every check is scoped to the refresh step's OWN block via `step_blocks`, then
asserted as a COUNT where a second copy could shadow the first. A whole-file scan
would prove `issues.update` exists SOMEWHERE in a 240-line workflow that already
contains a second `github-script` step doing issue work — presence, not
attribution. See `feedback-presence-vs-attribution`: that exact shape passed 1181
guards in #504.

stdlib-only (regex + the shared block scopers, no PyYAML — absent from
requirements-ci.txt). No network, no subprocess. Passes under pytest (the CI
runner) and `python3 -m unittest`. Does not import scanner/lib, so it never moves
the measured coverage gate.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SP 800-115 §6 (reporting is
part of the assessment, not an afterthought).
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    key_column,
    keys_at_column,
    step_blocks,
    yaml_key_pattern,
)

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dast-full-scan.yml"

REFRESH_STEP_NAME = "Refresh ZAP tracker body"
ZAP_STEP_NAME = "ZAP Full Scan"


def _step_named(text, name):
    """The `step_blocks` entry whose own `name:` is `name`, or None.

    Matched on the step's own key line rather than anywhere in the block, so a
    step that merely MENTIONS another step's name (this workflow's comments do)
    is not mistaken for it.
    """
    pat = re.compile(rf"(?m)^\s*-\s+{yaml_key_pattern('name')}:\s*{re.escape(name)}\s*$")
    for block in step_blocks(text):
        if pat.search(block):
            return block
    return None


def _step_keys(block):
    """The step's OWN top-level keys, at its derived column.

    Derived, never hardcoded: a `steps:` list may legally sit at its parent key's
    indent, and that cosmetic dedent walks every key out from under a fixed
    anchor with the suite green.
    """
    col = key_column(block)
    return [] if col is None else keys_at_column(block, col)


def _script_body(block):
    """The `script:` block scalar of a `github-script` step.

    Everything indented deeper than the `script:` key itself. Returns "" when the
    step has no `script:`, so callers must assert non-emptiness — an empty body
    satisfies every `assertNotIn` vacuously.
    """
    lines = block.splitlines()
    out, col = [], None
    for line in lines:
        if col is None:
            m = re.match(rf"^(\s*){yaml_key_pattern('script')}:\s*[|>][-+]?\s*$", line)
            if m:
                col = len(m.group(1))
            continue
        if not line.strip():
            out.append("")
            continue
        if (len(line) - len(line.lstrip())) <= col:
            break
        out.append(line)
    return "\n".join(out)


def _quoted_value(block, key):
    """The single- or double-quoted value assigned to `key:` in `block`."""
    m = re.search(
        rf"(?m)^\s*{yaml_key_pattern(key)}:\s*(?:\"([^\"]*)\"|'([^']*)')\s*$", block
    )
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def _js_const(script, name):
    """The string literal assigned to `const <name> = '...'` in a script body."""
    m = re.search(
        rf"(?m)^\s*const\s+{re.escape(name)}\s*=\s*(?:'([^']*)'|\"([^\"]*)\")\s*;",
        script,
    )
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


class TestRefreshStepExists(unittest.TestCase):
    """Canary. Without it every check below passes vacuously on a missing step."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def test_workflow_exists(self):
        self.assertTrue(WORKFLOW.is_file(), f"{WORKFLOW} not found")

    def test_refresh_step_present(self):
        self.assertIsNotNone(
            _step_named(self.text, REFRESH_STEP_NAME),
            f"`{REFRESH_STEP_NAME}` is gone from dast-full-scan.yml — the ZAP "
            "tracker body would freeze on its first-ever snapshot again, showing "
            "fixed findings as live (the #498 state).",
        )

    def test_refresh_step_is_unique(self):
        blocks = [
            b for b in step_blocks(self.text)
            if re.search(
                rf"(?m)^\s*-\s+{yaml_key_pattern('name')}:\s*"
                rf"{re.escape(REFRESH_STEP_NAME)}\s*$",
                b,
            )
        ]
        self.assertEqual(
            len(blocks),
            1,
            f"Expected exactly one `{REFRESH_STEP_NAME}` step, found "
            f"{len(blocks)} — two copies race on the same issue body and the "
            "last writer wins non-deterministically.",
        )


class TestRefreshStepCannotGoInert(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        cls.block = _step_named(cls.text, REFRESH_STEP_NAME) or ""
        cls.script = _script_body(cls.block)

    def test_script_body_is_not_empty(self):
        # Non-vacuity precondition for every scan below.
        self.assertTrue(
            self.script.strip(),
            "the refresh step has no `script:` body — every content check below "
            "would pass against an empty string.",
        )

    def test_runs_unconditionally(self):
        # THE central invariant. `if: steps.zap.outcome == 'failure'` (the gate on
        # the sibling notify step, and the obvious thing to copy) reintroduces the
        # whole bug: the body is then only ever rewritten on runs that FOUND
        # something, so a clean run can never overwrite an alarming snapshot.
        # Fixed-and-still-red is precisely the state #498 was in.
        keys = _step_keys(self.block)
        self.assertEqual(
            keys.count("if"),
            1,
            f"expected exactly one `if:` on the refresh step, found "
            f"{keys.count('if')} in {keys}",
        )
        self.assertRegex(
            self.block,
            r"(?m)^\s*if:\s*always\(\)\s*$",
            "the refresh step is no longer `if: always()`. Gated on failure it "
            "only rewrites the body when the scan found something, so a CLEAN "
            "run can never clear a stale alarming snapshot — which is the exact "
            "defect this step exists to fix.",
        )

    def test_tracker_title_matches_the_zap_action_input(self):
        # The silent no-op. The script finds the issue BY TITLE; the ZAP action
        # creates it from `issue_title:`. Change either and the lookup matches
        # nothing, the step logs "nothing to refresh", the job stays green, and
        # the body freezes again with no signal anywhere.
        zap_block = _step_named(self.text, ZAP_STEP_NAME)
        self.assertIsNotNone(zap_block, f"`{ZAP_STEP_NAME}` step not found")
        action_title = _quoted_value(zap_block, "issue_title")
        script_title = _js_const(self.script, "TRACKER_TITLE")
        self.assertIsNotNone(
            action_title, "`issue_title:` is missing from the ZAP Full Scan step"
        )
        self.assertIsNotNone(
            script_title,
            "`const TRACKER_TITLE = '...'` is missing from the refresh script",
        )
        self.assertEqual(
            script_title,
            action_title,
            "the refresh script looks up a different issue title than the one the "
            f"ZAP action writes ({script_title!r} vs {action_title!r}). The lookup "
            "would match nothing and the step becomes a green no-op.",
        )

    def test_it_updates_the_body_rather_than_commenting(self):
        # Commenting is what the ZAP action already does, and what leaves the body
        # stale. Only `issues.update` with a `body` moves it.
        self.assertRegex(
            self.script,
            r"issues\.update\(",
            "the refresh step no longer calls `issues.update` — appending a "
            "comment leaves the body frozen, which is the whole defect.",
        )
        self.assertRegex(
            self.script,
            r"(?m)^\s*body,\s*$",
            "`issues.update` is called without passing `body` — it would update "
            "the issue without changing the text anyone reads.",
        )

    def test_unreadable_report_does_not_render_as_clean(self):
        # "I could not read the report" must never render the same as "I read it
        # and the site is clean" — the distinction #502 was built to preserve. The
        # catch branch must produce its own text, not fall through to the
        # zero-alerts wording.
        self.assertRegex(
            self.script,
            r"}\s*catch\s*\(",
            "the report parse has no `catch` — a malformed report_json.json would "
            "throw and the body would keep its stale contents with the job green.",
        )
        self.assertRegex(
            self.script,
            r"NOT a statement that the target is clean",
            "the catch branch no longer distinguishes 'could not read the report' "
            "from 'no alerts found'. Those must not render alike.",
        )

    def test_no_expression_interpolation_in_the_script(self):
        # CWE-94 posture, uniform (#349): workflow expressions reach a script body
        # through `env:`, never `${{ }}` inside it.
        self.assertNotIn(
            "${{",
            self.script,
            "a `${{ }}` expression is interpolated into the refresh script body. "
            "Pass it through the step's `env:` and read `process.env` instead.",
        )
        self.assertRegex(
            self.block,
            r"(?m)^\s*ZAP_OUTCOME:\s*\$\{\{\s*steps\.zap\.outcome\s*\}\}\s*$",
            "the ZAP outcome is no longer passed through `env: ZAP_OUTCOME` — "
            "either it was inlined (CWE-94 shape) or the body lost the field that "
            "distinguishes 'scan found alerts' from 'scan could not run'.",
        )


class TestPermissionIsGranted(unittest.TestCase):
    """#502's lesson, applied one workflow over.

    That watchdog shipped INERT because its logic was reviewed and its token grant
    was not: an Actions-API read with no `actions: read`. `issues.update` needs
    `issues: write`, and without it every nightly 403s inside a step nobody looks
    at.
    """

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def _workflow_permissions_block(self):
        out, col = [], None
        for raw in self.text.splitlines():
            if col is None:
                m = re.match(rf"^(\s*){yaml_key_pattern('permissions')}:\s*$", raw)
                # Workflow level only: column 0. A job-level block is indented.
                if m and len(m.group(1)) == 0:
                    col = 0
                continue
            if raw.strip() and not raw.lstrip().startswith("#") and not raw[0].isspace():
                break
            out.append(raw)
        return "\n".join(out)

    def test_issues_write_is_granted(self):
        block = self._workflow_permissions_block()
        self.assertTrue(
            block.strip(),
            "no workflow-level `permissions:` block in dast-full-scan.yml",
        )
        self.assertRegex(
            block,
            rf"(?m)^\s*{yaml_key_pattern('issues')}:\s*['\"]?write['\"]?\s*$",
            "`issues: write` is gone from dast-full-scan.yml's workflow-level "
            "permissions. `issues.update` would 403 on every nightly and the "
            "tracker body would silently freeze — the failure shape that shipped "
            "the #502 watchdog inert.",
        )


class TestDetectorMutations(unittest.TestCase):
    """Non-vacuity: each helper must actually distinguish the shapes it claims to.

    Written against synthetic workflows so a real-file green result cannot be
    mistaken for a working detector — the surrogate-vs-real-detector trap that
    left `TestAutoReleaseTriggerScoping` unable to notice a missing scope (#504).
    """

    _WF = (
        "on:\n  schedule:\n    - cron: '0 2 * * *'\n"
        "permissions:\n  contents: read\n  issues: write\n"
        "jobs:\n"
        "  dast-full:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: ZAP Full Scan\n"
        "        id: zap\n"
        "        with:\n"
        '          issue_title: "ZAP Full Scan Report"\n'
        "      - name: Refresh ZAP tracker body\n"
        "        if: always()\n"
        "        env:\n"
        "          ZAP_OUTCOME: ${{ steps.zap.outcome }}\n"
        "        with:\n"
        "          script: |\n"
        "            const TRACKER_TITLE = 'ZAP Full Scan Report';\n"
        "            await github.rest.issues.update({\n"
        "              body,\n"
        "            });\n"
        "      - name: Teardown\n"
        "        run: docker compose down\n"
    )

    def test_finds_the_named_step_and_nothing_else(self):
        block = _step_named(self._WF, REFRESH_STEP_NAME)
        self.assertIsNotNone(block)
        self.assertIn("TRACKER_TITLE", block)
        self.assertNotIn(
            "docker compose down",
            block,
            "the next step leaked into this one — a later step's content would be "
            "credited to the refresh step.",
        )

    def test_a_mention_in_another_step_is_not_the_step(self):
        wf = self._WF.replace(
            "      - name: Teardown\n        run: docker compose down\n",
            "      - name: Teardown\n"
            "        run: echo 'see Refresh ZAP tracker body'\n",
        )
        block = _step_named(wf, REFRESH_STEP_NAME)
        self.assertNotIn("docker", block or "")
        self.assertIn("TRACKER_TITLE", block or "")

    def test_script_body_stops_at_the_next_step(self):
        script = _script_body(_step_named(self._WF, REFRESH_STEP_NAME))
        self.assertIn("TRACKER_TITLE", script)
        self.assertNotIn("Teardown", script)

    def test_missing_script_yields_empty_not_a_false_pass(self):
        wf = self._WF.replace("          script: |\n", "          x: 1\n")
        self.assertEqual(_script_body(_step_named(wf, REFRESH_STEP_NAME) or ""), "")

    def test_title_mismatch_is_detected(self):
        wf = self._WF.replace(
            "const TRACKER_TITLE = 'ZAP Full Scan Report';",
            "const TRACKER_TITLE = 'ZAP Report';",
        )
        block = _step_named(wf, REFRESH_STEP_NAME)
        zap = _step_named(wf, ZAP_STEP_NAME)
        self.assertNotEqual(
            _js_const(_script_body(block), "TRACKER_TITLE"),
            _quoted_value(zap, "issue_title"),
            "a drifted tracker title went undetected — the refresh would silently "
            "match no issue.",
        )

    def test_quoted_key_forms_are_read(self):
        wf = self._WF.replace(
            '          issue_title: "ZAP Full Scan Report"\n',
            "          'issue_title': 'ZAP Full Scan Report'\n",
        )
        self.assertEqual(
            _quoted_value(_step_named(wf, ZAP_STEP_NAME), "issue_title"),
            "ZAP Full Scan Report",
            "a quoted `issue_title` key evaded the reader — the same blindness "
            "that hit eight guards in #391/#393/#394.",
        )

    def test_step_keys_are_the_steps_own(self):
        keys = _step_keys(_step_named(self._WF, REFRESH_STEP_NAME))
        self.assertIn("if", keys)
        self.assertIn("env", keys)
        self.assertNotIn(
            "body",
            keys,
            "a key from inside the script body was counted as a step key.",
        )


if __name__ == "__main__":
    unittest.main()
