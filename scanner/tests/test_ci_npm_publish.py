"""
Regression guards for the npm release workflow `.github/workflows/npm-publish.yml`.

Four supply-chain / release invariants, all silently weakenable:

1. **SLSA provenance** — every `npm publish` invocation must pass `--provenance`.
   This is the whole point of the workflow (OIDC trusted-publisher + SLSA
   attestation). Dropping `--provenance` still publishes successfully, so the
   regression is invisible: packages ship WITHOUT attestation and nobody sees a
   failure. Plausible incident: a "fix the failing publish" commit removes the
   flag. (OWASP A08 Software & Data Integrity Failures; SLSA provenance.)

2. **Least-privilege default token** — the workflow-level `permissions:` block
   must stay `contents: read`. Broadening it (e.g. `write-all`) silently grants
   the release workflow extra scope across all jobs. The `publish` job legitimately
   ADDS `id-token: write` (OIDC) and `contents: write` (push the release tag) at
   the JOB level; this guard inspects only the top-level block, so those job-level
   grants are not flagged.

3. **npm upgraded for OIDC trusted publishing** — OIDC tokenless publish requires
   npm >= 11.5.1, but Node 22 (the pinned runtime) bundles npm 10.x. The publish
   job MUST upgrade npm before publishing, else `--provenance` silently falls back
   to a (now non-existent) NODE_AUTH_TOKEN and the publish fails / loses OIDC.

4. **Auto-release trigger** — the workflow must fire on a push to `main` (the
   version-bump auto-publish path) in addition to `v*` tags. Removing the branch
   trigger silently reverts to "manual-tag-only", so merged version bumps would
   stop publishing with no failure signal.

Semantics: PRESENCE for the flag / step / trigger; the top-level permissions
block must contain `contents: read` and no `write` grant. If you intentionally
change any of these, update this guard in the same PR and justify it.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib.

Scope note: action SHA-pinning for this file is already covered by
test_ci_gate_topology.py (it globs all workflows) — NOT duplicated here.
The npm package payload (files[]) is guarded by test_ci_npm_files.py.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_regex_mutation,
    block_ends_at,
    extract_on_block,
    trigger_block,
    yaml_key_pattern,
)
from _ci_guard_util import strip_inline_comment as _strip_comment  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
NPM_PUBLISH = REPO_ROOT / ".github" / "workflows" / "npm-publish.yml"

# `branches:` bare OR quoted, anchored to a mapping key so the substring inside a
# value (or the longer `branches-ignore`) is not counted, and matched in both
# block and flow style (`{branches: [main]}` after a `{` or `,`).
# The boundary is a fixed-width negative lookbehind rather than a consuming
# `(?:^|[\s{,])`, so `findall` returns the key itself and two adjacent keys
# cannot overlap-swallow each other's delimiter.
_BRANCHES_KEY_RE = re.compile(
    rf"(?<![^\s{{,]){yaml_key_pattern('branches')}\s*:"
)
_BRANCHES_MAIN_RE = re.compile(
    rf"{yaml_key_pattern('branches')}\s*:\s*(?:-\s*|\[\s*)['\"]?main\b"
)


def push_trigger_block(text: str) -> str:
    """The body of the top-level `on:` -> `push:` trigger, or "" if absent."""
    return trigger_block(extract_on_block(text), "push")


def push_branch_filter_keys(text: str) -> list:
    """Every `branches:` key declared under `on: push:` — the auto-release filter.

    Scoped to the `push:` block on purpose. The predecessor scanned the whole
    comment-stripped workflow, which answers "does `branches:` exist anywhere",
    a question a decoy under any other trigger also answers yes to.
    """
    return _BRANCHES_KEY_RE.findall(push_trigger_block(text))


def push_targets_main(text: str) -> bool:
    """Whether `on: push:`'s own `branches:` filter includes `main`."""
    return bool(_BRANCHES_MAIN_RE.search(push_trigger_block(text)))


class TestNpmPublishProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            NPM_PUBLISH.read_text(encoding="utf-8") if NPM_PUBLISH.is_file() else ""
        )

    def test_npm_publish_yml_exists(self):
        self.assertTrue(NPM_PUBLISH.is_file(), f"{NPM_PUBLISH} not found")

    def test_every_npm_publish_has_provenance(self):
        # Match `npm publish ...` run lines (ignore inline comments). Both the
        # dry-run and the real publish step must carry --provenance.
        publish_lines = [
            line.strip()
            for line in self.text.splitlines()
            if re.search(r"\bnpm\s+publish\b", _strip_comment(line))
        ]
        self.assertTrue(
            publish_lines,
            "No `npm publish` invocation found in npm-publish.yml — the publish "
            "step was removed or renamed.",
        )
        missing = [ln for ln in publish_lines if "--provenance" not in ln]
        self.assertEqual(
            missing,
            [],
            "`npm publish` without `--provenance` (packages would ship without "
            "SLSA attestation, silently):\n  " + "\n  ".join(missing),
        )


class TestNpmPublishLeastPrivilege(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            NPM_PUBLISH.read_text(encoding="utf-8") if NPM_PUBLISH.is_file() else ""
        )

    def _top_level_permissions_block(self):
        # Capture the WORKFLOW-level `permissions:` block: from a column-0
        # `permissions:` header to the next column-0 top-level key (jobs:, etc.).
        # Job-level permissions live under `jobs:` and are NOT captured here.
        out, in_perms = [], False
        for raw in self.text.splitlines():
            if re.match(rf"^{yaml_key_pattern('permissions')}\s*:\s*$", raw):
                in_perms = True
                continue
            if in_perms:
                # A column-0 COMMENT is not a dedent: PyYAML keeps every entry after
                # it in the same mapping. Breaking there truncated this block and
                # hid a live `packages: write` while all 12 tests passed
                # (measured 2026-08-11) — including the whole-block anchor below,
                # because the truncated block really was exactly `contents: read`.
                if block_ends_at(raw, 0):
                    break
                out.append(raw)
        return "\n".join(out)

    def test_top_level_permissions_is_least_privilege(self):
        block = self._top_level_permissions_block()
        self.assertTrue(
            block.strip(),
            "No workflow-level `permissions:` block found in npm-publish.yml — the "
            "least-privilege default was removed (GITHUB_TOKEN would fall back to "
            "broad default scopes).",
        )
        # ORDER MATTERS. The write-grant scan runs FIRST so that a broadened
        # permission is reported by the check that actually diagnoses it.
        #
        # It used to run second, behind the whole-block anchor below, and that
        # ordering hid a genuine false negative for as long as it existed: the scan
        # `:\s*write\b` missed a QUOTED grant value (`packages: "write"` is the same
        # grant to any YAML parser), so `write_grants` came back EMPTY while the
        # permission was live. The test still failed — but on the anchor, i.e. by
        # accident, with a message about block shape rather than about a write
        # grant. Fixing the scan alone was not enough: with the anchor first, the
        # scan could never be the reporter, so its correctness was unobservable in
        # the integrated path (verified — the fixed scan's message did not appear).
        # Both are now load-bearing and independently observable.
        write_grants = [
            ln.strip()
            for ln in block.splitlines()
            if re.search(r""":\s*["']?write\b""", _strip_comment(ln))
        ]
        self.assertEqual(
            write_grants,
            [],
            "Workflow-level `permissions:` was broadened with a write grant "
            "(least-privilege regression — keep it `contents: read`; job-level "
            "`id-token: write` belongs under the publish job, not here):\n  "
            + "\n  ".join(write_grants),
        )
        # The missing `re.MULTILINE` here is deliberate: `^`/`$` anchor the WHOLE
        # block, so this passes only when `contents: read` is its sole entry. That
        # makes it a structural catch-all for any added key the write-grant scan
        # above does not classify (a read-scope addition, a stray anchor, a typo).
        self.assertRegex(
            block,
            r"^\s*contents:\s*read\s*$",
            "Workflow-level permissions must keep `contents: read` as its ONLY "
            "entry (this pattern intentionally anchors the whole block).",
        )


class TestNpmPublishAutoRelease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (
            NPM_PUBLISH.read_text(encoding="utf-8") if NPM_PUBLISH.is_file() else ""
        )
        # The push-trigger checks below run against the COMMENT-STRIPPED text:
        # over the raw file, a commented-out `branches: [main]` satisfies both
        # and the guard goes inert while auto-release is dead. `branches:` is a
        # YAML key, so the whitespace-boundary stripper is the right one here.
        cls.scan = "\n".join(_strip_comment(ln) for ln in cls.text.splitlines())

    def test_npm_upgraded_before_publish(self):
        # OIDC trusted publishing needs npm >= 11.5.1; Node 22 bundles npm 10.x.
        # F-6: require the upgrade to PRECEDE `npm publish` (an upgrade placed
        # after the publish, or absent before it, would leave the publish on npm
        # 10.x and lose OIDC). Lines are comment-stripped so a `# npm install -g
        # npm` cannot satisfy it.
        lines = [_strip_comment(ln) for ln in self.text.splitlines()]
        upgrade_idx = next(
            (i for i, ln in enumerate(lines)
             if re.search(r"\bnpm\s+(?:install|i)\s+-g\s+npm\b", ln)),
            None,
        )
        publish_idx = next(
            (i for i, ln in enumerate(lines) if re.search(r"\bnpm\s+publish\b", ln)),
            None,
        )
        self.assertIsNotNone(
            upgrade_idx,
            "No `npm install -g npm` step found — Node 22 ships npm 10.x, which "
            "cannot do OIDC trusted publishing (needs >= 11.5.1).",
        )
        self.assertIsNotNone(publish_idx, "No `npm publish` found in npm-publish.yml.")
        self.assertLess(
            upgrade_idx,
            publish_idx,
            "`npm install -g npm` must PRECEDE `npm publish` — an upgrade after "
            "(or absent before) the publish leaves it on npm 10.x and loses OIDC.",
        )

    def test_auto_release_push_to_main_trigger(self):
        # The `push:` trigger must target main (auto-publish on a merged version
        # bump). Tolerant to YAML list form (`branches:\n  - main`) and flow form
        # (`branches: [main]`), with optional quoting on key and value.
        #
        # Scoped to the `push:` BLOCK, not the whole file. Both checks used to
        # scan the comment-stripped workflow text, which proves `branches:` EXISTS
        # somewhere — never that it belongs to the trigger that fires. Measured
        # 2026-09-01 on the real file: move the `branches: - main` under a new
        # `pull_request:` and leave `push:` with only its `tags:` filter, and the
        # version-bump auto-release is dead (PyYAML: `push -> {'tags': ['v*']}`)
        # with 14 tests here and 1181 CI guards repo-wide GREEN.
        self.assertRegex(
            extract_on_block(self.text),
            rf"(?m)^\s*{yaml_key_pattern('push')}\s*:",
            "npm-publish.yml lost its `push:` trigger entirely — no auto-release "
            "path remains (manual-dispatch-only regression).",
        )
        block = push_trigger_block(self.text)
        keys = push_branch_filter_keys(self.text)
        # COUNT, not presence: exactly one, so a second copy cannot shadow the
        # first and leave the `main` check satisfied by the wrong one.
        self.assertEqual(
            len(keys),
            1,
            "Expected exactly one `branches:` filter under `push:` in "
            f"npm-publish.yml, found {len(keys)}. None means auto-publish on a "
            "main version bump is gone (manual-tag-only regression); more than "
            "one means the effective filter is ambiguous.\n"
            f"push block:\n{block}",
        )
        self.assertTrue(
            push_targets_main(self.text),
            "the `push:` trigger no longer targets `main` — version-bump "
            "auto-release would silently stop firing.\n"
            f"push block:\n{block}",
        )

    def test_publish_job_can_tag(self):
        # The auto-release path pushes the vX.Y.Z tag from the publish job, which
        # needs job-level `contents: write`. Its ABSENCE means tag creation fails
        # (or the workflow-level grant was broadened — caught by the LP guard).
        # F-6: comment-strip first so a `# contents: write` cannot satisfy it.
        scan = "\n".join(_strip_comment(ln) for ln in self.text.splitlines())
        self.assertRegex(
            scan,
            r"contents:\s*write",
            "No `contents: write` anywhere — the publish job cannot push the "
            "release tag, so auto-tagging on version bump is broken.",
        )


class TestNpmPublishFsixHardening(unittest.TestCase):
    """F-6 mutation self-tests: upgrade-ordering and comment-evasion."""

    def test_upgrade_after_publish_is_detected(self):
        # `npm publish` before `npm install -g npm` must trip (ordering invariant).
        text = "run: npm publish --provenance\nrun: npm install -g npm@latest"
        lines = [_strip_comment(ln) for ln in text.splitlines()]
        up = next((i for i, ln in enumerate(lines)
                   if re.search(r"\bnpm\s+(?:install|i)\s+-g\s+npm\b", ln)), None)
        pub = next((i for i, ln in enumerate(lines)
                    if re.search(r"\bnpm\s+publish\b", ln)), None)
        self.assertFalse(
            up is not None and pub is not None and up < pub,
            "F-6: an upgrade placed AFTER publish should not satisfy the ordering.",
        )

    def test_contents_write_only_in_comment_does_not_satisfy(self):
        scan = "\n".join(
            _strip_comment(ln) for ln in "run: echo x  # contents: write".splitlines()
        )
        self.assertNotRegex(
            scan,
            r"contents:\s*write",
            "F-6: a `# contents: write` surviving only in a comment must not "
            "satisfy the tag-permission check.",
        )



class TestAutoReleaseTriggerScoping(unittest.TestCase):
    """Non-vacuity for the auto-release trigger check, in two rounds.

    Round 1 (2026-08-11): the checks were aimed at the RAW workflow text, so
    commenting the trigger out left both green. `extract_on_block` fixed that.

    Round 2 (2026-09-01): comment-stripping answers the *commented-out*
    regression and nothing else. The checks still scanned the whole file, so a
    `branches:` living under ANY other trigger satisfied them — the
    wrong-location shape. Measured on the real `npm-publish.yml`: `push:` left
    with only `tags:` and `branches: - main` moved to a new `pull_request:`
    (PyYAML-confirmed `push -> {'tags': ['v*']}`, so the version-bump
    auto-release is dead) passed 14 tests here and 1181 CI guards repo-wide.

    These exercise the real detectors by name; a surrogate re-implementation of
    the pattern would go stale against the functions the guard actually calls.
    """

    @staticmethod
    def _wf(on_body):
        return "on:\n" + on_body + "\njobs:\n  publish:\n    runs-on: ubuntu-latest\n"

    _LIVE = "  push:\n    branches:\n      - main\n    tags:\n      - 'v*'"

    def test_live_trigger_is_counted(self):
        wf = self._wf(self._LIVE)
        self.assertEqual(push_branch_filter_keys(wf), ["branches:"])
        self.assertTrue(push_targets_main(wf))

    def test_commented_trigger_is_not_counted(self):
        for mutant in ("  push:\n    # branches: [main]\n    tags: ['v*']",
                       "  push:\n    tags: ['v*']  # branches: [main]"):
            with self.subTest(mutant=mutant):
                wf = self._wf(mutant)
                self.assertEqual(push_branch_filter_keys(wf), [])
                self.assertFalse(push_targets_main(wf))

    def test_filter_under_a_sibling_trigger_is_not_attributed_to_push(self):
        # The shipped bypass. `branches: [main]` is present and targets main —
        # just not on the trigger that publishes.
        wf = self._wf("  push:\n    tags: ['v*']\n  pull_request:\n    branches:\n      - main")
        self.assertIn("branches:", wf, "probe is inert: no `branches:` planted")
        self.assertEqual(
            push_branch_filter_keys(wf),
            [],
            "a sibling trigger's `branches:` was attributed to `push:` — the "
            "auto-release filter would read as live while it is gone.",
        )
        self.assertFalse(push_targets_main(wf))

    def test_filter_in_a_job_body_is_not_attributed_to_push(self):
        wf = ("on:\n  push:\n    tags: ['v*']\n"
              "jobs:\n  publish:\n    runs-on: ubuntu-latest\n"
              "    steps:\n      - run: echo 'branches: [main]'\n")
        self.assertEqual(push_branch_filter_keys(wf), [])
        self.assertFalse(push_targets_main(wf))

    def test_quoted_and_flow_forms_are_counted(self):
        for on_body in ('  push:\n    "branches": [main]',
                        "  push:\n    'branches': ['main']",
                        '  push:\n    branches: ["main"]',
                        "  push: {branches: [main]}",
                        '  "push":\n    branches:\n      - main'):
            with self.subTest(on_body=on_body):
                wf = self._wf(on_body)
                self.assertEqual(
                    len(push_branch_filter_keys(wf)),
                    1,
                    "a standard authoring style evaded the filter count — the "
                    "guard would fail on a workflow that is actually correct.",
                )
                self.assertTrue(push_targets_main(wf))

    def test_branches_ignore_is_not_counted_as_branches(self):
        wf = self._wf("  push:\n    branches-ignore:\n      - main")
        self.assertEqual(
            push_branch_filter_keys(wf),
            [],
            "`branches-ignore:` is the OPPOSITE filter and must not satisfy the "
            "auto-release check.",
        )

    def test_a_second_copy_is_reported_not_shadowed(self):
        wf = self._wf("  push:\n    branches: [release]\n    branches: [main]")
        self.assertEqual(
            len(push_branch_filter_keys(wf)),
            2,
            "a duplicate `branches:` under `push:` must be reported — with only "
            "a presence check the second copy silently shadows the first.",
        )


class TestPermissionsBlockTruncation(unittest.TestCase):
    """Non-vacuity for the 2026-08-11 fix: a comment line must not truncate the
    workflow-level `permissions:` block.

    The extractor ended the block at the first line matching `^\\S` — "dedent to
    the next top-level key" — and a column-0 `#` comment matches that. PyYAML does
    not: it discards comment lines before structure, so every entry after one is
    still in the same mapping. Measured on the real `npm-publish.yml`:

        permissions:
          contents: read
        # regrouped for readability
          packages: write

        PyYAML             {'contents': 'read', 'packages': 'write'}
        this guard         12 passed

    Both least-privilege assertions were defeated at once, including the one whose
    comment calls it "a structural catch-all for any added key the write-grant scan
    does not classify" — it is a catch-all only over what the EXTRACTOR returns, and
    the truncated block really was exactly `contents: read`."""

    @classmethod
    def setUpClass(cls):
        cls.text = NPM_PUBLISH.read_text(encoding="utf-8")

    def _block_of(self, text):
        """The extractor under test, driven with substituted text (nothing is
        written to `.github/`)."""
        holder = TestNpmPublishLeastPrivilege("test_top_level_permissions_is_least_privilege")
        holder.text = text
        return holder._top_level_permissions_block()

    def test_a_column_zero_comment_does_not_hide_a_write_grant(self):
        # Regex fixture, not a literal one: the key may legitimately be written
        # `"permissions":`, and a literal anchor then goes STALE — which reads as a
        # guard failure while nothing is wrong with the guard (observed while
        # probing this very sweep). `apply_regex_mutation` reports the miss as a
        # stale fixture; tolerating the quoting removes the trap entirely.
        mutant = apply_regex_mutation(
            self.text,
            r"(?P<k>[\"']?permissions[\"']?\s*:\n\s*contents:\s*read\n)",
            r"\g<k># regrouped for readability\n  packages: write\n",
        )
        block = self._block_of(mutant)
        self.assertIn(
            "packages: write", block,
            "the comment truncated the permissions block, so a live write grant "
            f"never reached either assertion. Extracted:\n{block!r}",
        )

    def test_the_real_block_is_still_bounded_by_the_next_top_level_key(self):
        # Direction: the fix must not widen the block into `jobs:`. A step-level
        # `id-token: write` under the publish job is legitimate and must stay
        # outside this scan, or the guard false-alarms on a correct workflow.
        block = self._block_of(self.text)
        self.assertNotIn("jobs:", block)
        self.assertNotIn("runs-on", block)
        self.assertRegex(block, r"^\s*contents:\s*read\s*$")


class TestWriteGrantScanMutation(unittest.TestCase):
    """Non-vacuity for the 2026-08-06 sweep fix: the write-grant scan itself must
    catch a QUOTED grant value. Before it, `packages: "write"` produced an empty
    `write_grants` list — the scan reported no violation while the permission was
    live, and only the (unrelated) whole-block anchor happened to fail."""

    @staticmethod
    def _write_grants(block):
        return [
            ln.strip()
            for ln in block.splitlines()
            if re.search(r""":\s*["']?write\b""", _strip_comment(ln))
        ]

    def test_fires_on_quoted_and_bare_write_grants(self):
        for line in (
            '  packages: "write"',
            "  packages: 'write'",
            "  packages: write",
            '  id-token: "write"',
        ):
            with self.subTest(line=line.strip()):
                self.assertTrue(
                    self._write_grants(line),
                    "Mutation FAILED: a quoted write grant was invisible to the "
                    "write-grant scan — a least-privilege regression would be "
                    "reported as no violation.",
                )

    def test_quiet_on_read_grants_and_comments(self):
        for line in ("  contents: read", '  contents: "read"', "  # packages: write"):
            with self.subTest(line=line.strip()):
                self.assertEqual(
                    self._write_grants(line),
                    [],
                    "False positive: a read grant or a commented-out grant was "
                    "reported as a live write grant.",
                )


if __name__ == "__main__":
    unittest.main()
