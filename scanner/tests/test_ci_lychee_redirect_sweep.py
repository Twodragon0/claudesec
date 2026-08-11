"""CI config regression guard: the monthly Lychee Redirect Sweep stays a
scheduled, notifier-only backstop that actually surfaces redirects.

WHAT THIS PROTECTS
------------------
`.github/workflows/lychee-redirect-sweep.yml` is the backstop for link rot the
PR-time `link-check` job hides on purpose. `link-check` runs lychee with
`--accept '100..=599'`, so every HTTP response (3xx redirects, 4xx/5xx dead
links) passes CI. The monthly sweep re-runs lychee with a STRICT accept range
and `--max-redirects 0` so anything that is not a clean 2xx is surfaced into a
single self-healing GitHub issue.

Two ways this quietly breaks, both guarded here:

1. The sweep loses its teeth. If `--max-redirects 0` or the strict
   `--accept '200..=299'` is dropped (e.g. "aligned" with the PR job's broad
   range), redirects resolve to their 200 target and rot is re-hidden — the
   workflow still runs green and looks healthy while catching nothing.

2. The sweep turns into a required PR check. If a `pull_request` trigger is
   added, this broad external-URL fetch runs on every PR, flakes on unrelated
   external sites, and (once required) blocks merges — the exact failure mode
   the notifier-only design avoids (cf. prowler-python-watch, protection-drift
   -watch).

It also pins the shared invariants: reuse of the single-source `lychee.toml`
exclude allowlist (so intentional redirects stay quiet) and the load-bearing
`lycheeVersion: v0.23.0` binary pin (v0.24.x nests the binary in a subdir the
pinned action installer can't find — see lint.yml / MEMORY.md).

FALSE-NEGATIVE HARDENING (why the arg checks are block-scoped)
--------------------------------------------------------------
The workflow's "Build issue body" step ECHOES `--max-redirects 0`,
`--accept '200..=299'` and `--config lychee.toml` as human-readable triage
instructions. Those are `run:`-script string values, NOT `#`-comments, so
`strip_comment_lines` does not remove them. A naive whole-file substring check
would therefore still pass even if the flag were deleted from the ACTUAL lychee
`args:` — the CRITICAL false-negative class this repo's guards have repeatedly
shipped. So the three arg-presence checks match ONLY the extracted `args:`
folded-scalar block, and `test_arg_checks_are_scoped_to_the_args_block` proves
(by mutation) that dropping the real flag makes the check fail.

Maps to OWASP CICD-SEC-7 (Insecure System Configuration): a check silently
weakened into a no-op, or a notifier silently promoted into a blocking gate.

stdlib-only; no PyYAML; no `scanner/lib` import. Passes under pytest and
`python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    extract_on_block,
    strip_comment_lines,
    yaml_key_pattern,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SWEEP_YML = REPO_ROOT / ".github" / "workflows" / "lychee-redirect-sweep.yml"

# The exact lychee-action binary pin shared with lint.yml's link-check. Bumping
# it without verifying the install path end-to-end regressed CI before (#204,
# reverted #209/#210); keep the sweep on the same proven pin.
LYCHEE_VERSION_PIN = "lycheeVersion: v0.23.0"


def _extract_args_block(text):
    """Return only the lines INSIDE the lychee step's `args: >-` folded scalar
    (continuation lines indented deeper than the `args:` key), joined.

    Scopes arg-flag checks to the ACTUAL lychee invocation so a flag echoed as a
    string elsewhere in the workflow (e.g. the issue-body `run:` step's triage
    instructions) cannot satisfy them. Pure function over text — a self-test can
    feed it a mutated copy without touching the real workflow. Returns "" if no
    `args: >-` block is present."""
    out, indent = [], None
    for line in text.splitlines():
        if indent is None:
            m = re.match(rf"^(\s*){yaml_key_pattern('args')}\s*:\s*>-?\s*$", line)
            if m:
                indent = len(m.group(1))
            continue
        if not line.strip():
            continue
        cur = len(line) - len(line.lstrip())
        if cur <= indent:  # dedent to the `args:` key (or beyond) ends the block
            break
        out.append(line.strip())
    return "\n".join(out)


class TestCiLycheeRedirectSweep(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SWEEP_YML.read_text(encoding="utf-8") if SWEEP_YML.is_file() else ""
        # For non-arg invariants (permissions, fail:, version pin, triggers) a
        # comment-stripped whole-file view is fine — none of those tokens are
        # echoed as run-script strings. Arg-flag checks use the block extractor
        # instead (see the module docstring's FALSE-NEGATIVE HARDENING note).
        cls.active = strip_comment_lines(cls.text)
        cls.args_block = _extract_args_block(cls.text)
        # `on:` block, comment-stripped, so a token in a comment can't satisfy
        # (or trip) a trigger check.
        # The SHARED extractor, not a local one. The local version matched
        # `^on:\s*(#.*)?$` — bare `on:` ONLY — so a quoted `"on":` (the spelling
        # GitHub's own docs recommend, because bare `on` resolves to the YAML-1.1
        # boolean `True`) made `on_block` empty and
        # `test_not_a_pull_request_check`, which this file's docstring calls its
        # single most important invariant, passed VACUOUSLY. Verified by
        # execution: with `"on":` and an added `pull_request:` trigger the local
        # extractor returned `''`; `extract_on_block` returns the block with the
        # trigger in it. Dormant when found (the real workflow uses bare `on:`),
        # but one cosmetic normalisation away from live — the exact
        # bypassable-by-YAML-shape class of #391/#393/#394, reintroduced by not
        # reusing the primitive that exists to close it (2026-08-08 audit).
        cls.on_block = extract_on_block(strip_comment_lines(cls.text))

    def test_workflow_exists(self):
        self.assertTrue(
            SWEEP_YML.is_file(),
            f"{SWEEP_YML} not found — the monthly redirect-sweep backstop is "
            "missing. Link rot would no longer be caught anywhere (the PR "
            "link-check accepts 100..=599 by design).",
        )

    def test_scheduled_and_dispatchable(self):
        self.assertRegex(
            self.on_block,
            r"schedule\s*:",
            "The sweep must keep a `schedule:` trigger — it is the monthly "
            "cadence that catches link rot the PR job hides.",
        )
        self.assertRegex(
            self.on_block,
            r"cron\s*:",
            "The `schedule:` trigger must declare a `cron:` cadence.",
        )
        self.assertRegex(
            self.on_block,
            r"workflow_dispatch\s*:?",
            "Keep `workflow_dispatch` so the sweep can be run on demand.",
        )

    def test_not_a_pull_request_check(self):
        # The single most important invariant: a scheduled notifier must never
        # gain a pull_request trigger, or this broad external-URL fetch runs on
        # every PR, flakes, and (once required) blocks merges.
        self.assertNotRegex(
            self.on_block,
            r"pull_request",
            "The redirect sweep must NOT trigger on `pull_request`. It is a "
            "scheduled notifier only; a broad external-URL fetch on every PR "
            "would flake and, if made required, block merges. Use the PR-time "
            "`link-check` job in lint.yml for per-PR link validation instead.",
        )

    def test_on_block_extraction_survives_a_quoted_on_key(self):
        """Non-vacuity for `test_not_a_pull_request_check`.

        That check asserts a token is ABSENT, so an extractor returning `''`
        satisfies it perfectly while having looked at nothing. The local
        extractor this file used to carry matched bare `on:` only, so the quoted
        `"on":` spelling — which GitHub's own docs recommend, since bare `on`
        resolves to the YAML-1.1 boolean `True` — emptied the block and the
        invariant passed vacuously (2026-08-08 audit). Both spellings must yield
        a block that still contains the triggers, or the absence assertion above
        proves nothing.
        """
        base = (
            "on:\n"
            "  schedule:\n"
            "    - cron: '0 3 1 * *'\n"
            "  workflow_dispatch:\n"
            "jobs:\n"
            "  sweep:\n"
            "    runs-on: ubuntu-latest\n"
        )
        for spelling in ("on:", '"on":', "'on':"):
            with self.subTest(spelling=spelling):
                block = extract_on_block(base.replace("on:", spelling, 1))
                self.assertIn(
                    "workflow_dispatch",
                    block,
                    f"the `on:` block came back without its triggers for {spelling} — "
                    "an empty block makes test_not_a_pull_request_check vacuous",
                )
                self.assertIn(
                    "pull_request",
                    extract_on_block(
                        base.replace("on:", spelling, 1).replace(
                            "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"
                        )
                    ),
                    f"a `pull_request` trigger was INVISIBLE under {spelling} — the "
                    "guard's most important check would pass while the trigger was live",
                )

    def test_can_write_issues(self):
        self.assertRegex(
            self.active,
            r"issues\s*:\s*write",
            "The sweep needs `permissions: issues: write` to open/update/close "
            "its self-healing tracking issue.",
        )

    def test_can_read_contents_for_checkout(self):
        # `actions/checkout` needs `contents: read`. If the permissions block is
        # narrowed to issues-only, checkout fails on the first step.
        self.assertRegex(
            self.active,
            r"contents\s*:\s*read",
            "The sweep must keep `permissions: contents: read` for the checkout "
            "step (the workflow declares an explicit least-privilege block, so "
            "the read default no longer applies once `issues: write` is set).",
        )

    def test_reuses_lychee_toml_excludes(self):
        self.assertIn(
            "--config lychee.toml",
            self.args_block,
            "The sweep's lychee `args:` must include `--config lychee.toml` so "
            "it reuses the single-source exclude allowlist (intentional "
            "redirects, bot-blocked hosts). Without it the sweep re-flags every "
            "already-triaged intentional redirect.",
        )

    def test_does_not_follow_redirects(self):
        # `--max-redirects 0` is what makes a 3xx surface as a 3xx instead of
        # resolving to its 200 destination. Dropping it silently re-hides every
        # redirect while the workflow still runs green.
        self.assertRegex(
            self.args_block,
            r"--max-redirects\s+0\b",
            "The sweep's `args:` must pass `--max-redirects 0` so redirects are "
            "reported instead of followed to their 200 target. Dropping this "
            "turns the sweep into a no-op that hides the very redirects it "
            "exists to find.",
        )

    def test_uses_strict_accept_range(self):
        # A strict 2xx-only accept is the other half of surfacing non-clean
        # links. If this widens toward the PR job's `100..=599`, redirects and
        # dead links pass and the sweep reports nothing.
        self.assertRegex(
            self.args_block,
            r"--accept\s+'?200\.\.=299'?",
            "The sweep's `args:` must use a strict `--accept '200..=299'` so "
            "only clean 2xx links pass. Widening it (e.g. to the PR job's "
            "`100..=599`) re-hides redirects and dead links.",
        )

    def test_arg_checks_are_scoped_to_the_args_block(self):
        # Mutate-then-verify self-test: prove the three arg checks above are NOT
        # false-negatives. The issue-body `run:` step echoes these same flags as
        # triage text, so a whole-file search would still pass after the real
        # flag was deleted. Delete the real `--max-redirects 0` arg line from a
        # COPY (never the real file) and assert the extractor no longer sees it —
        # i.e. the guard WOULD fail, as intended.
        for flag in ("--max-redirects 0", "--accept '200..=299'", "--config lychee.toml"):
            self.assertIn(
                flag, self.args_block,
                f"self-test setup: {flag!r} is not in the extracted args block.",
            )
        mutated = re.sub(r"\n\s*--max-redirects\s+0(?=\n)", "", self.text, count=1)
        self.assertNotEqual(
            mutated, self.text,
            "self-test setup: could not locate the real `--max-redirects 0` arg "
            "line to remove.",
        )
        self.assertNotIn(
            "--max-redirects 0",
            _extract_args_block(mutated),
            "FALSE-NEGATIVE: the args-block extractor still surfaces "
            "`--max-redirects 0` after it was removed from the real args block. "
            "A flag echoed as a string elsewhere (the issue-body step) is "
            "leaking into the check — the guard would not catch a weakened sweep.",
        )
        # Sanity: the un-mutated block still carries the flag.
        self.assertIn("--max-redirects 0", _extract_args_block(self.text))

    def test_lychee_does_not_fail_the_workflow(self):
        # Findings must not turn the schedule red; the classify step inspects
        # exit_code and opens an issue instead.
        self.assertRegex(
            self.active,
            r"fail\s*:\s*false",
            "The lychee step must set `fail: false` so link rot surfaces as a "
            "tracking issue, not a red scheduled run (which would train "
            "maintainers to ignore it).",
        )

    def test_lychee_version_pinned(self):
        self.assertIn(
            LYCHEE_VERSION_PIN,
            self.active,
            f"The sweep must pin the lychee binary with `{LYCHEE_VERSION_PIN}` "
            "(the same load-bearing pin as lint.yml). v0.24.x nests the binary "
            "in a subdir the pinned action installer cannot find. See lint.yml "
            "and MEMORY.md 'Lychee pin rationale'.",
        )


class TestArgsBlockMustNotBePreStripped(unittest.TestCase):
    """`_extract_args_block` is fed the RAW text on purpose. Do not "fix" it.

    The 2026-08-11 caller-side sweep asked why this extractor gets `cls.text`
    while the token assertions get `cls.active` (comment-stripped). The answer is
    the grammar: `args: >-` is a FOLDED SCALAR, and inside one a `#` line is
    CONTENT, not a comment. Measured with PyYAML:

        a:\n  args: >-\n    --one\n      # c\n    --two   ->  '--one\n  # c\n--two'
        a:\n  args: >-\n    --one\n  # c\n    --two       ->  ParserError

    So pre-stripping would DELETE a live CLI token from the block the guard then
    asserts on — the ordering rule ADR-001 §2 asks for is wrong here, and applying
    it uniformly would introduce the defect it exists to prevent. The second line
    also shows the only comment placement that could truncate this extractor is
    invalid YAML, so the workflow it describes could never run: no bypass exists to
    close.

    Identical on today's file (both forms yield the same 5-line block; the real
    workflow has no `#`-leading line inside the block), which is exactly why this
    needs a test rather than a comment — nothing would notice the change until a
    flag line happened to start with `#`."""

    def test_a_content_line_starting_with_hash_survives_extraction(self):
        fixture = (
            "jobs:\n  x:\n    steps:\n      - uses: a/b@c\n        with:\n"
            "          args: >-\n"
            "            --config lychee.toml\n"
            "            # not-a-comment-here\n"
            "            --max-redirects 0\n"
        )
        block = _extract_args_block(fixture)
        self.assertIn("--max-redirects 0", block)
        self.assertIn("# not-a-comment-here", block)

    def test_pre_stripping_would_drop_a_live_token(self):
        # The regression this pins: if someone routes the extractor through
        # `strip_comment_lines`, a folded-scalar content line vanishes.
        fixture = (
            "jobs:\n  x:\n    steps:\n      - uses: a/b@c\n        with:\n"
            "          args: >-\n"
            "            --config lychee.toml\n"
            "            # --max-redirects 0 lives on this line in the scalar\n"
        )
        self.assertIn("--max-redirects 0", _extract_args_block(fixture))
        self.assertNotIn(
            "--max-redirects 0",
            _extract_args_block(strip_comment_lines(fixture)),
            "pre-stripping no longer changes the extracted block — if the extractor "
            "was deliberately changed, update this test and say why; do not delete "
            "it, it is the reason the raw text is passed in",
        )

    def test_the_real_block_is_unaffected_today(self):
        # Direction/canary: the two paths agree on the current file, so this PR
        # changes no behaviour. If they ever diverge, the raw path is the correct
        # one and the divergence is a finding to read, not to normalise away.
        self.assertEqual(
            _extract_args_block(self.__class__._raw()),
            _extract_args_block(strip_comment_lines(self.__class__._raw())),
        )

    @staticmethod
    def _raw():
        return SWEEP_YML.read_text(encoding="utf-8") if SWEEP_YML.is_file() else ""


if __name__ == "__main__":
    unittest.main()
