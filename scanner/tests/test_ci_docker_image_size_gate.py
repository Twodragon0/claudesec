"""
Regression guard for the Docker image-size gate in
`.github/workflows/lint.yml` (the `dashboard-regression-check` job).

The scanner runtime image was reduced from ~1.47 GB to ~513 MB by stripping
unused prowler cloud-provider SDKs in cycle #217-#237. The `max_mb=N` check in
the "Check image size" step is the only thing keeping that win from silently
regressing — e.g. re-adding a stripped provider (~700 MB) or loosening the cap
back toward the old 1.8 GB.

This test asserts the gate is PRESENT and has NOT been loosened above the
locked-in ceiling:

- `max_mb = N`, N <= 600

Semantics are `<=`, not `==`: tightening the cap DOWN is allowed (and should not
break this test), but loosening or removing it trips the guard. If you
intentionally raise the cap (e.g. a justified trivy/kubectl bump), update
MAX_IMAGE_SIZE_MB here in the same PR and explain why.

stdlib-only; passes under pytest (the CI runner) and `python3 -m unittest`.
No network, no subprocess.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines, strip_inline_comment  # noqa: E402

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

# Maximum acceptable image-size cap (MB). Lower this freely; raise it ONLY in
# the same PR that raises the matching `max_mb` in lint.yml, with rationale.
MAX_IMAGE_SIZE_MB = 600


def active_text(text):
    """`text` with whole-line AND trailing-inline `#` comments removed, so a
    cap value surviving only in a comment cannot satisfy the gate check
    (comment-evasion false-negative class).

    OPEN GAP (under-strip / false negative, NOT accepted — being fixed):
    `strip_inline_comment` is whitespace-boundary only, so a shell metacharacter
    adjacency such as `echo "…";#exit 1` is left intact even though bash treats
    it as a comment. The `exit 1` assertion below therefore still passes on that
    one mutant. The bash-aware stripper (`strip_inline_comment_sh`) arrives with
    #376; this scan switches to it in the follow-up that adopts it repo-wide,
    rather than growing a divergent local copy of the boundary logic here.
    """
    return "\n".join(
        strip_inline_comment(ln) for ln in strip_comment_lines(text).splitlines()
    )


_BREACH_IF_RE = re.compile(
    r'if\s*\[\s*"?\$?\{?size_mb\}?"?\s+-gt\s+"?\$?\{?max_mb\}?"?\s*\]\s*;\s*then'
)


def breach_block(text):
    """The body of `if [ "$size_mb" -gt "$max_mb" ]; then … fi`, or None.

    Bounding the `exit 1` assertion to THIS block is load-bearing. `lint.yml`
    holds a dozen unrelated `exit 1` lines, so an unscoped presence check is
    satisfied by any of them and cannot detect removal of the size gate's own
    exit — the guard passes while the cap only echoes (inert-guard class). The
    closing `fi` is found by BALANCED if/fi depth, not the first `fi`, so a
    nested `if … fi` cannot end the capture early and hide a trailing `exit 1`.
    """
    m = _BREACH_IF_RE.search(text)
    if not m:
        return None
    rest = text[m.end() :]
    depth, end = 1, len(rest)
    for tk in re.finditer(r"\bif\b|\bfi\b", rest):
        depth += 1 if tk.group(0) == "if" else -1
        if depth == 0:
            end = tk.start()
            break
    return rest[:end]


class TestCiDockerImageSizeGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.text = active_text(raw)

    def test_lint_yml_exists(self):
        self.assertTrue(
            LINT_YML.is_file(),
            f"CI workflow not found at {LINT_YML} — path assumption broke",
        )

    def test_image_size_cap_present_and_not_loosened(self):
        matches = [int(m) for m in re.findall(r"max_mb\s*=\s*(\d+)", self.text)]
        self.assertTrue(
            matches,
            "No `max_mb=N` found in lint.yml — the Docker image-size gate has "
            "been removed (the dashboard-regression-check size check).",
        )
        worst = max(matches)
        self.assertLessEqual(
            worst,
            MAX_IMAGE_SIZE_MB,
            f"Docker image-size cap loosened to {worst} MB (max allowed "
            f"{MAX_IMAGE_SIZE_MB} MB). Re-adding a stripped prowler provider or "
            f"reverting toward the old 1.8 GB cap would slip through. If "
            f"intentional, update MAX_IMAGE_SIZE_MB in this test and justify in "
            f"the PR.",
        )

    def test_size_check_fails_build_on_breach(self):
        # The gate must actually fail the job (`exit 1`) when the cap is
        # exceeded — a cap that only echoes is not a gate. The `exit 1` must be
        # INSIDE the breach block: unscoped, any other `exit 1` in lint.yml
        # satisfies it and the check goes inert.
        body = breach_block(self.text)
        self.assertIsNotNone(
            body,
            "The image-size step must compare size_mb against max_mb (the "
            "`if [ \"$size_mb\" -gt \"$max_mb\" ]; then` breach check) — it is "
            "gone, so nothing enforces the cap.",
        )
        self.assertRegex(
            body,
            r"\bexit\s+1\b",
            "The image-size breach block must `exit 1` so the build fails. A cap "
            "that only echoes is not a gate (an `exit 1` elsewhere in lint.yml "
            "does not count).",
        )


class TestImageSizeCommentEvasion(unittest.TestCase):
    """A cap surviving only in a comment must not satisfy the gate."""

    def test_commented_cap_is_not_counted(self):
        mutant = "# max_mb=9999\nrun: echo hi  # max_mb=9999"
        scan = active_text(mutant)
        self.assertEqual(
            re.findall(r"max_mb\s*=\s*(\d+)", scan),
            [],
            "comment-evasion: a `max_mb=` surviving only in a whole-line or "
            "trailing comment must NOT count as an active size gate.",
        )

    def test_active_cap_is_counted(self):
        scan = active_text("          max_mb=600")
        self.assertEqual(re.findall(r"max_mb\s*=\s*(\d+)", scan), ["600"])


class TestBreachBlockScoping(unittest.TestCase):
    """Mutation self-tests for `breach_block`.

    The unscoped `assertIn("exit 1", text)` this replaced could not detect
    removal of the size gate's own exit, because `lint.yml` contains many other
    `exit 1` lines. These prove the scoped version does.
    """

    _GOOD = (
        '          if [ "$size_mb" -gt "$max_mb" ]; then\n'
        "            echo error\n"
        "            exit 1\n"
        "          fi\n"
    )
    # The breach block no longer exits, but an UNRELATED `exit 1` remains later
    # in the file — the exact shape the old unscoped check called green.
    _GUTTED = (
        '          if [ "$size_mb" -gt "$max_mb" ]; then\n'
        "            echo error\n"
        "          fi\n"
        "      - name: some other step\n"
        "        run: |\n"
        "          if [ -z \"$X\" ]; then\n"
        "            exit 1\n"
        "          fi\n"
    )
    # A nested `if … fi` must not end the capture early and hide the exit.
    _NESTED = (
        '          if [ "$size_mb" -gt "$max_mb" ]; then\n'
        '            if [ -n "$CI" ]; then echo ci; fi\n'
        "            exit 1\n"
        "          fi\n"
    )

    def test_good_block_contains_exit(self):
        self.assertRegex(breach_block(self._GOOD), r"\bexit\s+1\b")

    def test_unrelated_exit_does_not_satisfy(self):
        body = breach_block(self._GUTTED)
        self.assertIsNotNone(body, "breach `if` should still be found")
        self.assertNotRegex(
            body,
            r"\bexit\s+1\b",
            "Scoping failure: an `exit 1` from a LATER step leaked into the "
            "breach block, so removing the gate's own exit would go undetected.",
        )

    def test_nested_if_does_not_truncate(self):
        self.assertRegex(breach_block(self._NESTED), r"\bexit\s+1\b")

    def test_missing_breach_check_returns_none(self):
        self.assertIsNone(breach_block("          echo 'no gate here'\n"))


if __name__ == "__main__":
    unittest.main()
