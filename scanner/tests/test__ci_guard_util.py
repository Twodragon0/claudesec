"""
Direct unit tests for the shared `_ci_guard_util` primitives.

The double-underscore name (`test__ci_guard_util.py`) keeps this file OUT of the
`test_ci_*.py` catalog glob the meta-guards enforce (so it needs no Catalog row —
it tests a helper, not a CI invariant), while still being collected by pytest
(`test_*.py`). It gives the shared helpers their first direct coverage and locks
the F-7 hardening (inline-comment stripping inside `extract_on_block`).

stdlib-only; passes under pytest and `python3 -m unittest`. No network/subprocess.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    extract_on_block,
    shell_if_body,
    strip_comment_lines,
    strip_html_comments,
    strip_inline_comment,
    strip_inline_comment_sh,
    top_level_jobs,
)

CRITS_ANCHOR = r'\[\s*"\$CRITS"\s+-gt\s+0\s*\]\s*;\s*then'


class TestStripInlineComment(unittest.TestCase):
    def test_strips_trailing_comment(self):
        self.assertEqual(strip_inline_comment("uses: foo@abc  # v1.2.3"), "uses: foo@abc")

    def test_requires_whitespace_before_hash(self):
        # `foo#bar` is not a shell comment — a `#` with no preceding space stays.
        self.assertEqual(strip_inline_comment("image@sha256:dead#beef"), "image@sha256:dead#beef")


class TestStripInlineCommentSh(unittest.TestCase):
    """Bash-aware trailing-comment stripping: `#` at a command-separator boundary
    (`;#`/`&#`/`|#`) is a real bash comment even with no preceding space."""

    def test_strips_after_whitespace(self):
        self.assertEqual(strip_inline_comment_sh("exit 1  # done"), "exit 1")

    def test_strips_semicolon_adjacent(self):
        # The proven Security-Scan-Gate evasion: `;#exit 1` is a real comment.
        self.assertEqual(strip_inline_comment_sh('echo x;#exit 1'), "echo x;")

    def test_strips_amp_and_pipe_adjacent(self):
        self.assertEqual(strip_inline_comment_sh("a &#c"), "a &")
        self.assertEqual(strip_inline_comment_sh("a |#c"), "a |")

    def test_strips_after_subshell_close_and_redirect(self):
        # A SUBSHELL close `)` and a redirect `>` are real command boundaries, so a
        # `#` immediately after them starts a comment (verified: `(echo A)#x ; echo
        # DONE` prints only A). `>#f` is a comment (bash errors on the missing
        # redirect target), so stripping to `cmd >` is correct.
        self.assertEqual(strip_inline_comment_sh("(echo A)#c"), "(echo A)")
        self.assertEqual(strip_inline_comment_sh("cmd >#not-a-file"), "cmd >")

    def test_overstrips_cmdsub_in_word_documented(self):
        # DOCUMENTED over-strip (fail-safe): a command substitution CLOSING inside a
        # word keeps the `#` LITERAL — verified: `x=$(echo hi)#ZZZ` -> x=[hi#ZZZ].
        # A single-preceding-char model cannot tell a subshell `)` (command
        # boundary) from a `$(...)` `)` (mid-word), so we over-strip here. This
        # drops live text -> a guard sees LESS -> a false ALARM, never a silent
        # bypass; it is not triggered by the shell blocks the current guards scan.
        self.assertEqual(
            strip_inline_comment_sh('FILES=$(git diff)#|| git diff HEAD~1'),
            "FILES=$(git diff)",
        )

    def test_ansi_c_escaped_quote_is_not_a_reopen(self):
        # 5th-pass finding (ADR-001 §2): `$'\''` is ONE ANSI-C string — the `\'` is
        # an escaped literal quote, NOT a close+reopen — so the trailing ` #exit 1`
        # is a real comment (the exit never runs). A single-quote branch with no
        # escape awareness runs off the line "in a quote" and fails to strip it,
        # an UNDER-strip that hid a dead `exit 1` from the Security-Scan-Gate guard.
        self.assertEqual(
            strip_inline_comment_sh(r": $'\'' #exit 1"), r": $'\''"
        )

    def test_ansi_c_preserves_internal_hash(self):
        # A `#` inside an ANSI-C string is literal content, not a comment.
        self.assertEqual(strip_inline_comment_sh(r"echo $'a#b'"), r"echo $'a#b'")

    def test_strips_after_backtick(self):
        # `` `#cmd` `` — a `#` right after an opening backtick starts a comment.
        self.assertEqual(strip_inline_comment_sh("echo x`#exit 1`"), "echo x`")

    def test_preserves_backtick_hash_inside_quotes(self):
        # inside double quotes the whole thing is literal string data.
        self.assertEqual(
            strip_inline_comment_sh('echo "x`#y`"'), 'echo "x`#y`"'
        )

    def test_start_of_line_is_a_comment(self):
        self.assertEqual(strip_inline_comment_sh("#whole"), "")

    def test_preserves_midword_hash(self):
        # Not a word boundary → literal, not a comment.
        self.assertEqual(strip_inline_comment_sh("echo foo#bar"), "echo foo#bar")

    def test_preserves_param_length_expansion(self):
        self.assertEqual(strip_inline_comment_sh("echo ${#arr[@]}"), "echo ${#arr[@]}")

    def test_preserves_hash_inside_quotes(self):
        self.assertEqual(
            strip_inline_comment_sh('echo "a # b" ; run'), 'echo "a # b" ; run'
        )
        self.assertEqual(strip_inline_comment_sh("echo 'a;#b'"), "echo 'a;#b'")


class TestExtractOnBlockF7(unittest.TestCase):
    """F-7: extract_on_block strips whole-line AND trailing-inline comments."""

    def test_inline_comment_on_trigger_is_stripped(self):
        wf = "on:\n  pull_request:  # only on PRs\n    branches: [main]  # gate\njobs:\n  x: {}"
        block = extract_on_block(wf)
        self.assertNotIn("#", block, "F-7: inline comments must be stripped from the on: block")
        self.assertIn("pull_request:", block)

    def test_whole_line_comment_dropped(self):
        wf = "on:\n  # a prose mention of pull_request\n  push:\n    branches: [main]\njobs: {}"
        block = extract_on_block(wf)
        self.assertNotIn("pull_request", block, "whole-line comment must be dropped")
        self.assertIn("push:", block)

    def test_flow_style_and_quoted_on_key(self):
        self.assertIn("pull_request", extract_on_block("on: [push, pull_request]  # ci\njobs: {}"))
        self.assertIn("schedule", extract_on_block("'on':\n  schedule:\n    - cron: '0 0 * * *'\njobs: {}"))


class TestTopLevelJobs(unittest.TestCase):
    def test_parses_block_jobs_and_strips_inline_comment(self):
        wf = "jobs:\n  build:  # the build\n    runs-on: x\n  test:\n    runs-on: y\non: {}"
        self.assertEqual(top_level_jobs(wf), ["build", "test"])


class TestStripCommentLines(unittest.TestCase):
    def test_drops_whole_line_comments_only(self):
        self.assertEqual(strip_comment_lines("a\n# c\n  b"), "a\n  b")



class TestStripHtmlComments(unittest.TestCase):
    """Markdown has no `#` comment; `<!-- -->` is the escape hatch the catalog
    meta-guards must see through."""

    def test_single_line_comment_removed(self):
        self.assertEqual(strip_html_comments("a <!-- hidden --> b"), "a  b")

    def test_multiline_comment_removed(self):
        self.assertEqual(strip_html_comments("a <!--\nx\ny\n--> b"), "a  b")

    def test_multiple_comments_removed_independently(self):
        self.assertEqual(strip_html_comments("<!--x-->A<!--y-->B"), "AB")

    def test_non_greedy_does_not_swallow_between_comments(self):
        # A greedy `.*` would eat `KEEP` along with both comments.
        self.assertIn("KEEP", strip_html_comments("<!--a-->KEEP<!--b-->"))

    def test_unclosed_opener_is_left_intact(self):
        # Under-strip beats blanking the document: a stray `<!--` must not eat
        # the rest of the file and make every consumer fail at once.
        self.assertEqual(
            strip_html_comments("live row\n<!-- dangling"), "live row\n<!-- dangling"
        )

    def test_text_without_comments_is_unchanged(self):
        self.assertEqual(strip_html_comments("plain text"), "plain text")


class TestShellIfBody(unittest.TestCase):
    """`shell_if_body` bounds an `exit 1` assertion to one `if` block. Both
    consumers protect a merge-blocking control, so every case here is the
    difference between a guard that fires and one that certifies a dead gate."""

    def test_body_is_the_block_only(self):
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n  exit 1\nfi\necho after\n', CRITS_ANCHOR
        )
        self.assertRegex(body, r"\bexit\s+1\b")
        self.assertNotIn("after", body)

    def test_missing_anchor_returns_none(self):
        self.assertIsNone(shell_if_body("echo hi\n", CRITS_ANCHOR))

    def test_comment_stripped_before_the_anchor_is_searched(self):
        # The anchor is part of the haystack: a `#`-commented copy of the whole
        # block must not anchor the scan (bash exits 0 here — gate dead).
        self.assertIsNone(
            shell_if_body(
                '# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi\necho no gate\n',
                CRITS_ANCHOR,
            ),
            "a commented-out block anchored the scan inside itself",
        )

    def test_commented_exit_does_not_survive_in_the_body(self):
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n  echo warn  # exit 1\nfi\n', CRITS_ANCHOR
        )
        self.assertNotRegex(body, r"\bexit\s+1\b")

    def test_metachar_commented_exit_does_not_survive(self):
        # `;#exit 1` is a real bash comment with no preceding space.
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n  echo warn;#exit 1\nfi\n', CRITS_ANCHOR
        )
        self.assertNotRegex(body, r"\bexit\s+1\b")

    def test_nested_if_does_not_end_the_body_early(self):
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n'
            '  if [ -n "$CI" ]; then\n    echo ci\n  fi\n'
            "  exit 1\n"
            "fi\n",
            CRITS_ANCHOR,
        )
        self.assertRegex(body, r"\bexit\s+1\b")

    def test_unbalanced_block_fails_closed(self):
        # Fail CLOSED: returning the remainder would hand the consumer every
        # later `exit 1` in the file.
        self.assertIsNone(
            shell_if_body(
                'if [ "$CRITS" -gt 0 ]; then\n  echo warn\nsteps:\n  - run: exit 1\n',
                CRITS_ANCHOR,
            )
        )

    def test_if_as_an_english_word_is_not_a_nesting_level(self):
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n'
            '  echo "failing the build if any critical is found"\n'
            "  exit 1\n"
            "fi\n"
            "echo after\n",
            CRITS_ANCHOR,
        )
        self.assertIsNotNone(body, "an English `if` unbalanced the depth count")
        self.assertNotIn("after", body)
        self.assertRegex(body, r"\bexit\s+1\b")

    def test_inline_nested_if_fi_on_one_line_is_balanced(self):
        # `fi` is counted wherever it is a word, so a one-line nested block nets
        # out even though its `if` is at command position on the same line.
        body = shell_if_body(
            'if [ "$CRITS" -gt 0 ]; then\n'
            '  if [ -n "$CI" ]; then echo ci; fi\n'
            "  exit 1\n"
            "fi\n"
            "echo after\n",
            CRITS_ANCHOR,
        )
        self.assertIsNotNone(body)
        self.assertRegex(body, r"\bexit\s+1\b")
        self.assertNotIn("after", body)


if __name__ == "__main__":
    unittest.main()
