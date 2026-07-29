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
    strip_comment_lines,
    strip_inline_comment,
    strip_inline_comment_sh,
    top_level_jobs,
)


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

    def test_strips_after_close_paren_and_redirect(self):
        # `)#` (after a command substitution) and `>#` are real bash comments.
        self.assertEqual(
            strip_inline_comment_sh('FILES=$(git diff)#|| git diff HEAD~1'),
            "FILES=$(git diff)",
        )
        self.assertEqual(strip_inline_comment_sh("cmd >#not-a-file"), "cmd >")

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


if __name__ == "__main__":
    unittest.main()
