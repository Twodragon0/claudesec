"""
Direct unit tests for the shared guard helpers in `scanner/tests/_ci_guard_util.py`.

The CI config regression guards (`test_ci_*.py`) exercise these helpers only
indirectly, through their own assertions. This file tests each helper in
isolation so a future edit to the shared module is caught here with a precise
failure, not as a confusing downstream guard failure.

Named `test_guard_util.py` (NOT `test_ci_*`) on purpose: it is a unit test of
the helper module, not a CI config regression guard, so it must stay out of the
`test_ci_*.py` catalog glob (`ci-config-regression-guards.md`) and needs no
Catalog row. pytest still auto-discovers it via the `test_*.py` default; it
imports nothing from `scanner/lib`, so it does not touch the 99% coverage gate.
Runs under pytest (the CI runner) and `python3 -m unittest`.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    extract_on_block,
    join_continuations,
    non_comment_lines,
    on_key_inline,
    strip_comment_lines,
)


class TestNonCommentLines(unittest.TestCase):
    def test_drops_full_line_comments(self):
        self.assertEqual(
            non_comment_lines("a\n# comment\nb"), ["a", "b"]
        )

    def test_drops_indented_comments(self):
        self.assertEqual(
            non_comment_lines("a\n    # indented\nb"), ["a", "b"]
        )

    def test_keeps_line_with_trailing_inline_hash(self):
        # Only WHOLE-line comments are dropped; a code line with a trailing # stays.
        self.assertEqual(
            non_comment_lines('x = 1  # trailing'), ['x = 1  # trailing']
        )

    def test_empty_and_blank(self):
        self.assertEqual(non_comment_lines(""), [])
        self.assertEqual(non_comment_lines("\n\n"), ["", ""])


class TestStripCommentLines(unittest.TestCase):
    def test_rejoins_without_comments(self):
        self.assertEqual(strip_comment_lines("a\n# c\nb"), "a\nb")

    def test_token_only_in_comment_is_removed(self):
        scan = strip_comment_lines('# DESIRED_X="true"\nDESIRED_X="false"')
        self.assertNotIn('DESIRED_X="true"', scan)
        self.assertIn('DESIRED_X="false"', scan)

    def test_empty(self):
        self.assertEqual(strip_comment_lines(""), "")


class TestJoinContinuations(unittest.TestCase):
    def test_joins_backslash_newline(self):
        # The `\`+newline collapses to a single space; surrounding spaces are
        # left as-is, so assert the meaningful property: one line, no backslash.
        result = join_continuations("RUN pip install \\\n    prowler")
        self.assertNotIn("\n", result)
        self.assertNotIn("\\", result)
        self.assertEqual(result.split(), ["RUN", "pip", "install", "prowler"])

    def test_no_continuation_unchanged(self):
        self.assertEqual(join_continuations("a\nb"), "a\nb")

    def test_multiple_continuations(self):
        result = join_continuations("a \\\nb \\\nc")
        self.assertNotIn("\n", result)
        self.assertEqual(result.split(), ["a", "b", "c"])

    def test_empty(self):
        self.assertEqual(join_continuations(""), "")


class TestOnKeyInline(unittest.TestCase):
    def test_bare_on_returns_empty(self):
        self.assertEqual(on_key_inline("on:"), "")

    def test_quoted_keys_return_empty(self):
        self.assertEqual(on_key_inline("'on':"), "")
        self.assertEqual(on_key_inline('"on":'), "")

    def test_flow_style_returns_inline(self):
        self.assertEqual(
            on_key_inline("on: [push, pull_request]"), " [push, pull_request]"
        )

    def test_indented_on_is_not_a_top_level_key(self):
        self.assertIsNone(on_key_inline("  on:"))

    def test_non_on_lines_return_none(self):
        self.assertIsNone(on_key_inline("one: foo"))
        self.assertIsNone(on_key_inline("on_failure:"))
        self.assertIsNone(on_key_inline("permissions:"))

    def test_trailing_whitespace_tolerated(self):
        self.assertEqual(on_key_inline("on:   "), "")


class TestExtractOnBlock(unittest.TestCase):
    def test_block_style_children(self):
        wf = "name: x\non:\n  schedule:\n    - cron: '0 0 * * *'\n  workflow_dispatch:\npermissions:\n  contents: read"
        block = extract_on_block(wf)
        self.assertIn("schedule:", block)
        self.assertIn("workflow_dispatch:", block)
        self.assertNotIn("permissions:", block)  # stops at next top-level key

    def test_flow_style_pull_request_captured(self):
        wf = "on: [push, pull_request]\npermissions:\n  contents: read"
        self.assertIn("pull_request", extract_on_block(wf))

    def test_quoted_on_key_children_captured(self):
        wf = "'on':\n  pull_request:\n    branches: [main]\npermissions:"
        self.assertIn("pull_request", extract_on_block(wf))

    def test_comment_mentioning_trigger_is_not_in_block(self):
        wf = "# MUST NOT run on pull_request events\non:\n  schedule:\n    - cron: '0 0 * * *'\npermissions:"
        block = extract_on_block(wf)
        self.assertNotIn("pull_request", block)
        self.assertIn("schedule:", block)

    def test_no_on_key_returns_empty(self):
        self.assertEqual(extract_on_block("name: x\npermissions:\n  contents: read"), "")


if __name__ == "__main__":
    unittest.main()
