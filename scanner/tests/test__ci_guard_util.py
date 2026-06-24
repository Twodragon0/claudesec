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
    top_level_jobs,
)


class TestStripInlineComment(unittest.TestCase):
    def test_strips_trailing_comment(self):
        self.assertEqual(strip_inline_comment("uses: foo@abc  # v1.2.3"), "uses: foo@abc")

    def test_requires_whitespace_before_hash(self):
        # `foo#bar` is not a shell comment — a `#` with no preceding space stays.
        self.assertEqual(strip_inline_comment("image@sha256:dead#beef"), "image@sha256:dead#beef")


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
