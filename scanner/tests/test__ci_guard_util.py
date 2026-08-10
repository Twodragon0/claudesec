"""
Direct unit tests for the shared `_ci_guard_util` primitives.

The `test_ci_*.py` guards exercise these helpers only INDIRECTLY, through their
own assertions, so an edit to the shared module surfaces as a confusing failure
in some downstream guard — or, worse, as no failure at all where no consumer
happens to hit the changed path. This file tests each helper in isolation.

The double-underscore name (`test__ci_guard_util.py`) mirrors the module it
tests (`_ci_guard_util.py`) and keeps this file OUT of the `test_ci_*.py`
catalog glob the meta-guards enforce, so it needs no Catalog row — it tests a
helper, not a CI invariant. pytest still collects it via the default `test_*.py`
pattern.

CONSOLIDATION (2026-08-10)
--------------------------
This file absorbed `scanner/tests/test_guard_util.py`, which had grown up
independently as a second direct-unit-test file for the SAME module. Two test
files for one module is the same defect class the module itself exists to
prevent: `TestStripCommentLines` and the `extract_on_block` cases existed in
both with different coverage, so "is this primitive tested?" had two answers and
neither file was authoritative. Every case from that file is preserved below.

The merge also closed the gap that made the split visible — FIVE primitives had
no direct test in either file (`yaml_key_pattern`, `explicit_key_lines`,
`keys_at_column`, `job_block`, `job_needs`), despite each docstring naming a
specific incident it was written to prevent. Those incidents are now pinned here
rather than only in the consumer guards that happened to hit them.

Three more primitives moved INTO the shared module later the same day —
`desired_contexts`, `job_display_name`, `required_aggregators` — when a second
guard needed to resolve the required status checks and was about to grow its own
copy. They are tested here for the same reason as the other five.

stdlib-only; passes under pytest and `python3 -m unittest`. No network/subprocess.
Imports nothing from `scanner/lib`, so it does not touch the 99% coverage gate.
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ci_guard_util  # noqa: E402  (module handle: the enumeration test patches its dirs)
from _ci_guard_util import (  # noqa: E402
    desired_contexts,
    explicit_key_lines,
    extract_on_block,
    job_block,
    job_display_name,
    job_needs,
    join_continuations,
    keys_at_column,
    non_comment_lines,
    on_key_inline,
    required_aggregators,
    strip_comment_lines,
    strip_html_comments,
    strip_inline_comment,
    strip_inline_comment_sh,
    top_level_jobs,
    workflow_and_action_files,
    yaml_key_pattern,
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


class TestNonCommentLines(unittest.TestCase):
    def test_drops_full_line_comments(self):
        self.assertEqual(non_comment_lines("a\n# comment\nb"), ["a", "b"])

    def test_drops_indented_comments(self):
        self.assertEqual(non_comment_lines("a\n    # indented\nb"), ["a", "b"])

    def test_keeps_line_with_trailing_inline_hash(self):
        # Only WHOLE-line comments are dropped; a code line with a trailing # stays.
        self.assertEqual(non_comment_lines('x = 1  # trailing'), ['x = 1  # trailing'])

    def test_empty_and_blank(self):
        self.assertEqual(non_comment_lines(""), [])
        self.assertEqual(non_comment_lines("\n\n"), ["", ""])


class TestStripCommentLines(unittest.TestCase):
    def test_drops_whole_line_comments_only(self):
        self.assertEqual(strip_comment_lines("a\n# c\n  b"), "a\n  b")

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

    # F-7: extract_on_block strips whole-line AND trailing-inline comments.
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


class TestYamlKeyPattern(unittest.TestCase):
    """The fragment that exists so no guard hand-writes `key\\s*:` again — the
    blindness that hit EIGHT guards in #391/#393/#394, each verified green while
    its control was gone."""

    def test_matches_all_three_spellings(self):
        pat = re.compile(rf"^{yaml_key_pattern('uses')}:")
        for line in ("uses: x", '"uses": x', "'uses': x"):
            with self.subTest(line=line):
                self.assertTrue(pat.match(line))

    def test_does_not_match_a_different_key(self):
        pat = re.compile(rf"^{yaml_key_pattern('uses')}:")
        self.assertIsNone(pat.match("used: x"))
        self.assertIsNone(pat.match("use: x"))

    def test_mismatched_quotes_do_not_match(self):
        # `"uses'` is neither spelling; accepting it would mean the fragment is
        # matching loosely rather than enumerating the three real forms.
        pat = re.compile(rf"^{yaml_key_pattern('uses')}:")
        self.assertIsNone(pat.match("\"uses': x"))

    def test_key_is_regex_escaped(self):
        # A key containing a regex metacharacter must be matched literally, or a
        # caller's key would silently become a wildcard.
        self.assertIsNone(re.fullmatch(yaml_key_pattern("a.b"), "axb"))
        self.assertTrue(re.fullmatch(yaml_key_pattern("a.b"), "a.b"))

    def test_returns_a_non_capturing_group(self):
        # The docstring promises it is safe to embed. If it captured, every
        # caller's group numbering would shift by one — a silent, wide break.
        m = re.match(rf"({yaml_key_pattern('a')})", "a")
        self.assertEqual(len(m.groups()), 1)

    def test_is_a_single_alternation_unit(self):
        # Embedded after an anchor, the alternation must not leak: `^X|Y` would
        # bind `^` to the first branch only. A wrapping group prevents that.
        pat = re.compile(rf"^  {yaml_key_pattern('on')}:")
        self.assertIsNone(pat.match('"on": x'), "must still require the 2-space indent")
        self.assertTrue(pat.match('  "on": x'))


class TestExplicitKeyLines(unittest.TestCase):
    """YAML's explicit-key form yields the same mapping key while the substring
    `key:` never appears, so no line matcher can reach the value. Guards fail
    CLOSED on the shape rather than pretending to scan it."""

    def test_matches_every_documented_form(self):
        text = (
            "steps:\n"
            "  - ? run\n"
            "    : echo hi\n"
            '  ? "run"\n'
            "  ? run  # trailing comment\n"
            "  ? run : cmd\n"
        )
        self.assertEqual(
            explicit_key_lines(text, "run"),
            ["- ? run", '? "run"', "? run  # trailing comment", "? run : cmd"],
        )

    def test_ordinary_key_is_not_matched(self):
        # Direction check: the ordinary form is the REMEDIATION, so flagging it
        # would make the tripwire unresolvable.
        self.assertEqual(explicit_key_lines("  run: echo hi\n", "run"), [])

    def test_other_keys_are_not_matched(self):
        self.assertEqual(explicit_key_lines("  ? name\n  : x\n", "run"), [])

    def test_accepts_several_keys(self):
        text = "  ? run\n  ? uses\n"
        self.assertEqual(explicit_key_lines(text, "run", "uses"), ["? run", "? uses"])

    def test_empty_text(self):
        self.assertEqual(explicit_key_lines("", "run"), [])


class TestKeysAtColumn(unittest.TestCase):
    """Column EQUALITY, not `^\\s{N}` and not "anywhere in the block". A key one
    level deeper belongs to another mapping; a key higher up belongs to the
    parent. The second direction is the silent one — it lets a disable hide."""

    BLOCK = 'a:\n  b:\n    c:\n  # d:\n  "e":\n\n      f:\n'

    def test_reads_only_the_requested_column(self):
        self.assertEqual(keys_at_column(self.BLOCK, 0), ["a"])
        self.assertEqual(keys_at_column(self.BLOCK, 4), ["c"])
        self.assertEqual(keys_at_column(self.BLOCK, 6), ["f"])

    def test_quoted_key_is_unquoted_and_deeper_keys_excluded(self):
        # `"e"` must be reported as `e`, and `c`/`f` (deeper) must not appear.
        self.assertEqual(keys_at_column(self.BLOCK, 2), ["b", "e"])

    def test_comment_lines_are_skipped(self):
        # `  # d:` sits at the requested column but is a comment — reporting it
        # would let a commented-out key satisfy a presence check.
        #
        # Pins the BEHAVIOUR, not the explicit `startswith("#")` guard: deleting
        # that guard changes nothing today, because the key regex's `[^\s:#]+`
        # already cannot start a match at `#`. It is defence in depth, and this
        # test is what would catch a future key regex that loosened it.
        self.assertNotIn("d", keys_at_column(self.BLOCK, 2))

    def test_blank_lines_do_not_produce_keys(self):
        self.assertEqual(keys_at_column("\n\n   \n", 0), [])

    def test_no_keys_at_an_unused_column(self):
        self.assertEqual(keys_at_column(self.BLOCK, 1), [])

    def test_a_dedented_block_moves_its_keys(self):
        # The reason the docstring says DERIVE the column, never hardcode it: a
        # block sequence may legally sit at its parent key's indent, which is a
        # cosmetic diff that walks every key out from under a fixed anchor.
        deep = "    steps:\n      - name: x\n        if: false\n"
        flat = "    steps:\n    - name: x\n      if: false\n"
        self.assertEqual(keys_at_column(deep, 8), ["if"])
        self.assertEqual(keys_at_column(deep, 6), [])
        self.assertEqual(keys_at_column(flat, 6), ["if"])
        self.assertEqual(keys_at_column(flat, 8), [])


class TestJobBlock(unittest.TestCase):
    WF = (
        "jobs:\n"
        "  first:\n"
        "    runs-on: x\n"
        "  last:\n"
        "    runs-on: y\n"
        "    steps:\n"
        "      - run: z\n"
    )

    def test_bounded_by_indentation_not_by_the_next_job_key(self):
        # The LAST job in a file has no following `  <key>:` to stop at. A bound
        # written as "up to the next job key" reads correct and silently returns
        # nothing (or everything) here.
        block = job_block(self.WF, "last")
        self.assertIn("runs-on: y", block)
        self.assertIn("- run: z", block)
        self.assertNotIn("first", block)

    def test_stops_before_the_following_job(self):
        block = job_block(self.WF, "first")
        self.assertIn("runs-on: x", block)
        self.assertNotIn("runs-on: y", block)

    def test_stops_at_a_following_top_level_key(self):
        # The case that separates "indent <= 2" from "the next `  <key>:`": a
        # top-level key sits at indent 0, so a bound written against the job
        # column alone never fires and the block runs to EOF, swallowing
        # unrelated document content into the job under inspection.
        wf = "jobs:\n  only:\n    runs-on: x\non:\n  pull_request:\n"
        self.assertEqual(job_block(wf, "only"), "  only:\n    runs-on: x")

    def test_quoted_job_header_is_found(self):
        wf = 'jobs:\n  "scan":\n    runs-on: x\n'
        self.assertIn("runs-on: x", job_block(wf, "scan"))

    def test_comment_decoy_does_not_open_a_block(self):
        # `#  scan:` must neither shadow the real job nor invent one.
        wf = "jobs:\n  #  scan:\n  scan:\n    runs-on: x\n"
        block = job_block(wf, "scan")
        self.assertEqual(block, "  scan:\n    runs-on: x")

    def test_missing_key_returns_none(self):
        self.assertIsNone(job_block(self.WF, "nope"))

    def test_duplicate_key_returns_none_rather_than_guessing(self):
        # Fail CLOSED: callers assert on None, instead of silently scanning one
        # of two blocks that happen to share a name.
        self.assertIsNone(job_block("jobs:\n  x:\n    a: 1\n  x:\n    b: 2\n", "x"))


class TestJobNeeds(unittest.TestCase):
    def test_block_style_list(self):
        self.assertEqual(
            job_needs("  gate:\n    needs:\n      - a\n      - b\n    runs-on: x\n"),
            ["a", "b"],
        )

    def test_flow_style_list(self):
        self.assertEqual(job_needs("  gate:\n    needs: [a, b]\n    runs-on: x\n"), ["a", "b"])

    def test_scalar_value(self):
        self.assertEqual(job_needs("  gate:\n    needs: build\n    runs-on: x\n"), ["build"])

    def test_quoted_items_are_unquoted(self):
        self.assertEqual(
            job_needs("  gate:\n    needs:\n      - \"a\"\n      - 'b'\n"), ["a", "b"]
        )

    def test_list_items_elsewhere_in_the_job_are_not_dependencies(self):
        # A matrix entry is a `- name:` list item too. Reading list items
        # job-wide would invent dependencies — and, worse, mask a real one that
        # was dropped, since the count would still look plausible.
        block = (
            "  gate:\n"
            "    runs-on: x\n"
            "    strategy:\n"
            "      matrix:\n"
            "        include:\n"
            "          - name: NOTADEP\n"
        )
        self.assertEqual(job_needs(block), [])

    def test_no_needs_key(self):
        self.assertEqual(job_needs("  gate:\n    runs-on: x\n"), [])

    def test_empty_block(self):
        self.assertEqual(job_needs(""), [])
        self.assertEqual(job_needs("  gate:\n"), [])


class TestDesiredContexts(unittest.TestCase):
    """Moved here 2026-08-10 from `test_ci_required_graph_not_disabled.py`, because
    a second guard (`test_ci_gate_topology.py`) needed to know the required checks
    and a second copy is where two guards drift apart."""

    def test_reads_the_real_protection_script(self):
        self.assertEqual(
            desired_contexts(), ["Lint", "Security Scan Gate"],
            "the codified required contexts changed — acknowledge, do not absorb",
        )

    def test_parses_single_and_double_quoted_assignment(self):
        for q in ('"', "'"):
            with self.subTest(quote=q):
                self.assertEqual(
                    desired_contexts(f'DESIRED_CONTEXTS={q}["A", "B"]{q}\n'), ["A", "B"]
                )

    def test_returns_none_when_absent_or_malformed(self):
        # Fail CLOSED: callers treat None as "cannot resolve" and report a
        # problem. Returning [] instead would make every consumer pass vacuously.
        self.assertIsNone(desired_contexts("nothing here\n"))
        self.assertIsNone(desired_contexts('DESIRED_CONTEXTS="[not json"\n'))
        self.assertIsNone(desired_contexts('DESIRED_CONTEXTS="{}"\n'))

    def test_commented_assignment_still_parses_by_design(self):
        # Documented: the regex allows leading whitespace but not a `#`, so a
        # commented-out line does NOT satisfy it.
        self.assertIsNone(desired_contexts('# DESIRED_CONTEXTS="[\\"A\\"]"\n'))


class TestJobDisplayName(unittest.TestCase):
    def test_name_key_wins(self):
        self.assertEqual(
            job_display_name("  gate:\n    name: Security Scan Gate\n", "gate"),
            "Security Scan Gate",
        )

    def test_falls_back_to_the_job_key(self):
        self.assertEqual(job_display_name("  gate:\n    runs-on: x\n", "gate"), "gate")

    def test_quoted_name_key_and_value(self):
        self.assertEqual(
            job_display_name('  gate:\n    "name": "Lint"\n', "gate"), "Lint"
        )

    def test_a_step_name_is_not_the_job_name(self):
        # The step `name:` is deeper than the job's own key column. Reading it
        # would rename the job to whatever its first step is called, and branch
        # protection matches on the JOB's display name.
        block = "  gate:\n    runs-on: x\n    steps:\n      - name: Check stuff\n"
        self.assertEqual(job_display_name(block, "gate"), "gate")

    def test_empty_block_falls_back(self):
        self.assertEqual(job_display_name("  gate:\n", "gate"), "gate")


class TestRequiredAggregators(unittest.TestCase):
    LINT = "jobs:\n  lint-gate:\n    name: Lint\n    needs:\n      - a\n"
    SCAN = "jobs:\n  security-scan-gate:\n    name: Security Scan Gate\n    needs:\n      - b\n"

    def test_maps_each_required_context_to_its_workflow(self):
        got, problems = required_aggregators({"lint.yml": self.LINT, "scan.yml": self.SCAN})
        self.assertEqual(problems, [])
        self.assertEqual(
            got, {"lint.yml": "lint-gate", "scan.yml": "security-scan-gate"}
        )

    def test_a_context_resolving_to_zero_jobs_is_a_problem(self):
        # Fail CLOSED. Silently skipping would leave the consumer scanning fewer
        # workflows than branch protection actually requires.
        got, problems = required_aggregators({"lint.yml": self.LINT})
        self.assertTrue(any("Security Scan Gate" in p for p in problems))
        self.assertNotIn("scan.yml", got)

    def test_a_context_resolving_to_many_jobs_is_a_problem(self):
        dup = self.SCAN + "  impostor:\n    name: Security Scan Gate\n"
        _, problems = required_aggregators({"lint.yml": self.LINT, "scan.yml": dup})
        self.assertTrue(any("resolves to 2 jobs" in p for p in problems))

    def test_resolves_the_real_repo_to_the_two_known_aggregators(self):
        texts = {
            Path(p).name: Path(p).read_text(encoding="utf-8")
            for p in workflow_and_action_files()
            if "/workflows/" in p
        }
        got, problems = required_aggregators(texts)
        self.assertEqual(problems, [])
        self.assertEqual(
            got, {"lint.yml": "lint-gate", "security-scan.yml": "security-scan-gate"}
        )


class TestWorkflowAndActionFiles(unittest.TestCase):
    """The enumeration two guards were silently blind in: Actions honours
    `.yaml` as well as `.yml`, and `.github/actions/**/action.yml` carries
    `steps[].run`/`uses` exactly like a workflow."""

    def test_finds_both_extensions_and_composite_entrypoints_only(self):
        original_wf = _ci_guard_util.WORKFLOW_DIR
        original_act = _ci_guard_util.ACTION_DIR
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp, "workflows")
            wf.mkdir()
            Path(wf, "a.yml").write_text("jobs: {}\n", encoding="utf-8")
            Path(wf, "b.yaml").write_text("jobs: {}\n", encoding="utf-8")
            Path(wf, "notes.txt").write_text("ignored\n", encoding="utf-8")
            act = Path(tmp, "actions")
            (act / "c").mkdir(parents=True)
            (act / "d").mkdir(parents=True)
            Path(act, "c", "action.yml").write_text("runs: {}\n", encoding="utf-8")
            Path(act, "d", "action.yaml").write_text("runs: {}\n", encoding="utf-8")
            # NOT an entrypoint Actions resolves, so not executable workflow content.
            Path(act, "c", "helper.yml").write_text("x: 1\n", encoding="utf-8")
            try:
                _ci_guard_util.WORKFLOW_DIR = wf
                _ci_guard_util.ACTION_DIR = act
                found = sorted(Path(p).name for p in workflow_and_action_files())
            finally:
                _ci_guard_util.WORKFLOW_DIR = original_wf
                _ci_guard_util.ACTION_DIR = original_act
        self.assertEqual(found, ["a.yml", "action.yaml", "action.yml", "b.yaml"])

    def test_finds_this_repo_workflows_and_actions(self):
        # Vacuity canary: the paths must resolve against the real repo, or every
        # consumer guard scans an empty set and passes for free.
        found = workflow_and_action_files()
        self.assertTrue([p for p in found if "/workflows/" in p])
        self.assertTrue([p for p in found if "/actions/" in p])


if __name__ == "__main__":
    unittest.main()
