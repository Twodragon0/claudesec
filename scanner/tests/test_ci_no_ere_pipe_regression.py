"""
Regression guard: no `\\|` (backslash-pipe) in an ERE context inside
`scanner/checks/**/*.sh` or `scanner/lib/**/*.sh`.

Background
----------
In POSIX ERE (used by `grep -E`, `grep -qE`, `grep -nE`, `grep -rE`, and bash
`[[ ... =~ ... ]]`), the alternation operator is a plain `|`.  Writing `\\|`
instead is a LITERAL pipe character match, not alternation — so
`grep -E 'foo\\|bar'` matches the four-character string `foo|bar` and silently
fails to match either `foo` or `bar` alone.  This class of bug was found and
fixed in scanner/checks/ across PRs #221, #223, and #224.  Two intentional
literal-pipe uses survived; they are allowlisted below.

Contexts detected as ERE (conservative — lean toward NOT flagging uncertain
constructs to keep the false-positive rate near zero):
  * grep -[qnrlc]*E  (any grep invocation with an -E flag)
  * _code_grep '...'  (injection.sh helper; wraps `grep -nE "$pattern"`)
  * files_contain "..." "..."  (checks.sh helper; wraps `grep -[l]E "$pattern"`)
  * file_contains "..." "..."  (checks.sh helper; wraps `grep -qE "$pattern"`)
  * [[ ... =~ ... ]]  (bash ERE match)

Out of scope (noted, not flagged):
  * sed / awk patterns — different regex dialects; `\\|` in sed BRE IS
    alternation on GNU sed, so flagging those would be both a false positive and
    wrong advice.
  * Plain `grep` / `grep -G` without -E — in GNU BRE `\\|` is an extension for
    alternation (non-portable but functional), so it is deliberately outside this
    guard's scope.
  * Comments and echo/printf display strings — never flagged (see _is_ere_context
    for the heuristic).

Allowlisted intentional literals
---------------------------------
1. scanner/checks/code/injection.sh  — pattern `\\|safe`
   The `|safe` Jinja2 template filter is a LITERAL pipe + word "safe".  The
   scanner is looking for that exact character sequence in Python/HTML source.
   `grep -nE '...\\|safe'` correctly matches only `|safe`.  Flagging it would
   be wrong.

2. scanner/checks/saas/solutions.sh  — pattern `(curl|wget).*(\\||;)...`
   This ERE pattern is detecting `curl | sh` / `wget | sh` pipe-to-shell
   invocations in Jenkinsfiles.  The outer group `(\\||;)` deliberately matches
   either a LITERAL `|` character or `;`.  The `\\|` is intentional.

Allowlist implementation
------------------------
Allowlist entries match on (filename stem + offending substring) so they are
immune to line-number drift.  A substring match is tight enough to be precise
but loose enough not to break on minor reformatting.

Coverage extensions (PRs #244 → this PR)
-----------------------------------------
* scanner/lib/**/*.sh is now included in the scan set in addition to
  scanner/checks/**/*.sh.  The `files_contain`, `file_contains`, and
  `_code_grep` helpers are defined in scanner/lib/checks.sh; any \\|-in-ERE
  bug introduced there would have been invisible to the #244 guard.

* Multi-line call detection: when a `_code_grep`, `files_contain`, or
  `file_contains` call uses a backslash line-continuation (the function name
  on line N ends with `\\`, or the pattern argument is on the next physical
  line N+1), the detector now joins the two physical lines before checking for
  \\|.  A plain `grep -E` whose pattern is on the continuation line is also
  caught.

stdlib-only (re, pathlib, unittest).  No network, no subprocess.
Passes under `pytest` (CI) and `python3 -m unittest`.
"""

import re
import textwrap
import unittest
from pathlib import Path

# scanner/tests/<this> -> parents[0]=scanner/tests, [1]=scanner, [2]=repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_DIR = REPO_ROOT / "scanner" / "checks"
LIB_DIR = REPO_ROOT / "scanner" / "lib"

# ---------------------------------------------------------------------------
# Allowlist of intentional \\| occurrences.
# Each entry: (filename_stem, offending_substring_in_line)
# The filename_stem is the Path.name (e.g. "injection.sh").
# The offending_substring is a plain string that must appear in the *same line*
# as the \\| to qualify for exemption.
# ---------------------------------------------------------------------------
ALLOWLIST: list[tuple[str, str]] = [
    # Jinja2 |safe filter -- literal pipe is intentional, not ERE alternation
    ("injection.sh", r"\|safe"),
    # curl|sh / wget|sh detector -- (\\||;) deliberately matches literal pipe
    ("solutions.sh", r"(\\||;)"),
]


# ---------------------------------------------------------------------------
# ERE-context detection heuristics
# ---------------------------------------------------------------------------

# Regex that matches a line containing grep with -E (in any flag combination).
# Examples: grep -qE, grep -E, grep -nrE, grep -rE
_GREP_E_RE = re.compile(r"\bgrep\b[^|&;\n]*-[A-Za-z]*E")

# The named helpers in scanner/lib/checks.sh and injection.sh that internally
# call grep -E.  Match the function name followed by its first argument quote.
_HELPER_RE = re.compile(r"\b(?:files_contain|file_contains|_code_grep)\s+['\"]")

# Bash ERE match: [[ ... =~ ... ]]
_BASH_ERE_RE = re.compile(r"\[\[.*=~")


def _is_ere_context(line: str) -> bool:
    """Return True if the line contains an ERE-context expression."""
    stripped = line.strip()
    # Skip comment-only lines
    if stripped.startswith("#"):
        return False
    # Skip echo/printf display strings (conservative: only skip when the first
    # word is echo/printf and the line has no grep or helper call)
    parts = stripped.split()
    first_word = parts[0] if parts else ""
    if first_word in ("echo", "printf") and not _GREP_E_RE.search(line):
        return False
    return bool(
        _GREP_E_RE.search(line)
        or _HELPER_RE.search(line)
        or _BASH_ERE_RE.search(line)
    )


def _is_allowlisted(filepath: Path, line: str) -> bool:
    """Return True if this (file, line) combination is in the allowlist."""
    filename = filepath.name
    for stem, substring in ALLOWLIST:
        if filename == stem and substring in line:
            return True
    return False


# ---------------------------------------------------------------------------
# Line-continuation joining
# ---------------------------------------------------------------------------
# When a shell script uses backslash line-continuation, the ERE pattern
# argument may appear on the *next* physical line after the helper name.
# We join consecutive continuation lines before checking so that a `\\|`
# hiding on the second physical line is not missed.
#
# Strategy: if physical line N ends with `\` (after stripping), concatenate
# it (minus the trailing `\`) with line N+1 and treat the joined string as a
# single logical line for detection purposes.  We yield *both* the joined
# logical line (so the detector sees the full expression) *and* keep the
# original physical lines so that violation reporting shows useful context.

def _logical_lines(
    physical_lines: list[str],
) -> list[tuple[int, str]]:
    """
    Yield (first_physical_lineno, logical_line) pairs.

    A logical line is formed by joining consecutive physical lines that end
    with a backslash continuation.  The reported line number is always the
    first physical line of the logical group (1-based).

    The join keeps a single space between parts (the trailing backslash and
    any leading whitespace on the continuation line are stripped) so that
    regex patterns that span the join boundary can be matched.
    """
    result: list[tuple[int, str]] = []
    i = 0
    while i < len(physical_lines):
        lineno = i + 1  # 1-based
        parts = [physical_lines[i]]
        # Follow the continuation chain
        while parts[-1].rstrip().endswith("\\") and i + 1 < len(physical_lines):
            # Strip the trailing backslash from the current part
            parts[-1] = parts[-1].rstrip()[:-1]
            i += 1
            parts.append(physical_lines[i])
        logical = " ".join(p.strip() for p in parts)
        result.append((lineno, logical))
        i += 1
    return result


def _scan_dir(scan_dir: Path) -> list[tuple[Path, int, str]]:
    """
    Walk scan_dir recursively for *.sh files.
    Return a list of (filepath, lineno, logical_line) for each violation:
    a logical line that (a) is in an ERE context, (b) contains \\|, and
    (c) is NOT allowlisted.

    The lineno is the first physical line of the logical group.
    """
    violations: list[tuple[Path, int, str]] = []
    for sh_file in sorted(scan_dir.rglob("*.sh")):
        physical = sh_file.read_text(encoding="utf-8").splitlines()
        for lineno, logical in _logical_lines(physical):
            if r"\|" not in logical:
                continue
            if not _is_ere_context(logical):
                continue
            if _is_allowlisted(sh_file, logical):
                continue
            violations.append((sh_file, lineno, logical.rstrip()))
    return violations


def _scan_dirs(
    dirs: list[Path],
) -> list[tuple[Path, int, str]]:
    """Scan multiple directories and merge results."""
    all_violations: list[tuple[Path, int, str]] = []
    for d in dirs:
        if d.is_dir():
            all_violations.extend(_scan_dir(d))
    return all_violations


def _scan_text_lines(
    source_text: str, filename: str = "<synthetic>"
) -> list[tuple[str, int, str]]:
    """Same logic as _scan_dir but operates on a raw string (for tests)."""
    fake_path = Path(filename)
    violations = []
    physical = source_text.splitlines()
    for lineno, logical in _logical_lines(physical):
        if r"\|" not in logical:
            continue
        if not _is_ere_context(logical):
            continue
        if _is_allowlisted(fake_path, logical):
            continue
        violations.append((filename, lineno, logical.rstrip()))
    return violations


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScanDirectoriesExist(unittest.TestCase):
    def test_checks_dir_exists(self):
        self.assertTrue(
            CHECKS_DIR.is_dir(),
            f"scanner/checks directory not found at {CHECKS_DIR} -- path assumption broke",
        )

    def test_checks_dir_contains_sh_files(self):
        sh_files = list(CHECKS_DIR.rglob("*.sh"))
        self.assertTrue(
            sh_files,
            f"No .sh files found under {CHECKS_DIR} -- glob assumption broke",
        )

    def test_lib_dir_exists(self):
        self.assertTrue(
            LIB_DIR.is_dir(),
            f"scanner/lib directory not found at {LIB_DIR} -- path assumption broke",
        )

    def test_lib_dir_contains_sh_files(self):
        sh_files = list(LIB_DIR.rglob("*.sh"))
        self.assertTrue(
            sh_files,
            f"No .sh files found under {LIB_DIR} -- glob assumption broke",
        )


class TestNoEREPipeInChecksAndLib(unittest.TestCase):
    """
    Scans every scanner/checks/**/*.sh AND scanner/lib/**/*.sh for \\| in an
    ERE context.  Only the two explicitly allowlisted intentional occurrences
    are permitted.  Any other \\| in an ERE pattern is flagged as a regression.
    """

    def test_no_unallowlisted_ere_pipe(self):
        violations = _scan_dirs([CHECKS_DIR, LIB_DIR])
        if violations:
            lines = [
                f"  {v[0].relative_to(REPO_ROOT)}:{v[1]}: {v[2]!r}"
                for v in violations
            ]
            self.fail(
                "Found \\| in ERE context (use plain | for alternation in grep -E "
                "/ files_contain / file_contains / _code_grep / [[ =~ ]]):\n"
                + "\n".join(lines)
                + "\n\nIf the literal pipe is intentional, add an entry to "
                "ALLOWLIST in this test with a rationale comment."
            )

    def test_allowlisted_literals_still_present(self):
        """
        Each allowlist entry must still exist in the real tree.
        A stale allowlist entry (pattern removed, file renamed) is dead config --
        fail so it gets cleaned up.
        """
        for stem, substring in ALLOWLIST:
            found = False
            for scan_dir in (CHECKS_DIR, LIB_DIR):
                if found:
                    break
                for sh_file in scan_dir.rglob("*.sh"):
                    if sh_file.name != stem:
                        continue
                    for raw in sh_file.read_text(encoding="utf-8").splitlines():
                        if substring in raw:
                            found = True
                            break
                    if found:
                        break
            self.assertTrue(
                found,
                f"Allowlist entry ({stem!r}, {substring!r}) not found in the real "
                "tree -- it may have been removed or the file renamed. Remove the "
                "stale entry from ALLOWLIST in this test.",
            )


class TestMutationSelfTest(unittest.TestCase):
    """
    Non-vacuous self-test: synthetic snippets that MUST be flagged (bad) or
    MUST NOT be flagged (good).  Verifies the detector's basic correctness
    without touching any real file.
    """

    # --- BAD snippets: each must be flagged ---

    def test_detects_grep_E_with_backslash_pipe(self):
        snippet = "  grep -qE 'x\\|y' somefile"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: grep -qE 'x\\\\|y' should be detected "
            "as an ERE \\| regression but was NOT flagged.",
        )

    def test_detects_grep_E_alternation_bug_full_line(self):
        snippet = textwrap.dedent(
            """\
            # check for foo or bar
            grep -E 'foo\\|bar' "$file" && echo found
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: grep -E 'foo\\\\|bar' should be detected "
            "but was NOT flagged.",
        )

    def test_detects_files_contain_helper_with_backslash_pipe(self):
        snippet = '  files_contain "*.py" "import\\|require"'
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: files_contain with \\\\| should be detected "
            "but was NOT flagged.",
        )

    def test_detects_bash_ere_match_with_backslash_pipe(self):
        snippet = '  [[ "$line" =~ foo\\|bar ]]'
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: bash [[ =~ ]] with \\\\| should be detected "
            "but was NOT flagged.",
        )

    # --- BAD snippets: scanner/lib coverage (new in this PR) ---

    def test_detects_ere_pipe_in_lib_helper_pattern(self):
        """
        A \\| inside a files_contain/file_contains pattern as if it appeared
        in scanner/lib/checks.sh should be flagged.  The filename stem is set
        to "checks.sh" (matching the lib filename) to confirm lib coverage.
        """
        # Simulate a hypothetical bug introduced in scanner/lib/checks.sh:
        # a helper that hardcodes an ERE pattern with \\| instead of |
        snippet = '  grep -lE "foo\\|bar" "$SCAN_DIR"/*.sh'
        hits = _scan_text_lines(snippet, "checks.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: grep -lE '..\\\\|..' in a lib helper "
            "(checks.sh) should be detected but was NOT flagged.",
        )

    def test_detects_file_contains_in_lib_with_backslash_pipe(self):
        """
        A file_contains call (as defined and called from scanner/lib/) with a
        \\| in the pattern should be flagged regardless of which file it is in.
        """
        snippet = '  file_contains "config.yml" "value_a\\|value_b"'
        hits = _scan_text_lines(snippet, "checks.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: file_contains with \\\\| in lib context "
            "should be detected but was NOT flagged.",
        )

    # --- BAD snippets: multi-line continuation (new in this PR) ---

    def test_detects_multiline_code_grep_backslash_pipe_on_continuation(self):
        """
        A _code_grep call split over two physical lines (backslash continuation)
        where the \\| appears on the SECOND physical line (inside the pattern
        argument) must be detected.

        _code_grep \\
          'foo\\|bar' "*.sh"
        """
        snippet = textwrap.dedent(
            """\
            _code_grep \\
              'foo\\|bar' "*.sh"
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: multi-line _code_grep with \\\\| on the "
            "continuation line should be detected but was NOT flagged.",
        )

    def test_detects_multiline_files_contain_backslash_pipe_on_continuation(self):
        """
        A files_contain call split over two lines where the pattern (second arg)
        is on the continuation line and contains \\|.

        files_contain "*.sh" \\
          "alpha\\|beta"
        """
        snippet = textwrap.dedent(
            """\
            files_contain "*.sh" \\
              "alpha\\|beta"
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: multi-line files_contain with \\\\| on "
            "the continuation line should be detected but was NOT flagged.",
        )

    def test_detects_multiline_grep_E_backslash_pipe_on_continuation(self):
        """
        A grep -E call split over two lines where the pattern is on the
        continuation line and contains \\|.

        grep -E \\
          'foo\\|bar' file
        """
        snippet = textwrap.dedent(
            """\
            grep -E \\
              'foo\\|bar' file
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertTrue(
            hits,
            "MUTATION SELF-TEST FAILED: multi-line grep -E with \\\\| on the "
            "continuation line should be detected but was NOT flagged.",
        )

    # --- GOOD snippets: each must NOT be flagged ---

    def test_allows_grep_E_with_plain_pipe_alternation(self):
        snippet = "  grep -qE 'x|y' somefile"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: grep -qE 'x|y' (correct ERE) was incorrectly "
            f"flagged: {hits}",
        )

    def test_allows_backslash_pipe_in_comment(self):
        snippet = "  # grep -E 'a\\|b' would be wrong (use a|b instead)"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: \\\\| in a comment was incorrectly flagged: {hits}",
        )

    def test_allows_backslash_pipe_in_sed(self):
        # sed uses BRE by default; \| in sed is an extension for alternation
        # (not a bug for sed), so we deliberately do not flag it
        snippet = "  sed -n 's/foo\\|bar/baz/g' file"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: \\\\| in sed (non-ERE context) was incorrectly "
            f"flagged: {hits}",
        )

    def test_allows_grep_without_E_flag(self):
        # Plain grep (BRE): \\| is a GNU extension for alternation in BRE --
        # non-portable but functional; out of scope for this ERE guard
        snippet = "  grep 'foo\\|bar' somefile"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: grep (no -E) with \\\\| was incorrectly flagged: "
            f"{hits}",
        )

    def test_allows_echo_with_backslash_pipe(self):
        snippet = r"  echo 'pattern is foo\|bar'"
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: echo display string with \\\\| was incorrectly "
            f"flagged: {hits}",
        )

    def test_allowlist_injection_safe_not_flagged(self):
        # Mirrors the real injection.sh allowlisted line
        snippet = r"""  _py_xss=$(_code_grep '(mark_safe|Markup)\s*\(|__html__|autoescape\s+off|\|safe' "*.py,*.html")"""
        hits = _scan_text_lines(snippet, "injection.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: injection.sh \\|safe allowlist entry was incorrectly "
            f"flagged: {hits}",
        )

    def test_allowlist_solutions_curl_pipe_not_flagged(self):
        # Mirrors the real solutions.sh allowlisted line
        snippet = r'  if files_contain "Jenkinsfile" "(curl|wget).*(\\||;)[[:space:]]*(sh|bash)" 2>/dev/null; then'
        hits = _scan_text_lines(snippet, "solutions.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: solutions.sh (\\\\||;) allowlist entry was incorrectly "
            f"flagged: {hits}",
        )

    def test_allows_multiline_continuation_correct_ere(self):
        """
        A multi-line files_contain call where the pattern uses correct ERE
        (plain | alternation, no \\|) must NOT be flagged.

        files_contain "*.sh" \\
          "alpha|beta"
        """
        snippet = textwrap.dedent(
            """\
            files_contain "*.sh" \\
              "alpha|beta"
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: multi-line files_contain with correct ERE | was "
            f"incorrectly flagged: {hits}",
        )

    def test_allows_multiline_grep_continuation_correct_ere(self):
        """
        A multi-line grep -E call where the pattern on the continuation line
        uses correct ERE (plain |) must NOT be flagged.

        grep -E \\
          'foo|bar' file
        """
        snippet = textwrap.dedent(
            """\
            grep -E \\
              'foo|bar' file
            """
        )
        hits = _scan_text_lines(snippet, "synthetic.sh")
        self.assertFalse(
            hits,
            f"FALSE POSITIVE: multi-line grep -E with correct ERE | on the "
            f"continuation line was incorrectly flagged: {hits}",
        )


if __name__ == "__main__":
    unittest.main()
