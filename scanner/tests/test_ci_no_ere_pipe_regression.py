"""
Regression guard: no `\\|` (backslash-pipe) in an ERE context inside
`scanner/checks/**/*.sh`.

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


def _scan_checks_dir(checks_dir: Path) -> list[tuple[Path, int, str]]:
    """
    Walk checks_dir recursively for *.sh files.
    Return a list of (filepath, lineno, line) for each violation:
    a line that (a) is in an ERE context, (b) contains \\|, and
    (c) is NOT allowlisted.
    """
    violations: list[tuple[Path, int, str]] = []
    for sh_file in sorted(checks_dir.rglob("*.sh")):
        for lineno, raw in enumerate(
            sh_file.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if r"\|" not in raw:
                continue
            if not _is_ere_context(raw):
                continue
            if _is_allowlisted(sh_file, raw):
                continue
            violations.append((sh_file, lineno, raw.rstrip()))
    return violations


def _scan_text_lines(
    source_text: str, filename: str = "<synthetic>"
) -> list[tuple[str, int, str]]:
    """Same logic as _scan_checks_dir but operates on a raw string (for tests)."""
    violations = []
    fake_path = Path(filename)
    for lineno, raw in enumerate(source_text.splitlines(), start=1):
        if r"\|" not in raw:
            continue
        if not _is_ere_context(raw):
            continue
        if _is_allowlisted(fake_path, raw):
            continue
        violations.append((filename, lineno, raw.rstrip()))
    return violations


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestChecksDirectoryExists(unittest.TestCase):
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


class TestNoEREPipeInChecks(unittest.TestCase):
    """
    Scans every scanner/checks/**/*.sh for \\| in an ERE context.
    Only the two explicitly allowlisted intentional occurrences are permitted.
    Any other \\| in an ERE pattern is flagged as a regression.
    """

    def test_no_unallowlisted_ere_pipe(self):
        violations = _scan_checks_dir(CHECKS_DIR)
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
            for sh_file in CHECKS_DIR.rglob("*.sh"):
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


if __name__ == "__main__":
    unittest.main()
