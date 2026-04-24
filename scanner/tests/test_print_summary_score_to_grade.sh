#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh::_print_summary_score_to_grade()
# Extracted pure helper: maps a numeric score (0-100) to "grade color".
# Run: bash scanner/tests/test_print_summary_score_to_grade.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((TEST_FAILED++))
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

# shellcheck disable=SC1091
source "$LIB_DIR/output.sh" 2>/dev/null || true

# Override color sentinels AFTER source (output.sh assigns them unconditionally).
# Using distinct placeholders lets us assert which color branch was selected
# without depending on raw ANSI escape bytes.
RED="RED" GREEN="GREEN" YELLOW="YELLOW" BLUE="" CYAN="" DIM="" NC="" BOLD="" MAGENTA=""

# Parse "grade color" into two variables.
_parse() {
  local out="$1"
  read -r _G _C <<< "$out"
  echo "$_G|$_C"
}

echo ""
echo "=== _print_summary_score_to_grade() ==="

# Grade A boundary (>=90)
assert_eq "score 100 → A GREEN" "A|GREEN" "$(_parse "$(_print_summary_score_to_grade 100)")"
assert_eq "score 95  → A GREEN" "A|GREEN" "$(_parse "$(_print_summary_score_to_grade 95)")"
assert_eq "score 90  → A GREEN" "A|GREEN" "$(_parse "$(_print_summary_score_to_grade 90)")"

# Grade B boundary (80..89)
assert_eq "score 89  → B GREEN" "B|GREEN" "$(_parse "$(_print_summary_score_to_grade 89)")"
assert_eq "score 80  → B GREEN" "B|GREEN" "$(_parse "$(_print_summary_score_to_grade 80)")"

# Grade C boundary (70..79)
assert_eq "score 79  → C YELLOW" "C|YELLOW" "$(_parse "$(_print_summary_score_to_grade 79)")"
assert_eq "score 70  → C YELLOW" "C|YELLOW" "$(_parse "$(_print_summary_score_to_grade 70)")"

# Grade D boundary (60..69)
assert_eq "score 69  → D YELLOW" "D|YELLOW" "$(_parse "$(_print_summary_score_to_grade 69)")"
assert_eq "score 60  → D YELLOW" "D|YELLOW" "$(_parse "$(_print_summary_score_to_grade 60)")"

# Grade F (<60)
assert_eq "score 59  → F RED" "F|RED" "$(_parse "$(_print_summary_score_to_grade 59)")"
assert_eq "score 30  → F RED" "F|RED" "$(_parse "$(_print_summary_score_to_grade 30)")"
assert_eq "score 0   → F RED" "F|RED" "$(_parse "$(_print_summary_score_to_grade 0)")"

# Single-line output (exactly one line)
lines=$(_print_summary_score_to_grade 85 | wc -l | tr -d ' ')
assert_eq "output is exactly 1 line" "1" "$lines"

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
