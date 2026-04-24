#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh::_print_summary_render_progress_bar()
# Extracted pure helper: builds a unicode progress bar from (score, width).
# Run: bash scanner/tests/test_print_summary_render_progress_bar.sh
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
    echo "    expected: [$expected]"
    echo "    actual:   [$actual]"
    ((TEST_FAILED++))
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""
FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

# shellcheck disable=SC1091
source "$LIB_DIR/output.sh" 2>/dev/null || true

# Helper to count occurrences of a substring
_count() {
  local s="$1" needle="$2"
  awk -v n="$needle" '{ c += gsub(n, n) } END { print c+0 }' <<< "$s"
}

echo ""
echo "=== _print_summary_render_progress_bar() ==="

# Score 0 with width 30 → all empty
bar0="$(_print_summary_render_progress_bar 0 30)"
assert_eq "score 0 width 30: 0 filled"  "0"  "$(_count "$bar0" "█")"
assert_eq "score 0 width 30: 30 empty"  "30" "$(_count "$bar0" "░")"

# Score 100 with width 30 → all filled
bar100="$(_print_summary_render_progress_bar 100 30)"
assert_eq "score 100 width 30: 30 filled" "30" "$(_count "$bar100" "█")"
assert_eq "score 100 width 30: 0 empty"   "0"  "$(_count "$bar100" "░")"

# Score 50 with width 30 → 15 filled + 15 empty (integer math: 50*30/100=15)
bar50="$(_print_summary_render_progress_bar 50 30)"
assert_eq "score 50 width 30: 15 filled" "15" "$(_count "$bar50" "█")"
assert_eq "score 50 width 30: 15 empty"  "15" "$(_count "$bar50" "░")"

# Score 75 with width 30 → 22 filled + 8 empty (75*30/100=22 via int math)
bar75="$(_print_summary_render_progress_bar 75 30)"
assert_eq "score 75 width 30: 22 filled" "22" "$(_count "$bar75" "█")"
assert_eq "score 75 width 30: 8 empty"   "8"  "$(_count "$bar75" "░")"

# Total bar length always equals width (sum of filled + empty)
assert_eq "score 33 width 10: total length = 10" "10" "$(_count "$(_print_summary_render_progress_bar 33 10)" "[█░]")"

# Custom width 10, score 10 → 1 filled + 9 empty
bar_w10="$(_print_summary_render_progress_bar 10 10)"
assert_eq "score 10 width 10: 1 filled" "1" "$(_count "$bar_w10" "█")"
assert_eq "score 10 width 10: 9 empty"  "9" "$(_count "$bar_w10" "░")"

# Produces no trailing newline (printf, not echo)
captured="$(_print_summary_render_progress_bar 100 3)"
# In a command substitution, trailing newlines are stripped, so this is a
# structural check: the raw bytes should only be box-drawing chars, no spaces.
assert_eq "score 100 width 3 body exact" "███" "$captured"

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
