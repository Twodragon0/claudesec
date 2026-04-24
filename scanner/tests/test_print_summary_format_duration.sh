#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh::_print_summary_format_duration()
# Extracted pure helper: formats integer seconds as "Xm Ys" (>=60) or "Zs".
# Run: bash scanner/tests/test_print_summary_format_duration.sh
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

RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""
FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

# shellcheck disable=SC1091
source "$LIB_DIR/output.sh" 2>/dev/null || true

echo ""
echo "=== _print_summary_format_duration() ==="

# Sub-minute values → "Zs"
assert_eq "0 seconds"  "0s"  "$(_print_summary_format_duration 0)"
assert_eq "1 second"   "1s"  "$(_print_summary_format_duration 1)"
assert_eq "30 seconds" "30s" "$(_print_summary_format_duration 30)"
assert_eq "59 seconds" "59s" "$(_print_summary_format_duration 59)"

# 60s boundary → "1m 0s" (not "60s")
assert_eq "60 boundary" "1m 0s" "$(_print_summary_format_duration 60)"

# Minute + second combinations
assert_eq "61 seconds"   "1m 1s"  "$(_print_summary_format_duration 61)"
assert_eq "90 seconds"   "1m 30s" "$(_print_summary_format_duration 90)"
assert_eq "119 seconds"  "1m 59s" "$(_print_summary_format_duration 119)"
assert_eq "120 seconds"  "2m 0s"  "$(_print_summary_format_duration 120)"
assert_eq "125 seconds"  "2m 5s"  "$(_print_summary_format_duration 125)"
assert_eq "3600 seconds" "60m 0s" "$(_print_summary_format_duration 3600)"

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
