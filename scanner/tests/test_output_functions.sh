#!/usr/bin/env bash
# Unit tests for output.sh: fail(), append_json(), _emit_finding_json()
# Run: bash scanner/tests/test_output_functions.sh
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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected NOT to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Stub color codes so output.sh does not override them with ANSI escapes
RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""

# Variables output.sh and its callers need
FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

# Stub should_report() so fail() does not error on unset SEVERITY logic;
# override after sourcing so our stub wins.
source "$LIB_DIR/output.sh" 2>/dev/null || true

# Override should_report to always return true (we want fail() to count everything)
should_report() { return 0; }

# ── Helper: reset all state between test groups ────────────────────────────────
_reset_state() {
  TOTAL_CHECKS=0
  PASSED=0
  FAILED=0
  WARNINGS=0
  SKIPPED=0
  JSON_RESULTS="[]"
  FINDINGS_CRITICAL=()
  FINDINGS_HIGH=()
  FINDINGS_MEDIUM=()
  FINDINGS_LOW=()
  FINDINGS_WARN=()
}

# ==============================================================================
# Test Group 1: append_json()
# ==============================================================================
echo ""
echo "=== append_json() ==="

# 1. Basic fields
_reset_state
append_json "CHK-001" "Test title" "fail" "Some details" "high"
assert_contains "basic: id field"       "$JSON_RESULTS" '"id":"CHK-001"'
assert_contains "basic: status field"   "$JSON_RESULTS" '"status":"fail"'
assert_contains "basic: severity field" "$JSON_RESULTS" '"severity":"high"'

# 2. With location param
_reset_state
append_json "CHK-001" "Test title" "fail" "details" "high" "/path/to/file"
assert_contains "with location: location field" "$JSON_RESULTS" '"location":"/path/to/file"'

# 3. Escapes double-quotes in title
_reset_state
append_json "CHK-001" 'Test "quoted" title' "fail" "details" "high"
assert_contains "escape quotes: backslash-quote present" "$JSON_RESULTS" '\"quoted\"'

# 4. Multiple entries produce valid bracketed array with comma separator
_reset_state
append_json "CHK-001" "First"  "fail" "" "high"
append_json "CHK-002" "Second" "pass" "" "low"
assert_contains "multiple: starts with ["    "$JSON_RESULTS" '['
assert_contains "multiple: ends with ]"      "$JSON_RESULTS" ']'
assert_contains "multiple: comma separator"  "$JSON_RESULTS" ',{'

# 5. No location param → no location key in output
_reset_state
append_json "CHK-001" "No location" "pass" "" ""
assert_not_contains "empty location: no location key" "$JSON_RESULTS" '"location"'

# ==============================================================================
# Test Group 2: fail()
# ==============================================================================
echo ""
echo "=== fail() ==="

# 1. Increments TOTAL_CHECKS and FAILED
_reset_state
fail "CHK-002" "Bad config" "high" "details here" "fix it" "/etc/config"
assert_eq "counters: TOTAL_CHECKS=1" "1" "$TOTAL_CHECKS"
assert_eq "counters: FAILED=1"       "1" "$FAILED"

# 2. High severity → FINDINGS_HIGH
_reset_state
fail "CHK-002" "High finding" "high" "d" "r" ""
assert_eq "high: FINDINGS_HIGH has 1 entry" "1" "${#FINDINGS_HIGH[@]}"

# 3. Critical severity → FINDINGS_CRITICAL
_reset_state
fail "CHK-003" "Critical finding" "critical" "d" "r" ""
assert_eq "critical: FINDINGS_CRITICAL has 1 entry" "1" "${#FINDINGS_CRITICAL[@]}"

# 4. Medium severity → FINDINGS_MEDIUM
_reset_state
fail "CHK-004" "Medium finding" "medium" "d" "r" ""
assert_eq "medium: FINDINGS_MEDIUM has 1 entry" "1" "${#FINDINGS_MEDIUM[@]}"

# 5. Low severity → FINDINGS_LOW
_reset_state
fail "CHK-005" "Low finding" "low" "d" "r" ""
assert_eq "low: FINDINGS_LOW has 1 entry" "1" "${#FINDINGS_LOW[@]}"

# 6. Location appears in the FINDINGS_HIGH entry string
_reset_state
fail "CHK-006" "High with loc" "high" "details" "remediate" "/k8s/pod.yaml"
assert_contains "location in FINDINGS_HIGH entry" "${FINDINGS_HIGH[0]}" "/k8s/pod.yaml"

# ==============================================================================
# Test Group 3: pipe-delimited format (indirect _emit_finding_json testing)
# ==============================================================================
echo ""
echo "=== pipe-delimited entry format (for _emit_finding_json) ==="

# 1. Entry has 6 pipe-delimited fields in order: id|title|severity|remediation|details|location
_reset_state
fail "CHK-010" "Pipe test" "high" "detail text" "fix text" "/some/file"
entry="${FINDINGS_HIGH[0]}"
IFS='|' read -r f_id f_title f_sev f_fix f_details f_loc <<< "$entry"
assert_eq "pipe format: field 1 = id"          "CHK-010"    "$f_id"
assert_eq "pipe format: field 2 = title"       "Pipe test"  "$f_title"
assert_eq "pipe format: field 3 = severity"    "high"       "$f_sev"
assert_eq "pipe format: field 4 = remediation" "fix text"   "$f_fix"
assert_eq "pipe format: field 5 = details"     "detail text" "$f_details"
assert_eq "pipe format: field 6 = location"    "/some/file" "$f_loc"

# 2. Location (field 6) is preserved correctly
_reset_state
fail "CHK-011" "Loc test" "high" "" "" "/k8s/deployment.yaml"
entry="${FINDINGS_HIGH[0]}"
IFS='|' read -r _ _ _ _ _ f_loc2 <<< "$entry"
assert_eq "pipe format: location field preserved" "/k8s/deployment.yaml" "$f_loc2"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
