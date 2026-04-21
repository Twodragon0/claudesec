#!/usr/bin/env bash
# Unit tests for output.sh::generate_html_dashboard()
# Focus: scan-report.json persistence + HTML output (legacy fallback path)
# Run: bash scanner/tests/test_generate_html_dashboard.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR_REAL="$SCRIPT_DIR/../lib"

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
    ((TEST_FAILED++))
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Stub color codes so sourcing output.sh does not inject ANSI escapes
RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""

FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

source "$LIB_DIR_REAL/output.sh" 2>/dev/null || true

should_report() { return 0; }

# ==============================================================================
# Test Group 1: legacy fallback path (python generator unavailable)
# ==============================================================================
echo ""
echo "=== generate_html_dashboard() — legacy fallback ==="

# Force legacy fallback by pointing LIB_DIR at a directory without dashboard-gen.py
LIB_DIR="$tmpdir/no-py"
mkdir -p "$LIB_DIR"

# Minimal state: no findings, trivial counters
TOTAL_CHECKS=2
PASSED=2
FAILED=0
WARNINGS=0
SKIPPED=0
FINDINGS_CRITICAL=()
FINDINGS_HIGH=()
FINDINGS_MEDIUM=()
FINDINGS_LOW=()
FINDINGS_WARN=()

# Disable diagram generation side effect (diagram-gen.py may not exist in test LIB_DIR)
CLAUDESEC_GENERATE_DIAGRAMS=0

out_html="$tmpdir/dashboard.html"
generate_html_dashboard "$out_html"

assert_eq "empty findings: html file created" "true" "$([[ -f "$out_html" ]] && echo true || echo false)"
html_content="$(cat "$out_html")"
assert_contains "empty findings: legacy html tag"        "$html_content" "<html>"
assert_contains "empty findings: legacy body tag"        "$html_content" "<body>"
assert_contains "empty findings: legacy dashboard title" "$html_content" "ClaudeSec Dashboard"

# scan-report.json is always written, regardless of dashboard generator availability
scan_report="$SCAN_DIR/scan-report.json"
assert_eq "scan-report.json created" "true" "$([[ -f "$scan_report" ]] && echo true || echo false)"
report_content="$(cat "$scan_report")"
assert_contains "scan-report: passed field"  "$report_content" '"passed":2'
assert_contains "scan-report: failed field"  "$report_content" '"failed":0'
assert_contains "scan-report: total field"   "$report_content" '"total":2'
assert_contains "scan-report: score=100"     "$report_content" '"score":100'
assert_contains "scan-report: grade=A"       "$report_content" '"grade":"A"'
assert_contains "scan-report: findings key"  "$report_content" '"findings":['

# ==============================================================================
# Test Group 2: findings are serialized into scan-report.json
# ==============================================================================
echo ""
echo "=== generate_html_dashboard() — findings serialization ==="

rm -f "$scan_report" "$out_html"

TOTAL_CHECKS=4
PASSED=1
FAILED=3
WARNINGS=0
SKIPPED=0
FINDINGS_CRITICAL=("IAM-001|Root key exposed|critical|Rotate now|Key present in .env|/app/.env")
FINDINGS_HIGH=("NET-010|TLS 1.0 enabled|high|Disable TLS 1.0|Legacy protocol|")
FINDINGS_MEDIUM=("CICD-020|No branch protection|medium|Enable protection||")
FINDINGS_LOW=()
FINDINGS_WARN=()

generate_html_dashboard "$out_html"

assert_eq "with findings: html file created" "true" "$([[ -f "$out_html" ]] && echo true || echo false)"
assert_eq "with findings: scan-report.json created" "true" "$([[ -f "$scan_report" ]] && echo true || echo false)"

report_content="$(cat "$scan_report")"
# active = TOTAL_CHECKS - SKIPPED = 4; score = PASSED*100/active = 25
assert_contains "scan-report: score=25"              "$report_content" '"score":25'
assert_contains "scan-report: grade=F"               "$report_content" '"grade":"F"'
assert_contains "scan-report: failed=3"              "$report_content" '"failed":3'
assert_contains "scan-report: critical id present"   "$report_content" '"id":"IAM-001"'
assert_contains "scan-report: high id present"       "$report_content" '"id":"NET-010"'
assert_contains "scan-report: medium id present"     "$report_content" '"id":"CICD-020"'
assert_contains "scan-report: critical severity"     "$report_content" '"severity":"critical"'
assert_contains "scan-report: high severity"         "$report_content" '"severity":"high"'
assert_contains "scan-report: medium severity"       "$report_content" '"severity":"medium"'
# Category mapping (IAM→access-control, NET→network, CICD→cicd)
assert_contains "scan-report: IAM→access-control"    "$report_content" '"category":"access-control"'
assert_contains "scan-report: NET→network"           "$report_content" '"category":"network"'
assert_contains "scan-report: CICD→cicd"             "$report_content" '"category":"cicd"'
# Location passthrough for entries that have one
assert_contains "scan-report: location preserved"    "$report_content" '"location":"/app/.env"'

# ==============================================================================
# Test Group 3: grade thresholds
# ==============================================================================
echo ""
echo "=== generate_html_dashboard() — grade thresholds ==="

_check_grade() {
  local label="$1" passed="$2" total="$3" expected_grade="$4" expected_score="$5"
  rm -f "$scan_report" "$out_html"
  TOTAL_CHECKS="$total"
  PASSED="$passed"
  FAILED=$(( total - passed ))
  WARNINGS=0
  SKIPPED=0
  FINDINGS_CRITICAL=()
  FINDINGS_HIGH=()
  FINDINGS_MEDIUM=()
  FINDINGS_LOW=()
  FINDINGS_WARN=()
  generate_html_dashboard "$out_html"
  local rc; rc="$(cat "$scan_report")"
  assert_contains "$label: grade"  "$rc" "\"grade\":\"$expected_grade\""
  assert_contains "$label: score"  "$rc" "\"score\":$expected_score"
}

_check_grade "grade A (95/100)"   95  100 A 95
_check_grade "grade B (85/100)"   85  100 B 85
_check_grade "grade C (75/100)"   75  100 C 75
_check_grade "grade D (65/100)"   65  100 D 65
_check_grade "grade F (40/100)"   40  100 F 40

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
