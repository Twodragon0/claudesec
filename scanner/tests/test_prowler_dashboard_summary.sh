#!/usr/bin/env bash
# Unit tests for output.sh::_prowler_dashboard_summary()
# Run: bash scanner/tests/test_prowler_dashboard_summary.sh
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

source "$LIB_DIR/output.sh" 2>/dev/null || true

should_report() { return 0; }

# ==============================================================================
# Test Group 1: no prowler directory → returns 0 with no output
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary() — missing directory ==="

out="$(_prowler_dashboard_summary)"
assert_eq "missing dir: returns empty output" "" "$out"

# ==============================================================================
# Test Group 2: empty prowler directory → returns 0 with no output
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary() — empty directory ==="

prowler_dir="$tmpdir/.claudesec-prowler"
mkdir -p "$prowler_dir"

out="$(_prowler_dashboard_summary)"
assert_eq "empty dir: returns empty output" "" "$out"

# ==============================================================================
# Test Group 3: single AWS provider file with mixed severity findings
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary() — AWS provider ==="

# Fixture: 1 Critical FAIL, 2 High FAIL, 1 Medium FAIL, 1 Low FAIL, 1 PASS (ignored)
# Format follows what the function greps/awks for: "severity": "X" and "status_code": "FAIL"
cat > "$prowler_dir/prowler-aws.ocsf.json" <<'AWSEOF'
{"finding_info":{"title":"f1"},"severity": "Critical","status_code": "FAIL"}
{"finding_info":{"title":"f2"},"severity": "High","status_code": "FAIL"}
{"finding_info":{"title":"f3"},"severity": "High","status_code": "FAIL"}
{"finding_info":{"title":"f4"},"severity": "Medium","status_code": "FAIL"}
{"finding_info":{"title":"f5"},"severity": "Low","status_code": "FAIL"}
{"finding_info":{"title":"f6"},"severity": "High","status_code": "PASS"}
AWSEOF

out="$(_prowler_dashboard_summary)"

# Outer wrapper markers
assert_contains "aws: wrapper div class"       "$out" "class=\"findings prowler-report\""
assert_contains "aws: header emoji+text"       "$out" "Prowler 클라우드 리포트"
assert_contains "aws: provider column header"  "$out" "프로바이더"
assert_contains "aws: critical column header"  "$out" "치명적"

# Provider label transformation: aws → AWS
assert_contains "aws: label 'AWS'"             "$out" ">AWS<"

# Severity counts (5 FAILs total; 1C, 2H, 1M, 1L)
assert_contains "aws: total FAIL=5"            "$out" ">5<"
# Critical cell color marker + value
assert_contains "aws: critical cell color"     "$out" "color:#dc2626"
assert_contains "aws: high cell color"         "$out" "color:#ef4444"
assert_contains "aws: medium cell color"       "$out" "color:#eab308"

# Footer note references the artifact path
assert_contains "aws: footer artifact hint"    "$out" ".claudesec-prowler/prowler-*.ocsf.json"
assert_contains "aws: footer rerun command"    "$out" "claudesec scan -c prowler"

# ==============================================================================
# Test Group 4: multiple providers — labels & ordering
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary() — multiple providers ==="

# Add kubernetes and github provider files
cat > "$prowler_dir/prowler-kubernetes.ocsf.json" <<'KUBEEOF'
{"severity": "High","status_code": "FAIL"}
KUBEEOF

cat > "$prowler_dir/prowler-github.ocsf.json" <<'GHEOF'
{"severity": "Medium","status_code": "FAIL"}
{"severity": "Medium","status_code": "FAIL"}
GHEOF

out="$(_prowler_dashboard_summary)"

assert_contains "multi: AWS label"        "$out" ">AWS<"
assert_contains "multi: Kubernetes label" "$out" ">Kubernetes<"
assert_contains "multi: GitHub label"     "$out" ">GitHub<"

# Each provider gets its own <tr> row
rows=$(grep -c '<tr><td style="padding:0.5rem 0.75rem' <<< "$out" || true)
assert_eq "multi: three provider rows rendered" "3" "$rows"

# ==============================================================================
# Test Group 5: unknown provider name falls through to raw name
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary() — unknown provider ==="

# Start with a clean dir so only our unknown file is picked up
rm -f "$prowler_dir"/prowler-*.ocsf.json

cat > "$prowler_dir/prowler-madeupcloud.ocsf.json" <<'UEOF'
{"severity": "Low","status_code": "FAIL"}
UEOF

out="$(_prowler_dashboard_summary)"
assert_contains "unknown: raw provider name rendered" "$out" ">madeupcloud<"
assert_contains "unknown: total=1"                    "$out" ">1<"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
