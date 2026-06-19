#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh: coverage for previously-uncovered branches.
# Targets: _id_to_category (L651-668), _emit_finding_json FINDINGS_WARN/LOW (L697-701),
#          _print_finding_inline_fail severity-color branches (L93-99),
#          _prowler_dashboard_summary awk severity counter (L551-558),
#          load_scan_history multi-entry concat (L471),
#          _prowler_dashboard_summary_provider_label full switch.
# Run: bash scanner/tests/test_output_coverage.sh
set -uo pipefail

# Hermetic offline guard (PR #190): this test calls generate_html_dashboard(),
# which spawns dashboard-gen.py. Without offline mode that makes live GitHub API
# calls and can hang for minutes (root cause of the kcov 27min stalls). Force
# offline here so the test never depends on the network or on the CI job's env,
# and stays fast everywhere it runs.
export CLAUDESEC_DASHBOARD_OFFLINE=1

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

# Stub color codes
RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""

# Minimal required variables for output.sh to source cleanly
FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

source "$LIB_DIR/output.sh" 2>/dev/null || true
should_report() { return 0; }

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
# Test Group 1: _print_finding_inline_fail severity color branches (L93-99)
# The fail() function only emits the inline output when QUIET is unset and
# FORMAT=text. We turn off QUIET and ensure should_report passes so that
# the severity-specific color branch (medium → YELLOW, low → DIM) is exercised.
# ==============================================================================
echo ""
echo "=== fail() inline output: severity color branches (L93-99) ==="

_reset_state
QUIET=""
FORMAT="text"

# medium severity → YELLOW path (L94)
fail_med_out="$( set +x; fail "CHK-M01" "Medium title" "medium" "some detail" "fix med" "" 2>&1 )"
assert_contains "fail medium: FAIL marker present"  "$fail_med_out" "FAIL"
assert_contains "fail medium: id in output"         "$fail_med_out" "CHK-M01"
assert_contains "fail medium: title in output"      "$fail_med_out" "Medium title"
assert_contains "fail medium: detail shown"         "$fail_med_out" "some detail"
assert_contains "fail medium: remediation shown"    "$fail_med_out" "fix med"

# low severity → DIM path (L95)
_reset_state
QUIET=""
fail_low_out="$( set +x; fail "CHK-L01" "Low title" "low" "low detail" "fix low" "/some/file" 2>&1 )"
assert_contains "fail low: FAIL marker present"  "$fail_low_out" "FAIL"
assert_contains "fail low: id in output"         "$fail_low_out" "CHK-L01"
assert_contains "fail low: location shown"       "$fail_low_out" "/some/file"

# critical severity → RED path (L93); detail + remediation + no location
_reset_state
QUIET=""
fail_crit_out="$( set +x; fail "CHK-C01" "Critical title" "critical" "crit detail" "fix crit" "" 2>&1 )"
assert_contains "fail critical: FAIL marker"     "$fail_crit_out" "FAIL"
assert_contains "fail critical: detail shown"    "$fail_crit_out" "crit detail"
assert_not_contains "fail critical: no location" "$fail_crit_out" "📍"

# Verify empty details/remediation suppression works (L97-L99 branches not taken)
_reset_state
QUIET=""
fail_no_extra_out="$( set +x; fail "CHK-H01" "High no extras" "high" "" "" "" 2>&1 )"
assert_contains     "fail high no-extras: FAIL present"         "$fail_no_extra_out" "FAIL"
assert_not_contains "fail high no-extras: no detail line"       "$fail_no_extra_out" "→"
assert_not_contains "fail high no-extras: no location line"     "$fail_no_extra_out" "📍"

QUIET=1
FORMAT="text"

# ==============================================================================
# Test Group 2: _id_to_category() inside generate_html_dashboard (L651-668)
# This inner function is defined inside generate_html_dashboard(); to exercise
# it we call generate_html_dashboard() with scan data and verify the resulting
# scan-report.json categories, then check the FINDINGS_WARN/LOW emit loops
# (L697-701) are triggered.
# ==============================================================================
echo ""
echo "=== generate_html_dashboard: _id_to_category + FINDINGS_WARN/LOW emit (L651-701) ==="

_reset_state
TOTAL_CHECKS=6
PASSED=0
FAILED=4
WARNINGS=1
SKIPPED=0
SCAN_DURATION=0

# Populate all severity arrays including FINDINGS_WARN and FINDINGS_LOW to
# cover L697 (FINDINGS_WARN loop) and L700 (FINDINGS_LOW loop).
FINDINGS_CRITICAL+=("INFRA-001|Infra finding|critical|fix infra|d")
FINDINGS_HIGH+=("CODE-INJ-001|Code injection|high|fix code|d")
FINDINGS_MEDIUM+=("CLOUD-001|Cloud finding|medium|fix cloud|d")
FINDINGS_WARN+=("AI-001|AI warning|medium||warn detail")
FINDINGS_LOW+=("WIN-001|Windows low|low|fix win|d")

# Disable diagram-gen (no python script present in test env) to keep test fast
CLAUDESEC_GENERATE_DIAGRAMS=0

dash_file="$tmpdir/test_dashboard.html"
# We call generate_html_dashboard; if python3 + dashboard-gen.py are absent it
# falls through to the legacy generator — both paths write the output file.
generate_html_dashboard "$dash_file" 2>/dev/null || true

# Verify scan-report.json was written (L708-710) and contains expected fields
scan_report="$tmpdir/scan-report.json"
assert_eq "scan-report.json created" "true" "$([[ -f "$scan_report" ]] && echo true || echo false)"
report_content="$(cat "$scan_report" 2>/dev/null)"
assert_contains "scan-report: findings array"  "$report_content" '"findings":'
assert_contains "scan-report: passed field"    "$report_content" '"passed":0'
assert_contains "scan-report: failed field"    "$report_content" '"failed":4'

# The findings_json built by the _emit_finding_json inner function must contain
# entries from all arrays including WARN (L697) and LOW (L700-701).
assert_contains "scan-report: INFRA category (infra)"     "$report_content" '"category":"infra"'
assert_contains "scan-report: CODE category (code)"       "$report_content" '"category":"code"'
assert_contains "scan-report: CLOUD category (cloud)"     "$report_content" '"category":"cloud"'
assert_contains "scan-report: AI category (ai)"           "$report_content" '"category":"ai"'
assert_contains "scan-report: WIN category (windows)"     "$report_content" '"category":"windows"'
# WARN entry appears with severity=warning
assert_contains "scan-report: WARN entry severity=warning"  "$report_content" '"severity":"warning"'
# LOW entry appears with severity=low
assert_contains "scan-report: LOW entry severity=low"       "$report_content" '"severity":"low"'

# ==============================================================================
# Test Group 3: _id_to_category full branch matrix (L652-667)
# We use a helper that calls generate_html_dashboard with a single entry per
# prefix, then inspect scan-report.json for the expected category string.
# This covers all case arms: INFRA, NET/TLS, CICD, CODE/SAST/SECRETS/TRIVY,
# AI/LLM, CLOUD/AWS/GCP/AZURE, MAC/CIS, SAAS, WIN/KISA, PROWLER, DOCKER, other.
# ==============================================================================
echo ""
echo "=== _id_to_category (via generate_html_dashboard) — full switch L652-667 ==="

_exercise_category() {
  local id="$1" expected_cat="$2"
  _reset_state
  TOTAL_CHECKS=1; PASSED=0; FAILED=1; WARNINGS=0; SKIPPED=0; SCAN_DURATION=0
  FINDINGS_HIGH+=("${id}|Test title|high|fix|detail")
  CLAUDESEC_GENERATE_DIAGRAMS=0
  generate_html_dashboard "$tmpdir/cat_test.html" 2>/dev/null || true
  local content
  content="$(cat "$tmpdir/scan-report.json" 2>/dev/null)"
  assert_contains "_id_to_category ${id}: has ${expected_cat}" "$content" "\"category\":\"${expected_cat}\""
}

_exercise_category "IAM-001"     "access-control"
_exercise_category "INFRA-001"   "infra"
_exercise_category "NET-001"     "network"
_exercise_category "TLS-002"     "network"
_exercise_category "CICD-001"    "cicd"
_exercise_category "CODE-001"    "code"
_exercise_category "SAST-001"    "code"
_exercise_category "SECRETS-001" "code"
_exercise_category "TRIVY-001"   "code"
_exercise_category "AI-001"      "ai"
_exercise_category "LLM-001"     "ai"
_exercise_category "CLOUD-001"   "cloud"
_exercise_category "AWS-001"     "cloud"
_exercise_category "GCP-001"     "cloud"
_exercise_category "AZURE-001"   "cloud"
_exercise_category "MAC-001"     "macos"
_exercise_category "CIS-001"     "macos"
_exercise_category "SAAS-001"    "saas"
_exercise_category "WIN-001"     "windows"
_exercise_category "KISA-001"    "windows"
_exercise_category "PROWLER-001" "prowler"
_exercise_category "DOCKER-001"  "infra"
_exercise_category "FOO-001"     "other"

# ==============================================================================
# Test Group 4: _prowler_dashboard_summary awk severity counter (L551-558)
# We create a minimal .claudesec-prowler directory with a synthetic OCSF JSON
# fixture and call _prowler_dashboard_summary(), verifying it emits HTML with
# the correct counts. This exercises the awk block on L552-557.
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary awk severity counter (L551-558) ==="

prowler_dir="$tmpdir/.claudesec-prowler"
mkdir -p "$prowler_dir"

# Create a minimal OCSF JSON file with known severity/status_code values.
# The awk in _prowler_dashboard_summary uses pattern /"severity":/ then strips
# the prefix up to the opening quote of the value; the value must end with a quote.
# We write one JSON key per line so each awk pattern matches exactly one line.
# 2 Critical FAILs, 1 High FAIL, 1 Medium FAIL, 0 Low FAILs, 1 PASS (ignored).
cat > "$prowler_dir/prowler-aws.ocsf.json" <<'OCSF_EOF'
{"severity": "Critical",
"status_code": "FAIL",
"metadata": {"event_code": "iam-001"}}
{"severity": "Critical",
"status_code": "FAIL",
"metadata": {"event_code": "iam-002"}}
{"severity": "High",
"status_code": "FAIL",
"metadata": {"event_code": "s3-001"}}
{"severity": "Medium",
"status_code": "FAIL",
"metadata": {"event_code": "ec2-001"}}
{"severity": "Low",
"status_code": "PASS",
"metadata": {"event_code": "kms-001"}}
OCSF_EOF

OLD_SCAN_DIR="$SCAN_DIR"
SCAN_DIR="$tmpdir"
prowler_html="$( set +x; _prowler_dashboard_summary 2>/dev/null )"

assert_contains "prowler_summary: table header" "$prowler_html" "<table"
assert_contains "prowler_summary: aws label"    "$prowler_html" "AWS"
# Critical=2, High=1, Medium=1, Low=0 (awk counter END block)
assert_contains "prowler_summary: crit count 2"   "$prowler_html" ">2<"
assert_contains "prowler_summary: high count 1"   "$prowler_html" ">1<"
# Low=0 (awk counter END block emits 0)
assert_contains "prowler_summary: low count 0"    "$prowler_html" ">0<"
# Total FAIL count via grep -c
assert_contains "prowler_summary: total 4"        "$prowler_html" ">4<"

SCAN_DIR="$OLD_SCAN_DIR"

# ==============================================================================
# Test Group 5: _prowler_dashboard_summary_provider_label full switch
# ==============================================================================
echo ""
echo "=== _prowler_dashboard_summary_provider_label full switch ==="

assert_eq "provider_label: aws"            "AWS"             "$( set +x; _prowler_dashboard_summary_provider_label aws )"
assert_eq "provider_label: kubernetes"     "Kubernetes"      "$( set +x; _prowler_dashboard_summary_provider_label kubernetes )"
assert_eq "provider_label: azure"          "Azure"           "$( set +x; _prowler_dashboard_summary_provider_label azure )"
assert_eq "provider_label: gcp"            "GCP"             "$( set +x; _prowler_dashboard_summary_provider_label gcp )"
assert_eq "provider_label: github"         "GitHub"          "$( set +x; _prowler_dashboard_summary_provider_label github )"
assert_eq "provider_label: googleworkspace" "Google Workspace" "$( set +x; _prowler_dashboard_summary_provider_label googleworkspace )"
assert_eq "provider_label: m365"           "Microsoft 365"   "$( set +x; _prowler_dashboard_summary_provider_label m365 )"
assert_eq "provider_label: cloudflare"     "Cloudflare"      "$( set +x; _prowler_dashboard_summary_provider_label cloudflare )"
assert_eq "provider_label: nhn"            "NHN Cloud"       "$( set +x; _prowler_dashboard_summary_provider_label nhn )"
assert_eq "provider_label: iac"            "IaC"             "$( set +x; _prowler_dashboard_summary_provider_label iac )"
assert_eq "provider_label: llm"            "LLM"             "$( set +x; _prowler_dashboard_summary_provider_label llm )"
assert_eq "provider_label: image"          "Container Image" "$( set +x; _prowler_dashboard_summary_provider_label image )"
assert_eq "provider_label: oraclecloud"    "Oracle Cloud"    "$( set +x; _prowler_dashboard_summary_provider_label oraclecloud )"
assert_eq "provider_label: alibabacloud"   "Alibaba Cloud"   "$( set +x; _prowler_dashboard_summary_provider_label alibabacloud )"
assert_eq "provider_label: openstack"      "OpenStack"       "$( set +x; _prowler_dashboard_summary_provider_label openstack )"
assert_eq "provider_label: mongodbatlas"   "MongoDB Atlas"   "$( set +x; _prowler_dashboard_summary_provider_label mongodbatlas )"
assert_eq "provider_label: unknown passthrough" "custom-prov" "$( set +x; _prowler_dashboard_summary_provider_label custom-prov )"

# ==============================================================================
# Test Group 6: load_scan_history multi-entry concat (L471 entries="${entries},${content}")
# Two or more scan files → the entries are comma-joined inside the array.
# ==============================================================================
echo ""
echo "=== load_scan_history multi-entry concat (L471) ==="

hist_base="$(mktemp -d)"
OLD_SCAN_DIR2="$SCAN_DIR"
SCAN_DIR="$hist_base"

mkdir -p "$hist_base/.claudesec-history"
printf '{"timestamp":"2026-01-01T00:00:00Z","score":70,"passed":7,"failed":3,"warnings":0,"skipped":0,"total":10,"critical":0,"high":1,"medium":2,"low":0,"warn":0}\n' \
  > "$hist_base/.claudesec-history/scan-20260101T000000Z.json"
printf '{"timestamp":"2026-01-02T00:00:00Z","score":80,"passed":8,"failed":2,"warnings":0,"skipped":0,"total":10,"critical":0,"high":0,"medium":2,"low":0,"warn":0}\n' \
  > "$hist_base/.claudesec-history/scan-20260102T000000Z.json"

loaded="$( set +x; load_scan_history )"
# Must be a valid JSON array with both entries comma-separated (L471 exercises the branch)
assert_contains "load_scan_history multi: starts with ["  "$loaded" "["
assert_contains "load_scan_history multi: ends with ]"    "$loaded" "]"
assert_contains "load_scan_history multi: entry1 score70" "$loaded" '"score":70'
assert_contains "load_scan_history multi: entry2 score80" "$loaded" '"score":80'
# Comma between entries (the L471 concat branch)
assert_contains "load_scan_history multi: comma separator" "$loaded" '},'

SCAN_DIR="$OLD_SCAN_DIR2"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
