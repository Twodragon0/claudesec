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
# Test Group 4: print_banner / section / category_label
# ==============================================================================
echo ""
echo "=== print_banner / section / category_label ==="

# Need VERSION, SCAN_DIR, CATEGORY, SEVERITY defined for print_banner
CATEGORY="all"
banner_out="$(print_banner 2>&1)"
assert_contains "print_banner: name present"    "$banner_out" "ClaudeSec Scanner"
assert_contains "print_banner: VERSION present" "$banner_out" "test"
assert_contains "print_banner: scan dir shown"  "$banner_out" "$tmpdir"
assert_contains "print_banner: category shown"  "$banner_out" "all"
assert_contains "print_banner: severity shown"  "$banner_out" "low"

section_out="$(section "Hello Title" 2>&1)"
assert_contains "section: contains title"  "$section_out" "Hello Title"
assert_contains "section: delimiter shown" "$section_out" "━"

assert_eq "category_label: infra"          "Infrastructure Security"          "$(category_label infra)"
assert_eq "category_label: ai"             "AI / LLM Security"                "$(category_label ai)"
assert_eq "category_label: network"        "Network Security"                 "$(category_label network)"
assert_eq "category_label: cloud"          "Cloud Security (AWS/GCP/Azure)"   "$(category_label cloud)"
assert_eq "category_label: access-control" "Access Control & IAM"             "$(category_label access-control)"
assert_eq "category_label: cicd"           "CI/CD Pipeline Security"          "$(category_label cicd)"
assert_eq "category_label: code"           "Code Vulnerability Analysis (SAST)" "$(category_label code)"
assert_eq "category_label: macos"          "macOS / CIS Benchmark Security"   "$(category_label macos)"
assert_eq "category_label: saas"           "SaaS & Solutions Security"        "$(category_label saas)"
assert_eq "category_label: windows"        "Windows Security (KISA)"          "$(category_label windows)"
assert_eq "category_label: prowler"        "Prowler Deep Scan (Multi-Cloud)"  "$(category_label prowler)"
assert_eq "category_label: unknown passes through" "mystery" "$(category_label mystery)"

# ==============================================================================
# Test Group 5: pass() / warn() / skip() + colored wrappers
# ==============================================================================
echo ""
echo "=== pass / warn / skip / info / success / warning / error ==="

# pass(): bumps counters and emits JSON entry; QUIET=1 means nothing printed.
_reset_state
pass "CHK-P1" "Good config" "all ok"
assert_eq "pass: TOTAL_CHECKS=1" "1" "$TOTAL_CHECKS"
assert_eq "pass: PASSED=1"       "1" "$PASSED"
assert_contains "pass: JSON status" "$JSON_RESULTS" '"status":"pass"'
assert_contains "pass: JSON id"     "$JSON_RESULTS" '"id":"CHK-P1"'

# pass() with non-quiet output
_reset_state
QUIET=""
pass_out="$(pass "CHK-P2" "Another good" "details here" 2>&1)"
assert_contains "pass verbose: title in output"   "$pass_out" "Another good"
assert_contains "pass verbose: details in output" "$pass_out" "details here"
assert_contains "pass verbose: PASS marker"       "$pass_out" "PASS"
QUIET=1

# warn() appends to FINDINGS_WARN and bumps WARNINGS
_reset_state
warn "CHK-W1" "Best practice" "some detail"
assert_eq "warn: WARNINGS=1"            "1" "$WARNINGS"
assert_eq "warn: TOTAL_CHECKS=1"        "1" "$TOTAL_CHECKS"
assert_eq "warn: FINDINGS_WARN has 1"   "1" "${#FINDINGS_WARN[@]}"
assert_contains "warn: JSON warning status" "$JSON_RESULTS" '"status":"warning"'

# warn() with non-quiet output
_reset_state
QUIET=""
warn_out="$(warn "CHK-W2" "A warn title" "warn detail" 2>&1)"
assert_contains "warn verbose: WARN marker" "$warn_out" "WARN"
assert_contains "warn verbose: title shown" "$warn_out" "A warn title"
assert_contains "warn verbose: detail shown" "$warn_out" "warn detail"
QUIET=1

# skip() bumps SKIPPED and TOTAL_CHECKS; does not write to JSON_RESULTS
_reset_state
skip "CHK-S1" "Skipped check" "no target host"
assert_eq "skip: SKIPPED=1"       "1" "$SKIPPED"
assert_eq "skip: TOTAL_CHECKS=1"  "1" "$TOTAL_CHECKS"
assert_eq "skip: JSON untouched"  "[]" "$JSON_RESULTS"

# skip() with non-quiet output prints the reason
_reset_state
QUIET=""
skip_out="$(skip "CHK-S2" "Skipped again" "no host" 2>&1)"
assert_contains "skip verbose: SKIP marker" "$skip_out" "SKIP"
assert_contains "skip verbose: reason shown" "$skip_out" "no host"
QUIET=1

# info() emits only when FORMAT=text
info_out="$(info "hello info" 2>&1)"
assert_contains "info: text emits message" "$info_out" "hello info"

OLD_FORMAT="$FORMAT"
FORMAT="json"
info_json_out="$(info "should not print" 2>&1)"
assert_eq "info: json format produces no output" "" "$info_json_out"
FORMAT="$OLD_FORMAT"

# success / warning / error wrappers
assert_contains "success: text emitted" "$(success "done!" 2>&1)" "done!"
assert_contains "warning: text emitted" "$(warning "be careful" 2>&1)" "be careful"
# error() writes to stderr
error_out="$(error "oops" 2>&1 1>/dev/null)"
assert_contains "error: text emitted on stderr" "$error_out" "oops"

# ==============================================================================
# Test Group 6: should_report() - all severity modes
# ==============================================================================
echo ""
echo "=== should_report() ==="

# Remove our earlier stub so the real function is tested
unset -f should_report
source "$LIB_DIR/output.sh" 2>/dev/null || true

OLD_SEV="$SEVERITY"

SEVERITY="all"
should_report critical && sr_all_crit=true || sr_all_crit=false
should_report low      && sr_all_low=true  || sr_all_low=false
assert_eq "should_report all: critical passes" "true" "$sr_all_crit"
assert_eq "should_report all: low passes"      "true" "$sr_all_low"

SEVERITY="critical"
should_report critical && r=true || r=false
assert_eq "should_report critical: critical yes" "true" "$r"
should_report high     && r=true || r=false
assert_eq "should_report critical: high no"      "false" "$r"
should_report medium   && r=true || r=false
assert_eq "should_report critical: medium no"    "false" "$r"
should_report low      && r=true || r=false
assert_eq "should_report critical: low no"       "false" "$r"

SEVERITY="high"
should_report critical && r=true || r=false
assert_eq "should_report high: critical yes" "true" "$r"
should_report high     && r=true || r=false
assert_eq "should_report high: high yes"     "true" "$r"
should_report medium   && r=true || r=false
assert_eq "should_report high: medium no"    "false" "$r"
should_report low      && r=true || r=false
assert_eq "should_report high: low no"       "false" "$r"

SEVERITY="medium"
should_report critical && r=true || r=false
assert_eq "should_report medium: critical yes" "true" "$r"
should_report high     && r=true || r=false
assert_eq "should_report medium: high yes"     "true" "$r"
should_report medium   && r=true || r=false
assert_eq "should_report medium: medium yes"   "true" "$r"
should_report low      && r=true || r=false
assert_eq "should_report medium: low no"       "false" "$r"

SEVERITY="low"
should_report critical && r=true || r=false
assert_eq "should_report low: critical yes" "true" "$r"
should_report low      && r=true || r=false
assert_eq "should_report low: low yes"      "true" "$r"

SEVERITY="$OLD_SEV"
# Restore stub for subsequent tests
should_report() { return 0; }

# ==============================================================================
# Test Group 7: html_escape()
# ==============================================================================
echo ""
echo "=== html_escape() ==="

assert_eq "html_escape: amp"      "&amp;"             "$(html_escape '&')"
assert_eq "html_escape: lt"       "&lt;"              "$(html_escape '<')"
assert_eq "html_escape: gt"       "&gt;"              "$(html_escape '>')"
assert_eq "html_escape: dquote"   "&quot;"            "$(html_escape '"')"
assert_eq "html_escape: squote"   "&#x27;"            "$(html_escape "'")"
assert_eq "html_escape: plain"    "Hello World"       "$(html_escape "Hello World")"
assert_eq "html_escape: mixed"    "a&amp;b&lt;c&gt;d" "$(html_escape 'a&b<c>d')"
assert_eq "html_escape: empty"    ""                  "$(html_escape '')"
assert_contains "html_escape: script tag" "$(html_escape '<script>alert(1)</script>')" "&lt;script&gt;"

# ==============================================================================
# Test Group 8: _finding_ref_url() - ID prefix mapping
# ==============================================================================
echo ""
echo "=== _finding_ref_url() ==="

assert_contains "ref_url: CODE-INJ-*"     "$(_finding_ref_url CODE-INJ-001)"  "A03_2021-Injection"
assert_contains "ref_url: CODE-SEC-001"   "$(_finding_ref_url CODE-SEC-001)"  "Cryptographic_Failures"
assert_contains "ref_url: CODE-SEC-002"   "$(_finding_ref_url CODE-SEC-002)"  "Software_and_Data_Integrity"
assert_contains "ref_url: CODE-SEC-003"   "$(_finding_ref_url CODE-SEC-003)"  "Authentication_Failures"
assert_contains "ref_url: SECRETS-*"      "$(_finding_ref_url SECRETS-ENV)"   "Authentication_Failures"
assert_contains "ref_url: CODE-SEC-other" "$(_finding_ref_url CODE-SEC-999)"  "owasp.org/Top10/"
assert_contains "ref_url: CICD-*"         "$(_finding_ref_url CICD-001)"      "ci-cd-security-risks"
assert_contains "ref_url: AI-*"           "$(_finding_ref_url AI-001)"        "large-language-model"
assert_contains "ref_url: LLM-*"          "$(_finding_ref_url LLM-010)"       "large-language-model"
assert_contains "ref_url: IAM-*"          "$(_finding_ref_url IAM-001)"       "A01_2021-Broken_Access_Control"
assert_contains "ref_url: NET-*"          "$(_finding_ref_url NET-001)"       "Cryptographic_Failures"
assert_contains "ref_url: TLS-*"          "$(_finding_ref_url TLS-002)"       "Cryptographic_Failures"
assert_contains "ref_url: INFRA-*"        "$(_finding_ref_url INFRA-001)"     "cisecurity.org/benchmark/docker"
assert_contains "ref_url: DOCKER-*"       "$(_finding_ref_url DOCKER-003)"    "cisecurity.org/benchmark/docker"
assert_contains "ref_url: MAC-*"          "$(_finding_ref_url MAC-001)"       "cisecurity.org/benchmark/apple_os"
assert_contains "ref_url: CIS-*"          "$(_finding_ref_url CIS-001)"       "cisecurity.org/benchmark/apple_os"
assert_contains "ref_url: WIN-*"          "$(_finding_ref_url WIN-001)"       "kisa.or.kr"
assert_contains "ref_url: KISA-*"         "$(_finding_ref_url KISA-001)"      "kisa.or.kr"
assert_contains "ref_url: CLOUD-*"        "$(_finding_ref_url CLOUD-001)"     "aws.amazon.com/securityhub"
assert_contains "ref_url: AWS-*"          "$(_finding_ref_url AWS-001)"       "aws.amazon.com/securityhub"
assert_contains "ref_url: SAAS-ZIA-*"     "$(_finding_ref_url SAAS-ZIA-001)"  "help.zscaler.com"
assert_contains "ref_url: SAAS-API-*"     "$(_finding_ref_url SAAS-API-001)"  "A01_2021-Broken_Access_Control"
assert_contains "ref_url: SAAS-other"     "$(_finding_ref_url SAAS-OTHER)"    "A01_2021-Broken_Access_Control"
assert_contains "ref_url: TRIVY-*"        "$(_finding_ref_url TRIVY-001)"     "aquasecurity.github.io/trivy"
assert_contains "ref_url: PROWLER-*"      "$(_finding_ref_url PROWLER-001)"   "hub.prowler.com"
assert_eq       "ref_url: unknown empty"  ""                                  "$(_finding_ref_url UNKNOWN-001)"

# ==============================================================================
# Test Group 9: _finding_id_to_category() - full branch matrix
# ==============================================================================
echo ""
echo "=== _finding_id_to_category() ==="

assert_eq "cat: IAM"     "access-control" "$(_finding_id_to_category IAM-001)"
assert_eq "cat: INFRA"   "infra"          "$(_finding_id_to_category INFRA-001)"
assert_eq "cat: NET"     "network"        "$(_finding_id_to_category NET-001)"
assert_eq "cat: TLS"     "network"        "$(_finding_id_to_category TLS-002)"
assert_eq "cat: CICD"    "cicd"           "$(_finding_id_to_category CICD-007)"
assert_eq "cat: CODE"    "code"           "$(_finding_id_to_category CODE-INJ-1)"
assert_eq "cat: SAST"    "code"           "$(_finding_id_to_category SAST-001)"
assert_eq "cat: AI"      "ai"             "$(_finding_id_to_category AI-001)"
assert_eq "cat: LLM"     "ai"             "$(_finding_id_to_category LLM-010)"
assert_eq "cat: CLOUD"   "cloud"          "$(_finding_id_to_category CLOUD-001)"
assert_eq "cat: AWS"     "cloud"          "$(_finding_id_to_category AWS-001)"
assert_eq "cat: GCP"     "cloud"          "$(_finding_id_to_category GCP-001)"
assert_eq "cat: AZURE"   "cloud"          "$(_finding_id_to_category AZURE-001)"
assert_eq "cat: MAC"     "macos"          "$(_finding_id_to_category MAC-001)"
assert_eq "cat: CIS"     "macos"          "$(_finding_id_to_category CIS-001)"
assert_eq "cat: SAAS"    "saas"           "$(_finding_id_to_category SAAS-API-1)"
assert_eq "cat: WIN"     "windows"        "$(_finding_id_to_category WIN-001)"
assert_eq "cat: KISA"    "windows"        "$(_finding_id_to_category KISA-001)"
assert_eq "cat: PROWLER" "prowler"        "$(_finding_id_to_category PROWLER-1)"
assert_eq "cat: SECRETS" "code"           "$(_finding_id_to_category SECRETS-01)"
assert_eq "cat: TRIVY"   "code"           "$(_finding_id_to_category TRIVY-CVE1)"
assert_eq "cat: DOCKER"  "infra"          "$(_finding_id_to_category DOCKER-01)"
assert_eq "cat: unknown" "other"          "$(_finding_id_to_category FOO-001)"

# ==============================================================================
# Test Group 10: _print_findings()
# ==============================================================================
echo ""
echo "=== _print_findings() ==="

_reset_state
FINDINGS_HIGH+=("CHK-100|High finding title|high|fix this now|details")
FINDINGS_HIGH+=("CHK-101|Second high|high|remediate me|more details")
pf_out="$(_print_findings FINDINGS_HIGH "HIGH" true 2>&1)"
assert_contains "_print_findings: first id"       "$pf_out" "CHK-100"
assert_contains "_print_findings: second id"      "$pf_out" "CHK-101"
assert_contains "_print_findings: first title"    "$pf_out" "High finding title"
assert_contains "_print_findings: fix shown"      "$pf_out" "fix this now"
assert_contains "_print_findings: label present"  "$pf_out" "HIGH"

# show_fix=false suppresses fix text
_reset_state
FINDINGS_MEDIUM+=("CHK-200|Medium title|medium|should be hidden|d")
pf_out2="$(_print_findings FINDINGS_MEDIUM "MED" false 2>&1)"
assert_contains     "_print_findings(no fix): id shown"    "$pf_out2" "CHK-200"
assert_not_contains "_print_findings(no fix): fix hidden"  "$pf_out2" "should be hidden"

# Empty array → no output
_reset_state
pf_empty="$(_print_findings FINDINGS_LOW "LOW" true 2>&1)"
assert_eq "_print_findings: empty array no output" "" "$pf_empty"

# ==============================================================================
# Test Group 11: print_summary()
# ==============================================================================
echo ""
echo "=== print_summary() ==="

# Grade A path (score >= 90)
_reset_state
TOTAL_CHECKS=10; PASSED=10; FAILED=0; WARNINGS=0; SKIPPED=0
ps_a="$(print_summary 5 2>&1)"
assert_contains "print_summary A: score 100" "$ps_a" "100"
assert_contains "print_summary A: grade A"   "$ps_a" "Grade:"
assert_contains "print_summary A: dashboard heading" "$ps_a" "SCAN DASHBOARD"
assert_contains "print_summary A: seconds shown"     "$ps_a" "5s"

# Grade B path (80 <= score < 90)
_reset_state
TOTAL_CHECKS=10; PASSED=8; FAILED=2; WARNINGS=0; SKIPPED=0
ps_b="$(print_summary 10 2>&1)"
assert_contains "print_summary B: score 80" "$ps_b" "80"

# Grade C path (70 <= score < 80)
_reset_state
TOTAL_CHECKS=10; PASSED=7; FAILED=3; WARNINGS=0; SKIPPED=0
ps_c="$(print_summary 10 2>&1)"
assert_contains "print_summary C: score 70" "$ps_c" "70"

# Grade D path (60 <= score < 70)
_reset_state
TOTAL_CHECKS=10; PASSED=6; FAILED=4; WARNINGS=0; SKIPPED=0
ps_d="$(print_summary 10 2>&1)"
assert_contains "print_summary D: score 60" "$ps_d" "60"

# Grade F path (score < 60)
_reset_state
TOTAL_CHECKS=10; PASSED=3; FAILED=7; WARNINGS=0; SKIPPED=0
ps_f="$(print_summary 10 2>&1)"
assert_contains "print_summary F: score 30" "$ps_f" "30"

# Zero-active edge case (score stays 0)
_reset_state
TOTAL_CHECKS=0; PASSED=0; FAILED=0; WARNINGS=0; SKIPPED=0
ps_z="$(print_summary 0 2>&1)"
assert_contains "print_summary zero: dashboard heading" "$ps_z" "SCAN DASHBOARD"
assert_contains "print_summary zero: 0s duration"       "$ps_z" "0s"

# Minute-scale duration formatter (>=60 seconds)
_reset_state
TOTAL_CHECKS=1; PASSED=1; FAILED=0; WARNINGS=0; SKIPPED=0
ps_min="$(print_summary 125 2>&1)"
assert_contains "print_summary: minutes in duration"  "$ps_min" "2m"
assert_contains "print_summary: seconds in duration"  "$ps_min" "5s"

# Severity breakdown with critical/high/med/low/warn all populated
_reset_state
TOTAL_CHECKS=5; PASSED=0; FAILED=4; WARNINGS=1; SKIPPED=0
FINDINGS_CRITICAL+=("CHK-C1|Critical thing|critical|fix crit|d")
FINDINGS_HIGH+=("CHK-H1|High thing|high|fix high|d")
FINDINGS_MEDIUM+=("CHK-M1|Medium thing|medium|fix med|d")
FINDINGS_LOW+=("CHK-L1|Low thing|low|fix low|d")
FINDINGS_WARN+=("CHK-W1|Warn thing|medium||d")
ps_sev="$(print_summary 3 2>&1)"
assert_contains "print_summary sev: CRITICAL shown" "$ps_sev" "CRITICAL"
assert_contains "print_summary sev: HIGH shown"     "$ps_sev" "HIGH"
assert_contains "print_summary sev: MEDIUM shown"   "$ps_sev" "MEDIUM"
assert_contains "print_summary sev: LOW shown"      "$ps_sev" "LOW"
assert_contains "print_summary sev: WARNING shown"  "$ps_sev" "WARNING"
assert_contains "print_summary sev: Action Required" "$ps_sev" "Action Required"
assert_contains "print_summary sev: Recommended Fixes" "$ps_sev" "Recommended Fixes"
assert_contains "print_summary sev: Warnings section"  "$ps_sev" "Warnings"

# ==============================================================================
# Test Group 12: print_json_summary()
# ==============================================================================
echo ""
echo "=== print_json_summary() ==="

_reset_state
TOTAL_CHECKS=10; PASSED=9; FAILED=1; WARNINGS=0; SKIPPED=0
JSON_RESULTS='[{"id":"CHK-1","status":"pass"}]'
js_a="$(print_json_summary 42 2>&1)"
assert_contains "print_json_summary: version"      "$js_a" '"version": "test"'
assert_contains "print_json_summary: duration"     "$js_a" '"duration_seconds": 42'
assert_contains "print_json_summary: total"        "$js_a" '"total": 10'
assert_contains "print_json_summary: passed"       "$js_a" '"passed": 9'
assert_contains "print_json_summary: failed"       "$js_a" '"failed": 1'
assert_contains "print_json_summary: score 90"     "$js_a" '"score": 90'
assert_contains "print_json_summary: grade A"      "$js_a" '"grade": "A"'
assert_contains "print_json_summary: results array" "$js_a" '"results":'

# Grade B
_reset_state
TOTAL_CHECKS=10; PASSED=8; FAILED=2; WARNINGS=0; SKIPPED=0
js_b="$(print_json_summary 1 2>&1)"
assert_contains "print_json_summary: grade B" "$js_b" '"grade": "B"'

# Grade C
_reset_state
TOTAL_CHECKS=10; PASSED=7; FAILED=3; WARNINGS=0; SKIPPED=0
js_c="$(print_json_summary 1 2>&1)"
assert_contains "print_json_summary: grade C" "$js_c" '"grade": "C"'

# Grade D
_reset_state
TOTAL_CHECKS=10; PASSED=6; FAILED=4; WARNINGS=0; SKIPPED=0
js_d="$(print_json_summary 1 2>&1)"
assert_contains "print_json_summary: grade D" "$js_d" '"grade": "D"'

# Grade F
_reset_state
TOTAL_CHECKS=10; PASSED=0; FAILED=10; WARNINGS=0; SKIPPED=0
js_f="$(print_json_summary 1 2>&1)"
assert_contains "print_json_summary: grade F" "$js_f" '"grade": "F"'

# Zero-active (SKIPPED==TOTAL) → score 0, grade F
_reset_state
TOTAL_CHECKS=3; PASSED=0; FAILED=0; WARNINGS=0; SKIPPED=3
js_skip="$(print_json_summary 1 2>&1)"
assert_contains "print_json_summary: skipped=total score 0" "$js_skip" '"score": 0'

# ==============================================================================
# Test Group 13: save_scan_history / load_scan_history / compute_trend
# ==============================================================================
echo ""
echo "=== save_scan_history / load_scan_history / compute_trend ==="

hist_base="$(mktemp -d)"
OLD_SCAN_DIR="$SCAN_DIR"
SCAN_DIR="$hist_base"

# Empty history dir → load_scan_history returns "[]"
assert_eq "load_scan_history: missing dir returns []" "[]" "$(load_scan_history)"

# Save one scan
_reset_state
TOTAL_CHECKS=10; PASSED=8; FAILED=2; WARNINGS=0; SKIPPED=0
save_scan_history
hist_count=$(find "$hist_base/.claudesec-history" -name 'scan-*.json' | wc -l | tr -d ' ')
assert_eq "save_scan_history: file created" "1" "$hist_count"

# load_scan_history populates
loaded="$(load_scan_history)"
assert_contains "load_scan_history: starts with [" "$loaded" "["
assert_contains "load_scan_history: ends with ]"   "$loaded" "]"
assert_contains "load_scan_history: score field"   "$loaded" '"score":80'
assert_contains "load_scan_history: passed field"  "$loaded" '"passed":8'

# Save second scan (improved) → compute_trend produces deltas
_reset_state
TOTAL_CHECKS=10; PASSED=9; FAILED=1; WARNINGS=0; SKIPPED=0
compute_trend
assert_eq "compute_trend: TREND_HAS_PREV"      "true" "${TREND_HAS_PREV:-}"
assert_eq "compute_trend: score delta +10"     "10"   "${TREND_SCORE_DELTA:-}"
assert_eq "compute_trend: failed delta -1"     "-1"   "${TREND_FAILED_DELTA:-}"
assert_eq "compute_trend: prev score=80"       "80"   "${TREND_PREV_SCORE:-}"

# History pruning: force HISTORY_MAX=2 and create 5 files so 3 are pruned
rm -rf "$hist_base/.claudesec-history"
OLD_HISTORY_MAX="$HISTORY_MAX"
HISTORY_MAX=2
_reset_state
TOTAL_CHECKS=1; PASSED=1; FAILED=0; WARNINGS=0; SKIPPED=0
mkdir -p "$hist_base/.claudesec-history"
# Pre-populate with 5 dummy files whose names sort lexicographically
for i in 1 2 3 4 5; do
  printf '{"timestamp":"2026-01-0%dT00:00:00Z","score":50,"passed":0,"failed":0,"warnings":0,"skipped":0,"total":0,"critical":0,"high":0,"medium":0,"low":0,"warn":0}\n' "$i" \
    > "$hist_base/.claudesec-history/scan-2026010${i}T000000Z.json"
done
save_scan_history  # adds 6th, which should trigger prune down to HISTORY_MAX=2
remaining=$(find "$hist_base/.claudesec-history" -name 'scan-*.json' | wc -l | tr -d ' ')
assert_eq "save_scan_history: prunes to HISTORY_MAX" "2" "$remaining"
HISTORY_MAX="$OLD_HISTORY_MAX"

SCAN_DIR="$OLD_SCAN_DIR"

# ==============================================================================
# Test Group 14: generate_html_dashboard_legacy()
# ==============================================================================
echo ""
echo "=== generate_html_dashboard_legacy() ==="

legacy_file="$tmpdir/legacy.html"
generate_html_dashboard_legacy "$legacy_file"
assert_eq "legacy: file created" "true" "$([[ -f "$legacy_file" ]] && echo true || echo false)"
legacy_content="$(cat "$legacy_file")"
assert_contains "legacy: html tag"           "$legacy_content" "<html>"
assert_contains "legacy: body tag"           "$legacy_content" "<body>"
assert_contains "legacy: title heading"      "$legacy_content" "ClaudeSec Dashboard"
assert_contains "legacy: fallback mention"   "$legacy_content" "fallback"
assert_contains "legacy: install python hint" "$legacy_content" "Python 3"

# ==============================================================================
# Test Group 15: _html_findings_rows / _html_findings_rows_limited
# ==============================================================================
echo ""
echo "=== _html_findings_rows / _html_findings_rows_limited ==="

# Basic rows with details → row + detail-row
_reset_state
FINDINGS_HIGH+=("CHK-HR1|High <danger> &title|high|Fix it|extra details")
findings_html=""
_html_findings_rows FINDINGS_HIGH "high" "badge-high" "HIGH"
assert_contains "html_rows: id in output"           "$findings_html" "CHK-HR1"
assert_contains "html_rows: title escaped"          "$findings_html" "&lt;danger&gt;"
assert_contains "html_rows: amp escaped"            "$findings_html" "&amp;title"
assert_contains "html_rows: fix shown"              "$findings_html" "Fix it"
assert_contains "html_rows: badge class"            "$findings_html" "badge-high"
assert_contains "html_rows: sev class row"          "$findings_html" '"high clickable"'
assert_contains "html_rows: detail-row present"     "$findings_html" "detail-row"
assert_contains "html_rows: clickable handler"      "$findings_html" "toggleDetail"
assert_contains "html_rows: expand icon"            "$findings_html" "expand-icon"

# Row without details → no detail-row, non-clickable
_reset_state
FINDINGS_MEDIUM+=("CHK-HR2|Med title|medium|Fix med|")
findings_html=""
_html_findings_rows FINDINGS_MEDIUM "medium" "badge-med" "MED"
assert_contains     "html_rows(no details): id shown"            "$findings_html" "CHK-HR2"
assert_not_contains "html_rows(no details): no detail-row"       "$findings_html" "detail-row"
assert_not_contains "html_rows(no details): no toggle"           "$findings_html" "toggleDetail"

# Empty findings array → no html produced
_reset_state
findings_html=""
_html_findings_rows FINDINGS_LOW "low" "badge-low" "LOW"
assert_eq "html_rows: empty array produces nothing" "" "$findings_html"

# _html_findings_rows_limited with max=0 (unlimited) emits every entry
_reset_state
FINDINGS_HIGH+=("CHK-L1|First|high|fix1|")
FINDINGS_HIGH+=("CHK-L2|Second|high|fix2|")
FINDINGS_HIGH+=("CHK-L3|Third|high|fix3|")
out_unlim=""
_html_findings_rows_limited out_unlim FINDINGS_HIGH "high" "badge-high" "HIGH" 0
assert_contains "html_rows_limited(max=0): first"  "$out_unlim" "CHK-L1"
assert_contains "html_rows_limited(max=0): second" "$out_unlim" "CHK-L2"
assert_contains "html_rows_limited(max=0): third"  "$out_unlim" "CHK-L3"

# max=1 caps at a single row
out_capped=""
_html_findings_rows_limited out_capped FINDINGS_HIGH "high" "badge-high" "HIGH" 1
assert_contains     "html_rows_limited(max=1): first included"  "$out_capped" "CHK-L1"
assert_not_contains "html_rows_limited(max=1): second excluded" "$out_capped" "CHK-L2"
assert_not_contains "html_rows_limited(max=1): third excluded"  "$out_capped" "CHK-L3"

# max=2 caps at two rows
out_two=""
_html_findings_rows_limited out_two FINDINGS_HIGH "high" "badge-high" "HIGH" 2
assert_contains     "html_rows_limited(max=2): first"         "$out_two" "CHK-L1"
assert_contains     "html_rows_limited(max=2): second"        "$out_two" "CHK-L2"
assert_not_contains "html_rows_limited(max=2): third missing" "$out_two" "CHK-L3"

# Preserves existing content in outvar (append semantics)
_reset_state
FINDINGS_MEDIUM+=("CHK-APP1|Append test|medium|fix|")
out_existing="PRIOR-CONTENT"
_html_findings_rows_limited out_existing FINDINGS_MEDIUM "medium" "badge-med" "MED" 0
assert_contains "html_rows_limited: preserves prior content" "$out_existing" "PRIOR-CONTENT"
assert_contains "html_rows_limited: appends new row"         "$out_existing" "CHK-APP1"

# Row with details in limited variant → clickable + detail-row
_reset_state
FINDINGS_HIGH+=("CHK-LD1|Limited detail|high|fix|lots of details here")
out_det=""
_html_findings_rows_limited out_det FINDINGS_HIGH "high" "badge-high" "HIGH" 5
assert_contains "html_rows_limited: detail-row present" "$out_det" "detail-row"
assert_contains "html_rows_limited: toggleDetail"       "$out_det" "toggleDetail"
assert_contains "html_rows_limited: details in output"  "$out_det" "lots of details here"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
