#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/saas/zscaler.sh
#
# WHY THIS TEST IS NARROW:
# zscaler.sh (SAAS-ZIA-001..007) delegates all live API communication to
# scanner/lib/zscaler-api.py. The shell check invokes the Python helper via
# `python3 "$LIB_DIR/zscaler-api.py"` and parses the JSON response. Every
# substantive check (user hygiene, advanced settings, permission scope, group
# coverage, NSS feeds, SAML/SSO) runs only when:
#   1. All four Zscaler credentials are set (ZSCALER_API_KEY, ZSCALER_API_ADMIN,
#      ZSCALER_API_PASSWORD, ZSCALER_BASE_URL), AND
#   2. zscaler-api.py successfully authenticates and returns JSON.
#
# NOT OFFLINE-TESTABLE (require live credentials + network + zscaler-api.py):
#   SAAS-ZIA-001  auth_failed / warn / pass — needs ZIA API response
#   SAAS-ZIA-002  User hygiene — needs users JSON from ZIA
#   SAAS-ZIA-003  Advanced settings audit — needs ZIA advanced settings API
#   SAAS-ZIA-004  API permission scope — needs policy_access JSON
#   SAAS-ZIA-005  Group/department coverage — needs groups/departments JSON
#   SAAS-ZIA-006  NSS log streaming — needs nss_feeds JSON
#   SAAS-ZIA-007  SAML/SSO settings — needs auth_settings JSON
#
# WHAT IS TESTABLE OFFLINE:
#   SAAS-ZIA-001 SKIP when any Zscaler credential is absent — the credential-
#     guard fires before any Python call.
#   SAAS-ZIA-001 FAIL (auth_failed) when python3/zscaler-api.py returns
#     {"error":"auth_failed"} — simulated via stub, no network needed.
#   SAAS-ZIA-001 WARN when python3/zscaler-api.py returns a connection error —
#     simulated via stub.
#   SAAS-ZIA-001 PASS and SAAS-ZIA-002..007 exercised from stubs returning
#     a well-formed JSON response with ACTIVE status — all parse-logic branches
#     covered offline via the stub python3 approach.
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_saas_zscaler.sh
set -uo pipefail

export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
FORMAT="text"
QUIET=1
SEVERITY="low"

RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"
    ((TEST_FAILED++))
  fi
}

assert_no_result() {
  local desc="$1" unexpected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${unexpected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if ! $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (unexpected $unexpected_type:$check_id found)"
    ((TEST_FAILED++))
  fi
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir"
# Stub LIB_DIR to a directory that contains a fake zscaler-api.py
# (the check does: python3 "$LIB_DIR/zscaler-api.py")
mkdir -p "$tmpdir/stub_lib"
cp "$LIB_DIR/checks.sh" "$tmpdir/stub_lib/checks.sh"
LIB_DIR_REAL="$LIB_DIR"

run_check_with_json() {
  local json_response="$1"
  RESULTS=()
  # Install a stub zscaler-api.py that outputs the provided JSON
  printf '#!/usr/bin/env python3\nprint("""%s""")\n' "$json_response" \
    > "$tmpdir/stub_lib/zscaler-api.py"
  LIB_DIR="$tmpdir/stub_lib"
  source "$CHECKS_DIR/saas/zscaler.sh" 2>/dev/null || true
  LIB_DIR="$LIB_DIR_REAL"
}

run_check_no_creds() {
  RESULTS=()
  unset ZSCALER_API_KEY ZSCALER_API_ADMIN ZSCALER_API_PASSWORD ZSCALER_BASE_URL \
    2>/dev/null || true
  LIB_DIR="$tmpdir/stub_lib"
  source "$CHECKS_DIR/saas/zscaler.sh" 2>/dev/null || true
  LIB_DIR="$LIB_DIR_REAL"
}

# ── SAAS-ZIA-001: no credentials -> SKIP ─────────────────────────────────────

echo "=== SAAS-ZIA-001: no Zscaler credentials -> SKIP ==="

run_check_no_creds
assert_has_result "No Zscaler creds -> SKIP SAAS-ZIA-001" "SKIP" "SAAS-ZIA-001"

# ── SAAS-ZIA-001: auth_failed error -> FAIL ───────────────────────────────────

echo "=== SAAS-ZIA-001: auth_failed -> FAIL ==="

export ZSCALER_API_KEY="dummykey"
export ZSCALER_API_ADMIN="admin@example.com"
export ZSCALER_API_PASSWORD="dummypass"
export ZSCALER_BASE_URL="https://zsapi.example.com"

run_check_with_json '{"error":"auth_failed"}'
assert_has_result "auth_failed -> FAIL SAAS-ZIA-001" "FAIL" "SAAS-ZIA-001"

# ── SAAS-ZIA-001: missing_credentials error -> SKIP ──────────────────────────

echo "=== SAAS-ZIA-001: missing_credentials from Python -> SKIP ==="

run_check_with_json '{"error":"missing_credentials"}'
assert_has_result "missing_credentials from Python -> SKIP SAAS-ZIA-001" "SKIP" "SAAS-ZIA-001"

# ── SAAS-ZIA-001: connection error -> WARN ────────────────────────────────────

echo "=== SAAS-ZIA-001: connection error -> WARN ==="

run_check_with_json '{"error":"connection_timeout"}'
assert_has_result "connection error -> WARN SAAS-ZIA-001" "WARN" "SAAS-ZIA-001"

# ── SAAS-ZIA-001: ACTIVE status -> PASS ──────────────────────────────────────

echo "=== SAAS-ZIA-001: ACTIVE status -> PASS ==="

# Full healthy JSON: no issues in any sub-check
_healthy_json='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":2,"restricted_count":3},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_healthy_json"
assert_has_result "ACTIVE status -> PASS SAAS-ZIA-001" "PASS" "SAAS-ZIA-001"

# ── SAAS-ZIA-002: users accessible, all assigned -> PASS ─────────────────────

echo "=== SAAS-ZIA-002: all users assigned -> PASS ==="

_users_good='{"service_status":"ACTIVE","users":{"accessible":true,"total":50,"no_group":3,"unassigned":0},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_users_good"
assert_has_result "Users all assigned -> PASS SAAS-ZIA-002" "PASS" "SAAS-ZIA-002"

# ── SAAS-ZIA-002: many users with no group -> FAIL ────────────────────────────

echo "=== SAAS-ZIA-002: many users no group -> FAIL ==="

_users_bad='{"service_status":"ACTIVE","users":{"accessible":true,"total":100,"no_group":80,"unassigned":10},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_users_bad"
assert_has_result "Many users without group -> FAIL SAAS-ZIA-002" "FAIL" "SAAS-ZIA-002"

# ── SAAS-ZIA-003: excessive bypass URLs -> FAIL ───────────────────────────────

echo "=== SAAS-ZIA-003: excessive bypass URLs -> FAIL ==="

_adv_bad='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":true,"auth_bypass_urls_count":20,"auth_bypass_apps_count":10,"domain_fronting_bypass_count":2},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_adv_bad"
assert_has_result "Excessive bypass URLs -> FAIL SAAS-ZIA-003" "FAIL" "SAAS-ZIA-003"

# ── SAAS-ZIA-003: safe bypass config -> PASS ─────────────────────────────────

echo "=== SAAS-ZIA-003: safe bypass config -> PASS ==="

_adv_good='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":true,"auth_bypass_urls_count":2,"auth_bypass_apps_count":1,"domain_fronting_bypass_count":0},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_adv_good"
assert_has_result "Safe bypass config -> PASS SAAS-ZIA-003" "PASS" "SAAS-ZIA-003"

# ── SAAS-ZIA-004: broad API access -> WARN ───────────────────────────────────

echo "=== SAAS-ZIA-004: broad API access -> WARN ==="

_scope_broad='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":10,"restricted_count":0},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_scope_broad"
assert_has_result "Broad API access -> WARN SAAS-ZIA-004" "WARN" "SAAS-ZIA-004"

# ── SAAS-ZIA-004: scoped API access -> PASS ──────────────────────────────────

echo "=== SAAS-ZIA-004: scoped API access -> PASS ==="

_scope_good='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":2,"restricted_count":8},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_scope_good"
assert_has_result "Scoped API access -> PASS SAAS-ZIA-004" "PASS" "SAAS-ZIA-004"

# ── SAAS-ZIA-005: few groups -> WARN ─────────────────────────────────────────

echo "=== SAAS-ZIA-005: too few groups -> WARN ==="

_groups_few='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":true,"total":1},"departments":{"accessible":true,"total":5},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_groups_few"
assert_has_result "Too few groups -> WARN SAAS-ZIA-005" "WARN" "SAAS-ZIA-005"

# ── SAAS-ZIA-005: healthy org structure -> PASS ───────────────────────────────

echo "=== SAAS-ZIA-005: healthy org structure -> PASS ==="

_groups_good='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":true,"total":10},"departments":{"accessible":true,"total":5},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":false}}'
run_check_with_json "$_groups_good"
assert_has_result "Healthy org structure -> PASS SAAS-ZIA-005" "PASS" "SAAS-ZIA-005"

# ── SAAS-ZIA-006: no NSS feeds -> FAIL ───────────────────────────────────────

echo "=== SAAS-ZIA-006: no NSS feeds -> FAIL ==="

_nss_none='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":true,"total":0},"auth_settings":{"accessible":false}}'
run_check_with_json "$_nss_none"
assert_has_result "No NSS feeds -> FAIL SAAS-ZIA-006" "FAIL" "SAAS-ZIA-006"

# ── SAAS-ZIA-006: NSS feeds configured -> PASS ───────────────────────────────

echo "=== SAAS-ZIA-006: NSS feeds configured -> PASS ==="

_nss_good='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":true,"total":2},"auth_settings":{"accessible":false}}'
run_check_with_json "$_nss_good"
assert_has_result "NSS feeds configured -> PASS SAAS-ZIA-006" "PASS" "SAAS-ZIA-006"

# ── SAAS-ZIA-007: SAML disabled -> FAIL ──────────────────────────────────────

echo "=== SAAS-ZIA-007: SAML SSO disabled -> FAIL ==="

_sso_bad='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":true,"saml_enabled":"False","auto_provision":"False","auth_frequency":"SESSION"}}'
run_check_with_json "$_sso_bad"
assert_has_result "SAML SSO disabled -> FAIL SAAS-ZIA-007" "FAIL" "SAAS-ZIA-007"

# ── SAAS-ZIA-007: SAML + auto-provision -> PASS ───────────────────────────────

echo "=== SAAS-ZIA-007: SAML + auto-provision -> PASS ==="

_sso_good='{"service_status":"ACTIVE","users":{"accessible":false},"advanced_settings":{"accessible":false},"policy_access":{"accessible_count":1,"restricted_count":1},"groups":{"accessible":false},"departments":{"accessible":false},"nss_feeds":{"accessible":false},"auth_settings":{"accessible":true,"saml_enabled":"True","auto_provision":"True","auth_frequency":"SESSION"}}'
run_check_with_json "$_sso_good"
assert_has_result "SAML + auto-provision -> PASS SAAS-ZIA-007" "PASS" "SAAS-ZIA-007"

# Cleanup credentials
unset ZSCALER_API_KEY ZSCALER_API_ADMIN ZSCALER_API_PASSWORD ZSCALER_BASE_URL \
  2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
