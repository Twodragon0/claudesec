#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/saas/api-extended.sh
#
# WHY THIS TEST IS NARROW:
# api-extended.sh (SAAS-API-009..019) covers Slack, PagerDuty, Jira/Atlassian,
# Grafana, New Relic, Splunk, Twilio, MongoDB Atlas, Elastic Cloud, and deep-scan
# extensions for Datadog (018) and Okta (019). Every check authenticates against a
# live SaaS API — the guard condition is the presence of env credentials/tokens.
#
# NOT OFFLINE-TESTABLE (require live credentials + network):
#   SAAS-API-009  Slack auth.test — needs SLACK_API_TOKEN or SLACK_BOT_TOKEN
#   SAAS-API-010  PagerDuty abilities — needs PAGERDUTY_API_KEY or PD_API_KEY
#   SAAS-API-011  Jira myself — needs ATLASSIAN_API_TOKEN + EMAIL + DOMAIN
#   SAAS-API-012  Grafana health — needs GRAFANA_URL + GRAFANA_API_KEY or GRAFANA_TOKEN
#   SAAS-API-013  New Relic users — needs NEW_RELIC_API_KEY or NEWRELIC_API_KEY
#   SAAS-API-014  Splunk server info — needs SPLUNK_URL + SPLUNK_TOKEN
#   SAAS-API-015  Twilio account — needs TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN
#   SAAS-API-016  MongoDB Atlas orgs — needs MONGODB_ATLAS_PUBLIC_KEY + PRIVATE_KEY
#   SAAS-API-017  Elastic Cloud user — needs ELASTIC_API_KEY or ELASTIC_CLOUD_ID + password
#   SAAS-API-018  Datadog deep scan — needs DD_API_KEY + DD_APP_KEY (live APIs)
#   SAAS-API-019  Okta deep scan — needs OKTA_ORG_URL + token (live APIs)
#
# WHAT IS TESTABLE OFFLINE:
#   All checks above SKIP when their credentials are absent — these SKIP paths are
#   fully deterministic without any network access.
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_saas_api_extended.sh
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

run_check() {
  RESULTS=()
  # Ensure no stray credentials from the runner environment
  unset SLACK_API_TOKEN SLACK_BOT_TOKEN \
        PAGERDUTY_API_KEY PD_API_KEY \
        ATLASSIAN_API_TOKEN ATLASSIAN_EMAIL ATLASSIAN_DOMAIN \
        GRAFANA_URL GRAFANA_API_KEY GRAFANA_TOKEN \
        NEW_RELIC_API_KEY NEWRELIC_API_KEY \
        SPLUNK_URL SPLUNK_TOKEN \
        TWILIO_ACCOUNT_SID TWILIO_AUTH_TOKEN \
        MONGODB_ATLAS_PUBLIC_KEY MONGODB_ATLAS_PRIVATE_KEY \
        ELASTIC_API_KEY ELASTIC_CLOUD_ID ELASTIC_PASSWORD \
        DD_API_KEY DD_APP_KEY DD_SITE \
        OKTA_ORG_URL OKTA_OAUTH_TOKEN OKTA_API_TOKEN 2>/dev/null || true
  source "$CHECKS_DIR/saas/api-extended.sh" 2>/dev/null || true
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir"

# ── SAAS-API-009: no Slack token -> SKIP ─────────────────────────────────────

echo "=== SAAS-API-009: no Slack token -> SKIP ==="

run_check
assert_has_result "No SLACK_API_TOKEN -> SKIP SAAS-API-009" "SKIP" "SAAS-API-009"

# ── SAAS-API-010: no PagerDuty key -> SKIP ───────────────────────────────────

echo "=== SAAS-API-010: no PagerDuty key -> SKIP ==="

run_check
assert_has_result "No PAGERDUTY_API_KEY -> SKIP SAAS-API-010" "SKIP" "SAAS-API-010"

# ── SAAS-API-011: no Atlassian creds -> SKIP ─────────────────────────────────

echo "=== SAAS-API-011: no Atlassian creds -> SKIP ==="

run_check
assert_has_result "No ATLASSIAN_API_TOKEN -> SKIP SAAS-API-011" "SKIP" "SAAS-API-011"

# ── SAAS-API-012: no Grafana creds -> SKIP ───────────────────────────────────

echo "=== SAAS-API-012: no Grafana creds -> SKIP ==="

run_check
assert_has_result "No GRAFANA_URL -> SKIP SAAS-API-012" "SKIP" "SAAS-API-012"

# ── SAAS-API-013: no New Relic key -> SKIP ───────────────────────────────────

echo "=== SAAS-API-013: no New Relic key -> SKIP ==="

run_check
assert_has_result "No NEW_RELIC_API_KEY -> SKIP SAAS-API-013" "SKIP" "SAAS-API-013"

# ── SAAS-API-014: no Splunk creds -> SKIP ────────────────────────────────────

echo "=== SAAS-API-014: no Splunk creds -> SKIP ==="

run_check
assert_has_result "No SPLUNK_TOKEN -> SKIP SAAS-API-014" "SKIP" "SAAS-API-014"

# ── SAAS-API-015: no Twilio creds -> SKIP ────────────────────────────────────

echo "=== SAAS-API-015: no Twilio creds -> SKIP ==="

run_check
assert_has_result "No TWILIO_ACCOUNT_SID -> SKIP SAAS-API-015" "SKIP" "SAAS-API-015"

# ── SAAS-API-016: no MongoDB Atlas keys -> SKIP ──────────────────────────────

echo "=== SAAS-API-016: no MongoDB Atlas keys -> SKIP ==="

run_check
assert_has_result "No MONGODB_ATLAS_PUBLIC_KEY -> SKIP SAAS-API-016" "SKIP" "SAAS-API-016"

# ── SAAS-API-017: no Elastic creds -> SKIP ───────────────────────────────────

echo "=== SAAS-API-017: no Elastic creds -> SKIP ==="

run_check
assert_has_result "No ELASTIC_API_KEY -> SKIP SAAS-API-017" "SKIP" "SAAS-API-017"

# ── SAAS-API-018/019: no Datadog/Okta deep-scan keys -> no output ─────────────
# SAAS-API-018 and SAAS-API-019 are only entered (no skip emitted) when creds
# ARE present; when absent they produce no result at all (guarded by outer if).

echo "=== SAAS-API-018: no DD keys -> no result (guarded block, not a skip) ==="

run_check
assert_no_result "No DD_API_KEY -> no SAAS-API-018 output" "SKIP" "SAAS-API-018"
assert_no_result "No DD_API_KEY -> no SAAS-API-018 pass" "PASS" "SAAS-API-018"

echo "=== SAAS-API-019: no Okta keys -> no result (guarded block, not a skip) ==="

run_check
assert_no_result "No OKTA_ORG_URL -> no SAAS-API-019 output" "SKIP" "SAAS-API-019"
assert_no_result "No OKTA_ORG_URL -> no SAAS-API-019 pass" "PASS" "SAAS-API-019"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
