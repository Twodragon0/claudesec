#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/saas/api-checks.sh
#
# WHY THIS TEST IS NARROW:
# api-checks.sh (SAAS-API-001..008, SAAS-API-020..021) authenticates to live SaaS
# APIs via CLI tools (gh), OAuth tokens (CF_API_TOKEN, VERCEL_TOKEN, etc.), or
# credential env vars (DD_API_KEY, SENTRY_AUTH_TOKEN, OKTA_*, SENDGRID_API_KEY,
# HARBOR_URL, JENKINS_URL). All substantive logic runs only when credentials are
# present and the network is reachable.
#
# NOT OFFLINE-TESTABLE (require live API responses or CLI auth):
#   SAAS-API-001  gh CLI + OAuth: pass/warn/fail — needs `gh auth status` + live API
#   SAAS-API-002  GitHub Actions workflow runs — needs live GitHub API + authenticated gh
#   SAAS-API-003  Datadog API key validation — needs DD_API_KEY network request
#   SAAS-API-004  Cloudflare token verification — needs CF_API_TOKEN network request
#   SAAS-API-005  Vercel token validation — needs VERCEL_TOKEN network request
#   SAAS-API-006  Sentry auth token — needs SENTRY_AUTH_TOKEN network request
#   SAAS-API-007  Okta API (users/policies) — needs OKTA_ORG_URL + token + network
#   SAAS-API-008  SendGrid profile fetch — needs SENDGRID_API_KEY network request
#   SAAS-API-020  Harbor ping — needs HARBOR_URL reachable
#   SAAS-API-021  Jenkins whoAmI + crumbIssuer — needs JENKINS_URL reachable
#
# WHAT IS TESTABLE OFFLINE (no creds, no network):
#   All checks above produce SKIP when credentials/CLI are absent. These SKIP
#   paths exercise every credential-guard branch without any network call.
#   SAAS-API-020 WARN when HARBOR_URL is http:// (non-HTTPS) — URL-format check
#     only, no network required.
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_saas_api_checks.sh
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
  # Ensure no stray credentials leak in from the test runner environment
  unset DD_API_KEY DD_APP_KEY CF_API_TOKEN VERCEL_TOKEN SENTRY_AUTH_TOKEN \
        OKTA_ORG_URL OKTA_OAUTH_TOKEN OKTA_API_TOKEN SENDGRID_API_KEY \
        HARBOR_URL HARBOR_USERNAME HARBOR_PASSWORD HARBOR_AUTH_HEADER \
        JENKINS_URL JENKINS_USER JENKINS_API_TOKEN 2>/dev/null || true
  source "$CHECKS_DIR/saas/api-checks.sh" 2>/dev/null || true
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── SAAS-API-001: no gh CLI or not a git repo -> SKIP ────────────────────────

echo "=== SAAS-API-001: no gh CLI / not a git repo -> SKIP ==="

# Override has_command and is_git_repo to simulate absent CLI
has_command() { return 1; }
is_git_repo() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command is_git_repo 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No gh CLI -> SKIP SAAS-API-001" "SKIP" "SAAS-API-001"

# ── SAAS-API-002: no gh CLI -> SKIP ──────────────────────────────────────────

echo "=== SAAS-API-002: no gh CLI -> SKIP ==="

has_command() { return 1; }
is_git_repo() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command is_git_repo 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No gh CLI -> SKIP SAAS-API-002" "SKIP" "SAAS-API-002"

# ── SAAS-API-003: no DD_API_KEY -> SKIP ──────────────────────────────────────

echo "=== SAAS-API-003: no DD_API_KEY -> SKIP ==="

has_command() { return 1; }  # also disable datadog-agent
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No DD_API_KEY -> SKIP SAAS-API-003" "SKIP" "SAAS-API-003"

# ── SAAS-API-004: no CF_API_TOKEN and no cloudflared -> SKIP ─────────────────

echo "=== SAAS-API-004: no CF_API_TOKEN -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No CF_API_TOKEN -> SKIP SAAS-API-004" "SKIP" "SAAS-API-004"

# ── SAAS-API-005: no VERCEL_TOKEN and no vercel CLI -> SKIP ──────────────────

echo "=== SAAS-API-005: no VERCEL_TOKEN -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No VERCEL_TOKEN -> SKIP SAAS-API-005" "SKIP" "SAAS-API-005"

# ── SAAS-API-006: no SENTRY_AUTH_TOKEN -> SKIP ───────────────────────────────

echo "=== SAAS-API-006: no SENTRY_AUTH_TOKEN -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No SENTRY_AUTH_TOKEN -> SKIP SAAS-API-006" "SKIP" "SAAS-API-006"

# ── SAAS-API-007: no OKTA_ORG_URL -> SKIP ────────────────────────────────────

echo "=== SAAS-API-007: no OKTA_ORG_URL -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No OKTA_ORG_URL -> SKIP SAAS-API-007" "SKIP" "SAAS-API-007"

# ── SAAS-API-008: no SENDGRID_API_KEY -> SKIP ────────────────────────────────

echo "=== SAAS-API-008: no SENDGRID_API_KEY -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No SENDGRID_API_KEY -> SKIP SAAS-API-008" "SKIP" "SAAS-API-008"

# ── SAAS-API-020: no HARBOR_URL -> SKIP ──────────────────────────────────────

echo "=== SAAS-API-020: no HARBOR_URL -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No HARBOR_URL -> SKIP SAAS-API-020" "SKIP" "SAAS-API-020"

# ── SAAS-API-020: HTTP HARBOR_URL -> WARN (no network call needed) ─────────────
#
# The non-HTTPS guard fires before any curl is attempted, so this is hermetic.
# We bypass run_check (which unsets HARBOR_URL) and source the check directly
# after setting the variable, then unset it again afterward.

echo "=== SAAS-API-020: HTTP HARBOR_URL -> WARN (URL format only) ==="

RESULTS=()
HARBOR_URL="http://harbor.example.com"
# Stub run_with_timeout/curl so no real network call is made if curl is reached
run_with_timeout() { return 1; }
SCAN_DIR="$tmpdir"
source "$CHECKS_DIR/saas/api-checks.sh" 2>/dev/null || true
unset HARBOR_URL
unset -f run_with_timeout 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "HTTP HARBOR_URL -> WARN SAAS-API-020" "WARN" "SAAS-API-020"

# ── SAAS-API-021: no JENKINS_URL -> SKIP ─────────────────────────────────────

echo "=== SAAS-API-021: no JENKINS_URL -> SKIP ==="

has_command() { return 1; }
SCAN_DIR="$tmpdir"
run_check
unset -f has_command 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "No JENKINS_URL -> SKIP SAAS-API-021" "SKIP" "SAAS-API-021"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
