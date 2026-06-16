#!/usr/bin/env bash
# Unit tests for the _prowler_provider_available helper introduced in
# scanner/checks/prowler/integration.sh to detect absent provider modules
# and emit accurate skip messages in the lean container image.
#
# Strategy: define _prowler_provider_available inline (same body as the
# production function) so the test is fully hermetic — no prowler binary,
# no network, no live install needed.  A separate group verifies the body
# matches the production source so the copy cannot silently drift.
#
# Run: bash scanner/tests/test_prowler_provider_build_parity.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_SH="$SCRIPT_DIR/../checks/prowler/integration.sh"

TEST_PASSED=0
TEST_FAILED=0

# ── Inline copy of the helper (must stay in sync with integration.sh) ────────
# _prowler_install_dir is the control variable; tests override it directly.
_prowler_install_dir=""

_prowler_provider_available() {
  local provider="$1"
  # Map nhn -> openstack (NHN Cloud scans via the openstack provider)
  [[ "$provider" == "nhn" ]] && provider="openstack"
  # If we couldn't resolve the install dir, default to available (full install)
  [[ -z "$_prowler_install_dir" ]] && return 0
  [[ -d "${_prowler_install_dir}/providers/${provider}" ]]
}

# ── Drift guard: verify the inline body matches what's in integration.sh ─────
# Extract the production function body and compare it to ours.
assert_helper_in_sync() {
  # Pull the function body from integration.sh between the function definition
  # and its closing brace.
  local prod_body
  prod_body=$(awk '
    /^_prowler_provider_available\(\)/ { found=1; next }
    found && /^\}/ { exit }
    found { print }
  ' "$INTEGRATION_SH" 2>/dev/null | sed 's/^[[:space:]]*//' | grep -v '^$' || true)

  local test_body
  test_body=$(awk '
    /^_prowler_provider_available\(\)/ { found=1; next }
    found && /^\}/ { exit }
    found { print }
  ' "${BASH_SOURCE[0]}" 2>/dev/null | sed 's/^[[:space:]]*//' | grep -v '^$' || true)

  if [[ "$prod_body" == "$test_body" ]]; then
    echo "  PASS: inline helper body matches integration.sh"
    ((TEST_PASSED++))
  else
    echo "  FAIL: inline helper has drifted from integration.sh"
    echo "    --- integration.sh ---"
    echo "$prod_body"
    echo "    --- this test ---"
    echo "$test_body"
    ((TEST_FAILED++))
  fi
}

assert_available() {
  local desc="$1" provider="$2"
  if _prowler_provider_available "$provider"; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected available, got absent)"
    ((TEST_FAILED++))
  fi
}

assert_absent() {
  local desc="$1" provider="$2"
  if ! _prowler_provider_available "$provider"; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected absent, got available)"
    ((TEST_FAILED++))
  fi
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── Drift check ───────────────────────────────────────────────────────────────

echo "=== Drift guard: inline helper matches integration.sh ==="
assert_helper_in_sync

# ── Group 1: lean container layout (subset of providers) ─────────────────────

echo "=== Group 1: lean container — kept providers are available ==="

# Simulate lean image: only aws, kubernetes, github, iac present
mkdir -p \
  "$tmpdir/providers/aws" \
  "$tmpdir/providers/kubernetes" \
  "$tmpdir/providers/github" \
  "$tmpdir/providers/iac"

_prowler_install_dir="$tmpdir"

assert_available "aws present in lean image"        "aws"
assert_available "kubernetes present in lean image" "kubernetes"
assert_available "github present in lean image"     "github"
assert_available "iac present in lean image"        "iac"

echo "=== Group 1: lean container — stripped providers are absent ==="

assert_absent "azure stripped from lean image"           "azure"
assert_absent "gcp stripped from lean image"             "gcp"
assert_absent "m365 stripped from lean image"            "m365"
assert_absent "googleworkspace stripped from lean image" "googleworkspace"
assert_absent "cloudflare stripped from lean image"      "cloudflare"
assert_absent "mongodbatlas stripped from lean image"    "mongodbatlas"
assert_absent "oraclecloud stripped from lean image"     "oraclecloud"
assert_absent "alibabacloud stripped from lean image"    "alibabacloud"
assert_absent "openstack stripped from lean image"       "openstack"
assert_absent "llm stripped from lean image"             "llm"
assert_absent "image stripped from lean image"           "image"

echo "=== Group 1: nhn maps to openstack module ==="

# nhn uses the openstack provider; openstack is absent -> nhn is absent
assert_absent "nhn absent when openstack stripped" "nhn"

# Add openstack back and re-check
mkdir -p "$tmpdir/providers/openstack"
assert_available "nhn available when openstack present" "nhn"
rmdir "$tmpdir/providers/openstack"

# ── Group 2: full local install (all 16 providers present) ───────────────────

echo "=== Group 2: full install — all providers available ==="

tmpdir2=$(mktemp -d)
trap 'rm -rf "$tmpdir" "$tmpdir2"' EXIT

mkdir -p \
  "$tmpdir2/providers/aws" \
  "$tmpdir2/providers/azure" \
  "$tmpdir2/providers/gcp" \
  "$tmpdir2/providers/kubernetes" \
  "$tmpdir2/providers/github" \
  "$tmpdir2/providers/m365" \
  "$tmpdir2/providers/googleworkspace" \
  "$tmpdir2/providers/cloudflare" \
  "$tmpdir2/providers/mongodbatlas" \
  "$tmpdir2/providers/oraclecloud" \
  "$tmpdir2/providers/alibabacloud" \
  "$tmpdir2/providers/openstack" \
  "$tmpdir2/providers/iac" \
  "$tmpdir2/providers/llm" \
  "$tmpdir2/providers/image"

_prowler_install_dir="$tmpdir2"

for _p in aws azure gcp kubernetes github m365 googleworkspace cloudflare \
           mongodbatlas oraclecloud alibabacloud openstack iac llm image nhn; do
  assert_available "full install: $_p available" "$_p"
done

# ── Group 3: inconclusive detection defaults to available (no false negatives) ─

echo "=== Group 3: empty install dir defaults to available ==="

_prowler_install_dir=""

assert_available "empty install dir: aws defaults available"   "aws"
assert_available "empty install dir: azure defaults available" "azure"
assert_available "empty install dir: nhn defaults available"   "nhn"

# ── Group 4: no auth-WARN for stripped providers ──────────────────────────────
#
# Regression guard for the ordering fix in #238: when a provider is absent from
# the build, the parity-skip must fire and the "_prowler_report" auth-warning
# ("Check authentication and permissions") must NEVER be emitted.
#
# Approach: behavioural test — inline a minimal faithful copy of the provider
# dispatch logic (Azure chosen as the representative stripped provider), stub
# all external helpers (warn, skip, _prowler_provider_available, etc.), capture
# stdout+stderr, and assert on the emitted output.
#
# We exercise the real branch logic rather than source-grepping because source
# ordering is necessary but not sufficient: a logic error could still bypass the
# guard. The inline copy is kept minimal (exact boolean conditions from
# integration.sh) so it is easy to maintain.  If integration.sh's Azure block
# changes materially, this test will start failing — the intended signal.

echo "=== Group 4: no auth-WARN emitted for stripped providers ==="

# ── Stubs for the dispatch harness ───────────────────────────────────────────

_harness_output=""

# Capture skip/warn/pass/fail into _harness_output for assertions.
_harness_skip() { _harness_output="${_harness_output}SKIP:$*:"; }
_harness_warn() { _harness_output="${_harness_output}WARN:$*:"; }
_harness_pass() { :; }
_harness_fail() { :; }
_harness_info() { :; }

# Stub _prowler_should_run: always allow (worst-case path where credentials
# appear present but the build is stripped).
_prowler_should_run_stub() { return 0; }

# Stub credential checks: return "present" to force the credential-present branch
# (the branch that would reach _prowler_report if the parity guard were absent).
_has_az_stub()     { return 0; }
_has_az_account_stub() { return 0; }

# _prowler_scan stub: returns an empty string (simulates no JSON output file,
# which is what triggers the auth-warn in _prowler_report when unchecked).
_prowler_scan_stub() { echo ""; }

# _prowler_report stub: emits the auth-warn exactly as the real function does
# when json_file is absent/empty — so if it's called we will detect it.
# (The real _prowler_report also has other paths; the guard we're testing is
# the CALL SITE guard, i.e. "don't call _prowler_report at all for stripped
# providers".)
_prowler_report_stub() {
  local _provider="$1" _json_file="$2"
  if [[ ! -f "${_json_file:-/nonexistent}" || ! -s "${_json_file:-/nonexistent}" ]]; then
    _harness_warn "000" "Prowler ${_provider} scan produced no output" \
      "Check authentication and permissions for ${_provider}"
  fi
}

# ── Inline dispatch logic: Azure (representative stripped provider) ───────────
#
# This mirrors lines 358-378 of integration.sh at the time of #238.  The
# boolean conditions and call structure are reproduced verbatim; only the called
# functions are replaced by the stubs above.  If integration.sh's Azure block
# changes, update this copy and document the change.

_run_azure_dispatch_stripped() {
  # Reset output capture.
  _harness_output=""
  # Lean-image layout: azure provider dir is ABSENT.
  _prowler_install_dir="$1"

  # Credentials present (AZURE_CLIENT_ID path) — worst-case scenario.
  local AZURE_CLIENT_ID="fake-client-id"
  local AZURE_TENANT_ID="fake-tenant-id"

  # Replicate integration.sh Azure block verbatim (stubs replace real helpers).
  if _prowler_should_run_stub "azure" && [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
    if ! _prowler_provider_available "azure"; then
      _harness_skip "PROWLER-AZ-001" "Prowler Azure scan" \
        "Provider not included in this build (lean container image — see Dockerfile). Use a full prowler install."
    else
      _harness_info "Prowler: Scanning Azure (service principal)"
      local _azure_json
      _azure_json=$(_prowler_scan_stub "azure" --sp-env-auth)
      _prowler_report_stub "Azure" "$_azure_json" "PROWLER-AZ"
    fi
  elif _prowler_should_run_stub "azure" && _has_az_stub && _has_az_account_stub; then
    if ! _prowler_provider_available "azure"; then
      _harness_skip "PROWLER-AZ-001" "Prowler Azure scan" \
        "Provider not included in this build (lean container image — see Dockerfile). Use a full prowler install."
    else
      _harness_info "Prowler: Scanning Azure (CLI auth)"
      local _azure_json
      _azure_json=$(_prowler_scan_stub "azure" --az-cli-auth)
      _prowler_report_stub "Azure" "$_azure_json" "PROWLER-AZ"
    fi
  elif ! _prowler_should_run_stub "azure"; then
    _harness_skip "PROWLER-AZ-001" "Prowler Azure scan" \
      "Disabled by config (set prowler_providers in .claudesec.yml)"
  else
    _harness_skip "PROWLER-AZ-001" "Prowler Azure scan" \
      "Azure not configured (az login or set AZURE_CLIENT_ID)"
  fi
}

# ── Assert helpers for Group 4 ───────────────────────────────────────────────

assert_no_auth_warn() {
  local desc="$1"
  if echo "$_harness_output" | grep -q "Check authentication and permissions"; then
    echo "  FAIL: $desc — unexpected auth-WARN in output: $_harness_output"
    ((TEST_FAILED++))
  else
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  fi
}

assert_parity_skip() {
  local desc="$1"
  if echo "$_harness_output" | grep -q "not included in this build"; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc — parity-skip message absent in output: $_harness_output"
    ((TEST_FAILED++))
  fi
}

# ── Run Group 4 cases ────────────────────────────────────────────────────────

# Lean-image tmpdir: azure provider dir is absent (only aws is present).
_run_azure_dispatch_stripped "$tmpdir"

assert_no_auth_warn "azure stripped + creds present: no auth-WARN emitted"
assert_parity_skip  "azure stripped + creds present: parity-skip fires"

# Double-check: if azure IS present, the report path is taken (warn CAN appear).
# This validates the stub faithfully exercises the real path when provider is
# available — without it the stub could be broken and give a false-green above.
mkdir -p "$tmpdir/providers/azure"
_run_azure_dispatch_stripped "$tmpdir"
rmdir "$tmpdir/providers/azure"

if echo "$_harness_output" | grep -q "not included in this build"; then
  echo "  FAIL: azure present: parity-skip should NOT fire (stub is broken)"
  ((TEST_FAILED++))
else
  echo "  PASS: azure present: parity-skip does not fire (report path taken)"
  ((TEST_PASSED++))
fi

# ── Source-ordering guard: belt-and-suspenders ───────────────────────────────
# In addition to the behavioural test above, assert that in the real
# integration.sh the _prowler_provider_available guard appears before
# _prowler_report in each provider block.  This catches copy-paste ordering
# mistakes even if the harness above somehow misses them.
#
# Strategy: extract line numbers for every occurrence of both patterns in
# integration.sh and assert that each _prowler_report call is always preceded
# by a _prowler_provider_available call with a smaller line number (within the
# same provider block).  We use a simple check: the last _prowler_provider_available
# line before each _prowler_report line must exist and be smaller.

_check_ordering() {
  local avail_lines report_lines last_avail
  avail_lines=$(grep -n "_prowler_provider_available" "$INTEGRATION_SH" \
    | grep -v "^[0-9]*:#" \
    | cut -d: -f1)
  report_lines=$(grep -n "_prowler_report" "$INTEGRATION_SH" \
    | grep -v "^[0-9]*:#\|^[0-9]*:.*_prowler_report()" \
    | grep -v "^[0-9]*:_prowler_report()" \
    | cut -d: -f1)

  if [[ -z "$report_lines" ]]; then
    echo "  FAIL: ordering guard: no _prowler_report call sites found in integration.sh"
    ((TEST_FAILED++))
    return
  fi

  local all_ok=true
  while IFS= read -r rline; do
    # Find the largest _prowler_provider_available line number less than rline.
    last_avail=$(echo "$avail_lines" | awk -v r="$rline" '$1 < r {last=$1} END {print last+0}')
    if [[ "$last_avail" -eq 0 ]]; then
      echo "  FAIL: ordering guard: _prowler_report at line $rline has no preceding _prowler_provider_available"
      ((TEST_FAILED++))
      all_ok=false
    fi
  done <<< "$report_lines"

  if [[ "$all_ok" == "true" ]]; then
    echo "  PASS: ordering guard: every _prowler_report call site is preceded by _prowler_provider_available"
    ((TEST_PASSED++))
  fi
}

_check_ordering

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
