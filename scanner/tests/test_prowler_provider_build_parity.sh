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

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
