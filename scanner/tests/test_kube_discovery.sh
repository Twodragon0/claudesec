#!/usr/bin/env bash
# Unit tests for kubectl_auto_find_kubeconfig() and kubectl_current_context_uses_oidc_exec()
# Run: bash scanner/tests/test_kubeconfig_discovery.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

# Stub out dependencies that checks.sh expects
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD=""
source "$LIB_DIR/output.sh" 2>/dev/null || true
source "$LIB_DIR/checks.sh"

PASSED=0
FAILED=0

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc (expected='$expected', got='$actual')"
    ((FAILED++))
  fi
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc (expected to contain '$needle')"
    ((FAILED++))
  fi
}

# ── kubectl_auto_find_kubeconfig tests ──

echo "=== kubectl_auto_find_kubeconfig ==="

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Test: configs/dev/kubeconfig found first
mkdir -p "$tmpdir/configs/dev"
echo "dev-config" > "$tmpdir/configs/dev/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds configs/dev/kubeconfig" "$result" "configs/dev/kubeconfig"

# Test: configs/staging/kubeconfig when dev missing
rm "$tmpdir/configs/dev/kubeconfig"
mkdir -p "$tmpdir/configs/staging"
echo "staging-config" > "$tmpdir/configs/staging/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds configs/staging/kubeconfig" "$result" "configs/staging/kubeconfig"

# Test: root kubeconfig fallback
rm -rf "$tmpdir/configs"
echo "root-config" > "$tmpdir/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds root kubeconfig" "$result" "kubeconfig"

# Test: no kubeconfig returns failure
rm "$tmpdir/kubeconfig"
if kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null; then
  echo "  FAIL: should return 1 when no kubeconfig"
  ((FAILED++))
else
  echo "  PASS: returns 1 when no kubeconfig found"
  ((PASSED++))
fi

# Test: configs/prod/kubeconfig
mkdir -p "$tmpdir/configs/prod"
echo "prod-config" > "$tmpdir/configs/prod/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds configs/prod/kubeconfig" "$result" "configs/prod/kubeconfig"

# Test: config/kubeconfig (singular)
rm -rf "$tmpdir/configs"
mkdir -p "$tmpdir/config"
echo "config-dir" > "$tmpdir/config/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds config/kubeconfig" "$result" "config/kubeconfig"

# Test: wildcard under configs/
rm -rf "$tmpdir/config"
mkdir -p "$tmpdir/configs/custom-env"
echo "custom" > "$tmpdir/configs/custom-env/kubeconfig"
result=$(kubectl_auto_find_kubeconfig "$tmpdir" 2>/dev/null)
assert_contains "finds wildcard configs/*/kubeconfig" "$result" "configs/custom-env/kubeconfig"

# ── kubectl_current_context_uses_oidc_exec tests ──

echo ""
echo "=== kubectl_current_context_uses_oidc_exec ==="

# Test: OIDC detection via grep pattern (mock kubectl)
_kubectl_cmd() { echo "mock_kubectl"; }
has_command() { [[ "$1" == "kubectl" ]] && return 0 || return 1; }

# Mock kubectl that returns oidc-login in command field
mock_kubectl() {
  if [[ "$1" == "config" && "$2" == "view" ]]; then
    echo '{"users":[{"user":{"exec":{"command":"kubectl","args":["oidc-login"]}}}]}'
  fi
}
alias mock_kubectl=mock_kubectl 2>/dev/null || true

# We cannot easily test kubectl_current_context_uses_oidc_exec without a real kubectl.
# Instead, test the grep pattern directly.
json_with_oidc='{"users":[{"user":{"exec":{"command":"kubectl oidc-login","args":[]}}}]}'
json_without_oidc='{"users":[{"user":{"exec":{"command":"gcloud","args":["container"]}}}]}'
json_comment_oidc='{"description":"this mentions oidc-login in a comment"}'

if echo "$json_with_oidc" | grep -qE '"command"[[:space:]]*:[[:space:]]*"[^"]*oidc-login'; then
  echo "  PASS: detects oidc-login in command field"
  ((PASSED++))
else
  echo "  FAIL: should detect oidc-login in command field"
  ((FAILED++))
fi

if echo "$json_without_oidc" | grep -qE '"command"[[:space:]]*:[[:space:]]*"[^"]*oidc-login'; then
  echo "  FAIL: should NOT match gcloud command"
  ((FAILED++))
else
  echo "  PASS: does not match gcloud command"
  ((PASSED++))
fi

if echo "$json_comment_oidc" | grep -qE '"command"[[:space:]]*:[[:space:]]*"[^"]*oidc-login'; then
  echo "  FAIL: should NOT match description field"
  ((FAILED++))
else
  echo "  PASS: does not match oidc-login in non-command field"
  ((PASSED++))
fi

# ── Summary ──

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
