#!/usr/bin/env bash
# shellcheck disable=SC2034
# Direct-call coverage tests for scanner/lib/checks.sh.
#
# The existing test_checks_coverage.sh relies on var=$( source ...; cmd )
# command-substitution blocks for stub scoping. kcov v42 cannot reliably
# trace lines inside `$(...)` forked subshells, which leaves
# `return 0`/branch-success lines uncovered even when the path executes.
#
# This file uses the alternative pattern: define stubs, call the SUT in
# the *current* shell, then restore the stubs via stored declare -f
# output. kcov DEBUG-trap fires on each in-shell line, so lib branches
# get coverage.
#
# Targets (from kcov main artifact 26552645502):
#   L374  has_gcp_credentials   gcloud-auth success branch
#   L403  has_github_credentials  gh-auth-status success branch
#
# Run: bash scanner/tests/test_checks_lib_direct.sh
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

# Stub color codes referenced by checks.sh
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

# Snapshot the original definitions we'll override so each test can
# restore them. Bash's `declare -f` returns the function body as a
# multi-line string we can `eval` back later.
_orig_has_command=$(declare -f has_command)
_orig_run_with_timeout=$(declare -f run_with_timeout)

_restore_originals() {
  unset -f has_command 2>/dev/null || true
  unset -f run_with_timeout 2>/dev/null || true
  unset -f gcloud 2>/dev/null || true
  unset -f gh 2>/dev/null || true
  unset -f grep_stub 2>/dev/null || true
  eval "$_orig_has_command"
  eval "$_orig_run_with_timeout"
}

# ============================================================================
# L374: has_gcp_credentials -> gcloud auth list success path
#
# Override has_command to recognize 'gcloud' as present, run_with_timeout
# to passthrough, gcloud to emit an account name on stdout. The pipeline
# `... | grep -q .` then succeeds and the inline `return 0` runs.
# ============================================================================
echo ""
echo "=== L374: has_gcp_credentials gcloud-success branch ==="

has_command() { [[ "$1" == "gcloud" ]]; }
run_with_timeout() {
  shift          # consume timeout
  "$@"           # passthrough — the real impl uses `timeout/gtimeout/python3 fallback`
}
gcloud() {
  # Mimic `gcloud auth list --filter=status:ACTIVE --format=value(account)`
  # producing a single active-account line so the downstream `grep -q .`
  # matches.
  echo "tester@example.com"
}

has_gcp_credentials
rc=$?
assert_eq "L374: has_gcp_credentials returns 0 with active gcloud account" "0" "$rc"

_restore_originals

# ============================================================================
# L403: has_github_credentials -> gh auth status success path
#
# Two preconditions on the function: GH_TOKEN and GITHUB_TOKEN must both
# be empty (so the env-var branch is skipped), and gh auth status must
# succeed under run_with_timeout.
# ============================================================================
echo ""
echo "=== L403: has_github_credentials gh-auth-status success branch ==="

OLD_GH_TOKEN="${GH_TOKEN:-}"
OLD_GITHUB_TOKEN="${GITHUB_TOKEN:-}"
unset GH_TOKEN GITHUB_TOKEN

has_command() { [[ "$1" == "gh" ]]; }
run_with_timeout() {
  shift          # consume timeout
  "$@"
}
gh() {
  # `gh auth status` exits 0 when authenticated.
  [[ "$1" == "auth" && "$2" == "status" ]] && return 0
  return 1
}

has_github_credentials
rc=$?
assert_eq "L403: has_github_credentials returns 0 with gh-auth-status success" "0" "$rc"

# Restore env
[[ -n "$OLD_GH_TOKEN" ]] && export GH_TOKEN="$OLD_GH_TOKEN"
[[ -n "$OLD_GITHUB_TOKEN" ]] && export GITHUB_TOKEN="$OLD_GITHUB_TOKEN"
_restore_originals

# ============================================================================
# Additional pass: drive has_gcp_credentials through its OTHER branches
# (L376-377 ADC file path) and has_github_credentials through its env-var
# path (L400) to ensure no regression in already-covered code.
# ============================================================================
echo ""
echo "=== Regression: existing branches still pass ==="

# has_gcp_credentials L376-377: GOOGLE_APPLICATION_CREDENTIALS set + file present
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
touch "$tmpdir/adc.json"
has_command() { return 1; }   # gcloud absent
OLD_GAC="${GOOGLE_APPLICATION_CREDENTIALS:-}"
export GOOGLE_APPLICATION_CREDENTIALS="$tmpdir/adc.json"
has_gcp_credentials
rc=$?
assert_eq "regression: has_gcp_credentials ADC-file branch returns 0" "0" "$rc"
[[ -n "$OLD_GAC" ]] && export GOOGLE_APPLICATION_CREDENTIALS="$OLD_GAC" || unset GOOGLE_APPLICATION_CREDENTIALS
_restore_originals

# has_github_credentials L399-400: GH_TOKEN env var set
export GH_TOKEN="ghp_test_token"
has_github_credentials
rc=$?
assert_eq "regression: has_github_credentials GH_TOKEN-env branch returns 0" "0" "$rc"
unset GH_TOKEN

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "Results: PASSED=$TEST_PASSED FAILED=$TEST_FAILED"
echo "=========================================="
[[ "$TEST_FAILED" -eq 0 ]] && exit 0 || exit 1
