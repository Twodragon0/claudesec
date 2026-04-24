#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh::_prowler_dashboard_summary_provider_label()
# Extracted pure helper: prowler provider slug → human-readable label.
# Run: bash scanner/tests/test_prowler_dashboard_summary_provider_label.sh
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

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

RED="" YELLOW="" CYAN="" GREEN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""
FORMAT="text"
QUIET=1
SEVERITY="low"
VERSION="test"
SCAN_DIR="$tmpdir"

# shellcheck disable=SC1091
source "$LIB_DIR/output.sh" 2>/dev/null || true

echo ""
echo "=== _prowler_dashboard_summary_provider_label() ==="

# Known single-word providers
assert_eq "aws"         "AWS"         "$(_prowler_dashboard_summary_provider_label aws)"
assert_eq "kubernetes"  "Kubernetes"  "$(_prowler_dashboard_summary_provider_label kubernetes)"
assert_eq "azure"       "Azure"       "$(_prowler_dashboard_summary_provider_label azure)"
assert_eq "gcp"         "GCP"         "$(_prowler_dashboard_summary_provider_label gcp)"
assert_eq "github"      "GitHub"      "$(_prowler_dashboard_summary_provider_label github)"
assert_eq "cloudflare"  "Cloudflare"  "$(_prowler_dashboard_summary_provider_label cloudflare)"
assert_eq "nhn"         "NHN Cloud"   "$(_prowler_dashboard_summary_provider_label nhn)"
assert_eq "iac"         "IaC"         "$(_prowler_dashboard_summary_provider_label iac)"
assert_eq "llm"         "LLM"         "$(_prowler_dashboard_summary_provider_label llm)"
assert_eq "openstack"   "OpenStack"   "$(_prowler_dashboard_summary_provider_label openstack)"

# Providers whose labels contain spaces
assert_eq "googleworkspace" "Google Workspace" "$(_prowler_dashboard_summary_provider_label googleworkspace)"
assert_eq "m365"            "Microsoft 365"    "$(_prowler_dashboard_summary_provider_label m365)"
assert_eq "image"           "Container Image"  "$(_prowler_dashboard_summary_provider_label image)"
assert_eq "oraclecloud"     "Oracle Cloud"     "$(_prowler_dashboard_summary_provider_label oraclecloud)"
assert_eq "alibabacloud"    "Alibaba Cloud"    "$(_prowler_dashboard_summary_provider_label alibabacloud)"
assert_eq "mongodbatlas"    "MongoDB Atlas"    "$(_prowler_dashboard_summary_provider_label mongodbatlas)"

# Unknown slugs pass through unchanged (fallthrough case)
assert_eq "unknown pass-through"     "madeupcloud"      "$(_prowler_dashboard_summary_provider_label madeupcloud)"
assert_eq "empty string pass-through" ""                "$(_prowler_dashboard_summary_provider_label "")"

# Case-sensitivity: the helper matches lowercase slugs only; upper-case passes through.
assert_eq "uppercase AWS pass-through" "AWS" "$(_prowler_dashboard_summary_provider_label AWS)"
assert_eq "mixed-case passes through"  "Kubernetes-Foo" "$(_prowler_dashboard_summary_provider_label Kubernetes-Foo)"

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
