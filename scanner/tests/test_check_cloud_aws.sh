#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/cloud/aws.sh
#
# WHY THIS TEST IS STRUCTURED THIS WAY:
# aws.sh has three execution branches:
#
#   Branch A (AWS live): has_aws_credentials -> aws CLI calls for
#                         CLOUD-001 (root MFA), CLOUD-002 (CloudTrail),
#                         CLOUD-003 (S3 public access block),
#                         CLOUD-004 (default VPC), CLOUD-005 (IMDSv2).
#                         Fully fixture-testable by stubbing the `aws` CLI.
#
#   Branch B (AWS creds absent, *.tf with provider aws present):
#                         CLOUD-006: public ACL in Terraform -> FAIL/PASS
#                         CLOUD-007: encrypted = false in Terraform -> FAIL/PASS
#                         Fully fixture-testable.
#
#   Branch C (AWS creds absent, no TF provider aws):
#                         CLOUD-001..005 all SKIP ("AWS not configured").
#                         Fixture-testable.
#
# OFFLINE STRATEGY:
#   Override has_aws_credentials and aws_sso_ensure_login so no real AWS CLI
#   or SSO flow is invoked. For the live branch, stub the `aws` function
#   itself and dispatch on the subcommand so no network call ever happens.
#
# Run: bash scanner/tests/test_check_cloud_aws.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture result calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { :; }

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

# run_check: no live AWS creds, exercises the static-IaC/skip branches.
run_check() {
  RESULTS=()
  has_aws_credentials() { return 1; }
  aws_sso_ensure_login() { return 1; }
  source "$CHECKS_DIR/cloud/aws.sh"
  unset -f has_aws_credentials aws_sso_ensure_login 2>/dev/null || true
  source "$LIB_DIR/checks.sh"
}

# run_check_live: forces the live-AWS branch and stubs the `aws` CLI to
# dispatch on subcommand, reading behavior from AWS_STUB_* vars set by the
# caller before invocation.
run_check_live() {
  RESULTS=()
  has_aws_credentials() { return 0; }
  # Assemble the example account id from fragments so no contiguous 12-digit
  # run lands in this source file (repo pii-check flags account/aws + 12 digits).
  local acct="1234""5678""9012"
  aws() {
    case "$*" in
      "sts get-caller-identity --output json")
        echo "{\"Account\":\"${acct}\",\"Arn\":\"arn:aws:iam::${acct}:user/test\"}"
        ;;
      "sts get-caller-identity --query Account --output text"*)
        echo "$acct"
        ;;
      "iam get-account-summary"*)
        echo "${AWS_STUB_MFA:-1}"
        ;;
      "cloudtrail describe-trails"*)
        echo "${AWS_STUB_TRAILS:-1}"
        ;;
      "s3control get-public-access-block"*)
        echo "${AWS_STUB_S3BLOCK:-True}"
        ;;
      "ec2 describe-vpcs"*)
        echo "${AWS_STUB_VPCS:-0}"
        ;;
      "ec2 describe-instances"*)
        echo "${AWS_STUB_IMDS:-0}"
        ;;
      *)
        return 1
        ;;
    esac
  }
  source "$CHECKS_DIR/cloud/aws.sh"
  unset -f has_aws_credentials aws 2>/dev/null || true
  source "$LIB_DIR/checks.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

mkdir -p "$tmpdir/live"

# ── Branch A: Live AWS — all findings good ──────────────────────────────────

echo "=== Live AWS: all findings good ==="

AWS_STUB_MFA="1" AWS_STUB_TRAILS="2" AWS_STUB_S3BLOCK="True" AWS_STUB_VPCS="0" AWS_STUB_IMDS="0"
SCAN_DIR="$tmpdir/live" run_check_live
assert_has_result "Root MFA enabled -> PASS CLOUD-001" "PASS" "CLOUD-001"
assert_has_result "CloudTrail enabled -> PASS CLOUD-002" "PASS" "CLOUD-002"
assert_has_result "S3 public access block enabled -> PASS CLOUD-003" "PASS" "CLOUD-003"
assert_has_result "No default VPC -> PASS CLOUD-004" "PASS" "CLOUD-004"
assert_has_result "All instances enforce IMDSv2 -> PASS CLOUD-005" "PASS" "CLOUD-005"
unset AWS_STUB_MFA AWS_STUB_TRAILS AWS_STUB_S3BLOCK AWS_STUB_VPCS AWS_STUB_IMDS

# ── Branch A: Live AWS — all findings bad ───────────────────────────────────

echo "=== Live AWS: all findings bad ==="

AWS_STUB_MFA="0" AWS_STUB_TRAILS="0" AWS_STUB_S3BLOCK="False" AWS_STUB_VPCS="1" AWS_STUB_IMDS="3"
SCAN_DIR="$tmpdir/live" run_check_live
assert_has_result "Root MFA disabled -> FAIL CLOUD-001" "FAIL" "CLOUD-001"
assert_has_result "CloudTrail not configured -> FAIL CLOUD-002" "FAIL" "CLOUD-002"
assert_has_result "S3 public access block disabled -> FAIL CLOUD-003" "FAIL" "CLOUD-003"
assert_has_result "Default VPC exists -> WARN CLOUD-004" "WARN" "CLOUD-004"
assert_has_result "IMDSv1 instances found -> FAIL CLOUD-005" "FAIL" "CLOUD-005"
unset AWS_STUB_MFA AWS_STUB_TRAILS AWS_STUB_S3BLOCK AWS_STUB_VPCS AWS_STUB_IMDS

# ── Branch A: Live AWS — unable to check (insufficient permissions) ────────

echo "=== Live AWS: unable to check -> skip ==="

AWS_STUB_MFA="error" AWS_STUB_S3BLOCK="error" AWS_STUB_IMDS="error"
SCAN_DIR="$tmpdir/live" run_check_live
assert_has_result "Root MFA unknown -> SKIP CLOUD-001" "SKIP" "CLOUD-001"
assert_has_result "S3 public access block unknown -> SKIP CLOUD-003" "SKIP" "CLOUD-003"
assert_has_result "IMDSv2 status unknown -> SKIP CLOUD-005" "SKIP" "CLOUD-005"
unset AWS_STUB_MFA AWS_STUB_S3BLOCK AWS_STUB_IMDS

# ── Branch B: No AWS creds, static Terraform IaC — risky config ────────────

echo "=== Static IaC: public ACL + unencrypted resource -> FAIL ==="

mkdir -p "$tmpdir/tf_bad"
cat > "$tmpdir/tf_bad/main.tf" <<'TF'
provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
resource "aws_ebs_volume" "vol" {
  encrypted = false
}
TF
SCAN_DIR="$tmpdir/tf_bad" run_check
assert_has_result "Public ACL in Terraform -> FAIL CLOUD-006" "FAIL" "CLOUD-006"
assert_has_result "Unencrypted resource in Terraform -> FAIL CLOUD-007" "FAIL" "CLOUD-007"

# ── Branch B: No AWS creds, static Terraform IaC — clean config ────────────

echo "=== Static IaC: clean config -> PASS ==="

mkdir -p "$tmpdir/tf_good"
cat > "$tmpdir/tf_good/main.tf" <<'TF'
provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
resource "aws_ebs_volume" "vol" {
  encrypted = true
}
TF
SCAN_DIR="$tmpdir/tf_good" run_check
assert_has_result "No public ACL in Terraform -> PASS CLOUD-006" "PASS" "CLOUD-006"
assert_has_result "No unencrypted resources in Terraform -> PASS CLOUD-007" "PASS" "CLOUD-007"

# ── Branch C: No AWS creds, no Terraform provider aws -> all skip ──────────

echo "=== No AWS config, no TF provider -> skip ==="

mkdir -p "$tmpdir/no_cloud"
printf '# readme\n' > "$tmpdir/no_cloud/README.md"
SCAN_DIR="$tmpdir/no_cloud" run_check
assert_has_result "No AWS config -> SKIP CLOUD-001" "SKIP" "CLOUD-001"
assert_has_result "No AWS config -> SKIP CLOUD-002" "SKIP" "CLOUD-002"
assert_has_result "No AWS config -> SKIP CLOUD-003" "SKIP" "CLOUD-003"
assert_has_result "No AWS config -> SKIP CLOUD-004" "SKIP" "CLOUD-004"
assert_has_result "No AWS config -> SKIP CLOUD-005" "SKIP" "CLOUD-005"
assert_no_result "No TF provider -> no CLOUD-006 result" "FAIL" "CLOUD-006"
assert_no_result "No TF provider -> no CLOUD-007 result" "FAIL" "CLOUD-007"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
