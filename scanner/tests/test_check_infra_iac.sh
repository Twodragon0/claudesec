#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/infra/iac.sh
# Run: bash scanner/tests/test_check_infra_iac.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes (checks.sh uses these variables for output formatting)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture pass/fail/warn/skip calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }

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
  source "$CHECKS_DIR/infra/iac.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── No Terraform / No Helm -> all skip ──────────────────────────────────────

echo "=== INFRA-020/021/022: No Terraform files -> skip ==="

mkdir -p "$tmpdir/empty"
printf '# readme\n' > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "No .tf files -> skip INFRA-020" "SKIP" "INFRA-020"
assert_has_result "No .tf files -> skip INFRA-021" "SKIP" "INFRA-021"
assert_has_result "No .tf files -> skip INFRA-022" "SKIP" "INFRA-022"

echo "=== INFRA-023: No Helm chart -> skip ==="

SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "No Chart.yaml -> skip INFRA-023" "SKIP" "INFRA-023"

# ── INFRA-020: Hardcoded secrets in Terraform ────────────────────────────────

echo "=== INFRA-020: Hardcoded secrets in Terraform ==="

# FAIL: password hardcoded in .tf file
# Runtime-assemble the dummy password from two fragments so the committed test
# source carries no `password = "<value>"` literal for GitGuardian to flag; the
# fixture written to disk still holds the full assignment the check detects.
mkdir -p "$tmpdir/tf_secret"
printf 'resource "aws_db_instance" "db" {\n  password = "%s%s"\n}\n' \
  'hunter2' 'supersecret' > "$tmpdir/tf_secret/main.tf"
SCAN_DIR="$tmpdir/tf_secret" run_check
assert_has_result "Hardcoded password in .tf -> FAIL INFRA-020" "FAIL" "INFRA-020"

# FAIL: api_key hardcoded in .tf file
mkdir -p "$tmpdir/tf_apikey"
cat > "$tmpdir/tf_apikey/vars.tf" <<'TF'
variable "config" {
  default = ""
}
resource "example" "r" {
  api_key = "some-hardcoded-key-value"
}
TF
SCAN_DIR="$tmpdir/tf_apikey" run_check
assert_has_result "Hardcoded api_key in .tf -> FAIL INFRA-020" "FAIL" "INFRA-020"

# FAIL: token hardcoded in .tf file
mkdir -p "$tmpdir/tf_token"
cat > "$tmpdir/tf_token/main.tf" <<'TF'
resource "service_account" "sa" {
  token = "my-static-token-value"
}
TF
SCAN_DIR="$tmpdir/tf_token" run_check
assert_has_result "Hardcoded token in .tf -> FAIL INFRA-020" "FAIL" "INFRA-020"

# PASS: .tf file present but no hardcoded secrets (uses var reference)
mkdir -p "$tmpdir/tf_clean"
cat > "$tmpdir/tf_clean/main.tf" <<'TF'
resource "aws_db_instance" "db" {
  engine   = "postgres"
  password = var.db_password
}
TF
SCAN_DIR="$tmpdir/tf_clean" run_check
assert_has_result "Terraform using var reference -> PASS INFRA-020" "PASS" "INFRA-020"

# ── INFRA-021: Terraform state file in repository ───────────────────────────

echo "=== INFRA-021: Terraform state file in repo ==="

# FAIL: terraform.tfstate present
mkdir -p "$tmpdir/tf_state"
cat > "$tmpdir/tf_state/main.tf" <<'TF'
resource "null_resource" "example" {}
TF
printf '{"version":4,"terraform_version":"1.5.0","resources":[]}\n' \
  > "$tmpdir/tf_state/terraform.tfstate"
SCAN_DIR="$tmpdir/tf_state" run_check
assert_has_result "terraform.tfstate present -> FAIL INFRA-021" "FAIL" "INFRA-021"

# PASS: .tf present but no .tfstate
mkdir -p "$tmpdir/tf_no_state"
cat > "$tmpdir/tf_no_state/main.tf" <<'TF'
resource "null_resource" "example" {}
TF
SCAN_DIR="$tmpdir/tf_no_state" run_check
assert_has_result "No terraform.tfstate -> PASS INFRA-021" "PASS" "INFRA-021"

# ── INFRA-022: Terraform lock file ───────────────────────────────────────────

echo "=== INFRA-022: Terraform dependency lock file ==="

# WARN: .tf present but no .terraform.lock.hcl
mkdir -p "$tmpdir/tf_no_lock"
cat > "$tmpdir/tf_no_lock/main.tf" <<'TF'
resource "null_resource" "example" {}
TF
SCAN_DIR="$tmpdir/tf_no_lock" run_check
assert_has_result "Missing .terraform.lock.hcl -> WARN INFRA-022" "WARN" "INFRA-022"

# PASS: both .tf and .terraform.lock.hcl present
mkdir -p "$tmpdir/tf_with_lock"
cat > "$tmpdir/tf_with_lock/main.tf" <<'TF'
resource "null_resource" "example" {}
TF
cat > "$tmpdir/tf_with_lock/.terraform.lock.hcl" <<'HCL'
provider "registry.terraform.io/hashicorp/null" {
  version = "3.2.1"
}
HCL
SCAN_DIR="$tmpdir/tf_with_lock" run_check
assert_has_result "Lock file present -> PASS INFRA-022" "PASS" "INFRA-022"

# ── INFRA-023: Helm chart default passwords ──────────────────────────────────

echo "=== INFRA-023: Helm default passwords in values.yaml ==="

# FAIL: default password in values.yaml
mkdir -p "$tmpdir/helm_bad/charts"
cat > "$tmpdir/helm_bad/Chart.yaml" <<'YAML'
apiVersion: v2
name: myapp
version: 0.1.0
YAML
cat > "$tmpdir/helm_bad/values.yaml" <<'YAML'
database:
  password: "admin"
YAML
SCAN_DIR="$tmpdir/helm_bad" run_check
assert_has_result "Default password in Helm values.yaml -> FAIL INFRA-023" "FAIL" "INFRA-023"

# FAIL: 'changeme' value in values.yaml
mkdir -p "$tmpdir/helm_changeme/charts"
cat > "$tmpdir/helm_changeme/Chart.yaml" <<'YAML'
apiVersion: v2
name: myapp
version: 0.1.0
YAML
cat > "$tmpdir/helm_changeme/values.yaml" <<'YAML'
auth:
  secret: "changeme"
YAML
SCAN_DIR="$tmpdir/helm_changeme" run_check
assert_has_result "'changeme' in Helm values.yaml -> FAIL INFRA-023" "FAIL" "INFRA-023"

# PASS: Chart.yaml present but values.yaml uses non-default value
mkdir -p "$tmpdir/helm_clean/charts"
cat > "$tmpdir/helm_clean/Chart.yaml" <<'YAML'
apiVersion: v2
name: myapp
version: 0.1.0
YAML
cat > "$tmpdir/helm_clean/values.yaml" <<'YAML'
database:
  password: ""
auth:
  existingSecret: my-app-secret
YAML
SCAN_DIR="$tmpdir/helm_clean" run_check
assert_has_result "No default passwords in Helm values -> PASS INFRA-023" "PASS" "INFRA-023"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
