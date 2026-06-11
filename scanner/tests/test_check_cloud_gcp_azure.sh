#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/cloud/gcp-azure.sh
#
# WHY THIS TEST IS NARROW:
# gcp-azure.sh has three execution branches:
#
#   Branch A (GCP live):  has_gcp_credentials -> gcloud CLI calls.
#                         CLOUD-010 and CLOUD-011 are entirely live-CLI-dependent
#                         (gcloud projects get-iam-policy, gcloud iam list).
#                         Offline-testable only as SKIP when the helper returns false.
#
#   Branch B (GCP static IaC, gcloud absent but *.tf with provider google):
#                         CLOUD-012: uniform_bucket_level_access = false -> FAIL
#                                    otherwise -> PASS
#                         Fully fixture-testable.
#
#   Branch C (GCP absent, no TF provider google):
#                         CLOUD-010 SKIP, CLOUD-011 SKIP.
#                         Fixture-testable.
#
#   Branch D (Azure live): has_azure_credentials -> az CLI calls.
#                          CLOUD-020 and CLOUD-021 require a live az session.
#                          Offline-testable only as SKIP.
#
#   Branch E (Azure static IaC, az absent but *.tf with provider azurerm):
#                         CLOUD-022: https_only = false -> FAIL
#                                    otherwise -> PASS
#                         Fully fixture-testable.
#
#   Branch F (Azure absent, no TF provider azurerm):
#                         CLOUD-020 SKIP, CLOUD-021 SKIP.
#                         Fixture-testable.
#
# OFFLINE STRATEGY:
#   Override has_gcp_credentials and has_azure_credentials to return 1 (not found),
#   then create fixture *.tf files to exercise the static IaC paths.
#   For the "no cloud configured" branches, use directories with no *.tf provider
#   content and the same overrides.
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_cloud_gcp_azure.sh
export CLAUDESEC_DASHBOARD_OFFLINE=1
set -uo pipefail

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

# Capture result calls instead of printing
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

# run_check: override the two credential helpers to return 1 (no live cloud),
# then source the check so static-IaC and skip branches are exercised.
run_check() {
  RESULTS=()
  has_gcp_credentials() { return 1; }
  has_azure_credentials() { return 1; }
  source "$CHECKS_DIR/cloud/gcp-azure.sh"
  unset -f has_gcp_credentials has_azure_credentials 2>/dev/null || true
  # Re-import real helpers so subsequent calls to checks.sh work correctly
  source "$LIB_DIR/checks.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── Branch C: No GCP config, no TF google provider -> CLOUD-010/011 skip ─────

echo "=== CLOUD-010/011: No GCP config and no TF -> skip ==="

mkdir -p "$tmpdir/no_cloud"
cat > "$tmpdir/no_cloud/main.tf" <<'TF'
resource "null_resource" "example" {}
TF
SCAN_DIR="$tmpdir/no_cloud" run_check
assert_has_result "No GCP config -> skip CLOUD-010" "SKIP" "CLOUD-010"
assert_has_result "No GCP config -> skip CLOUD-011" "SKIP" "CLOUD-011"

echo "=== CLOUD-010/011: Completely empty project -> skip ==="

mkdir -p "$tmpdir/empty"
printf '# readme\n' > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "Empty project -> skip CLOUD-010" "SKIP" "CLOUD-010"
assert_has_result "Empty project -> skip CLOUD-011" "SKIP" "CLOUD-011"

# ── Branch B: GCP static IaC — CLOUD-012 ─────────────────────────────────────

echo "=== CLOUD-012: uniform_bucket_level_access = false -> FAIL ==="

mkdir -p "$tmpdir/gcp_bucket_bad"
cat > "$tmpdir/gcp_bucket_bad/storage.tf" <<'TF'
provider "google" {
  project = "example-project"
}
resource "google_storage_bucket" "my_bucket" {
  name                        = "my-bucket"
  location                    = "US"
  uniform_bucket_level_access = false
}
TF
SCAN_DIR="$tmpdir/gcp_bucket_bad" run_check
assert_has_result "uniform_bucket_level_access=false -> FAIL CLOUD-012" "FAIL" "CLOUD-012"

echo "=== CLOUD-012: uniform_bucket_level_access = true -> PASS ==="

mkdir -p "$tmpdir/gcp_bucket_good"
cat > "$tmpdir/gcp_bucket_good/storage.tf" <<'TF'
provider "google" {
  project = "example-project"
}
resource "google_storage_bucket" "my_bucket" {
  name                        = "my-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}
TF
SCAN_DIR="$tmpdir/gcp_bucket_good" run_check
assert_has_result "uniform_bucket_level_access=true -> PASS CLOUD-012" "PASS" "CLOUD-012"

echo "=== CLOUD-012: GCP TF provider, no bucket resource -> PASS ==="

mkdir -p "$tmpdir/gcp_no_bucket"
cat > "$tmpdir/gcp_no_bucket/main.tf" <<'TF'
provider "google" {
  project = "example-project"
}
resource "google_compute_instance" "vm" {
  name         = "my-vm"
  machine_type = "e2-micro"
}
TF
SCAN_DIR="$tmpdir/gcp_no_bucket" run_check
assert_has_result "GCP TF no bucket resource -> PASS CLOUD-012" "PASS" "CLOUD-012"

# ── Branch F: No Azure config, no TF azurerm provider -> CLOUD-020/021 skip ──

echo "=== CLOUD-020/021: No Azure config and no TF -> skip ==="

SCAN_DIR="$tmpdir/no_cloud" run_check
assert_has_result "No Azure config -> skip CLOUD-020" "SKIP" "CLOUD-020"
assert_has_result "No Azure config -> skip CLOUD-021" "SKIP" "CLOUD-021"

# ── Branch E: Azure static IaC — CLOUD-022 ───────────────────────────────────

echo "=== CLOUD-022: https_only = false -> FAIL ==="

mkdir -p "$tmpdir/az_https_bad"
cat > "$tmpdir/az_https_bad/webapp.tf" <<'TF'
provider "azurerm" {
  features {}
}
resource "azurerm_app_service" "app" {
  name                = "my-app"
  resource_group_name = "my-rg"
  location            = "eastus"
  https_only          = false
}
TF
SCAN_DIR="$tmpdir/az_https_bad" run_check
assert_has_result "https_only=false -> FAIL CLOUD-022" "FAIL" "CLOUD-022"

echo "=== CLOUD-022: https_only = true -> PASS ==="

mkdir -p "$tmpdir/az_https_good"
cat > "$tmpdir/az_https_good/webapp.tf" <<'TF'
provider "azurerm" {
  features {}
}
resource "azurerm_app_service" "app" {
  name                = "my-app"
  resource_group_name = "my-rg"
  location            = "eastus"
  https_only          = true
}
TF
SCAN_DIR="$tmpdir/az_https_good" run_check
assert_has_result "https_only=true -> PASS CLOUD-022" "PASS" "CLOUD-022"

echo "=== CLOUD-022: Azure TF provider, no https_only attribute -> PASS ==="

mkdir -p "$tmpdir/az_no_https_attr"
cat > "$tmpdir/az_no_https_attr/network.tf" <<'TF'
provider "azurerm" {
  features {}
}
resource "azurerm_virtual_network" "vnet" {
  name                = "my-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = "eastus"
  resource_group_name = "my-rg"
}
TF
SCAN_DIR="$tmpdir/az_no_https_attr" run_check
assert_has_result "Azure TF no https_only attribute -> PASS CLOUD-022" "PASS" "CLOUD-022"

# ── Mixed: GCP and Azure TF providers in same project ─────────────────────────

echo "=== Mixed GCP+Azure TF: CLOUD-012 PASS and CLOUD-022 PASS ==="

mkdir -p "$tmpdir/mixed_cloud"
cat > "$tmpdir/mixed_cloud/gcp.tf" <<'TF'
provider "google" {
  project = "example-project"
}
resource "google_storage_bucket" "b" {
  name                        = "safe-bucket"
  location                    = "US"
  uniform_bucket_level_access = true
}
TF
cat > "$tmpdir/mixed_cloud/azure.tf" <<'TF'
provider "azurerm" {
  features {}
}
resource "azurerm_app_service" "app" {
  name                = "my-app"
  resource_group_name = "my-rg"
  location            = "eastus"
  https_only          = true
}
TF
SCAN_DIR="$tmpdir/mixed_cloud" run_check
assert_has_result "Mixed cloud: GCP bucket OK -> PASS CLOUD-012" "PASS" "CLOUD-012"
assert_has_result "Mixed cloud: Azure HTTPS OK -> PASS CLOUD-022" "PASS" "CLOUD-022"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
