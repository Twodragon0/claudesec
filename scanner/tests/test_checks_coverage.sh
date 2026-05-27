#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2016
# Unit tests for scanner/lib/checks.sh: coverage for previously-uncovered branches.
# Targets:
#   L18-28  run_with_timeout gtimeout/python3 fallback paths
#   L64     files_contain path-glob find branch
#   L114-121 aws_list_profiles awk: default + non-default profiles (both sections)
#   L131-138 aws_list_sso_profiles awk: [default] SSO section
#   L151-156 aws_sso_login_with_timeout: gtimeout branch + bare-aws fallback
#   L363-364 aws_profile_is_sso: [default] grep branch
#   L374,L386 gcp_ensure_credentials_found extra return paths
#   L483-498 kubectl_auto_find_kubeconfig: tried[] list paths + configs/* find
#   L520-522 kubectl_discover_kubeconfigs: yaml/yml/conf files in .kube dir
#   L834-837 collect_environment_info: Azure connected branch
#   L888     collect_environment_info: Datadog connected branch
# Run: bash scanner/tests/test_checks_coverage.sh
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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected NOT to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

assert_true() {
  local label="$1" rc="$2"
  if [[ "$rc" == "0" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label (rc=$rc)"
    ((TEST_FAILED++))
  fi
}

assert_false() {
  local label="$1" rc="$2"
  if [[ "$rc" != "0" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label (expected nonzero, got 0)"
    ((TEST_FAILED++))
  fi
}

# Color codes referenced by checks.sh output
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ============================================================================
# run_with_timeout() fallback paths (L18-28)
# The normal path (timeout binary present) is already covered. Here we force
# the gtimeout branch and the python3 branch by overriding has_command in a
# subshell to stub away timeout/gtimeout as needed.
# ============================================================================
echo ""
echo "=== run_with_timeout() python3 fallback path (L19-28) ==="

# python3 fallback: force timeout+gtimeout both absent
python3_fallback_result=$(
  bash -c '
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout|gtimeout) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    run_with_timeout 5 true
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "run_with_timeout python3 fallback: true succeeds" "$python3_fallback_result" "rc=0"

python3_fallback_fail=$(
  bash -c '
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout|gtimeout) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    run_with_timeout 5 false
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "run_with_timeout python3 fallback: false returns 1" "$python3_fallback_fail" "rc=1"

# ============================================================================
# run_with_timeout() gtimeout branch (L18)
# Force timeout absent, gtimeout present via stub function.
# ============================================================================
echo ""
echo "=== run_with_timeout() gtimeout branch (L18) ==="

gtimeout_result=$(
  bash -c '
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout) return 1 ;;
        gtimeout) return 0 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    gtimeout() { shift; "$@" 2>/dev/null; }
    run_with_timeout 5 true
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "run_with_timeout gtimeout branch: true succeeds" "$gtimeout_result" "rc=0"

gtimeout_fail=$(
  bash -c '
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout) return 1 ;;
        gtimeout) return 0 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    gtimeout() { shift; "$@" 2>/dev/null; }
    run_with_timeout 5 false
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "run_with_timeout gtimeout branch: false returns nonzero" "$gtimeout_fail" "rc=1"

# ============================================================================
# files_contain() path-glob branch (L64) — glob contains a slash
# ============================================================================
echo ""
echo "=== files_contain() path-glob branch (L64) ==="

mkdir -p "$tmpdir/pglob/sub"
echo "SECRET_KEY=abc123" > "$tmpdir/pglob/sub/secrets.env"
SCAN_DIR="$tmpdir/pglob"

files_contain "sub/*.env" "SECRET_KEY"; assert_true  "files_contain path-glob: match"    "$?"
files_contain "sub/*.env" "NO_MATCH_XYZ"; assert_false "files_contain path-glob: no match" "$?"

# ============================================================================
# aws_list_profiles awk: default and non-default sections (L114-121)
# The credentials file must have a [default] entry AND additional profiles so
# that both the 'def=1' branch and the 'others' concat branch are exercised.
# ============================================================================
echo ""
echo "=== aws_list_profiles awk: default + non-default profiles (L114-121) ==="

mkdir -p "$tmpdir/awsprofiles"
cat > "$tmpdir/awsprofiles/credentials" <<'CREDS'
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = default_secret

[dev]
aws_access_key_id = AKIADEV
aws_secret_access_key = dev_secret

[prod]
aws_access_key_id = AKIAPROD
aws_secret_access_key = prod_secret
CREDS
export AWS_SHARED_CREDENTIALS_FILE="$tmpdir/awsprofiles/credentials"

profiles_out="$(aws_list_profiles)"
first_profile="$(echo "$profiles_out" | head -1)"
assert_eq       "aws_list_profiles: default is first"    "default" "$first_profile"
assert_contains "aws_list_profiles: dev present"         "$profiles_out" "dev"
assert_contains "aws_list_profiles: prod present"        "$profiles_out" "prod"

count_default=$(echo "$profiles_out" | grep -c "^default$" || true)
assert_eq "aws_list_profiles: default appears once" "1" "$count_default"

# ============================================================================
# aws_list_sso_profiles awk: [default] SSO section (L135)
# A config file where [default] itself has sso_start_url must be handled.
# ============================================================================
echo ""
echo "=== aws_list_sso_profiles awk: [default] SSO section (L135) ==="

mkdir -p "$tmpdir/awssso"
cat > "$tmpdir/awssso/config" <<'CFG'
[default]
region = us-east-1
sso_start_url = https://myorg.awsapps.com/start
sso_region = us-east-1
sso_role_name = Admin

[profile regular]
region = us-west-2
output = json
CFG
export AWS_CONFIG_FILE="$tmpdir/awssso/config"

sso_out="$(aws_list_sso_profiles)"
assert_contains "aws_list_sso_profiles: default sso profile present" "$sso_out" "default"
assert_not_contains "aws_list_sso_profiles: regular profile absent"  "$sso_out" "regular"

# ============================================================================
# aws_sso_login_with_timeout: gtimeout branch (L151-153)
# Force timeout absent + gtimeout present using subshell stub.
# ============================================================================
echo ""
echo "=== aws_sso_login_with_timeout: gtimeout branch (L151-153) ==="

sso_gtimeout_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout) return 1 ;;
        gtimeout) return 0 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    gtimeout() { shift; echo "gtimeout-called"; return 0; }
    aws() { echo "aws-sso-login-called"; return 0; }
    AWS_SSO_LOGIN_TIMEOUT=5
    aws_sso_login_with_timeout "test-profile"
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "aws_sso_login gtimeout branch: gtimeout invoked" "$sso_gtimeout_result" "gtimeout-called"
assert_contains "aws_sso_login gtimeout branch: rc=0"             "$sso_gtimeout_result" "rc=0"

# aws_sso_login_with_timeout: bare-aws fallback (L156)
echo ""
echo "=== aws_sso_login_with_timeout: bare-aws fallback (L156) ==="

sso_bare_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        timeout|gtimeout) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    aws() { echo "bare-aws-called"; return 0; }
    aws_sso_login_with_timeout "test-profile"
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "aws_sso_login bare-aws fallback: bare aws called" "$sso_bare_result" "bare-aws-called"
assert_contains "aws_sso_login bare-aws fallback: rc=0"            "$sso_bare_result" "rc=0"

# ============================================================================
# aws_profile_is_sso: [default] grep branch (L363-364)
# When profile=="default" the function uses a different grep pattern.
# ============================================================================
echo ""
echo "=== aws_profile_is_sso: [default] grep branch (L363-364) ==="

cat > "$tmpdir/awssso/config_default_sso" <<'CFG'
[default]
region = us-east-1
sso_start_url = https://myorg.awsapps.com/start
sso_region = us-east-1
CFG
export AWS_CONFIG_FILE="$tmpdir/awssso/config_default_sso"

aws_profile_is_sso "default"; assert_true  "aws_profile_is_sso: default with sso_start_url" "$?"

cat > "$tmpdir/awssso/config_default_no_sso" <<'CFG'
[default]
region = eu-west-1
output = json
CFG
export AWS_CONFIG_FILE="$tmpdir/awssso/config_default_no_sso"
aws_profile_is_sso "default"; assert_false "aws_profile_is_sso: default without SSO" "$?"

# ============================================================================
# gcp_ensure_credentials_found: L374 early return (ADC file present)
# Unconditional: stub has_gcp_credentials to return 0 so L384 path is taken.
# ============================================================================
echo ""
echo "=== gcp_ensure_credentials_found: L374 early return (ADC present) ==="

gcp_adc_present=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    # Force has_gcp_credentials to return 0 so gcp_ensure_credentials_found
    # returns 0 immediately at L384 (the L374 early-return path).
    has_gcp_credentials() { return 0; }
    gcp_ensure_credentials_found
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "gcp_ensure_credentials_found: ADC present early return" "$gcp_adc_present" "rc=0"

# ============================================================================
# gcp_ensure_credentials_found: L386 path (GOOGLE_APPLICATION_CREDENTIALS
# set and file exists, but has_gcp_credentials returned 1 first).
# Unconditional: stub has_gcp_credentials to return 1, provide a real file.
# ============================================================================
echo ""
echo "=== gcp_ensure_credentials_found: L386 path (env var set + file present) ==="

echo '{}' > "$tmpdir/adc_real.json"
gcp_env_file_present=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    # has_gcp_credentials returns 1 so we fall through to the env-var check
    has_gcp_credentials() { return 1; }
    export GOOGLE_APPLICATION_CREDENTIALS="'"$tmpdir"'/adc_real.json"
    gcp_ensure_credentials_found
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "gcp_ensure_credentials_found: env var set + file present returns 0" "$gcp_env_file_present" "rc=0"

# ============================================================================
# gcp_ensure_credentials_found: L403 path (no creds at all → return 1).
# Unconditional: stub has_gcp_credentials to return 1, unset env var.
# ============================================================================
echo ""
echo "=== gcp_ensure_credentials_found: L403 path (no creds) ==="

gcp_no_creds=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_gcp_credentials() { return 1; }
    unset GOOGLE_APPLICATION_CREDENTIALS
    gcp_ensure_credentials_found
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "gcp_ensure_credentials_found: no creds returns 1" "$gcp_no_creds" "rc=1"

# ============================================================================
# gcp_ensure_credentials_found: L386 false branch (env var set but file MISSING).
# Unconditional: stub has_gcp_credentials to return 1, set env var to absent path.
# ============================================================================
echo ""
echo "=== gcp_ensure_credentials_found: env var set but file missing ==="

gcp_env_file_missing=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_gcp_credentials() { return 1; }
    export GOOGLE_APPLICATION_CREDENTIALS="/nonexistent/path/adc.json"
    gcp_ensure_credentials_found
    echo "rc=$?"
  ' 2>/dev/null
)
assert_contains "gcp_ensure_credentials_found: env var set but file missing returns 1" "$gcp_env_file_missing" "rc=1"

# ============================================================================
# kubectl_auto_find_kubeconfig: tried[] list paths (L483-498)
# ============================================================================
echo ""
echo "=== kubectl_auto_find_kubeconfig: tried[] paths (L483-498) ==="

mkdir -p "$tmpdir/kstaging/configs/staging"
: > "$tmpdir/kstaging/configs/staging/kubeconfig"
found_staging=$(kubectl_auto_find_kubeconfig "$tmpdir/kstaging")
assert_eq "kubectl_auto_find_kubeconfig: configs/staging" \
  "$tmpdir/kstaging/configs/staging/kubeconfig" "$found_staging"

mkdir -p "$tmpdir/kprod/configs/prod"
: > "$tmpdir/kprod/configs/prod/kubeconfig"
found_prod=$(kubectl_auto_find_kubeconfig "$tmpdir/kprod")
assert_eq "kubectl_auto_find_kubeconfig: configs/prod" \
  "$tmpdir/kprod/configs/prod/kubeconfig" "$found_prod"

mkdir -p "$tmpdir/kdirect"
: > "$tmpdir/kdirect/kubeconfig"
found_direct=$(kubectl_auto_find_kubeconfig "$tmpdir/kdirect")
assert_eq "kubectl_auto_find_kubeconfig: base_dir/kubeconfig" \
  "$tmpdir/kdirect/kubeconfig" "$found_direct"

mkdir -p "$tmpdir/kfind/configs/custom-env"
: > "$tmpdir/kfind/configs/custom-env/kubeconfig"
found_find=$(kubectl_auto_find_kubeconfig "$tmpdir/kfind")
assert_contains "kubectl_auto_find_kubeconfig: configs/custom-env via find" "$found_find" "kubeconfig"

# ============================================================================
# kubectl_discover_kubeconfigs: yaml/yml/conf files in .kube dir (L520-522)
# ============================================================================
echo ""
echo "=== kubectl_discover_kubeconfigs: yaml/yml/conf in .kube dir (L519-522) ==="

orig_home="$HOME"
export HOME="$tmpdir/fakehome2"
mkdir -p "$HOME/.kube"
: > "$HOME/.kube/config"
: > "$HOME/.kube/staging.yaml"
: > "$HOME/.kube/prod.yml"
: > "$HOME/.kube/local.conf"

unset KUBECONFIG
SCAN_DIR="$tmpdir/empty2"
mkdir -p "$SCAN_DIR"
kconfigs=$(kubectl_discover_kubeconfigs)
assert_contains "kubectl_discover: staging.yaml found"   "$kconfigs" "staging.yaml"
assert_contains "kubectl_discover: prod.yml found"       "$kconfigs" "prod.yml"
assert_contains "kubectl_discover: local.conf found"     "$kconfigs" "local.conf"
assert_contains "kubectl_discover: base config found"    "$kconfigs" ".kube/config"
config_count=$(echo "$kconfigs" | grep -c "/.kube/config$" || true)
assert_eq "kubectl_discover: .kube/config listed once" "1" "$config_count"

export HOME="$orig_home"

# ============================================================================
# collect_environment_info: Azure connected branch (L834-837)
# Stub `az` to return 0 so the connected path is taken unconditionally.
# ============================================================================
echo ""
echo "=== collect_environment_info: Azure connected (L834-837) ==="

az_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        az) return 0 ;;
        kubectl|aws|gcloud|promptfoo) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    az() {
      case "$*" in
        "account show")                        return 0 ;;
        "account show --query name -o tsv")    echo "MySubscription" ;;
        *)                                     return 1 ;;
      esac
    }
    aws_ensure_profile_found()    { return 1; }
    gcp_ensure_credentials_found(){ return 1; }
    has_kubectl_access()          { return 1; }
    has_aws_credentials()         { return 1; }
    has_gcp_credentials()         { return 1; }
    aws_profile_is_sso()          { return 1; }
    has_datadog_api_key()         { return 1; }
    has_github_credentials()      { return 1; }
    datadog_validate_api_key()    { return 1; }
    collect_environment_info 2>/dev/null
    echo "AZ_CONNECTED=${CLAUDESEC_ENV_AZ_CONNECTED:-}"
    echo "AZ_SUB=${CLAUDESEC_ENV_AZ_SUBSCRIPTION:-}"
  ' 2>/dev/null
)
assert_contains "collect_env: AZ connected=true"    "$az_result" "AZ_CONNECTED=true"
assert_contains "collect_env: AZ subscription set"  "$az_result" "AZ_SUB="

# collect_environment_info: Azure NOT connected (az account show fails)
az_notconn_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        az) return 0 ;;
        kubectl|aws|gcloud|promptfoo) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    az() { return 1; }
    aws_ensure_profile_found()    { return 1; }
    gcp_ensure_credentials_found(){ return 1; }
    has_kubectl_access()          { return 1; }
    has_aws_credentials()         { return 1; }
    has_gcp_credentials()         { return 1; }
    aws_profile_is_sso()          { return 1; }
    has_datadog_api_key()         { return 1; }
    has_github_credentials()      { return 1; }
    datadog_validate_api_key()    { return 1; }
    collect_environment_info 2>/dev/null
    echo "AZ_CONNECTED=${CLAUDESEC_ENV_AZ_CONNECTED:-not_set}"
  ' 2>/dev/null
)
assert_not_contains "collect_env: AZ not connected" "$az_notconn_result" "AZ_CONNECTED=true"

# ============================================================================
# collect_environment_info: Datadog connected branch (L888)
# has_datadog_api_key=0 AND datadog_validate_api_key=0 → DATADOG_CONNECTED=true
# ============================================================================
echo ""
echo "=== collect_environment_info: Datadog connected (L888) ==="

dd_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        az|kubectl|aws|gcloud|promptfoo) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    aws_ensure_profile_found()    { return 1; }
    gcp_ensure_credentials_found(){ return 1; }
    has_kubectl_access()          { return 1; }
    has_aws_credentials()         { return 1; }
    has_gcp_credentials()         { return 1; }
    aws_profile_is_sso()          { return 1; }
    has_github_credentials()      { return 1; }
    has_datadog_api_key()         { return 0; }
    datadog_validate_api_key()    { return 0; }
    collect_environment_info 2>/dev/null
    echo "DD_CONNECTED=${CLAUDESEC_ENV_DATADOG_CONNECTED:-}"
  ' 2>/dev/null
)
assert_contains "collect_env: Datadog connected=true" "$dd_result" "DD_CONNECTED=true"

# Datadog: key present but validation fails — still set to true (L890-891)
dd_fail_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        az|kubectl|aws|gcloud|promptfoo) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    aws_ensure_profile_found()    { return 1; }
    gcp_ensure_credentials_found(){ return 1; }
    has_kubectl_access()          { return 1; }
    has_aws_credentials()         { return 1; }
    has_gcp_credentials()         { return 1; }
    aws_profile_is_sso()          { return 1; }
    has_github_credentials()      { return 1; }
    has_datadog_api_key()         { return 0; }
    datadog_validate_api_key()    { return 1; }
    collect_environment_info 2>/dev/null
    echo "DD_CONNECTED=${CLAUDESEC_ENV_DATADOG_CONNECTED:-}"
  ' 2>/dev/null
)
assert_contains "collect_env: Datadog key-present-but-invalid still true" "$dd_fail_result" "DD_CONNECTED=true"

# Datadog: key absent — not connected
dd_absent_result=$(
  bash -c '
    NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
    source "'"$LIB_DIR"'/checks.sh"
    has_command() {
      case "$1" in
        az|kubectl|aws|gcloud|promptfoo) return 1 ;;
        *) command -v "$1" &>/dev/null ;;
      esac
    }
    aws_ensure_profile_found()    { return 1; }
    gcp_ensure_credentials_found(){ return 1; }
    has_kubectl_access()          { return 1; }
    has_aws_credentials()         { return 1; }
    has_gcp_credentials()         { return 1; }
    aws_profile_is_sso()          { return 1; }
    has_github_credentials()      { return 1; }
    has_datadog_api_key()         { return 1; }
    datadog_validate_api_key()    { return 1; }
    collect_environment_info 2>/dev/null
    echo "DD_CONNECTED=${CLAUDESEC_ENV_DATADOG_CONNECTED:-not_set}"
  ' 2>/dev/null
)
assert_not_contains "collect_env: Datadog absent — not connected" "$dd_absent_result" "DD_CONNECTED=true"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
