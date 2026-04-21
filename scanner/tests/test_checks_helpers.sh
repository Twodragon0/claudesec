#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2016
# Unit tests for scanner/lib/checks.sh helper functions.
# Focuses on pure-shell helpers: file/dir/grep helpers, compliance map,
# AWS/GCP/GitHub/Okta/Datadog/kubectl helpers where they can be exercised
# without external CLIs.
# Run: bash scanner/tests/test_checks_helpers.sh
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
    echo "  FAIL: $label (rc=$rc)"
    ((TEST_FAILED++))
  fi
}

# Color codes some helpers reference
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ============================================================================
# has_command()
# ============================================================================
echo ""
echo "=== has_command() ==="

has_command bash; assert_true "has_command: bash present" "$?"
has_command __definitely_not_a_cmd_xyz__; assert_false "has_command: bogus missing" "$?"

# ============================================================================
# run_with_timeout()
# ============================================================================
echo ""
echo "=== run_with_timeout() ==="

run_with_timeout 5 true; assert_true "run_with_timeout: true succeeds" "$?"
run_with_timeout 5 false; assert_false "run_with_timeout: false returns nonzero" "$?"

# ============================================================================
# has_file() / has_dir() / file_contains() / files_contain() / count_files()
# ============================================================================
echo ""
echo "=== has_file / has_dir / file_contains / files_contain / count_files ==="

mkdir -p "$tmpdir/fs/sub"
echo "hello world" > "$tmpdir/fs/a.txt"
echo "secret=abc" > "$tmpdir/fs/b.env"
echo "goodbye"    > "$tmpdir/fs/sub/c.txt"

SCAN_DIR="$tmpdir/fs"

has_file "a.txt"; assert_true "has_file: existing file" "$?"
has_file "missing.txt"; assert_false "has_file: missing file" "$?"
has_dir "sub"; assert_true "has_dir: existing dir" "$?"
has_dir "nope"; assert_false "has_dir: missing dir" "$?"

file_contains "a.txt" "hello"; assert_true  "file_contains: match"    "$?"
file_contains "a.txt" "nomatch"; assert_false "file_contains: no match" "$?"
file_contains "missing.txt" "x"; assert_false "file_contains: missing file" "$?"

files_contain "*.txt" "hello"; assert_true "files_contain: glob match" "$?"
files_contain "*.txt" "never_present_pattern_xyz"; assert_false "files_contain: no match" "$?"
files_contain "sub/*.txt" "goodbye"; assert_true "files_contain: glob with slash" "$?"

count_txt=$(count_files "*.txt")
# Two .txt files: a.txt and sub/c.txt
assert_eq "count_files: finds 2 .txt" "2" "$count_txt"
count_env=$(count_files "*.env")
assert_eq "count_files: finds 1 .env" "1" "$count_env"

# Exclusions: files under excluded dirs should NOT be counted
mkdir -p "$tmpdir/fs/node_modules" "$tmpdir/fs/.git" "$tmpdir/fs/.venv" "$tmpdir/fs/dist"
echo "x" > "$tmpdir/fs/node_modules/junk.txt"
echo "x" > "$tmpdir/fs/.git/junk.txt"
echo "x" > "$tmpdir/fs/.venv/junk.txt"
echo "x" > "$tmpdir/fs/dist/junk.txt"
count_txt_after=$(count_files "*.txt")
assert_eq "count_files: excludes vendored dirs" "2" "$count_txt_after"

# files_contain should also skip excluded dirs
echo "NEVER_COUNTED_PATTERN" > "$tmpdir/fs/node_modules/junk.txt"
files_contain "*.txt" "NEVER_COUNTED_PATTERN"
assert_false "files_contain: excludes vendored dir hits" "$?"

# ============================================================================
# is_git_repo() / git_remote_url()
# ============================================================================
echo ""
echo "=== is_git_repo / git_remote_url ==="

if command -v git >/dev/null 2>&1; then
  mkdir -p "$tmpdir/gitrepo"
  (cd "$tmpdir/gitrepo" && git init -q && git remote add origin https://example.com/fake/repo.git)
  SCAN_DIR="$tmpdir/gitrepo"
  is_git_repo; assert_true "is_git_repo: inside git repo" "$?"
  url=$(git_remote_url)
  assert_eq "git_remote_url: returns remote" "https://example.com/fake/repo.git" "$url"

  SCAN_DIR="$tmpdir/fs"
  is_git_repo; assert_false "is_git_repo: outside git repo" "$?"
else
  echo "  SKIP: git not available"
fi

# ============================================================================
# aws_list_profiles / aws_list_sso_profiles / aws_default_or_first_profile
# ============================================================================
echo ""
echo "=== aws_list_profiles / aws_list_sso_profiles / aws_default_or_first_profile ==="

mkdir -p "$tmpdir/aws"
cat > "$tmpdir/aws/credentials" <<'CREDS'
[default]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = secret

[profile staging]
aws_access_key_id = AKIASTG
aws_secret_access_key = secret

[prod]
aws_access_key_id = AKIAPROD
aws_secret_access_key = secret
CREDS
export AWS_SHARED_CREDENTIALS_FILE="$tmpdir/aws/credentials"

profiles=$(aws_list_profiles)
assert_contains "aws_list_profiles: default first" "$(echo "$profiles" | head -1)" "default"
assert_contains "aws_list_profiles: staging present" "$profiles" "staging"
assert_contains "aws_list_profiles: prod present" "$profiles" "prod"

first=$(aws_default_or_first_profile)
assert_eq "aws_default_or_first_profile: default" "default" "$first"

# Missing credentials file
export AWS_SHARED_CREDENTIALS_FILE="$tmpdir/nonexistent/credentials"
p_empty=$(aws_list_profiles)
assert_eq "aws_list_profiles: missing file empty" "" "$p_empty"

# SSO profiles in config
cat > "$tmpdir/aws/config" <<'CFG'
[default]
region = us-east-1

[profile sso-eng]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 000000000001
sso_role_name = Engineer

[profile sso-prod]
sso_session = team
sso_account_id = 000000000002
sso_role_name = Admin

[profile keyed-only]
region = eu-west-1
output = json
CFG
export AWS_CONFIG_FILE="$tmpdir/aws/config"

sso_list=$(aws_list_sso_profiles)
assert_contains "aws_list_sso_profiles: sso-eng present" "$sso_list" "sso-eng"
assert_contains "aws_list_sso_profiles: sso-prod present" "$sso_list" "sso-prod"
assert_not_contains "aws_list_sso_profiles: keyed-only absent" "$sso_list" "keyed-only"

# aws_profile_is_sso: positive / negative
aws_profile_is_sso "sso-eng"; assert_true "aws_profile_is_sso: sso-eng yes" "$?"
aws_profile_is_sso "keyed-only"; assert_false "aws_profile_is_sso: keyed-only no" "$?"
aws_profile_is_sso ""; assert_false "aws_profile_is_sso: empty arg" "$?"

# aws_ensure_profile_found
unset AWS_PROFILE AWS_DEFAULT_PROFILE
export AWS_SHARED_CREDENTIALS_FILE="$tmpdir/aws/credentials"
aws_ensure_profile_found
assert_eq "aws_ensure_profile_found: sets AWS_PROFILE to default" "default" "${AWS_PROFILE:-}"

# Missing config file → no SSO profiles
export AWS_CONFIG_FILE="$tmpdir/nonexistent/config"
sso_empty=$(aws_list_sso_profiles)
assert_eq "aws_list_sso_profiles: missing file empty" "" "$sso_empty"

# ============================================================================
# api_key_found()
# ============================================================================
echo ""
echo "=== api_key_found() ==="

unset MY_API_KEY
api_key_found "MY_API_KEY"; assert_false "api_key_found: unset is false" "$?"

export MY_API_KEY=""
api_key_found "MY_API_KEY"; assert_false "api_key_found: empty is false" "$?"

export MY_API_KEY="abc"
api_key_found "MY_API_KEY"; assert_true "api_key_found: set returns true" "$?"
unset MY_API_KEY

# ============================================================================
# has_gcp_credentials / gcp_ensure_credentials_found
# ============================================================================
echo ""
echo "=== has_gcp_credentials / gcp_ensure_credentials_found ==="

unset GOOGLE_APPLICATION_CREDENTIALS
# Without gcloud in env, with no ADC path → false
# We can't reliably mock gcloud CLI output. The ADC path branch is testable:
export GOOGLE_APPLICATION_CREDENTIALS="$tmpdir/adc.json"
echo '{}' > "$tmpdir/adc.json"
has_gcp_credentials; assert_true "has_gcp_credentials: ADC file present" "$?"
gcp_ensure_credentials_found; assert_true "gcp_ensure_credentials_found: ADC file present" "$?"

export GOOGLE_APPLICATION_CREDENTIALS="$tmpdir/missing_adc.json"
# ADC file missing; rely on gcloud branch. If gcloud missing, should return 1.
if ! command -v gcloud >/dev/null 2>&1; then
  has_gcp_credentials; assert_false "has_gcp_credentials: no gcloud, no ADC" "$?"
  gcp_ensure_credentials_found; assert_false "gcp_ensure_credentials_found: no gcloud, no ADC" "$?"
fi
unset GOOGLE_APPLICATION_CREDENTIALS

# ============================================================================
# has_datadog_api_key / datadog_validate_api_key (key missing branch)
# ============================================================================
echo ""
echo "=== has_datadog_api_key / datadog_validate_api_key ==="

unset DD_API_KEY DATADOG_API_KEY
has_datadog_api_key; assert_false "has_datadog_api_key: unset is false" "$?"
datadog_validate_api_key; assert_false "datadog_validate_api_key: no key returns 1" "$?"

export DD_API_KEY="dd-test-key"
has_datadog_api_key; assert_true "has_datadog_api_key: DD_API_KEY set" "$?"
unset DD_API_KEY

export DATADOG_API_KEY="dd-test-key"
has_datadog_api_key; assert_true "has_datadog_api_key: DATADOG_API_KEY set" "$?"
unset DATADOG_API_KEY

# ============================================================================
# has_github_credentials / has_okta_credentials
# ============================================================================
echo ""
echo "=== has_github_credentials / has_okta_credentials ==="

unset GH_TOKEN GITHUB_TOKEN
# Without gh CLI, should be false
if ! command -v gh >/dev/null 2>&1; then
  has_github_credentials; assert_false "has_github_credentials: no creds, no gh" "$?"
fi
export GITHUB_TOKEN="ghp_test"
has_github_credentials; assert_true "has_github_credentials: GITHUB_TOKEN set" "$?"
unset GITHUB_TOKEN
export GH_TOKEN="ghp_test"
has_github_credentials; assert_true "has_github_credentials: GH_TOKEN set" "$?"
unset GH_TOKEN

unset OKTA_API_TOKEN OKTA_OAUTH_TOKEN
has_okta_credentials; assert_false "has_okta_credentials: unset false" "$?"
export OKTA_API_TOKEN="okta-tok"
has_okta_credentials; assert_true "has_okta_credentials: OKTA_API_TOKEN set" "$?"
unset OKTA_API_TOKEN
export OKTA_OAUTH_TOKEN="okta-oauth"
has_okta_credentials; assert_true "has_okta_credentials: OKTA_OAUTH_TOKEN set" "$?"
unset OKTA_OAUTH_TOKEN

# ============================================================================
# _kubectl_cmd()
# ============================================================================
echo ""
echo "=== _kubectl_cmd() ==="

unset KUBECONFIG CLAUDESEC_KUBECONTEXT
cmd=$(_kubectl_cmd)
assert_eq "_kubectl_cmd: plain" "kubectl" "$cmd"

export KUBECONFIG="/tmp/fake/kubeconfig"
cmd=$(_kubectl_cmd)
assert_contains "_kubectl_cmd: includes --kubeconfig" "$cmd" "--kubeconfig"
assert_contains "_kubectl_cmd: includes path"        "$cmd" "/tmp/fake/kubeconfig"
unset KUBECONFIG

export CLAUDESEC_KUBECONTEXT="my-ctx"
cmd=$(_kubectl_cmd)
assert_contains "_kubectl_cmd: includes --context" "$cmd" "--context"
assert_contains "_kubectl_cmd: includes ctx name"  "$cmd" "my-ctx"
unset CLAUDESEC_KUBECONTEXT

# ============================================================================
# kubectl_detect_cluster_type()
# ============================================================================
echo ""
echo "=== kubectl_detect_cluster_type() ==="

assert_eq "cluster_type: eks"             "eks"             "$(kubectl_detect_cluster_type "arn:aws:eks:us-east-1:123:cluster/my-cluster")"
assert_eq "cluster_type: eks short"       "eks"             "$(kubectl_detect_cluster_type "my-eks-cluster")"
assert_eq "cluster_type: gke"             "gke"             "$(kubectl_detect_cluster_type "gke_my-project_us-central1-a_my-cluster")"
assert_eq "cluster_type: aks"             "aks"             "$(kubectl_detect_cluster_type "aks-dev")"
assert_eq "cluster_type: azure"           "aks"             "$(kubectl_detect_cluster_type "azure-prod")"
assert_eq "cluster_type: docker-desktop"  "docker-desktop"  "$(kubectl_detect_cluster_type "docker-desktop")"
assert_eq "cluster_type: minikube"        "minikube"        "$(kubectl_detect_cluster_type "minikube")"
assert_eq "cluster_type: kind"            "kind"            "$(kubectl_detect_cluster_type "kind-local")"
assert_eq "cluster_type: rancher-desktop" "rancher-desktop" "$(kubectl_detect_cluster_type "rancher-desktop")"
assert_eq "cluster_type: generic"         "generic"         "$(kubectl_detect_cluster_type "some-random-ctx")"

# ============================================================================
# kubectl_auto_find_kubeconfig()
# ============================================================================
echo ""
echo "=== kubectl_auto_find_kubeconfig() ==="

# No kubeconfig anywhere → returns 1
kubectl_auto_find_kubeconfig "$tmpdir/empty_base" >/dev/null 2>&1
assert_false "kubectl_auto_find_kubeconfig: empty returns 1" "$?"

# Direct kubeconfig at base_dir
mkdir -p "$tmpdir/kbase1"
: > "$tmpdir/kbase1/kubeconfig"
found=$(kubectl_auto_find_kubeconfig "$tmpdir/kbase1")
assert_eq "kubectl_auto_find_kubeconfig: direct kubeconfig" "$tmpdir/kbase1/kubeconfig" "$found"

# configs/dev/kubeconfig
mkdir -p "$tmpdir/kbase2/configs/dev"
: > "$tmpdir/kbase2/configs/dev/kubeconfig"
found=$(kubectl_auto_find_kubeconfig "$tmpdir/kbase2")
assert_eq "kubectl_auto_find_kubeconfig: configs/dev" "$tmpdir/kbase2/configs/dev/kubeconfig" "$found"

# config/kubeconfig
mkdir -p "$tmpdir/kbase3/config"
: > "$tmpdir/kbase3/config/kubeconfig"
found=$(kubectl_auto_find_kubeconfig "$tmpdir/kbase3")
assert_eq "kubectl_auto_find_kubeconfig: config/kubeconfig" "$tmpdir/kbase3/config/kubeconfig" "$found"

# Arbitrary configs/*/kubeconfig falls through to find
mkdir -p "$tmpdir/kbase4/configs/custom"
: > "$tmpdir/kbase4/configs/custom/kubeconfig"
found=$(kubectl_auto_find_kubeconfig "$tmpdir/kbase4")
assert_contains "kubectl_auto_find_kubeconfig: custom found" "$found" "kubeconfig"

# ============================================================================
# compliance_map()
# ============================================================================
echo ""
echo "=== compliance_map() ==="

assert_contains "compliance_map: IAM-*"      "$(compliance_map "IAM-001")"     "NIST:AC-2"
assert_contains "compliance_map: NET-*"      "$(compliance_map "NET-042")"     "NIST:SC-7"
assert_contains "compliance_map: CLOUD-*"    "$(compliance_map "CLOUD-013")"   "NIST:CM-6"
assert_contains "compliance_map: CICD-*"     "$(compliance_map "CICD-007")"    "NIST:SA-11"
assert_contains "compliance_map: AI-*"       "$(compliance_map "AI-002")"      "NIST-AI:MAP"
assert_contains "compliance_map: INFRA-*"    "$(compliance_map "INFRA-001")"   "NIST:CM-6"
assert_contains "compliance_map: MAC-*"      "$(compliance_map "MAC-001")"     "CIS:macOS-Benchmark"
assert_contains "compliance_map: CIS-*"      "$(compliance_map "CIS-002")"     "CIS:macOS-Benchmark"
assert_contains "compliance_map: SECRETS-*"  "$(compliance_map "SECRETS-001")" "NIST:IA-5"
assert_contains "compliance_map: SAAS-API-*" "$(compliance_map "SAAS-API-01")" "NIST:AC-2"
assert_contains "compliance_map: SAAS-*"     "$(compliance_map "SAAS-ZIA-01")" "NIST:AC-2"
assert_contains "compliance_map: WIN-*"      "$(compliance_map "WIN-011")"     "KISA-W:W-01"
assert_contains "compliance_map: PROWLER-*"  "$(compliance_map "PROWLER-1")"   "CIS:Benchmark"
assert_eq       "compliance_map: unknown empty" "" "$(compliance_map "UNKNOWN-1")"

# ============================================================================
# kubectl_discover_kubeconfigs() — no HOME/.kube (uses real $HOME but tolerates)
# ============================================================================
echo ""
echo "=== kubectl_discover_kubeconfigs() ==="

# Point HOME at a throwaway location so we only see files we control
orig_home="$HOME"
export HOME="$tmpdir/fakehome"
mkdir -p "$HOME/.kube"
: > "$HOME/.kube/config"

unset KUBECONFIG
SCAN_DIR="$tmpdir/empty_base"
out=$(kubectl_discover_kubeconfigs)
assert_contains "kubectl_discover_kubeconfigs: finds ~/.kube/config" "$out" ".kube/config"

# With KUBECONFIG pointing to existing file
extra="$tmpdir/fakehome/extra_kubeconfig"
: > "$extra"
export KUBECONFIG="$extra"
out=$(kubectl_discover_kubeconfigs)
assert_contains "kubectl_discover_kubeconfigs: picks up KUBECONFIG file" "$out" "extra_kubeconfig"

unset KUBECONFIG
export HOME="$orig_home"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
