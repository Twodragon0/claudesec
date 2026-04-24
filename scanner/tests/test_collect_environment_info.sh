#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for checks.sh::collect_environment_info().
# Focus: the many env-var branches (M365, GWS, Cloudflare, NHN, LLM, Datadog,
# GitHub, Okta, identifier toggle, Kubernetes/AWS/GCP/Azure "connected" flags).
# No external CLI is ever invoked: kubectl/aws/az/gcloud/promptfoo/curl are all
# stubbed via a throwaway PATH-prepended directory.
# Run: bash scanner/tests/test_collect_environment_info.sh
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

# Color codes referenced by sourced lib
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Stubs for every CLI collect_environment_info() can reach. All stubs exit 1
# so the "not connected" branches are exercised by default. Individual tests
# toggle behaviour by swapping in replacements.
# ──────────────────────────────────────────────────────────────────────────────
stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

make_stub_fail() {
  cat > "$stub_dir/$1" <<'STUB'
#!/usr/bin/env bash
exit 1
STUB
  chmod +x "$stub_dir/$1"
}

make_stub_ok() {
  cat > "$stub_dir/$1" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  chmod +x "$stub_dir/$1"
}

for tool in kubectl aws az gcloud curl gh; do
  make_stub_fail "$tool"
done
# promptfoo is intentionally NOT created so has_command promptfoo returns false
# by default; individual tests create/remove it to flip the LLM branch.

# `timeout` passthrough so run_with_timeout doesn't swallow stubs. We
# word-split the remaining args via `eval $*` so callers like
# `run_with_timeout 10 "$(_kubectl_cmd)" cluster-info` — which pass the
# kubectl invocation as one quoted arg — still exec `kubectl --kubeconfig …`
# correctly.
cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
shift
# shellcheck disable=SC2086
eval $*
STUB
chmod +x "$stub_dir/timeout"

export PATH="$stub_dir:$PATH"

# Helper: clear every CLAUDESEC_ENV_* export between scenarios
reset_env_vars() {
  while IFS= read -r var; do
    unset "$var"
  done < <(env | grep -oE '^CLAUDESEC_ENV_[A-Z0-9_]+' | sort -u)
  # Also reset inputs
  unset CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS
  unset AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_CLIENT_SECRET
  unset GOOGLE_WORKSPACE_CUSTOMER_ID GOOGLE_APPLICATION_CREDENTIALS
  unset CLOUDFLARE_API_TOKEN CF_API_TOKEN CLOUDFLARE_API_KEY CLOUDFLARE_API_EMAIL
  unset OS_AUTH_URL NHN_API_URL
  unset OPENAI_API_KEY ANTHROPIC_API_KEY
  unset DD_API_KEY DATADOG_API_KEY
  unset GH_TOKEN GITHUB_TOKEN
  unset OKTA_API_TOKEN OKTA_OAUTH_TOKEN
  unset AWS_PROFILE AWS_DEFAULT_PROFILE
}

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 1: everything disconnected (all stubs fail, no env creds)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 1: fully disconnected ==="

reset_env_vars
collect_environment_info >/dev/null 2>&1 || true

assert_eq "s1: SHOW_IDENTIFIERS default false" "false" "${CLAUDESEC_ENV_SHOW_IDENTIFIERS:-}"
assert_eq "s1: K8S_CONNECTED false"            "false" "${CLAUDESEC_ENV_K8S_CONNECTED:-}"
assert_eq "s1: AWS_CONNECTED false"            "false" "${CLAUDESEC_ENV_AWS_CONNECTED:-}"
assert_eq "s1: AWS_SSO_CONFIGURED false"       "false" "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-}"
assert_eq "s1: GCP_CONNECTED false"            "false" "${CLAUDESEC_ENV_GCP_CONNECTED:-}"
assert_eq "s1: AZ_CONNECTED false"             "false" "${CLAUDESEC_ENV_AZ_CONNECTED:-}"
assert_eq "s1: M365_CONNECTED false"           "false" "${CLAUDESEC_ENV_M365_CONNECTED:-}"
assert_eq "s1: GWS_CONNECTED false"            "false" "${CLAUDESEC_ENV_GWS_CONNECTED:-}"
assert_eq "s1: CF_CONNECTED false"             "false" "${CLAUDESEC_ENV_CF_CONNECTED:-}"
assert_eq "s1: NHN_CONNECTED false"            "false" "${CLAUDESEC_ENV_NHN_CONNECTED:-}"
assert_eq "s1: LLM_CONNECTED false"            "false" "${CLAUDESEC_ENV_LLM_CONNECTED:-}"
assert_eq "s1: DATADOG_CONNECTED false"        "false" "${CLAUDESEC_ENV_DATADOG_CONNECTED:-}"
assert_eq "s1: GITHUB_CONNECTED false"         "false" "${CLAUDESEC_ENV_GITHUB_CONNECTED:-}"
assert_eq "s1: OKTA_CONNECTED false"           "false" "${CLAUDESEC_ENV_OKTA_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 2: SHOW_IDENTIFIERS=1 opt-in
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 2: SHOW_IDENTIFIERS toggle ==="

reset_env_vars
export CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS=1
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s2: SHOW_IDENTIFIERS true" "true" "${CLAUDESEC_ENV_SHOW_IDENTIFIERS:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 3: M365 via service-principal env vars only (no az CLI needed)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 3: M365 via SP env vars ==="

reset_env_vars
export AZURE_CLIENT_ID="cid"
export AZURE_TENANT_ID="tid"
export AZURE_CLIENT_SECRET="sec"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s3: M365_CONNECTED true"  "true"  "${CLAUDESEC_ENV_M365_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 4: Google Workspace via customer id + ADC file
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 4: Google Workspace ==="

reset_env_vars
export GOOGLE_WORKSPACE_CUSTOMER_ID="C01abcd"
export GOOGLE_APPLICATION_CREDENTIALS="$tmpdir/adc.json"
echo '{}' > "$GOOGLE_APPLICATION_CREDENTIALS"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s4: GWS_CONNECTED true"          "true"      "${CLAUDESEC_ENV_GWS_CONNECTED:-}"
# GCP is also "connected" through ADC
assert_eq "s4: GCP_CONNECTED true (via ADC)" "true"     "${CLAUDESEC_ENV_GCP_CONNECTED:-}"
# GWS_CUSTOMER_ID only exported when SHOW_IDENTIFIERS=true
assert_eq "s4: GWS_CUSTOMER_ID hidden"      ""          "${CLAUDESEC_ENV_GWS_CUSTOMER_ID:-}"

reset_env_vars
export GOOGLE_WORKSPACE_CUSTOMER_ID="C01abcd"
export GOOGLE_APPLICATION_CREDENTIALS="$tmpdir/adc.json"
export CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS=1
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s4b: GWS_CUSTOMER_ID shown when opted in" "C01abcd" "${CLAUDESEC_ENV_GWS_CUSTOMER_ID:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 5: Cloudflare — token form
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 5: Cloudflare ==="

reset_env_vars
export CLOUDFLARE_API_TOKEN="cf-token-xyz"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s5a: CF_CONNECTED via CLOUDFLARE_API_TOKEN" "true" "${CLAUDESEC_ENV_CF_CONNECTED:-}"

# Legacy key + email form
reset_env_vars
export CLOUDFLARE_API_KEY="legacy-key"
export CLOUDFLARE_API_EMAIL="user@example.com"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s5b: CF_CONNECTED via key+email" "true" "${CLAUDESEC_ENV_CF_CONNECTED:-}"

# CF_API_TOKEN alias
reset_env_vars
export CF_API_TOKEN="alt-token"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s5c: CF_CONNECTED via CF_API_TOKEN" "true" "${CLAUDESEC_ENV_CF_CONNECTED:-}"

# Key without email → NOT connected
reset_env_vars
export CLOUDFLARE_API_KEY="legacy-key"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s5d: CF_CONNECTED false (key but no email)" "false" "${CLAUDESEC_ENV_CF_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 6: NHN Cloud via OS_AUTH_URL pattern / NHN_API_URL
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 6: NHN Cloud ==="

reset_env_vars
export OS_AUTH_URL="https://api-identity.infrastructure.nhncloud.com/v2.0/"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s6a: NHN via nhncloud URL" "true" "${CLAUDESEC_ENV_NHN_CONNECTED:-}"

reset_env_vars
export OS_AUTH_URL="https://identity.toastcloud.example/v3"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s6b: NHN via toast URL" "true" "${CLAUDESEC_ENV_NHN_CONNECTED:-}"

reset_env_vars
export NHN_API_URL="https://nhn-api.example"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s6c: NHN via NHN_API_URL" "true" "${CLAUDESEC_ENV_NHN_CONNECTED:-}"

reset_env_vars
export OS_AUTH_URL="https://unrelated.example/v3"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s6d: NHN false for unrelated URL" "false" "${CLAUDESEC_ENV_NHN_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 7: LLM (requires promptfoo on PATH + OpenAI/Anthropic key)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 7: LLM ==="

reset_env_vars
# Without promptfoo on PATH → not connected even with key
export OPENAI_API_KEY="sk-test"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s7a: LLM false (no promptfoo)" "false" "${CLAUDESEC_ENV_LLM_CONNECTED:-}"

# Promote promptfoo stub to success + provide key → connected
make_stub_ok promptfoo
reset_env_vars
export ANTHROPIC_API_KEY="sk-ant"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s7b: LLM true (promptfoo + ANTHROPIC_API_KEY)" "true" "${CLAUDESEC_ENV_LLM_CONNECTED:-}"

# Promptfoo present but no API key → not connected
reset_env_vars
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s7c: LLM false (promptfoo but no key)" "false" "${CLAUDESEC_ENV_LLM_CONNECTED:-}"

# Remove promptfoo stub so has_command returns false in later scenarios
rm -f "$stub_dir/promptfoo"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 8: Datadog — key present but curl stub fails validation
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 8: Datadog ==="

reset_env_vars
export DD_API_KEY="dd-test"
collect_environment_info >/dev/null 2>&1 || true
# Function sets DATADOG_CONNECTED=true whether validation passes or not
# (comment in source: "Key present but validation failed"). Both branches
# set "true".
assert_eq "s8a: DATADOG_CONNECTED true (DD_API_KEY)" "true" "${CLAUDESEC_ENV_DATADOG_CONNECTED:-}"

reset_env_vars
export DATADOG_API_KEY="dd-test"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s8b: DATADOG_CONNECTED true (DATADOG_API_KEY)" "true" "${CLAUDESEC_ENV_DATADOG_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 9: GitHub + Okta credentials via env
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 9: GitHub + Okta ==="

reset_env_vars
export GITHUB_TOKEN="ghp_test"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s9a: GITHUB_CONNECTED true" "true" "${CLAUDESEC_ENV_GITHUB_CONNECTED:-}"

reset_env_vars
export GH_TOKEN="ghp_test"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s9b: GITHUB_CONNECTED true (GH_TOKEN)" "true" "${CLAUDESEC_ENV_GITHUB_CONNECTED:-}"

reset_env_vars
export OKTA_API_TOKEN="okta-tok"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s9c: OKTA_CONNECTED true" "true" "${CLAUDESEC_ENV_OKTA_CONNECTED:-}"

reset_env_vars
export OKTA_OAUTH_TOKEN="okta-oauth"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s9d: OKTA_CONNECTED true (OAUTH)" "true" "${CLAUDESEC_ENV_OKTA_CONNECTED:-}"

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 10: AWS_SSO_CONFIGURED flag when profile is SSO
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 10: AWS SSO configured flag ==="

reset_env_vars
# Build a fake ~/.aws/config pointing at an SSO profile
aws_dir="$tmpdir/aws"
mkdir -p "$aws_dir"
cat > "$aws_dir/config" <<CFG
[profile ssoprof]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_role_name = Engineer
CFG
export AWS_CONFIG_FILE="$aws_dir/config"
export AWS_PROFILE="ssoprof"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s10a: AWS_SSO_CONFIGURED=true for SSO profile" "true" "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-}"
# Since aws CLI stub fails, AWS is NOT "connected" → SSO_SESSION reports "expired"
assert_eq "s10b: AWS_SSO_SESSION=expired"                  "expired" "${CLAUDESEC_ENV_AWS_SSO_SESSION:-}"

# Non-SSO profile → SSO_CONFIGURED=false, SSO_SESSION=unknown
reset_env_vars
cat > "$aws_dir/config" <<CFG
[profile keyonly]
region = us-east-1
CFG
export AWS_CONFIG_FILE="$aws_dir/config"
export AWS_PROFILE="keyonly"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s10c: AWS_SSO_CONFIGURED=false for non-SSO" "false"   "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-}"
assert_eq "s10d: AWS_SSO_SESSION=unknown"              "unknown" "${CLAUDESEC_ENV_AWS_SSO_SESSION:-}"

unset AWS_CONFIG_FILE AWS_PROFILE

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 11: has_kubectl_access() true — exercises checks.sh:775-788
# (K8S_CONNECTED true branch with CONTEXT/SERVER/TYPE/VERSION exports).
# Swaps kubectl stub to one that answers every subcommand used by
# kubectl_cluster_info() and kubectl_server_version().
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 11: K8S connected (full cluster info path) ==="

cat > "$stub_dir/kubectl" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"cluster-info"*)                    exit 0 ;;
  *"config current-context"*)          echo "prod-eks" ;;
  *"config view --minify"*"jsonpath"*) echo "https://api.example.eks.aws:443" ;;
  *"version -o json"*)
    printf '%s\n' '{"serverVersion":{"gitVersion":"v1.30.1"}}' ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/kubectl"

reset_env_vars
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s11a: K8S_CONNECTED true"     "true"                              "${CLAUDESEC_ENV_K8S_CONNECTED:-}"
assert_eq "s11b: K8S_CONTEXT set"        "prod-eks"                          "${CLAUDESEC_ENV_K8S_CONTEXT:-}"
assert_eq "s11c: K8S_SERVER set"         "https://api.example.eks.aws:443"   "${CLAUDESEC_ENV_K8S_SERVER:-}"
# "prod-eks" matches kubectl_detect_cluster_type()'s *eks* glob → "eks"
assert_eq "s11d: K8S_TYPE=eks"           "eks"                               "${CLAUDESEC_ENV_K8S_TYPE:-}"
assert_eq "s11e: K8S_VERSION parsed"     "v1.30.1"                           "${CLAUDESEC_ENV_K8S_VERSION:-}"

# KUBECONFIG export round-trip (only set when the env var itself is set).
kubeconfig_file="$tmpdir/kcfg"; : > "$kubeconfig_file"
reset_env_vars
export KUBECONFIG="$kubeconfig_file"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s11f: K8S_KUBECONFIG exported" "$kubeconfig_file" "${CLAUDESEC_ENV_K8S_KUBECONFIG:-}"
unset KUBECONFIG

# CLAUDESEC_KUBE_NAMESPACE round-trip
reset_env_vars
export CLAUDESEC_KUBE_NAMESPACE="sec-audit"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s11g: K8S_NAMESPACE exported" "sec-audit" "${CLAUDESEC_ENV_K8S_NAMESPACE:-}"
unset CLAUDESEC_KUBE_NAMESPACE

# Restore the always-fail kubectl stub so the closing aggregate (if any future
# scenarios land here) starts from the disconnected baseline again.
make_stub_fail kubectl

# ──────────────────────────────────────────────────────────────────────────────
# Scenario 12: has_aws_credentials() true — exercises checks.sh:800-811
# (AWS_CONNECTED true branch with ACCOUNT/ARN/SSO_SESSION exports).
# Swaps aws stub to one that succeeds on sts get-caller-identity and emits
# well-formed JSON that aws_identity_info() parses.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Scenario 12: AWS connected (identity info parsed) ==="

cat > "$stub_dir/aws" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"sts get-caller-identity"*)
    # Non-numeric account placeholder keeps hooks/pii-check.sh happy.
    printf '%s\n' '{"UserId":"AIDAEXAMPLE","Account":"acctid","Arn":"arn:aws:iam::acctid:user/tester"}'
    exit 0
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/aws"

reset_env_vars
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s12a: AWS_CONNECTED true"         "true"                                 "${CLAUDESEC_ENV_AWS_CONNECTED:-}"
assert_eq "s12b: AWS_ACCOUNT parsed"         "acctid"                               "${CLAUDESEC_ENV_AWS_ACCOUNT:-}"
assert_eq "s12c: AWS_ARN parsed"             "arn:aws:iam::acctid:user/tester"      "${CLAUDESEC_ENV_AWS_ARN:-}"
# No SSO config → SSO_SESSION defaults to "unknown" (set by the SSO_CONFIGURED
# false path earlier in collect_environment_info).
assert_eq "s12d: AWS_SSO_SESSION unknown"    "unknown"                              "${CLAUDESEC_ENV_AWS_SSO_SESSION:-}"

# AWS_PROFILE round-trip: only exported to CLAUDESEC_ENV_AWS_PROFILE when set.
reset_env_vars
export AWS_PROFILE="dev"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s12e: AWS_PROFILE round-tripped" "dev" "${CLAUDESEC_ENV_AWS_PROFILE:-}"
unset AWS_PROFILE

# Combined path: SSO-configured profile + live credentials → SSO_SESSION=valid.
reset_env_vars
aws_dir="$tmpdir/aws"
mkdir -p "$aws_dir"
cat > "$aws_dir/config" <<CFG
[profile ssolive]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
CFG
export AWS_CONFIG_FILE="$aws_dir/config"
export AWS_PROFILE="ssolive"
collect_environment_info >/dev/null 2>&1 || true
assert_eq "s12f: AWS_SSO_CONFIGURED=true" "true"    "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-}"
assert_eq "s12g: AWS_SSO_SESSION=valid"   "valid"   "${CLAUDESEC_ENV_AWS_SSO_SESSION:-}"
unset AWS_CONFIG_FILE AWS_PROFILE

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
