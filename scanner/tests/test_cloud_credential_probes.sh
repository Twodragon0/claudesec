#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for cloud credential probe helpers in checks.sh.
# Covers:
#   - has_aws_credentials()         (aws sts get-caller-identity success/fail)
#   - has_azure_credentials()       (az account show success/fail + missing CLI)
#   - has_kubectl_access()          (kubectl cluster-info success/fail + missing CLI)
#   - datadog_validate_api_key()    (200/401 HTTP branches + site override + no curl)
#
# All external CLIs (aws/az/kubectl/curl/timeout) are stubbed via a
# throwaway PATH-prepended directory so nothing touches the network.
# Run: bash scanner/tests/test_cloud_credential_probes.sh
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

# Color codes some helpers reference (silenced for test output)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

# ──────────────────────────────────────────────────────────────────────────────
# Stubs
#   aws     → sts get-caller-identity keyed on AWS_STUB_MODE (ok|fail)
#   az      → account show keyed on AZ_STUB_MODE (ok|fail)
#   kubectl → cluster-info keyed on KCTL_STUB_MODE (ok|fail)
#   curl    → echoes HTTP status keyed on CURL_STUB_CODE (e.g. 200/401)
#   timeout → passthrough (drops the secs arg)
# ──────────────────────────────────────────────────────────────────────────────

cat > "$stub_dir/aws" <<'STUB'
#!/usr/bin/env bash
mode="${AWS_STUB_MODE:-fail}"
args="$*"
case "$args" in
  *"sts get-caller-identity"*)
    [[ "$mode" == "ok" ]] && exit 0 || exit 1
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/aws"

cat > "$stub_dir/az" <<'STUB'
#!/usr/bin/env bash
mode="${AZ_STUB_MODE:-fail}"
args="$*"
case "$args" in
  *"account show"*)
    [[ "$mode" == "ok" ]] && exit 0 || exit 1
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/az"

cat > "$stub_dir/kubectl" <<'STUB'
#!/usr/bin/env bash
mode="${KCTL_STUB_MODE:-fail}"
args="$*"
case "$args" in
  *"cluster-info"*)
    [[ "$mode" == "ok" ]] && exit 0 || exit 1
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/kubectl"

cat > "$stub_dir/curl" <<'STUB'
#!/usr/bin/env bash
# Minimal curl stub: the caller pipes our output to `grep -q 200`, so we just
# print $CURL_STUB_CODE (default 200) and exit with matching rc.
code="${CURL_STUB_CODE:-200}"
# The -f flag makes real curl exit nonzero on HTTP 4xx/5xx; emulate that.
if [[ "$code" == "200" ]]; then
  printf '%s' "$code"
  exit 0
fi
# Non-2xx: print the code but exit nonzero like curl -f would
printf '%s' "$code"
exit 22
STUB
chmod +x "$stub_dir/curl"

cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
# Drop the timeout-seconds arg and run the rest
shift
"$@"
STUB
chmod +x "$stub_dir/timeout"

export PATH="$stub_dir:$PATH"
orig_path="$PATH"   # captured AFTER stub prepend so restoration keeps stubs
empty_dir="$tmpdir/empty_path"
mkdir -p "$empty_dir"

# ──────────────────────────────────────────────────────────────────────────────
# has_aws_credentials()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== has_aws_credentials() ==="

# 1. Happy path: stubbed aws sts succeeds
export AWS_STUB_MODE="ok"
has_aws_credentials
assert_true "has_aws_credentials: sts-ok returns 0" "$?"

# 2. Failure path: sts exits nonzero
export AWS_STUB_MODE="fail"
has_aws_credentials
assert_false "has_aws_credentials: sts-fail returns nonzero" "$?"

# 3. Missing aws CLI on PATH → has_command short-circuits to false
PATH="$empty_dir"
has_aws_credentials
assert_false "has_aws_credentials: no aws CLI returns nonzero" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# has_azure_credentials()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== has_azure_credentials() ==="

# 1. Happy path: az account show succeeds
export AZ_STUB_MODE="ok"
has_azure_credentials
assert_true "has_azure_credentials: az-ok returns 0" "$?"

# 2. Failure path: az returns nonzero
export AZ_STUB_MODE="fail"
has_azure_credentials
assert_false "has_azure_credentials: az-fail returns nonzero" "$?"

# 3. Missing az CLI → has_command short-circuits
PATH="$empty_dir"
has_azure_credentials
assert_false "has_azure_credentials: no az CLI returns nonzero" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# has_kubectl_access()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== has_kubectl_access() ==="

# Need _kubectl_cmd to return just "kubectl" (no overrides set)
unset KUBECONFIG CLAUDESEC_KUBECONTEXT || true

# 1. Happy path: kubectl cluster-info succeeds
export KCTL_STUB_MODE="ok"
has_kubectl_access
assert_true "has_kubectl_access: cluster-info-ok returns 0" "$?"

# 2. Failure path: cluster-info returns nonzero
export KCTL_STUB_MODE="fail"
has_kubectl_access
assert_false "has_kubectl_access: cluster-info-fail returns nonzero" "$?"

# 3. Missing kubectl CLI
PATH="$empty_dir"
has_kubectl_access
assert_false "has_kubectl_access: no kubectl returns nonzero" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# datadog_validate_api_key() — happy path with curl stub
# (test_checks_helpers.sh already covers the "no key" branch; we exercise
#  the API-call branches plus DD_SITE base_url selection.)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== datadog_validate_api_key() ==="

# 1. HTTP 200 with default site → returns 0
unset DATADOG_API_KEY DD_SITE
export DD_API_KEY="fake-dd-key-for-test"
export CURL_STUB_CODE="200"
datadog_validate_api_key
assert_true "datadog_validate_api_key: 200 with DD_API_KEY returns 0" "$?"

# 2. HTTP 401 → returns nonzero (grep -q 200 fails)
export CURL_STUB_CODE="401"
datadog_validate_api_key
assert_false "datadog_validate_api_key: 401 returns nonzero" "$?"

# 3. DATADOG_API_KEY (alt env var) also works
unset DD_API_KEY
export DATADOG_API_KEY="alt-dd-key"
export CURL_STUB_CODE="200"
datadog_validate_api_key
assert_true "datadog_validate_api_key: DATADOG_API_KEY 200 returns 0" "$?"

# 4. DD_SITE overrides pick the right base_url branch (exercises case statement
#    lines) — we cannot easily assert the URL from outside, but we confirm the
#    function still returns success with a stubbed 200 for each site.
for site in datadoghq.eu us3.datadoghq.com us5.datadoghq.com ddog-gov.com; do
  export DD_SITE="$site"
  export CURL_STUB_CODE="200"
  datadog_validate_api_key
  assert_true "datadog_validate_api_key: site=$site returns 0" "$?"
done
unset DD_SITE

# 5. No curl on PATH → function returns 0 ("key found only" fallback)
PATH="$empty_dir"
datadog_validate_api_key
assert_true "datadog_validate_api_key: no curl → key-found fallback returns 0" "$?"
PATH="$orig_path"

# 6. Empty key → returns 1 regardless of curl stub
unset DATADOG_API_KEY DD_API_KEY
datadog_validate_api_key
assert_false "datadog_validate_api_key: no key returns nonzero" "$?"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
