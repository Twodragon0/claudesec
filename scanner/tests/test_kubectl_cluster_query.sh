#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for kubectl cluster query helpers in checks.sh.
# Covers:
#   - kubectl_cluster_info()    (returns "context|server" using kubectl config)
#   - kubectl_server_version()  (parses kubectl version -o json gitVersion)
#
# No real kubectl is ever invoked. A throwaway PATH-prepended stub kubectl
# replays canned responses based on which subcommand is called.
# Run: bash scanner/tests/test_kubectl_cluster_query.sh
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

# Color codes some helpers reference (silenced for test output)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Stub `kubectl` via PATH. Behaviour keyed off KCTL_STUB_MODE:
#   normal    → current-context=prod, server=https://kube.example/, v1.29.2
#   empty-ctx → current-context empty, server missing (parsing fallbacks)
#   fail      → all subcommands exit non-zero (triggers || true fallbacks)
#   badjson   → version emits non-parseable output (triggers "unknown" fallback)
# ──────────────────────────────────────────────────────────────────────────────
stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

cat > "$stub_dir/kubectl" <<'STUB'
#!/usr/bin/env bash
mode="${KCTL_STUB_MODE:-normal}"
args="$*"

case "$args" in
  *"config current-context"*)
    case "$mode" in
      normal)   echo "prod-cluster" ;;
      empty-ctx) echo "" ;;
      fail)     exit 1 ;;
      badjson)  echo "prod-cluster" ;;
      *) echo "" ;;
    esac
    ;;
  *"config view --minify"*)
    case "$mode" in
      normal)   echo "https://kube.example.com:6443" ;;
      empty-ctx) echo "" ;;
      fail)     exit 1 ;;
      badjson)  echo "https://kube.example.com:6443" ;;
      *) echo "" ;;
    esac
    ;;
  *"version"*)
    case "$mode" in
      normal|empty-ctx)
        # Compact form matches checks.sh grep pattern '"gitVersion":"[^"]*"'
        echo '{"serverVersion":{"gitVersion":"v1.29.2","gitCommit":"abc1234"}}'
        ;;
      fail)    exit 1 ;;
      badjson) echo "not json" ;;
      *) echo "" ;;
    esac
    ;;
  *"cluster-info"*)
    case "$mode" in
      normal) echo "Kubernetes control plane is running"; exit 0 ;;
      fail)   exit 1 ;;
      *)      exit 0 ;;
    esac
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/kubectl"

# `timeout` passthrough so run_with_timeout picks our stubbed kubectl.
cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
shift
"$@"
STUB
chmod +x "$stub_dir/timeout"

export PATH="$stub_dir:$PATH"

# Clear kube-related overrides between tests
unset KUBECONFIG CLAUDESEC_KUBECONTEXT || true

# ──────────────────────────────────────────────────────────────────────────────
# kubectl_cluster_info()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_cluster_info() ==="

# 1. Normal: "ctx|server"
export KCTL_STUB_MODE="normal"
info=$(kubectl_cluster_info)
assert_eq       "kubectl_cluster_info: context"    "prod-cluster"                 "$(echo "$info" | cut -d'|' -f1)"
assert_eq       "kubectl_cluster_info: server"     "https://kube.example.com:6443" "$(echo "$info" | cut -d'|' -f2)"
assert_contains "kubectl_cluster_info: pipe"        "$info" "|"

# 2. Empty context / server → "unknown|unknown" fallback
export KCTL_STUB_MODE="empty-ctx"
info_empty=$(kubectl_cluster_info)
assert_eq "kubectl_cluster_info: empty ctx fallback"    "unknown" "$(echo "$info_empty" | cut -d'|' -f1)"
assert_eq "kubectl_cluster_info: empty server fallback" "unknown" "$(echo "$info_empty" | cut -d'|' -f2)"

# 3. Command failure → still "unknown|unknown"
export KCTL_STUB_MODE="fail"
info_fail=$(kubectl_cluster_info)
assert_eq "kubectl_cluster_info: fail ctx"    "unknown" "$(echo "$info_fail" | cut -d'|' -f1)"
assert_eq "kubectl_cluster_info: fail server" "unknown" "$(echo "$info_fail" | cut -d'|' -f2)"

# 4. With KUBECONFIG override, _kubectl_cmd builds args that our stub ignores;
#    the function should still produce "ctx|server" from the stub.
export KUBECONFIG="$tmpdir/fake_kubeconfig"
: > "$KUBECONFIG"
export KCTL_STUB_MODE="normal"
info_kcfg=$(kubectl_cluster_info)
assert_contains "kubectl_cluster_info: KUBECONFIG still returns pipe" "$info_kcfg" "|"
assert_eq       "kubectl_cluster_info: KUBECONFIG ctx"                "prod-cluster" "$(echo "$info_kcfg" | cut -d'|' -f1)"
unset KUBECONFIG

# 5. With CLAUDESEC_KUBECONTEXT override — kubectl_current_context honours
#    this env var directly and short-circuits the stubbed kubectl call.
export CLAUDESEC_KUBECONTEXT="custom-ctx"
info_ctx=$(kubectl_cluster_info)
assert_eq "kubectl_cluster_info: CLAUDESEC_KUBECONTEXT ctx" "custom-ctx" "$(echo "$info_ctx" | cut -d'|' -f1)"
unset CLAUDESEC_KUBECONTEXT

# ──────────────────────────────────────────────────────────────────────────────
# kubectl_server_version()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_server_version() ==="

# 1. Normal path parses gitVersion
export KCTL_STUB_MODE="normal"
ver=$(kubectl_server_version)
assert_eq "kubectl_server_version: v1.29.2" "v1.29.2" "$ver"
assert_not_contains "kubectl_server_version: no quotes" "$ver" '"'

# 2. Command failure → "unknown"
export KCTL_STUB_MODE="fail"
ver_fail=$(kubectl_server_version)
assert_eq "kubectl_server_version: fail returns unknown" "unknown" "$ver_fail"

# 3. Malformed JSON → grep finds no gitVersion match; with pipefail active
#    in the caller, the pipeline exits nonzero and the "|| echo unknown"
#    fallback produces "unknown". Without pipefail, it prints empty. Either
#    is an acceptable "no version" signal.
export KCTL_STUB_MODE="badjson"
ver_bad=$(kubectl_server_version)
if [[ -z "$ver_bad" || "$ver_bad" == "unknown" ]]; then
  echo "  PASS: kubectl_server_version: bad json no-version"
  ((TEST_PASSED++))
else
  echo "  FAIL: kubectl_server_version: bad json no-version (got '$ver_bad')"
  ((TEST_FAILED++))
fi

# 4. Works with KUBECONFIG override (same stub response)
export KUBECONFIG="$tmpdir/fake_kubeconfig"
export KCTL_STUB_MODE="normal"
ver_kcfg=$(kubectl_server_version)
assert_eq "kubectl_server_version: with KUBECONFIG" "v1.29.2" "$ver_kcfg"
unset KUBECONFIG

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
