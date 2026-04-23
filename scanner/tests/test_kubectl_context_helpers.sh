#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for kubectl context-query helpers in checks.sh.
# Covers:
#   - kubectl_list_contexts()                  (kubectl config get-contexts -o name)
#   - kubectl_current_context()                (with and without CLAUDESEC_KUBECONTEXT)
#   - kubectl_current_context_uses_oidc_exec() (grep on `kubectl config view --minify -o json`)
#
# No real kubectl is ever invoked. A throwaway PATH-prepended stub kubectl
# returns canned responses keyed on $KCTL_STUB_MODE and the subcommand.
# Run: bash scanner/tests/test_kubectl_context_helpers.sh
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

# Color codes some helpers reference (silenced for test output)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

# ──────────────────────────────────────────────────────────────────────────────
# Stub `kubectl`. Behaviour keyed off $KCTL_STUB_MODE:
#   many      → get-contexts returns 3 context names; current-context=prod
#   single    → get-contexts returns 1; current-context=only
#   empty     → get-contexts returns nothing; current-context empty
#   fail      → all subcommands exit non-zero
#   oidc      → `config view --minify -o json` emits kubeconfig with oidc-login
#   plainauth → `config view --minify -o json` emits kubeconfig without oidc
#   badjson   → `config view --minify` returns malformed output
# ──────────────────────────────────────────────────────────────────────────────
cat > "$stub_dir/kubectl" <<'STUB'
#!/usr/bin/env bash
mode="${KCTL_STUB_MODE:-many}"
args="$*"

case "$args" in
  *"config get-contexts -o name"*)
    case "$mode" in
      many)    printf 'prod\nstaging\ndev\n' ;;
      single)  printf 'only\n' ;;
      empty)   : ;;  # no output
      fail)    exit 1 ;;
      *)       : ;;
    esac
    ;;
  *"config current-context"*)
    case "$mode" in
      many)    echo "prod" ;;
      single)  echo "only" ;;
      empty)   echo "" ;;
      fail)    exit 1 ;;
      oidc|plainauth|badjson) echo "some-ctx" ;;
      *)       echo "" ;;
    esac
    ;;
  *"config view --minify"*)
    case "$mode" in
      oidc)
        cat <<'JSON'
{
  "users": [
    {
      "name": "test-user",
      "user": {
        "exec": {
          "apiVersion": "client.authentication.k8s.io/v1beta1",
          "command": "kubectl-oidc-login",
          "args": ["get-token", "--issuer-url=https://example.com"]
        }
      }
    }
  ]
}
JSON
        ;;
      plainauth)
        cat <<'JSON'
{
  "users": [
    {
      "name": "test-user",
      "user": {
        "token": "ey.redacted.jwt"
      }
    }
  ]
}
JSON
        ;;
      badjson)  echo "not a json" ;;
      fail)     exit 1 ;;
      *)        echo "{}" ;;
    esac
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/kubectl"

export PATH="$stub_dir:$PATH"
orig_path="$PATH"
empty_dir="$tmpdir/empty_path"
mkdir -p "$empty_dir"

# Ensure no kube overrides leak from the host environment
unset KUBECONFIG CLAUDESEC_KUBECONTEXT || true

# ──────────────────────────────────────────────────────────────────────────────
# kubectl_list_contexts()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_list_contexts() ==="

# 1. Many contexts → emits each on its own line
export KCTL_STUB_MODE="many"
ctxs=$(kubectl_list_contexts)
assert_contains "kubectl_list_contexts: contains prod"    "$ctxs" "prod"
assert_contains "kubectl_list_contexts: contains staging" "$ctxs" "staging"
assert_contains "kubectl_list_contexts: contains dev"     "$ctxs" "dev"
line_count=$(echo "$ctxs" | wc -l | tr -d ' ')
assert_eq "kubectl_list_contexts: 3 lines" "3" "$line_count"

# 2. Single context
export KCTL_STUB_MODE="single"
ctxs_one=$(kubectl_list_contexts)
assert_eq "kubectl_list_contexts: single context exact" "only" "$ctxs_one"

# 3. Empty / failure → returns empty (or nonzero rc silenced)
export KCTL_STUB_MODE="empty"
ctxs_empty=$(kubectl_list_contexts)
assert_eq "kubectl_list_contexts: empty output" "" "$ctxs_empty"

export KCTL_STUB_MODE="fail"
ctxs_fail=$(kubectl_list_contexts 2>/dev/null || true)
assert_eq "kubectl_list_contexts: fail suppressed" "" "$ctxs_fail"

# 4. Missing kubectl on PATH → returns nonzero before invoking anything
PATH="$empty_dir"
kubectl_list_contexts >/dev/null 2>&1
assert_false "kubectl_list_contexts: no kubectl returns nonzero" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# kubectl_current_context()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_current_context() ==="

# 1. Reads from stubbed kubectl when CLAUDESEC_KUBECONTEXT unset
unset CLAUDESEC_KUBECONTEXT
export KCTL_STUB_MODE="many"
cur=$(kubectl_current_context)
assert_eq "kubectl_current_context: many → prod" "prod" "$cur"

export KCTL_STUB_MODE="single"
cur1=$(kubectl_current_context)
assert_eq "kubectl_current_context: single → only" "only" "$cur1"

# 2. Empty / failure → empty string (function echoes "" on failure)
export KCTL_STUB_MODE="empty"
cur_empty=$(kubectl_current_context)
assert_eq "kubectl_current_context: empty stub → empty" "" "$cur_empty"

export KCTL_STUB_MODE="fail"
cur_fail=$(kubectl_current_context)
assert_eq "kubectl_current_context: fail stub → empty" "" "$cur_fail"

# 3. CLAUDESEC_KUBECONTEXT override short-circuits stubbed kubectl
export CLAUDESEC_KUBECONTEXT="override-ctx"
export KCTL_STUB_MODE="many"   # stub would say "prod" but override wins
cur_override=$(kubectl_current_context)
assert_eq "kubectl_current_context: override wins" "override-ctx" "$cur_override"
unset CLAUDESEC_KUBECONTEXT

# 4. Missing kubectl → nonzero return code (still no stdout)
PATH="$empty_dir"
cur_nocli=$(kubectl_current_context 2>/dev/null || echo "__no_kubectl__")
assert_eq "kubectl_current_context: no kubectl sentinel" "__no_kubectl__" "$cur_nocli"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# kubectl_current_context_uses_oidc_exec()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_current_context_uses_oidc_exec() ==="

# 1. Kubeconfig with oidc-login exec plugin → returns 0
export KCTL_STUB_MODE="oidc"
kubectl_current_context_uses_oidc_exec
assert_true "uses_oidc_exec: oidc config returns 0" "$?"

# 2. Kubeconfig with plain token → returns nonzero
export KCTL_STUB_MODE="plainauth"
kubectl_current_context_uses_oidc_exec
assert_false "uses_oidc_exec: plain-auth config returns nonzero" "$?"

# 3. Malformed config view output → nonzero
export KCTL_STUB_MODE="badjson"
kubectl_current_context_uses_oidc_exec
assert_false "uses_oidc_exec: bad json returns nonzero" "$?"

# 4. kubectl config view fails → function returns nonzero via early return
export KCTL_STUB_MODE="fail"
kubectl_current_context_uses_oidc_exec
assert_false "uses_oidc_exec: kubectl fail returns nonzero" "$?"

# 5. Missing kubectl CLI → returns nonzero
PATH="$empty_dir"
kubectl_current_context_uses_oidc_exec
assert_false "uses_oidc_exec: no kubectl returns nonzero" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
