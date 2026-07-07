#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/infra/kubernetes.sh
#
# kubernetes.sh has two independent sections:
#
#   Section 1 (static manifests): files_contain scans *.yaml/*.yml for
#                                  Deployment/Pod/StatefulSet/DaemonSet kinds
#                                  and drives INFRA-010..015. Fully
#                                  fixture-testable.
#
#   Section 2 (live cluster): has_kubectl_access -> kubectl calls for
#                              INFRA-016 (pods as root), INFRA-017 (Pod
#                              Security Standards), INFRA-018 (RBAC
#                              cluster-admin bindings). Fixture-testable by
#                              stubbing kubectl helpers and the kubectl
#                              command itself.
#
# OFFLINE STRATEGY:
#   Override has_kubectl_access and kubectl_ensure_access so no real cluster
#   is ever contacted. For the live-cluster tests, additionally stub
#   _kubectl_cmd, kubectl_cluster_info, kubectl_server_version, and a
#   `kubectl` shell function that dispatches on subcommand.
#
# Run: bash scanner/tests/test_check_infra_kubernetes.sh
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

# run_check: no live cluster access -> only Section 1 (static manifest) logic
# is exercised; Section 2 always resolves to SKIP.
run_check() {
  RESULTS=()
  has_kubectl_access() { return 1; }
  kubectl_ensure_access() { return 1; }
  source "$CHECKS_DIR/infra/kubernetes.sh"
  unset -f has_kubectl_access kubectl_ensure_access 2>/dev/null || true
  source "$LIB_DIR/checks.sh"
}

# run_check_live_k8s: forces the live-cluster branch and stubs kubectl to
# dispatch on subcommand, reading behavior from KUBECTL_STUB_* vars set by
# the caller before invocation.
run_check_live_k8s() {
  RESULTS=()
  has_kubectl_access() { return 0; }
  kubectl_ensure_access() { return 0; }
  _kubectl_cmd() { echo "kubectl"; }
  kubectl_cluster_info() { echo "test-ctx|https://test-server:6443"; }
  kubectl_server_version() { echo "v1.28.0"; }
  kubectl() {
    case "$1 $2" in
      "get pods")
        printf '%s\n' "${KUBECTL_STUB_PODS:-}"
        ;;
      "get namespaces")
        if [[ "$*" == *"--no-headers"* ]]; then
          printf '%s\n' "${KUBECTL_STUB_NS_LIST:-}"
        else
          printf '%s\n' "${KUBECTL_STUB_PSS_LABELS:-}"
        fi
        ;;
      "get clusterrolebindings")
        printf '%s\n' "${KUBECTL_STUB_CRB:-}"
        ;;
      *)
        return 1
        ;;
    esac
  }
  source "$CHECKS_DIR/infra/kubernetes.sh"
  unset -f has_kubectl_access kubectl_ensure_access _kubectl_cmd \
    kubectl_cluster_info kubectl_server_version kubectl 2>/dev/null || true
  source "$LIB_DIR/checks.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── Section 1: Well-configured manifests -> all pass ────────────────────────

echo "=== Static manifests: hardened config -> pass ==="

mkdir -p "$tmpdir/hardened"
cat > "$tmpdir/hardened/deployment.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: myapp:1.0
          securityContext:
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes:
    - Ingress
YAML
SCAN_DIR="$tmpdir/hardened" run_check
assert_has_result "runAsNonRoot true -> PASS INFRA-010" "PASS" "INFRA-010"
assert_has_result "drop ALL capabilities -> PASS INFRA-011" "PASS" "INFRA-011"
assert_has_result "resource limits present -> PASS INFRA-012" "PASS" "INFRA-012"
assert_has_result "readOnlyRootFilesystem true -> PASS INFRA-013" "PASS" "INFRA-013"
assert_has_result "NetworkPolicy present -> PASS INFRA-014" "PASS" "INFRA-014"
assert_has_result "automountServiceAccountToken false -> PASS INFRA-015" "PASS" "INFRA-015"

# ── Section 1: Missing everything -> fail/warn ──────────────────────────────

echo "=== Static manifests: minimal config -> fail/warn ==="

mkdir -p "$tmpdir/minimal"
cat > "$tmpdir/minimal/deployment.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
YAML
SCAN_DIR="$tmpdir/minimal" run_check
assert_has_result "Missing runAsNonRoot -> FAIL INFRA-010" "FAIL" "INFRA-010"
assert_has_result "Missing dropped capabilities -> WARN INFRA-011" "WARN" "INFRA-011"
assert_has_result "Missing resource limits -> FAIL INFRA-012" "FAIL" "INFRA-012"
assert_has_result "Missing readOnlyRootFilesystem -> WARN INFRA-013" "WARN" "INFRA-013"
assert_has_result "Missing NetworkPolicy -> FAIL INFRA-014" "FAIL" "INFRA-014"
assert_has_result "Missing automountServiceAccountToken -> WARN INFRA-015" "WARN" "INFRA-015"

# ── Section 1: No Kubernetes manifests -> all skip ──────────────────────────

echo "=== No Kubernetes manifests -> skip ==="

mkdir -p "$tmpdir/no_k8s"
printf '# readme\n' > "$tmpdir/no_k8s/README.md"
SCAN_DIR="$tmpdir/no_k8s" run_check
assert_has_result "No manifests -> SKIP INFRA-010" "SKIP" "INFRA-010"
assert_has_result "No manifests -> SKIP INFRA-011" "SKIP" "INFRA-011"
assert_has_result "No manifests -> SKIP INFRA-012" "SKIP" "INFRA-012"
assert_has_result "No manifests -> SKIP INFRA-013" "SKIP" "INFRA-013"
assert_has_result "No manifests -> SKIP INFRA-014" "SKIP" "INFRA-014"
assert_has_result "No manifests -> SKIP INFRA-015" "SKIP" "INFRA-015"

# ── Section 2: Live cluster, healthy state -> all pass ──────────────────────

echo "=== Live cluster: healthy state -> pass ==="

KUBECTL_STUB_PODS="default/pod1: true"
KUBECTL_STUB_PSS_LABELS="restricted
restricted"
KUBECTL_STUB_NS_LIST="default
kube-system"
KUBECTL_STUB_CRB="cluster-admin"
SCAN_DIR="$tmpdir/no_k8s" run_check_live_k8s
assert_has_result "No root pods -> PASS INFRA-016" "PASS" "INFRA-016"
assert_has_result "PSS labels present -> PASS INFRA-017" "PASS" "INFRA-017"
assert_has_result "Single cluster-admin binding -> PASS INFRA-018" "PASS" "INFRA-018"
unset KUBECTL_STUB_PODS KUBECTL_STUB_PSS_LABELS KUBECTL_STUB_NS_LIST KUBECTL_STUB_CRB

# ── Section 2: Live cluster, unhealthy state -> fail/warn ───────────────────

echo "=== Live cluster: unhealthy state -> fail/warn ==="

KUBECTL_STUB_PODS="default/pod1: false
default/pod2: false"
KUBECTL_STUB_PSS_LABELS=""
KUBECTL_STUB_NS_LIST="default"
KUBECTL_STUB_CRB="cluster-admin
cluster-admin
cluster-admin"
SCAN_DIR="$tmpdir/no_k8s" run_check_live_k8s
assert_has_result "Root pods found -> FAIL INFRA-016" "FAIL" "INFRA-016"
assert_has_result "No PSS labels -> WARN INFRA-017" "WARN" "INFRA-017"
assert_has_result "Multiple cluster-admin bindings -> WARN INFRA-018" "WARN" "INFRA-018"
unset KUBECTL_STUB_PODS KUBECTL_STUB_PSS_LABELS KUBECTL_STUB_NS_LIST KUBECTL_STUB_CRB

# ── Section 2: No cluster access -> all skip ────────────────────────────────

echo "=== No cluster access -> skip ==="

SCAN_DIR="$tmpdir/no_k8s" run_check
assert_has_result "No cluster access -> SKIP INFRA-016" "SKIP" "INFRA-016"
assert_has_result "No cluster access -> SKIP INFRA-017" "SKIP" "INFRA-017"
assert_has_result "No cluster access -> SKIP INFRA-018" "SKIP" "INFRA-018"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
