#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for kubectl_ensure_access() in scanner/lib/checks.sh.
# Covers every credential-refresh branch: noninteractive early-return,
# CLAUDESEC_KUBECONTEXT override, already-connected shortcut, EKS/GKE/AKS
# refresh, OIDC longer-timeout path, fall-through auth guide banner, and
# the _KUBECTL_ENSURE_ACCESS_DONE cache.
#
# No real kubectl / aws / gcloud / az is ever invoked. A per-test stub_dir
# is prepended to PATH with passthrough stubs for timeout + cloud CLIs.
# Run: bash scanner/tests/test_kubectl_ensure_access.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "  FAIL: $label"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: $haystack"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  PASS: $label"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "  FAIL: $label"
    echo "    expected NOT to contain: $needle"
    echo "    actual: $haystack"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

assert_true() {
  local label="$1" rc="$2"
  if [[ "$rc" == "0" ]]; then
    echo "  PASS: $label"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "  FAIL: $label (rc=$rc)"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

assert_false() {
  local label="$1" rc="$2"
  if [[ "$rc" != "0" ]]; then
    echo "  PASS: $label"
    TEST_PASSED=$((TEST_PASSED + 1))
  else
    echo "  FAIL: $label (rc=$rc)"
    TEST_FAILED=$((TEST_FAILED + 1))
  fi
}

# Color codes some helpers reference (silenced for test output)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

# Isolate HOME so kubectl_discover_kubeconfigs() doesn't touch the real ~/.kube.
# We also pre-create ~/.kube/config so the "Kubeconfig:" branch fires without
# forcing KUBECONFIG (setting KUBECONFIG makes _kubectl_cmd emit a multi-word
# string that breaks the stubbed `timeout` pass-through at exec time).
export HOME="$tmpdir/home"
mkdir -p "$HOME/.kube"
: > "$HOME/.kube/config"

# ──────────────────────────────────────────────────────────────────────────────
# Stub kubectl — behavior driven by env vars so each test can reconfigure:
#   STUB_CONTEXTS              newline-separated `get-contexts -o name` output
#   STUB_CURRENT_CTX           `config current-context` output (empty → blank)
#   STUB_CLUSTER_INFO_MODE     "always-fail" | "always-ok" | "switch-after-N"
#   STUB_CLUSTER_INFO_COUNTER  path to counter file (incremented per call)
#   STUB_CONFIG_VIEW_MODE      "empty" (default) | "oidc"
#   STUB_TRACE                 path to append one line per invocation (debug)
# ──────────────────────────────────────────────────────────────────────────────
cat > "$stub_dir/kubectl" <<'STUB'
#!/usr/bin/env bash
args="$*"
[[ -n "${STUB_TRACE:-}" ]] && echo "kubectl $args" >> "$STUB_TRACE"

case "$args" in
  *"config get-contexts -o name"*)
    printf '%s\n' "${STUB_CONTEXTS:-}"
    ;;
  *"config current-context"*)
    echo "${STUB_CURRENT_CTX:-}"
    ;;
  *"config view --minify"*)
    case "${STUB_CONFIG_VIEW_MODE:-empty}" in
      oidc)
        cat <<'JSON'
{"users":[{"name":"u","user":{"exec":{"command":"kubectl-oidc-login"}}}]}
JSON
        ;;
      *) echo "{}" ;;
    esac
    ;;
  *"cluster-info"*)
    mode="${STUB_CLUSTER_INFO_MODE:-always-fail}"
    counter_file="${STUB_CLUSTER_INFO_COUNTER:-/dev/null}"
    count=0
    if [[ -f "$counter_file" ]]; then count=$(cat "$counter_file" 2>/dev/null || echo 0); fi
    count=$((count + 1))
    [[ "$counter_file" != "/dev/null" ]] && echo "$count" > "$counter_file"
    case "$mode" in
      always-ok)   exit 0 ;;
      always-fail) exit 1 ;;
      switch-after-*)
        threshold="${mode#switch-after-}"
        if (( count > threshold )); then exit 0; else exit 1; fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  *"config use-context"*) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/kubectl"

# Pass-through timeout so run_with_timeout uses our stubs. We word-split the
# remaining args via `$*` (unquoted) rather than `"$@"` because callers in
# checks.sh invoke run_with_timeout with `"$(_kubectl_cmd)"` as a single
# quoted arg that still needs to be exec'd as `kubectl --context …`.
cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
shift
# shellcheck disable=SC2086
eval $*
STUB
chmod +x "$stub_dir/timeout"

# Cloud-CLI stubs — record that they were called, always exit 0.
cat > "$stub_dir/aws" <<'STUB'
#!/usr/bin/env bash
[[ -n "${STUB_AWS_CALLED:-}" ]] && echo "aws $*" >> "$STUB_AWS_CALLED"
exit 0
STUB
chmod +x "$stub_dir/aws"

cat > "$stub_dir/gcloud" <<'STUB'
#!/usr/bin/env bash
[[ -n "${STUB_GCLOUD_CALLED:-}" ]] && echo "gcloud $*" >> "$STUB_GCLOUD_CALLED"
exit 0
STUB
chmod +x "$stub_dir/gcloud"

cat > "$stub_dir/az" <<'STUB'
#!/usr/bin/env bash
[[ -n "${STUB_AZ_CALLED:-}" ]] && echo "az $*" >> "$STUB_AZ_CALLED"
# `az aks list --query ... -o tsv` is used to discover the resource group.
case "$*" in
  *"aks list"*) echo "my-rg" ;;
  *) : ;;
esac
exit 0
STUB
chmod +x "$stub_dir/az"

export PATH="$stub_dir:$PATH"
orig_path="$PATH"
empty_dir="$tmpdir/empty_path"
mkdir -p "$empty_dir"

# Defensively clear any host-side kube state.
unset KUBECONFIG CLAUDESEC_KUBECONTEXT CLAUDESEC_NONINTERACTIVE _KUBECTL_ENSURE_ACCESS_DONE || true

# Helper: reset per-test state before each scenario.
reset_state() {
  unset _KUBECTL_ENSURE_ACCESS_DONE CLAUDESEC_NONINTERACTIVE CLAUDESEC_KUBECONTEXT KUBECONFIG \
        STUB_CONTEXTS STUB_CURRENT_CTX STUB_CLUSTER_INFO_MODE STUB_CLUSTER_INFO_COUNTER \
        STUB_CONFIG_VIEW_MODE STUB_AWS_CALLED STUB_GCLOUD_CALLED STUB_AZ_CALLED STUB_TRACE || true
  PATH="$orig_path"
}

# ──────────────────────────────────────────────────────────────────────────────
# 1. No kubectl on PATH → returns nonzero immediately, no output.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: missing kubectl ==="
reset_state
PATH="$empty_dir"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false "missing kubectl: returns nonzero" "$rc"
assert_eq    "missing kubectl: no output" "" "$out"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
# 2. CLAUDESEC_NONINTERACTIVE=1 with no context/KUBECONFIG → early return 1.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: noninteractive early-return ==="
reset_state
export CLAUDESEC_NONINTERACTIVE=1
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false "noninteractive no-ctx: returns nonzero" "$rc"
assert_eq    "noninteractive no-ctx: silent" "" "$out"

# ──────────────────────────────────────────────────────────────────────────────
# 3. CLAUDESEC_KUBECONTEXT override + cluster-info ok → "Connected" banner.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: kubecontext override success ==="
reset_state
export CLAUDESEC_KUBECONTEXT="override-ctx"
export STUB_CLUSTER_INFO_MODE="always-ok"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true     "kubecontext override: rc 0" "$rc"
assert_contains "kubecontext override: banner" "$out" "Connected to cluster"
assert_contains "kubecontext override: ctx name" "$out" "override-ctx"

# ──────────────────────────────────────────────────────────────────────────────
# 4. CLAUDESEC_KUBECONTEXT override + cluster-info fails → prints
#    "Specified context … is not reachable" warning, then short-circuits at
#    checks.sh:627 because STUB_CONTEXTS is empty (no contexts to iterate).
#    Fall-through to the auth guide is covered separately in Scenario 11.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: kubecontext override unreachable ==="
reset_state
export CLAUDESEC_KUBECONTEXT="bad-ctx"
export STUB_CONTEXTS=""
export STUB_CLUSTER_INFO_MODE="always-fail"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false    "kubecontext unreachable: rc nonzero" "$rc"
assert_contains "kubecontext unreachable: warning" "$out" "is not reachable"

# ──────────────────────────────────────────────────────────────────────────────
# 5. _KUBECTL_ENSURE_ACCESS_DONE=1 cache → skips banner, uses has_kubectl_access.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: DONE cache short-circuit ==="
reset_state
export _KUBECTL_ENSURE_ACCESS_DONE=1
export STUB_CLUSTER_INFO_MODE="always-ok"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true         "cache hit: rc 0"             "$rc"
assert_not_contains "cache hit: no banner"        "$out" "Connected to cluster"
assert_not_contains "cache hit: no auth guide"    "$out" "Authentication Guide"

# ──────────────────────────────────────────────────────────────────────────────
# 6. First cluster-info succeeds (no override) → rc 0, no output at all.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: already connected ==="
reset_state
export STUB_CLUSTER_INFO_MODE="always-ok"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true         "already connected: rc 0" "$rc"
assert_not_contains "already connected: silent" "$out" "Kubernetes Authentication Guide"

# ──────────────────────────────────────────────────────────────────────────────
# 7. EKS refresh path — cluster-info fails once, succeeds after aws eks refresh.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: EKS refresh branch ==="
reset_state
export STUB_CURRENT_CTX="arn:aws:eks:us-east-1:acctid:cluster/my-eks"
export STUB_CONTEXTS="arn:aws:eks:us-east-1:acctid:cluster/my-eks"
export STUB_CLUSTER_INFO_COUNTER="$tmpdir/eks_cnt"; : > "$STUB_CLUSTER_INFO_COUNTER"
export STUB_CLUSTER_INFO_MODE="switch-after-1"   # fail first probe, succeed after refresh
export STUB_AWS_CALLED="$tmpdir/aws_called"; : > "$STUB_AWS_CALLED"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true     "EKS: rc 0 after refresh"            "$rc"
assert_contains "EKS: refresh banner"                "$out" "Refreshing EKS credentials"
assert_contains "EKS: cluster name in banner"        "$out" "my-eks"
aws_log=$(cat "$STUB_AWS_CALLED" 2>/dev/null || true)
assert_contains "EKS: aws eks update-kubeconfig ran" "$aws_log" "eks update-kubeconfig"
assert_contains "EKS: cluster name passed"           "$aws_log" "--name my-eks"
assert_contains "EKS: region passed"                 "$aws_log" "--region us-east-1"

# ──────────────────────────────────────────────────────────────────────────────
# 8. GKE refresh path — gcloud container clusters get-credentials invoked.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: GKE refresh branch ==="
reset_state
export STUB_CURRENT_CTX="gke_my-proj_us-central1_mycluster"
export STUB_CONTEXTS="gke_my-proj_us-central1_mycluster"
export STUB_CLUSTER_INFO_COUNTER="$tmpdir/gke_cnt"; : > "$STUB_CLUSTER_INFO_COUNTER"
export STUB_CLUSTER_INFO_MODE="switch-after-1"   # fail first probe, succeed after refresh
export STUB_GCLOUD_CALLED="$tmpdir/gcloud_called"; : > "$STUB_GCLOUD_CALLED"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true     "GKE: rc 0 after refresh"             "$rc"
assert_contains "GKE: refresh banner"                 "$out" "Refreshing GKE credentials"
assert_contains "GKE: cluster name in banner"         "$out" "mycluster"
gcloud_log=$(cat "$STUB_GCLOUD_CALLED" 2>/dev/null || true)
assert_contains "GKE: gcloud get-credentials ran"     "$gcloud_log" "container clusters get-credentials"
assert_contains "GKE: zone passed"                    "$gcloud_log" "--zone us-central1"
assert_contains "GKE: project passed"                 "$gcloud_log" "--project my-proj"

# ──────────────────────────────────────────────────────────────────────────────
# 9. AKS refresh path — az aks list + az aks get-credentials invoked.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: AKS refresh branch ==="
reset_state
export STUB_CURRENT_CTX="my-aks-cluster"
export STUB_CONTEXTS="my-aks-cluster"
export STUB_CLUSTER_INFO_COUNTER="$tmpdir/aks_cnt"; : > "$STUB_CLUSTER_INFO_COUNTER"
export STUB_CLUSTER_INFO_MODE="switch-after-1"   # fail first probe, succeed after refresh
export STUB_AZ_CALLED="$tmpdir/az_called"; : > "$STUB_AZ_CALLED"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true     "AKS: rc 0 after refresh"                 "$rc"
assert_contains "AKS: refresh banner"                     "$out" "Refreshing AKS credentials"
az_log=$(cat "$STUB_AZ_CALLED" 2>/dev/null || true)
assert_contains "AKS: az aks list queried resourceGroup"  "$az_log" "aks list"
assert_contains "AKS: az aks get-credentials ran"         "$az_log" "aks get-credentials"
assert_contains "AKS: resource group piped through"       "$az_log" "--resource-group my-rg"

# ──────────────────────────────────────────────────────────────────────────────
# 10. OIDC branch — cluster-info fails the first refresh pass, OIDC-detected,
#     longer-timeout retry succeeds.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: OIDC longer-timeout retry ==="
reset_state
export STUB_CURRENT_CTX="some-generic-ctx"
export STUB_CONTEXTS="some-generic-ctx"
export STUB_CONFIG_VIEW_MODE="oidc"
export STUB_CLUSTER_INFO_COUNTER="$tmpdir/oidc_cnt"; : > "$STUB_CLUSTER_INFO_COUNTER"
# Fail first two cluster-info probes, succeed on the OIDC (3rd) retry.
export STUB_CLUSTER_INFO_MODE="switch-after-2"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_true     "OIDC: rc 0 after browser retry"  "$rc"
assert_contains "OIDC: login hint"                "$out" "OIDC login"
# Pin the longer-timeout branch at checks.sh:690 — asserts that the retry
# actually ran through the 45s path, not just any OIDC-hinting code.
assert_contains "OIDC: 45s waiting banner"        "$out" "Waiting up to 45s"

# ──────────────────────────────────────────────────────────────────────────────
# 11. All contexts fail → prints full Kubernetes Authentication Guide banner.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: auth guide banner ==="
reset_state
export STUB_CURRENT_CTX="generic-ctx"
export STUB_CONTEXTS=$'generic-ctx\nother-ctx'
export STUB_CLUSTER_INFO_MODE="always-fail"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false    "auth guide: rc nonzero"              "$rc"
assert_contains "auth guide: banner header"           "$out" "Kubernetes Authentication Guide"
assert_contains "auth guide: EKS example"             "$out" "aws eks update-kubeconfig"
assert_contains "auth guide: GKE example"             "$out" "gcloud container clusters get-credentials"
assert_contains "auth guide: AKS example"             "$out" "az aks get-credentials"
assert_contains "auth guide: custom kubeconfig hint"  "$out" "--kubeconfig"
assert_contains "auth guide: OIDC hint"               "$out" "OIDC"

# ──────────────────────────────────────────────────────────────────────────────
# 12. No contexts at all → returns 1 before auth guide banner.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: no contexts available ==="
reset_state
export STUB_CONTEXTS=""
export STUB_CLUSTER_INFO_MODE="always-fail"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false        "no contexts: rc nonzero"          "$rc"
assert_not_contains "no contexts: skips auth guide"    "$out" "Kubernetes Authentication Guide"

# ──────────────────────────────────────────────────────────────────────────────
# 13. Missing KUBECONFIG file path → takes the "not found" discovery branch.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_ensure_access: kubeconfig-not-found branch ==="
reset_state
export KUBECONFIG="$tmpdir/does-not-exist"
export STUB_CONTEXTS=""
export STUB_CLUSTER_INFO_MODE="always-fail"
out=$(kubectl_ensure_access 2>&1)
rc=$?
assert_false    "kubeconfig missing: rc nonzero"  "$rc"
assert_contains "kubeconfig missing: warning"     "$out" "Kubeconfig not found"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
