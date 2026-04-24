#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for kubectl_auto_find_kubeconfig() in scanner/lib/checks.sh.
# Covers the conventional-path lookup order (configs/dev → staging → prod →
# ./kubeconfig → config/kubeconfig) and the final `find configs/*/kubeconfig`
# fallback — the whole helper was previously uncovered by kcov.
# Run: bash scanner/tests/test_kubectl_auto_find_kubeconfig.sh
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

# Color codes referenced by sourced lib
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Each scenario uses a fresh base_dir so the `tried` array lookup is
# deterministic and doesn't inherit files from earlier cases.
mkbase() {
  local d; d=$(mktemp -d -p "$tmpdir")
  echo "$d"
}

# ──────────────────────────────────────────────────────────────────────────────
# 1. configs/dev/kubeconfig — highest-priority conventional path
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: configs/dev wins ==="
base=$(mkbase)
mkdir -p "$base/configs/dev" "$base/configs/staging" "$base/configs/prod"
: > "$base/configs/dev/kubeconfig"
: > "$base/configs/staging/kubeconfig"
: > "$base/configs/prod/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "configs/dev wins over staging+prod" "$base/configs/dev/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 2. configs/staging/kubeconfig — chosen when dev missing
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: configs/staging when dev absent ==="
base=$(mkbase)
mkdir -p "$base/configs/staging" "$base/configs/prod"
: > "$base/configs/staging/kubeconfig"
: > "$base/configs/prod/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "configs/staging wins over prod" "$base/configs/staging/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 3. configs/prod/kubeconfig — chosen when dev+staging missing
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: configs/prod when dev+staging absent ==="
base=$(mkbase)
mkdir -p "$base/configs/prod"
: > "$base/configs/prod/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "configs/prod returned" "$base/configs/prod/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 4. base_dir/kubeconfig — flat project layout, no configs/ dir
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: base_dir/kubeconfig (flat layout) ==="
base=$(mkbase)
: > "$base/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "base_dir/kubeconfig returned" "$base/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 5. base_dir/config/kubeconfig — last item in the tried[] array
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: config/kubeconfig (tried[] tail) ==="
base=$(mkbase)
mkdir -p "$base/config"
: > "$base/config/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "config/kubeconfig returned" "$base/config/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 6. Fallback `find configs/*/kubeconfig` — only non-conventional configs/
#    subdir exists (not dev/staging/prod), so the tried[] loop misses and the
#    while+find branch fires.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: find fallback under configs/* ==="
base=$(mkbase)
mkdir -p "$base/configs/qa"
: > "$base/configs/qa/kubeconfig"
got=$(kubectl_auto_find_kubeconfig "$base")
assert_eq "find fallback picks configs/qa/kubeconfig" "$base/configs/qa/kubeconfig" "$got"

# ──────────────────────────────────────────────────────────────────────────────
# 7. Nothing exists — function returns 1 with empty stdout.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: nothing found ==="
base=$(mkbase)
got=$(kubectl_auto_find_kubeconfig "$base")
rc=$?
assert_eq    "nothing found: empty output" "" "$got"
assert_false "nothing found: rc nonzero"   "$rc"

# ──────────────────────────────────────────────────────────────────────────────
# 8. Default arg — base_dir="${1:-.}" lets callers omit the argument.
#    Run from an empty cwd so the function looks at "."/configs/… which
#    doesn't exist → rc nonzero, empty output. Proves the default triggers
#    without exploding.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== kubectl_auto_find_kubeconfig: default base_dir=. ==="
base=$(mkbase)
pushd "$base" >/dev/null || exit 1
got=$(kubectl_auto_find_kubeconfig)
rc=$?
popd >/dev/null || exit 1
assert_eq    "default base_dir: empty output" "" "$got"
assert_false "default base_dir: rc nonzero"   "$rc"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
