#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for run_with_timeout() in scanner/lib/checks.sh.
# Targets the python3 fallback (L19-28) and the "no runner" else branch
# (L29-30) — neither is reachable when a real `timeout` or `gtimeout` sits
# first on PATH, which is the common case in every other fixture.
# Run: bash scanner/tests/test_run_with_timeout_fallbacks.sh
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

# Color codes referenced by sourced lib
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

orig_path="$PATH"

# ──────────────────────────────────────────────────────────────────────────────
# Resolve absolute paths for the binaries we exec through run_with_timeout.
# Each branch of run_with_timeout relies on PATH for its *runner* lookup
# (timeout / gtimeout / python3) but the *target* command is taken verbatim
# from "$@". Using absolute paths lets us restrict PATH without breaking the
# workload itself.
# ──────────────────────────────────────────────────────────────────────────────
pick_abs() {
  local name="$1" p
  for p in "/usr/bin/$name" "/bin/$name" "/usr/local/bin/$name"; do
    [[ -x "$p" ]] && { echo "$p"; return 0; }
  done
  return 1
}

BIN_TRUE=$(pick_abs true)     || { echo "skip: no absolute true"  >&2; exit 0; }
BIN_FALSE=$(pick_abs false)   || { echo "skip: no absolute false" >&2; exit 0; }
BIN_SLEEP=$(pick_abs sleep)   || { echo "skip: no absolute sleep" >&2; exit 0; }
BIN_PY3=$(pick_abs python3)   || { echo "skip: no absolute python3" >&2; exit 0; }

# ──────────────────────────────────────────────────────────────────────────────
# Build two restricted PATH directories:
#   - py_only:  exposes *only* python3 (no timeout, no gtimeout)
#   - empty:    exposes nothing (forces the last-resort `"$@" 2>/dev/null`)
# We deliberately DO NOT symlink `timeout`/`gtimeout` into py_only, so
# has_command returns false for both and execution falls through to python3.
# ──────────────────────────────────────────────────────────────────────────────
py_only="$tmpdir/py_only"; mkdir -p "$py_only"
ln -s "$BIN_PY3" "$py_only/python3"

empty_dir="$tmpdir/empty"; mkdir -p "$empty_dir"

# ──────────────────────────────────────────────────────────────────────────────
# 1. python3 fallback — successful command (rc 0 propagates from subprocess)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== run_with_timeout: python3 fallback (success) ==="
PATH="$py_only"
run_with_timeout 5 "$BIN_TRUE"
rc=$?
PATH="$orig_path"
assert_true "python3 fallback: true returns 0" "$rc"

# ──────────────────────────────────────────────────────────────────────────────
# 2. python3 fallback — failing command (non-zero rc propagates)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== run_with_timeout: python3 fallback (failure) ==="
PATH="$py_only"
run_with_timeout 5 "$BIN_FALSE"
rc=$?
PATH="$orig_path"
assert_eq "python3 fallback: false returns 1" "1" "$rc"

# ──────────────────────────────────────────────────────────────────────────────
# 3. python3 fallback — timeout triggers SystemExit(124)
#    (maps subprocess.TimeoutExpired to rc=124, matching GNU timeout's
#    convention that claudesec relies on elsewhere.)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== run_with_timeout: python3 fallback (timeout) ==="
PATH="$py_only"
run_with_timeout 0.1 "$BIN_SLEEP" 5
rc=$?
PATH="$orig_path"
assert_eq "python3 fallback: sleep 5 with 0.1s returns 124" "124" "$rc"

# ──────────────────────────────────────────────────────────────────────────────
# 4. else branch — no timeout/gtimeout/python3 on PATH.
#    Function falls all the way through to `"$@" 2>/dev/null`, which exec's
#    the absolute-path target directly.
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== run_with_timeout: else branch (no runner, success) ==="
PATH="$empty_dir"
run_with_timeout 5 "$BIN_TRUE"
rc=$?
PATH="$orig_path"
assert_true "else branch: true returns 0" "$rc"

echo ""
echo "=== run_with_timeout: else branch (no runner, failure) ==="
PATH="$empty_dir"
run_with_timeout 5 "$BIN_FALSE"
rc=$?
PATH="$orig_path"
assert_eq "else branch: false returns 1" "1" "$rc"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
