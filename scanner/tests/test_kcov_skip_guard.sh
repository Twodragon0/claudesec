#!/usr/bin/env bash
# Executes the kcov-skip guard in the two browser-smoke tests, both directions.
#
# WHY THIS EXISTS: the guard it pins replaced one that never worked. The original
# read `/proc/self/status` for a non-zero `TracerPid`, on the premise that kcov
# shows up as a ptrace tracer. It does not — kcov 42 instruments bash through
# XTRACE. Measured under the exact CI invocation
# (`timeout 30 kcov --include-pattern=… <script>`), `TracerPid` is 0 for the
# script itself, while kcov announces itself in the environment:
#
#     KCOV_BASH_COMMAND=/bin/bash
#     KCOV_BASH_XTRACEFD=262144
#     PS4=kcov@${BASH_SOURCE}@${LINENO}@
#
# So both smokes drove headless Chrome under kcov for as long as the guard
# existed — 7s, 9s, 13s, 21s and 30s across five observed runs, one of them a red
# build on PR #465 that blocked a merge for a change touching none of this.
#
# A guard whose premise is wrong reads exactly like a guard that is working, so
# this test EXECUTES it rather than grepping for it, and pins BOTH directions:
# under-firing costs a flaky required check, and OVER-firing would make the
# dedicated dashboard-control-smoke workflow skip too — silently dropping the
# only coverage those 34 controls have.
#
# Run: bash scanner/tests/test_kcov_skip_guard.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TEST_PASSED=0
TEST_FAILED=0

SUBJECTS=(
  "test_dashboard_control_liveness.sh"
  "test_asset_dashboard_control_liveness.sh"
)

KCOV_SKIP_MARKER="running under kcov"

BASH_BIN="$(command -v bash)"

# A PATH that resolves everything the subjects need BEFORE their own node check
# (measured: `dirname` and `python3`) but deliberately NOT `node`. Starving PATH
# entirely was the first draft and it broke the scripts at their `dirname` call,
# long before the branch under test — a harness failure that read as a guard
# failure. Chrome is unreachable via CHROME_BIN below; the node check fires first
# in both subjects, so that is the skip we expect.
shim_dir="$(mktemp -d)"
trap 'rm -rf "$shim_dir"' EXIT
for tool in dirname python3; do
  tool_path="$(command -v "$tool" 2>/dev/null)" || {
    echo "  FAIL: harness needs $tool on PATH to build the shim"
    exit 1
  }
  ln -s "$tool_path" "$shim_dir/$tool"
done

pass() { echo "  PASS: $1"; ((TEST_PASSED++)); }
fail() {
  echo "  FAIL: $1"
  [[ -n "${2:-}" ]] && echo "    $2"
  ((TEST_FAILED++))
}

echo "=== kcov-skip guard ==="

for name in "${SUBJECTS[@]}"; do
  target="$SCRIPT_DIR/$name"
  if [[ ! -s "$target" ]]; then
    fail "$name exists" "not found or empty: $target"
    continue
  fi

  # ── direction 1: under kcov it must skip, instantly and successfully ────────
  # `KCOV_BASH_XTRACEFD` is what kcov exports; setting it is the whole simulation.
  out="$(KCOV_BASH_XTRACEFD=262144 bash "$target" 2>&1)"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    fail "$name: exits 0 under kcov" "rc=$rc, output: $out"
  elif [[ "$out" != *"$KCOV_SKIP_MARKER"* ]]; then
    fail "$name: announces the kcov skip" \
      "expected a line containing '$KCOV_SKIP_MARKER', got: $out"
  else
    pass "$name: skips under KCOV_BASH_XTRACEFD (rc=0)"
  fi

  # The other variable kcov exports must work on its own, so dropping either
  # spelling upstream cannot silently disable the guard.
  out="$(KCOV_BASH_COMMAND=/bin/bash bash "$target" 2>&1)"
  rc=$?
  if [[ $rc -eq 0 && "$out" == *"$KCOV_SKIP_MARKER"* ]]; then
    pass "$name: skips under KCOV_BASH_COMMAND (rc=0)"
  else
    fail "$name: skips under KCOV_BASH_COMMAND" "rc=$rc, output: $out"
  fi

  # ── direction 2: NOT under kcov it must not claim to be ─────────────────────
  # Deliberately starved of node and Chrome so the script takes one of its own
  # tooling skips instead of launching a browser: this asserts WHICH skip fires,
  # never that the smoke can run here. An over-firing kcov guard would make the
  # dedicated workflow a no-op, and nothing else would notice.
  # `bash` is invoked by ABSOLUTE path because the starved `PATH` cannot resolve
  # it — the first draft set `PATH=/nonexistent` and `env` failed with rc=127
  # before the script ever started, which looked like a guard failure.
  out="$(env -u KCOV_BASH_XTRACEFD -u KCOV_BASH_COMMAND \
    PATH="$shim_dir" CHROME_BIN=/nonexistent-for-this-test \
    "$BASH_BIN" "$target" 2>&1)"
  rc=$?
  if [[ "$out" == *"$KCOV_SKIP_MARKER"* ]]; then
    fail "$name: does NOT claim kcov when unset" \
      "the kcov skip fired with both variables unset — it would also fire in the dedicated workflow, silently dropping the browser coverage. Output: $out"
  elif [[ $rc -ne 0 ]]; then
    fail "$name: exits 0 when tooling is absent" "rc=$rc, output: $out"
  else
    pass "$name: takes a tooling skip, not the kcov skip, when kcov is absent"
  fi

  # ── the dead mechanism must not come back ──────────────────────────────────
  # `TracerPid` may still be NAMED in the explanatory comment — that history is
  # worth keeping — but it must not be read into a variable the control flow uses.
  if grep -nE '^[^#]*TracerPid' "$target" >/dev/null 2>&1; then
    fail "$name: no live TracerPid read" \
      "TracerPid appears outside a comment; kcov 42 does not ptrace, so such a check cannot fire: $(grep -nE '^[^#]*TracerPid' "$target")"
  else
    pass "$name: TracerPid appears only in comments, if at all"
  fi
done

echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
