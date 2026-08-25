#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for output.sh::generate_html_dashboard() — stderr surfacing.
#
# WHAT THIS PINS. The python generator used to be invoked as
# `python3 "$py_script" "$output_file" 2>/dev/null`, which discarded two
# different things on the ONLY path a real scan takes:
#
#   1. A traceback. The generator failed, `generate_html_dashboard_legacy` took
#      its place, and the operator got a poorer dashboard with nothing on screen
#      or in the log saying so — the #445/#446/#448 "wrong by omission" shape.
#   2. Warnings on the SUCCESS path. `dashboard_auth.py` warns when
#      `.claudesec-assets/dashboard-data.json` is unusable and the SSO card
#      renders as N/A. The dashboard is produced, with a known gap, and the
#      warning was unreachable outside unit tests.
#
# The legacy fallback is deliberately KEPT — a scan that cannot render the rich
# dashboard should still produce one — so what is asserted here is that the
# DOWNGRADE IS ANNOUNCED, not that it stopped happening.
#
# Run: bash scanner/tests/test_output_dashboard_gen_stderr.sh

set -uo pipefail

# Hermetic offline guard (PR #190). Every stub below replaces dashboard-gen.py,
# so no real generator runs, but `generate_html_dashboard` is the function under
# test and the guard must hold for any future case that does not stub it.
export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR_REAL="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

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

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label (expected '$expected', got '$actual')"
    ((TEST_FAILED++))
  fi
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Point TMPDIR at this run's own directory so the `mktemp` inside
# `generate_html_dashboard` lands somewhere only this run can touch. Without it,
# Case 6's leak check reads the shared /tmp and reports on other runs' residue —
# see the note there. Exported (not just set) because the function runs in this
# shell and shells out to python3.
export TMPDIR="$tmpdir"

SCAN_DIR="$tmpdir"
source "$LIB_DIR_REAL/output.sh" 2>/dev/null || true
should_report() { return 0; }

# Minimal scan state shared by every case.
TOTAL_CHECKS=2
PASSED=2
FAILED=0
WARNINGS=0
SKIPPED=0
FINDINGS_CRITICAL=()
FINDINGS_HIGH=()
FINDINGS_MEDIUM=()
FINDINGS_LOW=()
FINDINGS_WARN=()
CLAUDESEC_GENERATE_DIAGRAMS=0

# Install a stubbed dashboard-gen.py and point LIB_DIR at it. The stub is the
# real seam: `generate_html_dashboard` shells out to `$LIB_DIR/dashboard-gen.py`,
# so replacing that file drives every branch without needing the generator to be
# broken for real.
_install_stub() {
  local name="$1" body="$2"
  LIB_DIR="$tmpdir/lib-$name"
  mkdir -p "$LIB_DIR"
  printf '%s\n' "$body" > "$LIB_DIR/dashboard-gen.py"
  chmod +x "$LIB_DIR/dashboard-gen.py"
}

# ==============================================================================
# Case 1: generator FAILS — the traceback and the downgrade must both be visible
# ==============================================================================
echo ""
echo "=== generator failure is announced, not swallowed ==="

_install_stub fail '
import sys
print("Traceback (most recent call last):", file=sys.stderr)
print("RuntimeError: synthetic generator failure", file=sys.stderr)
sys.exit(1)
'
out_html="$tmpdir/fail.html"
err_fail="$(generate_html_dashboard "$out_html" 2>&1 >/dev/null)"

assert_contains "stderr from the generator reaches the operator" \
  "$err_fail" "RuntimeError: synthetic generator failure"
assert_contains "stderr lines are tagged so they are attributable" \
  "$err_fail" "[dashboard]"
assert_contains "the downgrade itself is announced" \
  "$err_fail" "falling back to the legacy bash dashboard"
assert_contains "the announcement says what the operator loses" \
  "$err_fail" "omits Prowler, compliance and network sections"
assert_contains "the exit code is reported" "$err_fail" "(exit 1)"
# The fallback must still run: a scan that cannot render the rich dashboard is
# expected to produce the legacy one rather than nothing.
assert_eq "legacy fallback still produced a file" "true" \
  "$([[ -f "$out_html" ]] && echo true || echo false)"
assert_contains "the file is the legacy dashboard" "$(cat "$out_html")" "ClaudeSec Dashboard"

# ==============================================================================
# Case 2: generator SUCCEEDS but warns — the gap must be visible, with NO downgrade
# ==============================================================================
echo ""
echo "=== success-path warnings survive (this is the half unit tests could not reach) ==="

_install_stub warn '
import sys
print("RuntimeWarning: Ignoring unusable asset data at dashboard-data.json", file=sys.stderr)
open(sys.argv[1], "w").write("<html><body>RICH DASHBOARD</body></html>")
sys.exit(0)
'
out_html="$tmpdir/warn.html"
err_warn="$(generate_html_dashboard "$out_html" 2>&1 >/dev/null)"

assert_contains "the warning is surfaced on the success path" \
  "$err_warn" "Ignoring unusable asset data"
assert_not_contains "success must NOT claim a downgrade" \
  "$err_warn" "falling back to the legacy bash dashboard"
assert_contains "the rich dashboard is what was written" \
  "$(cat "$out_html")" "RICH DASHBOARD"

# ==============================================================================
# Case 3: clean success — no noise at all
# ==============================================================================
echo ""
echo "=== a clean run stays quiet ==="

_install_stub clean '
import sys
open(sys.argv[1], "w").write("<html><body>RICH DASHBOARD</body></html>")
sys.exit(0)
'
out_html="$tmpdir/clean.html"
err_clean="$(generate_html_dashboard "$out_html" 2>&1 >/dev/null)"

assert_eq "no stderr on a clean run" "" "$err_clean"
assert_contains "rich dashboard written" "$(cat "$out_html")" "RICH DASHBOARD"

# ==============================================================================
# Case 4: generator exits 0 but writes no file — still a failure
# ==============================================================================
echo ""
echo "=== exit 0 with no output file is treated as failure ==="

_install_stub nofile '
import sys
sys.exit(0)
'
out_html="$tmpdir/nofile.html"
err_nofile="$(generate_html_dashboard "$out_html" 2>&1 >/dev/null)"

assert_contains "missing output file triggers the downgrade notice" \
  "$err_nofile" "falling back to the legacy bash dashboard"
assert_contains "exit 0 is reported honestly in the notice" "$err_nofile" "(exit 0)"
assert_eq "legacy fallback produced the file instead" "true" \
  "$([[ -f "$out_html" ]] && echo true || echo false)"

# ==============================================================================
# Case 5: python3-absent path must not reference the temp file (set -u safety)
# ==============================================================================
echo ""
echo "=== python-absent path is unbound-variable safe ==="

# No dashboard-gen.py at all: the `if` guard is false, so `gen_err` is never
# created. Under the scanner's `set -u`, a cleanup line outside the branch would
# abort here with "gen_err: unbound variable" — this is the regression pin for
# that, and it fails LOUDLY rather than silently going quiet.
LIB_DIR="$tmpdir/lib-absent"
mkdir -p "$LIB_DIR"
out_html="$tmpdir/absent.html"
err_absent="$( (set -u; generate_html_dashboard "$out_html") 2>&1 >/dev/null )"

assert_not_contains "no unbound-variable error on the python-absent path" \
  "$err_absent" "unbound variable"
assert_eq "legacy fallback produced the file" "true" \
  "$([[ -f "$out_html" ]] && echo true || echo false)"

# ==============================================================================
# Case 6: no temp files are left behind on any path
# ==============================================================================
echo ""
echo "=== the stderr temp file is cleaned up ==="

# Scoped to THIS test's own directory, not the shared `$TMPDIR`.
#
# The first version scanned `${TMPDIR:-/tmp}` wholesale, which made the result
# depend on state no run of this file controls. Measured: after an unrelated
# earlier run of the PRE-FIX code (which creates these files and never removes
# them — the very leak this asserts against), four strays sat in `$TMPDIR` and
# this assertion reported `expected '0', got '4'` on a tree whose behaviour was
# correct. It passed in CI, where the runner is fresh, and failed locally. A
# check that reads another run's residue is not measuring this one.
#
# `TMPDIR` is exported for the whole file above, so `mktemp` inside `output.sh`
# lands here and the scan is exact.
leftover="$(find "$tmpdir" -maxdepth 1 -name 'claudesec-dashgen.*' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "no claudesec-dashgen.* temp files remain" "0" "$leftover"

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
exit "$TEST_FAILED"
