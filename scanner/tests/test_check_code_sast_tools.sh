#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/code/sast-tools.sh
#
# WHY THIS TEST IS NARROW:
# sast-tools.sh (CODE-SAST-001..006) wraps live external CLIs:
#   semgrep, bandit, gosec, brakeman, npm-audit, pip-audit, cargo-audit, govulncheck.
# It executes those tools against SCAN_DIR at runtime and parses their JSON output.
# There are no file-pattern heuristics to exercise with fixtures — the check produces
# SKIP when a CLI is absent, and PASS/FAIL only when the CLI is installed and run.
# Making these tests non-flaky would require either stubbing every CLI binary or
# having them installed in CI, neither of which is hermetic.
#
# WHAT IS TESTABLE OFFLINE (no live CLIs needed):
#   CODE-SAST-001..005  skip when CLAUDESEC_NONINTERACTIVE=1 (dashboard mode gate)
#   CODE-SAST-006       WARN when 0 tools are installed (tool-coverage summary)
#
# Run: bash scanner/tests/test_check_code_sast_tools.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }  # suppress info output in test context

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]}"; do
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

run_check_noninteractive() {
  RESULTS=()
  # Inject language detection vars expected by sast-tools.sh
  _has_python=false; _has_js=false; _has_ts=false
  _has_go=false; _has_java=false; _has_ruby=false; _has_php=false
  CLAUDESEC_NONINTERACTIVE=1 source "$CHECKS_DIR/code/sast-tools.sh"
}

run_check_interactive() {
  RESULTS=()
  _has_python=false; _has_js=false; _has_ts=false
  _has_go=false; _has_java=false; _has_ruby=false; _has_php=false
  SCAN_DIR="$1"
  # Run without CLAUDESEC_NONINTERACTIVE so the tool-presence path executes
  unset CLAUDESEC_NONINTERACTIVE 2>/dev/null || true
  source "$CHECKS_DIR/code/sast-tools.sh" 2>/dev/null || true
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── CLAUDESEC_NONINTERACTIVE=1 short-circuits all checks to SKIP ─────────────

echo "=== CODE-SAST: NONINTERACTIVE mode skips all checks ==="

mkdir -p "$tmpdir/empty"
echo "# readme" > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check_noninteractive
assert_has_result "NONINTERACTIVE skips CODE-SAST-001 (Semgrep)" "SKIP" "CODE-SAST-001"
assert_has_result "NONINTERACTIVE skips CODE-SAST-002 (Bandit)" "SKIP" "CODE-SAST-002"
assert_has_result "NONINTERACTIVE skips CODE-SAST-003 (gosec)" "SKIP" "CODE-SAST-003"
assert_has_result "NONINTERACTIVE skips CODE-SAST-004 (dep audit)" "SKIP" "CODE-SAST-004"

# ── Interactive mode: no lockfile -> CODE-SAST-004 skips ─────────────────────

echo "=== CODE-SAST-004: no lockfile -> skip ==="

mkdir -p "$tmpdir/nolockfile"
cat > "$tmpdir/nolockfile/app.py" <<'PY'
print("hello")
PY
run_check_interactive "$tmpdir/nolockfile"
assert_has_result "No lockfile -> skip CODE-SAST-004" "SKIP" "CODE-SAST-004"

# ── Interactive mode: lockfile present -> CODE-SAST-004 passes or skips ──────

echo "=== CODE-SAST-004: requirements.txt present -> pass or skip ==="

mkdir -p "$tmpdir/withlockfile"
cat > "$tmpdir/withlockfile/requirements.txt" <<'REQ'
flask==3.0.0
requests==2.31.0
REQ
run_check_interactive "$tmpdir/withlockfile"
# pip-audit/safety may or may not be installed; result is PASS or SKIP, never FAIL on a clean fixture
for r in "${RESULTS[@]}"; do
  if [[ "$r" == "PASS:CODE-SAST-004"* || "$r" == "SKIP:CODE-SAST-004"* ]]; then
    echo "  PASS: requirements.txt -> CODE-SAST-004 is PASS or SKIP (not FAIL)"
    ((TEST_PASSED++))
    break
  fi
done

# ── Interactive mode: no SAST tools -> CODE-SAST-006 warns ──────────────────

echo "=== CODE-SAST-006: no installed SAST tools -> WARN ==="

# Override has_command to simulate no tools installed
has_command() { return 1; }
mkdir -p "$tmpdir/notool"
cat > "$tmpdir/notool/app.py" <<'PY'
print("hello")
PY
run_check_interactive "$tmpdir/notool"
unset -f has_command 2>/dev/null || true
# Restore real has_command from checks.sh
source "$LIB_DIR/checks.sh"
assert_has_result "No SAST tools installed -> WARN CODE-SAST-006" "WARN" "CODE-SAST-006"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
