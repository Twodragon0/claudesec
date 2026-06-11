#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
# Live integration test for scanner/checks/windows/kisa-security.sh
#
# PURPOSE:
#   Run on a real Windows runner (windows-latest) with Git-Bash.  Asserts
#   STRUCTURE only: every check ID (WIN-001..020) emits exactly one result
#   and the verdict type is one of PASS|FAIL|WARN|SKIP.  FAILs must carry a
#   severity in {critical,high,medium,low}.  Specific verdicts are NOT
#   asserted — runner security state is uncontrolled.
#
#   WIN-020 may legitimately SKIP when Get-MpComputerStatus returns no data.
#
# HERMETIC GUARDS:
#   - SCAN_DIR  -> fresh tmpdir (no real project files)
#   - HOME      -> fresh tmpdir (no runner dotfiles)
#   - Read-only: the test never runs secedit /import, Set-NetFirewallProfile,
#     or any other state-mutating command.
#
# NON-WINDOWS BEHAVIOUR:
#   On Linux/macOS the kisa-security.sh OS guard fires: all 20 IDs emit SKIP.
#   This test treats that as a valid structural outcome, so it passes cleanly
#   on non-Windows hosts (uname != MINGW*/MSYS*/CYGWIN*, SYSTEMROOT unset).
#
# SHELL NOTE:
#   The GitHub Actions step sets shell: bash so this runs under Git-Bash on
#   windows-latest. kisa-security.sh's uname -s returns MINGW64 (or similar)
#   in Git-Bash, which matches the Windows guard, so the live checks execute.
#
# This file is intentionally NOT listed in scanner-unit-tests in lint.yml
# (it is Windows-only); the offline SKIP test is registered there instead.
#
# Run: bash scanner/tests/test_check_windows_kisa_security_live.sh
export CLAUDESEC_DASHBOARD_OFFLINE=1
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes (checks.sh uses these for output formatting)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture pass/fail/warn/skip calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${3:-unknown}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

# shellcheck source=../lib/checks.sh
source "$LIB_DIR/checks.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

assert_exactly_one_result() {
  local check_id="$1"
  local count=0
  local verdict=""
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == PASS:"${check_id}"* || "$r" == FAIL:"${check_id}"* || \
          "$r" == WARN:"${check_id}"* || "$r" == SKIP:"${check_id}"* ]]; then
      ((count++))
      verdict="$r"
    fi
  done

  if [[ "$count" -eq 1 ]]; then
    echo "  PASS: $check_id emitted exactly one result ($verdict)"
    ((TEST_PASSED++))
  elif [[ "$count" -eq 0 ]]; then
    echo "  FAIL: $check_id emitted NO result (expected exactly 1)"
    ((TEST_FAILED++))
    return
  else
    echo "  FAIL: $check_id emitted $count results (expected exactly 1): ${RESULTS[*]:-}"
    ((TEST_FAILED++))
    return
  fi

  # Assert verdict type is one of PASS|FAIL|WARN|SKIP
  local vtype="${verdict%%:*}"
  case "$vtype" in
    PASS|FAIL|WARN|SKIP)
      echo "  PASS: $check_id verdict type '$vtype' is valid"
      ((TEST_PASSED++))
      ;;
    *)
      echo "  FAIL: $check_id verdict type '$vtype' is not PASS|FAIL|WARN|SKIP"
      ((TEST_FAILED++))
      return
      ;;
  esac

  # If FAIL, assert severity is in {critical,high,medium,low}
  if [[ "$vtype" == "FAIL" ]]; then
    # RESULTS format: FAIL:<id>:<severity>
    local severity="${verdict#"FAIL:${check_id}:"}"
    case "$severity" in
      critical|high|medium|low)
        echo "  PASS: $check_id FAIL severity '$severity' is valid"
        ((TEST_PASSED++))
        ;;
      *)
        echo "  FAIL: $check_id FAIL severity '$severity' not in {critical,high,medium,low}"
        ((TEST_FAILED++))
        ;;
    esac
  fi
}

# ---------------------------------------------------------------------------
# Setup: isolated SCAN_DIR and HOME
# ---------------------------------------------------------------------------

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir/scan"
mkdir -p "$SCAN_DIR"

# Override HOME so no runner dotfiles are read.
fake_home="$tmpdir/home"
mkdir -p "$fake_home"
export HOME="$fake_home"

# ---------------------------------------------------------------------------
# Run the live Windows KISA check
# ---------------------------------------------------------------------------

_uname_s="$(uname -s)"
_is_windows=false
if [[ "$_uname_s" == *"MINGW"* || "$_uname_s" == *"MSYS"* || \
      "$_uname_s" == *"CYGWIN"* || -n "${SYSTEMROOT:-}" ]]; then
  _is_windows=true
fi

if "$_is_windows"; then
  echo "=== Running live Windows KISA check under $_uname_s ==="
else
  echo "=== Non-Windows host ($_uname_s) — all checks will SKIP via OS guard ==="
fi
echo "    SCAN_DIR=$SCAN_DIR"
echo "    HOME=$HOME"
echo ""

RESULTS=()
# shellcheck source=../checks/windows/kisa-security.sh
source "$CHECKS_DIR/windows/kisa-security.sh"

echo ""
echo "=== Raw RESULTS array ==="
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  echo "  $r"
done
echo ""

# ---------------------------------------------------------------------------
# Structural assertions: exactly one result per ID, valid type, valid severity
# ---------------------------------------------------------------------------

echo "=== Structural assertions: WIN-001..020 ==="
for id in WIN-001 WIN-002 WIN-003 WIN-004 WIN-005 \
           WIN-006 WIN-007 WIN-008 WIN-009 WIN-010 \
           WIN-011 WIN-012 WIN-013 WIN-014 WIN-015 \
           WIN-016 WIN-017 WIN-018 WIN-019 WIN-020; do
  assert_exactly_one_result "$id"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
