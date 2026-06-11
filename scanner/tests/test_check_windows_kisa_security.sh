#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for scanner/checks/windows/kisa-security.sh
#
# WHY THIS TEST IS NARROW:
# kisa-security.sh requires a Windows Bash environment (MINGW/MSYS/CYGWIN or
# SYSTEMROOT set) and invokes PowerShell via ps_cmd() for every check:
#   powershell.exe, net accounts, auditpol, Get-LocalUser, Get-SmbShare,
#   Get-NetFirewallProfile, Get-MpComputerStatus, secedit, registry reads, etc.
#
# All 20 check IDs (WIN-001..WIN-020) are gated by the top-level OS guard:
#   if [[ "$(uname -s)" != *MINGW* && ... && -z "${SYSTEMROOT:-}" ]]; then
# On Linux/macOS CI runners the guard fires and every check emits SKIP.
#
# WHAT IS TESTABLE OFFLINE:
#   - Non-Windows OS: all 20 IDs emit SKIP (the OS guard path)
#   - WIN-003/005/006/007/020 pure-bash branching: these checks parse the
#     numeric output of ps_cmd() with grep -oE '[0-9]+' and bash integer
#     comparison. We test the branches by inlining the exact logic with
#     controlled input strings — isolating each check avoids cross-contamination
#     from other checks' ps_cmd calls when the whole file is sourced.
#
# NOT TESTABLE OFFLINE (reason):
#   WIN-001  powershell.exe Get-LocalUser — no PowerShell on Linux/macOS
#   WIN-002  powershell.exe Get-LocalUser — same
#   WIN-004  secedit /export + PasswordComplexity grep — Windows-only binary
#   WIN-008  HKLM registry LimitBlankPasswordUse — Windows registry absent
#   WIN-009  Get-NetFirewallProfile — Windows-only cmdlet
#   WIN-010  HKCU registry ScreenSave* — Windows registry absent
#   WIN-011  HKLM RDP-Tcp registry + fDenyTSConnections — Windows registry
#   WIN-012  HKLM Lsa RestrictAnonymousSAM registry — Windows registry absent
#   WIN-013  Get-SmbShare — Windows-only cmdlet
#   WIN-014  Get-Service loop — Windows-only cmdlet
#   WIN-015  Get-SmbServerConfiguration — Windows-only cmdlet
#   WIN-016  Microsoft.Update.AutoUpdate COM — Windows-only COM object
#   WIN-017  auditpol /get — Windows-only binary
#   WIN-018  Get-MpComputerStatus + SecurityCenter2 CIM — Windows-only
#   WIN-019  HKLM EnableLUA registry — Windows registry absent
#
# Run: bash scanner/tests/test_check_windows_kisa_security.sh
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
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

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

# ── 1. Non-Windows OS: OS guard emits SKIP for all 20 check IDs ──────────────
#
# On Linux/macOS uname -s returns "Linux" or "Darwin", and SYSTEMROOT is unset,
# so the guard fires and all 20 IDs emit SKIP before any PowerShell call.

_is_windows=false
if [[ "$(uname -s)" == *"MINGW"* || "$(uname -s)" == *"MSYS"* || \
      "$(uname -s)" == *"CYGWIN"* || -n "${SYSTEMROOT:-}" ]]; then
  _is_windows=true
fi

if ! $_is_windows; then
  echo "=== Windows OS guard: non-Windows system -> all 20 checks SKIP ==="
  RESULTS=()
  source "$CHECKS_DIR/windows/kisa-security.sh"
  assert_has_result "Non-Windows: WIN-001 skipped" "SKIP" "WIN-001"
  assert_has_result "Non-Windows: WIN-002 skipped" "SKIP" "WIN-002"
  assert_has_result "Non-Windows: WIN-003 skipped" "SKIP" "WIN-003"
  assert_has_result "Non-Windows: WIN-004 skipped" "SKIP" "WIN-004"
  assert_has_result "Non-Windows: WIN-005 skipped" "SKIP" "WIN-005"
  assert_has_result "Non-Windows: WIN-006 skipped" "SKIP" "WIN-006"
  assert_has_result "Non-Windows: WIN-007 skipped" "SKIP" "WIN-007"
  assert_has_result "Non-Windows: WIN-008 skipped" "SKIP" "WIN-008"
  assert_has_result "Non-Windows: WIN-009 skipped" "SKIP" "WIN-009"
  assert_has_result "Non-Windows: WIN-010 skipped" "SKIP" "WIN-010"
  assert_has_result "Non-Windows: WIN-011 skipped" "SKIP" "WIN-011"
  assert_has_result "Non-Windows: WIN-012 skipped" "SKIP" "WIN-012"
  assert_has_result "Non-Windows: WIN-013 skipped" "SKIP" "WIN-013"
  assert_has_result "Non-Windows: WIN-014 skipped" "SKIP" "WIN-014"
  assert_has_result "Non-Windows: WIN-015 skipped" "SKIP" "WIN-015"
  assert_has_result "Non-Windows: WIN-016 skipped" "SKIP" "WIN-016"
  assert_has_result "Non-Windows: WIN-017 skipped" "SKIP" "WIN-017"
  assert_has_result "Non-Windows: WIN-018 skipped" "SKIP" "WIN-018"
  assert_has_result "Non-Windows: WIN-019 skipped" "SKIP" "WIN-019"
  assert_has_result "Non-Windows: WIN-020 skipped" "SKIP" "WIN-020"
fi

# ── 2. Pure-bash branching logic (inlined, isolated per check) ────────────────
#
# Checks WIN-003/005/006/007/020 all follow the same pattern:
#   raw=$(ps_cmd "net accounts | Select-String 'X'" | tr -d '\r')
#   val=$(echo "$raw" | grep -oE '[0-9]+' || echo "0")
#   if [[ val <= threshold ]]; then pass; elif ...; then warn; else fail; fi
#
# We inline each check's exact logic with a controlled input string to exercise
# every branch.  This is hermetic on any OS and avoids cross-contamination when
# the whole check file is sourced (all 20 checks run at once sharing ps_cmd).

# ── WIN-003: Account lockout threshold ───────────────────────────────────────

run_win003() {
  # $1 = simulated ps_cmd output for the lockout line
  RESULTS=()
  local lockout="$1"
  local lockout_val
  lockout_val=$(echo "$lockout" | grep -oE '[0-9]+' || echo "0")
  if [[ -n "$lockout_val" && "$lockout_val" -gt 0 && "$lockout_val" -le 5 ]]; then
    pass "WIN-003" "Account lockout threshold is set to ${lockout_val} attempts (KISA W-04)"
  elif [[ -n "$lockout_val" && "$lockout_val" -gt 5 ]]; then
    warn "WIN-003" "Account lockout threshold is ${lockout_val} (recommended: <=5) (KISA W-04)" \
      "Set: net accounts /lockoutthreshold:5"
  else
    fail "WIN-003" "Account lockout is not configured (KISA W-04)" "high" \
      "Without lockout, brute-force attacks are unrestricted" \
      "Set threshold: net accounts /lockoutthreshold:5"
  fi
}

echo "=== WIN-003: lockout threshold 3 -> PASS ==="
run_win003 "Lockout threshold:                3"
assert_has_result "Lockout threshold 3 -> PASS WIN-003" "PASS" "WIN-003"

echo "=== WIN-003: lockout threshold 10 -> WARN ==="
run_win003 "Lockout threshold:                10"
assert_has_result "Lockout threshold 10 -> WARN WIN-003" "WARN" "WIN-003"

echo "=== WIN-003: lockout threshold Never (no digits) -> FAIL ==="
run_win003 "Lockout threshold:                Never"
assert_has_result "Lockout 'Never' -> FAIL WIN-003" "FAIL" "WIN-003"

echo "=== WIN-003: lockout threshold 0 -> FAIL ==="
run_win003 "Lockout threshold:                0"
assert_has_result "Lockout 0 -> FAIL WIN-003" "FAIL" "WIN-003"

# ── WIN-005: Minimum password length ─────────────────────────────────────────

run_win005() {
  RESULTS=()
  local pw_len="$1"
  local pw_len_val
  pw_len_val=$(echo "$pw_len" | grep -oE '[0-9]+' || echo "0")
  if [[ -n "$pw_len_val" && "$pw_len_val" -ge 8 ]]; then
    pass "WIN-005" "Minimum password length is ${pw_len_val} chars (KISA W-49)"
  elif [[ -n "$pw_len_val" && "$pw_len_val" -gt 0 ]]; then
    warn "WIN-005" "Minimum password length is ${pw_len_val} (recommended: >=8) (KISA W-49)" \
      "Set: net accounts /minpwlen:8"
  else
    fail "WIN-005" "No minimum password length configured (KISA W-49)" "high" \
      "Short passwords are easily cracked" \
      "Set minimum: net accounts /minpwlen:8"
  fi
}

echo "=== WIN-005: minimum password length 12 -> PASS ==="
run_win005 "Minimum password length:          12"
assert_has_result "Minimum pw length 12 -> PASS WIN-005" "PASS" "WIN-005"

echo "=== WIN-005: minimum password length 8 -> PASS ==="
run_win005 "Minimum password length:          8"
assert_has_result "Minimum pw length 8 -> PASS WIN-005 (boundary)" "PASS" "WIN-005"

echo "=== WIN-005: minimum password length 6 -> WARN ==="
run_win005 "Minimum password length:          6"
assert_has_result "Minimum pw length 6 -> WARN WIN-005" "WARN" "WIN-005"

echo "=== WIN-005: minimum password length 0 -> FAIL ==="
run_win005 "Minimum password length:          0"
assert_has_result "Minimum pw length 0 -> FAIL WIN-005" "FAIL" "WIN-005"

# ── WIN-006: Maximum password age ────────────────────────────────────────────

run_win006() {
  RESULTS=()
  local pw_max="$1"
  local pw_max_val
  pw_max_val=$(echo "$pw_max" | grep -oE '[0-9]+' || echo "0")
  if [[ -n "$pw_max_val" && "$pw_max_val" -le 90 && "$pw_max_val" -gt 0 ]]; then
    pass "WIN-006" "Maximum password age is ${pw_max_val} days (KISA W-50)"
  else
    fail "WIN-006" "Maximum password age is not set or too long (KISA W-50)" "medium" \
      "Passwords should be rotated periodically" \
      "Set: net accounts /maxpwage:90"
  fi
}

echo "=== WIN-006: maximum password age 60 -> PASS ==="
run_win006 "Maximum password age (days):      60"
assert_has_result "Max pw age 60 -> PASS WIN-006" "PASS" "WIN-006"

echo "=== WIN-006: maximum password age 90 -> PASS (boundary) ==="
run_win006 "Maximum password age (days):      90"
assert_has_result "Max pw age 90 -> PASS WIN-006 (boundary)" "PASS" "WIN-006"

echo "=== WIN-006: maximum password age 180 -> FAIL ==="
run_win006 "Maximum password age (days):      180"
assert_has_result "Max pw age 180 -> FAIL WIN-006" "FAIL" "WIN-006"

echo "=== WIN-006: maximum password age 0 -> FAIL ==="
run_win006 "Maximum password age (days):      0"
assert_has_result "Max pw age 0 -> FAIL WIN-006" "FAIL" "WIN-006"

# ── WIN-007: Minimum password age ────────────────────────────────────────────

run_win007() {
  RESULTS=()
  local pw_min="$1"
  local pw_min_val
  pw_min_val=$(echo "$pw_min" | grep -oE '[0-9]+' || echo "0")
  if [[ -n "$pw_min_val" && "$pw_min_val" -ge 1 ]]; then
    pass "WIN-007" "Minimum password age is ${pw_min_val} day(s) (KISA W-51)"
  else
    warn "WIN-007" "Minimum password age is 0 days (KISA W-51)" \
      "Set to at least 1 day: net accounts /minpwage:1"
  fi
}

echo "=== WIN-007: minimum password age 2 -> PASS ==="
run_win007 "Minimum password age (days):      2"
assert_has_result "Min pw age 2 -> PASS WIN-007" "PASS" "WIN-007"

echo "=== WIN-007: minimum password age 1 -> PASS (boundary) ==="
run_win007 "Minimum password age (days):      1"
assert_has_result "Min pw age 1 -> PASS WIN-007 (boundary)" "PASS" "WIN-007"

echo "=== WIN-007: minimum password age 0 -> WARN ==="
run_win007 "Minimum password age (days):      0"
assert_has_result "Min pw age 0 -> WARN WIN-007" "WARN" "WIN-007"

# ── WIN-020: Antivirus definition age ────────────────────────────────────────
#
# WIN-020 parses the numeric output of a multi-line ps_cmd call then branches:
#   def_age -le 3 -> PASS, -le 7 -> WARN, > 7 -> FAIL, non-numeric -> SKIP

run_win020() {
  RESULTS=()
  local def_age="$1"
  if [[ -n "$def_age" && "$def_age" =~ ^[0-9]+$ ]]; then
    if [[ "$def_age" -le 3 ]]; then
      pass "WIN-020" "Antivirus definitions updated within ${def_age} day(s) (KISA W-37)"
    elif [[ "$def_age" -le 7 ]]; then
      warn "WIN-020" "Antivirus definitions are ${def_age} days old (KISA W-37)" \
        "Update definitions: Update-MpSignature"
    else
      fail "WIN-020" "Antivirus definitions are ${def_age} days old (KISA W-37)" "high" \
        "Outdated definitions miss new threats" \
        "Update immediately: Update-MpSignature"
    fi
  else
    skip "WIN-020" "Antivirus definition age check" "Could not determine definition age"
  fi
}

echo "=== WIN-020: defs 1 day old -> PASS ==="
run_win020 "1"
assert_has_result "Defs 1 day old -> PASS WIN-020" "PASS" "WIN-020"

echo "=== WIN-020: defs 3 days old -> PASS (boundary) ==="
run_win020 "3"
assert_has_result "Defs 3 days old -> PASS WIN-020 (boundary)" "PASS" "WIN-020"

echo "=== WIN-020: defs 5 days old -> WARN ==="
run_win020 "5"
assert_has_result "Defs 5 days old -> WARN WIN-020" "WARN" "WIN-020"

echo "=== WIN-020: defs 7 days old -> WARN (boundary) ==="
run_win020 "7"
assert_has_result "Defs 7 days old -> WARN WIN-020 (boundary)" "WARN" "WIN-020"

echo "=== WIN-020: defs 10 days old -> FAIL ==="
run_win020 "10"
assert_has_result "Defs 10 days old -> FAIL WIN-020" "FAIL" "WIN-020"

echo "=== WIN-020: empty output -> SKIP ==="
run_win020 ""
assert_has_result "Empty def_age -> SKIP WIN-020" "SKIP" "WIN-020"

echo "=== WIN-020: non-numeric output -> SKIP ==="
run_win020 "N/A"
assert_has_result "Non-numeric def_age -> SKIP WIN-020" "SKIP" "WIN-020"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
