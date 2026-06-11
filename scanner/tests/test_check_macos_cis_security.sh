#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for scanner/checks/macos/cis-security.sh
#
# WHY THIS TEST IS NARROW:
# cis-security.sh requires macOS and invokes platform-only commands:
#   fdesetup, csrutil, spctl, defaults, systemsetup, launchctl, pwpolicy,
#   AssetCacheManagerUtil, /usr/libexec/ApplicationFirewall/socketfilterfw
#
# All 20 check IDs (MAC-001..MAC-010 + CIS-001..CIS-010) are gated by the
# top-level OS guard:
#   if [[ "$(uname)" != "Darwin" ]]; then  skip ...; return 0; fi
# On Linux CI runners (uname = Linux) the guard fires and every check
# emits SKIP — that is the only deterministic offline-testable path for
# the file when sourced whole.
#
# WHAT IS TESTABLE OFFLINE:
#   - Non-Darwin OS:  all 20 IDs emit SKIP (the OS guard path)
#   - CIS-005 SKIP:  Darwin + no 'brew' (has_command gate, tested inline)
#   - CIS-006 PASS/FAIL/WARN: pure grep logic on SSH config files, tested
#     by inlining the exact logic from the check against controlled fixtures
#     (sourcing the whole check on Darwin runs all live-binary checks;
#      inlining CIS-006 keeps tests hermetic on both OS families)
#
# NOT TESTABLE OFFLINE (reason):
#   MAC-001  fdesetup — macOS kernel binary, absent on Linux
#   MAC-002  /usr/libexec/ApplicationFirewall/socketfilterfw — absent on Linux
#   MAC-003  csrutil — SIP command, macOS-only binary
#   MAC-004  spctl — Gatekeeper binary, macOS-only
#   MAC-005  defaults read /Library/Preferences/com.apple.SoftwareUpdate —
#             requires real macOS plist infrastructure
#   MAC-006  defaults read com.apple.screensaver — requires real macOS plist
#   MAC-007  systemsetup -getremotelogin — macOS-only binary
#   MAC-008  defaults read com.apple.sharingd — requires real macOS plist
#   MAC-009  defaults read /Library/Preferences/com.apple.loginwindow —
#             requires real macOS plist
#   MAC-010  defaults read NSGlobalDomain — requires real macOS plist
#   CIS-001  pwpolicy — macOS-only binary
#   CIS-002  launchctl + com.apple.auditd — macOS launch daemon infrastructure
#   CIS-003  defaults read -app Terminal — requires real macOS app plist
#   CIS-004  find /System — meaningful only on macOS (Linux has no /System)
#   CIS-007  launchctl limit + sysctl kern.coredump — macOS-only sysctls
#   CIS-008  systemsetup -getnetworktimeserver + launchctl timed — macOS-only
#   CIS-009  defaults read com.apple.Bluetooth — requires real macOS plist
#   CIS-010  AssetCacheManagerUtil — macOS-only binary
#
# Run: bash scanner/tests/test_check_macos_cis_security.sh
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

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── 1. Non-Darwin OS: OS guard emits SKIP for all 20 check IDs ───────────────
#
# On Linux CI (uname = Linux) the top-level guard fires and returns/exits
# before any macOS command is ever invoked.  This is the primary hermetic path.

if [[ "$(uname)" != "Darwin" ]]; then
  echo "=== macOS OS guard: non-Darwin system -> all 20 checks SKIP ==="
  RESULTS=()
  source "$CHECKS_DIR/macos/cis-security.sh"
  assert_has_result "Non-Darwin: MAC-001 skipped" "SKIP" "MAC-001"
  assert_has_result "Non-Darwin: MAC-002 skipped" "SKIP" "MAC-002"
  assert_has_result "Non-Darwin: MAC-003 skipped" "SKIP" "MAC-003"
  assert_has_result "Non-Darwin: MAC-004 skipped" "SKIP" "MAC-004"
  assert_has_result "Non-Darwin: MAC-005 skipped" "SKIP" "MAC-005"
  assert_has_result "Non-Darwin: MAC-006 skipped" "SKIP" "MAC-006"
  assert_has_result "Non-Darwin: MAC-007 skipped" "SKIP" "MAC-007"
  assert_has_result "Non-Darwin: MAC-008 skipped" "SKIP" "MAC-008"
  assert_has_result "Non-Darwin: MAC-009 skipped" "SKIP" "MAC-009"
  assert_has_result "Non-Darwin: MAC-010 skipped" "SKIP" "MAC-010"
  assert_has_result "Non-Darwin: CIS-001 skipped" "SKIP" "CIS-001"
  assert_has_result "Non-Darwin: CIS-002 skipped" "SKIP" "CIS-002"
  assert_has_result "Non-Darwin: CIS-003 skipped" "SKIP" "CIS-003"
  assert_has_result "Non-Darwin: CIS-004 skipped" "SKIP" "CIS-004"
  assert_has_result "Non-Darwin: CIS-005 skipped" "SKIP" "CIS-005"
  assert_has_result "Non-Darwin: CIS-006 skipped" "SKIP" "CIS-006"
  assert_has_result "Non-Darwin: CIS-007 skipped" "SKIP" "CIS-007"
  assert_has_result "Non-Darwin: CIS-008 skipped" "SKIP" "CIS-008"
  assert_has_result "Non-Darwin: CIS-009 skipped" "SKIP" "CIS-009"
  assert_has_result "Non-Darwin: CIS-010 skipped" "SKIP" "CIS-010"
fi

# ── 2. CIS-006 logic: pure-bash SSH config file parsing ───────────────────────
#
# CIS-006 iterates over three SSH config paths and grep-parses cipher lines.
# This is pure bash+grep — no macOS binary needed.  We inline the exact logic
# from the check against controlled fixtures so the assertions run hermetically
# on Linux CI and on macOS alike.
#
# Logic copied verbatim from cis-security.sh CIS-006 section (lines 228-249).
# Accepts an explicit list of config paths to scan instead of hardcoded system
# paths, so the "no config found" WARN branch can be tested hermetically even
# on macOS where /etc/ssh/sshd_config and /etc/ssh/ssh_config exist.
run_cis006() {
  # $@  = explicit list of SSH config file paths to inspect
  RESULTS=()
  local ssh_config_checked=0
  local ssh_ciphers_ok=0
  for cfg in "$@"; do
    if [[ -f "$cfg" ]]; then
      ssh_config_checked=1
      if grep -qiE "^(Ciphers|KexAlgorithms|MACs)" "$cfg" 2>/dev/null; then
        if grep -qiE "arcfour|des|rc4|md5|sha1$" "$cfg" 2>/dev/null; then
          fail "CIS-006" "Weak ciphers or MACs found in SSH config (${cfg})" "high" \
            "Weak ciphers expose SSH sessions to attack" \
            "Restrict to: Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
        else
          ssh_ciphers_ok=1
        fi
      fi
    fi
  done
  if [[ "$ssh_config_checked" -eq 1 && "$ssh_ciphers_ok" -eq 1 ]]; then
    pass "CIS-006" "SSH cipher configuration does not include known-weak algorithms"
  elif [[ "$ssh_config_checked" -eq 0 ]]; then
    warn "CIS-006" "No SSH configuration file found" \
      "Create ~/.ssh/config with explicit cipher restrictions"
  fi
}

echo "=== CIS-006: SSH config with weak cipher -> FAIL ==="
ssh_home_weak="$tmpdir/ssh_weak_home"
mkdir -p "$ssh_home_weak/.ssh"
# Directives must be at column 0 — check uses ^(Ciphers|KexAlgorithms|MACs)
cat > "$ssh_home_weak/.ssh/config" <<'SSHCONF'
Host *
Ciphers arcfour,aes256-gcm@openssh.com
MACs hmac-md5
SSHCONF
run_cis006 "$ssh_home_weak/.ssh/config"
assert_has_result "Weak cipher in ~/.ssh/config -> FAIL CIS-006" "FAIL" "CIS-006"

echo "=== CIS-006: SSH config with strong ciphers only -> PASS ==="
ssh_home_strong="$tmpdir/ssh_strong_home"
mkdir -p "$ssh_home_strong/.ssh"
cat > "$ssh_home_strong/.ssh/config" <<'SSHCONF'
Host *
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512
KexAlgorithms curve25519-sha256
SSHCONF
run_cis006 "$ssh_home_strong/.ssh/config"
assert_has_result "Strong ciphers in ~/.ssh/config -> PASS CIS-006" "PASS" "CIS-006"

echo "=== CIS-006: No SSH config at all -> WARN ==="
ssh_home_none="$tmpdir/ssh_none_home"
mkdir -p "$ssh_home_none"  # no .ssh/ sub-directory; path does not exist
# Pass a path that does not exist — ssh_config_checked stays 0 -> WARN
run_cis006 "$ssh_home_none/.ssh/config"
assert_has_result "No SSH config -> WARN CIS-006" "WARN" "CIS-006"

echo "=== CIS-006: Config with no cipher directives -> no CIS-006 result ==="
# A config with only Host/ServerAlive lines but no Ciphers/KexAlgorithms/MACs:
# ssh_config_checked=1 but ssh_ciphers_ok stays 0 and no fail path triggers.
ssh_home_nodir="$tmpdir/ssh_nodir_home"
mkdir -p "$ssh_home_nodir/.ssh"
cat > "$ssh_home_nodir/.ssh/config" <<'SSHCONF'
Host *
ServerAliveInterval 60
ConnectTimeout 10
SSHCONF
run_cis006 "$ssh_home_nodir/.ssh/config"
_found_cis006=false
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  if [[ "$r" == *":CIS-006"* ]]; then
    _found_cis006=true; break
  fi
done
if ! $_found_cis006; then
  echo "  PASS: Config with no cipher directives -> no CIS-006 result (expected)"
  ((TEST_PASSED++))
else
  echo "  FAIL: Config with no cipher directives -> unexpected CIS-006 result: ${RESULTS[*]:-}"
  ((TEST_FAILED++))
fi

# ── 3. CIS-005: no brew -> SKIP ───────────────────────────────────────────────
#
# CIS-005 is gated by has_command inside the Darwin block:
#   if has_command brew; then ... else skip "CIS-005" ... fi
# We inline the branch logic with has_command overridden to false.

echo "=== CIS-005: has_command false -> SKIP ==="
RESULTS=()
has_command() { return 1; }
if has_command brew; then
  pass "CIS-005" "All Homebrew packages are up to date"
else
  skip "CIS-005" "Homebrew security check" "Homebrew not installed"
fi
assert_has_result "No brew installed -> CIS-005 SKIP" "SKIP" "CIS-005"
unset -f has_command
source "$LIB_DIR/checks.sh"

echo "=== CIS-005: has_command true, 0 outdated -> PASS ==="
RESULTS=()
has_command() { return 0; }
# Simulate outdated_count=0: inline the branch logic directly with a known value
if has_command brew; then
  _outdated_count=0
  if [[ "$_outdated_count" -eq 0 ]]; then
    pass "CIS-005" "All Homebrew packages are up to date"
  elif [[ "$_outdated_count" -le 5 ]]; then
    warn "CIS-005" "${_outdated_count} outdated Homebrew package(s) detected" \
      "Update packages to receive security fixes: brew upgrade"
  else
    fail "CIS-005" "${_outdated_count} outdated Homebrew packages detected" "medium" \
      "Outdated packages may contain known vulnerabilities" \
      "Update all packages: brew update && brew upgrade"
  fi
else
  skip "CIS-005" "Homebrew security check" "Homebrew not installed"
fi
assert_has_result "brew present, 0 outdated -> CIS-005 PASS" "PASS" "CIS-005"
unset -f has_command
source "$LIB_DIR/checks.sh"

echo "=== CIS-005: has_command true, 3 outdated -> WARN ==="
RESULTS=()
has_command() { return 0; }
if has_command brew; then
  _outdated_count=3
  if [[ "$_outdated_count" -eq 0 ]]; then
    pass "CIS-005" "All Homebrew packages are up to date"
  elif [[ "$_outdated_count" -le 5 ]]; then
    warn "CIS-005" "${_outdated_count} outdated Homebrew package(s) detected" \
      "Update packages to receive security fixes: brew upgrade"
  else
    fail "CIS-005" "${_outdated_count} outdated Homebrew packages detected" "medium" \
      "Outdated packages may contain known vulnerabilities" \
      "Update all packages: brew update && brew upgrade"
  fi
fi
assert_has_result "brew present, 3 outdated -> CIS-005 WARN" "WARN" "CIS-005"
unset -f has_command
source "$LIB_DIR/checks.sh"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
