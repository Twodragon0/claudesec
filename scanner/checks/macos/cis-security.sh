#!/usr/bin/env bash
# ClaudeSec — macOS: CIS Benchmark Security Checks

# All checks require macOS — skip everything on non-Darwin systems
if [[ "$(uname)" != "Darwin" ]]; then
  skip "MAC-001" "FileVault disk encryption" "Not running on macOS"
  skip "MAC-002" "Firewall enabled" "Not running on macOS"
  skip "MAC-003" "System Integrity Protection" "Not running on macOS"
  skip "MAC-004" "Gatekeeper enabled" "Not running on macOS"
  skip "MAC-005" "Automatic software updates" "Not running on macOS"
  skip "MAC-006" "Screen lock configured" "Not running on macOS"
  skip "MAC-007" "Remote login (SSH) disabled" "Not running on macOS"
  skip "MAC-008" "AirDrop restricted" "Not running on macOS"
  skip "MAC-009" "Guest account disabled" "Not running on macOS"
  skip "MAC-010" "File extensions visible" "Not running on macOS"
  skip "CIS-001" "Password complexity policy" "Not running on macOS"
  skip "CIS-002" "Audit logging (auditd)" "Not running on macOS"
  skip "CIS-003" "Secure Keyboard Entry in Terminal" "Not running on macOS"
  skip "CIS-004" "No world-writable files in /System" "Not running on macOS"
  skip "CIS-005" "Homebrew security check" "Not running on macOS"
  skip "CIS-006" "SSH strong ciphers configured" "Not running on macOS"
  skip "CIS-007" "Core dumps restricted" "Not running on macOS"
  skip "CIS-008" "NTP time sync enabled" "Not running on macOS"
  skip "CIS-009" "Bluetooth usage policy" "Not running on macOS"
  skip "CIS-010" "Content caching disabled" "Not running on macOS"
  return 0 2>/dev/null || exit 0
fi

# ---------------------------------------------------------------------------
# macOS Security Checks (MAC-0xx)
# KISA PC-series mapping:
#   MAC-001 (FileVault)      → PC-03 (디스크 암호화)
#   MAC-002 (Firewall)       → PC-11 (방화벽 활성화)
#   MAC-003 (SIP)            → PC-18 (시스템 무결성 보호)
#   MAC-005 (Auto updates)   → PC-16 (보안 업데이트)
#   MAC-006 (Screen lock)    → PC-12 (화면보호기 잠금)
#   MAC-009 (Guest account)  → PC-02 (Guest 계정 비활성화)
#   CIS-001 (Password)       → PC-04 (패스워드 복잡성)
#   CIS-002 (Audit log)      → PC-15 (로깅 설정)
# ---------------------------------------------------------------------------

# MAC-001: FileVault disk encryption enabled
fv_status=$(fdesetup status 2>/dev/null)
if echo "$fv_status" | grep -q "FileVault is On"; then
  pass "MAC-001" "FileVault disk encryption is enabled"
elif echo "$fv_status" | grep -q "FileVault is Off"; then
  fail "MAC-001" "FileVault disk encryption is disabled" "critical" \
    "Without FileVault, data on disk is accessible if the device is lost or stolen" \
    "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On"
else
  warn "MAC-001" "FileVault status could not be determined" \
    "Run 'sudo fdesetup status' to check FileVault state"
fi

# MAC-002: Firewall enabled
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if echo "$fw_state" | grep -q "enabled"; then
  pass "MAC-002" "macOS Application Firewall is enabled"
else
  fail "MAC-002" "macOS Application Firewall is disabled" "high" \
    "The application firewall blocks unauthorized inbound connections" \
    "Enable firewall: System Settings > Network > Firewall > Turn On"
fi

# MAC-003: SIP (System Integrity Protection) enabled
sip_status=$(csrutil status 2>/dev/null)
if echo "$sip_status" | grep -q "enabled"; then
  pass "MAC-003" "System Integrity Protection (SIP) is enabled"
elif echo "$sip_status" | grep -q "disabled"; then
  fail "MAC-003" "System Integrity Protection (SIP) is disabled" "critical" \
    "SIP prevents malicious software from modifying protected files and processes" \
    "Boot into Recovery Mode (hold Cmd+R), open Terminal, run: csrutil enable"
else
  warn "MAC-003" "SIP status could not be determined" \
    "Run 'csrutil status' to verify SIP state"
fi

# MAC-004: Gatekeeper enabled
gk_status=$(spctl --status 2>/dev/null)
if echo "$gk_status" | grep -q "assessments enabled"; then
  pass "MAC-004" "Gatekeeper is enabled"
else
  fail "MAC-004" "Gatekeeper is disabled" "high" \
    "Gatekeeper verifies that downloaded apps are from identified developers" \
    "Enable Gatekeeper: sudo spctl --master-enable"
fi

# MAC-005: Automatic software updates enabled
au_enabled=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
if [[ "$au_enabled" == "1" ]]; then
  pass "MAC-005" "Automatic software update checks are enabled"
else
  fail "MAC-005" "Automatic software update checks are disabled" "medium" \
    "Disabling update checks delays security patches from being applied" \
    "Enable: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"
fi

# MAC-006: Screen lock configured (askForPassword = 1)
ask_password=$(defaults read com.apple.screensaver askForPassword 2>/dev/null)
if [[ "$ask_password" == "1" ]]; then
  ask_delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)
  if [[ -n "$ask_delay" && "$ask_delay" -le 60 ]]; then
    pass "MAC-006" "Screen lock requires password within ${ask_delay}s"
  else
    warn "MAC-006" "Screen lock password delay is too long or unset" \
      "Set delay to 60 seconds or less: defaults write com.apple.screensaver askForPasswordDelay -int 5"
  fi
else
  fail "MAC-006" "Screen lock does not require password" "high" \
    "Without a screen lock password, physical access grants full account access" \
    "Enable: defaults write com.apple.screensaver askForPassword -bool true"
fi

# MAC-007: Remote login (SSH) disabled
ssh_status=$(systemsetup -getremotelogin 2>/dev/null)
if echo "$ssh_status" | grep -q "Remote Login: Off"; then
  pass "MAC-007" "Remote login (SSH) is disabled"
elif echo "$ssh_status" | grep -q "Remote Login: On"; then
  warn "MAC-007" "Remote login (SSH) is enabled" \
    "SSH increases the attack surface; disable it if not actively needed. Run: sudo systemsetup -setremotelogin off"
else
  warn "MAC-007" "Remote login status could not be determined" \
    "Run 'sudo systemsetup -getremotelogin' to check SSH state"
fi

# MAC-008: AirDrop set to contacts only or disabled
airdrop_mode=$(defaults read com.apple.sharingd DiscoverableMode 2>/dev/null)
if [[ "$airdrop_mode" == "Contacts Only" || "$airdrop_mode" == "Off" ]]; then
  pass "MAC-008" "AirDrop is restricted (${airdrop_mode})"
elif [[ "$airdrop_mode" == "Everyone" ]]; then
  fail "MAC-008" "AirDrop is set to Everyone" "medium" \
    "AirDrop set to Everyone allows strangers to send files without prior approval" \
    "Set AirDrop to Contacts Only: Finder > AirDrop > Allow me to be discovered by: Contacts Only"
else
  warn "MAC-008" "AirDrop discoverability mode could not be determined" \
    "Check AirDrop settings in Finder or Control Center"
fi

# MAC-009: Guest account disabled
guest_enabled=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [[ "$guest_enabled" == "0" || "$guest_enabled" == "" ]]; then
  pass "MAC-009" "Guest account is disabled"
elif [[ "$guest_enabled" == "1" ]]; then
  fail "MAC-009" "Guest account is enabled" "medium" \
    "The Guest account allows unauthenticated local access to the system" \
    "Disable: System Settings > Users & Groups > Guest User > Allow guests to log in: Off"
else
  warn "MAC-009" "Guest account status could not be determined" \
    "Run 'defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled'"
fi

# MAC-010: File extensions shown (helps detect masqueraded files)
show_extensions=$(defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null)
if [[ "$show_extensions" == "1" ]]; then
  pass "MAC-010" "All file extensions are visible in Finder"
else
  warn "MAC-010" "File extensions are hidden in Finder" \
    "Hiding extensions can mask malicious files (e.g., 'invoice.pdf.app'); enable with: defaults write NSGlobalDomain AppleShowAllExtensions -bool true"
fi

# ---------------------------------------------------------------------------
# CIS Benchmark Priority Checks (CIS-0xx)
# ---------------------------------------------------------------------------

# CIS-001: Password complexity policy
pw_policy=$(pwpolicy -getaccountpolicies 2>/dev/null || true)
if echo "$pw_policy" | grep -qiE "minChars|minimumLength|requiresAlpha|requiresNumeric"; then
  pass "CIS-001" "Password complexity policy is configured"
else
  warn "CIS-001" "No explicit password complexity policy detected" \
    "Configure a password policy via pwpolicy or MDM. CIS recommends minimum 15 characters with complexity requirements."
fi

# CIS-002: Audit logging (auditd) enabled
if launchctl list 2>/dev/null | grep -q "com.apple.auditd"; then
  pass "CIS-002" "Audit logging daemon (auditd) is running"
else
  fail "CIS-002" "Audit logging daemon (auditd) is not running" "high" \
    "Without audit logging, security events cannot be investigated or correlated" \
    "Enable: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
fi

# CIS-003: Secure Keyboard Entry in Terminal
secure_kbd=$(defaults read -app Terminal SecureKeyboardEntry 2>/dev/null)
if [[ "$secure_kbd" == "1" ]]; then
  pass "CIS-003" "Secure Keyboard Entry is enabled in Terminal"
else
  warn "CIS-003" "Secure Keyboard Entry is not enabled in Terminal" \
    "Without Secure Keyboard Entry, other apps may intercept keystrokes; enable via Terminal > Settings > Secure Keyboard Entry"
fi

# CIS-004: No world-writable files in /System
# Exclude known-legitimate macOS world-writable paths:
#   /System/Volumes/         — APFS volume mount points (Preboot, Update, Data)
#   /System/Library/AssetsV2 — system asset update staging (SIP-protected)
# On SIP-enabled systems /System/Library is protected regardless of permission bits.
# Note: -not -path uses literal matching; symlinks resolving to these paths are already excluded by -not -type l
ww_count=$(find /System -maxdepth 4 -perm -0002 -not -type l \
  -not -path '/System/Volumes/*' \
  -not -path '/System/Library/AssetsV2/*' \
  2>/dev/null | wc -l | tr -d ' ')
if [[ "$ww_count" -eq 0 ]]; then
  pass "CIS-004" "No world-writable files found in /System (SIP-managed paths excluded)"
else
  fail "CIS-004" "World-writable files found in /System (${ww_count} files)" "high" \
    "World-writable system files can be modified by any user, enabling privilege escalation" \
    "Review with: sudo find /System -maxdepth 4 -perm -0002 -not -type l -not -path '/System/Volumes/*'"
fi

# CIS-005: Homebrew security (outdated packages)
if has_command brew; then
  outdated_count=$(brew outdated 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$outdated_count" -eq 0 ]]; then
    pass "CIS-005" "All Homebrew packages are up to date"
  elif [[ "$outdated_count" -le 5 ]]; then
    warn "CIS-005" "${outdated_count} outdated Homebrew package(s) detected" \
      "Update packages to receive security fixes: brew upgrade"
  else
    fail "CIS-005" "${outdated_count} outdated Homebrew packages detected" "medium" \
      "Outdated packages may contain known vulnerabilities" \
      "Update all packages: brew update && brew upgrade"
  fi
else
  skip "CIS-005" "Homebrew security check" "Homebrew not installed"
fi

# CIS-006: SSH strong ciphers configured
ssh_config_checked=0
ssh_ciphers_ok=0
for cfg in "$HOME/.ssh/config" /etc/ssh/sshd_config /etc/ssh/ssh_config; do
  if [[ -f "$cfg" ]]; then
    ssh_config_checked=1
    if grep -qiE "^(Ciphers|KexAlgorithms|MACs)" "$cfg" 2>/dev/null; then
      if grep -qiE "arcfour|des|rc4|md5|sha1$" "$cfg" 2>/dev/null; then
        fail "CIS-006" "Weak ciphers or MACs found in SSH config (${cfg})" "high" \
          "Weak ciphers (arcfour, DES, RC4) and deprecated MACs (MD5, SHA-1) expose SSH sessions to attack" \
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
    "Create ~/.ssh/config with explicit cipher restrictions for outbound connections"
fi

# CIS-007: Core dumps restricted
core_limit=$(launchctl limit core 2>/dev/null | awk '{print $2}')
sysctl_core=$(sysctl kern.coredump 2>/dev/null | awk '{print $2}')
if [[ "$sysctl_core" == "0" || "$core_limit" == "0" ]]; then
  pass "CIS-007" "Core dumps are restricted"
else
  warn "CIS-007" "Core dumps are not explicitly restricted" \
    "Core dumps may expose sensitive memory contents; restrict with: sudo launchctl limit core 0 0"
fi

# CIS-008: NTP time sync enabled
ntp_status=$(systemsetup -getnetworktimeserver 2>/dev/null)
sntp_running=$(launchctl list 2>/dev/null | grep -E "timed|ntpd")
if echo "$ntp_status" | grep -qiE "Network Time Server:" && [[ -n "$sntp_running" ]]; then
  pass "CIS-008" "NTP time synchronization is enabled"
elif [[ -n "$sntp_running" ]]; then
  pass "CIS-008" "Time daemon (timed) is running"
else
  fail "CIS-008" "NTP time synchronization does not appear to be active" "medium" \
    "Inaccurate system time breaks certificate validation and audit log correlation" \
    "Enable: sudo systemsetup -setusingnetworktime on"
fi

# CIS-009: Bluetooth off when not in use
bt_power=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
if [[ "$bt_power" == "0" ]]; then
  pass "CIS-009" "Bluetooth is currently powered off"
else
  warn "CIS-009" "Bluetooth is powered on" \
    "Bluetooth increases the wireless attack surface; disable when not in use via Control Center or System Settings > Bluetooth"
fi

# CIS-010: Content caching disabled
cc_status=$(AssetCacheManagerUtil status 2>/dev/null || true)
if echo "$cc_status" | grep -q '"Activated" : true'; then
  warn "CIS-010" "Content caching is enabled" \
    "Content caching stores copies of software updates and app downloads; disable if not required to reduce data exposure: System Settings > General > Sharing > Content Caching > Off"
else
  pass "CIS-010" "Content caching is disabled"
fi
