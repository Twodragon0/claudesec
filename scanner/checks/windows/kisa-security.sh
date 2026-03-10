#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Windows: KISA Security Checks
# Based on KISA 주요정보통신기반시설 기술적 취약점 분석·평가 (W-01~W-84)
# ============================================================================

# All checks require Windows — skip everything on non-Windows systems
if [[ "$(uname -s)" != *"MINGW"* && "$(uname -s)" != *"MSYS"* && "$(uname -s)" != *"CYGWIN"* && -z "${SYSTEMROOT:-}" ]]; then
  skip "WIN-001" "Administrator account renamed (KISA W-01)" "Not running on Windows"
  skip "WIN-002" "Guest account disabled (KISA W-02)" "Not running on Windows"
  skip "WIN-003" "Account lockout threshold (KISA W-04)" "Not running on Windows"
  skip "WIN-004" "Password complexity enabled (KISA W-48)" "Not running on Windows"
  skip "WIN-005" "Minimum password length (KISA W-49)" "Not running on Windows"
  skip "WIN-006" "Password maximum age (KISA W-50)" "Not running on Windows"
  skip "WIN-007" "Password minimum age (KISA W-51)" "Not running on Windows"
  skip "WIN-008" "Blank password restriction (KISA W-56)" "Not running on Windows"
  skip "WIN-009" "Windows Firewall enabled (KISA PC-11)" "Not running on Windows"
  skip "WIN-010" "Screen saver password (KISA W-06/PC-12)" "Not running on Windows"
  skip "WIN-011" "Remote Desktop NLA (KISA W-15)" "Not running on Windows"
  skip "WIN-012" "Audit policy enabled (KISA W-34)" "Not running on Windows"
  skip "WIN-013" "Windows Update enabled (KISA W-32)" "Not running on Windows"
  skip "WIN-014" "Shared folder access control (KISA W-09)" "Not running on Windows"
  skip "WIN-015" "Anonymous SID enumeration (KISA W-12)" "Not running on Windows"
  skip "WIN-016" "Unnecessary services disabled (KISA W-10)" "Not running on Windows"
  skip "WIN-017" "Antivirus installed (KISA W-36)" "Not running on Windows"
  skip "WIN-018" "SMBv1 disabled (KISA W-72)" "Not running on Windows"
  skip "WIN-019" "UAC enabled (KISA W-73)" "Not running on Windows"
  skip "WIN-020" "Windows Defender active (KISA W-37)" "Not running on Windows"
  return 0 2>/dev/null || exit 0
fi

# ---------------------------------------------------------------------------
# Helper: Run PowerShell command and capture output
# ---------------------------------------------------------------------------
ps_cmd() {
  powershell.exe -NoProfile -NonInteractive -Command "$1" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Account Management (KISA W-01~W-08, W-46~W-57)
# ---------------------------------------------------------------------------

# WIN-001: Administrator account rename (KISA W-01)
# Check if default 'Administrator' account has been renamed
admin_check=$(ps_cmd "Get-LocalUser | Where-Object { \$_.Name -eq 'Administrator' -and \$_.Enabled -eq \$true } | Select-Object -ExpandProperty Name" | tr -d '\r')
if [[ -z "$admin_check" ]]; then
  pass "WIN-001" "Default Administrator account is renamed or disabled (KISA W-01)"
else
  fail "WIN-001" "Default Administrator account is active and not renamed (KISA W-01)" "high" \
    "The default Administrator account is a common attack target" \
    "Rename: Rename-LocalUser -Name Administrator -NewName <NewName>"
fi

# WIN-002: Guest account disabled (KISA W-02)
guest_check=$(ps_cmd "Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled" | tr -d '\r')
if [[ "$guest_check" == "False" || -z "$guest_check" ]]; then
  pass "WIN-002" "Guest account is disabled (KISA W-02)"
else
  fail "WIN-002" "Guest account is enabled (KISA W-02)" "high" \
    "Guest account allows anonymous access to the system" \
    "Disable: Disable-LocalUser -Name Guest"
fi

# WIN-003: Account lockout threshold (KISA W-04)
lockout=$(ps_cmd "net accounts | Select-String 'Lockout threshold'" | tr -d '\r')
lockout_val=$(echo "$lockout" | grep -oE '[0-9]+' || echo "0")
if [[ -n "$lockout_val" && "$lockout_val" -gt 0 && "$lockout_val" -le 5 ]]; then
  pass "WIN-003" "Account lockout threshold is set to ${lockout_val} attempts (KISA W-04)"
elif [[ -n "$lockout_val" && "$lockout_val" -gt 5 ]]; then
  warn "WIN-003" "Account lockout threshold is ${lockout_val} (recommended: ≤5) (KISA W-04)" \
    "Set: net accounts /lockoutthreshold:5"
else
  fail "WIN-003" "Account lockout is not configured (KISA W-04)" "high" \
    "Without lockout, brute-force attacks are unrestricted" \
    "Set threshold: net accounts /lockoutthreshold:5"
fi

# WIN-004: Password complexity enabled (KISA W-48)
pw_complex=$(ps_cmd "secedit /export /cfg \$env:TEMP\\secpol.cfg /quiet; Select-String 'PasswordComplexity' \$env:TEMP\\secpol.cfg" | tr -d '\r')
if echo "$pw_complex" | grep -q '= 1'; then
  pass "WIN-004" "Password complexity requirements enabled (KISA W-48)"
else
  fail "WIN-004" "Password complexity requirements not enabled (KISA W-48)" "high" \
    "Weak passwords are susceptible to dictionary and brute-force attacks" \
    "Enable via Local Security Policy > Account Policies > Password Policy"
fi

# WIN-005: Minimum password length (KISA W-49)
pw_len=$(ps_cmd "net accounts | Select-String 'Minimum password length'" | tr -d '\r')
pw_len_val=$(echo "$pw_len" | grep -oE '[0-9]+' || echo "0")
if [[ -n "$pw_len_val" && "$pw_len_val" -ge 8 ]]; then
  pass "WIN-005" "Minimum password length is ${pw_len_val} chars (KISA W-49)"
elif [[ -n "$pw_len_val" && "$pw_len_val" -gt 0 ]]; then
  warn "WIN-005" "Minimum password length is ${pw_len_val} (recommended: ≥8) (KISA W-49)" \
    "Set: net accounts /minpwlen:8"
else
  fail "WIN-005" "No minimum password length configured (KISA W-49)" "high" \
    "Short passwords are easily cracked" \
    "Set minimum: net accounts /minpwlen:8"
fi

# WIN-006: Maximum password age (KISA W-50)
pw_max=$(ps_cmd "net accounts | Select-String 'Maximum password age'" | tr -d '\r')
pw_max_val=$(echo "$pw_max" | grep -oE '[0-9]+' || echo "0")
if [[ -n "$pw_max_val" && "$pw_max_val" -le 90 && "$pw_max_val" -gt 0 ]]; then
  pass "WIN-006" "Maximum password age is ${pw_max_val} days (KISA W-50)"
else
  fail "WIN-006" "Maximum password age is not set or too long (KISA W-50)" "medium" \
    "Passwords should be rotated periodically" \
    "Set: net accounts /maxpwage:90"
fi

# WIN-007: Minimum password age (KISA W-51)
pw_min=$(ps_cmd "net accounts | Select-String 'Minimum password age'" | tr -d '\r')
pw_min_val=$(echo "$pw_min" | grep -oE '[0-9]+' || echo "0")
if [[ -n "$pw_min_val" && "$pw_min_val" -ge 1 ]]; then
  pass "WIN-007" "Minimum password age is ${pw_min_val} day(s) (KISA W-51)"
else
  warn "WIN-007" "Minimum password age is 0 days (KISA W-51)" \
    "Set to at least 1 day: net accounts /minpwage:1"
fi

# WIN-008: Restrict blank passwords to console only (KISA W-56)
blank_pw=$(ps_cmd "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LimitBlankPasswordUse' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LimitBlankPasswordUse" | tr -d '\r')
if [[ "$blank_pw" == "1" ]]; then
  pass "WIN-008" "Blank password remote login is restricted (KISA W-56)"
else
  fail "WIN-008" "Blank passwords can be used for remote login (KISA W-56)" "critical" \
    "Accounts with blank passwords can be exploited remotely" \
    "Set registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse = 1"
fi

# ---------------------------------------------------------------------------
# Network & Service Management (KISA W-09~W-31, W-58~W-68)
# ---------------------------------------------------------------------------

# WIN-009: Windows Firewall enabled (KISA PC-11)
fw_status=$(ps_cmd "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled" | tr -d '\r' | head -1)
if [[ "$fw_status" == "True" ]]; then
  pass "WIN-009" "Windows Firewall is enabled (KISA PC-11)"
else
  fail "WIN-009" "Windows Firewall is disabled (KISA PC-11)" "critical" \
    "The firewall is the first line of defense against network attacks" \
    "Enable: Set-NetFirewallProfile -All -Enabled True"
fi

# WIN-010: Screen saver with password (KISA W-06/PC-12)
ss_active=$(ps_cmd "Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaveActive' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaveActive" | tr -d '\r')
ss_secure=$(ps_cmd "Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScreenSaverIsSecure" | tr -d '\r')
if [[ "$ss_active" == "1" && "$ss_secure" == "1" ]]; then
  pass "WIN-010" "Screen saver with password protection is enabled (KISA W-06)"
else
  fail "WIN-010" "Screen saver password protection is not configured (KISA W-06)" "medium" \
    "Unattended sessions can be accessed without authentication" \
    "Enable screen saver lock via Group Policy or registry"
fi

# WIN-011: Remote Desktop with NLA (KISA W-15)
nla_check=$(ps_cmd "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserAuthentication" | tr -d '\r')
rdp_enabled=$(ps_cmd "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty fDenyTSConnections" | tr -d '\r')
if [[ "$rdp_enabled" == "1" ]]; then
  pass "WIN-011" "Remote Desktop is disabled (KISA W-15)"
elif [[ "$nla_check" == "1" ]]; then
  pass "WIN-011" "Remote Desktop requires Network Level Authentication (KISA W-15)"
else
  fail "WIN-011" "Remote Desktop enabled without NLA (KISA W-15)" "high" \
    "Without NLA, attackers can interact with the login screen before authenticating" \
    "Enable NLA: System Properties > Remote > Require NLA"
fi

# WIN-012: Anonymous SID enumeration restricted (KISA W-12)
anon_sid=$(ps_cmd "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RestrictAnonymousSAM" | tr -d '\r')
if [[ "$anon_sid" == "1" ]]; then
  pass "WIN-012" "Anonymous SID/Name enumeration is restricted (KISA W-12)"
else
  fail "WIN-012" "Anonymous SID/Name enumeration is allowed (KISA W-12)" "medium" \
    "Attackers can enumerate user accounts without authentication" \
    "Set registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM = 1"
fi

# WIN-013: Shared folder audit (KISA W-09)
shares=$(ps_cmd "Get-SmbShare | Where-Object { \$_.Name -notlike '*\$' } | Measure-Object | Select-Object -ExpandProperty Count" | tr -d '\r')
if [[ -n "$shares" && "$shares" -eq 0 ]]; then
  pass "WIN-013" "No non-default shared folders found (KISA W-09)"
else
  warn "WIN-013" "Found ${shares:-unknown} shared folder(s) — review access controls (KISA W-09)" \
    "Audit shares: Get-SmbShare | Select Name,Path,Description"
fi

# ---------------------------------------------------------------------------
# Service Management (KISA W-10, W-16~W-31)
# ---------------------------------------------------------------------------

# WIN-014: Unnecessary services check (KISA W-10)
risky_services=("Telnet" "SNMP" "RemoteRegistry" "Fax" "XblGameSave" "XboxNetApiSvc")
risky_running=0
for svc in "${risky_services[@]}"; do
  svc_status=$(ps_cmd "Get-Service -Name '$svc' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status" | tr -d '\r')
  if [[ "$svc_status" == "Running" ]]; then
    risky_running=$((risky_running + 1))
  fi
done
if [[ $risky_running -eq 0 ]]; then
  pass "WIN-014" "No unnecessary risky services are running (KISA W-10)"
else
  fail "WIN-014" "${risky_running} unnecessary service(s) running (KISA W-10)" "medium" \
    "Services like Telnet, SNMP, RemoteRegistry increase attack surface" \
    "Disable: Stop-Service <name>; Set-Service <name> -StartupType Disabled"
fi

# WIN-015: SMBv1 disabled (KISA W-72)
smbv1=$(ps_cmd "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol" | tr -d '\r')
if [[ "$smbv1" == "False" ]]; then
  pass "WIN-015" "SMBv1 protocol is disabled (KISA W-72)"
elif [[ "$smbv1" == "True" ]]; then
  fail "WIN-015" "SMBv1 protocol is enabled (KISA W-72)" "critical" \
    "SMBv1 is vulnerable to EternalBlue (WannaCry, NotPetya) exploits" \
    "Disable: Set-SmbServerConfiguration -EnableSMB1Protocol \$false -Force"
else
  warn "WIN-015" "SMBv1 status could not be determined (KISA W-72)"
fi

# ---------------------------------------------------------------------------
# Patch & Update Management (KISA W-32~W-33)
# ---------------------------------------------------------------------------

# WIN-016: Windows Update enabled (KISA W-32)
wu_status=$(ps_cmd "(New-Object -ComObject Microsoft.Update.AutoUpdate).ServiceEnabled" | tr -d '\r')
if [[ "$wu_status" == "True" ]]; then
  pass "WIN-016" "Windows Update service is enabled (KISA W-32)"
else
  fail "WIN-016" "Windows Update service is disabled (KISA W-32)" "high" \
    "Without automatic updates, known vulnerabilities remain unpatched" \
    "Enable Windows Update via Settings > Update & Security"
fi

# ---------------------------------------------------------------------------
# Log Management (KISA W-34~W-35, W-70~W-71)
# ---------------------------------------------------------------------------

# WIN-017: Audit policy configured (KISA W-34)
audit_logon=$(ps_cmd "auditpol /get /category:'Logon/Logoff' 2>&1" | tr -d '\r')
if echo "$audit_logon" | grep -qiE 'Success|Failure'; then
  pass "WIN-017" "Audit policy for logon events is configured (KISA W-34)"
else
  fail "WIN-017" "Audit policy for logon events is not configured (KISA W-34)" "high" \
    "Without audit logging, security incidents cannot be detected or investigated" \
    "Configure: auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable"
fi

# ---------------------------------------------------------------------------
# Security Management (KISA W-36~W-45, W-72~W-82)
# ---------------------------------------------------------------------------

# WIN-018: Antivirus / Windows Defender active (KISA W-36/W-37)
defender=$(ps_cmd "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RealTimeProtectionEnabled" | tr -d '\r')
if [[ "$defender" == "True" ]]; then
  pass "WIN-018" "Windows Defender real-time protection is active (KISA W-37)"
else
  av_installed=$(ps_cmd "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count" | tr -d '\r')
  if [[ -n "$av_installed" && "$av_installed" -gt 0 ]]; then
    warn "WIN-018" "Windows Defender is not active but ${av_installed} AV product(s) found (KISA W-36)" \
      "Verify third-party AV is running and up-to-date"
  else
    fail "WIN-018" "No active antivirus protection detected (KISA W-36)" "critical" \
      "Systems without antivirus are vulnerable to malware" \
      "Enable: Set-MpPreference -DisableRealtimeMonitoring \$false"
  fi
fi

# WIN-019: UAC enabled (KISA W-73)
uac_check=$(ps_cmd "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableLUA" | tr -d '\r')
if [[ "$uac_check" == "1" ]]; then
  pass "WIN-019" "User Account Control (UAC) is enabled (KISA W-73)"
else
  fail "WIN-019" "User Account Control (UAC) is disabled (KISA W-73)" "critical" \
    "Without UAC, all programs run with full admin privileges" \
    "Enable: Set-ItemProperty -Path HKLM:\\SOFTWARE\\...\\Policies\\System -Name EnableLUA -Value 1"
fi

# WIN-020: Windows Defender definitions up to date (KISA W-37)
def_age=$(ps_cmd "
  \$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
  if (\$status) { ((Get-Date) - \$status.AntivirusSignatureLastUpdated).Days }
" | tr -d '\r')
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
