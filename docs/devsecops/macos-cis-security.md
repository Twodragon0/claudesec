---
title: macOS CIS Security Benchmark Guide
description: macOS hardening based on CIS Apple macOS Benchmark v4.0 — checks, remediation steps, and enterprise MDM guidance
tags: [macos, cis-benchmark, hardening, endpoint-security, mdm, compliance]
---

# macOS CIS Security Benchmark Guide

## Overview

The **CIS Apple macOS Benchmark** (v4.0) is the industry-standard hardening guide for macOS endpoints. Published by the Center for Internet Security, it defines two implementation levels:

| Level | Scope |
|-------|-------|
| **Level 1** | Essential, low-disruption controls suitable for all organisations |
| **Level 2** | Defense-in-depth controls; may impact usability in some environments |

This guide covers the checks implemented in the ClaudeSec `macos` scanner category and provides terminal-based remediation commands for each control.

> **Reference**: [CIS Apple macOS 14.0 Sonoma Benchmark v1.0.0](https://www.cisecurity.org/benchmark/apple_os)

---

## Priority-Ordered Security Hardening Checklist

Work through these controls in order — critical items first.

### Critical Priority

- [ ] `MAC-001` FileVault disk encryption enabled
- [ ] `MAC-003` System Integrity Protection (SIP) enabled
- [ ] `CIS-002` Audit logging (auditd) running

### High Priority

- [ ] `MAC-002` Application Firewall enabled
- [ ] `MAC-004` Gatekeeper enabled
- [ ] `MAC-006` Screen lock requires password
- [ ] `CIS-004` No world-writable files in `/System`
- [ ] `CIS-006` SSH strong ciphers configured

### Medium Priority

- [ ] `MAC-005` Automatic software updates enabled
- [ ] `MAC-007` Remote login (SSH) disabled
- [ ] `MAC-008` AirDrop restricted to Contacts Only
- [ ] `MAC-009` Guest account disabled
- [ ] `CIS-005` Homebrew packages up to date
- [ ] `CIS-008` NTP time sync enabled

### Low / Informational

- [ ] `MAC-010` File extensions visible in Finder
- [ ] `CIS-001` Password complexity policy configured
- [ ] `CIS-003` Secure Keyboard Entry in Terminal enabled
- [ ] `CIS-007` Core dumps restricted
- [ ] `CIS-009` Bluetooth off when not in use
- [ ] `CIS-010` Content caching disabled

---

## MAC-xxx Check Reference

### MAC-001 — FileVault Disk Encryption

**Why it matters**: Without full-disk encryption, a stolen or lost Mac exposes all data at rest. An attacker with physical access can bypass the login password entirely by booting from an external drive.

**Check**:

```bash
fdesetup status
# Expected: "FileVault is On."
```

**Remediation**:

```bash
# Via GUI: System Settings > Privacy & Security > FileVault > Turn On FileVault
# Via CLI (initiates the process — user must log out/in to complete):
sudo fdesetup enable
```

**Notes**: Encryption applies per-volume. Store the recovery key in your password manager or escrow it via MDM. Enterprise deployments should use institutional recovery keys.

---

### MAC-002 — Application Firewall

**Why it matters**: The macOS Application Firewall blocks incoming connections to applications that have not been explicitly permitted. It limits network exposure without requiring manual `pf` rule management.

**Check**:

```bash
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
# Expected: "Firewall is enabled. (State = 1)"
```

**Remediation**:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
# Enable stealth mode (drops probes without replying):
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

---

### MAC-003 — System Integrity Protection (SIP)

**Why it matters**: SIP (introduced in OS X El Capitan) restricts the root user from modifying protected system files, directories, and processes. Disabling it is a prerequisite for many macOS rootkits.

**Check**:

```bash
csrutil status
# Expected: "System Integrity Protection status: enabled."
```

**Remediation** (re-enabling after it has been disabled):

```bash
# 1. Restart into Recovery Mode: hold Cmd+R during boot (Intel) or hold Power (Apple Silicon)
# 2. Open Terminal from the Utilities menu
csrutil enable
# 3. Restart normally
```

**Note**: SIP can only be modified from Recovery Mode — this is by design.

---

### MAC-004 — Gatekeeper

**Why it matters**: Gatekeeper checks the digital signature and notarisation status of downloaded applications before allowing them to run. It prevents trivially-distributed malware from executing.

**Check**:

```bash
spctl --status
# Expected: "assessments enabled"
```

**Remediation**:

```bash
sudo spctl --master-enable
# Verify:
spctl --status
```

---

### MAC-005 — Automatic Software Updates

**Why it matters**: Timely patching is the single highest-ROI security control. CIS Benchmark requires that macOS automatically checks for and installs critical security patches.

**Check**:

```bash
defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
# Expected: 1
```

**Remediation**:

```bash
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
```

---

### MAC-006 — Screen Lock Password

**Why it matters**: A screen lock without a password requirement provides no security. Physical access to an unlocked screen is equivalent to full account access.

**Check**:

```bash
defaults read com.apple.screensaver askForPassword
# Expected: 1
defaults read com.apple.screensaver askForPasswordDelay
# Expected: 0–60 (seconds)
```

**Remediation**:

```bash
defaults write com.apple.screensaver askForPassword -bool true
defaults write com.apple.screensaver askForPasswordDelay -int 5
# Via System Settings: Lock Screen > Require password after screen saver begins: Immediately
```

---

### MAC-007 — Remote Login (SSH)

**Why it matters**: SSH increases the network attack surface. If SSH is not actively needed for remote administration, it should be disabled to eliminate the exposure entirely.

**Check**:

```bash
sudo systemsetup -getremotelogin
# Expected: "Remote Login: Off"
```

**Remediation**:

```bash
sudo systemsetup -setremotelogin off
# If SSH is required, restrict it:
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/sbin/sshd
# And configure /etc/ssh/sshd_config with:
#   PermitRootLogin no
#   PasswordAuthentication no
#   AllowUsers yourusername
```

---

### MAC-008 — AirDrop Restricted

**Why it matters**: AirDrop set to "Everyone" allows any nearby device to send files without prior approval, enabling social-engineering attacks or unwanted content delivery.

**Check**:

```bash
defaults read com.apple.sharingd DiscoverableMode
# Expected: "Contacts Only" or "Off"
```

**Remediation**:

```bash
# Via GUI: Finder > AirDrop > Allow me to be discovered by: No One / Contacts Only
# Via CLI:
defaults write com.apple.sharingd DiscoverableMode -string "Contacts Only"
```

---

### MAC-009 — Guest Account Disabled

**Why it matters**: The Guest account grants unauthenticated local access to a Safari browser and temporary home directory. This can be abused for local privilege escalation research or data exfiltration.

**Check**:

```bash
defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
# Expected: 0
```

**Remediation**:

```bash
sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
# Verify via: System Settings > Users & Groups > Guest User
```

---

### MAC-010 — File Extensions Visible

**Why it matters**: macOS hides file extensions by default. Attackers exploit this by naming malicious executables `document.pdf.app` — users see only `document.pdf`. Showing extensions removes this deception vector.

**Check**:

```bash
defaults read NSGlobalDomain AppleShowAllExtensions
# Expected: 1
```

**Remediation**:

```bash
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
# Restart Finder to apply:
killall Finder
```

---

## CIS-xxx Check Reference

### CIS-001 — Password Complexity Policy

**Why it matters**: Weak passwords are the leading cause of account compromise. CIS recommends a minimum of 15 characters with uppercase, lowercase, number, and symbol requirements.

**Check**:

```bash
pwpolicy -getaccountpolicies
```

**Remediation**:

```bash
# Set minimum password length (requires admin):
pwpolicy -setaccountpolicies /dev/stdin <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>policyCategoryPasswordContent</key>
  <array>
    <dict>
      <key>policyContent</key>
      <string>policyAttributePassword matches '.{15,}'</string>
      <key>policyIdentifier</key>
      <string>com.example.password.minlength</string>
    </dict>
  </array>
</dict>
</plist>
EOF
```

**Enterprise note**: Manage via MDM password policy profile (Jamf/Intune) rather than `pwpolicy` for consistency across the fleet.

---

### CIS-002 — Audit Logging (auditd)

**Why it matters**: The OpenBSM audit subsystem records privileged operations, authentication events, and file access. Without it, forensic investigation of incidents is severely limited.

**Check**:

```bash
launchctl list | grep auditd
# Expected: com.apple.auditd appears in output
sudo audit -s && echo "auditd running"
```

**Remediation**:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
# Verify audit flags in /etc/security/audit_control:
cat /etc/security/audit_control
```

**Recommended `/etc/security/audit_control` settings**:

```
dir:/var/audit
flags:lo,aa,ad,fd,fm,-all
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:60d
```

---

### CIS-003 — Secure Keyboard Entry in Terminal

**Why it matters**: Without Secure Keyboard Entry, other applications on the system can intercept keystrokes entered in Terminal — including passwords and SSH passphrases.

**Check**:

```bash
defaults read -app Terminal SecureKeyboardEntry
# Expected: 1
```

**Remediation**:

```bash
# Via Terminal menu: Terminal > Secure Keyboard Entry (toggle on)
defaults write -app Terminal SecureKeyboardEntry -bool true
```

**Note**: This applies to Terminal.app only. iTerm2 has an equivalent setting under Preferences > Advanced > Secure Keyboard Entry.

---

### CIS-004 — No World-Writable Files in /System

**Why it matters**: World-writable files in `/System` allow any user to modify system components, enabling trivial privilege escalation or persistent malware installation.

**Check**:

```bash
sudo find /System -maxdepth 4 -perm -0002 -not -type l 2>/dev/null
# Expected: no output
```

**Remediation**:

```bash
# Review each file found and remove world-write permission:
sudo chmod o-w /path/to/file
# If SIP is enabled and files appear, this may indicate a compromise — investigate further
```

---

### CIS-005 — Homebrew Package Security

**Why it matters**: Outdated Homebrew packages frequently contain publicly-disclosed CVEs. Developers often install tools via Homebrew that run with elevated privileges during CI builds.

**Check**:

```bash
brew outdated
brew audit --strict 2>/dev/null | head -20
```

**Remediation**:

```bash
brew update
brew upgrade
# Review deprecation warnings:
brew doctor
```

**Automation**: Add to weekly cron or a pre-commit hook:

```bash
#!/usr/bin/env bash
# ~/.config/periodic/weekly/brew-update
brew update && brew upgrade && brew cleanup
```

---

### CIS-006 — SSH Strong Ciphers

**Why it matters**: Legacy SSH ciphers (arcfour/RC4, DES, CBC-mode AES) are vulnerable to attacks including BEAST, Sweet32, and padding oracle exploits. Modern equivalents have no known weaknesses.

**Check**:

```bash
grep -iE "^(Ciphers|KexAlgorithms|MACs)" ~/.ssh/config /etc/ssh/sshd_config 2>/dev/null
```

**Recommended `~/.ssh/config` hardening**:

```
Host *
  Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
  PasswordAuthentication no
  ServerAliveInterval 60
  ServerAliveCountMax 3
```

---

### CIS-007 — Core Dumps Restricted

**Why it matters**: Core dump files capture the entire memory state of a crashed process, which may include encryption keys, credentials, and session tokens written in plaintext.

**Check**:

```bash
launchctl limit core
# Expected: 0 0
sysctl kern.coredump
# Expected: kern.coredump: 0
```

**Remediation**:

```bash
sudo launchctl limit core 0 0
sudo sysctl -w kern.coredump=0
# Persist across reboots — add to /etc/sysctl.conf:
echo "kern.coredump=0" | sudo tee -a /etc/sysctl.conf
```

---

### CIS-008 — NTP Time Synchronization

**Why it matters**: Accurate system time is critical for TLS certificate validation, Kerberos authentication, and meaningful audit log timestamps. Time drift can cause authentication failures or create gaps in log correlation.

**Check**:

```bash
sudo systemsetup -getnetworktimeserver
launchctl list | grep -E "timed|ntpd"
# Expected: com.apple.timed appears in output
```

**Remediation**:

```bash
sudo systemsetup -setusingnetworktime on
sudo systemsetup -setnetworktimeserver time.apple.com
# Verify:
sntp -t 1 time.apple.com
```

---

### CIS-009 — Bluetooth Usage Policy

**Why it matters**: Bluetooth is a short-range wireless protocol with a history of serious vulnerabilities (BlueBorne, BIAS, BLESA). Disabling it when not in use eliminates this attack surface.

**Check**:

```bash
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState
# Expected: 0 (off)
```

**Remediation**:

```bash
# Via Control Center: click Bluetooth icon > Turn Bluetooth Off
# Via CLI (requires restart of Bluetooth daemon):
sudo defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -int 0
sudo killall -HUP bluetoothd
```

---

### CIS-010 — Content Caching Disabled

**Why it matters**: Content Caching stores copies of Apple software, app updates, and iCloud data for sharing with nearby devices. Unless explicitly needed for an enterprise lab network, it unnecessarily expands local data storage and network exposure.

**Check**:

```bash
AssetCacheManagerUtil status 2>/dev/null | grep Activated
# Expected: "Activated" : false
```

**Remediation**:

```bash
# Via GUI: System Settings > General > Sharing > Content Caching > Off
AssetCacheManagerUtil deactivate
```

---

## Enterprise MDM Considerations

### Jamf Pro

Jamf Pro is the most widely deployed macOS MDM and can enforce all the controls above at scale.

**Key Jamf capabilities for these checks**:

| Control | Jamf Mechanism |
|---------|---------------|
| FileVault (MAC-001) | Disk Encryption configuration profile + escrow |
| Firewall (MAC-002) | Security & Privacy profile payload |
| SIP (MAC-003) | Not manageable via MDM — enforce through policy |
| Gatekeeper (MAC-004) | Security & Privacy payload: `AllowIdentifiedDevelopers` |
| Screen lock (MAC-006) | Passcode payload: `maxInactivity`, `minutesUntilFailedLoginReset` |
| Guest account (MAC-009) | Login Window payload: `GuestEnabled: false` |
| Password policy (CIS-001) | Passcode payload: `minLength`, `requireAlphanumeric`, `minComplexChars` |

**Example Jamf configuration profile snippet** (Passcode payload):

```xml
<key>PayloadType</key>
<string>com.apple.mobiledevicemanagement.PasscodePolicy</string>
<key>minLength</key>
<integer>15</integer>
<key>requireAlphanumeric</key>
<true/>
<key>maxInactivity</key>
<integer>2</integer>
<key>maxPINAgeInDays</key>
<integer>90</integer>
```

### Microsoft Intune

Intune manages macOS via its own MDM channel and supports many of the same profiles.

**Key Intune policy types**:

- **Endpoint Security > Disk Encryption**: FileVault key escrow to Intune
- **Device Configuration > Settings Catalog**: Granular macOS preference domain controls
- **Compliance Policies**: Report non-compliant devices and block conditional access

**Compliance policy example** (targeting FileVault):

```json
{
  "storageRequireEncryption": true,
  "passwordRequired": true,
  "passwordMinimumLength": 15,
  "passwordRequiredType": "alphanumericWithSymbols",
  "osMinimumVersion": "14.0"
}
```

### CIS Benchmarks via MDM

Both Jamf and Intune support importing the CIS macOS Benchmark as a compliance baseline:

- **Jamf**: Use the [CIS-CAT Pro](https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro/) integration or community Jamf scripts
- **Intune**: Import CIS benchmark settings via the Settings Catalog (search for "CIS")
- **Third-party**: [Tenable.io](https://www.tenable.com/) and [Qualys](https://www.qualys.com/) offer agent-based CIS compliance scanning for macOS fleets

---

## ClaudeSec Scanner Integration

The `macos` check category is implemented in `scanner/checks/macos/cis-security.sh` and runs automatically when ClaudeSec detects a macOS host.

### Running macOS Checks

```bash
# Scan all macOS/CIS controls
claudesec scan --category macos

# Scan with verbose output showing all checks
claudesec scan --category macos --verbose

# Output as JSON for SIEM/dashboard ingestion
claudesec scan --category macos --format json

# Run as part of a full system scan
claudesec scan --all
```

### Example Output

```
[PASS] MAC-001  FileVault disk encryption is enabled
[PASS] MAC-002  macOS Application Firewall is enabled
[PASS] MAC-003  System Integrity Protection (SIP) is enabled
[PASS] MAC-004  Gatekeeper is enabled
[WARN] MAC-005  Automatic software update checks are disabled
[FAIL] MAC-006  Screen lock does not require password            [HIGH]
[PASS] MAC-007  Remote login (SSH) is disabled
[WARN] MAC-008  AirDrop is powered on
[PASS] MAC-009  Guest account is disabled
[WARN] MAC-010  File extensions are hidden in Finder
[WARN] CIS-001  No explicit password complexity policy detected
[PASS] CIS-002  Audit logging daemon (auditd) is running
[WARN] CIS-003  Secure Keyboard Entry is not enabled in Terminal
[PASS] CIS-004  No world-writable files found in /System
[WARN] CIS-005  3 outdated Homebrew package(s) detected
[PASS] CIS-006  SSH cipher configuration does not include known-weak algorithms
[WARN] CIS-007  Core dumps are not explicitly restricted
[PASS] CIS-008  Time daemon (timed) is running
[WARN] CIS-009  Bluetooth is powered on
[PASS] CIS-010  Content caching is disabled

Summary: 10 passed, 9 warnings, 1 failed (critical: 0, high: 1, medium: 0)
```

### Integrating Into CI/CD

For developer MacBook compliance checks in a pre-commit or onboarding script:

```bash
#!/usr/bin/env bash
# scripts/macos-compliance-check.sh
set -euo pipefail

echo "Running ClaudeSec macOS compliance check..."
claudesec scan --category macos --format json --output /tmp/macos-scan.json

failed=$(jq '[.results[] | select(.status == "fail")] | length' /tmp/macos-scan.json)
critical=$(jq '[.results[] | select(.status == "fail" and .severity == "critical")] | length' /tmp/macos-scan.json)

if [[ "$critical" -gt 0 ]]; then
  echo "ERROR: $critical critical security control(s) failed. Fix before continuing."
  jq -r '.results[] | select(.status == "fail" and .severity == "critical") | "  \(.id): \(.message)"' /tmp/macos-scan.json
  exit 1
elif [[ "$failed" -gt 0 ]]; then
  echo "WARNING: $failed security control(s) failed. Review and remediate."
  exit 0
else
  echo "All macOS security controls passed."
fi
```

---

## References

- [CIS Apple macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os) — official benchmark documents (free registration required)
- [NIST SP 800-179 Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/publications/detail/sp/800-179/final)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [macOS Security Compliance Project (mSCP)](https://github.com/usnistgov/macos_security) — NIST/DISA automation scripts
- [Jamf CIS Benchmark resources](https://www.jamf.com/resources/white-papers/cis-benchmark/)
- [DISA macOS STIG](https://public.cyber.mil/stigs/downloads/) — DoD security requirements, stricter than CIS Level 2
