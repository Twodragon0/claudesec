---
title: "Remediation Guide: Audit Logging Daemon (auditd) Not Running [CIS-002]"
description: Step-by-step remediation for the HIGH finding CIS-002 — enabling macOS audit logging to restore security event visibility.
tags: [macos, cis-benchmark, auditd, audit-logging, remediation, compliance, nist]
---

# Remediation Guide: Audit Logging Daemon (auditd) Not Running [CIS-002]

## Overview

The macOS **audit daemon (auditd)** records security-relevant system events — authentication attempts, privilege escalations, file access, and process execution — to tamper-resistant log files. These logs are essential for incident response, forensic investigation, and regulatory compliance.

**Finding severity:** HIGH
**CIS control:** CIS Apple macOS Benchmark v3.0+, Section 3.2 — "Ensure security auditing is enabled"
**NIST mapping:** NIST CSF DE.CM-3 (Personnel activity monitoring), AU-2, AU-9, AU-12

Without auditd running, security events are silently lost. Attackers can operate undetected and investigations become impossible after the fact.

---

## Remediation Steps

### 1. Verify the current state

```bash
sudo launchctl list | grep auditd
```

If this returns no output, auditd is not loaded.

```bash
ls -lh /var/audit/
```

If the directory is empty or missing recent `.not_terminated` log files, audit logging has been inactive.

### 2. Enable auditd immediately (current session)

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
```

The `-w` flag writes a persistent override so the daemon survives reboots.

### 3. Confirm the daemon is running

```bash
sudo launchctl list | grep auditd
# Expected: a line containing "com.apple.auditd" with a PID

sudo audit -n && sudo audit -s
# -n rotates the current log; -s starts a new session cleanly
```

### 4. Verify log output

```bash
ls -lht /var/audit/ | head -5
# Should show recent .not_terminated or timestamped log files

sudo praudit /var/audit/current | head -20
# Human-readable view of recent audit events
```

---

## Audit Policy Configuration (Optional Hardening)

The default policy is minimal. Review `/etc/security/audit_control` to ensure relevant event classes are captured:

```bash
cat /etc/security/audit_control
```

Recommended flags for CIS Level 1 compliance:

```
flags:lo,aa,ad,fd,fm,-all
minfree:5
naflags:lo,aa
```

| Flag | Events captured |
|------|----------------|
| `lo` | Login/logout |
| `aa` | Authentication and authorization |
| `ad` | Administrative actions |
| `fd` | File deletion |
| `fm` | File attribute modification |

Apply changes:

```bash
sudo audit -s   # reload audit_control without restart
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Operation not permitted` on load | SIP or MDM policy blocking | Check with MDM admin; SIP must allow auditd |
| `/var/audit` missing | Directory removed | `sudo mkdir -p /var/audit && sudo chown root:wheel /var/audit` |
| Plist not found | macOS upgrade reset | Reinstall via `sudo softwareupdate --reinstall` or re-apply MDM baseline |
| Daemon loads but no logs appear | `audit_control` misconfigured | Verify `flags` line is not empty in `/etc/security/audit_control` |

---

## Compliance Mapping

| Framework | Control | Requirement |
|-----------|---------|-------------|
| CIS Apple macOS Benchmark v3.0 | 3.2 | Security auditing must be enabled |
| NIST SP 800-53 Rev 5 | AU-2, AU-9, AU-12 | Audit events, audit log protection, audit record generation |
| NIST CSF 2.0 | DE.CM-3 | Personnel and system activity monitored |
| ISO/IEC 27001:2022 | A.8.15 | Logging of system activities |

---

## How ClaudeSec Detects This Issue

ClaudeSec scanner check **[CIS-002]** runs the following test:

```bash
launchctl list | grep -q com.apple.auditd
```

- **Pass**: auditd process entry found with a valid PID
- **Fail (HIGH)**: no entry returned — auditd not loaded or disabled

The check maps directly to CIS Apple macOS Benchmark v3.0, Section 3.2, Level 1.

To re-run the macOS checks after remediation:

```bash
claudesec scan --category macos
```

To isolate the `CIS-002` result from the scan output:

```bash
claudesec scan --category macos | grep 'CIS-002'
```

---

## References

- [CIS Apple macOS Benchmark](https://www.cisecurity.org/benchmark/apple_os) — Center for Internet Security
- [NIST SP 800-53 Rev 5: AU Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Audit and Accountability
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) — audit subsystem documentation
- `man audit`, `man auditd`, `man audit_control` — local macOS manpages
