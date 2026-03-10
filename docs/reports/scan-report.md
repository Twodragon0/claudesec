---
title: "ClaudeSec Security Scan Report"
description: "DevSecOps security best practices scan of the claudesec repository. Covers infrastructure, AI/LLM, network, cloud, IAM, CI/CD, and macOS/CIS hardening checks."
tags:
  - security
  - devsecops
  - cis-benchmark
  - macos
  - ci-cd
  - iam
---

# ClaudeSec Security Scan Report

> Generated on **2026-03-10** by ClaudeSec Scanner v0.1.0

---

## Summary

| Metric | Value |
|--------|-------|
| Total Checks | 70 |
| [PASS] Passed | 14 |
| [FAIL] Failed | 7 |
| [WARN] Warnings | 8 |
| [SKIP] Skipped | 41 |
| **Security Score** | **20 / 100 (F)** |
| Scan Duration | 19 seconds |

> **Note:** 41 checks were skipped because the relevant technology (Docker, Kubernetes, Terraform, AWS, Azure, AI/LLM, web server) was not detected in this repository. The score reflects only applicable checks.

---

## Findings by Category

### 1. Infrastructure Security

All infrastructure checks were skipped — no Dockerfile, docker-compose, Terraform, Helm, or Kubernetes manifests were found. kubectl was also unavailable or not connected to a live cluster.

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| INFRA-001 | [SKIP] Skip | Dockerfile non-root user | — |
| INFRA-002 | [SKIP] Skip | Docker image pinning | — |
| INFRA-003 | [SKIP] Skip | Docker secrets check | — |
| INFRA-004 | [SKIP] Skip | Docker Compose security | — |
| INFRA-005 | [SKIP] Skip | Docker ignore file | — |
| INFRA-010 | [SKIP] Skip | K8s pod security | — |
| INFRA-011 | [SKIP] Skip | K8s capabilities | — |
| INFRA-012 | [SKIP] Skip | K8s resource limits | — |
| INFRA-013 | [SKIP] Skip | K8s read-only filesystem | — |
| INFRA-014 | [SKIP] Skip | K8s NetworkPolicy | — |
| INFRA-015 | [SKIP] Skip | K8s service account token | — |
| INFRA-016 | [SKIP] Skip | K8s live cluster check | — |
| INFRA-020 | [SKIP] Skip | Terraform secrets | — |
| INFRA-021 | [SKIP] Skip | Terraform state | — |
| INFRA-022 | [SKIP] Skip | Terraform lock | — |
| INFRA-023 | [SKIP] Skip | Helm chart security | — |

---

### 2. AI / LLM Security

All AI/LLM checks were skipped — no AI/LLM application code was detected in the repository.

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| AI-001 | [SKIP] Skip | LLM API key check | — |
| AI-002 | [SKIP] Skip | Prompt injection defense | — |
| AI-003 | [SKIP] Skip | LLM output validation | — |
| AI-004 | [SKIP] Skip | AI rate limiting | — |
| AI-005 | [SKIP] Skip | Token budget | — |
| AI-006 | [SKIP] Skip | System prompt exposure | — |
| AI-007 | [SKIP] Skip | eval() of LLM output | — |
| AI-008 | [SKIP] Skip | RAG security | — |
| AI-009 | [SKIP] Skip | Agent tool permissions | — |

---

### 3. Network Security

All network checks were skipped — no application source files or web server configuration were detected.

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| NET-001 | [SKIP] Skip | HTTPS enforcement | — |
| NET-002 | [SKIP] Skip | TLS configuration | — |
| NET-003 | [SKIP] Skip | Security headers | — |
| NET-004 | [SKIP] Skip | CORS configuration | — |
| NET-005 | [SKIP] Skip | Firewall rules (IaC) | — |

---

### 4. Cloud Security (AWS / GCP / Azure)

All cloud checks were skipped — AWS and Azure are not configured in this environment.

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| CLOUD-001 | [SKIP] Skip | AWS root MFA | — |
| CLOUD-002 | [SKIP] Skip | AWS CloudTrail | — |
| CLOUD-003 | [SKIP] Skip | S3 public block | — |
| CLOUD-004 | [SKIP] Skip | Default VPC | — |
| CLOUD-005 | [SKIP] Skip | EC2 IMDSv2 | — |
| CLOUD-020 | [SKIP] Skip | Azure Defender | — |
| CLOUD-021 | [SKIP] Skip | Azure MFA | — |

---

### 5. Access Control & IAM

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| IAM-001 | [PASS] Pass | No `.env` files tracked in git | — |
| IAM-002 | [WARN] Warn | `.gitignore` missing patterns: `*.pem`, `*.key`, `credentials`, `*.secret` | Medium |
| IAM-003 | [SKIP] Skip | Password hashing | — |
| IAM-004 | [SKIP] Skip | JWT security | — |
| IAM-005 | [SKIP] Skip | Session/cookie security | — |
| IAM-006 | [FAIL] Fail | No `SECURITY.md` found | Medium |

---

### 6. CI/CD Pipeline Security

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| CICD-001 | [PASS] Pass | GitHub Actions workflows define permissions | — |
| CICD-002 | [WARN] Warn | Actions pinned to version tags, not full SHA | Medium |
| CICD-003 | [PASS] Pass | No obvious secret logging in workflows | — |
| CICD-004 | [WARN] Warn | No dependency review action in CI | Medium |
| CICD-005 | [FAIL] Fail | No security scanning (SAST/SCA) in CI pipeline | High |
| CICD-006 | [PASS] Pass | No user-controlled event data in workflows | — |
| CICD-007 | [SKIP] Skip | Lock file check | — |
| CICD-008 | [WARN] Warn | No `CODEOWNERS` file | Low |

---

### 7. macOS / CIS Benchmark Security

| ID | Status | Description | Severity |
|----|--------|-------------|----------|
| MAC-001 | [PASS] Pass | FileVault disk encryption is enabled | — |
| MAC-002 | [PASS] Pass | macOS Application Firewall is enabled | — |
| MAC-003 | [PASS] Pass | System Integrity Protection (SIP) is enabled | — |
| MAC-004 | [PASS] Pass | Gatekeeper is enabled | — |
| MAC-005 | [FAIL] Fail | Automatic software update checks are disabled | Medium |
| MAC-006 | [FAIL] Fail | Screen lock does not require password | High |
| MAC-007 | [WARN] Warn | Remote login (SSH) status could not be determined | Medium |
| MAC-008 | [PASS] Pass | AirDrop is restricted (Off) | — |
| MAC-009 | [PASS] Pass | Guest account is disabled | — |
| MAC-010 | [PASS] Pass | All file extensions are visible in Finder | — |
| CIS-001 | [WARN] Warn | No explicit password complexity policy detected | Medium |
| CIS-002 | [FAIL] Fail | Audit logging daemon (auditd) is not running | High |
| CIS-003 | [WARN] Warn | Secure Keyboard Entry not enabled in Terminal | Low |
| CIS-004 | [FAIL] Fail | World-writable files found in /System (14 files) | High |
| CIS-005 | [FAIL] Fail | 42 outdated Homebrew packages detected | Medium |
| CIS-007 | [PASS] Pass | Core dumps are restricted | — |
| CIS-008 | [PASS] Pass | Time daemon (timed) is running | — |
| CIS-009 | [WARN] Warn | Bluetooth is powered on | Low |
| CIS-010 | [PASS] Pass | Content caching is disabled | — |

---

## Action Items

All FAIL and WARN findings listed below, ordered by severity (Critical → High → Medium → Low).

### [FAIL] High Severity

#### CICD-005 — No security scanning in CI pipeline

- **Issue:** No SAST or SCA tools detected in GitHub Actions workflows.
- **Risk:** Vulnerable code and dependencies may reach production undetected.
- **Remediation:**
  1. Add CodeQL analysis to `.github/workflows/`:

     ```yaml
     - uses: github/codeql-action/analyze@v3
     ```

  2. Alternatively, add Semgrep or Trivy for SAST/container scanning.
  3. Consider adding `actions/dependency-review-action` alongside (see CICD-004).

#### MAC-006 — Screen lock does not require password

- **Issue:** Physical access to the machine grants full account access without authentication.
- **Risk:** High — anyone with brief physical access can read files, exfiltrate data, or install malware.
- **Remediation:**

  ```bash
  defaults write com.apple.screensaver askForPassword -bool true
  defaults write com.apple.screensaver askForPasswordDelay -int 0
  ```

#### CIS-002 — Audit logging daemon (auditd) is not running

- **Issue:** macOS audit daemon is inactive; security events are not being recorded.
- **Risk:** High — incident response and forensic investigation are severely limited without audit logs.
- **Remediation:**

  ```bash
  sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
  ```

  Verify with: `sudo launchctl list | grep auditd`

#### CIS-004 — World-writable files found in /System (14 files)

- **Issue:** 14 files under `/System` have world-writable permissions.
- **Risk:** High — any local user can modify system files, enabling privilege escalation.
- **Remediation:**
  1. Review the affected files:

     ```bash
     sudo find /System -maxdepth 4 -perm -0002 -not -type l
     ```

  2. Remove world-write bits where appropriate:

     ```bash
     sudo chmod o-w <file>
     ```

  3. If files are Apple-managed, running `sudo /usr/libexec/repair_packages --repair --standard-pkgs` may restore correct permissions.

---

### [FAIL] Medium Severity

#### IAM-006 — No SECURITY.md found

- **Issue:** The repository lacks a security vulnerability disclosure policy.
- **Risk:** Security researchers have no defined path to responsibly report vulnerabilities.
- **Remediation:**
  1. Create `SECURITY.md` in the repository root. A template is available at `templates/SECURITY.md`.
  2. At minimum, include: supported versions, how to report a vulnerability, expected response time, and a PGP key or email contact.

#### MAC-005 — Automatic software update checks are disabled

- **Issue:** macOS is not automatically checking for software updates.
- **Risk:** Security patches may be delayed indefinitely.
- **Remediation:**

  ```bash
  sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
  sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
  sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
  ```

#### CIS-005 — 42 outdated Homebrew packages detected

- **Issue:** 42 Homebrew packages are out of date and may contain known CVEs.
- **Risk:** Medium — outdated tools (compilers, interpreters, CLI utilities) can be exploited.
- **Remediation:**

  ```bash
  brew update && brew upgrade
  # Audit for known vulnerabilities:
  brew audit --strict
  ```

---

### [WARN] Medium Severity

#### IAM-002 — .gitignore missing critical patterns

- **Issue:** `.gitignore` does not exclude `*.pem`, `*.key`, `credentials`, or `*.secret` files.
- **Risk:** Private keys or credentials could be accidentally committed.
- **Remediation:** Add the following to `.gitignore`:

  ```gitignore
  *.pem
  *.key
  *.secret
  credentials
  credentials.json
  .env*
  ```

#### CICD-002 — GitHub Actions pinned to version tags, not SHA

- **Issue:** Actions use `@v3`-style tags which are mutable and can be changed by the action author.
- **Risk:** Supply chain attack via tag mutation.
- **Remediation:** Pin each action to its full commit SHA, e.g.:

  ```yaml
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
  ```

  Use tools like `pin-github-action` or Dependabot to automate this.

#### CICD-004 — No dependency review action in CI

- **Issue:** No `actions/dependency-review-action` is configured to block PRs introducing vulnerable dependencies.
- **Remediation:**

  ```yaml
  - uses: actions/dependency-review-action@v4
    with:
      fail-on-severity: moderate
  ```

#### MAC-007 — Remote login (SSH) status could not be determined

- **Issue:** Scanner could not verify whether SSH remote login is enabled.
- **Remediation:** Check manually and disable if not needed:

  ```bash
  sudo systemsetup -getremotelogin
  sudo systemsetup -setremotelogin off
  ```

#### CIS-001 — No explicit password complexity policy detected

- **Issue:** No `pwpolicy` or MDM-enforced password complexity rules are configured.
- **Risk:** Weak passwords may be in use on local accounts.
- **Remediation:**

  ```bash
  # Example: require minimum 15 characters with complexity
  sudo pwpolicy -setaccountpolicies
  ```

  CIS Benchmark recommends at least 15 characters with uppercase, lowercase, number, and symbol requirements.

---

### [WARN] Low Severity

#### CICD-008 — No CODEOWNERS file

- **Issue:** No `.github/CODEOWNERS` file is present.
- **Risk:** No automatic review assignment; security-sensitive files may be merged without appropriate expert review.
- **Remediation:** Create `.github/CODEOWNERS`:

  ```
  # Default owners for all files
  *       @your-team

  # Security-sensitive files require security team review
  /scanner/  @security-team
  /.github/  @devops-team
  ```

#### CIS-003 — Secure Keyboard Entry not enabled in Terminal

- **Issue:** Other applications may be able to intercept keystrokes entered in Terminal.
- **Remediation:** In Terminal.app: **Settings > Profiles > (select profile) > check "Secure Keyboard Entry"**, or via menu **Terminal > Secure Keyboard Entry**.

#### CIS-009 — Bluetooth is powered on

- **Issue:** Active Bluetooth increases wireless attack surface.
- **Remediation:** Disable Bluetooth when not in use via **System Settings > Bluetooth > Turn Off**, or:

  ```bash
  blueutil -p 0
  ```

---

## macOS / CIS Hardening Status

Detailed breakdown of all 20 macOS/CIS checks across 5 control areas.

### Disk & System Protection (4/4 Pass)

| Check | ID | Result | Notes |
|-------|----|--------|-------|
| FileVault disk encryption | MAC-001 | [PASS] Pass | Full-disk encryption active |
| Application Firewall | MAC-002 | [PASS] Pass | macOS firewall enabled |
| System Integrity Protection | MAC-003 | [PASS] Pass | SIP prevents system file modification |
| Gatekeeper | MAC-004 | [PASS] Pass | Only signed apps allowed |

### Authentication & Access (1/3 Pass)

| Check | ID | Result | Notes |
|-------|----|--------|-------|
| Screen lock requires password | MAC-006 | [FAIL] Fail | HIGH — no password required on lock |
| Guest account disabled | MAC-009 | [PASS] Pass | Guest login disabled |
| Password complexity policy | CIS-001 | [WARN] Warn | No pwpolicy/MDM policy configured |

### Network & Connectivity (2/3 Pass)

| Check | ID | Result | Notes |
|-------|----|--------|-------|
| AirDrop restricted | MAC-008 | [PASS] Pass | AirDrop is Off |
| Remote login (SSH) | MAC-007 | [WARN] Warn | Status could not be determined |
| Bluetooth powered on | CIS-009 | [WARN] Warn | Increases wireless attack surface |

### Auditing & Updates (1/4 Pass)

| Check | ID | Result | Notes |
|-------|----|--------|-------|
| Automatic software updates | MAC-005 | [FAIL] Fail | Update checks disabled |
| Audit logging (auditd) | CIS-002 | [FAIL] Fail | HIGH — no audit trail |
| Time daemon (timed) | CIS-008 | [PASS] Pass | Clock sync active |
| Secure Keyboard Entry | CIS-003 | [WARN] Warn | Not enabled in Terminal |

### System Integrity & Miscellaneous (5/6 Pass)

| Check | ID | Result | Notes |
|-------|----|--------|-------|
| File extensions visible in Finder | MAC-010 | [PASS] Pass | All extensions shown |
| Core dumps restricted | CIS-007 | [PASS] Pass | Core dumps are off |
| Content caching disabled | CIS-010 | [PASS] Pass | Not caching Apple CDN content |
| World-writable /System files | CIS-004 | [FAIL] Fail | HIGH — 14 files world-writable |
| Outdated Homebrew packages | CIS-005 | [FAIL] Fail | 42 packages need updates |

---

## Recommendations

The following 5 actions are prioritized by security impact and ease of implementation.

### 1. Enable Screen Lock Password (MAC-006) — High / Immediate

This is the single most impactful quick fix. Without a screen lock password, any brief physical access to the machine bypasses all other security controls.

```bash
defaults write com.apple.screensaver askForPassword -bool true
defaults write com.apple.screensaver askForPasswordDelay -int 0
```

### 2. Add Security Scanning to CI Pipeline (CICD-005) — High / Short-term

Integrate CodeQL or Semgrep into GitHub Actions to catch vulnerabilities before they reach the default branch. This is a one-time workflow addition that provides ongoing automated protection.

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]
jobs:
  codeql:
    uses: github/codeql-action/analyze@<sha>
```

### 3. Enable Audit Logging (CIS-002) — High / Immediate

`auditd` records security events essential for incident response. Enabling it takes a single command and has negligible performance impact.

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
```

### 4. Remediate World-Writable /System Files (CIS-004) — High / Short-term

Review and correct the 14 world-writable files in `/System`. Start with:

```bash
sudo find /System -maxdepth 4 -perm -0002 -not -type l
```

### 5. Update Outdated Homebrew Packages + Enable Auto-Updates (CIS-005 + MAC-005) — Medium / Immediate

Update all 42 outdated packages and re-enable macOS update checks to prevent this from recurring.

```bash
brew update && brew upgrade
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
```

---

*Report generated by ClaudeSec Scanner v0.1.0 on 2026-03-10.*
