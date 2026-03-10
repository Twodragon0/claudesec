---
title: DevSecOps Pipeline Guide
description: Building a secure CI/CD pipeline with integrated security gates
tags: [devsecops, ci-cd, pipeline, sast, dast]
---

# DevSecOps Pipeline Guide

## Overview

A DevSecOps pipeline integrates security checks at every stage of the software delivery lifecycle, rather than treating security as a final gate.

```
Code → Commit → Build → Test → Deploy → Monitor
  ↓       ↓       ↓       ↓       ↓        ↓
Lint   Secrets  SAST    DAST   Config   Runtime
Check  Scan     Scan    Scan   Audit    Protection
```

## Pipeline Stages

### 1. Pre-Commit (Developer Workstation)

Security starts before code leaves the developer's machine.

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-added-large-files
        args: ['--maxkb=500']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

**Claude Code Integration:**
```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Write|Edit",
      "command": "bash scripts/check-secrets.sh $FILE"
    }]
  }
}
```

### 2. Commit Stage (CI Trigger)

| Check | Tool | Purpose |
|-------|------|---------|
| Secret scanning | Gitleaks, TruffleHog | Prevent credential leaks |
| Dependency audit | `npm audit`, `pip-audit` | Known vulnerability detection |
| License compliance | FOSSA, Licensee | OSS license verification |

### 3. Build Stage

```yaml
# GitHub Actions example
- name: Build with SBOM
  run: |
    docker build --sbom=true -t myapp:${{ github.sha }} .

- name: Sign image
  uses: sigstore/cosign-installer@v3
  run: cosign sign myapp:${{ github.sha }}
```

### 4. Test Stage — SAST

Static Application Security Testing analyzes source code for vulnerabilities.

| Language | Tool | Coverage |
|----------|------|----------|
| Multi | Semgrep | Custom rules, OWASP patterns |
| JavaScript | ESLint security plugin | XSS, injection |
| Python | Bandit | Common Python security issues |
| Go | gosec | Go-specific vulnerabilities |
| Java | SpotBugs + FindSecBugs | Java security patterns |

```yaml
- name: SAST with Semgrep
  uses: semgrep/semgrep-action@v1
  with:
    config: >-
      p/owasp-top-ten
      p/security-audit
```

### 5. Test Stage — DAST

Dynamic testing against running applications:

```yaml
- name: DAST with ZAP
  uses: zaproxy/action-full-scan@v0.10.0
  with:
    target: 'https://staging.example.com'
    rules_file_name: '.zap/rules.tsv'
```

### 6. Deploy Stage

```yaml
- name: Config audit
  run: |
    # Check Kubernetes manifests
    kubesec scan deployment.yaml
    # Check Terraform
    tfsec .
    # Check Dockerfiles
    hadolint Dockerfile
```

### 7. Runtime Monitoring

- **RASP**: Runtime Application Self-Protection
- **WAF**: Web Application Firewall rules
- **SIEM**: Security event aggregation and alerting
- **Falco**: Container runtime security monitoring

## Maturity Model

| Level | Description | Key Activities |
|-------|-------------|----------------|
| Level 1 | Ad-hoc | Manual reviews, basic linting |
| Level 2 | Repeatable | CI secret scanning, dependency audit |
| Level 3 | Defined | SAST/DAST in pipeline, security gates |
| Level 4 | Managed | Metrics-driven, SLA on fix times |
| Level 5 | Optimized | Automated remediation, threat intel integration |

## References

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [NIST SP 800-218 — Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [CISA Secure by Design](https://www.cisa.gov/securebydesign)
