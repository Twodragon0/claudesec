---
title: DevSecOps Audit Checklist
description: Comprehensive security audit points for CI/CD, access control, and infrastructure
tags: [audit, checklist, access-control, ci-cd, zero-trust, compliance]
---

# DevSecOps Audit Checklist

Inspired by [querypie/audit-points](https://github.com/querypie/audit-points) and CIS Benchmarks. Covers the full DevSecOps pipeline from development environment to production access control.

## Coverage Map

```
[Dev Environment]  →  [CI/CD]  →  [Artifacts]  →  [Infrastructure]  →  [Access Control]
IDE Security       Jenkins/GHA   Harbor/Registry  Cloud/K8s           IAM/DB/Server
```

---

## 1. Identity & Authentication

### Account Management

| # | Audit Point | Priority |
|---|------------|----------|
| IAM-01 | Dormant accounts locked after 90 days of inactivity | High |
| IAM-02 | Login failure lockout policy configured (5 attempts / 15 min) | High |
| IAM-03 | Password policy meets NIST 800-63b (12+ chars, breached list check) | High |
| IAM-04 | Session timeout configured (idle: 15 min, absolute: 8 hours) | Medium |
| IAM-05 | MFA enforced for all human users | Critical |
| IAM-06 | Separate MFA for admin/privileged access | Critical |
| IAM-07 | Shared/generic accounts prohibited | High |
| IAM-08 | Onboarding/offboarding process documented and auditable | High |
| IAM-09 | Service account credentials rotated (max 90-day lifetime) | High |
| IAM-10 | API token expiration and rotation policy enforced | Medium |

### Access Control

| # | Audit Point | Priority |
|---|------------|----------|
| AC-01 | IP-based ACL for admin interfaces | High |
| AC-02 | Separate admin and user access controls | High |
| AC-03 | Approval workflow for privilege escalation | High |
| AC-04 | Time-based access control for sensitive resources | Medium |
| AC-05 | Just-in-time (JIT) access provisioning | Medium |
| AC-06 | Quarterly access review for all users/roles | High |
| AC-07 | Mandatory justification for sensitive resource access | Medium |
| AC-08 | Cross-account/cross-tenant access documented and reviewed | High |

---

## 2. CI/CD Pipeline (Jenkins / GitHub Actions)

### Build Security

| # | Audit Point | Priority |
|---|------------|----------|
| CI-01 | CI/CD platform version kept current (within 2 minor versions) | High |
| CI-02 | Plugins/actions pinned to SHA and regularly updated | High |
| CI-03 | No auto-login / persistent sessions on build servers | Medium |
| CI-04 | Authentication via SSO/OIDC (not local accounts) | High |
| CI-05 | CSRF protection enabled | Medium |
| CI-06 | TLS encryption on all CI/CD endpoints | High |
| CI-07 | API tokens scoped to minimum required permissions | High |
| CI-08 | Credential storage reviewed (no plaintext secrets) | Critical |
| CI-09 | RBAC implemented (separate build, deploy, admin roles) | High |
| CI-10 | Admin activity fully logged and monitored | High |
| CI-11 | Pipeline definitions version-controlled and reviewed | High |
| CI-12 | Separation of duties between code commit and deploy | High |
| CI-13 | Build environments ephemeral (fresh per job) | Medium |
| CI-14 | Secrets scoped per environment (dev/staging/prod) | High |
| CI-15 | MFA required for CI/CD admin access | Critical |

### Artifact Management (Harbor / Nexus)

| # | Audit Point | Priority |
|---|------------|----------|
| AR-01 | Vulnerability scanner configured and enforced on push | High |
| AR-02 | CVE exception list reviewed quarterly | Medium |
| AR-03 | Artifact integrity verification (content trust / signing) | High |
| AR-04 | Project-level access control configured | High |
| AR-05 | Token/credential expiration policy enforced | Medium |
| AR-06 | No anonymous pull access on private registries | High |
| AR-07 | Image retention and cleanup policy configured | Low |
| AR-08 | SBOM generated and stored with each artifact | Medium |

---

## 3. Database Access Control

| # | Audit Point | Priority |
|---|------------|----------|
| DB-01 | Unused database connections disabled after 30 days | Medium |
| DB-02 | Maximum connection/access duration enforced | Medium |
| DB-03 | Query volume limits per connection configured | Low |
| DB-04 | Time-of-day access restrictions for sensitive databases | Medium |
| DB-05 | All queries audit-logged for sensitive databases | High |
| DB-06 | Mandatory justification for database access requests | Medium |
| DB-07 | Access permissions reviewed quarterly | High |
| DB-08 | Column-level access control for PII/sensitive data | High |
| DB-09 | Sensitive table/column access history reviewed | High |
| DB-10 | Database encryption at rest enabled | High |
| DB-11 | TLS enforced for all database connections | High |
| DB-12 | Database admin access logged separately | High |

---

## 4. Server/System Access Control

| # | Audit Point | Priority |
|---|------------|----------|
| SRV-01 | SSH login failure lockout configured | High |
| SRV-02 | Restricted commands enforced (session terminated on violation) | High |
| SRV-03 | Session timeout configured | Medium |
| SRV-04 | Insecure protocols disabled (telnet, FTP, rlogin) | Critical |
| SRV-05 | MFA required for critical infrastructure access | Critical |
| SRV-06 | Approval-based server access workflow | High |
| SRV-07 | Password rotation enforced (or SSH key rotation) | High |
| SRV-08 | Command audit logging enabled | High |
| SRV-09 | Session recording for privileged access | Medium |
| SRV-10 | Concurrent session limits configured | Low |
| SRV-11 | Role-based access reviewed quarterly | High |
| SRV-12 | Bastion host / jump server for production access | High |
| SRV-13 | Direct root/admin login disabled | Critical |

---

## 5. Kubernetes Access Control

| # | Audit Point | Priority |
|---|------------|----------|
| K8S-01 | Pod session timeout configured | Medium |
| K8S-02 | API server audit logging enabled | High |
| K8S-03 | Pod shell session recording enabled | Medium |
| K8S-04 | RBAC follows least privilege principle | Critical |
| K8S-05 | API permissions granular (no wildcard `*`) | High |
| K8S-06 | Service account per workload (not default SA) | High |
| K8S-07 | User/group role assignments reviewed quarterly | High |
| K8S-08 | Approval workflow for cluster-admin actions | High |
| K8S-09 | Pod Security Standards enforced (Baseline minimum) | High |
| K8S-10 | NetworkPolicy default-deny configured | High |
| K8S-11 | Secrets encrypted at rest in etcd | High |
| K8S-12 | External secrets operator used (not K8s native secrets) | Medium |

---

## 6. Logging & Monitoring

| # | Audit Point | Priority |
|---|------------|----------|
| LOG-01 | All authentication events logged (success AND failure) | Critical |
| LOG-02 | Admin/privileged actions fully logged | Critical |
| LOG-03 | Log storage separate from application servers | High |
| LOG-04 | Log retention meets compliance requirements (90+ days) | High |
| LOG-05 | Log integrity protection (append-only, signed) | High |
| LOG-06 | Real-time alerting for critical security events | High |
| LOG-07 | Sensitive data excluded from logs (passwords, tokens, PII) | Critical |
| LOG-08 | Log access restricted and audited | High |
| LOG-09 | Incident response playbook exists and tested | High |
| LOG-10 | Security events correlated across systems (SIEM) | Medium |

---

## Compliance Mapping

| Audit Domain | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS |
|-------------|-------|-----------|-------------|---------|
| Identity & Auth | CC6.1 | A.9 | IA, AC | Req 7, 8 |
| CI/CD | CC6.6 | A.14 | SA, CM | Req 6 |
| Database | CC6.1 | A.9 | AC, AU | Req 7, 10 |
| Server Access | CC6.1 | A.9 | AC, IA | Req 7, 8 |
| Kubernetes | CC6.6 | A.13 | AC, CM | Req 1, 2 |
| Logging | CC7.2 | A.12 | AU, IR | Req 10, 12 |

---

## Audit Automation

```bash
# Prowler — cloud infrastructure audit
prowler aws --compliance cis_2.0_aws soc2 --severity critical high

# kube-bench — Kubernetes CIS audit
kube-bench run --targets master,node,policies

# GitHub — repository security audit
prowler github --personal-access-token "$TOKEN" --repository "org/repo"

# Custom audit script
#!/bin/bash
echo "=== Identity Audit ==="
# Check for MFA enforcement
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
# Check for unused credentials
aws iam generate-credential-report
```

## References

- [querypie/audit-points](https://github.com/querypie/audit-points) — DevSecOps tool audit points
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
