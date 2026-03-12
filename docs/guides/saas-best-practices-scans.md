---
title: SaaS & DevSecOps Best-Practices Scans
description: Enable ClaudeSec best-practices checks for Harbor, Jenkins, Okta, QueryPie, and IDE workspaces
tags: [saas, devsecops, jenkins, harbor, okta, querypie, ide, best-practices]
---

# SaaS & DevSecOps Best-Practices Scans

ClaudeSec includes two layers of checks:

- **Repo-local checks**: detect risky patterns in config/code (fast, offline).
- **Live API checks (optional)**: query real SaaS configurations using API tokens (more accurate).

## What’s covered

| Product | Repo-local checks | Live API checks |
|--------|-------------------|----------------|
| **Harbor** | `SAAS-017` | `SAAS-API-020` |
| **Jenkins** | `SAAS-018` | `SAAS-API-021` |
| **Okta** | `SAAS-008` | `SAAS-API-007`, `SAAS-API-019`, `SAAS-API-022` |
| **QueryPie** | `SAAS-014` + `AUDIT-001` | (not implemented yet) |
| **IDEs** | `SAAS-019` | — |

## Enable live scans (recommended)

Copy the template and export env vars securely:

- Template: `templates/claudesec-saas-integrations.example.yml`
- Prefer a secret manager / CI secrets over files (OWASP Secrets Management Cheat Sheet: `https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html`)

Then run:

```bash
claudesec scan -c saas
```

## Notes by product

### Jenkins

- ClaudeSec checks **common hardening signals** (anonymous access surface, CSRF crumb endpoint behavior) and **pipeline anti-patterns** (hardcoded secrets, `curl|bash`, `:latest` tags).
- Jenkins hardening guidance: `https://www.jenkins.io/doc/book/security/`
- CI/CD security patterns: OWASP CI/CD Security Cheat Sheet `https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html`

### Harbor

- ClaudeSec performs a minimal API reachability/auth check and flags obvious insecure config patterns.
- Harbor documentation: `https://goharbor.io/docs/`

### Okta

- Live scans validate security posture signals like MFA policy presence and risky OAuth redirect URIs.
- Strong authentication recommendations are aligned with NIST Digital Identity Guidelines (NIST SP 800-63): `https://pages.nist.gov/800-63-3/`

### IDE workspaces

- Flags settings that weaken TLS verification or workspace trust in shared repos.

## Security & privacy

- ClaudeSec **does not print tokens**. Keep tokens out of repos and prefer ephemeral/least-privilege credentials (OWASP).
- For shareable outputs (e.g., dashboard HTML), keep `CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS=0` unless you explicitly need identifiers.
