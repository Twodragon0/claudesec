---
title: OWASP Top 10 2025 Complete Guide
description: All 10 categories with practical security controls and Claude Code integration
tags: [owasp, top-10, 2025, web-security, appsec]
---

# OWASP Top 10 2025

The [OWASP Top 10 2025](https://owasp.org/Top10/) reflects the current web application threat landscape. Key changes from 2021: Supply Chain Failures is new at #3, Security Misconfiguration rose from #5 to #2, and a new #10 covers Exceptional Condition handling.

## Changes from 2021

| 2021 | 2025 | Change |
|------|------|--------|
| A01 Broken Access Control | A01 Broken Access Control | Expanded (absorbed SSRF) |
| A05 Security Misconfiguration | A02 Security Misconfiguration | Rose from #5 |
| A09 Vulnerable Components | A03 Supply Chain Failures | **New** (expanded scope) |
| A02 Cryptographic Failures | A04 Cryptographic Failures | Dropped from #2 |
| A03 Injection | A05 Injection | Dropped from #3 |
| A04 Insecure Design | A06 Insecure Design | Dropped from #4 |
| A07 Auth Failures | A07 Authentication Failures | Renamed |
| A08 Integrity Failures | A08 Integrity Failures | Maintained |
| A09 Logging Failures | A09 Logging & Alerting Failures | Alerting added |
| A10 SSRF | A10 Exceptional Conditions | **New** (SSRF → A01) |

---

## A01: Broken Access Control

Users acting beyond intended permissions. Now includes SSRF (CWE-918).

### Key Threats

- IDOR (Insecure Direct Object References)
- Privilege escalation via JWT manipulation
- CORS misconfiguration allowing unauthorized origins
- Path traversal and forced browsing
- Missing function-level access control

### Controls

```typescript
// Deny by default — allow only explicitly permitted
function authorize(user: User, resource: Resource, action: Action): boolean {
  // Check ownership
  if (resource.ownerId !== user.id && !user.hasRole('admin')) {
    return false;
  }
  // Check action permission
  return user.permissions.includes(`${resource.type}:${action}`);
}

// SSRF prevention — URL allowlist
const ALLOWED_HOSTS = new Set(['api.stripe.com', 'hooks.slack.com']);
function validateUrl(url: string): boolean {
  const parsed = new URL(url);
  return ALLOWED_HOSTS.has(parsed.hostname);
}
```

### Claude Code Review Prompt

```
Review this code for broken access control:
1. Are all endpoints checking authorization (not just authentication)?
2. Can users access/modify other users' resources (IDOR)?
3. Are admin functions protected from regular users?
4. Is CORS configured restrictively?
5. Are server-side URL requests validated against an allowlist (SSRF)?
```

---

## A02: Security Misconfiguration

Jumped from #5 to #2 — cloud-native and container adoption expanded the misconfiguration attack surface.

### Key Threats

- Default credentials on databases, admin panels
- Unnecessary features enabled (debug, directory listing)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Verbose error messages exposing internals
- Cloud storage permissions (public S3 buckets)

### Controls

```yaml
# Security headers (nginx)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

```bash
# Automated hardening check with Prowler
prowler aws --severity critical high \
  --compliance cis_2.0_aws \
  --output-formats json
```

### Checklist

- [ ] Default credentials changed on all services
- [ ] Debug mode disabled in production
- [ ] Unnecessary ports/services/endpoints removed
- [ ] Security headers configured and verified
- [ ] Error pages don't expose stack traces or internals
- [ ] Cloud resource permissions reviewed (no public access by default)

---

## A03: Supply Chain Failures (NEW)

Expanded from "Vulnerable Components" to cover the **entire software supply chain** — dependencies, CI/CD, build tools, artifact repositories, developer workstations.

### Key Threats

- Dependency confusion / typosquatting attacks
- Compromised CI/CD pipelines (2025 Bybit: $1.5B)
- Malicious packages in npm/PyPI/Maven
- Unsigned artifacts and missing provenance
- Abandoned/unmaintained dependencies

### Controls

{% raw %}

```yaml
# SBOM generation in CI
- name: Generate SBOM
  run: syft . -o spdx-json > sbom.spdx.json

# Artifact signing
- name: Sign container image
  run: cosign sign --yes ghcr.io/${{ github.repository }}:${{ github.sha }}

# Dependency review gate
- uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: moderate
    deny-licenses: GPL-3.0, AGPL-3.0
```

{% endraw %}

See [Supply Chain Security Guide](supply-chain-security.md) for full SLSA/SBOM/Sigstore coverage.

---

## A04: Cryptographic Failures

### Key Threats

- Data transmitted in cleartext (HTTP, FTP, SMTP without TLS)
- Weak algorithms (MD5, SHA1, DES, RC4)
- Hardcoded encryption keys in source code
- Missing encryption for PII at rest
- Insufficient password hashing (plain MD5/SHA)

### Controls

```typescript
import { hash, verify } from 'argon2';

// Password hashing — use Argon2id
async function hashPassword(password: string): Promise<string> {
  return hash(password, {
    type: 2,        // argon2id
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });
}

// Never roll your own crypto — use established libraries
// Use TLS 1.2+ with PFS cipher suites
// Store keys in HSM or cloud KMS, never in code
```

### Post-Quantum Readiness

- NIST standardized ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+) in 2024
- Plan migration by 2030 — inventory all cryptographic usage now

---

## A05: Injection

### Key Threats

- SQL/NoSQL injection
- OS command injection
- LDAP injection
- XSS (Cross-Site Scripting)
- Expression Language / Template injection

### Controls

```typescript
// ALWAYS use parameterized queries
const user = await db.query(
  'SELECT * FROM users WHERE id = $1 AND org_id = $2',
  [userId, orgId]
);

// NEVER concatenate user input into queries
// BAD: `SELECT * FROM users WHERE id = ${userId}`

// For ORM — verify no raw query interpolation
const user = await prisma.user.findUnique({
  where: { id: userId },
});

// Output encoding for XSS prevention
// React auto-escapes by default — never use dangerouslySetInnerHTML
```

---

## A06: Insecure Design

Design flaws cannot be fixed by perfect implementation. Security must be built in from the start.

### Controls

- Threat modeling (STRIDE) for every major feature
- Security requirements in user stories
- Secure design pattern library (rate limiting, tenant isolation, auth flows)
- Abuse case / misuse case analysis alongside use cases

See [Threat Modeling Guide](threat-modeling.md) for AI-assisted STRIDE workflows.

---

## A07: Authentication Failures

### Controls

```typescript
// MFA enforcement
if (!user.mfaEnabled && resource.sensitivity === 'high') {
  throw new AuthError('MFA required for this resource');
}

// Rate limiting on login
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                     // 5 attempts
  skipSuccessfulRequests: true,
});

// Password policy (NIST 800-63b)
// - Minimum 8 characters (prefer 12+)
// - Check against breached password lists (HaveIBeenPwned)
// - No complexity rules (they reduce security)
// - No mandatory rotation (unless compromised)
```

---

## A08: Software & Data Integrity Failures

### Controls

- Verify digital signatures on all downloaded packages
- Use lock files (`package-lock.json`, `poetry.lock`) and verify checksums
- Require code review for all changes (CODEOWNERS)
- Never deserialize untrusted data without validation
- CI/CD pipeline access restricted with MFA and audit logging

---

## A09: Security Logging & Alerting Failures

### Controls

```typescript
// What to log
const AUDIT_EVENTS = [
  'auth.login.success',
  'auth.login.failure',
  'auth.mfa.bypass_attempt',
  'data.export',
  'admin.permission.change',
  'payment.transaction',
];

// Log injection prevention
function sanitizeLogEntry(entry: string): string {
  return entry.replace(/[\n\r\t]/g, '_');
}

// Structured logging
logger.info({
  event: 'auth.login.success',
  userId: user.id,
  ip: sanitizeLogEntry(req.ip),
  timestamp: new Date().toISOString(),
});
```

### Checklist

- [ ] All auth events logged (success AND failure)
- [ ] High-value transactions logged with tamper-evident audit trail
- [ ] Logs don't contain passwords, tokens, or PII
- [ ] Real-time alerting for critical security events
- [ ] Log retention meets compliance requirements (90+ days)
- [ ] Incident response playbook exists and tested

---

## A10: Mishandling of Exceptional Conditions (NEW)

Software that fails to prevent, detect, or properly respond to abnormal situations.

### Key Threats

- Unhandled exceptions exposing stack traces
- Race conditions leading to privilege escalation
- Integer overflow bypassing validation
- Resource exhaustion (memory, file descriptors)
- Fail-open instead of fail-closed behavior

### Controls

```typescript
// Fail closed — deny on error
async function authorize(req: Request): Promise<boolean> {
  try {
    const result = await authService.check(req);
    return result.allowed;
  } catch (error) {
    logger.error({ event: 'auth.error', error: error.message });
    return false;  // FAIL CLOSED — deny access on error
  }
}

// Resource limits
const server = http.createServer({
  maxHeaderSize: 8192,
  headersTimeout: 30000,
  requestTimeout: 60000,
});

// Transaction rollback on error
async function transferFunds(from: string, to: string, amount: number) {
  const tx = await db.transaction();
  try {
    await tx.debit(from, amount);
    await tx.credit(to, amount);
    await tx.commit();
  } catch (error) {
    await tx.rollback();  // Complete rollback on ANY error
    throw error;
  }
}
```

---

## Quick Reference Matrix

| # | Risk | Test Method | Key Tool |
|---|------|-------------|----------|
| A01 | Broken Access Control | Manual + DAST | Burp Suite, ZAP |
| A02 | Security Misconfiguration | CSPM + Config audit | Prowler, Checkov |
| A03 | Supply Chain Failures | SCA + SBOM | Trivy, Syft, Scorecard |
| A04 | Cryptographic Failures | SAST + Manual | Semgrep, ssl-labs |
| A05 | Injection | SAST + DAST | Semgrep, SQLMap, ZAP |
| A06 | Insecure Design | Threat modeling | Threat Dragon, STRIDE |
| A07 | Auth Failures | Pentest + DAST | Hydra, ZAP |
| A08 | Integrity Failures | Supply chain audit | Cosign, in-toto |
| A09 | Logging Failures | Log audit | ELK, Splunk |
| A10 | Exceptional Conditions | SAST + Fuzzing | Semgrep, AFL |

## References

- [OWASP Top 10:2025 Official](https://owasp.org/Top10/)
- [OWASP Top 10 GitHub Repository](https://github.com/OWASP/Top10/tree/master/2025)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
