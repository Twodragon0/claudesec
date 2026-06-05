# Security Rules

## Mandatory Security Checks

Before ANY commit:
- [ ] No hardcoded secrets (API keys, passwords, tokens)
- [ ] All user inputs validated
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (sanitized HTML)
- [ ] CSRF protection enabled
- [ ] Authentication/authorization verified
- [ ] Rate limiting on all endpoints
- [ ] Error messages don't leak sensitive data

## Secret Management

```typescript
// NEVER: Hardcoded secrets
const apiKey = "sk-proj-xxxxx"

// ALWAYS: Environment variables
const apiKey = process.env.API_KEY
if (!apiKey) throw new Error('API_KEY not configured')
```

## Security Response Protocol

If security issue found:
1. STOP immediately
2. Use `security-reviewer` agent
3. Fix CRITICAL issues before continuing
4. Rotate any exposed secrets
5. Review entire codebase for similar issues

## ClaudeSec-Specific Security

ClaudeSec ships no authenticated runtime service — it is a toolkit (scanner,
hooks, docs). "Security" here means keeping the repo and its outputs clean and
keeping security advice authoritative.

### Secrets & sensitive data in the repo

- CI enforces secret hygiene with **gitleaks** and **GitGuardian**; a
  **pii-check** job blocks personal data. Keep them green.
- Never commit real paths, hostnames, IPs, account IDs, emails, or secrets.
  Use placeholders (`~/.kube/config`, `your-api-key-here`).
- `.claudesec.yml` is gitignored; users copy from `templates/*.example.yml` and
  fill local paths locally only.
- When user input contains a secret, mask it — never echo it back verbatim.

### Authoritative sourcing

- Every security claim in docs must cite OWASP, NIST, or CIS.
- LLM/AI security guidance should reference MITRE ATLAS where relevant.

### Compliance scope

- Compliance guides target **NIST, ISO 27001, and ISMS-P** (see
  `docs/compliance/`). Run the `compliance-check` skill for gap analysis.

### Scanner & hooks

- Claude Code security hooks live in `hooks/`; least-privilege tool access only.
- The scanner runs against fixture projects offline — never point CI at a real
  external target without explicit authorization.
