# Security Policy

## Supported Versions

<!-- Update this table for your project -->

| Version | Supported |
|---------|-----------|
| x.y.z   | Yes — current release |
| x.y-1.z | Security fixes only |
| < x.y-1 | No |

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability:

1. **Do NOT open a public issue**
2. Use [GitHub Private Vulnerability Reporting](https://github.com/YOUR_ORG/YOUR_REPO/security/advisories/new)

### What to Include

- Description of the vulnerability and potential impact
- Steps to reproduce (PoC if possible)
- Affected version(s) and component(s)
- Suggested fix (if any)

### Response Timeline

| Severity | Acknowledgement | Fix SLA |
|----------|-----------------|---------|
| Critical (CVSS 9.0+) | 24 hours | 7 days |
| High (CVSS 7.0–8.9) | 48 hours | 14 days |
| Medium (CVSS 4.0–6.9) | 1 week | 30 days |
| Low (CVSS 0.1–3.9) | 2 weeks | 60 days |

### Recognition

We credit reporters in our security advisories and release notes (unless you prefer anonymity).

## Security Measures

This project implements:

- Dependency scanning via Dependabot
- Code scanning via CodeQL
- Secret scanning with push protection (gitleaks)
- PII detection hooks (pre-commit)
- Required code review for security-sensitive changes
- Pinned GitHub Actions with full SHA hashes
- `dependency-review-action` to block high-severity CVEs on PRs
- SLSA provenance for published packages

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
