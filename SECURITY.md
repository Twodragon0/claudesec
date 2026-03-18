# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.6.x   | :white_check_mark: Current |
| 0.5.x   | :white_check_mark: Security fixes only |
| < 0.5   | :x: End of life |

## Reporting a Vulnerability

If you discover a security vulnerability in ClaudeSec, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisory** (preferred): Use the [Report a Vulnerability](https://github.com/Twodragon0/claudesec/security/advisories/new) page.
2. **GitHub Issues** (non-sensitive): For low-severity issues that do not expose exploit details, you may open a [GitHub Issue](https://github.com/Twodragon0/claudesec/issues) with the `security` label.

### What to Include

- Description of the vulnerability and its potential impact
- Steps to reproduce (PoC if possible)
- Affected version(s) and component(s)
- Suggested fix (if any)

### Response Timeline

| Stage | SLA |
|-------|-----|
| Acknowledgement | Within 48 hours |
| Triage and severity assessment | Within 7 days |
| Fix development | Based on severity (Critical: 7 days, High: 14 days, Medium: 30 days) |
| Coordinated disclosure | After fix is released, in agreement with reporter |

### Severity Classification

We follow [CVSS v3.1](https://www.first.org/cvss/) for severity scoring:

| Severity | CVSS Score | Examples |
|----------|------------|----------|
| Critical | 9.0–10.0 | Remote code execution, credential exposure |
| High | 7.0–8.9 | Command injection, privilege escalation |
| Medium | 4.0–6.9 | Information disclosure, path traversal |
| Low | 0.1–3.9 | Minor information leak, verbose errors |

## Scope

### In Scope

- Security scanner code (`scanner/`)
- Docker images and build pipeline (`Dockerfile`, `docker-compose.yml`)
- Configuration templates (`templates/`)
- Automation scripts (`scripts/`) and hooks (`hooks/`)
- GitHub Actions workflows (`.github/workflows/`)
- Claude Code slash commands (`.claude/commands/`)
- npm package distribution (`package.json`, `bin/`)
- Documentation that provides incorrect or dangerous security advice

### Out of Scope

- Vulnerabilities in upstream dependencies (report to the upstream project; we monitor via Dependabot and `npm audit`)
- Issues in example projects that are intentionally insecure for demonstration purposes
- Social engineering or phishing attacks
- Denial of service against GitHub infrastructure

## Security Measures

ClaudeSec implements the following security controls:

### Supply Chain

- Pinned GitHub Actions with full SHA hashes
- Dependabot automatic dependency updates
- `dependency-review-action` blocks high-severity CVEs and GPL/AGPL licenses on PRs
- `npm audit` gate in CI pipeline
- SLSA provenance attestation for npm packages (via Trusted Publishers)

### Code Quality

- **gitleaks** — secret scanning on every push
- **PII detection hook** — blocks hardcoded user paths, account IDs, service credentials
- **ShellCheck** — static analysis for shell scripts
- **CodeQL** — GitHub default code scanning
- **pre-commit hooks** — gitleaks + PII + ShellCheck locally

### Runtime

- Docker images run as non-root user (uid 1000)
- No telemetry, no cloud backend, no data exfiltration
- All sensitive configuration via environment variables (never hardcoded)
- Scan results excluded from version control via `.gitignore`

### Branch Protection

- Required status checks: shell-lint, pii-check, gitleaks, scanner-unit-tests, markdown-lint
- Required pull request reviews (1 approver)
- Admin enforcement enabled

## Recognition

We appreciate responsible disclosure and will credit reporters in the release notes unless anonymity is requested. Significant findings may be acknowledged in the project README.
