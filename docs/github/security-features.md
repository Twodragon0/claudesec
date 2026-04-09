---
title: GitHub Security Features
description: Comprehensive guide to GitHub's built-in security tools
tags: [github, dependabot, code-scanning, secret-scanning, security]
---

# GitHub Security Features

## Overview

GitHub provides a layered security toolkit. This guide covers setup and best practices for each feature.

## 1. Dependabot

### Dependency Alerts

Automatically enabled for public repos. For private repos:

**Settings → Code security and analysis → Dependabot alerts → Enable**

### Dependabot Updates

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    # Group minor/patch updates to reduce PR noise
    groups:
      production-dependencies:
        patterns:
          - "*"
        exclude-patterns:
          - "@types/*"
          - "eslint*"
        update-types:
          - "minor"
          - "patch"

  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### Version Pinning Strategy

| Dependency Type | Strategy | Rationale |
|-----------------|----------|-----------|
| Direct production | Pin exact (`1.2.3`) | Reproducible builds |
| Dev tooling | Pin minor (`^1.2.0`) | Auto-patch updates OK |
| GitHub Actions | Pin SHA | Prevent supply chain attacks |

## 2. Code Scanning (CodeQL)

{% raw %}
```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: ['javascript', 'python']
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: +security-extended
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```
{% endraw %}

### Custom CodeQL Queries

```ql
/**
 * @name Hardcoded credentials
 * @description Finds hardcoded passwords and API keys
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @id js/hardcoded-credentials
 */
import javascript

from StringLiteral s
where s.getValue().regexpMatch("(?i)(password|api_key|secret)\\s*[:=]\\s*['\"][^'\"]+['\"]")
select s, "Possible hardcoded credential"
```

## 3. Secret Scanning

### Default Patterns

GitHub scans for 200+ secret types from partners (AWS, Azure, GCP, Stripe, etc.).

### Custom Patterns

**Settings → Code security → Secret scanning → Custom patterns**

```regex
# Internal API key format
company_api_[a-zA-Z0-9]{32}

# Internal service tokens
svc-token-[a-f0-9]{64}
```

### Push Protection

Blocks pushes containing detected secrets. Enable via:

**Settings → Code security → Secret scanning → Push protection → Enable**

```bash
# If legitimately blocked, you can:
# 1. Remove the secret and use environment variables
# 2. Mark as false positive (with justification)
# 3. Mark as used in tests (test credentials only)
```

## 4. Security Policies

### SECURITY.md

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | Security fixes only |
| < 1.0   | No        |

## Reporting a Vulnerability

1. **Do NOT open a public issue**
2. Use [GitHub Private Vulnerability Reporting](../../security/advisories/new)
3. Or email: security@example.com
4. Expected response time: 48 hours
5. Expected fix time: 7 days for critical, 30 days for others
```

## 5. Branch Protection

See [Branch Protection & CODEOWNERS](branch-protection.md) for detailed setup.

## Security Scorecard

Use OpenSSF Scorecard to assess your repository:

```yaml
- name: OSSF Scorecard
  uses: ossf/scorecard-action@v2
  with:
    results_file: results.sarif
    results_format: sarif
    publish_results: true
```

## References

- [GitHub Security Documentation](https://docs.github.com/en/code-security)
- [GitHub Advisory Database](https://github.com/advisories)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [NIST SP 800-53 RA-5: Vulnerability Monitoring and Scanning](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=RA-5)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
