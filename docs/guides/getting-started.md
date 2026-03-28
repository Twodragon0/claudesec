---
title: Getting Started with ClaudeSec
description: Quick start guide for integrating ClaudeSec into your project
tags: [getting-started, setup, quickstart]
---

# Getting Started with ClaudeSec

This guide follows the same scanner onboarding anchors as `README.md`.

## Scanner Anchors

- [Scanner Quick Start](#scanner-quick-start)
- [Scanner CI Templates](#scanner-ci-templates)
- [Scanner OAuth & Token Policy](#scanner-oauth--token-policy)
- [Scanner SaaS Live Scan](#scanner-saas-live-scan)

## Scanner Quick Start

### Copy-paste minimal example

```bash
./scripts/run-scan.sh
```

Expected output: security scan starts and creates `scan-report.json` in the project root.

### Prerequisites

- Git
- [Claude Code](https://code.claude.com/docs) CLI
- A project repository to secure

### Clone and run

```bash
git clone https://github.com/Twodragon0/claudesec.git
cd claudesec

./scripts/run-scan.sh
./scanner/claudesec scan -d .
./scanner/claudesec scan --category cloud
./scanner/claudesec scan --severity high,critical
```

## Scanner CI Templates

### Copy-paste minimal example

```bash
./scripts/setup.sh /path/to/project
```

Expected output: workflow templates and reusable actions are copied into the target repository.

### Bootstrap a target repository

```bash
./scripts/setup.sh /path/to/project
```

### Core templates

- `templates/prowler.yml`
- `templates/security-scan-suite.yml`
- `templates/codeql.yml`
- `templates/dependency-review.yml`

### Reusable workflow components

- `.github/actions/token-expiry-gate`
- `.github/actions/datadog-ci-collect`

### CI policy variables

- `CLAUDESEC_STRICT_SSO`
- `CLAUDESEC_TOKEN_EXPIRY_GATE_MODE`
- `CLAUDESEC_TOKEN_EXPIRY_PROVIDERS`
- `CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS`

## Scanner OAuth & Token Policy

### Copy-paste minimal example

```bash
export OKTA_OAUTH_TOKEN="<okta-oauth-access-token>"
./scanner/claudesec scan -c saas
```

Expected output: SaaS checks run with OAuth-first paths; strict mode (if enabled) fails on missing required scopes.

Okta automation should prefer scoped OAuth tokens over SSWS tokens.

- Preferred: `OKTA_OAUTH_TOKEN`
- Fallback: `OKTA_API_TOKEN`
- Strict scope mode: `CLAUDESEC_STRICT_OKTA_SCOPES=1`
- Scope customization: `CLAUDESEC_OKTA_REQUIRED_SCOPES`

```bash
export OKTA_ORG_URL="https://dev-123456.okta.com"
export OKTA_OAUTH_TOKEN="<okta-oauth-access-token>"
export CLAUDESEC_OKTA_REQUIRED_SCOPES="okta.users.read,okta.policies.read,okta.logs.read"
export CLAUDESEC_STRICT_OKTA_SCOPES=1
./scanner/claudesec scan -c saas
```

See [Okta OAuth guidance](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/#about-oauth-2-0-for-okta-api-endpoints).

## Scanner SaaS Live Scan

### Copy-paste minimal example

```bash
./scanner/claudesec dashboard --serve --host 127.0.0.1 --port 11665
```

Expected output: dashboard is generated and served locally at `http://127.0.0.1:11665`.

### SaaS scan + dashboard

```bash
./scanner/claudesec scan -c saas

export GH_TOKEN_EXPIRES_AT="2026-04-30T08:30:00Z"
export OKTA_OAUTH_TOKEN_EXPIRES_AT="2026-04-30T09:00:00Z"
export CLAUDESEC_TOKEN_EXPIRY_WARNING_24H="24h"
export CLAUDESEC_TOKEN_EXPIRY_WARNING_7D="7d"

./scanner/claudesec dashboard --serve --host 127.0.0.1 --port 11665
```

### Optional Datadog local fetch

```bash
DD_API_KEY=<your-dd-api-key> DD_APP_KEY=<your-dd-app-key> DD_SITE=datadoghq.com ./scanner/claudesec dashboard
```

### Kubernetes and Prowler: kubeconfig and OIDC

- **Kubeconfig**: If you do not set `KUBECONFIG` or `kubeconfig` in `.claudesec.yml`, the scanner auto-discovers from conventional paths: `configs/dev/kubeconfig`, `configs/staging/kubeconfig`, `./kubeconfig` (relative to the project). Prefer a relative path in `.claudesec.yml` (e.g. `kubeconfig: configs/dev/kubeconfig`) so the repo stays portable.
- **OIDC / Okta**: If your kubeconfig uses `kubectl oidc-login` (exec auth), run `kubectl get nodes` once to complete browser sign-in, then run `claudesec scan -c prowler` or `claudesec dashboard -c prowler`. The scanner will wait up to 45s for OIDC login when it detects an oidc-login context.

## What's Next?

1. [Workflow Components](./workflow-components.md)
2. [DevSecOps Pipeline Guide](../devsecops/pipeline.md)
3. [Branch Protection](../github/branch-protection.md)
4. [SaaS Best Practices Scans](./saas-best-practices-scans.md)
5. [Shell Lint Policy](./shell-lint-policy.md)

## References

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
