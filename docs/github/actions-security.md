---
title: GitHub Actions Security
description: Securing your CI/CD workflows against common attack vectors
tags: [github-actions, ci-cd, supply-chain, security]
---

# GitHub Actions Security

## Common Attack Vectors

### 1. Dependency Confusion / Typosquatting

```yaml
# BAD: Unpinned action
- uses: actions/checkout@main

# GOOD: Pin to full SHA
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
```

### 2. Script Injection

{% raw %}

```yaml
# BAD: Directly interpolating user input
- run: echo "Hello ${{ github.event.issue.title }}"

# GOOD: Use environment variable
- env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: echo "Hello $ISSUE_TITLE"
```

{% endraw %}

### 3. Excessive Permissions

```yaml
# BAD: Default broad permissions
permissions: write-all

# GOOD: Least privilege
permissions:
  contents: read
  pull-requests: write
```

## Security Hardening Checklist

### Workflow Permissions

```yaml
# Set restrictive defaults at workflow level
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write  # Only what's needed
```

### Secrets Management

{% raw %}

```yaml
# Use GitHub Environments for secret scoping
jobs:
  deploy:
    environment: production  # Secrets scoped to this environment
    steps:
      - name: Deploy
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./deploy.sh

# NEVER log secrets
      - name: Debug
        run: |
          # BAD: echo ${{ secrets.API_KEY }}
          # GOOD: Verify secret exists without exposing
          if [ -z "$API_KEY" ]; then echo "API_KEY not set"; exit 1; fi
```

{% endraw %}

### Third-Party Actions

```yaml
# Audit strategy for third-party actions:
# 1. Pin to SHA (not tag)
# 2. Fork critical actions to your org
# 3. Use Dependabot for actions updates

- uses: slackapi/slack-github-action@dcb1066f776dd043e64d0e8ba94ca15cc7e1875d # v4.0.0

# Or fork and use your own:
- uses: your-org/slack-github-action@pinned-sha
```

### Self-Hosted Runners

```yaml
# Isolate self-hosted runners
jobs:
  build:
    runs-on: [self-hosted, linux, ephemeral]
    # Use ephemeral runners that reset after each job
    # Never share runners between public and private repos
```

## Secure Workflow Templates

### Minimal Build & Test

```yaml
name: CI
on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version-file: '.nvmrc'
          cache: 'npm'
      - run: npm ci --ignore-scripts
      - run: npm test
```

### Secure Docker Build & Push

{% raw %}

```yaml
name: Docker
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write  # For signing

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          provenance: true
          sbom: true
```

{% endraw %}

## OpenSSF Best Practices

| Practice | Implementation |
|----------|----------------|
| Pin dependencies | SHA-pinned actions + lock files |
| Least privilege | Minimal `permissions` block |
| Audit third-party | Fork or vet all external actions |
| Ephemeral environments | Fresh runners per job |
| Signed artifacts | Sigstore/cosign for images |
| SBOM generation | `--sbom=true` in builds |
| Branch protection | Required status checks |

## References

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/reference/security/secure-use)
- [OpenSSF Secure Supply Chain Best Practices](https://best.openssf.org/)
- [StepSecurity — Harden Runner](https://github.com/step-security/harden-runner)
- [OWASP CI/CD Security Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [NIST SP 800-53 SA-11: Developer Testing and Evaluation](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-11)
- [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/insights/white-papers/cis-software-supply-chain-security-guide)
