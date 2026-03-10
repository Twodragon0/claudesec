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
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

### 2. Script Injection

```yaml
# BAD: Directly interpolating user input
- run: echo "Hello ${{ github.event.issue.title }}"

# GOOD: Use environment variable
- env:
    ISSUE_TITLE: ${{ github.event.issue.title }}
  run: echo "Hello $ISSUE_TITLE"
```

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

### Third-Party Actions

```yaml
# Audit strategy for third-party actions:
# 1. Pin to SHA (not tag)
# 2. Fork critical actions to your org
# 3. Use Dependabot for actions updates

- uses: slackapi/slack-github-action@6c661ce58804a1a20f6dc5fbee7f0381b469e001 # v1.25.0

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
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4
        with:
          node-version-file: '.nvmrc'
          cache: 'npm'
      - run: npm ci --ignore-scripts
      - run: npm test
```

### Secure Docker Build & Push

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
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
          provenance: true
          sbom: true
```

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

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OpenSSF Secure Supply Chain Best Practices](https://best.openssf.org/)
- [StepSecurity — Harden Runner](https://github.com/step-security/harden-runner)
