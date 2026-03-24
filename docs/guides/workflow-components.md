---
title: Workflow Components
description: Reusable composite actions for ClaudeSec CI/CD workflow templates
tags: [ci-cd, github-actions, workflow, security]
---

# Workflow Components

ClaudeSec workflow templates share reusable composite actions to reduce duplication and keep policy behavior consistent.

## Components

| Component | Path | Purpose |
|---|---|---|
| Token Expiry Gate | `.github/actions/token-expiry-gate` | Enforce token expiry window policy before downstream security jobs run |
| Datadog CI Collect | `.github/actions/datadog-ci-collect` | Collect and sanitize Datadog CI logs/signals/cases for dashboard artifacts |

## Token Expiry Gate Contract

- Action path: `.github/actions/token-expiry-gate`
- Backing script: `scripts/token-expiry-gate.py`
- Typical inputs:
  - `providers` (`github,okta,datadog,slack`)
  - `strict-providers` (`true`/`false`)
  - `gate-mode` (`24h`/`7d`/`off`)
  - per-provider expiry metadata values

### Policy Variables

- `CLAUDESEC_TOKEN_EXPIRY_GATE_MODE`
- `CLAUDESEC_TOKEN_EXPIRY_PROVIDERS`
- `CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS`
- `GH_TOKEN_EXPIRES_AT`, `GITHUB_TOKEN_EXPIRES_AT`
- `OKTA_OAUTH_TOKEN_EXPIRES_AT`
- `DATADOG_TOKEN_EXPIRES_AT`, `DD_TOKEN_EXPIRES_AT`, `DD_API_KEY_EXPIRES_AT`
- `SLACK_TOKEN_EXPIRES_AT`, `SLACK_BOT_TOKEN_EXPIRES_AT`
- `CLAUDESEC_DD_ARTIFACT_RETENTION_DAYS` (used by `templates/security-scan-suite.yml` Datadog artifact upload, valid range: 1-90)

## Datadog CI Collect Contract

- Action path: `.github/actions/datadog-ci-collect`
- Used by templates:
  - `templates/prowler.yml`
  - `templates/security-scan-suite.yml` (conditional)
- Produces sanitized artifacts in `.claudesec-datadog/`:
  - `datadog-logs-sanitized.json`
  - `datadog-cloud-signals-sanitized.json`
  - `datadog-cases-sanitized.json`
- Input keys:
  - `dd-api-key`, `dd-app-key`
  - `dd-site`, `dd-service`, `dd-env`
  - `ci-pipeline-id`, `dd-tags`

## Setup Integration

`scripts/setup.sh` copies both composite actions and `scripts/token-expiry-gate.py` to target repositories:

- `.github/actions/token-expiry-gate/action.yml`
- `.github/actions/datadog-ci-collect/action.yml`
- `scripts/token-expiry-gate.py`

## References

- [NIST SP 800-53 SA-15: Development Process, Standards, and Tools](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-15)
- [OWASP CI/CD Security Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
