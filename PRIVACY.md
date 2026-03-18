# Privacy Policy — ClaudeSec

**Last updated: 2026-03-18**

## Overview

ClaudeSec is an open-source DevSecOps toolkit that runs entirely on your local machine or within Docker containers you control. We do not collect, store, or transmit any personal data.

## Data Processing

- **All scans run locally** — ClaudeSec processes files only on your machine or within Docker containers you control.
- **No telemetry** — ClaudeSec does not phone home, send analytics, or track usage.
- **No cloud backend** — There is no ClaudeSec server. All data stays on your infrastructure.
- **No user accounts** — ClaudeSec does not require registration or authentication.

## npm Package

When installed via `npx claudesec` or `npm install claudesec`:

- The npm registry logs standard download metadata (IP, user-agent) per [npm's privacy policy](https://docs.npmjs.com/policies/privacy).
- ClaudeSec itself does not send any data after installation.
- SLSA provenance attestation is attached to published packages for supply chain verification.

## Docker Images

- Docker images are built from public base images (Alpine Linux).
- No data is collected or transmitted by the container runtime.
- Scan results stay within the container or mounted volumes you control.

## Third-Party Integrations (User-Configured)

ClaudeSec can optionally integrate with services you configure via environment variables. These integrations are **opt-in** and use **your own API keys**. ClaudeSec never proxies or stores credentials.

| Service | Data Flow | Purpose |
|---------|-----------|---------|
| **Datadog API** | Reads from your Datadog account | Infrastructure monitoring, SIEM signals |
| **Google Sheets API** | Reads/writes to your spreadsheets | Asset management registry sync |
| **Notion API** | Reads from your workspace | Security audit evidence history |
| **AWS CLI** | Uses your AWS credentials | Infrastructure inventory (EC2, RDS, EKS) |
| **Prowler** | Runs in your environment | Cloud security posture scanning |
| **Jamf Pro API** | Reads from your Jamf instance | macOS endpoint inventory |
| **Microsoft Intune** | Reads from your Intune tenant | Windows endpoint compliance |

## Scan Results

- Scan reports (`scan-report.json`, `claudesec-dashboard.html`) are generated locally.
- The `.gitignore` excludes scan results from version control by default.
- No findings are uploaded to any external service unless you configure it.
- Dashboard files contain scan metadata only — no source code or file contents.

## PII Protection

ClaudeSec includes built-in safeguards to prevent accidental PII exposure:

- **PII detection hook** (`hooks/pii-check.sh`) — scans for hardcoded user paths, account IDs, and email addresses before commit.
- **gitleaks** — scans for secrets and credentials in code and git history.
- **`.mailmap`** — normalizes git author identities to prevent name exposure.
- **Environment variables** — all sensitive IDs (Sheet IDs, AWS accounts, API keys) are loaded from environment variables, never hardcoded.

## Contact

For privacy questions: [GitHub Issues](https://github.com/Twodragon0/claudesec/issues)

## Changes

This policy may be updated as the project evolves. Changes will be noted in commit history and release notes.
