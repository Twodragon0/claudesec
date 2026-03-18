# Privacy Policy — ClaudeSec

**Last updated: 2026-03-18**

## Overview

ClaudeSec is an open-source DevSecOps toolkit that runs entirely on your local machine. We do not collect, store, or transmit any personal data.

## Data Processing

- **All scans run locally** — ClaudeSec processes files only on your machine or within Docker containers you control.
- **No telemetry** — ClaudeSec does not phone home, send analytics, or track usage.
- **No cloud backend** — There is no ClaudeSec server. All data stays on your infrastructure.

## Third-Party Integrations (User-Configured)

ClaudeSec can optionally integrate with services you configure via environment variables:

| Service | Data Sent | Purpose |
|---------|-----------|---------|
| **Datadog API** | API calls to your Datadog account | Infrastructure monitoring data collection |
| **Google Sheets API** | Reads/writes to your spreadsheets | Asset management registry sync |
| **Notion API** | Reads from your workspace | Security audit history |
| **AWS CLI** | Uses your AWS credentials | Infrastructure inventory |
| **Prowler** | Runs in your environment | Cloud security posture scanning |

These integrations are **opt-in** and use **your own API keys**. ClaudeSec never proxies or stores credentials.

## Scan Results

- Scan reports (`scan-report.json`, `claudesec-dashboard.html`) are generated locally.
- The `.gitignore` excludes scan results from version control by default.
- No findings are uploaded to any external service.

## Contact

For privacy questions: [GitHub Issues](https://github.com/Twodragon0/claudesec/issues)

## Changes

This policy may be updated as the project evolves. Changes will be noted in commit history.
