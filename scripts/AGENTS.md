# AGENTS.md — scripts/

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 -->

## Purpose

Automation scripts for scan execution, dashboard building, asset collection, and data synchronization. Most scripts are standalone bash or Python 3 — no framework required.

## Key Scripts

| Script | Language | Purpose |
|--------|----------|---------|
| `run-scan.sh` | bash | Run scanner locally |
| `run-scan-docker.sh` | bash | Run scanner in Docker |
| `run-dashboard-safe.sh` | bash | Full scan + serve with port fallback |
| `run-dashboard-docker.sh` | bash | Dashboard workflow in Docker |
| `run-full-dashboard.sh` | bash | Full scan + all integrations + serve |
| `build-dashboard.py` | Python | Collect data from all sources, build HTML |
| `collect-assets.sh` | bash | Collect assets from Jamf, AWS, etc. |
| `asset-gsheet-sync.py` | Python | Sync asset data to Google Sheets |
| `full-asset-sync.py` | Python | Full multi-source sync to Sheets |
| `sync-notion-audits-mcp.py` | Python | Sync audit evidence to Notion (MCP) |
| `sync-scan-to-dashboard.sh` | bash | Pipeline: scan result → dashboard |
| `sync-cost-xlsx.py` | Python | Sync SaaS cost data from Excel |
| `token-expiry-gate.py` | Python | Enforce token expiry before scans |
| `isms-p-report.py` | Python | Generate ISMS-P compliance report |
| `hourly-automation.sh` | bash | Hourly cron: pull + scan + sync |
| `setup.sh` | bash | Install hooks, templates, virtualenv |
| `quick-start.sh` | bash | Docker-first onboarding |
| `lint-shell.sh` | bash | ShellCheck wrapper (local + CI) |
| `gsheet-auth.py` | Python | Google Sheets OAuth helper |
| `update-pc-sheet.py` | Python | PC inventory sheet updater |

## For AI Agents

### Conventions

- Bash scripts: ShellCheck-clean. Run `./scripts/lint-shell.sh` before committing.
- Python scripts: PEP 8. Use `os.getenv()` for all credentials — no hardcoded values.
- Dashboard scripts read from `~/Desktop/.env` for API keys (not committed).
- Output HTML files (`claudesec-dashboard.html`, `claudesec-asset-dashboard.html`) are in `.gitignore`.

### Required Environment Variables

| Variable | Used by |
|----------|---------|
| `DD_API_KEY`, `DD_APP_KEY` | `build-dashboard.py`, `sync-scan-to-dashboard.sh` |
| `ASSET_SHEET_ID`, `AI_SHEET_ID` | `asset-gsheet-sync.py`, `full-asset-sync.py` |
| `NOTION_TOKEN`, `NOTION_DB_ID` | `sync-notion-audits-mcp.py` |
| `JAMF_URL`, `JAMF_TOKEN` | `collect-assets.sh` |
| `GH_TOKEN` / `GITHUB_TOKEN` | `token-expiry-gate.py`, scanner saas checks |

### Running the Dashboard

```bash
# Safe mode (auto port fallback, no Docker required)
./scripts/run-dashboard-safe.sh

# Kill stale process and serve
./scripts/run-dashboard-safe.sh --kill-port

# Docker mode
./scripts/run-dashboard-docker.sh

# Build only, no serve
./scripts/run-full-dashboard.sh --no-serve
```

Dashboard served at `http://localhost:11777/`.
