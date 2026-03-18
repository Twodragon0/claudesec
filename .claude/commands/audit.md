---
description: Run a comprehensive security audit with ClaudeSec + Prowler
---
Run a comprehensive security audit:
1. Run ClaudeSec scan: `./scanner/claudesec scan -d . -c all`
2. Check for Prowler results in `.claudesec-prowler/`
3. Generate the dashboard: `./scanner/claudesec dashboard -d . --no-serve`
4. Parse scan-report.json and summarize:
   - Total checks, passed, failed, warnings
   - Security grade and score
   - Top critical/high findings with remediation
   - Compliance framework mapping (if --compliance flag was used)
5. Suggest next steps based on findings
