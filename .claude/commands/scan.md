---
description: Run ClaudeSec security scan on the current project
---
Run the ClaudeSec scanner on the current directory:
1. Execute `./scanner/claudesec scan -d . -c all`
2. Parse the scan-report.json results
3. Show a summary of findings (critical, high, medium, warning)
4. For any critical/high findings, explain the issue and recommend remediation
