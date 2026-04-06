---
description: Run ClaudeSec security scan on the current project
---
Run the ClaudeSec scanner on the current directory:

1. Execute `./scanner/claudesec scan -d . -c all`

2. Parse scan-report.json and show a summary:
   - Total checks, passed, failed, warnings
   - Security grade and score
   - Findings broken down by severity (critical, high, medium, warning)

3. For any critical/high findings, explain the issue and recommend remediation

4. If Prowler results exist in `.claudesec-prowler/`, include a cloud security summary

5. Suggest next steps based on findings

---

**Parallel scanning (faster):** For large repositories, use 3 subagents in parallel:
- Agent 1: `./scanner/claudesec scan -d . -c code,cicd,access-control` (Code + CI/CD + IAM)
- Agent 2: `./scanner/claudesec scan -d . -c infra,cloud,network` (Infrastructure)
- Agent 3: `./scanner/claudesec scan -d . -c ai,saas` (AI/LLM + SaaS)

Collect results from all agents, then generate unified dashboard:
`./scanner/claudesec dashboard -d . -c all --no-serve`
