---
description: Multi-agent security scan — parallel scan across categories
---
Run a multi-agent security scan using parallel subagents:

1. Launch 3 parallel scan agents:
   - Agent 1: `./scanner/claudesec scan -d . -c code,cicd,access-control` (Code + CI/CD + IAM)
   - Agent 2: `./scanner/claudesec scan -d . -c infra,cloud,network` (Infrastructure)
   - Agent 3: `./scanner/claudesec scan -d . -c ai,saas` (AI/LLM + SaaS)

2. Collect results from all agents

3. Generate unified dashboard:
   `./scanner/claudesec dashboard -d . -c all --no-serve`

4. Summarize combined findings:
   - Total checks across all categories
   - Critical/High findings that need immediate attention
   - Security grade and score
   - Recommend top 3 remediation actions

5. If Prowler results exist in `.claudesec-prowler/`, include cloud security summary

Note: This uses Claude Code's parallel agent execution for faster scanning.
Each category group runs independently, then results are merged.
