---
description: Full DevSecOps pipeline review with coordinated multi-agent analysis
---
Run a comprehensive DevSecOps pipeline review using parallel agents:

## Workflow (coordinated by sec-orchestrator)

### Parallel Analysis Phase
Launch these agents simultaneously:

1. **sec-researcher** — Analyze current threat landscape relevant to this project
2. **architect** — Review pipeline design for gaps in docs/architecture/
3. **sec-reviewer** — Audit existing documentation for accuracy and completeness
4. **ci-pipeline** — Check .github/workflows/ for security scanning coverage gaps

### Sequential Fix Phase
Based on findings:

5. **sec-implementer** — Implement fixes: update scanner rules, hooks, templates
6. **test-engineer** — Validate all changes pass quality gates

### Output
Produce a structured report:
- Pipeline coverage matrix (SAST, DAST, SCA, secrets, container, IaC)
- Gap analysis with priority ranking
- Remediation actions taken
- Remaining items for manual follow-up
