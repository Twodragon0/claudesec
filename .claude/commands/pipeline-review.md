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
4. **ci-pipeline** — Check .github/workflows/ for security scanning coverage gaps.
   If a CI _test-coverage_ gate is red (`scanner-shell-coverage` kcov, or
   `scanner-unit-tests` pytest), route into the `/kcov-debug` playbook to diagnose
   before proposing a fix.

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

## See also

- `/kcov-debug` — coverage-gate debugging playbook (kcov bash / pytest
  `scanner/lib` hangs, missing `coverage.json`, floor-below-threshold). Use when
  the `ci-pipeline` step finds a red coverage CI job.
