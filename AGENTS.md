# ClaudeSec Agent Charter

Lead agent roles and practices for Claude/Cursor work in this repo. Full guide: [Claude Lead Agents and Best Practices](docs/guides/claude-lead-agents-and-best-practices.md).

## Lead Agent Roles

| Role | Responsibility |
|------|----------------|
| **Lead Orchestrator** | Task decomposition, assignment, priorities, final acceptance. Resolves conflicts. |
| **Researcher** | Code evidence and external refs (OWASP, NIST, CIS). Evidence before edits. |
| **Implementer** | Code/docs changes, verification. Single owner per task. |
| **Reviewer** | Correctness, security risk, regression. Proposes options; Lead finalizes. |

## Handoff Format

```txt
[Task] Goal: / Scope: / Constraints:
[Done] Files Changed: / Key Changes: / Validation:
[Open] Risks: / Next Actions:
```

## Principles

- Single owner per task; verify every change.
- Security advice: cite sources; no PII/paths/secrets in repo.
- Small, reviewable increments; Reviewer sign-off before merge.

See [docs/guides/claude-lead-agents-and-best-practices.md](docs/guides/claude-lead-agents-and-best-practices.md) for full best practices and Cursor rules alignment.
