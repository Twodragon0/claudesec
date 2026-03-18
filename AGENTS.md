# ClaudeSec Agent Charter

Lead agent roles and practices for Claude/Cursor work in this repo. Full guide: [Claude Lead Agents and Best Practices](docs/guides/claude-lead-agents-and-best-practices.md).

## Lead Agent Roles

| Role | Responsibility |
|------|----------------|
| **Lead Orchestrator** | Task decomposition, assignment, priorities, final acceptance. Resolves conflicts. |
| **Researcher** | Code evidence and external refs (OWASP, NIST, CIS). Evidence before edits. |
| **Implementer** | Code/docs changes, verification. Single owner per task. |
| **Reviewer** | Correctness, security risk, regression. Proposes options; Lead finalizes. |

## Claude Code Slash Commands

| Command | Description |
|---------|-------------|
| `/scan` | Run ClaudeSec security scanner on the project |
| `/dashboard` | Build and serve the security dashboard |
| `/audit` | Comprehensive security audit with multi-agent scan |
| `/team-scan` | Parallel multi-agent security scan |
| `/security-review` | Pre-commit security review of staged changes |

## Project Architecture

```
claudesec/
├── scanner/           # Security scanner CLI (bash + python)
│   ├── claudesec      # Main scanner entrypoint
│   ├── lib/           # Dashboard generators, compliance maps
│   └── tests/         # Unit tests (bash + python)
├── scripts/           # Automation (Docker, build, data collection)
├── docs/              # Documentation (DevSecOps, AI security, compliance)
├── hooks/             # Claude Code security hooks
├── .claude/commands/  # Slash commands for Claude Code
├── templates/         # Reusable config templates
└── examples/          # Example projects and configs
```

## Key Integration Points

| Integration | Purpose | Config |
|-------------|---------|--------|
| Datadog API | Infrastructure monitoring, SIEM signals | `DD_API_KEY`, `DD_APP_KEY` |
| Google Sheets | Asset registry (PC, Software, Users) | `ASSET_SHEET_ID`, `AI_SHEET_ID` |
| Notion API | Security audit evidence history | `NOTION_TOKEN`, `NOTION_DB_ID` |
| Prowler | Cloud security posture (AWS) | AWS credentials |
| Jamf Pro | macOS endpoint inventory | `JAMF_URL`, `JAMF_TOKEN` |
| SentinelOne | Endpoint threat detection | Via Datadog logs |
| AWS CLI | Infrastructure inventory (EC2, RDS, EKS) | AWS profile |

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
- All sensitive IDs (Sheet IDs, AWS account IDs) via environment variables only.
- Timestamps in KST (UTC+9) for consistency.

## CI/CD Pipeline

- **Lint**: ShellCheck, markdownlint, link-check, scanner unit tests
- **Dashboard Regression**: Docker build → scan → dashboard generation → Lighthouse accessibility
- **npm Publish**: Trusted Publishers (OIDC) with SLSA provenance on tag push
- **Security Scan**: CodeQL (GitHub default setup)

See [docs/guides/claude-lead-agents-and-best-practices.md](docs/guides/claude-lead-agents-and-best-practices.md) for full best practices and Cursor rules alignment.
