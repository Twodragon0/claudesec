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
| `/security-review` | Pre-commit security review of staged changes |
| `/hotfix` | Rapid security hotfix workflow |
| `/pipeline-review` | Review and validate CI/CD pipeline security |
| `/scanner-feature` | Guided workflow for adding a new scanner check |
| `/new-guide` | Scaffold a new DevSecOps guide document |
| `/compliance-check` | Run compliance mapping and gap analysis |

## Project Architecture

```
claudesec/                          # v0.6.5 — npm: claudesec
├── scanner/                        # Security scanner CLI (bash, 1029 lines)
│   ├── claudesec                   # Main entrypoint (bash)
│   ├── checks/                     # Check modules by category (11 dirs)
│   │   ├── access-control/         # IAM, SSO, MFA checks
│   │   ├── ai/                     # AI/LLM security, prompt injection
│   │   ├── cicd/                   # GitHub Actions, Jenkins, secrets
│   │   ├── cloud/                  # AWS, GCP, Azure posture
│   │   ├── code/                   # Static analysis, code injection
│   │   ├── infra/                  # Docker, Kubernetes, IaC
│   │   ├── macos/                  # macOS endpoint checks
│   │   ├── network/                # TLS, firewall, DNS
│   │   ├── prowler/                # Prowler OCSF integration
│   │   ├── saas/                   # Third-party integrations, API security
│   │   └── windows/                # Windows endpoint checks
│   ├── lib/                        # Shared libraries
│   │   ├── checks.sh               # Core check functions (906 lines)
│   │   ├── output.sh               # Output formatting
│   │   ├── dashboard-gen.py        # Dashboard HTML generator
│   │   ├── dashboard-template.html # Dashboard HTML template
│   │   ├── compliance-map.py       # ISMS-P / ISO / NIST mapping
│   │   ├── audit-points-scan.py    # Audit evidence collector
│   │   ├── diagram-gen.py          # Architecture diagram generator
│   │   ├── dashboard_api_client.py # Datadog API client
│   │   ├── dashboard_auth.py       # Authentication helpers
│   │   ├── dashboard_data_loader.py# Dashboard data loading
│   │   ├── dashboard_mapping.py    # Check-to-control mapping
│   │   ├── dashboard_utils.py      # Dashboard utilities
│   │   ├── csp_utils.py            # CSP header helpers
│   │   └── zscaler-api.py          # Zscaler ZIA API client
│   └── tests/                      # Unit and integration tests
│       ├── test_check_access_control.sh
│       ├── test_check_cicd_pipeline.sh
│       ├── test_check_code_injection.sh
│       ├── test_check_infra_docker.sh
│       ├── test_check_network_tls.sh
│       ├── test_compliance_map.py
│       ├── test_dashboard_gen_smoke.py
│       ├── test_kube_discovery.sh
│       ├── test_markdown_preview.py
│       ├── test_output_functions.sh
│       ├── test_prowler_ocsf.py
│       ├── test_prowler_ocsf_e2e.py
│       ├── test_run_full_dashboard_options.py
│       └── test_token_expiry_gate.py
├── scripts/                        # Automation scripts
│   ├── hourly-automation.sh        # Hourly cron entrypoint
│   ├── build-dashboard.py          # Dashboard build pipeline
│   ├── asset-gsheet-sync.py        # Google Sheets asset sync
│   ├── full-asset-sync.py          # Full asset synchronization
│   ├── collect-assets.sh           # Asset collection (Jamf, AWS, etc.)
│   ├── isms-p-report.py            # ISMS-P compliance report generator
│   ├── sync-notion-audits-mcp.py   # Notion audit sync (MCP)
│   ├── sync-cost-xlsx.py           # Cost data Excel sync
│   ├── sync-scan-to-dashboard.sh   # Scan result → dashboard pipeline
│   ├── run-dashboard-safe.sh       # Safe dashboard runner
│   ├── run-dashboard-docker.sh     # Docker-based dashboard runner
│   ├── run-full-dashboard.sh       # Full dashboard with all integrations
│   ├── run-scan.sh                 # Scanner runner
│   ├── run-scan-docker.sh          # Docker-based scanner runner
│   ├── run-prowler-k8s.sh          # Prowler on Kubernetes
│   ├── token-expiry-gate.py        # Token expiry enforcement
│   ├── update-license-active-accounts.py
│   ├── update-pc-sheet.py          # PC inventory sheet update
│   ├── gsheet-auth.py              # Google Sheets OAuth
│   ├── gsheet-auth-setup.py        # Google Sheets auth setup
│   ├── github-setup-labels.sh      # GitHub label setup
│   ├── lint-shell.sh               # Shell linting wrapper
│   ├── quick-start.sh              # Quick onboarding script
│   └── setup.sh                    # Full environment setup
├── hooks/                          # Claude Code security hooks
│   ├── pii-check.sh                # PII detection pre-commit hook
│   ├── secret-check.sh             # Secret/credential detection hook
│   ├── security-lint.sh            # Security linting hook
│   └── README.md
├── templates/                      # Reusable config templates
│   ├── claudesec.example.yml       # Base scanner config
│   ├── claudesec-network.example.yml
│   ├── claudesec-prowler-k8s.example.yml
│   ├── claudesec-prowler-multiprovider.example.yml
│   ├── claudesec-saas-integrations.example.yml
│   ├── codeql.yml                  # CodeQL GitHub Actions template
│   ├── dependabot.yml              # Dependabot config template
│   ├── dependency-review.yml       # Dependency review workflow
│   ├── security-scan-suite.yml     # Full security scan CI suite
│   ├── prowler.yml                 # Prowler CI template
│   ├── sbom.yml                    # SBOM generation workflow
│   ├── scorecard.yml               # OpenSSF Scorecard workflow
│   ├── hourly.cron                 # Cron schedule template
│   ├── ir-contacts.yml             # Incident response contacts
│   ├── zap-rules.tsv               # OWASP ZAP rule config
│   └── SECURITY.md                 # Security policy template
├── docs/                           # Documentation
│   ├── devsecops/                  # DevSecOps pipeline and practices
│   ├── github/                     # GitHub security features
│   ├── ai/                         # AI and LLM security
│   ├── compliance/                 # NIST CSF 2.0, ISO 27001, ISO 42001, ISMS-P
│   ├── architecture/               # Architecture and flow diagrams
│   ├── reports/                    # Report templates and samples
│   └── guides/                     # Step-by-step tutorials
│       ├── claude-lead-agents-and-best-practices.md
│       ├── getting-started.md
│       ├── hourly-operations.md
│       ├── incident-response.md
│       ├── compliance-mapping.md
│       ├── saas-best-practices-scans.md
│       ├── shell-lint-policy.md
│       ├── workflow-components.md
│       └── zscaler-zia-datadog.md
├── assets/                         # Branding assets
│   ├── claudesec-logo.png
│   ├── claudesec-logo-512.png
│   ├── claudesec-mascot.svg
│   └── asset-dashboard-arch.svg
├── bin/
│   └── claudesec-cli.sh            # npm bin entrypoint
├── .claude/
│   ├── agents/                     # Agent definition files
│   ├── commands/                   # Slash command definitions
│   └── rules/                      # Coding, security, git, testing rules
├── nginx/                          # Nginx config for dashboard serving
├── Dockerfile                      # Scanner image
├── Dockerfile.nginx                # Nginx dashboard image
├── docker-compose.yml              # Full stack compose
├── docker-compose.quickstart.yml   # Quick-start compose
├── package.json                    # npm package (v0.6.5)
├── static-analysis.datadog.yml     # Datadog static analysis config
└── scan-report.json                # Latest scan report output
```

## Scanner Usage

```bash
# Install via npm
npm install -g claudesec

# Or run directly
./scanner/claudesec scan
./scanner/claudesec scan --category network
./scanner/claudesec scan --format json --severity high
./scanner/claudesec scan --all
./scanner/claudesec report --output report.json
./scanner/claudesec init
./scanner/claudesec version

# Via npm scripts
npm run scan
npm run dashboard
npm run setup
npm run quickstart    # Docker quick-start
npm test              # pytest scanner/tests/
```

## Key Integration Points

| Integration | Purpose | Config |
|-------------|---------|--------|
| Datadog API | Infrastructure monitoring, SIEM signals, static analysis | `DD_API_KEY`, `DD_APP_KEY` |
| Google Sheets | Asset registry (PC, Software, Users) | `ASSET_SHEET_ID`, `AI_SHEET_ID` |
| Notion API | Security audit evidence history (MCP sync) | `NOTION_TOKEN`, `NOTION_DB_ID` |
| Prowler | Cloud security posture (AWS, multi-provider, K8s) | AWS credentials |
| Jamf Pro | macOS endpoint inventory | `JAMF_URL`, `JAMF_TOKEN` |
| SentinelOne | Endpoint threat detection | Via Datadog logs |
| AWS CLI | Infrastructure inventory (EC2, RDS, EKS) | AWS profile |
| Zscaler ZIA | Network security posture | `ZSCALER_API_KEY` |

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
- Markdown files: YAML frontmatter with title, description, tags.

## CI/CD Pipeline

- **Lint**: ShellCheck, markdownlint, link-check (lychee), scanner unit tests
- **Dashboard Regression**: Docker build → scan → dashboard generation → Lighthouse accessibility
- **npm Publish**: Trusted Publishers (OIDC) with SLSA provenance on tag push
- **Security Scan**: CodeQL (GitHub default setup), Dependabot, dependency-review, OpenSSF Scorecard

See [docs/guides/claude-lead-agents-and-best-practices.md](docs/guides/claude-lead-agents-and-best-practices.md) for full best practices and Cursor rules alignment.

## Project Agents (`.claude/agents/`)

These agent definition files provide specialized roles for Claude Code:

| Agent File | Model | Role |
|-----------|-------|------|
| `sec-orchestrator.md` | opus | 프로젝트 조율, 보안 워크플로우 관리 |
| `sec-researcher.md` | sonnet | 보안 리서치, 위협 분석 |
| `sec-implementer.md` | sonnet | 보안 가이드/도구 구현 |
| `sec-reviewer.md` | sonnet | 보안 문서/코드 리뷰 |
| `ci-pipeline.md` | sonnet | GitHub Actions, 보안 스캔 자동화 |

## Slash Commands (`.claude/commands/`)

| Command File | Purpose |
|-------------|---------|
| `scan.md` | Run security scanner |
| `dashboard.md` | Build and serve ISMS dashboard |
| `security-review.md` | Pre-commit staged-changes review |
| `hotfix.md` | Rapid security hotfix workflow |
| `pipeline-review.md` | CI/CD pipeline security review |
| `scanner-feature.md` | Add a new scanner check category |
| `new-guide.md` | Scaffold a new DevSecOps guide |
| `compliance-check.md` | Compliance mapping and gap analysis |

## Claude Code Rules (`.claude/rules/`)

| Rule File | Scope |
|-----------|-------|
| `coding-style.md` | Immutability, file size, error handling, input validation |
| `security.md` | Secret management, mandatory security checks |
| `git-workflow.md` | Conventional commits, PR workflow, branch naming |
| `testing.md` | TDD, 80% coverage minimum, edge case requirements |
| `performance.md` | Model selection (haiku/sonnet/opus), context window management |
| `karpathy-guidelines.md` | Anti-overengineering, surgical changes, goal-driven execution |

## Multi-Agent Workflow Patterns

- **Security Guide**: sec-researcher → sec-implementer → docs-writer → sec-reviewer → test-engineer
- **Scanner Feature**: architect → sec-implementer → test-engineer → ci-pipeline
- **Compliance Doc**: sec-researcher → docs-writer → sec-reviewer → test-engineer
- **Hotfix**: sec-researcher → sec-implementer → sec-reviewer
- **Pipeline Review**: sec-orchestrator coordinates all agents in parallel

## Model Routing

| Model | Use Cases |
|-------|-----------|
| **opus** | sec-orchestrator, architect — coordination, deep security audit, architecture decisions |
| **sonnet** | sec-implementer, sec-researcher, sec-reviewer, ci-pipeline — standard implementation work |
| **haiku** | explore, docs lookup, quick validation — read-only, lightweight tasks |
