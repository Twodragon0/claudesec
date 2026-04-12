# AGENTS.md — ClaudeSec

<!-- Generated: 2026-04-08 -->

## Purpose

ClaudeSec is a DevSecOps toolkit for AI-assisted secure development. It provides a zero-dependency bash security scanner (~120+ checks across 11 categories), an ISMS PDCA dashboard, asset management integrations, and reusable CI/CD templates — all designed to integrate with Claude Code workflows.

npm: `claudesec` — version 0.7.1

## Tech Stack

- **Scanner**: Bash (zero external dependencies), Python 3 (dashboard, compliance mapping)
- **Dashboard**: Python 3, HTML/JS (single-file output), nginx (Docker serve)
- **CI/CD**: GitHub Actions, Prowler, CodeQL, Semgrep, Trivy, Gitleaks, OSV-Scanner
- **Integrations**: Datadog, Google Sheets, Notion, Jamf Pro, AWS CLI, Zscaler ZIA
- **Runtime**: Docker, Node.js >=18 (npm package only)

## Directory Structure

```
claudesec/
├── scanner/               # Security scanner CLI (bash entrypoint + check modules)
│   ├── claudesec          # Main CLI entrypoint
│   ├── checks/            # 11 check categories (ai, cicd, cloud, code, infra, ...)
│   ├── lib/               # Shared bash/python helpers (output, dashboard, compliance)
│   └── tests/             # Unit and integration tests (bash + pytest)
├── scripts/               # Automation: scan runners, dashboard builders, asset sync
├── hooks/                 # Claude Code pre-commit and pre-write security hooks
├── templates/             # GitHub Actions workflow templates, example configs
├── docs/                  # DevSecOps guides, compliance docs, AI security, architecture
│   ├── devsecops/         # OWASP, supply chain, cloud/K8s, pipeline, threat modeling
│   ├── ai/                # LLM Top 10, MITRE ATLAS, prompt injection, code review
│   ├── compliance/        # NIST CSF 2.0, ISO 27001/42001, KISA ISMS-P
│   ├── github/            # GitHub security features, branch protection, Actions
│   └── guides/            # Getting started, hourly ops, compliance mapping, workflows
├── assets/                # Logo, mascot, dashboard architecture SVG
├── bin/                   # npm bin entrypoint (claudesec-cli.sh)
├── nginx/                 # nginx config for dashboard serving
├── Dockerfile             # Scanner image
├── Dockerfile.nginx       # Dashboard serving image
├── docker-compose.yml     # Full stack
└── docker-compose.quickstart.yml
```

## Quick Start

```bash
# No install
npx claudesec scan
npx claudesec dashboard

# From clone
./run                          # Full scan + dashboard + serve (localhost:11777)
./run --quick                  # Quick 3-category scan
./run --docker                 # Docker mode
npm test                       # pytest scanner/tests/

# Scanner direct
./scanner/claudesec scan
./scanner/claudesec scan --category network
./scanner/claudesec scan --format json --severity high

# Setup
./scripts/setup.sh             # Install hooks + templates
./scripts/quick-start.sh       # Docker-first quick start
```

Dashboard served at `http://localhost:11777/`.

## For AI Agents

### Working Instructions

- **Single owner per task.** Verify every change before handoff.
- **Security claims must cite sources**: OWASP, NIST, CIS, MITRE ATLAS.
- **No PII, secrets, or company-specific IDs in the repo.** Use environment variables only.
- **Markdown files** require YAML frontmatter with `title`, `description`, `tags`.
- **File names**: kebab-case. Code blocks must specify language.
- **Timestamps**: KST (UTC+9).

### Agent Roles

| Agent | Model | Responsibility |
|-------|-------|----------------|
| `sec-orchestrator` | opus | Coordination, security workflow management, final acceptance |
| `sec-researcher` | sonnet | Security research, threat analysis, OWASP/NIST evidence |
| `sec-implementer` | sonnet | Code/docs changes, scanner checks, CI templates |
| `sec-reviewer` | sonnet | Correctness, security risk, regression review |
| `ci-pipeline` | sonnet | GitHub Actions, security scan automation |

Multi-agent workflows:

- **Security guide**: researcher → implementer → writer → reviewer → test-engineer
- **Scanner feature**: architect → implementer → test-engineer → ci-pipeline
- **Hotfix**: researcher → implementer → reviewer

### Testing

```bash
npm test                                   # Full pytest suite
python3 -m pytest scanner/tests/ -v       # Verbose
bash scanner/tests/test_output_functions.sh
bash scanner/tests/test_check_cicd_pipeline.sh
```

- All new scanner checks require a corresponding test in `scanner/tests/`.
- All Markdown must pass `markdownlint`.
- Links validated with `lychee "**/*.md"`.

### Conventions

- Match existing bash style in `scanner/lib/checks.sh` for new checks.
- Use `log_info`, `log_warn`, `log_fail` from `scanner/lib/output.sh` — no raw `echo` in checks.
- New compliance mappings go in `scanner/lib/compliance-map.py`.
- CI templates live in `templates/`; reference composite actions in `.github/actions/`.

## Dependencies

| Tool | Required | Purpose |
|------|----------|---------|
| bash | Yes | Scanner runtime |
| Python 3 | Yes | Dashboard, compliance mapping, asset sync |
| Docker | No | Dashboard serving, scan isolation |
| Node.js >=18 | No | npm package only |
| Prowler | No | Deep cloud/K8s posture scanning |
| AWS CLI | No | Infrastructure inventory |
| pytest | Dev | Test runner (`requirements-ci.txt`) |
| ShellCheck | Dev | Shell lint (`scripts/lint-shell.sh`) |

Key environment variables: `DD_API_KEY`, `DD_APP_KEY`, `ASSET_SHEET_ID`, `NOTION_TOKEN`, `JAMF_URL`, `JAMF_TOKEN`, `OKTA_OAUTH_TOKEN`, `GH_TOKEN`, `ZSCALER_API_KEY`.

See [docs/guides/claude-lead-agents-and-best-practices.md](docs/guides/claude-lead-agents-and-best-practices.md) for full agent best practices.
