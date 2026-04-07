# AGENTS.md — docs/

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 -->

## Purpose

All documentation for ClaudeSec: DevSecOps guides, compliance frameworks, AI/LLM security, GitHub security features, architecture diagrams, and step-by-step tutorials. All files are Markdown with YAML frontmatter.

## Directory Structure

```
docs/
├── devsecops/       # DevSecOps pipeline and practices
├── ai/              # AI/LLM security (OWASP LLM, MITRE ATLAS, prompt injection)
├── compliance/      # NIST CSF 2.0, ISO 27001/42001, KISA ISMS-P
├── github/          # GitHub security features, branch protection, Actions
├── architecture/    # Draw.io diagrams (scanner flow, security domains)
├── reports/         # Report templates and samples
└── guides/          # Step-by-step tutorials and operations runbooks
```

## Key Files

| File | Description |
|------|-------------|
| `guides/getting-started.md` | Quick setup and first scan |
| `guides/claude-lead-agents-and-best-practices.md` | Multi-agent roles and handoff format |
| `guides/hourly-operations.md` | Hourly cron automation and improvement loop |
| `guides/compliance-mapping.md` | SOC 2, ISO 27001, NIST, PCI-DSS, KISA ISMS-P |
| `guides/workflow-components.md` | Reusable composite actions and template contract |
| `guides/incident-response.md` | IR runbook |
| `guides/shell-lint-policy.md` | ShellCheck scope, severity, and CI options |
| `devsecops/owasp-top10-2025.md` | OWASP Top 10 2025 with controls and code examples |
| `devsecops/pipeline.md` | End-to-end secure CI/CD pipeline |
| `ai/llm-top10-2025.md` | OWASP LLM Top 10 2025 |
| `ai/mitre-atlas.md` | MITRE ATLAS — 66 AI threat techniques |
| `compliance/isms-p.md` | KISA ISMS-P 102-item certification guide |
| `compliance/nist-csf-2.md` | NIST CSF 2.0 six-function framework |

## For AI Agents

### Writing Conventions

- Every Markdown file requires YAML frontmatter: `title`, `description`, `tags`.
- File names: kebab-case (e.g., `owasp-top10-2025.md`).
- Code blocks must specify language identifier (` ```bash `, ` ```yaml `, etc.).
- Security claims must cite authoritative sources: OWASP, NIST, CIS, MITRE ATLAS.
- No broken links — validate with `lychee "**/*.md"` before commit.

### Quality Gate

```bash
# Lint all docs
markdownlint "docs/**/*.md"

# Check links
lychee "docs/**/*.md"
```

### Adding a New Guide

1. Create `docs/guides/<kebab-name>.md` with YAML frontmatter.
2. Add an entry to the relevant table in `README.md` under the Documentation section.
3. If it introduces a new compliance control, update `scanner/lib/compliance-map.py`.
4. Use the `/new-guide` slash command for scaffolding.

### Compliance Coverage

| Framework | Location |
|-----------|----------|
| NIST CSF 2.0 | `compliance/nist-csf-2.md` |
| ISO 27001:2022 | `compliance/iso27001-2022.md` |
| ISO 42001:2023 | `compliance/iso42001-ai.md` |
| KISA ISMS-P | `compliance/isms-p.md` |
| OWASP Top 10 2025 | `devsecops/owasp-top10-2025.md` |
| OWASP LLM Top 10 | `ai/llm-top10-2025.md` |
