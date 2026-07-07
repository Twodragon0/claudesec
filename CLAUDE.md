# ClaudeSec Project Instructions

## Project Overview

ClaudeSec is a DevSecOps toolkit for AI-assisted secure development.
All documentation is in Markdown. No build system required.

## Conventions

- Markdown files use YAML frontmatter with title, description, tags
- File names: kebab-case
- Code examples must be tested and runnable
- Security advice must reference authoritative sources (OWASP, NIST, CIS)

## Directory Layout

- docs/devsecops/ — DevSecOps pipeline and practices
- docs/github/ — GitHub security features
- docs/ai/ — AI and LLM security
- docs/guides/ — Step-by-step tutorials
- docs/compliance/ — NIST, ISO, ISMS-P compliance guides
- docs/architecture/ — Architecture and flow diagrams
- docs/reports/ — Session reports, retrospectives, and generated scan/seminar collateral
- docs/plans/ — Strategy and planning documents
- assets/ — Logo and branding assets
- templates/ — Reusable config templates
- scanner/ — Security scanner CLI
- scripts/ — Automation scripts
- hooks/ — Claude Code security hooks
- examples/ — Example projects and configs

## Agents & Model Routing

Project agents live in `.claude/agents/` (the `sec-*` and `ci-pipeline` roles).
`architect`, `test-engineer`, and `explore` below are generic roles from the
global oh-my-claudecode catalog, not project-scoped files. Model selection:

- **opus**: sec-orchestrator, architect — coordination, architecture, security audit
- **sonnet**: sec-implementer, sec-researcher, sec-reviewer, ci-pipeline, test-engineer — standard work
- **haiku**: explore, docs lookup, quick validation — lightweight tasks

Key workflows:

- Security guide: researcher → implementer → writer → reviewer → test
- Scanner feature: architect → implementer → test → ci-pipeline
- Hotfix: researcher → implementer → reviewer

Token budget: prefer haiku subagents for read-only exploration. Use `run_in_background` for scans/builds.

## Token Optimization

- Read specific line ranges, not entire files: `Read(file, offset=10, limit=30)`
- Use Grep/Glob instead of Bash for file search — dedicated tools are cheaper
- Subagents for exploration: always use `model: "haiku"` for read-only tasks
- Prefer `run_in_background` for scans, builds, tests — frees context for other work
- Keep slash command outputs concise — scanner summary, not full report
- Autocompact at 70%: run `/compact` manually at logical milestones for better quality
- When compacting, always preserve the full list of modified files and test commands

## Local Testing

- Run scanner shell tests directly: `bash scanner/tests/test_<name>.sh`.
- **Set `CLAUDESEC_DASHBOARD_OFFLINE=1`** for any test that calls `generate_html_dashboard`. Without it, `dashboard-gen.py` makes live GitHub API calls and the test can hang for minutes. The kcov coverage job sets this at the job level and the three current dashboard tests also self-export it (PR #190/#191).

## Quality Gates

- All Markdown must pass markdownlint
- Links must be valid (no broken references)
- Code blocks must specify language
- Security claims must cite sources

## GitHub Actions Policy

- Keep a single CodeQL model: repository default setup only; do not add duplicate repo-level CodeQL workflow files.
- Require local pre-PR validation for docs changes: `markdownlint "**/*.md"` and `lychee "**/*.md"`.
- Treat external action download `401` as transient by default: rerun failed workflow up to 2 times before manual triage.
- For Dependabot action PR conflicts: apply required action-version updates directly to `main`, then close duplicate/conflicting Dependabot PRs with rationale.

## Continuous Operations

- Hourly automation entrypoint: see `docs/guides/hourly-operations.md`
- OpenCode profile: `OPENCODE.md`
- Improvement memory: `MEMORY.md`

## Continuous Improvement Workflow

- Use hourly automation for repository synchronization, scanner execution, and dashboard refresh.
- Use `MEMORY.md` to keep a persistent backlog across security, performance, operations, quality, and UX.
- Use `/ralph-loop` for autonomous iteration and `/ulw-loop` for deep-focus execution on highest-priority items.
