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
- templates/ — Reusable config templates
- scanner/ — Security scanner CLI
- scripts/ — Automation scripts
- hooks/ — Claude Code security hooks
- examples/ — Example projects and configs

## Quality Gates

- All Markdown must pass markdownlint
- Links must be valid (no broken references)
- Code blocks must specify language
- Security claims must cite sources

## Continuous Operations

- Hourly automation entrypoint: `/Users/REDACTED_USER/Desktop/.twodragon0/bin/hourly-opencode-git-pull.sh`
- Cron installer: `/Users/REDACTED_USER/Desktop/.twodragon0/bin/install-system-cron.sh`
- gws CLI installer: `/Users/REDACTED_USER/Desktop/.twodragon0/bin/setup-gws-cli.sh`
- gws auth verifier: `/Users/REDACTED_USER/Desktop/.twodragon0/bin/finalize-gws-auth-and-verify.sh`
- OpenCode profile: `OPENCODE.md`
- Improvement memory: `MEMORY.md`

## Continuous Improvement Workflow

- Use hourly automation for repository synchronization, scanner execution, and dashboard refresh.
- Use `MEMORY.md` to keep a persistent backlog across security, performance, operations, quality, and UX.
- Use `/ralph-loop` for autonomous iteration and `/ulw-loop` for deep-focus execution on highest-priority items.
