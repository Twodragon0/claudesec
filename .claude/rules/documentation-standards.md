---
description: ClaudeSec DevSecOps documentation standards
globs: ["docs/**/*.md", "scanner/**/*", "templates/**/*"]
---

# Documentation Standards

- Markdown files: YAML frontmatter required (title, description, tags)
- File names: kebab-case only
- Code examples: must be tested and runnable
- Security advice: cite authoritative sources (OWASP, NIST, CIS)
- All code blocks: must specify language

# Quality Gates

- `markdownlint "**/*.md"` — all Markdown passes linting
- `lychee "**/*.md"` — valid links, no broken references
- Pre-PR: markdownlint + lychee validation

# Directory Structure

- `docs/devsecops/` — DevSecOps pipeline practices
- `docs/github/` — GitHub security features
- `docs/ai/` — AI/LLM security
- `docs/guides/` — Step-by-step tutorials
- `docs/compliance/` — NIST, ISO, ISMS-P guides
- `scanner/` — Security scanner CLI
- `templates/` — Reusable config templates

# GitHub Actions Policy

- Single CodeQL model only (no duplicates)
- External action 401 = transient; rerun 2x before triage
- Dependabot conflicts: apply to main, close duplicates with rationale
