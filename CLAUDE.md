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
- templates/ — Reusable config templates
- scripts/ — Automation scripts
- hooks/ — Claude Code security hooks
- examples/ — Example projects and configs

## Quality Gates
- All Markdown must pass markdownlint
- Links must be valid (no broken references)
- Code blocks must specify language
- Security claims must cite sources
