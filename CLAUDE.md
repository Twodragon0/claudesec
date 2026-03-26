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
- assets/ — Logo and branding assets
- templates/ — Reusable config templates
- scanner/ — Security scanner CLI
- scripts/ — Automation scripts
- hooks/ — Claude Code security hooks
- examples/ — Example projects and configs

## Project Agents (`.claude/agents/`)

| Agent | Model | Role |
|-------|-------|------|
| `sec-orchestrator` | opus | 프로젝트 조율, 보안 워크플로우 관리 |
| `sec-researcher` | sonnet | 보안 리서치, 위협 분석 |
| `sec-implementer` | sonnet | 보안 가이드/도구 구현 |
| `sec-reviewer` | sonnet | 보안 문서/코드 리뷰 |
| `architect` | opus | 문서 구조 설계, 스캐너 아키텍처, 컴플라이언스 체계 |
| `test-engineer` | sonnet | 문서 검증, 링크 무결성, 스캐너 테스트 |
| `docs-writer` | sonnet | DevSecOps 가이드, 컴플라이언스 문서, AI 보안 콘텐츠 작성 |
| `ci-pipeline` | sonnet | GitHub Actions, 보안 스캔 자동화, 품질 게이트 관리 |

### Agent Responsibilities

| Agent | Primary Files | Key Tools |
|-------|--------------|-----------|
| `sec-orchestrator` | All — coordination role | Read, Grep, Glob, Bash, Write, Edit |
| `sec-researcher` | docs/ai/, docs/devsecops/, docs/compliance/ | Read, Grep, Glob, Bash |
| `sec-implementer` | scanner/, hooks/, templates/, docs/guides/ | Read, Grep, Glob, Bash, Write, Edit |
| `sec-reviewer` | All docs and code | Read, Grep, Glob, Bash |
| `architect` | docs/architecture/, scanner/ design | Read, Grep, Glob, Bash |
| `test-engineer` | All — validation role | Read, Grep, Glob, Bash, Write, Edit |
| `docs-writer` | docs/devsecops/, docs/github/, docs/ai/, docs/compliance/ | Read, Grep, Glob, Bash, Write, Edit |
| `ci-pipeline` | .github/workflows/, scripts/, Dockerfile | Read, Grep, Glob, Bash, Write, Edit |

## Multi-Agent Workflow Patterns

### New Security Guide (end-to-end)

```
sec-researcher  →  sec-implementer  →  docs-writer  →  sec-reviewer  →  test-engineer
(research)         (scanner/hooks)     (write guide)    (verify claims)   (lint + links)
```

### Scanner Feature Development

```
architect  →  sec-implementer  →  test-engineer  →  ci-pipeline
(design)      (build feature)     (test + validate)   (add to CI)
```

### Compliance Document

```
sec-researcher  →  docs-writer  →  sec-reviewer  →  test-engineer
(framework gap)    (draft guide)    (accuracy check)   (quality gate)
```

### Full DevSecOps Pipeline Review

```
sec-orchestrator coordinates:
  sec-researcher   (threat landscape)
  architect        (pipeline design gaps)
  sec-reviewer     (existing doc audit)
  ci-pipeline      (workflow gaps)
  → sec-implementer (fix + implement)
  → test-engineer   (validate all changes)
```

### Hotfix / Urgent Security Update

```
sec-researcher  →  sec-implementer  →  sec-reviewer
(CVE/threat)       (patch guide/hook)   (fast review)
```

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
