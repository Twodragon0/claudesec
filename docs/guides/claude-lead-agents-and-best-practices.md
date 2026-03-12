---
title: Claude Lead Agents and Best Practices
description: Lead agent roles, handoff format, and best practices for Claude/Cursor work in ClaudeSec
tags: [claude, cursor, agents, devsecops, best-practices]
---

# Claude Lead Agents and Best Practices

This guide extends the [Agent Team Charter](https://github.com/Twodragon0/claudesec/blob/main/AGENTS.md) (when present) with Claude/Cursor-specific roles and practices for secure, traceable work in ClaudeSec.

## Lead Agent Roles

| Role | Responsibility | When to Use |
|------|----------------|-------------|
| **Lead Orchestrator** | Task decomposition, assignment, priorities, final acceptance. Resolves priority/design conflicts. | Multi-step work, parallel tasks, unclear scope. |
| **Researcher** | Internal code evidence, external references (OWASP, NIST, CIS). Evidence before edits. | Before implementing security controls or new features. |
| **Implementer** | Code/docs changes, runs verification (tests, scanner, markdownlint). Single owner per task. | After scope and evidence are clear. |
| **Reviewer** | Correctness, security risk, regression impact. Proposes options on design conflicts; Lead finalizes. | Before considering a task done; before merge. |

## Standard Handoff Format

Use this structure for all inter-agent or human↔agent handoffs:

```txt
[Task]
- Goal:
- Scope:
- Constraints:

[Done]
- Files Changed:
- Key Changes:
- Validation:

[Open]
- Risks:
- Next Actions:
```

## Best Practices for Claude Work

### 1. Security-First

- **Cite sources**: Security advice must reference OWASP, NIST, or CIS (see [Security Citations](../../.cursor/rules/security-citations.mdc)).
- **No sensitive data**: Never commit company paths, PII, IPs, account IDs, or secrets (see [No Sensitive Paths](../../.cursor/rules/no-sensitive-paths.mdc)).
- **Least privilege**: When documenting or implementing agent/tool access, apply principle of least privilege (aligns with OWASP LLM06 Excessive Agency).

### 2. Small, Verifiable Increments

- One clear goal per task; each task should be testable or reviewable.
- Run verification before marking done: `./scanner/claudesec` where relevant, markdownlint for docs, tests if present.
- Prefer multiple small commits over one large commit.

### 3. Traceability

- Leave a short handoff (Goal, Done, Open) when switching context or ownership.
- Document key decisions in the repo (e.g. CONTRIBUTING.md, ADR, or inline comments) rather than only in chat.

### 4. File and Module Ownership

- Split ownership by module to avoid merge conflicts.
- If two implementers touch the same file, one is designated editor; the other provides patch notes or review only.

### 5. Definition of Done

- Requested behavior is implemented end-to-end.
- No unresolved diagnostics in modified files.
- Relevant tests and checks pass; Reviewer accepts with no blocking findings.
- Security claims in docs have citations; code examples are runnable.

### 6. Conflict and Deadlock

- **Priority**: Lead Orchestrator decides.
- **Design**: Reviewer proposes options; Lead Orchestrator finalizes.
- **Time-box (e.g. 15 min)**: Escalate with two alternatives and tradeoffs.

## Cursor Rules Alignment

- **claudesec-project.mdc**: Directory layout, kebab-case, no ad-hoc top-level folders.
- **security-citations.mdc**: Cite OWASP/NIST/CIS for security claims.
- **no-sensitive-paths.mdc**: Placeholders for paths; no PII or internal data.
- **markdown-quality.mdc**: Frontmatter, code block language, markdownlint.

## References

- [OWASP LLM Top 10 2025](../ai/llm-top10-2025.md) — agentic AI and excessive agency
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — what not to commit, conventions
- [CLAUDE.md](../../CLAUDE.md) — project instructions and quality gates
