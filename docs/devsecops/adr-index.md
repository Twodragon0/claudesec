---
title: Architecture Decision Records (ADR) Index
description: Convention and index for ClaudeSec Architecture Decision Records under docs/devsecops/adr-*.md
tags: [adr, devsecops, process, documentation]
---

# Architecture Decision Records (ADR) Index

An **Architecture Decision Record** captures a significant decision, the context
that forced it, and its consequences — so the *why* outlives the PR that made it.
ClaudeSec records decisions that shape its DevSecOps process (CI gates, guard
discipline, release flow) as ADRs here.

## Convention

- **Location & name**: `docs/devsecops/adr-NNN-<kebab-slug>.md`, where `NNN` is a
  zero-padded sequential number (`001`, `002`, …). This index is `adr-index.md`
  (not numbered).
- **Frontmatter**: every ADR needs `title`, `description`, `tags` (include `adr`).
- **Body sections**: `Status`, `Date`, then `## Context`, `## Decision`,
  `## Consequences`, `## References` (cite OWASP / NIST / CIS / vendor docs where
  a security claim is made — repo rule).
- **Status values**: `Proposed` → `Accepted` → (`Superseded by ADR-NNN` |
  `Deprecated`). Never edit an Accepted ADR's decision in place; supersede it with
  a new ADR and update its status.
- **Immutable intent**: ADRs are a log. Fix typos freely; record changed
  decisions as new ADRs.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-001](./adr-001-ci-guard-hardening-and-audit-cadence.md) | CI Guard Hardening Discipline & Periodic Adversarial Audit | Accepted | 2026-06-24 |

## Operationalization

The periodic-audit cadence in ADR-001 is reminded automatically by the
`Guard Audit Reminder` scheduled workflow
(`.github/workflows/guard-audit-reminder.yml`), which opens a quarterly idempotent
`guard-audit-due` issue. It is a scheduled notifier — never a required PR check.

## References

- ADR concept (Michael Nygard): <https://github.com/joelparkerhenderson/architecture-decision-record>
- In-repo: [CI Config Regression Guards](./ci-config-regression-guards.md)
