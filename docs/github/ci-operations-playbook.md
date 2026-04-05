---
title: CI Operations Playbook
description: Standard operating procedures for GitHub Actions reliability and dependency-update operations
tags: [github-actions, ci-cd, operations, dependabot, codeql]
---

# CI Operations Playbook

## Scope

This playbook defines operational standards for GitHub Actions in ClaudeSec:

1. Single CodeQL operating model
2. Required local docs validation before PR
3. Retry policy for transient external action failures (`401`)
4. Dependabot conflict handling policy

## 1) CodeQL Operating Model

- Use **repository default setup** as the only CodeQL model.
- Do not add or reintroduce duplicate repo-level CodeQL workflow files (for example `.github/workflows/codeql.yml`) unless an explicit migration plan is approved.
- If duplicate CodeQL workflows appear and conflict with default setup, remove the duplicate workflow and keep default setup.

## 2) Pre-PR Docs Validation (Required)

Before opening a PR that changes Markdown docs, run:

```bash
markdownlint "**/*.md"
lychee "**/*.md"
```

If either command fails, fix issues before pushing.

## 3) Transient `401` Action Download Failures

### Trigger

When a workflow fails with action download errors like `401 (Unauthorized)` from GitHub API tarball fetch.

### Response

1. Rerun the failed workflow.
2. If it fails again with the same transient signature, rerun one more time.
3. If it still fails after 2 reruns, move to manual triage.

### Manual Triage Checklist

- Confirm the referenced action/revision still exists.
- Confirm workflow token/permissions are not over-restricted for checkout and action download.
- Check GitHub Status for platform incidents.
- If needed, pin to a currently available action release and open a follow-up PR.

## 4) Dependabot Action PR Conflict Policy

When Dependabot PRs for GitHub Actions conflict with current `main`:

1. Apply the required action-version updates directly to `main`.
2. Verify CI passes on `main`.
3. Close duplicate/conflicting Dependabot PRs.
4. Add a closing rationale comment that links to the commit on `main`.

This keeps the PR queue clean and avoids repeated conflict churn.

## References

- GitHub Actions security hardening: [https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- GitHub Status: [https://www.githubstatus.com/](https://www.githubstatus.com/)
- Contribution policy mirror: [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
- PR checks snapshot template: [../../.github/comment-templates/pr-checks-snapshot.md](../../.github/comment-templates/pr-checks-snapshot.md)
- [NIST SP 800-53 SA-10: Developer Configuration Management](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-10)
- [NIST SP 800-53 CM-3: Configuration Change Control](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=CM-3)
