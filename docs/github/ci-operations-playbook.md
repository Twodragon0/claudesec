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
5. CI and dashboard triage priority
6. PR mergeability lag after green checks

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

## 5) CI and Dashboard Triage Priority

Use the lightest reproducible check first, then escalate to heavier paths only after local validation is clean.

### Priority 1: Fast local gates

Run these before touching workflows:

```bash
shellcheck -x scripts/run-dashboard-safe.sh scripts/run-dashboard-docker.sh scripts/run-full-dashboard.sh scripts/run-scan.sh scanner/claudesec scanner/checks/access-control/*.sh scanner/checks/cicd/*.sh scanner/checks/code/*.sh bin/claudesec-cli.sh
bash scanner/tests/test_check_access_control.sh
bash scanner/tests/test_check_code_injection.sh
python3 -m pytest scanner/tests -v --tb=short
```

If these fail, fix them before investigating GitHub Actions. They are the quickest signal for scanner regressions and dashboard-adjacent shell regressions.

### Priority 2: Dashboard generation reproducibility

Validate the offline dashboard path locally:

```bash
CLAUDESEC_DASHBOARD_OFFLINE=1 ./scripts/run-dashboard-safe.sh --no-serve
test -f claudesec-dashboard.html
```

This is the primary gate for dashboard regressions because it exercises the real `claudesec dashboard` flow without depending on browser serving or live API access.

### Priority 3: Workflow parity checks

After local shell/tests/dashboard pass, inspect the GitHub workflow paths that wrap them:

- `.github/workflows/lint.yml`
- `.github/workflows/security-scan.yml`
- `.github/workflows/dashboard-refresh.yml`

Keep workflow logic thin. Prefer calling the existing repo scripts rather than duplicating scan logic inline in YAML.

### Priority 4: Docker parity

Use Docker only after the local gates above pass:

```bash
./scripts/run-dashboard-docker.sh --quick --no-serve --build
./scripts/run-dashboard-docker.sh --no-serve
```

If Docker fails with local daemon or snapshot errors while the local scanner and dashboard paths pass, treat that as a workstation/runtime issue first, not an immediate repository regression.

### Priority 5: Feature investment order

When choosing improvement work after CI is stable, prefer this order:

1. Secret and credential detection quality (`access-control`)
2. Code injection and SAST correctness (`code`)
3. Dashboard determinism and offline generation
4. Workflow reuse and CI observability
5. Heavier cloud/SaaS integrations that depend on external credentials or APIs

## 6) PR Mergeability Lag After Green Checks

### Trigger

Sometimes GitHub reports all PR checks as `pass`, but `gh pr merge` still fails with messages like:

- `required status checks are expected`
- `the base branch policy prohibits the merge`

This is usually a short-lived GraphQL or branch-protection state propagation lag, not a real failing check.

### Response

1. Confirm checks are actually green:

```bash
gh pr checks <PR_NUMBER>
```

1. Use the retrying merge helper:

```bash
./scripts/gh-merge-ready-pr.sh <PR_NUMBER>
```

1. If you need a different merge strategy:

```bash
MERGE_METHOD=merge ./scripts/gh-merge-ready-pr.sh <PR_NUMBER>
MERGE_METHOD=squash ADMIN_MERGE=0 ./scripts/gh-merge-ready-pr.sh <PR_NUMBER>
```

### Notes

- Default behavior is `rebase + --delete-branch + --admin`.
- The helper waits for `gh pr checks` to go green first, then retries merge when GitHub still reports checks as `expected`.
- If it times out, inspect repository rulesets and branch protection directly in GitHub UI.

## References

- GitHub Actions security hardening: [https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- GitHub Status: [https://www.githubstatus.com/](https://www.githubstatus.com/)
- Contribution policy mirror: [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
- PR checks snapshot template: [../../.github/comment-templates/pr-checks-snapshot.md](../../.github/comment-templates/pr-checks-snapshot.md)
- [NIST SP 800-53 SA-10: Developer Configuration Management](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-10)
- [NIST SP 800-53 CM-3: Configuration Change Control](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=CM-3)
