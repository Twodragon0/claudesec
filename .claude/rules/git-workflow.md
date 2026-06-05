# Git Workflow Rules

## Commit Message Format

```
<type>: <description>

<optional body>
```

Types: feat, fix, refactor, docs, test, chore, perf, ci

## Pull Request Workflow

When creating PRs:
1. Analyze full commit history (not just latest commit)
2. Use `git diff [base-branch]...HEAD` to see all changes
3. Draft comprehensive PR summary
4. Include test plan with TODOs
5. Push with `-u` flag if new branch

## Feature Implementation Workflow

1. **Plan First** - Use `planner` agent
2. **TDD Approach** - Use `tdd-guide` agent
3. **Code Review** - Use `code-reviewer` agent after writing code
4. **Commit** - Follow conventional commits format

## Branch Naming

- `feature/` - New features
- `fix/` - Bug fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation changes

## ClaudeSec-Specific Git Rules

### Branch protection

- **Never push to `main`.** A pre-push hook blocks `git push origin main`.
  Always branch (`docs/`, `fix/`, `feat/`, ...) → open a PR → squash-merge.
- Use `--delete-branch` on merge to keep the remote clean.

### Pre-PR validation (docs changes)

Run locally before opening a docs PR:

```bash
markdownlint "**/*.md"
lychee "**/*.md"
```

### CI / required checks

- Heavy jobs (scanner, docker, lighthouse) are path-gated by the `Detect changed
  paths` job; unrelated changes show them as `skipping` — that is not a failure.
- Use job-level gating with an `always()` aggregator, never workflow-level
  `paths-ignore`, for any check that is a required status (it would block merges).
- Single CodeQL model: repository default setup only — do not add a duplicate
  repo-level CodeQL workflow file.
- Treat an external action download `401` as transient: rerun the failed
  workflow up to 2 times before manual triage.

### Dependabot action PRs

For action-version conflicts, apply the required update directly to `main`
(via PR), then close the duplicate/conflicting Dependabot PR with a rationale.
