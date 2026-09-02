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
- Use `--delete-branch` on merge to keep the remote clean. If the PR has open
  PRs stacked on it, retarget those FIRST — see [Stacked PRs](#stacked-prs-base--another-feature-branch).

### Always name the branch point

```bash
git fetch origin main -q && git switch -c <branch> origin/main
```

**Never bare `git switch -c <branch>`**, and never treat a `git status` taken
earlier in the session as evidence of where `HEAD` is now. This checkout is
shared — concurrent agent sessions and the hourly automation both run `git
checkout` in it.

Measured 2026-09-02: a session read `## main...origin/main` clean at startup,
and 35 seconds before it branched, another session created a branch and
committed to it. `git pull --ff-only origin main` then ran while `HEAD` was on
that branch — which merges `origin/main` INTO it and reports `Already up to
date`, without moving to `main` — and bare `git switch -c` forked from its tip.
The other session's commit rode into PR #513 and was squash-merged to `main`
unreviewed, leaving its own PR #512 open with an empty effective diff. Neither
command fails, so nothing signals it.

Two cheap confirmations, because the failure is silent by construction:

- `git log --oneline -1` right after branching must be the commit you expect.
- `git diff --stat origin/main` before committing must list only your files, and
  the file list `gh pr merge` prints must match. A file you never touched
  appearing there means stop, not ship.

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

### Stacked PRs (base = another feature branch)

**Default to branching from `main` and waiting for the dependency to merge.**
Stacking is allowed but has two costs, both measured on 2026-08-05:

1. **Retarget every dependent PR BEFORE merging its base.** Merging with
   `--delete-branch` (required posture — `DESIRED_DELETE_BRANCH="true"` in
   `scripts/sync-repo-protection.sh`) deletes the base ref, which **auto-closes**
   any open PR targeting it. A closed PR's base cannot be changed and the PR
   cannot be reopened once its base ref is gone:

   ```console
   $ gh pr edit 384 --base main
   Cannot change the base branch of a closed pull request.
   $ gh pr reopen 384
   Could not open the pull request.
   ```

   Recovery is a rebase plus a brand-new PR, losing the review thread:

   ```bash
   git rebase --onto origin/main <old-merge-base> <branch>
   git push --force-with-lease origin <branch>
   gh pr create --base main --head <branch>   # then comment "supersedes #<old>"
   ```

2. **Expect a rebase after each upstream merge.** `main` is strict
   (up-to-date-branch required), so an upstream PR that goes `BEHIND` needs
   `gh pr update-branch` and a full CI re-run before it can merge.

Since the `pull_request:` trigger on `lint.yml` / `security-scan.yml` is
unscoped (pinned by `scanner/tests/test_ci_pr_trigger_scope.py`), a stacked PR
**does** now get `Lint` and `Security Scan Gate`. If that filter is ever
re-added, a stacked PR loses both required checks silently — it previously got
3 checks instead of 28 — so state in the PR body that they did not run and that
local runs are the only evidence.

### Dependabot action PRs

For action-version conflicts, apply the required update directly to `main`
(via PR), then close the duplicate/conflicting Dependabot PR with a rationale.
