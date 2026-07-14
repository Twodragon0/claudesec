---
title: "PPTX Git LFS History Migration — Safe Execution Plan (Priority 3b)"
description: "Coordinated maintenance-window runbook to reclaim ~37 MB of committed .pptx blobs from git history via git lfs migrate import, with backup, verification, and rollback."
tags:
  - plan
  - git-lfs
  - maintenance
  - tech-debt
status: ready
---

# PPTX Git LFS History Migration — Safe Execution Plan (Priority 3b)

Runbook for **Phase (b)** of Priority 3 in
[`refactoring-backlog.md`](./refactoring-backlog.md): reclaiming the ~37 MB of
already-committed `*.pptx` blobs from packed git history. This is a **history
rewrite + force-push to `main`** and must run in a coordinated maintenance
window. It is intentionally deferred until nothing else is in flight.

> This document is a **plan only**. Do not execute any step until a maintainer
> has scheduled the window and confirmed the preconditions below.

## Current state (what is already done)

- **Phase (a) — stop the bleed: ✅ DONE.** `.gitattributes` routes
  `*.pptx filter=lfs diff=lfs merge=lfs -text`, so *new or modified* decks go to
  LFS. It does **not** convert the existing blobs.
- The decks are already excluded from the npm tarball (`package.json` `files[]`
  ships only `bin/ scanner/ scripts/ hooks/ templates/ …`, not `docs/`), so the
  only impact today is **clone / fetch size**, not published-package size.
- Two tracked files carry the weight:

  | File | Size |
  |------|------|
  | `docs/reports/claudesec-security-seminar-30min-template.pptx` | ~33 MB |
  | `docs/reports/ai-devsecops-work-improvement.pptx` | ~3.9 MB |

## Goal & non-goals

- **Goal:** remove the historical `*.pptx` blobs from the packed history and
  re-add the current versions as LFS pointers, shrinking fresh clones by ~37 MB.
- **Non-goals:** changing deck content; moving decks out of the repo; altering
  the npm package (already unaffected); touching any non-`.pptx` history.

## Preconditions (all must hold before starting)

1. **Zero open PRs**, or explicit agreement that every open PR will be rebased /
   recreated after the rewrite (a history rewrite invalidates every in-flight
   branch's merge base).
2. **Maintainer + window scheduled.** Only `Twodragon0` (CODEOWNERS `* @Twodragon0`,
   `enforce_admins=true`) can relax and restore branch protection.
3. **GitHub LFS enabled** for the repo (Settings → check LFS storage/bandwidth
   quota; 37 MB is well within the free tier but confirm).
4. **Local tooling:** `git-lfs >= 3.x` installed (`git lfs version`), and a clone
   with **no local uncommitted work**.
5. **A full mirror backup exists** (step 1) and its location is recorded.

## Execution runbook

Run from a **fresh, dedicated mirror clone**, never your working checkout.

### 1. Back up (mandatory, reversible escape hatch)

```bash
# Mirror backup — complete refs + objects. Keep until migration is verified good.
git clone --mirror https://github.com/Twodragon0/claudesec.git claudesec-backup.git
tar czf claudesec-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz claudesec-backup.git
# Record the tarball path/checksum somewhere durable (not in the repo).
```

### 2. Measure the "before"

```bash
git clone https://github.com/Twodragon0/claudesec.git claudesec-premigrate
du -sh claudesec-premigrate/.git          # baseline pack size
```

### 3. Rewrite history (LFS import)

```bash
cd claudesec-premigrate            # or a fresh clone dedicated to the rewrite
git lfs migrate import --include='*.pptx' --everything
```

- `--everything` rewrites **all** refs (all branches + tags), not just `HEAD`,
  so no stale non-LFS copies survive on other refs.
- `git lfs migrate` reuses the existing `.gitattributes` rule; the working tree
  files become LFS pointers, historical blobs are replaced by pointers.

> **BFG alternative:** `bfg --strip-blobs-bigger-than 1M` also works but does not
> re-add files as LFS pointers — prefer `git lfs migrate import` here so the decks
> stay versioned via LFS rather than being deleted from history.

### 4. Verify locally (before any push)

```bash
git lfs ls-files | grep pptx          # both decks listed as LFS objects
git cat-file -p HEAD:docs/reports/claudesec-security-seminar-30min-template.pptx | head -3
# ^ must print a "version https://git-lfs.github.com/spec/v1" pointer, not binary
du -sh .git                           # compare to step 2 — expect ~37 MB smaller
git log --oneline -5                  # history intact, only blobs changed
```

### 5. Relax branch protection (maintainer, momentary)

In Settings → Branches → `main` rule, temporarily **allow force pushes** and (if
needed) disable "Include administrators" for the window. Note the exact settings
so they can be restored verbatim.

### 6. Force-push the rewritten history

```bash
git lfs push --all origin             # upload LFS objects first
git push --force-with-lease origin --all
git push --force-with-lease origin --tags
```

`--force-with-lease` (not `--force`) aborts if the remote moved unexpectedly —
a guard against clobbering an unnoticed concurrent push.

### 7. Restore branch protection (maintainer, immediately)

Re-enable "Require a pull request", "Include administrators"
(`enforce_admins=true`), and **disable force pushes** — return the rule to its
pre-window state exactly.

### 8. Verify the "after"

```bash
git clone https://github.com/Twodragon0/claudesec.git claudesec-postmigrate
du -sh claudesec-postmigrate/.git     # expect ~37 MB smaller than step 2
cd claudesec-postmigrate && git lfs ls-files | grep pptx
```

- Trigger CI on a trivial no-op PR and confirm the full required-check set is
  green (Lint + Security Scan Gate + coverage jobs), i.e. the rewrite did not
  disturb any tracked source path.

## Rollback

If any verification fails **before** step 6 (force-push): discard the rewritten
clone; nothing on the remote changed.

If a problem is found **after** the force-push: restore from the step-1 mirror.

```bash
cd claudesec-backup.git
git push --force origin --all         # requires force temporarily re-enabled
git push --force origin --tags
```

Then re-lock branch protection. Because the mirror is a byte-for-byte copy of the
pre-migration remote, this fully reverts the operation.

## Post-migration follow-ups

- Notify all contributors to **re-clone** (or hard-reset) — their old clones
  reference rewritten commits and will diverge.
- Recreate/rebase any branch that was intentionally kept open.
- Update `refactoring-backlog.md` Priority 3 → ✅ DONE and drop the SCOPE /
  LIMITATION note in `.gitattributes` that points here.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Force-push clobbers a concurrent change | `--force-with-lease`; precondition of zero open PRs |
| Branch protection left relaxed | Step 7 restores it immediately; record exact prior settings in step 5 |
| LFS objects not uploaded before ref update | `git lfs push --all origin` precedes the ref push (step 6) |
| Contributors keep stale clones | Explicit re-clone notice (follow-ups) |
| Irreversible history loss | Mandatory mirror backup (step 1) enables full rollback |

## References

- `docs/plans/refactoring-backlog.md` — Priority 3 (a/b phasing)
- `.gitattributes` — the Phase (a) LFS routing rule and its documented limitation
- Git LFS: `git lfs migrate import` — <https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-migrate.adoc>
