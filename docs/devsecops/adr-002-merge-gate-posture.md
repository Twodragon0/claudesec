---
title: "ADR-002: Merge-Gate Posture for a Solo-Maintainer Repository"
description: What actually gates a merge on main, why the review count is zero while code-owner review is on, and why the Dependabot auto-arm must fail closed
tags: [adr, ci-cd, supply-chain, devsecops, branch-protection]
---

# ADR-002: Merge-Gate Posture for a Solo-Maintainer Repository

- **Status:** Accepted
- **Date:** 2026-09-04
- **Context owners:** ClaudeSec maintainers

## Context

Six decisions taken between 2026-09-01 and 2026-09-04 determine what can reach
`main`. Until now each lived in the comment next to the line it explained:
`scripts/sync-repo-protection.sh`, `.github/workflows/dependabot-auto-merge.yml`,
two retrospectives and four guards.

A comment answers *"why is this line here."* It does not answer *"what gates a
merge in this repository,"* and one of these decisions **reverses** another. The
`require_code_owner_reviews` flag was turned off in #403 and back on in #526; read
either comment alone and the posture looks arbitrary. That is what this ADR is
for.

**`scripts/sync-repo-protection.sh` remains authoritative for the live values.**
This document explains them and records the conditions under which each should
change. It deliberately does not restate the current pins — a document that
duplicates state it does not own goes stale silently and then reads as
authoritative, which is the failure mode `MEMORY.md` has recorded against itself.

Two properties of this repository drive everything below:

- **Exactly one account has push access** (`Twodragon0`, also the sole entry in
  `CODEOWNERS`). Verified 2026-09-03 via `gh api repos/.../collaborators`.
- **`enforce_admins` is on**, so the owner is not exempt from any rule. There is
  no admin escape hatch when a gate misfires.

## Decision

### §1 — The base gate is two required contexts, strict mode, and `enforce_admins`

`Lint` and `Security Scan Gate` are the required status checks; branches must be
up to date before merge; admins are not exempt. Everything else in this ADR sits
on top of that, and nothing below weakens it.

The corollary is load-bearing and easy to forget: **a job that never runs is
indistinguishable from a job that found nothing.** Path gating is deliberate here
for CI cost, so the required aggregators treat `skipped` as passing — which means
a gate's reachability is as much a control as its logic
(`test_ci_reachability.py`, ADR-001 §4).

### §2 — `required_approving_review_count` stays 0 while exactly one account has push

Raising it is a **merge outage, not a review**. GitHub does not let an author
approve their own pull request, and with `enforce_admins: true` there is no
override. With one push-holder the effect is asymmetric:

| PR author | effect of `count >= 1` |
|---|---|
| `dependabot[bot]` | owner can approve — still mergeable, one manual step |
| the owner | **nobody can approve — permanently unmergeable** |

The condition that reverses this decision is *a second account gaining push
access*, and since #524 that condition is **checked mechanically** rather than
remembered: `sync-repo-protection.sh` reads the collaborator list, counts push
holders, and fails while the count is 0 and more than one exists. It fails closed
when the list cannot be read, because an unchecked precondition is not a met one.

Reported separately from drift on purpose — the live settings still match the
codified desire, so calling it drift would be false and `--apply` cannot
remediate it. What changed is the world the desire was chosen for.

### §3 — `require_code_owner_reviews` is ON, and this reverses #403

**What #403 decided, and why it was reasonable.** With the count at 0, code-owner
review binds only PRs *not* authored by the sole code owner — in practice
Dependabot's. Across all 16 Dependabot PRs at that time every merged one carried
an approval, and #388 sat `BLOCKED` at 22/22 green until it was closed and
reapplied by hand as #400. #403 read that as cost without benefit.

**What changed.** #522 measured the auto-arm's path hard-excludes *failing open*:
an empty `gh pr diff` result walked the exclusion loop and armed auto-merge on a
`Dockerfile` PR, while the workflow's own comment called that path fail-closed.
Those hard-excludes were the only thing keeping sensitive Dependabot changes on
human review. So "gates nothing" stopped being true — #388 had been the control
working.

**Why it is safe here, measured rather than inferred.** Unlike §2 this does not
bind owner-authored PRs. Verified before flipping: with the flag on and the count
still 0, owner PR #525 stayed `MERGEABLE`/`CLEAN` with an empty `reviewDecision`,
re-read 65 s apart to rule out cached mergeability, then reverted to a byte-equal
baseline. Re-confirmed after apply on #512 — `MERGEABLE`/`BEHIND`, empty
`reviewDecision`; `BEHIND` is strict mode, not a review block. Re-confirmed a
third time on this ADR's own PR #527 — `MERGEABLE`/`CLEAN`, empty
`reviewDecision`, on a `docs/`-only diff rather than the `templates/` of #525 or
the `scanner/lib/` of #512.

**What that empty `reviewDecision` does and does not establish.** It rules out
two readings. Not a coverage gap: `CODEOWNERS` opens with `* @Twodragon0`, so no
path is unowned and no PR escapes by touching a file nobody owns — the three
observations above span three different path classes and all are matched. Not a
stale field either: on #527 `requested_reviewers` is empty for both users and
teams with zero reviews recorded, so GitHub asked nobody, rather than asking and
having the answer not land. What it does **not** do is separate the two live
explanations — the owner-exemption, and the possibility that
`required_approving_review_count: 0` leaves the flag binding *nobody*. Both
predict exactly this reading on an owner-authored PR, and every measurement so
far is owner-authored. Only a PR with a different author can tell them apart,
which is the same open item below and not an independent one.

**Still open, recorded rather than assumed:** that a Dependabot PR now reports
`REVIEW_REQUIRED`. No Dependabot PR has been open since the flip, so the evidence
for that half remains #388's observed `BLOCKED` state. Confirm on the next bump.

**The measured cost.** All eight of the most recently merged Dependabot PRs
carry an empty `reviewDecision` — #510, #477, #476, #354, #353, #322, #321, #294.
Each now needs an approval before its armed auto-merge fires; auto-merge becomes
*auto-merge after approval*. The reversing condition in this direction is written down too:
if that queue is routinely rubber-stamped or ignored the gate is theatre again
and should come back off — with the numbers, as #403 did.

### §4 — `dismiss_stale_reviews` is false, and that is load-bearing

Not laziness. `strict` forces a rebase whenever `main` moves, so dismissing the
approval on every rebase would make an approved Dependabot PR unmergeable in any
week with normal merge traffic. §3's gate only works because §4 holds.

### §5 — The auto-arm surface is `pip`, patch/minor, with a known non-empty path list

Auto-merge is armed only when **all** hold: ecosystem `pip`; update type
`semver-patch` or `semver-minor`; the changed-path list was successfully
retrieved; it is non-empty; and no entry matches a hard-excluded path.

`docker` left the allowlist in #524. Measured: every docker-ecosystem PR in this
repository's history touches a `Dockerfile*` (#476, #353, #293, #273, #235, #220),
so on the observed population nothing changed. **The claim is deliberately weaker
than the one for `github_actions`:** `docker` was not unreachable *by
construction* — a docker PR touching only, say, `README.md` armed before and is
refused now. That single changed input is an intended tightening, not an
accident, and the re-add condition sits next to the `case` arm.

### §6 — The hard-excludes are a control, and a control is proven by execution

PR #522 is the whole argument. Every `case` arm was present and spelled correctly
the entire time the gate was failing open, because the defect was in what the
loop *received*, not in what it matched. An `assertIn("Dockerfile", body)` guard
would have stayed green throughout.

So the guards for this surface run the extracted step body with `gh` stubbed and
decide from whether `pr merge` was actually invoked
(`test_ci_dependabot_auto_merge_fail_closed.py`). Same discipline as ADR-001 §4.

Two corollaries worth stating because both cost real time:

- **Exit status alone is a trap.** Once a body carries `set -euo pipefail`, a
  broken version also exits non-zero, so a status-only assertion passes on the
  exact regression it exists to catch. Assert the control's own output.
- **Failing closed is not enough if it is silent.** Every refusal comments on the
  PR. A gate that declines without saying why is the same invisibility class this
  posture exists to end.

## Consequences

**Accepted costs.**

- Every Dependabot PR needs a human approval click before auto-merge fires (§3).
- The `docker` ecosystem no longer auto-merges at all (§5); those bumps are
  reviewed by hand.
- A transient `gh` failure refuses to arm and comments, rather than proceeding
  (§5/§6) — a false refusal is cheap, a false arm is not.

**What remains unguarded, stated rather than glossed.**

- The Dependabot half of §3 (see above).
- `pull_request_target` paths cannot be exercised on demand in CI — there is no
  way to conjure a Dependabot PR — so §5/§6's guards execute the extracted body
  with the same env var names the runner uses, but not the runner's own event
  context.

**What this does not open up.** An outside contributor's PR comes from a fork,
nobody without write access can merge it, and the auto-arm's fork guard
(`head.repo.full_name == github.repository`) keeps a fork PR from ever being
armed.

**Relationship to ADR-001.** Different subject, not superseded: ADR-001 §4 is the
guard-authoring rule (*execute the gate, do not parse it*) that §6 applies to this
surface. Cite them separately.

**Follow-up.** `test_ci_adr_decision_numbering.py` and
`test_ci_adr_citation_spelling.py` are hardcoded to `ADR-001`. They do not break
on this document and are not needed while it has no citations, but ADR-001 reached
81 uncounted citations exactly by that route. Generalising both to `ADR-\d{3}` is
tracked as its own change rather than bundled here.

## References

- `scripts/sync-repo-protection.sh` — authoritative codified values, with the
  §2 precondition check and the §3 reversal recorded inline
- `.github/workflows/dependabot-auto-merge.yml` — the §5/§6 surface
- `docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md` — guard
  authoring discipline; ADR-001 §4 is applied by §6 above
- `docs/reports/green-while-dead-retrospective.md` — the measurements behind
  §3 and §6
- `docs/reports/runner-key-audit-retrospective.md` — required-check topology
  behind §1
- OWASP CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-4 (Poisoned Pipeline
  Execution)
- NIST SP 800-218 (SSDF) PO.3, PW.4
