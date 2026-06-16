---
title: Continuous Improvement Memory
description: Persistent improvement backlog and operating memory for ClaudeSec automation
tags: [memory, operations, quality, continuous-improvement]
---

# Continuous Improvement Memory

## Operating Cadence

- Hourly: central manager runs `git pull --ff-only` (see `docs/guides/hourly-operations.md`).
- Daily: triage new findings and failures from `docs/reports/hourly-scan.json`.
- Weekly: trend review across security, performance, code quality, and documentation quality.

## Improvement Buckets

- Security: unresolved high/critical findings, dependency risk, secret exposure paths.
- Performance and Optimization: repeated slow checks, scanner runtime drift, noisy failures.
- Monitoring and Operations: alert coverage, log quality, runbook freshness, backup of reports.
- Code and Content Quality: false positives, stale docs, missing source citations, broken links.
- UI/UX and Design: dashboard readability, navigation clarity, mobile rendering checks.

## Ralph and Ultrawork Trigger Policy

- Use `/ralph-loop` for autonomous improvement cycles when backlog depth increases.
- Use `/ulw-loop` for high-focus implementation bursts on prioritized items.
- Record decisions and deltas in this file after each focused cycle.

## Authoritative Review Anchors

- OWASP SAMM (continuous security governance)
- NIST SP 800-92 (log management and monitoring)
- CIS Controls v8 (continuous vulnerability management and secure configuration)

## Delta Log

### Cycle #217–#237 — scanner correctness, reproducible Docker, cross-OS CI (merged 2026-06)

- **Docker / supply chain:** base images pinned by digest + Dependabot-tracked (#218);
  builder stage made Python-version-agnostic (#233); alpine held on the py3.12 line
  with Dependabot ignoring minor/major bumps (#234); `prowler==5.30.1` pinned for
  reproducible builds (#237); quickstart healthcheck corrected (#217).
  Rationale: prowler 5.x requires Python `>=3.10,<3.13`; unpinned installs on py3.14
  silently backtrack to 3.11.3 (pydantic v1, runtime crash). Hold alpine until a
  prowler release supports py3.13+.
- **Scanner `grep -E` ERE / pipe-split bug class:** repaired ERE-lookahead + `IFS`
  pipe-split detections (#221); fixed broken `\|`-alternation in saas/ai (#223) and
  network/cloud/prowler (#224); tightened the `var\.` pattern (#227); stopped
  CLOUD-010/011 `grep -c` emitting a two-line `0\n0` (#229); swept
  `grep -c "… || echo 0"` → `|| true` across 29 sites (#231).
- **Test coverage & CI regression guards:** covered previously untested checks and
  extended the token-expiry gate (#219, #222); guarded NET-005 FAIL escalation and
  cross-OS non-required topology (#228).
- **Cross-OS CI (live integration, non-blocking):** macOS CIS (#225), Windows KISA
  (#226), deterministic CIS-006 FAIL assertion (#230); macOS test all-SKIPs on
  non-Darwin instead of hard-exiting (#232).

### Cycle #238–#242 — prowler provider parity, guard invariant, worktree hygiene (merged 2026-06)

- **Prowler provider build-parity (#238):** `integration.sh` now runtime-detects
  available prowler providers via `_prowler_install_dir` + `_prowler_provider_available()`.
  The 12 stripped providers (azure, gcp, m365, googleworkspace, cloudflare, mongodbatlas,
  oraclecloud, alibabacloud, openstack, nhn→openstack, llm, image) now emit an accurate
  "not included in this build" skip instead of a misleading "check authentication" warning.
  NHN scans via the stripped `openstack` provider are also handled.
- **Provider-parity test coverage (#241):** asserts no auth-`WARN` is emitted for stripped
  providers; adds a Docker smoke test confirming `_prowler_provider_available aws` resolves
  correctly inside the built lean image.
- **Guard-ordering invariant (#242):** stdlib-only pytest guard
  `test_ci_prowler_provider_guard_ordering.py` asserts that `_prowler_provider_available`
  precedes `_prowler_report` in `integration.sh`, mutation-verified.
- **Worktree gitignore (#240):** added `.claude/worktrees/` to `.gitignore` so
  background-agent worktrees no longer land as untracked files.

### Cycle #243–#246 — ERE-regression CI guards, prowler watch automation, deps (merged 2026-06)

- **ERE-pipe CI regression guard (#244):** `test_ci_no_ere_pipe_regression.py` (stdlib,
  mutation-verified) fails when a new `\|` appears in a `grep -E` ERE context under
  `scanner/checks`, allowlisting the 2 intentional literals (`code/injection.sh` `\|safe`,
  `solutions.sh:704` `curl|sh`).
- **ERE guard extended (#245):** scan widened to `scanner/lib` helpers
  (`files_contain`/`_code_grep`) and multi-line `_code_grep` calls; `scanner/lib` confirmed
  clean (no real bug).
- **Prowler Requires-Python watch (#246):** notification-only scheduled action +
  `scripts/check-prowler-python-ceiling.sh` that opens an issue only when prowler drops the
  `<3.13` ceiling (the alpine-unblock trigger). Verified no-op today via `workflow_dispatch`
  (`CEILING_LIFTED=false`, no issue).
- **Delta-log doc (#243):** recorded the #238–#242 cycle (this file).
- **Dependency bumps:** nginx `1.27`→`1.31-alpine` in `Dockerfile.nginx` (#235, the separate
  nginx image — unrelated to the prowler/alpine scanner base); pytest `>=9.1.0` in
  `requirements-ci.txt` (#236). Both required a code-owner approval (Dependabot is not a
  code owner — see backlog).

## Open Backlog

- **Prowler provider build-parity** — DONE. #238 merged (runtime provider detection +
  graceful skips); follow-up tests merged in #241; guard-ordering invariant merged in #242.
  No auth-`WARN` for stripped providers; Docker smoke test added.
- **`grep -E` ERE bug class** — DONE. #221/#223/#224 cleared all known sites (AI-007,
  SAAS-005/009/011/014/015, network/cloud/prowler); 2 intentional literal-pipe occurrences
  remain (`code/injection.sh` `\|safe`, `solutions.sh:704` `curl|sh`). CI regression guard
  merged (#244) and extended to `scanner/lib` + multi-line calls (#245).
- **Prowler 4.x/5.x → unblock alpine bumps.** Alpine is pinned to the py3.12 line only
  because prowler lacks py3.13+ support; revisit alpine minor/major Dependabot bumps once
  prowler ships py3.13+ compatibility. **Now auto-watched** by the #246 scheduled action
  (alerts via issue when prowler's PyPI `Requires-Python` drops the `<3.13` ceiling). Manual
  check: `curl -fsSL https://pypi.org/pypi/prowler/json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["info"]["version"], d["info"]["requires_python"])'`.
- **Dependabot auto-merge policy is broken / TODO.** The existing
  `.github/workflows/dependabot-auto-merge.yml` auto-approves with `GITHUB_TOKEN`, but
  `github-actions[bot]` is NOT a code owner so those approvals do NOT satisfy
  `require_code_owner_reviews` (proven by #235: 4 bot approvals, still BLOCKED, human had to
  approve+merge). Its `--auto` is also a silent no-op because repo `allow_auto_merge=false`.
  Recommended fix (architect plan, this session): enable repo auto-merge, drop the broken
  approve-as-bot step, and only auto-*arm* auto-merge on safe patch/minor pip/docker updates
  (never Dockerfile/base-image/major) — human code-owner approval stays the gate.
- **`.claude/worktrees/` not gitignored** — DONE (#240 merged).

> Reference: CIS Controls v8 (secure configuration & continuous vulnerability
> management) anchors the Docker-pinning and scanner-correctness work above.
