---
title: "Refactoring Backlog — Large-File Decomposition, Helper Reuse, Binary Bloat"
description: "우선순위화된 리팩토링 백로그와 실행 계획. api-extended 헬퍼 추출(완료), 대형 파일 분해(진행), 35MB pptx LFS 이전(대기)."
tags:
  - plan
  - refactor
  - maintainability
  - tech-debt
status: in-progress
---

# Refactoring Backlog — Decomposition, Helper Reuse, Binary Bloat

> **Status**: In progress. Each item ships as its own PR behind the enforced
> gates (`pytest --cov-fail-under=99` for `scanner/lib`, `kcov >= 90%` for bash,
> `shellcheck -S error`, `markdownlint`). Refactors must be **behavior-preserving**
> — verified against the existing suites (and, for network code, an arg-capture
> equivalence check), never by "looks the same".

## Measured baseline (2026-07-08)

| File | Lines | Note |
|------|-------|------|
| `scanner/claudesec` | 1252 | CLI parse + scan orchestration + Datadog collect + dashboard serve |
| `scanner/lib/diagram-gen.py` | ~930 | draw.io diagram builders |
| `scanner/lib/checks.sh` | ~930 | credential/env helpers (AWS/GCP/Azure/datadog) |
| `scanner/lib/output.sh` | 752 | result formatting + prowler summary |
| `scanner/lib/dashboard_data_loader.py` | ~744 | data loaders |
| `docs/reports/*.pptx` | 37 MB | 2 files = 96% of the 38.3 MB tracked under `docs/reports/` |
| `scanner/checks/saas/api-extended.sh` | ~660 | 39 hand-rolled `curl` call sites |

The coding-style guide sets an 800-line soft max; five files are at/over it.

## Priority 1 — SaaS API helper extraction — ✅ DONE (PR #324)

`api-extended.sh` duplicated `run_with_timeout 15 curl -sSf …` at 39 sites. The
calls are heterogeneous (`-k`, `--digest`, `-u`, two `-H` headers, `Content-Type`
vs `Accept`), so they could **not** fold into the rigid `_saas_api` /
`_saas_api_header` helpers without changing the wire request. Extracted only the
shared prefix into `_saas_curl() { run_with_timeout 15 curl -sSf "$@"; }`; each
call keeps its exact headers/flags. Proven byte-identical via an arg-capture
equivalence harness.

## Priority 2 — Large-file decomposition — 🔄 IN PROGRESS

Incremental, **one file per PR**, safest-first (thickest test coverage first).
Pure moves; the coverage gate is the safety net.

1. `dashboard_data_loader.py` — ✅ DONE (PR #325): hoisted the five pure nested
   closures out of the 308-line `load_datadog_logs` to module level
   (`_dd_normalize_log`, `_dd_normalize_signal_severity`, `_dd_inc_severity`,
   `_dd_extract_items`, `_dd_normalize_log_severity`).
2. `diagram-gen.py` — TODO: split the section/diagram builders (mirror the
   `dashboard_html_*` module split). Strong pytest coverage → low risk.
3. `output.sh` — TODO: extract the prowler-summary block into a focused unit
   (bash; kcov floor is the net).
4. `checks.sh` — TODO: group the AWS / GCP / Azure / datadog credential helpers
   into cohesive sections (bash; preserve global scope + `source` order).
5. `scanner/claudesec` — TODO, **last** (highest risk, integration-tested):
   extract Datadog artifact collection and the dashboard-serve logic into `lib/`.

**Guardrails for each step**: pure move, no logic change; assert `pytest 99%` /
`kcov 90%` hold before and after; for sourced bash, keep every function at the
same global scope and the `source` order in `claudesec` unchanged.

## Priority 3 — 35 MB pptx binary bloat — ⏳ DEFERRED (coordinated)

`docs/reports/*.pptx` (37 MB) is already excluded from the npm tarball
(`package.json` `files[]`), so the only impact is **clone size**. Two phases:

- **(a) Stop the bleed** — low risk, 1 PR: add `*.pptx filter=lfs` to
  `.gitattributes` (or move the decks to a GitHub Release / external store) so
  future updates do not re-bloat history.
- **(b) Reclaim history** — high risk, **maintenance window only**:
  `git lfs migrate import --include='*.pptx'` (or BFG) rewrites history, which
  needs a force-push to `main` (branch protection blocks this) and invalidates
  every open PR. Run solo, after all other PRs are merged, with maintainer
  coordination. Only this phase actually shrinks existing clones.

## Sequencing notes

- Priority 1 and each Priority 2 file are independent (distinct files) — safe to
  review in parallel, but merge serially to avoid rebase churn.
- Priority 3(b) must run **after** everything else merges (history rewrite
  invalidates in-flight branches).
- The CI `changes` job now tolerates a moved base (PR #318), so behind-branch
  PRs no longer hard-fail on "no merge base" during this multi-PR campaign.
