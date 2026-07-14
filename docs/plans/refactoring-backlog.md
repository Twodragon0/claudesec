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

## Priority 2 — Large-file decomposition — ✅ DONE

All five items shipped as their own PRs (#325, #339/#340, #343, #341, #342).
Incremental, **one file per PR**, safest-first (thickest test coverage first).
Pure moves; the coverage gate is the safety net.

1. `dashboard_data_loader.py` — ✅ DONE (PR #325): hoisted the five pure nested
   closures out of the 308-line `load_datadog_logs` to module level
   (`_dd_normalize_log`, `_dd_normalize_signal_severity`, `_dd_inc_severity`,
   `_dd_extract_items`, `_dd_normalize_log_severity`).
2. `diagram-gen.py` — ✅ DONE: extracted the scan-data layer to `diagram_data.py`
   (`CATEGORIES` + `_parse_ocsf_json` / `load_prowler_files` / `load_scan_history`
   / `aggregate_scan_data`) and the SVG builders to `diagram_svg.py` (`_svg_escape`
   / `generate_architecture_svg` / `generate_overview_svg`), re-exported into
   `diagram-gen.py` (838→545 lines). `generate_security_domains_diagram` stays put
   so the `test_ci_diagram_gen_canonical_sync` frameworks-derive guard still fires.
   Verified: pytest 99.12% floor holds, 129 diagram tests pass, and all six
   generated `.drawio`/`.svg` files are **byte-identical** (SHA-256) before/after.
3. `output.sh` — ✅ DONE (prowler compliance-summary extraction): moved the
   OCSF detection loop + embedded `python3` compliance parser out of
   `save_scan_history` into `_prowler_compliance_summary_json` in the sibling
   `scanner/lib/output_prowler.sh` (the existing home for prowler output logic).
   `save_scan_history` now just calls it and keeps the `comp_field` assignment.
   The python body is **byte-identical** (md5 verified); `${BASH_SOURCE[0]}` still
   resolves `compliance-map.py` from `scanner/lib/`. The prowler dashboard-summary
   HTML table (`_prowler_dashboard_summary`) was already split out earlier.
4. `checks.sh` — ✅ DONE (kubectl extraction): moved the 11 kubectl/kubeconfig
   discovery and cluster-access helpers (`_kubectl_cmd`, `has_kubectl_access`,
   `kubectl_list_contexts`, `kubectl_current_context`,
   `kubectl_auto_find_kubeconfig`, `kubectl_discover_kubeconfigs`,
   `kubectl_detect_cluster_type`, `kubectl_current_context_uses_oidc_exec`,
   `kubectl_ensure_access`, `kubectl_cluster_info`, `kubectl_server_version`)
   verbatim into a new `scanner/lib/kubectl.sh` (703→387 lines in `checks.sh`;
   ~329 lines in the new file). The generic helpers (`has_command`,
   `run_with_timeout`, `has_file`, `has_dir`, `file_contains`, `files_contain`,
   `count_files`, `is_git_repo`, `git_remote_url`) plus `collect_environment_info`
   and `run_category_checks` stay in `checks.sh`. The AWS / GCP / Azure / Datadog /
   GitHub / Okta credential helpers were already split out to
   `scanner/lib/checks_credentials.sh` in #332 — no further credential grouping is
   pending.
5. `scanner/claudesec` — ✅ DONE (dashboard-serve extraction): moved the
   dashboard HTTP-serve logic (`open_url_best_effort`, `serve_dashboard`)
   verbatim into a new `scanner/lib/dashboard_serve.sh` (839→723 lines in the
   entrypoint; ~140 lines in the new file). It is sourced after `output.sh`
   (whose `error`/`warning`/color helpers it uses). Like `datadog.sh` it is
   network-I/O code, so it is intentionally NOT added to the kcov
   `--include-pattern` SUT set. The Datadog artifact collection half of this item
   was already covered by `collect_datadog_dashboard_artifacts` in
   `scanner/lib/datadog.sh` (#334); only the entrypoint calls it.

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
