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

### Cycle #283–#284 — DAST alert signal quality + dashboard_mapping split (merged 2026-06-25)

- **DAST alert noise (#283):** `dast-full-scan.yml` defaulted its nightly scan to the
  placeholder `staging.example.com`, and the notify step opened a fresh date-stamped,
  detail-free critical issue on every failure (no dedup) — the root cause of the stale
  #71/#72/#74 noise. Fix: gate the scheduled run with
  `if: workflow_dispatch || vars.DAST_TARGET_URL != ''` (no more example.com fallback;
  manual dispatch requires an explicit authorized URL), and rewrite the notify step to
  deduplicate into a single open tracker issue (reopen + comment if present) carrying a
  real High/Medium/Low risk breakdown parsed from `report_json.json` plus the run URL.
  Retains the `schedule:` trigger + SARIF upload (guarded by `test_ci_security_gate.py`).
  To re-enable nightly scanning, set repo variable `DAST_TARGET_URL`.
- **dashboard_mapping split (#284):** `dashboard_mapping.py` (1293 lines, over the 800-line
  coding-style cap) split behavior-preservingly via façade re-export into
  `dashboard_compliance.py` (464) + `dashboard_arch.py` (243); `dashboard_mapping.py` now
  625 lines and re-exports all 16 public names (`# noqa: F401`), so the 9 importers are
  unchanged. The fallback-coverage test (`_reload_with_fallback`/`TestFallbackBranch`) now
  reloads `dashboard_compliance` (where the inline compliance fallback moved) — otherwise
  that branch drops to 29%. Verified: byte-for-byte block preservation, 1368 pytest passed,
  scanner/lib coverage 99.12% (≥99% floor; 3 affected modules at 100%), 195 CI guards passed.
- **Stale issue triage:** closed #71/#72/#73→#74 (DAST noise, superseded by #283) and #14
  (npm OIDC `--provenance` live via #262 + `provenance-verify.yml` green + v0.7.2 published).
  10 open issues remain (real backlog: compliance/perf/enhancement); #68 is the ZAP-baseline
  single-tracker issue and is intentionally kept open.
- **dashboard_data_loader split:** `dashboard_data_loader.py` (930 lines, over the cap) split
  via façade re-export into `dashboard_data_analysis.py` (220: Prowler analysis + provider
  filters + env status); loader now 735 lines, re-exports the moved public names plus
  `_normalize_severity` (a test accesses it through the loader namespace). Verified 1368
  pytest passed, scanner/lib 99.12%, both modules covered.
- **Deferred (deliberate, NOT done):** `diagram-gen.py` (927) and `scanner/lib/checks.sh` (930)
  are only ~16% over the 800-line *soft* cap and do not split cleanly via the façade pattern:
  - `diagram-gen.py` is a hyphenated CLI script loaded by its test via
    `spec_from_file_location` with **no `sys.path` setup**; any sibling-module extraction needs
    a `sys.path` bootstrap in the script AND risks internal import cycles (overview builders
    call the drawio primitives). Infra change for marginal benefit — revisit only if the file
    grows materially.
  - `checks.sh` is core Bash sourced by the scanner entry and gated by kcov (90% floor); a
    source-split is a different, higher-risk mechanism than Python re-export. Defer to a
    dedicated bash-refactor pass.

### Cycle #285–#303 — link hygiene, image size, plugin surface (merged 2026-06-25 → 07-05)

- **Lychee / link rot:** the exclude allowlist moved out of inline `lint.yml` args into
  `lychee.toml` as a single source, guarded by `test_ci_lychee_config.py` (#290, #292, #296);
  a monthly redirect / link-rot sweep landed as a notifier-only workflow with a self-healing
  issue (#298) plus a triage skill (#299). Redirects were resolved to canonical URLs
  (#291, #301, #302). **Standing gotcha:** CI runs lychee with `accept=100..=599`, so a 404
  PASSES CI and is still rot — capture the final status, not just the effective URL.
- **Gates:** Docker scanner image held at 513 MB by a tightened size gate (#286); Lighthouse
  Performance floored at >= 90 on live Pages (#288).
- **Plugin:** `/prowler` and `/compliance` marketplace slash commands (#289).

### Cycle #304–#320 — single-sourcing, and a hook that was a no-op (merged 2026-07-05 → 07-09)

- **One source per mapping.** `compliance-map.py` became the sole source of
  `COMPLIANCE_CONTROL_MAP` — the inline fallback in `dashboard_compliance.py` had drifted
  critically and now hard-fails instead (#304). Same treatment for Prowler provider labels
  (#305), diagram-gen domains/frameworks (#306), Prowler display order (#308), and
  `load_scan_results` + the scan-category list (#314).
- **Keyword false positives:** substring-matching keywords removed from the compliance map
  with a collision guard (#307). A blanket min-4-char rule was considered and **REJECTED** —
  it misses 4-char `port`/`node` and breaks ~11 legitimate 3-char acronyms (cve, iam, kms,
  mfa, pii, tls, vpc); a regression pin plus a proper-substring collision guard is used
  instead.
- **ISMS-P N/A:** non-assessable 3.x PII controls render N/A (#309), extended framework-wide
  to governance controls (#311), with the policy documented (#310, #312).
- **`hooks/security-lint` never ran.** The PreToolUse hook did not read stdin JSON, so it was
  a silent no-op (#313). Worth remembering as a class: a hook that exits 0 without parsing
  its input is indistinguishable from a hook that approved everything.

### Cycle #321–#348 — scanner decomposition + Docker hardening (merged 2026-07-07 → 07-15)

- **`checks.sh` / `output.sh` / `diagram-gen.py` decomposed** into leaf modules:
  cloud credential helpers (#332), `run_category_checks()` (#336), kubectl/kubeconfig
  (#341), dashboard-serve (#342), Prowler compliance-summary out of `output.sh` (#343) and
  then its embedded Python (#346) and awk (#348) out into real program files, Datadog
  collection (#334), draw.io XML primitives (#327), `diagram_data` + `diagram_svg` (#340).
  Extracting the embedded interpreters is what took `output_prowler.sh` from 65.79% to 100%
  kcov — an embedded heredoc is unmeasurable by definition.
- **Dead code removed** from `scanner/lib` (tested-but-unreachable functions) with a
  reachability guard added (#338, #339).
- **Docker:** dashboard container locked down per CIS Docker Benchmark (#331), capabilities
  dropped + `no-new-privileges` on scanner services (#333), bundled trivy 0.69.3 → 0.72.0
  clearing 1 CRITICAL + 45 HIGH (#335). **The bundled trivy binary is a `curl` ARG and is
  Dependabot-untracked — it is ~90% of the image's CVE count and must be bumped by hand.**
- **kcov:** a local docker-based coverage harness (#330) with a guard keeping it in sync with
  CI's patterns and floor (#337).

### Cycle #349–#364 — output-escaping: every hand-built sink (merged 2026-07-16 → 07-27)

- **CWE-94 code injection** removed from three Prowler helper scripts by passing values as
  env vars instead of interpolating into `python3 -c` (#349), with a regression guard
  extended to unquoted heredocs and quote-concatenation (#350) and later narrowed to flag
  only bash-EXPANDABLE `$` to drop a false positive (#352).
- **Findings JSON** rebuilt via `json.dumps` for correct escaping (#356), after fixing that
  it emitted only one of details/remediation (#355), read 5 of 6 packed fields (#357), lost
  `FINDINGS_*` arrays from parallel category subshells (#358) and emitted invalid JSON for
  control characters (#359); pinned by an offline E2E (#360).
- **The remaining sinks:** `SCAN_DIR` + Datadog service/env in hand-built JSON (#361),
  Prowler provider label HTML-escaped (#362 — `_prowler_html_escape` needs a
  `shopt patsub_replacement` guard, because neither bare `&` nor `\&` is portable across
  bash < 5.2 and >= 5.2), Datadog `ddtags` percent-encoded (#363). Source-pinned by
  `test_ci_no_raw_output_interpolation.py` (#364).

### Cycle #365–#375 — dashboard XSS / CSP hardening (merged 2026-07-27 → 08-05)

- Provider-name stored XSS fixed (#365); `onclick` inline-JS-string breakout and
  `javascript:` hrefs replaced by `data-action` delegation plus a `safe_url()` scheme
  allowlist (#366, #369). The `onclick` → `data-action` migration completed across all 48
  handlers (#367) — which made formerly-DEAD OWASP / Arch / Compliance / setup controls
  actually work, because a CSP that forbids inline handlers had been silently killing them.
- A headless-Chrome control-liveness smoke now drives every delegated `data-action`
  (#370, #372, #374); dead audit-points render wiring removed (#371). Retrospective in
  `docs/reports/dashboard-xss-csp-hardening-retrospective.md` (#373).
- **Standing baselines:** `test_dashboard_control_liveness.sh` 14/14 live + 2 documented
  skips; `test_asset_dashboard_control_liveness.sh` 20/20 + 2. Re-run both after ANY change
  under `scanner/lib/dashboard_html_*`.

### Cycle #376–#437 — the ADR-001 guard audits: guards that guarded nothing (merged 2026-08-05 → 08-13)

The largest block in this log and the one whose *method* matters more than its diffs. Read
`docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md` and the retrospectives
(#380, #395, #409, #418, #421, #428, #433) before touching a `test_ci_*.py`.

- **Guards read green while the control was gone.** Class-1 (comment / quote state): a
  `# exit 1` or `;#exit 1` satisfied a presence assertion (#376). Class-2 (matcher
  completeness): `case`-arm order, case-sensitive runner regexes (#378, #379). Then an AST
  meta-guard found **seven more** inert guards that had passed human review — assertions
  aimed at the raw whole file, satisfied by the workflow's own comments (#383, #385, #402).
- **A required check can be neutered without touching its logic:** one
  `continue-on-error` line (#407), a relocated `cwd` (#412), a `branches:` filter that meant
  the two required workflows never fired on a stacked PR (#386), a comment line truncating
  the block a collector was reading (#419), and `templates/` shipping workflows to other
  repos that no guard read (#415, #417).
- **Execute the gate, do not parse it.** #404 proved the CRITICAL severity gate blocks by
  RUNNING it, which closed ten evasion shapes at once where three parser fixes had closed
  one, four, then six. #406 then deleted the text guard it superseded. But execution only
  covers what the executed thing sees — runner-consumed keys needed their own
  column-derived, fail-closed matcher after four more defeats at `18 passed` (#408).
- **Shared primitives, never hand-rolled.** `_ci_guard_util.py` now owns comment stripping,
  key/column derivation, block collection and the mutation helpers (#393, #414, #419, #425);
  `apply_mutation` / `apply_regex_mutation` RAISE on a stale anchor because a bare
  `str.replace` no-ops silently (#416). **Note the asymmetry: `apply_mutation(…, count=0)`
  replaces NOTHING (`str.replace` semantics) while `apply_regex_mutation(…, count=0)`
  replaces ALL.**
- **The probe is evidence and gets audited like the guard.** Across #411/#415/#419/#420/#424
  the probe was wrong **nine** times and the guard right every time; those nine became a
  pre-flight checklist in the guard-authoring skill (#429, #432, #382). A "no observable
  effect" verdict is a measurement, not a conclusion — in #420 the immunity was one
  unasserted `strip_comment_lines` line in the CALLER.
- **The audit falsified its own retrospectives four times** (#418, #421, #428, #433) and the
  `ADR-001 §4` citation population was miscounted (81, not 67 — #423, #426, #430, #434,
  #436). Do not trust a number in a retrospective without re-deriving it.
- **Silent-skip fixes:** the `|| github.event_name == 'schedule'` arm was dead in seven jobs
  because `lint.yml` had no `schedule:` trigger at the time — **#394 added one**
  (`cron: '0 5 * * 3'`, Wednesday 05:00 UTC), so the arm is LIVE today and a new job may rely
  on it. Verify with `sed -n '1,40p' .github/workflows/lint.yml` before repeating the claim;
  the first draft of this entry asserted the present tense and was wrong. It had left
  `npm-audit` dark ~7 weeks / 117 commits and `dast-full-scan`'s
  nightly `skipped` ~42 nights; both now surface a self-healing issue instead of reading green
  (#394, #396, #397). A stuck check-run detector was added and wired into the merge wait loop
  (#427, #431).
- **Branch protection changed:** `require_code_owner_reviews` is now **false** and codified
  as the deliberate value in `scripts/sync-repo-protection.sh` (#403). A `BLOCKED` PR means
  CI in flight, not a missing approval.

### Cycle #438–#468 — positive controls, compliance correctness, guard reachability (merged 2026-08-12 → 08-21)

- **An assertion nobody has watched fail is not evidence.** `provenance-verify`'s
  terminal-silent install branch got a consumer (#438); the CRITICAL gate got a positive
  control on its own input (#439); and **21 of 54 shell tests turned out to be run only by a
  step that could not fail** (#440). The 99% coverage floor itself accepted 98.50% and exited
  0 until `--cov-precision=2` was made load-bearing (#453).
- **Compliance scoring was wrong in both directions.** The repo hand-wrote a worse copy of a
  mapping Prowler already ships, and now reads Prowler's instead (#450, #451). Keyword
  matching produced controls "failing" on 88 hits with none real (#454), `change` matching
  316 checks of which 308 were not changes (#449), `vulnerability` never matching
  `vulnerabilities` (#452), a subnet "associated" with a security group scoring as access
  control (#447), 261 checks scored against the wrong requirement (#459) and five keywords
  scoring a sibling control's checks (#461). CMMC scored 9/9 on an estate it had never
  looked at (#455) and NIST 800-53 10/10 on a Kubernetes estate (#456). **`map_compliance`
  sees ONLY Prowler OCSF findings, never `scanner/checks/**` — verify keywords against the
  Prowler catalog or expect a 66–100% miss rate.** SOC 2 (TSC) added as the 7th framework
  (#441). **Framework display names are load-bearing:** a native match is framework-level, so
  a wrong name marks ALL of that framework's controls FAIL.
- **Dashboard truthfulness:** Grade A over 40 checks with nothing on screen saying so (#445);
  the scan dashboard folded into the ISMS page, which had been lying about freshness (#446);
  `--output` printed "Report saved to X" and wrote nothing (#448).
- **Guard reachability:** the `ci_config` bucket + a dedicated `ci-guards` job (~15s,
  stdlib-only) because the guards could not run on the files they guard (#463). **Do NOT
  widen the `scanner` bucket for guard reachability — it fires kcov.** Two rounds of
  "reached but running nowhere" shapes closed (#465, #468), and the kcov-skip guard that had
  never once fired was fixed (#466): **detect kcov via `KCOV_BASH_XTRACEFD`, never
  `TracerPid` — kcov 42 instruments via xtrace, so `TracerPid` is 0.**

### Cycle #469 — Python static analysis (merged 2026-08-24)

- `lint.yml` ran 21 jobs and **none of them was a Python linter** — no ruff/flake8/pylint/
  mypy/black/bandit in any workflow, `.pre-commit-config.yaml`, or `requirements-ci.txt` —
  while Bash had shellcheck plus a 90% kcov floor. Added a `python-lint` job, `ruff.toml`
  (`select = ["E9","F"]`, `ignore = ["F541"]`) and a pinned `requirements-lint.txt`.
- **The 99% coverage floor cannot see dead code, and here is the measurement:** deleting 19
  dead statements moved `scanner/lib` from 3712/22/**99.41%** to 3693/22/**99.40%**.
  Coverage went DOWN and the missed count did not move, because every dead statement was
  already covered. Never cite a coverage floor as evidence against dead code.
- Scope is narrow on purpose: ~548 other ruff findings (`BLE001` blind-except 65, `S110`
  try-except-pass 24) are NOT enabled. `python-lint` is in `lint-gate.needs`, so widening
  `select` changes a required check and needs an explicit decision.
- Mutation-testing that wiring found a **pre-existing, general** hole: a typo in
  `needs.<job>.outputs.<name>` or `github.<prop>` yields `''`, so the job is permanently
  `skipped` and `lint-gate` counts `skipped` as a pass. Three such typos left all **918**
  existing guards GREEN. Now pinned by `test_ci_needs_output_refs.py`.

### Cycle #471–#490 — the decode boundary, and how many copies of a reader a repo can hide (merged 2026-08-24 → 08-26)

- **One non-UTF-8 byte flipped a compliance control FAIL → PASS while keeping
  `match_source="prowler"`.** `except Exception: providers[name] = []` plus an `open()` with
  no `encoding=` meant an unreadable Prowler file became an empty-but-present provider — and
  **corrupt was worse than missing**, because missing degrades to `"keyword"` matching while
  present-and-empty scores as a clean prowler-backed pass (#471). Three real FAILs reported
  as 0.
- **#471 fixed one of two independent copies of that loader, and the guard imported only the
  fixed one** (#484). `diagram_data.load_prowler_files` was a second implementation with the
  same defect. Fixed, then the three `diagram_data` loaders were single-sourced from
  `dashboard_data_loader` with an **object-identity (`assertIs`) guard**, because a
  source-line pin still passes against a re-added shadowing local `def` (#485).
- **`except json.JSONDecodeError` never caught the decode error it was guarding.**
  `UnicodeDecodeError` is a sibling `ValueError` subclass, not a `JSONDecodeError`, so one bad
  byte aborted the whole dashboard build. 15 real handler sites audited: 12 widened to
  `ValueError`, 3 given `errors="replace"` at the decode boundary, 2 left narrow on purpose
  (`str`-only input), 1 deferred to #472 (#487). All 16 `Path.read_text()` in
  `scripts/build-dashboard.py` now declare `encoding="utf-8"` (#486).
- **Then the same fixes turned out to have un-fixed CLONES in `scripts/`: this repo has SEVEN
  independent Prowler OCSF readers** (#488). 18 sites across 8 files. The guard now scans
  **`git ls-files` output, not the filesystem** — `.gitignore` excludes a local operator
  script, so a filesystem walk is red locally and green in CI. #490 then extracted the 7
  genuinely duplicated helpers into `scripts/lib/`; `load_env` and `collect_prowler` were
  deliberately NOT unified (secret-key normalisation, 140/389 diverged lines).
- **A corrupt artifact hid the warning that the artifact was missing** (#489): an unread nmap
  file made `network_evidence` truthy, which suppressed "network or Datadog telemetry
  missing" from `visibility_gaps`. It also surfaced a latent bug where the `defusedxml`-absent
  branch set `parser.entity = {}` — readonly on CPython 3.13, so that branch **always** raised
  and every nmap file silently became an empty scan.
- **Docker/CI pins:** prowler 5.39.1 (#473) with the six new providers stripped to restore
  size headroom (#481); alpine moved to **3.23, the last minor on the py3.12 line** (#479);
  codeql-action v4.37.8 at **all four** pinned sites (#483, superseding #478 which bumped one
  and left `templates/codeql.yml` ×3 behind). A temp-file leak test was reading other runs'
  residue (#480).
- **The `#472` stack (auth/SSO fail-closed) merged 2026-08-26 after human review**, using the
  retarget-before-merge order: `gh pr edit <dependent> --base main` FIRST, then squash-merge
  the base, then `git rebase --onto origin/main <captured fork point>`. `--delete-branch` on a
  base auto-closes dependents, and a closed PR's base cannot be changed.
- **Process lesson: enumerate with AST, never a single-line grep.** "17 handler sites" and
  "11 shared functions" were both wrong (real: 15 and 12) — multi-line tuples and structural
  clones need `ast.walk`. And **grep for other implementations before closing a fix.**

### Cycle #497–#504 — the two ways a scheduled check stops, and attribution (merged 2026-08-26 → 09-01)

- **A gate that never fires reads exactly like one that found nothing.** The nightly DAST was
  gated on an unset `DAST_TARGET_URL`, so 42 consecutive nights reported a clean `skipped`
  (#399/#497). The gate is gone — the nightly scans this repo's own dashboard container, the
  same target `dast-baseline.yml` already uses — so it cannot skip.
- **Removing the skip left the quieter half open: a schedule that never FIRES.** No run at
  all, so nothing is skipped, nothing is red, and an Actions list sorted by recency still
  shows the last green run. Five real causes (60-day inactivity shutdown, `gh workflow
  disable`, best-effort cron — a ~10h delay is on record in run `33070461602` — rename/
  default-branch change, all-runs-fail). `dast-freshness-watch.yml` (#502) watches the AGE of
  the newest **`event=schedule`** run and self-heals into one issue. Three load-bearing
  choices: `event=schedule` only (a `workflow_dispatch` proves someone pressed a button, not
  that cron is alive); it also runs on `push` to `main` (a cron-only watcher shares the exact
  failure mode it watches); 48h not 24h (a threshold at the cron period trips on ordinary
  jitter, and a notifier that cries wolf gets muted — silence again).
  **Its first commit was INERT**: `listWorkflowRuns` is an Actions-API read and the job had no
  `actions: read`. Reviewing the logic and not the token grant is how a watcher ships dead.
- **Guard-scoping, round N: presence is not attribution.** `test_ci_npm_publish.py` asserted
  `branches:` and `branches: … main` against the whole comment-stripped `npm-publish.yml`.
  Comment-stripping (#383) answers the *commented-out* regression only. Measured 2026-09-01,
  PyYAML-confirmed: leave `push:` with just `tags:` and move `branches: - main` to a new
  `pull_request:` — the version-bump auto-release is dead (`push -> {'tags': ['v*']}`) and
  **1181 CI guards repo-wide stay GREEN**. Two sibling shapes were equally invisible (`push:`
  deleted with the filter re-planted elsewhere; `branches:` → its opposite `branches-ignore:`).
  Fixed by the documented discipline — scope to the block, then assert a COUNT of exactly one
  — with `trigger_block()` promoted into `_ci_guard_util` so `test_ci_pr_trigger_scope.py`'s
  copy of that logic became a thin binding rather than a second implementation.
- **A guard's mutation self-tests must drive the real detector.** The old
  `TestAutoReleaseTriggerScoping` asserted against a re-implementation of the pattern, so it
  could not have noticed the block scoping was missing. Same family as #485's `assertIs`
  identity guard: pin the object the guard actually calls.
- Related sweeps in the same window: the inline-handler guard scanned 11 of 23 dashboard
  sources because `_SOURCE_FILES` was hand-written (#501 → glob over `git ls-files`), and four
  guard checks passed while the control they protect was gone (#503).

## Open Backlog

Re-derived from `gh issue list` + verified repo state on **2026-09-01**. **Verify before
working an item** — this list rotted twice before, and the previous revision (2026-08-26)
listed FOUR already-closed issues (#295, #297, #381, #399) as open.

**Closed since the last revision — do NOT re-propose as open:** `#295` (prowler/alpine
freeze), `#297` (quarterly ADR-001 audit), `#381` (lychee sweep), `#399` (DAST nightly not
running). Check with `gh issue list --state open` before trusting any entry below.

- **`#405` branch-protection drift-watch is not running** (`REPO_ADMIN_TOKEN` missing).
  **BLOCKED ON A HUMAN — there is no code fix.** The workflow self-heals into this issue
  rather than reporting green (#396), so the issue IS the alert, and it re-confirms itself on
  every scheduled run (last 2026-08-31T21:08). Unblock: a fine-grained PAT scoped to this repo
  with **Administration: read**, stored as the `REPO_ADMIN_TOKEN` repo secret; the next clean
  run closes the issue. Check: `gh run list --workflow=protection-drift-watch.yml` runs green
  either way, so the ISSUE state is the signal, not the run conclusion.
- **`#498` ZAP full-scan tracker — the BODY is stale, the comments are current.** The nightly
  reuses one issue and **appends a comment**; it never rewrites the body. So #498's body is
  still the 2026-08-26 snapshot listing style-src `unsafe-inline` + COEP/COOP/CORP as live,
  while its own 2026-08-28 comment reports all four under **"Resolved Alerts"** (fixed by
  #500 on 08-27). Everything still open on it is ZAP INFO-tier: suspicious comments,
  storable/cacheable content, User Agent Fuzzer. The `.../'+safeHref(hubUrl)+'` "URL" is ZAP
  scraping a JS string literal out of inline `<script>` source — not an endpoint. Check the
  NEWEST comment, never the body. The body-never-refreshed behaviour is itself worth fixing:
  a tracker that shows fixed MEDIUMs as live is the red-while-fixed twin of this repo's
  green-while-defeated class.
- **`#39` ISMS-P 29 FAIL controls prioritised remediation plan** and **`#15` incident-response
  process 65% → 80%** are product/content work, not CI.
- **`#68` ZAP baseline** is the intentional single-tracker issue — keep it open.
- **`#12` Zscaler MCP integration**, **`#18` GitHub Projects board**, **`#20` marketplace
  plugin update** are `enhancement`-labelled product asks, not correctness work.
- **ruff ruleset widening** — `python-lint` is in `lint-gate.needs`, so widening `select`
  changes a REQUIRED check; it needs a decision, not a cleanup pass (see Cycle #469). Measure,
  don't quote a number: `ruff check --isolated --select BLE001,S110 --statistics scanner/
  scripts/` (61 + 21 on 2026-09-01).
- **zscaler `_unreachable` `reason` — WIRED UP in this PR, do not re-propose.** It had been
  write-only since #472: four distinct states recorded, zero consumers, so all five
  inaccessible sections printed a fixed sentence and SAAS-ZIA-002's said "RBA restricted" —
  correct for exactly one of the four and a confident misdiagnosis for the other three.
  Measured before/after on the same six unreachable sections, `_unreachable(0)` (DNS failure):
  `"Users API not accessible (RBA restricted)"` → `"Users API not read: request never reached
  the API (DNS failure, timeout, TLS error or connection reset)"`. The rendering lives in
  `_unreachable_detail` (Python, covered by the `scanner/lib` gate) rather than in bash, and
  is keyed on `reason` rather than recomputed from the status code so the two cannot disagree.
  The docstring's "the three states" / lists four is fixed in the same change.
  **Still open from that review:** `_load_saas_sso_stats` rejects the whole file if **any**
  `saas` entry is a non-dict — confirm deliberate before changing. Check:
  `grep -n "_load_saas_sso_stats" -A20 scanner/lib/*.py`.
- **`MEMORY.md` maintenance** — this file went **~185 PRs stale** once (#470), and then the
  freshly-written `#295` entry was **false within five hours** of being written: it asserted
  `PROWLER_VERSION=5.30.1 on alpine:3.20` while #473/#479/#481 moved both the same day. The
  rot mechanism is not staleness alone — **a backlog entry that restates repo state it does
  not own goes stale silently and reads as authoritative.** State the *decision condition*
  and the command that checks it, never the current pin. `CLAUDE.md` points the
  continuous-improvement workflow here to pick work, so a wrong entry sends the next session
  at already-finished work. Append a cycle entry when a themed block of PRs merges, and
  re-derive the backlog from `gh issue list` rather than editing entries in place.

> Reference: CIS Controls v8 (secure configuration & continuous vulnerability
> management) anchors the Docker-pinning and scanner-correctness work above;
> OWASP CICD-SEC-1/-7 anchor the guard and required-check work in Cycles
> #376–#468.
