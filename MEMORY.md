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
  single-tracker issue and is intentionally kept open. **CORRECTED 2026-09-17: "single-tracker"
  implies something writes to it; nothing does** (`dast-baseline.yml` sets
  `allow_issue_writing: false`) — see the `#68` entry in Open Backlog.
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

### Cycle #505–#511 — the reassuring surface, and an error nobody could see (merged 2026-09-01 → 09-02)

- **Red-while-fixed, the mirror of this file's usual class.** The ZAP tracker's issue body
  froze on the day the action opened it: `zaproxy/action-full-scan` only ever APPENDS a delta
  comment, so #498's body showed four MEDIUMs as live for four days after #500 fixed them
  (#505). It costs what green-while-defeated costs — a tracker that cries wolf gets muted, and
  a muted DAST tracker is how the nightly went 42 nights unwatched. Read the NEWEST comment,
  never the body, on any tracker an action maintains.
  **SUPERSEDED 2026-09-17 for #498 — do not apply this sentence unqualified.** #505 added a
  body-refresh step, and once it existed the direction flipped: the body is regenerated nightly
  while the append-only delta stream goes quiet whenever a run has no new-vs-resolved alerts, so
  the newest comment is now the STALER surface there. The discriminator is **whether a
  body-refresh step exists**, not the tracker's age — see the `#498` entry in Open Backlog.
  Left in place rather than rewritten because this sentence was true when written and the
  reasoning above it still holds for trackers without such a step.
- **Write-only state is not state.** zscaler's `_unreachable` `reason` had recorded four
  distinct causes with zero consumers since #472, so all five inaccessible sections printed
  one fixed sentence and SAAS-ZIA-002's claimed "RBA restricted" — right for one of the four
  causes and a confident misdiagnosis for the other three (#506). Rendering lives in
  `_unreachable_detail` (Python, under the `scanner/lib` gate) and is keyed on `reason` rather
  than recomputed from the status code, so the two cannot disagree.
- **An unpinned design choice is not a decision.** `_load_saas_sso_stats` rejecting the whole
  list over one bad entry is CORRECT — its output is a DENOMINATOR, and skipping an entry
  shrinks Y silently while the percentage keeps looking confident. It needed work only because
  nothing distinguished it from the skip design: the all-entries-bad fixture cannot (both
  return `None`), and a warning skip variant passed all 54 tests. Four mixed-list cases pin it
  now (#507). Same "corrupt is worse than missing" shape as #471/#489.
- **`zip` truncates, so 73 keys and 73 positional arguments needed something holding them
  equal** (#509). The reason arity alone was not enough: a key with no `{{KEY}}` in the
  template is a DEAD replacement and FOUR already existed, so the common drift is adding
  key+argument and forgetting the template. Baselined as EQUAL, not merely non-growing, so
  wiring one up also fails until it is dropped. Deleting those four dead keys and their caller
  arguments was left OPEN here — a behaviour change in a 73-argument call, not a guard.
  **DONE 2026-09-02; this sentence contradicted the Open Backlog entry below for two weeks.**
  Verified 2026-09-17: `KNOWN_DEAD_KEYS = set()` and
  `python3 -m pytest scanner/tests/test_ci_template_keys_arity.py -q` → `14 passed`. Recorded
  rather than deleted because the shape is the point — a cycle entry states what was true *at
  merge*, so a follow-up sentence inside one silently becomes a false claim the moment the
  follow-up lands. Land the completion in the same edit that writes the next cycle, or do not
  write the "still OPEN" clause into the historical entry at all.
- **ruff widened to `["E9","F","B","PLE"]`** (#508). `B905` (`zip()` without `strict=`) is why,
  and its two sites needed OPPOSITE answers. `BLE001`/`S110` stay REJECTED **with the numbers**
  (61 + 21, concentrated in paths that exist to degrade rather than crash — 82 `# noqa` for
  zero defects); `PLW1508`'s 7 sites are all `int(os.environ.get(k, 0))`. Per-family
  measurements live in `ruff.toml` beside the `select`; re-measure with
  `ruff check --config ruff.toml --select <F> --statistics .` rather than re-deriving by hand.
- **`templates/codeql.yml` drifted behind the repo's own pin for the second time.** Dependabot
  bumps only what it can see, and a template workflow shipped to other repos is not in
  `.github/workflows/` — so #511's codeql bump moved one site and left three. Identical to
  #478→#483. `test_ci_template_pin_policy` caught it both times and is the only thing that
  will; the manual step is permanent, so **bump all FOUR sites** (`dast-full-scan.yml` +
  `templates/codeql.yml` ×3) whenever codeql moves. Note the blast radius of a guard that runs
  in two jobs: the three red checks on #511 (`ci-guards`, `scanner-unit-tests`, `Lint`) were
  one root cause, and reading them as three problems sends you chasing the action bumps.
- **An `##[error]` inside a green job is invisible.** The `Publish scanner unittest report`
  step had been printing two of them on every run — including green pushes to `main` — because
  `report_paths: 'test-reports/*.xml'` fed the Cobertura `coverage.xml` to a JUnit parser, and
  because creating a check run needs `checks: write` while `lint.yml` grants `contents: read`.
  Non-fatal both times (`fail_on_parse_error` and `fail_on_failure` default to `false`), so the
  `JUnit Test Report` check run the repo believed it published **had never once existed**.
  Fixed by cross-referencing `report_paths` to the producing `--junitxml=` path and setting
  `annotate_only: true`; pinned by `test_ci_junit_reporter_live.py`, whose either/or on the
  permissions arm carries a positive control so the arm cannot be dead text. **The general
  lesson: a step's declared config and its observed behaviour are different claims.** Nothing
  in this repo reads job logs, so a reporter can 403 forever behind a green check.

### Cycle #513–#522 — nine dead controls, and the sweep that reported none of them (merged 2026-09-02 → 09-03)

Full write-up in `docs/reports/green-while-dead-retrospective.md`. The METHOD is the
deliverable here; the diffs are small.

- **Nine instances of one shape: the declared capability and the observed behaviour were
  different claims and nothing compared them.** Worst two were on a required gate and a
  permission boundary — `pii-check` ran `find` and nothing else for 7 days (a `#` after a
  `\` continuation truncated the command; `bash -e` without pipefail hid the 127 in the
  left half of the pipe), and the Dependabot auto-arm's documented "Fail-closed" comment
  was FALSE (an empty path list walks the exclusion loop and arms auto-merge on a
  `Dockerfile` PR). The rest cost reporting only — but "it is only reporting" is a verdict
  you may state AFTER measuring, not instead of.
- **A positive control validates the MARKER it exercised, not "detection".** My log sweep
  proved it caught `##[error]` on a known-bad run, then reported 0 findings across 37 jobs.
  Wrong: `"error - "` (Codecov's own logger, lowercase, not an annotation) and
  `No files were found with the provided path` were not in the pattern set, and the static
  half only compared tokens against API calls, so it could not see shell-level swallowing.
  Three real defects sat inside the "clean" range.
- **`outcome=failure` matched ZERO times anywhere** — re-derived independently on 18 jobs
  of run `33745520620`, not taken on trust. It is the most plausible marker for a swallowed
  failure and it misses the whole class, because `fail_ci_if_error: false` makes the action
  exit 0 while its own logger writes at error level.
- **Static and log-empirical are complementary, not alternatives.** The junit `checks.create`
  call has no string in any YAML (it is inside a third-party action) so static cannot see
  it; the two broken `templates/` workflows never run here — one is rejected by GitHub
  outright — so no log can exist for them, and `actionlint` was the third surface.
- **A fix creates the class, three times over.** #496's explanatory comment is what broke
  `pii-check`. My own first `pii-check` fix was incomplete: `set -euo pipefail` catches the
  shipped shape but NOT the one where the orphan begins with `!`, because bash reads that as
  pipeline negation and exits 0 — so the `find` was collapsed onto one physical line, which
  makes the arrangement impossible rather than detected. And #516's own new merge-time check
  read the wrong diff (`gh pr merge --delete-branch` prints the local catch-up, not the
  squash), false-alarming twice before #517 fixed it.
- **A mutation that does not reproduce the hole may be defence in depth.** Stripping
  `PATHS_KNOWN` alone left the sibling empty-list gate holding. The guard's own message
  ("check the SECOND possibility first") is what surfaced it; the fixture now strips both
  and measures each gate's independent sufficiency.
- **Narrowing a guard's scope is a decision that needs its numbers.**
  `test_ci_watcher_states_consumed` deliberately is NOT a general dataflow analyser: a
  repo-wide survey reported four "unconsumed" states in `npm-publish.yml`, all false
  positives via job-level `outputs:` re-export. A guard people have to fight gets weakened,
  not repaired (#414).
- Guards 1088 → **1126**; catalog rows 62 → **67**; five new guards, three of which EXECUTE
  their subject. Codecov deleted outright — the repo has **zero** Actions secrets
  (`total_count: 0`), so no token ever existed and the badge rendered `unknown`.

### Cycle #523–#554 — the guards' own foundation under adversarial passes 7–10 (merged 2026-09-03 → 09-17)

**28 merged PRs** in the #523–#554 range (#532 is not a PR; #534 is still open; #535 and #547
are closed-unmerged Dependabot PRs superseded by #550 and #549). The through-line is that
**the checking apparatus became the subject**.
Where #513–#522 found declared-vs-observed gaps in the repo's controls, this cycle found them
in the guards that assert those controls — twice in the guard guarding the guards. Counts:
guards **1126 → 1472** (`python3 scanner/tests/_ci_guard_runner.py` → `ran=1472, OK (skipped=1)`),
catalog rows **67 → 73**.

- **Patching an enumeration a third time is the signal to invert it** (#528–#531, #533). #528
  widened the ADR guards off the literal `ADR-001` (the series is now DISCOVERED from
  `docs/devsecops/adr-[0-9]*.md`, so a new ADR cannot stay unscanned) — done the week ADR-002
  had **zero** citations, the one moment widening costs no baseline churn; ADR-001 had reached
  **81** uncounted citations by the other route. #529 then found that fix was inline in one
  guard while five others read published Markdown with less or nothing, and measured **all
  twenty guard-by-vector cells green-while-defeated before any fix**. Differential fuzz against
  markdown-it-py over 16,831 documents: **45 residual shapes → 14**, pinned as
  `MAX_SILENT_PASS_SHAPES`. **Why vectors 1 and 2 shipped at all is the sharpest part:**
  `markdown-it-py` was not in `requirements-ci.txt`, so every renderer-agreement class reported
  `testsRun=0, OK (skipped=1)` — the only check that could catch a primitive/renderer divergence
  never ran, and **failed open**. #530 stopped patching and inverted per ADR-001 §5: the
  catalog's machine-readable half moved to `ci-guard-inventory.toml` (70 guards, 17 collectors;
  `tomllib` is stdlib so `ci-guards` stays package-free), every verdict staying in prose. **The
  intuitive fix was measurably worse** — a single-pass reducer with shared block state scored
  **42** silent-pass shapes against the shipped 14, in two independent implementations. Measure
  before planning, not after. And state the inversion's limit honestly, as #530 does: the
  residual is **not eliminated, it moves** — to `test_ci_catalog_doc_sync.py`, where the failure
  mode becomes documentation drift instead of a guard certifying coverage the published
  inventory does not show. A better failure mode is the win; do not read it as a solved class.
- **A check that cannot run where it matters is not a check** (#531, #533). The only comparison
  that adjudicates the Markdown reduction *at a consumer* needs `markdown-it-py`, and
  `ci-guards` installs **zero packages by design** — a property documented in three places and
  asserted by none. So a catalog-only PR, the exact shape that introduces a residual, got the
  job and **skipped** the check; the measured payload leaves a reader seeing **0 of 70** guard
  rows with the suite green. Fixed with a separate 20 s `renderer-canary` rather than widening
  a bucket (which would have silently falsified those three docs). #531 **could not prove its
  own property** — its diff touched `scanner/tests/`, so the `scanner` bucket matched and kcov
  ran anyway. A doc-only PR is the only shape that can carry that proof, so #533 *is* the
  experiment, with its prediction written down before the run. Its first probe was also wrong:
  an anchored `re.match` reported `markdown` as no-match because the bucket pattern
  `(\.md$|^lychee\.toml$)` has no leading `^`. **The probe was wrong, not the bucket.**
- **The `ci-guards` execution proof reached its TENTH adversarial pass, and the attacker kept
  winning cheaply** (#536–#538, #543–#546, #548). Passes seven (#537), eight (#538), nine (#542)
  and ten (#546) are this cycle's, while #536 carries four earlier rounds inside one PR:
  a constant `ran=true` fell to closing a parking construct **above** it (2 lines);
  a parsed count fell to seeding `out="Ran 1 tests in 0.0s"` or `|| true` so a **red** suite
  publishes a real number; `grep -qE '^OK'` was not independent (`2>&1` captures the failure
  report, and guard messages put `OK  path` at column 0) and additionally fell to `cd /tmp/decoy`
  and to `-k` cutting **1264 tests to 18**. Pass 7 (#537): `load_tests` returning an empty suite
  — **two lines** — took 1262 tests to 1251 with the suite `OK` and the published count genuine,
  and it is invisible from the other side because **pytest does not honour `load_tests`** (same
  file: `Ran 0 / NO TESTS RAN` under unittest, `11 passed` under pytest). Pass 8 (#538) beat
  #537's per-file floor three ways, cheapest **1 line** (`C.__module__ = "test_ci_<victim>"`,
  because attribution was by a *writable attribute*); the repair was **attribution by
  construction** — discover one file at a time and let the union be what executes — at no
  measurable cost (~45 s either way). **The fail-open one is #543**, and it was in the check
  guarding the whole proof: `job_ran_proof_problems` pinned `lint-gate`'s positive-integer
  requirement with `re.search` over the **raw** block, which is a Python heredoc whose comments
  quote that very expression. Loosen the live regex to `r".*"`, leave a `# historical:` comment
  carrying the old spelling, and the detector returns `[]` — and since `re.fullmatch(r".*", "")`
  matches, `""` is exactly what a parked job publishes. Five rounds of execution proof, neutered
  by one edited line plus a comment.
- **Direction is the discriminator — the single most reusable rule this cycle produced** (#543,
  #552). A guard reading raw text is defeatable by a comment **only in the negative direction**:
  `if not <regex>.search(hay)` is a *pin*, and a comment supplies exactly the token the pin
  demands. A *positive* use is a scanner hunting offenders, where a comment hit is a false alarm
  at worst — so hardening it is not merely unnecessary, it is harmful. Measured on #543: every
  unanchored search over un-stripped text is **66 sites**, most of them scanners; restricted to
  the negative direction it is **11**. Fixing all 66 would produce a check that cries wolf, and
  a check that cries wolf gets ignored — costing exactly the detection it exists to provide.
  The same flip decides which text to read: **presence checks read RENDERED markdown** (a row
  hidden in a comment is a silent PASS), while **absence checks read RAW** (over-finding text a
  browser drops is a loud, fixable FAILURE, never a guard certifying what it did not check).
  Reducing first in an absence check would let a restated pin be smuggled into an HTML comment
  and pass. Read the direction before reaching for the anchor.
- **The mutation helper every fixture routes through was itself unguarded** (#544–#546, #548).
  #544 closed `apply_mutation` docstring shape 4 ("text edited in a comment that quotes the
  control verbatim"), which the docstring called unclosable: `str.replace` takes the **first**
  occurrence and in this repo the comment usually comes first, *because the comment quotes the
  command it explains* — twice this produced a silent pass read as a missing detection. #545
  renamed `count` → `expect_live` **before** migrating, because `apply_mutation(count=)` means
  "how many to replace" and `apply_live_mutation(count=)` means "how many must exist" — same
  name, different question, and a mechanical migration carrying `count=1` across keeps passing
  calls passing while changing what the number asserts; done at three callers rather than
  thirty. Pass 10 (#546) then found the helper's self-tests were named `test__ci_guard_util.py`
  — **two underscores**, mirroring the module — which the runner's `test_ci_*.py` discovery does
  not match: gutting `apply_live_mutation` entirely left `ci-guards` reporting **`ran=1285`,
  clean**, with all 74 meta-guard tests green.
- **A probe that reimplements the predicate is worth less than no probe** (#548). The sweep
  auditing all **164** `apply_mutation` call sites returned **ten findings, and all ten were
  false.** It wrote its own answer to "is this occurrence a comment?" twice and was wrong both
  times: `line.startswith("#")` is true of a Markdown **heading**, and
  `old.strip().splitlines()[0] in <comment line>` tests a **substring of the needle**, not an
  occurrence of it — `str.find` can never select there. Cost: a migration PR's worth of work and
  nearly four unnecessary rewrites. `live_offsets` is now exported so probes call the same
  predicate the code under test uses, instead of paraphrasing it.
- **actionlint: the claim rested on whoever opened the PR** (#539–#542). Every PR body in this
  repo recorded `actionlint … rc=0` while `grep -rn actionlint .github/workflows/*.yml` returned
  **nothing** — and actionlint exited **1 on `main`**, on an SC2129 that had sat there for weeks
  underneath those green bodies. #539 was a reconstruction, not a rebase: the abandoned worktree
  had **zero commits** and its tip was the merge-base, 62 commits back. #539 then **broke the
  scheduled `prowler-python-watch` workflow** by deleting a `result_code=` capture on the claim
  it "was never read again" — it is read fifty lines down the same `run:` body, so `set -u`
  aborted the step on the **ordinary exit-0 path**; #540 reproduced that by *executing* the step
  body against a stub before fixing anything. #541 found the job linting with the runner image's
  shellcheck **0.9.0** while `shell-lint` pins **0.11.0** — one repo, two rule sets, and the
  image free to move under us. #542 then defeated #541's four new pins **six ways**, one of them
  **fail-open**: an unanchored `re.search` means `# SHELLCHECK_VERSION: 0.11.0` commented above a
  live `0.9.0` makes the parity check report agreement while the job downloads, verifies and
  asserts 0.9.0 — every check green, restoring the exact asymmetry #541 existed to close. The
  one pin already anchored at line start was the **only** survivor.
- **"One constant, N spellings" — and the sweep for it was mostly false positives** (#547→#549,
  #535→#550, #551, #552). Dependabot bumped codeql-action at **one** of four pinned sites
  (#547); #549 superseded it covering all four, and `test_ci_template_pin_policy` caught it —
  the third time, after #478→#483 and #511. #535 likewise landed markdown-it-py 4.2.0 against an
  oracle still adjudicated at 4.0.0 and was correctly red. #550's re-adjudication is the method
  worth copying: **"the suite still passes" does not justify a repin**, because the residual is
  asserted as a *ceiling* and an inequality cannot distinguish a residual that stayed at 14 from
  one that **changed shape** and stayed at 14 — so both renderers ran the same seed-1234 corpus
  (16,831 docs) and the silent-pass documents were compared **as sets**: 14/14, identical
  `sha256 6f0e18c6ffc2038e`, symmetric difference empty in both directions. Then the honest
  part: #551's sweep flagged six constants and **five were false** (prowler, shellcheck,
  requests and trivy are fixture text or incident prose; `version`'s `4.11.0` is an unrelated
  OMC marker). #552 shipped `test_ci_doc_pin_restatement.py` **narrowed to one spelling on
  purpose** — `<pkg>==<ver>` for the 12 packages this repo pins in `requirements*.txt` — which
  matched **zero** lines on landing, so **five fixtures carry the weight** rather than let a
  vacuous ban read as protection: two plant the defect back (the shipped shape and the
  comment-hidden one) and must trip, two require the legal shapes — narrative tags, packages
  this repo does not own — to stay unflagged, and a fifth asserts the package list is non-empty,
  because an empty set matches nothing and would report success having checked nothing. **The catalog's eight `vX.Y.Z` tags are EXEMPT by design, not
  pinned.** They are incident narrative, and one quotes a wrong version deliberately (*a stale
  `# v4.2.2` comment on a `v7.0.0` SHA*) **because that is what the incident was** — it is the
  **negative** control the guard must never flag, and the stated reason the broader parity check
  ("every version named here must match reality") was **rejected**: it fails on exactly that
  line and then needs an exemption list, the enumeration ladder ADR-001 §5 says to stop
  climbing. Do not read those version claims as drift-guarded; by design they are not.
- **#554 corrects #553, and the correction is the entry.** #553 recorded that no detector change
  could make `test_commented_key_is_not_a_false_alarm` fail, and filed it as a pre-existing
  oddity. It fails, and it fails alone (`1 failed, 27 passed`). Both of #553's probes reached for
  comment-handling levers on the **step** path — the code that file itself contains — while the
  fixture travels `_declares` → `keys_at_column`, whose comment skip lives in `_ci_guard_util`
  one module over, on the **job** path. Neither probe could ever have moved it. **Two probes
  agreeing on "cannot fail" is worth nothing**; reading the call chain settled it in one pass.
  The lever is now written onto the fixture's docstring, because the next person will reach for
  the same two wrong ones.

### Cycle #555–#559 — a comment that restates code, and a guard that kept re-enumerating (merged 2026-09-17 → 09-18)

Six PRs. Five came out of one sweep and share a shape that is narrower than the last cycle's and
easier to recognise: **a comment, a doc or a backlog entry restating something it does not own,
and nothing comparing the two.** Every instance was found by measuring the claim against its
subject, and the two that looked worst on paper turned out to be the least interesting.

The sixth, #557, is the sweep's one real code finding and carries the cycle's other lesson: the
guard written to catch that class needed four passes to stop ENUMERATING the shapes it was
meant to model.

- **A stable issue set is not a verified backlog** (#555). The open-issue list was IDENTICAL to
  the previous revision's eight — which is exactly why re-reading it would have passed. Measuring
  found **three entries wrong about MECHANISM while naming the right issue**: `#405`'s watch
  rewrites the issue BODY and never comments (so the quoted "last re-confirmed" timestamp was
  read off a surface that does not exist), `#498`'s "prefer the newest comment over the body"
  habit had **inverted** once #505 added a body refresh (a no-delta run writes no comment, so
  comment silence is ambiguous between "nothing changed" and "nothing ran"), and `#68` was called
  a maintained tracker when `dast-baseline.yml` sets `allow_issue_writing: false` and nothing
  writes to it at all. A wrong mechanism reads exactly as authoritative as a right one, which is
  the failure this file is least able to detect on its own.
- **Fixing one instance of a contradiction and leaving the adjacent one IS the defect** (#555).
  That PR corrected the `#498` backlog entry and left the unqualified standing directive at line
  392 — inside the same bullet that cites #505, the PR that falsified it — plus the original
  "single-tracker" phrasing about `#68`. Review caught both. The rule now: before committing a
  correction, grep the whole file for the claim's other spellings, **headings included** (the
  same PR corrected "ten adversarial passes" in the body and left it in the section heading,
  which is what a scanning reader takes away).
- **Do not update a restated value — delete the restatement** (#556). `Dockerfile.nginx:2` said
  Dependabot bumps the digest "when nginx:1.27-alpine is rebuilt" while the `FROM` one line below
  read `1.31-alpine`. `31fb40e` (#235, 2026-06-16) moved the tag and left the sentence; **three**
  Dependabot digest bumps crossed the same file afterwards (#293, #353, #476) and none touched
  it, because Dependabot rewrites the `FROM` line only. Four commits through one file, three
  months, nothing comparing a claim to the code one line below it. Writing `1.31` would have
  repeated the defect at the next tag move; the comment now states the CONDITION and points at
  where the tag actually lives.
- **The document teaching SHA-pinning tag-pinned its own example** (#558). `actions-security.md`
  opens with a GOOD/BAD pair whose whole point is "pin to full SHA", and its hardened Docker
  example pinned `docker/setup-buildx-action@v3`, `docker/login-action@v3`,
  `docker/build-push-action@v5`. A reader copying the good example got the practice the same page
  calls unsafe. The staleness was the smaller half. **The sharper measurement is about aliases:**
  `b4ffde65` really IS `actions/checkout@v4.1.1`, but the `v4` ALIAS has since moved to
  `11d5960a`, so the doc's two `# v4` labels were true when written and are false now — a label
  can rot without anyone editing it. All 8 replacement labels were round-trip verified against
  their tags through the API before landing; internal consistency is not correctness.
- **The scanner was printing a 404** (#559). `https://owasp.org/www-project-top-10-ci-cd-security-risks/`
  404s after two redirects and the URL it resolves to 404s as well — 9 occurrences across 8
  tracked files, the worst being `scanner/lib/output.sh:172`, which emits it as the reference URL
  for every `CICD-*` finding. Replaced with the project's own repository, verified to still carry
  `CICD-SEC-01…10` so every citation still resolves to something real. **Why CI cannot see it is
  DELIBERATE and already written down** in `lint.yml`: `--accept '100..=599'` makes any HTTP
  status pass so a flaky 5xx cannot block a docs merge, and the compensating control is the
  monthly strict sweep. Checked before blaming it — the 2026-09-01 sweep ran clean (457 links, 0
  errors), so the link died after it; the sweep is not the defect. **Do not file the sweep as
  broken without that check.**
- **One probe saved from being a false finding** (#559). `https://www.kisa.or.kr/...` in the same
  function returns **400 to curl and 200 to a browser user-agent** — bot-blocking, not rot. All
  15 URLs `_finding_ref_url` emits were probed; 13 return 200 and only those two were worth a
  second look. The cheap conclusion on the KISA one is wrong, and the next sweep will hit the
  same 400.
- **The sweep's own yield, stated so the next one is scoped honestly.** Seven "comment restates
  code" candidates, **two real**. The five false were: a lighthouse label (`# v12.6.2` where that
  repo tags `12.6.2` — the version was right and the PROBE's predicate was wrong), the alpine →
  Python measurement table in `Dockerfile` (narrative, not a restatement), a fixture string in a
  guard, and a workflow `KEY: value` scan that returned **zero** hits because #542's guard holds.
  Expect that ratio. The real finds were the nginx comment and the `setup-python  # v6.1.0` label
  on a `v7.0.0` sha, which landed as #557 — the entry below.
- **#557: a label one MAJOR below what runs, and a guard that took four attempts to stop
  enumerating.** `lint.yml` pinned `actions/setup-python@5fda3b95  # v6.1.0` while that sha is
  **v7.0.0**. The sha is what Actions executes, so nothing misbehaved — the cost is that a
  reader, a reviewer or the next bumper reasons a major below reality. Six sibling refs were
  BARE, so the one wrong label had nothing to disagree with; that is why it survived.
  `test_ci_action_pin_labels.py` asserts INTERNAL CONSISTENCY only — one (action, sha) carries
  at most one label, one (action, label) maps to at most one sha, and an action labelled
  anywhere is labelled everywhere. **It cannot check a label against the real tag**: that needs
  the GitHub API and guards run offline, so the limit is written into the docstring AND the
  catalog row rather than implied away. 58% of identities are single-site, where nothing can
  fire at all.
- **The same mistake four times, one character apart each time** (#557). "Two spellings of one
  release read as two claims" had to be closed for uppercase (`V7.0.0`), for major aliases
  (`v7` vs `v7.0.1`), for the `v` prefix (`v12.6.2` vs `12.6.2`) and for bracketed context
  (`v4.38.0 (CodeQL bundle 2.19.0)`). Every one fired on CORRECT data, which is the direction
  that gets a guard deleted rather than fixed. And two core rules each took a THIRD attempt —
  label parsing (fullmatch → head+terminator → search) and the disarm pin (`>20` → `>=74` →
  an exact SET) — both times because the previous version enumerated shapes. ADR-001 §5 names
  this exactly; recognising it on attempt one would have saved both series.
- **A guard's own fixes are where the next defect comes from** (#557). Two adversarial passes
  found 21 real issues across several rounds, and a large share were introduced BY an earlier
  fix in the same PR: the sha was case-folded and the path was not; widening the corpus left
  13 of 32 files without an enumeration canary; the catalog row kept naming a constant that had
  been deleted; a "ratchet" was payable by unrelated additions; and the bracket fix moved the
  cry-wolf from the label path into the REPORT, where its message asserted something false.
  The last one is generalised in `WRAPPED_PRIMITIVES`: a caller must not reach past a decision
  function to the primitive it wraps, checked by AST (never grep — the module it polices
  mentions the forbidden name five times in prose explaining the rule).
- **Negative fixtures that proved nothing, twice in one file** (#557). Two `assertEqual([], …)`
  controls were vacuous: one put a different sha in the commented ref, so no comparison could
  ever occur and deleting the comment-skip changed nothing; the other routed out-of-scope ref
  FORMS through the detector, which returns `[]` for them regardless because none carries a
  label. Both now assert a DELTA or call the predicate directly, and the comment one carries a
  positive control. This file cited #553's "assert a delta, not an empty list" three tests above
  the first of them.

### Cycle #561–#565 — a self-test that drove only the shape its matcher could read (merged 2026-09-19 → 09-21)

Three PRs, all downstream of one line in #557's review: `_USES_LINE_RE` anchors `uses:` to the
start of a line, so a YAML FLOW mapping is invisible to it. Following that one observation
outward found **four** guards blind, in two different ways, and the cycle's lesson is about how
the blindness survived their own non-vacuity tests.

- **A guard's self-test can measure the FIXTURE instead of the guard** (#565). This is the new
  shape and it is worth recognising on sight. `test_ci_template_adopter_prereqs` had a private
  `_LOCAL_USES_RE = ^\s*uses:\s*\./…` — whitespace only before the key — which read **one of the
  eight** valid ways to write a local action ref. Its own `test_an_uninstalled_local_action_is_
  caught` drove `provisioning_problems` with `f"      uses: ./{ref}"`, *exclusively that one
  readable form*, so the guard was non-vacuous and green and blind, all three at once. The four
  live refs in `templates/` happen to use the same form, so nothing on disk contradicted it
  either. Measured pre/post in two clones:

  ```
                      PRE          POST
    uses: ./x         CAUGHT       CAUGHT
  - uses: ./x         blind        CAUGHT     <- a step's FIRST KEY, the ordinary way
    uses: './x'       blind        CAUGHT
    uses: "./x"       blind        CAUGHT
  - uses: "./x"       blind        CAUGHT
  - uses: ./x # local blind        CAUGHT
  - { uses: ./x }     blind        CAUGHT
  - { uses: "./x" }   blind        CAUGHT
  ```

  The rule: **a non-vacuity fixture must enumerate the input FORMS, not just the violation.** A
  mutation test that only ever feeds the shape the parser already handles proves the parser
  handles that shape.
- **A fourth independent copy of a matcher is how a guard ends up reading one form** (#565). The
  fix was not a wider private regex but routing `local_action_refs` through the shared
  `uses_refs` (ADR-001 §1), which closed all six block forms at once. This is the same lesson as
  the OCSF loader's two copies and `_SOURCE_FILES`' drift, arriving a third time: grep for other
  implementations BEFORE widening the one in front of you.
- **Each guard must own its check, not inherit it from a sibling** (#564). Two guards
  (`test_ci_gate_topology`, `test_ci_template_pin_policy`) were blind to a flow-style `uses:`
  while a third caught it. Leaning on the third is the attribution trap — it is not named for
  that property and scopes elsewhere, so its coverage could narrow for unrelated reasons and take
  the other two quiet with it, without a test changing. Each now asserts `unscannable_uses_lines`
  over its OWN corpus. A single red would have left the other two blind.
- **An allow-list and a deny-list backstopping each other will disagree** (#565 review). The
  block-form SHA-pin loop is a deny-list (`if not ./ and not docker://` → must be 40 hex); the
  new flow-form filter is an allow-list. The review recommended mirroring the deny-list so the
  halves agree. **Measuring rejected that fix:** the deny-list fires on all four of #557's false
  positives (`...`, `)`, `.a`, `${{`) because the flow matcher scans arbitrary text while
  `uses_refs` only yields values from real `uses:` keys — same rule, different input population.
  The real gap was narrower: `+` is a legal git refname character, so `owner/action@v1.0.0+build`
  was flagged in block form and invisible in flow form. Widening the rev class fixed it and kept
  the allow-list. **A recommendation from a review is a hypothesis too.**
- **Stating an invariant is not measuring it** (#565 review). The new test class docstring said
  the two filters partition by ref kind — and probed exactly the three refs that already
  partition. `./x@v1` (a directory legal on disk and legal to `uses:`) satisfied both, because
  `[\w.-]+` accepts a leading dot. The boundary is now a test.
- **A comment's REASON can be wrong while its conclusion is right** (#565 review). "`-uses: ./x`
  is excluded because PyYAML rejects it" — it does not; standalone it parses as the mapping
  `{'-uses': './x'}`. It raises only when it FOLLOWS a real sequence entry, which is the context
  my probe happened to use, so the measurement was true of the probe and false as written. The
  conclusion survived (a mapping key is not a step), the stated reason did not.
- **The guard that catches the next PR's drift is worth more than the count it fixes** (#561,
  #560). #561 corrected the README check counts and pinned them; the very next PR to land,
  #560, added three `cicd` checks, and the guard said `198 != 201` before review did. The README
  conflict between them also needed both sides — #561's `access-control` 6→10 miscount fix AND
  #560's `cicd` 8→11 — which is the ordinary case for a count conflict and the wrong place to
  pick a side.

Also in this cycle: my own commit lost a line while MOVING a comment, leaving a sentence without
a verb and deleting a clause that had become false — moving a comment is editing it. And
`test_ci_adr_citation_spelling` caught me citing an ADR section by the WORD rather than the
section mark, which is the kind of thing a guard should catch instead of a human. (Writing the
non-canonical spelling out here, even as an example, trips the same guard — so it is described
rather than quoted.)

### Cycle #560–#567 — the check that was not on the subject (merged 2026-09-21 → 09-22)

Three PRs. Two of them shipped a guard that was **green, non-vacuous, registered, and pointed at
the wrong thing** — and in both cases the review found it, not the test suite, because a guard
aimed one position away from its subject passes every test you can write about the position it IS
aimed at.

- **A visibility check on the ANCHOR is not a visibility check on the SUBJECT** (#567). The new
  slash-command guard reduced the section MARKER through `rendered_markdown` and then read the
  command names from RAW text — the split was deliberate, because the names live in a fence and
  the reduction blanks fences. The marker is not the subject. Hiding the FENCE while leaving the
  bold marker visible passed the check and returned all eight names, on the REAL README:

  ```
  case                                        guard  /scanner-feature seen by a reader
  CLEAN (control)                                 8  True
  unterminated `<!--` between marker and fence    8  False   <- FALSE GREEN
  fence wrapped in a closed `<!-- -->`            8  False   <- FALSE GREEN
  ```

  The fix is not a smarter marker check: it is to reduce the region so the SUBJECT is inside what
  gets reduced — `truncate_at_unclosed_html_comment(strip_html_comments(text))`, comments removed
  and fences kept. **Generalise as: name the thing the guard must not be wrong about, then check
  that the reduction covers THAT, not whatever is convenient to reduce.**
- **A canary can pass on precisely the edit it was written to detect** (#567). The same guard took
  "the next fence anywhere below the marker", so deleting the intended fence silently adopted the
  `Options` block further down — and `test_the_section_is_still_findable`, whose message reads
  "the section or its code fence is gone … this guard is scoped to nothing", **kept passing**,
  because a block WAS found. It collected nothing only because those lines happen to start with
  `npx`. A canary that asserts "something was found" cannot tell found-the-right-thing from
  found-anything; bound the search instead (the fence must open immediately after the marker).
- **Two of my own probes measured the wrong thing before the third was right** (#567), on the
  question of whether a reader sees the list. First used `rendered_markdown` as the oracle — it
  strips fences, so it reports False on the CLEAN file too. Second used `'/scan' in html`, where
  `/scan` occurs 15 times in the README and a commented-out string is still IN the HTML source.
  The repo already had the answer — `_browser_sees` (markdown → HTML → consume comments) and the
  recorded "containment lies" note — and a needle that occurs exactly once. **Before measuring
  visibility, check that the control case measures VISIBLE.**
- **A review recommendation is a hypothesis too** (#565). The reviewer proposed mirroring the
  block-form deny-list into the flow-form filter so the two halves would agree. Measuring rejected
  it: the deny-list fires on all four of #557's false positives, because the flow matcher scans
  arbitrary text while `uses_refs` only yields values from real `uses:` keys — same rule, different
  input population. The real gap was narrower (`+` is a legal git refname character, so
  `owner/action@v1.0.0+build` was flagged in block form and invisible in flow form).
- **A fresh sibling hid a dead one** (#560). CICD-011 consulted its `broken` accumulator only when
  NO successful run existed anywhere, and broke out of the loop on the first fresh workflow — so a
  scan that runs and never completes was reported only when it had no healthy sibling, and was
  often never queried at all. The file's own header calls `broken` "the worst of the four" states
  and declares an INVARIANT about it. Same shape as #392/#396/#397 one level in.
- **Widening a shared meta-guard needs its own measurement** (#567). Dropping `rendered_markdown`
  made the Markdown census flag the new module. `MARKDOWN_SCAN_EXEMPT` would have been misuse — it
  is for a `.md` literal that is a path or fixture, not a parsed document — so `applies_reduction`
  now also accepts the comment-only composition, requiring BOTH names (`strip_html_comments` alone
  and `truncate_at_unclosed_html_comment` alone both stay False). Measured over every tracked
  `test_ci_*.py`: exactly two modules call both, and the other is the primitives' own unit tests,
  not a census offender either way. Widening a meta-guard is fine when you can name everything the
  widening newly admits.
- **The guard that shipped last cycle caught the next PR's drift** (#561 → #560). #561 pinned the
  README check counts; #560 added three `cicd` checks and the guard said `198 != 201` before review
  did. Their README conflict needed BOTH sides — #561's `access-control` 6→10 miscount fix AND
  #560's `cicd` 8→11 — which is the ordinary case for a count conflict and the wrong place to pick
  a winner.

Also: a false claim shipped in TWO places (#567). The docstring and the catalog row both asserted
the design prevented the very bypass above. Correcting the code is not enough when the reasoning
was published alongside it — grep the claim, not just the function.

## Open Backlog

Re-derived from `gh issue list --state open` + measured repo state on **2026-09-17**, re-checked
**2026-09-18** and again **2026-09-21**, the set unchanged all three times. **Verify before
working an item** — this list rotted twice before, and the 2026-08-26 revision listed FOUR
already-closed issues (#295, #297, #381, #399) as open.

**Nothing opened or closed since the 2026-09-02 revision** — the same eight issues
(#405, #498, #68, #39, #15, #12, #18, #20). A stable issue set is not a verified backlog:
the 2026-09-18 pass found
**three entries that were wrong about MECHANISM** while naming the right issue, which is the
failure this file is least able to detect, because a wrong mechanism reads exactly as
authoritative as a right one. Check with `gh issue list --state open` before trusting any entry.

**The 2026-09-21 pass re-measured all three corrected mechanisms and they held** — `#405`
`comments=0` with the body refreshed that week, `#498` `comments=2` with a body newer than the
newest comment, `#68` still `updatedAt=2026-04-05` with `comments=0`. What it found instead is a
*third* failure mode, distinct from a wrong mechanism and from a closed issue: **an entry that is
correctly classified while the issue BODY describes a world that no longer exists.** Two of the
five product asks are in that state (`#20`, `#12`, below). A stale premise is not visible from the
issue list, from the labels, or from the mechanism — only from measuring the body's claims against
the tree, which is the check this section had never applied to the product-ask entries because
they were dismissed in one line as "not correctness work".

**Re-measuring the backlog also found a defect that was not IN it** — README advertised four slash
commands that do not exist and omitted five that do. Nothing in the backlog pointed at it; it
surfaced only because `#20`'s "현재 5개 slash command" premise had to be checked against
`.claude/commands/`. Fixed and guarded in #567. Worth noting as a property of this kind of sweep:
verifying a stale premise reads the same surface a drift guard would, so it finds drift the
backlog never tracked.

**Closed in an earlier revision — do NOT re-propose as open:** `#295` (prowler/alpine freeze),
`#297` (quarterly ADR-001 audit), `#381` (lychee sweep), `#399` (DAST nightly not running).

- **`#405` branch-protection drift-watch is not running** (`REPO_ADMIN_TOKEN` missing).
  **BLOCKED ON A HUMAN — there is no code fix.** The workflow self-heals into this issue
  rather than reporting green (#396), so the issue IS the alert. Unblock: a fine-grained PAT
  scoped to this repo with **Administration: read**, stored as the `REPO_ADMIN_TOKEN` repo
  secret; the next clean run closes the issue. Check the *decision condition*, never a date:
  `gh secret list` empty ⇒ still blocked (the repo has zero Actions secrets), and
  `gh run list --workflow=protection-drift-watch.yml` is green either way, so the ISSUE state
  is the signal, not the run conclusion. **Correction to the 2026-09-02 revision:** the
  workflow does not comment — it **rewrites the issue body** (`comments=0`, and `updatedAt`
  tracks the newest scheduled run). The quoted "last re-confirmed 2026-08-31T21:08" was
  therefore both stale and derived from the wrong surface; it is exactly the
  restating-state-it-does-not-own rot the last bullet of this section warns about, committed
  inside the warning's own list. **Branch protection has been unmonitored since 2026-06-17**,
  when `b2d7195` (#251) added the workflow — not since the issue was filed on 2026-08-07. #396
  only added the self-healing issue on 08-06; the secret never existed, so every scheduled run
  before that took the no-op branch and reported green with nothing to show for it. Dating the
  gap from the issue understates it by roughly seven weeks, which is the wrong direction for a
  control that is supposed to make silence loud.
  Scope precision: the endpoint is not unreachable — `gh api
  repos/Twodragon0/claudesec/branches/main/protection` returns fine from an admin-scoped local
  token (measured 2026-09-17: `code_owner=true`, `dismiss_stale=false`, `strict=true`,
  `enforce_admins=true`, 2 required contexts, consistent with ADR-002 and #526). **Only the
  Actions runner lacks a credential.** So the drift-watch gap is a missing secret, not missing
  access, and a human can read the current posture at any time without unblocking the watch —
  what stays unbuilt is the *continuous* comparison, which is the whole point of a drift watch.
- **`#498` ZAP full-scan tracker — stays open; the body-freeze is FIXED, do NOT re-propose it.**
  #505 added a step that rewrites the body from the newest run, pinned by
  `test_ci_dast_tracker_body_refresh.py`. **Check the condition, not the values below:** the
  body carries its own `Refreshed (UTC)` line and run URL, so compare that timestamp against
  `gh run list --workflow=dast-full-scan.yml` — if it tracks the newest nightly, the refresh
  step is working. (An earlier draft of this entry quoted the exact body timestamp and run id
  and was superseded by the next nightly **within a day** — the rot this file's closing rule
  exists to prevent, committed while correcting three instances of it.) Risk tiering when last
  read was INFO-only, but re-read it rather than trusting that. The
  `.../'+safeHref(hubUrl)+'` "URL" is ZAP scraping a JS string literal out of inline
  `<script>` source, not an endpoint.
  **Correction — the reading habit did NOT survive the fix, it INVERTED for this tracker.**
  The previous revision said to prefer the newest comment over the body. On #498 that is now
  backwards: the newest comment is **2026-09-01** while the body is **2026-09-16**, because
  #505's step refreshes the body nightly and the append-only delta stream simply stopped
  producing comments once there were no new-vs-resolved deltas to report. A no-delta run writes
  nothing, so on a delta-stream tracker **comment silence is ambiguous between "nothing changed"
  and "nothing ran"** — which is why the refreshed body, carrying its own run URL and timestamp,
  is the surface to read here. Keep the comment-first habit for trackers WITHOUT a refresh step;
  the discriminator is whether a body-refresh step exists, not the tracker's age.
- **`#39` ISMS-P 29 FAIL controls prioritised remediation plan** and **`#15` incident-response
  process 65% → 80%** are product/content work, not CI.
  **`#39`'s denominator no longer exists** (measured 2026-09-21). Its table is
  `PASS 13 / FAIL 29 / 42개, 준수율 31% (D)`; `COMPLIANCE_CONTROL_MAP["KISA ISMS-P"]` now holds
  **44** controls, of which **15** carry `assessable: False` and render N/A, leaving **29**
  scoreable. So the issue's 42 and today's 44 are different populations and its 13/31%
  cannot be compared to a current run at all. (The 29 is a coincidence of two different
  quantities — issue-FAIL versus today's assessable count — and conflating them is the trap.)
  Eleven of the fifteen N/A are the `3.x` PII controls #309 already recorded, which is the one
  number in this area that measured out exactly as written. Re-derive with
  `importlib` against **`scanner/lib/compliance-map.py`** — not `scanner/compliance-map.py`,
  which does not exist and is where an earlier attempt at this measurement died with
  `FileNotFoundError` and had to be redone. A current pass/fail needs a Prowler OCSF corpus and
  was NOT measured; treat any percentage in the issue as unverified rather than as a baseline.
  Related and also drifted: `COMPLIANCE_CONTROL_MAP` now has **8** frameworks, so this file's
  "SOC 2 (TSC) added as the 7th framework" is true-as-written-then and stale now — CMMC 2.0
  Level 2 (14 controls) is the eighth.
- **`#68` ZAP baseline — keep it open, but it is a DORMANT ARTIFACT, not a maintained tracker.**
  **Correction to the 2026-09-02 revision**, which called it "the intentional single-tracker
  issue" and so implied something still writes to it. Nothing does:
  `.github/workflows/dast-baseline.yml` sets `allow_issue_writing: false`, and the issue has
  `comments=0` with `updatedAt=2026-04-05` while the job still runs on code PRs (its
  `pull_request` trigger carries `paths-ignore` for `docs/**` and `**/*.md`, so docs-only PRs
  skip it — this very entry's PR did). The workflow's
  own comment (lines 47–55) already names all three non-blocking layers — `continue-on-error`,
  `fail_action: false`, `allow_issue_writing: false` — and states the consequence: baseline
  findings land ONLY in the `zap-baseline-results` artifact, "which nothing reads automatically
  … a scan that fails to run at all is indistinguishable from a clean scan." **That sentence IS
  the green-while-dead class, stated outright and knowingly ACCEPTED** — not, as an earlier draft
  of this entry had it, an exemption from it. The distinction that matters is accepted-with-its-
  cost-written-down versus undetected, and only the second is a defect; `dast-freshness-watch.yml`
  exists because the repo does treat the hazard as real elsewhere. So: no fix proposed for a
  non-required advisory job on a local container, but do not cite #68 as evidence the class is
  absent here. Contrast #498, which is the live tracker. Check:
  `grep -n allow_issue_writing .github/workflows/dast-baseline.yml`.
- **`#12` Zscaler MCP integration**, **`#18` GitHub Projects board**, **`#20` marketplace
  plugin update** are `enhancement`-labelled product asks, not correctness work. All three
  are untouched since 2026-03 (`comments=0` on each), and measuring their BODIES on 2026-09-21
  found two premises that no longer hold. Classification was right; the bodies had rotted
  underneath it, which no amount of re-reading the issue list would surface.
  - **`#20`'s premises are both stale.** It is titled "v0.6.0" and `package.json` says
    **0.7.2** — three minors past it. It says "현재 5개 slash command" and there are **8**.
    Two of its four tasks ask for `/compliance` and `/prowler`; neither exists as a slash
    command and neither is what the repo ships (`/compliance-check` does, and Prowler is a CLI
    subcommand). Re-scope it against `node -p "require('./package.json').version"` and
    `ls .claude/commands/` before working it, and note #567 changed the second of those.
  - **`#12`'s stated premise is partly false.** It argues MCP integration is *needed* to get
    ZIA/ZPA data into the dashboard — but `scanner/checks/saas/zscaler.sh` already implements
    `SAAS-ZIA-001..007`, seven checks, with no MCP server involved. Whatever remains of #12 is
    about the MCP surface specifically, not about ZIA coverage existing; check
    `grep -rl SAAS-ZIA scanner/checks/` first so the issue is not re-opened against a
    requirement that is already met by another route.
  - **`#18` is UNVERIFIED, not confirmed either way.** `gh project list --owner Twodragon0`
    fails with `your authentication token is missing required scopes [read:project]`, so
    whether a board exists was NOT established. Recorded as unverified on purpose — the
    alternative is a guess, and a guess here reads as authoritative exactly like the three
    wrong mechanisms did. Unblock with `gh auth refresh -s read:project` (which is the issue's
    own first task, so the check and the work share a prerequisite).
- **Merged 2026-09-01 → 09-02, do NOT re-propose as open.** The reasoning moved into the
  `#505–#511` cycle entry above and should be read there, not re-derived: the ruff `select`
  widening (#508), `_TEMPLATE_KEYS` caller arity (#509), the zscaler `_unreachable` `reason`
  wiring (#506), and `_load_saas_sso_stats`'s reject-the-whole-list behaviour, which is
  CONFIRMED-DELIBERATE and correct (#507).
- **Four dead template keys — DONE 2026-09-02, do NOT re-propose.** `ACTIVE`,
  `POLICY_022_TOP`, `N_INFO`, `TOTAL_ALL` were computed, passed through the call and never
  substituted; removed together with their positional arguments AND the four locals they were
  the only consumers of, so `KNOWN_DEAD_KEYS` is now empty. **How the off-by-one was ruled
  out, because arity cannot see a shift** — a shifted call passes the same NUMBER of
  arguments, just against the wrong keys: pair every key with its argument EXPRESSION by AST
  across both files, before and after, and assert the survivors byte-identical. That is the
  check to repeat, not a re-render (timestamps make a render diff noisy and it proves less).
  `CSP_NONCE` stays as the one baselined orphan PLACEHOLDER (nginx `sub_filter` supplies it
  per request). The upstream half followed in a second pass: `n_info` and `policy_022_top`
  were computed in `_compute_severity_counts`, re-exported through `build_overview_blocks`,
  and consumed by nothing. **`git log -S"POLICY_022_TOP" -- scanner/lib/dashboard-template.html`
  returns EMPTY — neither placeholder ever existed**, so these were born dead and survived
  three refactors. Removed with their tests; `_compute_severity_counts` now returns exactly
  the four bar severities and a test asserts the KEY SET by equality, because `assertIn` on
  four keys would not notice a fifth being recomputed and going unrendered again.
  `SAAS-API-022` itself is a LIVE Okta scope check — only its counter was dead, so re-adding
  the metric is three lines if anyone ever wants it on screen. Re-derive state with
  `python3 -m pytest scanner/tests/test_ci_template_keys_arity.py -q` rather than trusting
  this entry.
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
