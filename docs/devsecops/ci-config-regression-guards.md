---
title: CI Config Regression Guards
description: Catalog of ClaudeSec's pytest guards that prevent CI security/quality gates from being silently weakened or removed
tags: [ci-cd, supply-chain, devsecops, testing, branch-protection]
---

# CI Config Regression Guards

ClaudeSec's CI gates (coverage floors, action SHA pins, required-check topology,
the security-scan severity block) are the controls that stand between a
regression and a green build. They are also easy to weaken **silently** — a
lowered threshold, a job dropped from an aggregator's `needs:`, or a tag
re-introduced in a `uses:` line passes review unnoticed and disables enforcement
without any visible failure.

This is a recognised CI/CD risk class: **OWASP CICD-SEC-1 (Insufficient Flow
Control Mechanisms)** and **CICD-SEC-7 (Insecure System Configuration)**, and
the supply-chain integrity expectations of **NIST SSDF (SP 800-218) PO.3 /
PW.4**. To make any such weakening explicit and reviewable, ClaudeSec ships
small **config regression guards**: stdlib-only `pytest` tests that read the
workflow YAML and assert each invariant still holds.

## Conventions

All guards follow the same rules (see the existing files for reference):

- **Location**: `scanner/tests/test_ci_*.py`, executed by the `scanner-unit-tests`
  job (`python3 -m pytest scanner/tests/`).
- **Stdlib-only**: regex / line scanning, **no PyYAML** — it is not in
  `requirements-ci.txt`, so `import yaml` would fail in CI. (The
  `workflow-fork-guard` job installs PyYAML separately for its own script.)
- **No `scanner/lib` import**: guards add tests without touching the measured
  coverage, so they never move the 99% `scanner/lib` floor.
- **Direction-explicit semantics**: floors use `>=` (ratcheting a floor *up*
  stays green; lowering/removing trips it); pins use exact/`==`; presence checks
  assert a trigger/flag still exists. State the direction in the docstring.
- **Non-vacuous**: prove the guard fires on the regression it targets (simulate
  it) before shipping. Avoid regexes that match commentary in the workflow.
- **Dual-runner**: pass under both `pytest` (CI) and `python3 -m unittest`.
- **Shared primitives**: comment-stripping, continuation-joining, and `on:`-block
  extraction live in `scanner/tests/_ci_guard_util.py` (`strip_comment_lines`,
  `non_comment_lines`, `join_continuations`, `extract_on_block`). Import them as a
  top-level module after putting the test dir on `sys.path` so they resolve under
  both runners. The `_`-prefixed name keeps the module out of pytest collection
  and the `test_ci_*.py` catalog glob (no Catalog row needed). **Always strip
  comments and scope tokens** before a presence check — a token in a `#` comment
  or a second weaker assignment must not satisfy an invariant (the false-negative
  class hardened across these guards).

## Catalog

| Guard | Protects | Key assertions | Landed |
|-------|----------|----------------|--------|
| `scanner/tests/test_ci_coverage_thresholds.py` | Coverage floors in `lint.yml` | pytest `--cov-fail-under >= 99`; bash kcov `threshold >= 90.0`. Both floors are read from shell inside `run:` blocks, so the scan strips comments with the bash-aware `strip_inline_comment_sh` — a floor surviving only in a `;#`/`&#`/backtick comment is not an active gate | #200 |
| `scanner/tests/test_ci_gate_topology.py` | Enforcement topology of `lint.yml` | every `uses:` across all `.github/workflows/*.yml` is 40-hex SHA-pinned (OWASP A08); every job is in `lint-gate.needs` or a tiny documented allowlist | #201 (allowlist tightened in #203) |
| `scanner/tests/test_ci_security_gate.py` | `Security Scan Gate` + DAST signals | `security-scan-gate` keeps `name`, `if: always()`, `needs: ⊇ {changes, scan, lighthouse}`, pass-set `not in (success, skipped)`; `dast-baseline.yml` keeps its `pull_request` trigger; `dast-full-scan.yml` keeps its `schedule:` trigger | #205, #216 |
| `scanner/tests/test_ci_required_jobs_exist.py` | Existence of security/enforcement jobs in `lint.yml` | `{gitleaks, pii-check, dependency-review, workflow-fork-guard, scanner-unit-tests, scanner-shell-coverage}` are all present — deleting a whole job is a silent control loss the topology guard cannot see | #215 |
| `scanner/tests/test_ci_codeql_single_model.py` | Single CodeQL model (default setup only) | no workflow uses `github/codeql-action/init` or `/analyze` (a repo-level analysis would duplicate the default-setup model); `upload-sarif` is allowed (DAST SARIF upload, not analysis) | #215 |
| `scanner/tests/test_ci_npm_publish.py` | npm release supply-chain integrity + auto-release wiring (`npm-publish.yml`) | every `npm publish` carries `--provenance` (SLSA attestation); workflow-level `permissions:` stays `contents: read` (job-level `id-token: write` + `contents: write` are not flagged); the publish job upgrades npm (`npm install -g npm`, OIDC needs >= 11.5.1 but Node 22 ships npm 10.x); the `on:` block keeps a push-to-`main` trigger (version-bump auto-publish) and a `contents: write` exists for pushing the `vX.Y.Z` tag | #216, #262 |
| `scanner/tests/test_ci_cross_os_non_required.py` | Cross-OS live-runner workflow stays non-required | `cross-os-checks.yml` exists and keeps `workflow_dispatch` (standalone informational lane); `lint.yml` references none of `{cross-os, live-os-checks, macos-latest, windows-latest}` — so the costly/flaky macOS+Windows runs never become a required merge gate | #228 |
| `scanner/tests/test_ci_net005_fail_escalation.py` | NET-005 SSH-open-to-world FAIL escalation (`network/tls.sh`) | NET-005 keeps `fail "NET-005" ... "critical"` and an ERE `(0\.0\.0\.0/0.*22\|port.*22.*0\.0\.0\.0/0)` alternation; no `\|` literal-pipe regression (which silently downgraded it to WARN, fixed in #224) | #228 |
| `scanner/tests/test_ci_dependabot_automerge.py` | Dependabot auto-arm safety (`dependabot-auto-merge.yml`, a `pull_request_target` write-token workflow) | keeps the fork guard (`actor==dependabot[bot]` AND `head.repo.full_name==github.repository`), the hard-exclude path arms (`Dockerfile*`/`.github`/`scanner`/`hooks`/`scripts`), the `semver-patch\|minor`-only update-type allowlist + `semver-major` exclude, the `pip\|docker\|github-actions` ecosystem allowlist, and `gh pr merge --auto`; forbids `--admin` (code-owner bypass) and the `pr review --approve` bot self-approve removed in #249 (OWASP CICD-SEC-1/-4). Every check — the aggregate validator AND the narrower per-invariant tests — runs against the bash-comment-stripped text (`strip_inline_comment_sh`), so an arm parked behind `;#` neither satisfies a REQUIRED token nor false-trips a FORBIDDEN one | #249, #250 |
| `scanner/tests/test_ci_codeowners_invariants.py` | `.github/CODEOWNERS` keeps security-sensitive paths code-owner gated | every required pattern (`*`, `.github/workflows/`, `.github/CODEOWNERS`, `hooks/`, `scanner/`, `scripts/`, `templates/`, `Dockerfile*`, `docker-compose*.yml`) is present AND has a non-empty `@owner`; the global `*` default must have an owner — else those paths merge with NO code-owner review (`require_code_owner_reviews=true` only fires on a matched, owned pattern) | #248 |
| `scanner/tests/test_ci_no_ere_pipe_regression.py` | No literal `\|` in an ERE context in `scanner/checks/**` + `scanner/lib/**` `.sh` | flags `\|` (literal-pipe, NOT alternation) inside `grep -[qnrlc]*E`, the `_code_grep`/`files_contain`/`file_contains` helpers, and bash `[[ =~ ]]` — the silent detection-breaking bug class fixed in #221/#223/#224; two intentional literals (`code/injection.sh` `\|safe`, `solutions.sh` `curl\|sh`) are allowlisted and asserted still present | #244, #246 |
| `scanner/tests/test_ci_prowler_provider_guard_ordering.py` | `_prowler_provider_available` precedes `_prowler_report` per provider (`scanner/checks/prowler/integration.sh`) | within each provider section of the Provider Scans block, `min(guard line) < min(report line)` — reordering would silently regress the #238 build-parity fix (lean image would emit a misleading auth warning instead of an accurate "not in this build" skip); promotes the shell-level `#241` assertion into the pytest CI gate. `integration.sh` is pure bash, so guard/report call detection strips trailing comments with `strip_inline_comment_sh`: a decoy `echo x;#_prowler_provider_available "…"` must not lend its early line number to `min(guard)` and mask a real guard that now sits after the report | #242 |
| `scanner/tests/test_ci_catalog_completeness.py` | Completeness of this catalog vs the on-disk guard suite | every `scanner/tests/test_ci_*.py` file has its repo-relative path listed in this catalog (presence) — a new guard added without a Catalog row is silent documentation drift that makes the inventory understate coverage; the meta-guard documents itself so the invariant is uniform. HTML-comment-stripped, so a row parked in `<!-- ... -->` (invisible when rendered, the Markdown comment-evasion form) does NOT satisfy the presence check. Mutation self-tests | #254 |
| `scanner/tests/test_ci_catalog_no_ghost_rows.py` | No ghost rows in this catalog vs the on-disk guard suite | every concrete `scanner/tests/test_ci_<name>.py` path cited in this catalog resolves to a real file (existence) — the reverse of the completeness guard: a renamed/deleted guard left in the table is a ghost row that makes the inventory overstate coverage. Together the two guards verify a 1:1 catalog↔suite mapping. HTML-comment-stripped, the opposite direction from the completeness guard: a row parked in `<!-- ... -->` claims no coverage, so flagging it as a ghost would be a false alarm — a test pins that a commented ghost still does not mask a live one. Mutation self-tests | #255 |
| `scanner/tests/test_ci_branch_protection_codified.py` | Codified branch protection (`scripts/sync-repo-protection.sh`) + its nightly notifier (`protection-drift-watch.yml`) | the desired state keeps `DESIRED_CONTEXTS=["Lint","Security Scan Gate"]` (both required checks — an exact two-sided pin: dropping a context un-requires that aggregator, and silently *adding* a third required context is equally caught, proven by appended+prepended mutation self-tests), `DESIRED_ENFORCE_ADMINS="true"` (admins not exempt — no force-push to main), `strict`/`require_code_owner_reviews` true, `set -euo pipefail`, and the default-arm dry-run; the `DRIFT DETECTED` marker contract holds on both producer (script) and consumer (`grep -q`) sides; the watch keeps `schedule:` + tooling-error `exit 1` and its `on:` block never gains a `pull_request(_target)` trigger (scheduled notifier, must not become a required PR check). Protects the #250/#251 codification | #256 |
| `scanner/tests/test_ci_dependabot_config.py` | `.github/dependabot.yml` update coverage + alpine version freeze | all four ecosystems stay declared (`github-actions`, `npm`, `pip`, `docker`) so no surface silently stops getting update PRs (OWASP CICD-SEC-3); the `docker` `ignore` keeps the `alpine` `semver-minor`+`semver-major` freeze that holds alpine on its py3.12 minor line — loosening it would let Dependabot propose the bump that ships py3.14 and crashes prowler (pydantic v1, incident #220). Distinct from `test_ci_dependabot_automerge.py` (guards the *workflow*, not this *config*) | #256 |
| `scanner/tests/test_ci_prowler_version_pinned.py` | prowler install pin in `Dockerfile` | prowler is installed via an exact `==` pin through the `PROWLER_VERSION` build arg (version-shaped value), never a bare unpinned `pip install ... prowler`. An unpinned spec silently backtracks to ancient prowler 3.11.3 (pydantic v1) on a newer Python and crashes at runtime (incident #237). Pins the *pinning*, so a lockstep version bump stays green | #258 |
| `scanner/tests/test_ci_trivy_version_pinned.py` | Trivy install pin + integrity in `Dockerfile` | Trivy is `curl`-downloaded from a hardcoded `ARG TRIVY_VERSION` that Dependabot's `docker` ecosystem cannot track. The guard asserts an exact version-shaped `TRIVY_VERSION` pin (no blank/second override), a pinned `v${TRIVY_VERSION}` download tag (never floating `/releases/latest/`), and a `sha256sum -c` integrity check on the downloaded binary. Pins the *pinning + integrity*, so a version bump stays green | P3 cleanup |
| `scanner/tests/test_ci_dockerfile_base_pinned.py` | Container base-image pins (`Dockerfile`, `Dockerfile.nginx`) | every `FROM` carries an `@sha256:` digest (OWASP A08 — no moving-tag swap); the prowler `Dockerfile` holds every `FROM alpine:` on the `alpine:3.20` (py3.12) minor line and resolves site-packages with the version-agnostic `find ... -name 'python3.*'` glob (no hardcoded `python3.<n>/site-packages`, #234). Complements `test_ci_dependabot_config.py` (config freeze policy) by locking the actual image | #258 |
| `scanner/tests/test_ci_changes_job_merge_base.py` | `changes` job PR diff in `lint.yml` | The path-gating job diffs PR base↔head. A `--depth=1` base fetch + three-dot (`BASE...HEAD`) diff hard-fails with `fatal: no merge base` when the branch is behind a moved `main`, cascading to the Lint / Security Scan Gate aggregators and blocking the merge. The guard asserts the base is fetched WITH ancestry (not shallow-only) and the three-dot diff has a two-endpoint (`\|\|  git diff`) fallback, so a missing merge base degrades instead of failing | CI robustness |
| `scanner/tests/test_ci_compose_dashboard_hardening.py` | Dashboard container hardening (`docker-compose.yml`, `docker-compose.quickstart.yml`) | the network-exposed static-content dashboard service keeps its CIS hardening — `read_only: true` (+ tmpfs-backed writable paths), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `mem_limit`/`pids_limit`. Block-scoped so hardening on a sibling service can't satisfy it. As a security toolkit, ClaudeSec must not silently regress its own container's posture | CI robustness |
| `scanner/tests/test_ci_npm_files.py` | npm package payload (`package.json` `files[]` allowlist) | `docs/` is NOT in `files[]` (it shipped ~38 MB of `.pptx` not used at runtime — incident #261); the six operator-only scripts keep their `!scripts/<name>` negations (cost-xlsx / license / PC-sheet / full-asset-sync / gsheet-auth×2 — else internal tooling publishes to the public registry); `scripts/` stays included (so the negations have effect) and `CHANGELOG.md` stays shipped. `.npmignore` cannot express these — paths under a `files[]` dir override it (confirmed via `npm publish --dry-run`) | #262 |
| `scanner/tests/test_ci_provenance_verify.py` | Published-package supply-chain monitor (`provenance-verify.yml`) | the workflow keeps a `schedule:` trigger (periodic check of the *published* artifact), keeps a `workflow_run` trigger on "Publish to npm" whose `types:` list still includes `completed` (verifies right after each release — the cadence that maps to when the artifact changes; a `workflow_run` key without `completed` would silently never fire), never gains a `pull_request(_target)` trigger (a zero-dep `npm audit signatures` adds no PR value and must not become a flaky required gate / write-token foot-gun), and still RUNS `npm audit signatures` — matched in shell **command position** with whole-line comments dropped and quoted-string matches rejected, because the workflow names the command in four of its own comments and in two `echo "::error::…"` strings, so the former bare-substring check stayed green after the real invocation was deleted (inert-guard class; mutation self-tests pin the gutted-workflow case). Verifies npm registry signature + SLSA provenance, OWASP A08 | #263 |
| `scanner/tests/test_ci_injection_surface.py` | No GitHub Actions script-injection surface in any `.github/workflows/*.yml` or `*.yaml` | no documented-untrusted `${{ github.event.* }}` context (PR/issue/comment/review/discussion title·body, commit message, `head_ref`, `pages.*.page_name`, …) is interpolated DIRECTLY into a `run:` shell body — the OWASP CICD-SEC-4 / GitHub script-injection RCE class. Scans only `run:` bodies (inline + `\|`/`>` block scalars), threshold at the `run:` column so sibling `env:`/`with:`/`if:` keys aren't slurped; `env:`-block and expression-context (`if:`) interpolation and trusted contexts (`github.sha`, `needs.*`) are NOT flagged. The `run` key is matched plain or quoted (`"run":`), and three tripwires FAIL CLOSED on shapes a line scanner cannot reassemble — multi-line flow scalar, a `${{ }}` split across physical lines, and the explicit-key `? run` / `: cmd` form. Direction: presence-of-violation; mutation self-tests prove it fires on inline + block-scalar + quoted-key injection, that each tripwire fires on its shape, and that it stays quiet on the `env:` safe-fix and on a YAML comment beside a `run:`. Incident: `npm-publish.yml` inline `VERSION=` (hardened #266); `og-meta-verify.yml` is `pull_request`+`pull-requests:write` | #270, #391 |
| `scanner/tests/test_ci_npm_oidc_floor.py` | OIDC npm-CLI floor pin in `npm-publish.yml` + `provenance-verify.yml` | both workflows' `npm install -g npm` self-upgrade pins the trusted-publishing floor `npm@'>=11.5.1'` (version-shaped) and is NOT a bare `npm@latest` — OIDC `npm publish --provenance` / `npm audit signatures` break below npm 11.5.1, and Node 22 ships npm 10.x, so the floor must be a *visible* pin (Dependabot cannot track a runner binary installed by a shell command). Ratcheting the floor up stays green; reverting to `@latest` trips it (OWASP A08; SSDF PW.4) | #264 |
| `scanner/tests/test_ci_docker_image_size_gate.py` | Docker image-size cap in `lint.yml` (`dashboard-regression-check`) | the `max_mb=N` size gate is present, breaches the build (`size_mb -gt max_mb` → `exit 1`), and `N <= 600` MB — locking in the ~513 MB scanner image achieved by prowler-provider stripping (was 1.47 GB, cycle #217-#237, issue #11). Loosening the cap back toward the old 1.8 GB or re-adding a stripped ~700 MB provider would slip through; tightening DOWN stays green (CIS Docker Benchmark — minimal image surface). The `exit 1` assertion is scoped to the breach `if … fi` block by balanced depth — unscoped it was satisfied by any of `lint.yml`'s dozen unrelated `exit 1` lines and could not detect removal of this gate's own exit (inert-guard class). Comment-evasion-proof for BOTH the `max_mb` cap and the `exit 1` scan: the whole scan routes through the bash-aware `strip_inline_comment_sh`, so the `;#exit 1` metachar adjacency #383 recorded as a KNOWN OPEN under-strip is closed (primitive from #376) | #11 |
| `scanner/tests/test_ci_lighthouse_perf_gate.py` | Lighthouse Performance/SEO/A11y gate (`lighthouserc.json`, consumed by `lighthouse.yml` against live Pages) | each of `categories:{performance,seo,accessibility}` keeps an `error`-level floor `minScore >= 0.9` (demoting to `warn`/`off` or lowering the floor trips it; ratcheting UP stays green), and `collect.numberOfRuns >= 3` so lhci asserts on the MEDIAN run — reverting to a single run re-introduces the cold-vs-warm-CDN variance that would make the hard Performance gate flaky. Adds the Performance floor from issue #19 (live baseline 0.93 cold / 1.00 warm, 2026-06) | #19 |
| `scanner/tests/test_ci_plugin_skills_cli_parity.py` | Marketplace plugin skill ↔ CLI subcommand parity (`.claude-plugin/marketplace.json` ↔ `bin/claudesec-cli.sh`) | every `skills[].command` is `npx claudesec <sub>` where `<sub>` is a real `case` arm in the CLI — a skill pointing at a non-existent/typo'd subcommand would make that installed slash command silently fall through to usage for every user (the manifest and the CLI have no compile-time link); and the `{scan,prowler,compliance,dashboard,setup}` arms stay wired so a CLI refactor cannot silently drop a published surface. Adds the `/prowler` + `/compliance` commands from issue #20 | #20 |
| `scanner/tests/test_ci_lychee_config.py` | lychee link-check exclude allowlist single-source-of-truth (`lychee.toml` ↔ `lint.yml` `link-check`) | `lychee.toml` (undotted, auto-discoverable) exists and the dotted `.lychee.toml` does NOT (a dotted config is never auto-discovered, so it silently goes stale — the original drift); the `link-check` job wires `--config lychee.toml` and carries NO inline `--exclude`/`--exclude-path` flag (so the allowlist cannot drift back into a second copy); `lychee.toml`'s `exclude` includes the release-time `compare/` entry the inline list was missing (the CHANGELOG compare-URL 404 fix) and keeps `node_modules` in `exclude_path`; and `lychee.toml` stays in BOTH the `scanner` and `markdown` change-detection buckets of the `changes` job, so a `lychee.toml`-only PR still triggers this guard AND a live link-check (else the allowlist could change unvalidated at PR time). Comment-stripped + job-scoped; the `v0.23.0` binary pin is owned separately by `test_ci_gate_topology.py` (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_lychee_redirect_sweep.py` | Monthly `lychee-redirect-sweep.yml` stays a scheduled, notifier-only backstop that actually surfaces redirects | workflow exists; `on:` keeps `schedule:`/`cron:` + `workflow_dispatch` and has NO `pull_request` trigger (a broad external-URL fetch on every PR would flake and, once required, block merges — the notifier-only invariant); `permissions: issues: write` (self-healing tracking issue); the lychee run reuses `--config lychee.toml` (single-source excludes) and keeps BOTH teeth — `--max-redirects 0` (report 3xx instead of following to its 200) and strict `--accept '200..=299'` (widening toward the PR job's `100..=599` re-hides rot); `fail: false` (findings become an issue, not a red run); `lycheeVersion: v0.23.0` shared binary pin. Comment-stripped (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_provider_labels_sync.py` | Prowler provider label maps have a single source of truth (`scanner/lib/dashboard_providers.py` ↔ `scanner/lib/output.sh`) | the bash `case` in `output.sh` (`_prowler_dashboard_summary_provider_label`) has EXACTLY the same slug→label pairs as the canonical `PROVIDER_LABELS` — after the refactor consolidated four drifted inline Python dicts into `dashboard_providers.py`, the bash mirror is kept in place for perf (called in a loop) but must not drift; also asserts the shared constants stay complete and consistent (`PROVIDER_LABELS` 16 entries; `PROVIDER_LABELS_SHORT` differs from full ONLY by `kubernetes` → `K8s`, the intentional compact-table distinction; `PROVIDER_SUBTAB_MAP` 7 known keys; `PROWLER_SELECTABLE_ORDER` 7 known keys in the locked selector order). Parser ignores the `*)` default arm and has a mutation self-test | this PR |
| `scanner/tests/test_ci_diagram_gen_canonical_sync.py` | `scanner/lib/diagram-gen.py` single-sources security domains + compliance frameworks | diagram-gen imports `ARCH_DOMAINS` from `dashboard_arch` and `COMPLIANCE_FRAMEWORKS` from `dashboard_compliance`, has NO inline `ARCH_DOMAINS = [` reassignment and NO hand-rolled `frameworks = ["..."]` string list (it derives `frameworks = [f["name"] for f in COMPLIANCE_FRAMEWORKS]`); functional check asserts the loaded module's `ARCH_DOMAINS` IS the canonical object (imported, not copied) — the diagram previously drifted to a stale 6-domain / 6-framework mis-versioned subset (same bug-class as the removed `dashboard_compliance` inline `COMPLIANCE_CONTROL_MAP` fallback). Comment-stripped + mutation self-test (OWASP A08) | this PR |
| `scanner/tests/test_ci_compliance_keyword_guard.py` | `compliance-map.py` control `checks` keyword lists stay free of substring-false-positive tokens (`map_compliance()` marks a control FAIL on a plain substring match, so an over-broad keyword mis-attributes unrelated findings) | REGRESSION PINS: the specific over-broad tokens removed by this PR stay removed from their controls (`policy` from ISMS-P 1.1.1/2.1.1 + ISMS-Simple S-1.1/S-2.1; `api` from 2.6.3; `hsm` from 2.7.2; `waf`+`endpoint` from 2.10.1; `endpoint`+`edr` from 2.10.8; `transfer` from PII cross-border 3.3.4; `port` from CIS-4.1; `node` from CIS-K8s-4.1) AND each edited control keeps >=2 checks (a future edit cannot gut it). COLLISION GUARD: no keyword anywhere in the map is a PROPER substring (keyword != word, so an intended equal-match like 2.6.3/`session` or 2.10.5/`transfer` is not flagged) of a curated benign Prowler-adjacent word list (`support`/`report`/`transport`/`export`/`nodejs`/`node_modules`/`apigateway`/`capital`/`software`/`endpoint`/`dialog`/`login`/`transfer`/`session`); the 12 short (<=3 char) acronyms {cve,iam,kms,mfa,pii,ssl,ssn,sso,tls,vpc,xss} verified NON-colliding so ALLOWLIST is empty. Mutation self-tests: an injected fake `port` keyword fires the detector, and an equal-match keyword stays unflagged (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_docker_kcov_parity.py` | Local Docker kcov harness ↔ CI `scanner-shell-coverage` parity (`scripts/verify-shell-coverage-docker.sh` ↔ `lint.yml`) | the harness's `INCLUDE`/`EXCLUDE` declarations equal (as sets) CI's kcov `--include-pattern`/`--exclude-pattern`, and its `FLOOR` equals CI's enforced `threshold` — so the local pre-push mirror measures the exact same SUT files and floor as CI (drift already happened in #336: local `INCLUDE` was missing `checks_credentials.sh`, and `test_run_category_checks.sh` had to be added to `EXCLUDE` in both places at once). Also asserts CI's own tty vs non-tty kcov invocations use identical patterns (a single canonical value to compare). Comment-stripped (a pattern living only in a comment cannot satisfy the check) + mutation self-tests for each drift class | this PR |
| `scanner/tests/test_ci_scanner_lib_reachability.py` | No NEW unreachable (dead) top-level function in the kcov SUT libs (`scanner/lib/{checks,checks_credentials,output,output_prowler}.sh`) | the bash coverage floor measures "executed by a test", not "reachable from the scanner", so a test-only function stays fully covered while being dead (the class removed in the dead-code PR: `compute_trend`, `load_scan_history`, `_html_findings_rows*`, `html_escape`, `api_key_found`, `compliance_map`). For each top-level SUT function the guard requires >=1 reference in the production corpus (`scanner/claudesec` + `scanner/checks/**` + `scanner/lib/**`), comment-stripped, own-def-line excluded, whole-word (a substring/comment does not count). Regression-pin: asserts the dead set EQUALS the documented `KNOWN_UNREFERENCED` baseline (`_prowler_dashboard_summary`, `count_files`, `datadog_validate_api_key` — removal candidates), so a NEW dead function fails AND a stale allowlist entry fails once it is wired-up/removed. Conservative (only under-reports), so it never false-blocks a reachable function. Mutation self-tests | this PR |
| `scanner/tests/test_ci_no_code_injection_regression.py` | No CWE-94 code-injection sites where a bash variable is interpolated directly into a `python3 -c "..."` program body OR an unquoted heredoc feeding an interpreter (`scanner/claudesec`, `scanner/lib/**`, `scanner/checks/**`, `scripts/**`, `hooks/**`) | for every DOUBLE-quoted `python3 -c "..."` / `python -c "..."` site (captured across multi-line bodies, comment-stripped first, concatenation-aware for adjacent quoted segments), flags a `$NAME`/`${...}`/`$(...)` bash expansion inside the program text — splicing a shell value into Python source before parsing is OWASP A03:2021 / CWE-94 injection. ALSO flags an UNQUOTED heredoc (`<<EOF`/`<<-EOF`) whose owning command is a code-executing interpreter (`python`/`python3`/`sh`/`bash`/`awk`/`perl`/`node`/`ruby`, basename-matched, continuation-line-aware) — a quoted delimiter (`<<'EOF'`/`<<"EOF"`) disables expansion and stays safe; a heredoc feeding a non-interpreter (`cat`, `kubectl`, `gh api`, ...) is data, not code, and is never flagged. Regression-pin: asserts the violation set EQUALS the `KNOWN_INJECTION_SITES` baseline, empty after this PR's fix (`scripts/run-prowler-k8s.sh`, `scripts/check-prowler-python-ceiling.sh`, `scripts/sync-scan-to-dashboard.sh` moved the value to the environment, read via `os.environ`), mirroring the #346 `output_prowler.sh`/`prowler_compliance_summary.py` fix. Single-quoted `-c '...'`, argv/stdin/env-var-passed values are explicitly out of scope (safe); quote-concatenation in a `-c` argument is best-effort covered for adjacent quoted segments only (unquoted concatenated runs are not content-checked). Mutation self-tests | this PR |
| `scanner/tests/test_ci_no_raw_output_interpolation.py` | The hand-built JSON / HTML / URL output-assembly sinks in `scanner/lib` keep routing tainted (env / filename / scanned-content) values through an escaper — a source-level regression pin complementing the per-sink behavior tests (`test_output_functions.sh` / `test_datadog_json_payloads.sh` / `test_prowler_dashboard_summary.sh`) | For each known sink, against comment-stripped + continuation-joined source: asserts the required escaper INVOCATION is present AND the specific known RAW-interpolation string is ABSENT. Pins `output.sh::print_json_summary` → `_json_escape_str "$SCAN_DIR"` (`"scan_directory"` not raw `$SCAN_DIR`, #361); `datadog.sh` → `_json_escape_str`/`_url_encode` on `dd_service`/`dd_env` (intake/query JSON #361 + `ddtags=` URL query #363, neither raw); `output_prowler.sh::_prowler_dashboard_summary` → `_prowler_html_escape "$label"` (#362, filename-XSS). Deliberately a narrow pin over KNOWN sinks, not a general raw-interpolation static analyser (false-positive-prone on numeric/enum fields). Mutation self-tests: a removed escaper usage and a reintroduced raw interpolation both fire the detector | this PR |
| `scanner/tests/test_ci_dashboard_control_smoke.py` | Dashboard control-liveness smoke stays hermetic, path-gated, and bounded (`dashboard-control-smoke.yml` + `scanner/tests/{dashboard-control-liveness.mjs,test_dashboard_control_liveness.sh}`) | the workflow sets `CLAUDESEC_DASHBOARD_OFFLINE=1` (else the generator makes live GitHub API calls and can hang the job — #190) AND the harness wrapper self-exports it too (belt-and-suspenders, not CI-env-dependent); the `changes` job exposes a `dashboard` output and the `smoke` job is path-gated `if: needs.changes.outputs.dashboard == 'true'` (docs-only PRs skip the browser smoke; intentionally NON-required, a simple path-gate not an `always()` aggregator — that pattern is reserved for required checks per the paths-ignore/#186 incident); the browser step carries a per-step `timeout-minutes` (a hung headless Chrome can't burn the job budget) — asserted inside the isolated `- name:` step block that invokes the harness, because unscoped it was satisfied by the workflow's JOB-level `timeout-minutes` keys and could not detect removal of the per-step cap (inert-guard class; mutation self-tests pin job-level and wrong-step caps) — and invokes the real harness wrapper; both harness files exist on disk (a workflow pointing at a deleted script is a silent no-op). Comment-stripped presence checks (OWASP CICD-SEC-1) | this PR |
| `scanner/tests/test_ci_guard_assertion_scoping.py` | **Meta-guard** — no `test_ci_*.py` guard makes a POSITIVE presence assertion against the RAW, whole-file text of the artifact it protects | AST scan (stdlib `ast`, not text) of every guard file: `assertIn(tok, raw)` / `assertRegex(raw, pat)` / `assertTrue(tok in raw)` where the haystack is a name bound directly to `Path.read_text()` is an INERT assertion — commenting the control out leaves the token in the file, so the guard reads green while the control is dead, which is worse than no guard (a reviewer takes the green as proof). Exempts the two non-inert shapes: NEGATIVE assertions (raw scanning for a FORBIDDEN token only over-reports — a false alarm, never a bypass) and LINE-ANCHORED regexes (`(?m)^\s*token`, which a `#`-commented copy cannot satisfy). Regression-pin: the detected set must EQUAL `KNOWN_RAW_PRESENCE_ASSERTIONS`, currently **empty** — a new offender fails AND a stale exemption fails once its site is fixed. Generalizes the two inert guards #383 found by hand (`provenance_verify` `npm audit signatures`, `docker_image_size_gate` `exit 1`) into a check that runs on all 40 guards and on every new one. Under-reports by design (never false-blocks). Mutation self-tests | this PR |
| `scanner/tests/test_ci_pr_trigger_scope.py` | The two REQUIRED workflows (`lint.yml` → `Lint`, `security-scan.yml` → `Security Scan Gate`) keep an UNSCOPED `pull_request:` trigger | no `branches:` / `branches-ignore:` and no workflow-level `paths:` / `paths-ignore:` under `pull_request:`. Two opposite failure directions of one root cause — a workflow-level trigger filter on a required check. `branches:` filters by the PR's BASE ref, so `branches: [main]` hid both required checks from stacked PRs entirely: PR #384 (base = a feature branch) got 3 checks with neither required context, the same branch retargeted to `main` (#385) got 28 — the change was unverifiable until its base merged. `paths-ignore:` is the #186 mode: the required check never reports for a PR that DOES target `main`, so protection blocks the merge forever. Not symmetric — removing `branches:` is strictly additive (PRs targeting `main` behave identically, so #186 cannot recur), adding `paths-ignore:` IS #186. Job-level gating with the `changes` job + an `always()` aggregator stays the sanctioned pattern. Scoped to the two required workflows only: `dast-baseline.yml` legitimately carries both filters and is out of scope. Block membership is by indentation under the `on:` → `pull_request:` key, so a sibling `push: branches:` cannot false-trip it and `pull_request_target:` is never matched; flow-style values on the key line are captured. Mutation self-tests | this PR |

### Related enforcement (not a pytest guard)

- **`workflow-fork-guard`** (`lint.yml`) audits `pull_request_target` workflows
  for the head-repo fork guard (OWASP A08); wired into `lint-gate.needs` so it is
  merge-blocking (#203).
- **`Security Scan Gate` severity block** (`security-scan.yml`) fails the build
  on any CRITICAL scanner finding; HIGH findings warn only (#206).

## Why two required checks matter

`main` branch protection requires exactly two status checks: **`Lint`** (the
`lint-gate` aggregator in `lint.yml`) and **`Security Scan Gate`** (the
aggregator in `security-scan.yml`). Both use the `if: always()` +
"`skipped` counts as success" pattern so that path-gated jobs don't block
docs-only PRs (see the `paths-ignore` vs branch-protection incident, #186).

The consequence: **any job that is not wired into one of these two aggregators'
`needs:` is invisible to branch protection** — it can fail without blocking a
merge. That is precisely the gap the topology guards
(`test_ci_gate_topology.py`, `test_ci_security_gate.py`) exist to catch.

The topology guards check that every *present* job is gated; they cannot see a
job that is **deleted entirely** (a removed job simply leaves the gated set, and
the aggregator stays green). `test_ci_required_jobs_exist.py` closes that
complementary gap by asserting the load-bearing security jobs still exist.

## Unguarded invariants backlog

A standing list of CI invariants that are **not yet** protected by a guard,
triaged by the same bar used to add one (an incident, past or plausible, where
*silent* weakening disables enforcement — no incident means it likely is not
worth a guard, to avoid sprawl). Reviewed 2026-06-19; re-triaged 2026-06-22
(all Tier-3 workflows confirmed KEEP-AS-MONITOR — decision unchanged; the
`workflow_run` trigger added to `provenance-verify.yml` in #263/#264 is already
covered by `test_ci_provenance_verify.py`). **Quarterly ADR-001 adversarial
audit 2026-07-28** (issue #297): all 38 `test_ci_*.py` guards re-audited — see
"Quarterly audit 2026-07-28" below for the comment/unhandled-form findings fixed
and the matcher-completeness backlog opened.

### Tier 2 — incident-backed (now implemented)

Both former Tier-2 candidates landed in #258 and are now in the Catalog above:

- `test_ci_prowler_version_pinned.py` — exact `prowler==${PROWLER_VERSION}` pin
  in `Dockerfile` (#237).
- `test_ci_dockerfile_base_pinned.py` — `@sha256:` digest pins + `alpine:3.20`
  minor freeze + version-agnostic site resolution (#233/#234/#220).

### Tier 3 — monitor only (no guard yet; would be sprawl)

- **Auxiliary scheduled workflows** — `prowler-python-watch.yml`,
  `dashboard-refresh.yml`, `og-meta-verify.yml`: none is a required status check
  and none runs on `pull_request_target` with a write token, so silent weakening
  does not disable a merge gate. Add a guard only if one later gains enforcement
  responsibility (becomes required, or gains a write-token PR trigger).

  **Decision (2026-06-19): no dedicated "promotion-watch" guard.** Both ways one
  of these could *become* enforcement-bearing are already covered, so a guard
  asserting "they stay non-required / non-`pull_request_target`" would be
  redundant (the no-incident-it-catches bar fails):
  - *Gains a `pull_request_target` trigger* → the `workflow-fork-guard` job audits
    **every** `pull_request_target` workflow for the head-repo fork guard and is
    wired into `lint-gate.needs`, so a promoted-but-unguarded workflow fails the
    required `Lint` check.
  - *Becomes a required status check* → that is branch-protection drift:
    `test_ci_branch_protection_codified.py` pins `DESIRED_CONTEXTS` to exactly
    `Lint` + `Security Scan Gate`, and `protection-drift-watch.yml` reports any
    live divergence nightly.

  (`og-meta-verify.yml` already runs on `pull_request` — not `_target` — with
  `pull-requests: write`; a switch to `pull_request_target` is the case the
  fork-guard job catches.)
- **DAST trigger invariants** — `dast-baseline.yml` (`pull_request`) and
  `dast-full-scan.yml` (`schedule:`) triggers are already asserted by
  `test_ci_security_gate.py`; no separate guard needed.

- **`uses:` version-comment correctness vs the pinned SHA.**

  **Decision (2026-06-24): no version-comment guard.** A guard asserting the
  `# vX.Y.Z` comment matches the pinned SHA's actual tag would need to resolve
  SHA → tag via the GitHub API — a **network call**, which violates the
  stdlib-only / offline / no-subprocess constraint every guard here holds.
  A weaker *presence* check (every `uses:` has *some* version comment) is
  offline-feasible but would NOT have caught the real incident (a Dependabot bump
  that updated the SHA but left a STALE `# v4.2.2` comment on a `v7.0.0` SHA,
  normalized in the checkout-v7 cleanup) — it only catches a *missing* comment,
  not a wrong one. Crucially, the comment is **cosmetic**: `test_ci_gate_topology.py`
  already pins the 40-hex SHA (the actual supply-chain control), so a wrong
  comment is a readability/doc-accuracy wart, not a security regression — below
  the incident bar. Mitigation is a one-time normalization on each major action
  bump, not a guard.

### Quarterly audit 2026-07-28 (ADR-001, issue #297)

A full adversarial re-audit of all 38 `test_ci_*.py` guards (three independent
review passes; every finding reproduced with an executed proof, not a static
read). Three guards were confirmed CLEAN with the comment-evasion class
inapplicable by construction: `test_ci_lighthouse_perf_gate.py` (strict
`json.loads`), `test_ci_codeowners_invariants.py` (mirrors GitHub's own
CODEOWNERS grammar — no inline-comment syntax exists), `test_ci_compliance_keyword_guard.py`
(executes the real module and inspects the runtime `COMPLIANCE_CONTROL_MAP`, no
text surface).

**Fixed (Class 1 — comment/unhandled-form evasion; the natural "comment out the
control" regression path, the exact class ADR-001 §1/§3 target):**

- `test_ci_net005_fail_escalation.py` — section built from raw lines; a
  `# fail "NET-005" ... "critical"` comment satisfied the escalation check while
  active code downgraded to WARN → now routes through `strip_comment_lines` +
  comment-survival mutation test.
- `test_ci_changes_job_merge_base.py` — imported only `join_continuations`; the
  `|| git diff` fallback / non-shallow fetch tokens satisfied the check from a
  comment → now `join_continuations(strip_comment_lines(text))` + mutation test.
- `test_ci_compose_dashboard_hardening.py` — `_strip_comments` kept trailing
  inline comments and the `no-new-privileges` regex is (necessarily) unanchored,
  so the token rode a trailing comment on an unrelated line → now strips trailing
  inline comments via `strip_inline_comment` + mutation test.
- `test_ci_dependabot_config.py` — used `non_comment_lines` (whole-line only); a
  required ecosystem token rode a trailing inline comment → now composes
  `strip_inline_comment` + mutation test.
- `test_ci_security_gate.py` (**required `Security Scan Gate` merge-block**, the
  #271 F-1 incident class) — surfaced by the mandated ADR-001 §2 review chain: a
  `;#exit 1` (a REAL bash comment — no space before `#`, verified the `exit 1`
  never runs) survived `strip_inline_comment` and satisfied the CRITICAL
  merge-block check while the active code was warn-only. Root cause was the
  SHARED primitive: `strip_inline_comment` required whitespace before `#`, but
  bash starts a comment after a command separator (`;`/`&`/`|`) with no space.
  Added a quote-aware, bash-word-boundary `strip_inline_comment_sh` and routed
  the three shell-scanning guards (`security_gate`, `net005_fail_escalation`,
  `changes_job_merge_base`) through it (+ metachar AND backtick mutation tests).
  The comment-start boundary set (whitespace + the bash metacharacters
  `;`/`&`/`|`/`(`/`)`/`<`/`>` + backtick) was proven complete by enumerating
  every ASCII preceding char against real `bash` (a further review pass found the
  backtick `` `#… ` `` form after the initial metachar set; both are now closed
  and confirmed). The whitespace-only `strip_inline_comment` is retained for
  YAML/Dockerfile callers, where `;#` is literal scalar content, not a comment.
  A **5th-pass** review (ADR-001 §2) then found the ANSI-C `$'...'` case was NOT
  an over-strip but an **UNDER-strip** (false negative): `$'\''` is one escape-
  aware string, and a single-quote branch with no escape awareness ran off the
  line "in a quote" and never stripped the trailing `#`, hiding a dead `exit 1`
  from the gate. Modeled it (a `'` after an unescaped `$` opens an escape-aware
  string) + added ANSI-C mutation tests to the primitive, `security_gate`, and
  `net005_fail_escalation`. Remaining documented **over-strip** limitations
  (opposite direction — they drop live text → a false ALARM, never a silent
  bypass; none is triggered by the scanned blocks): cross-line quoted strings,
  heredoc bodies, and a command substitution `$(...)` closing inside a word
  (`x=$(cmd)#c` keeps `#c` literal, but the single preceding-char model cannot
  tell that `)` from a subshell `)`) — see the `strip_inline_comment_sh` docstring.
- `test_ci_injection_surface.py` — the twice-hardened block-scalar rule still
  missed single-line flow-style step mappings
  (`steps: [{run: "…${{ github.event.* }}…"}]`), leaving that `run:` body
  unscanned → added a grammar-complete flow-style extractor (ADR-001 §4) +
  mutation test. The multi-line-quoted flow scalar (unreassemblable by a
  no-PyYAML line scanner) is now caught by a **tripwire** (`unscannable_flow_runs`)
  that FAILS on the unscannable shape so an injection cannot hide in it — the
  author must use a block scalar or a single-line flow value (dormant on this
  repo: all `run:` are block style, so zero false positives). The
  multi-line-split `${{ }}` block-scalar form is **now closed the same way** —
  see the entry below.

**Class B follow-up — `strip_inline_comment_sh` adoption (this PR):**

The #383 sweep classified three further guards as **Class B**: they *do* catch a
plain deletion of the control, but they scanned shell with the whitespace-boundary
`strip_inline_comment`, so the same `;#` metachar adjacency that hid a dead
`exit 1` from the Security Scan Gate applied to them too. They waited on the
primitive rather than growing a divergent local copy of the bash boundary logic.
All three are now routed through `strip_inline_comment_sh`, together with the one
gap #383 recorded against itself:

- `test_ci_coverage_thresholds.py` — `pytest scanner/;#--cov-fail-under=99` left
  the floor token in the file with no gate running.
- `test_ci_dependabot_automerge.py` — `echo skip;#scanner/*|scanner)` parked a
  hard-exclude arm in a comment, so a `pull_request_target` write-token workflow
  would auto-arm `scanner/` changes with the guard green. The four narrower
  per-invariant tests additionally asserted against the **raw** file text, which
  made them inert against a plain comment-out; they now share the stripped scan.
- `test_ci_prowler_provider_guard_ordering.py` — a decoy
  `echo x;#_prowler_provider_available "…"` lent its early line number to
  `min(guard)` and masked a real guard placed after the report (the F-8 masking,
  reached via a metacharacter instead of leading whitespace).
- `test_ci_docker_image_size_gate.py` — the `exit 1` breach-block scan, the gap
  #383 documented in the function docstring and the catalog row; `;#exit 1` made
  a 900 MB image merge with a green guard.

Each was reproduced with an executed proof against real `bash` before the change,
and each fix ships mutation self-tests proven non-vacuous (all 10 FAIL when the
primitive is reverted to `strip_inline_comment`). The over-strip direction is
pinned too: a `#` inside quotes is literal and must not truncate a live control.

**Inert-assertion class, promoted to a meta-guard (this PR):**

The two inert guards #383 found (`provenance_verify`, `docker_image_size_gate`)
shared one shape: a positive presence assertion aimed at the **raw whole-file
text**. Hand triage caught them, but it does not scale to 40 guards and does not
run on new ones, so the triage is now codified as
`test_ci_guard_assertion_scoping.py` — an AST scan of the guard suite itself.

Running it found **seven more** live instances, each confirmed inert by executing
the guard against a commented-out artifact (green before the fix, red after —
same mutant, only the haystack changed):

| Site | Control left dead while the guard read green |
|---|---|
| `test_ci_branch_protection_codified.py` ×2 | `DESIRED_CONTEXTS` (both required merge contexts) and `DESIRED_ENFORCE_ADMINS="true"` commented out |
| `test_ci_branch_protection_codified.py` ×2 | the `DRIFT DETECTED` producer/consumer marker contract on both ends |
| `test_ci_cross_os_non_required.py` | the `macos-latest` runner canary |
| `test_ci_npm_publish.py` ×2 | the push-`branches: [main]` auto-release trigger |

All seven now assert against the guard's comment-stripped scan; the
branch-protection pair additionally moved to `strip_inline_comment_sh`, since
both artifacts are shell-bearing and were open to the same `;#` adjacency. The
baseline `KNOWN_RAW_PRESENCE_ASSERTIONS` therefore ships **empty**, and its
set-equality pin fails on a stale entry as well as a new offender.

The meta-guard deliberately exempts the two shapes that are not inert: negative
(FORBIDDEN-token) assertions, where raw scanning only over-reports, and
line-anchored regexes (`(?m)^\s*token`), which a `#`-commented copy cannot
satisfy — three guards rely on that form correctly and are not flagged.

**Catalog meta-guards hardened (this PR — closes the last non-deferred Class 2
item):**

`test_ci_catalog_completeness.py` and `test_ci_catalog_no_ghost_rows.py` shipped
with **no mutation self-test** — they only ever ran against the real catalog, so
a parser regression would have gone unnoticed and both would have passed
vacuously. Detectors are now extracted to module level (`missing_rows`,
`cited_paths` / `ghost_rows`) and exercised on synthetic input: undocumented
guard, ghost row, prose glob, duplicate citations, empty catalog.

Both also scanned the catalog RAW. Markdown has no `#` comment, so `<!-- ... -->`
is the escape hatch, and a row parked inside one renders as nothing while still
satisfying a substring check — a guard could vanish from the published inventory
with `catalog_completeness` green. Both now route through a shared
`strip_html_comments` in `_ci_guard_util.py`. The strip cuts **both ways, and
both are correct**: it makes `completeness` STRICTER (a hidden row no longer
satisfies presence) and `no_ghost_rows` more LENIENT (a commented row claims no
coverage, so flagging it would be a false alarm) — with a test pinning that a
commented ghost still does not mask a live one. An unclosed `<!--` degrades to
no-strip rather than blanking the document, which would fail every consumer at
once.

Non-vacuous: neutering `strip_html_comments` fails 3 of the new tests.

**`injection_surface` split-expression gap closed by tripwire (2026-08-06):**

The one remaining Class 2 row — a `${{ }}` split across two physical lines inside
a `run:` body — is no longer a documented gap. It is closed the way its flow-style
sibling was: `unscannable_block_runs` **fails closed on the unscannable shape**
(an opened `${{` with no `}}` on the same physical line inside a run body) instead
of guessing at semantics the guard cannot verify. The remediation is trivial and
always available — keep each expression on one line, which is how every `${{ }}`
in this repo is already written — so the shape ban costs nothing. Reassembling
folded YAML lines would need a real parser (stdlib-only / no-PyYAML), and whether
the Actions expression lexer even accepts the split form stays **unverified**;
failing on the shape makes that question moot rather than load-bearing.

Building it surfaced an **adjacent hole the audit had not recorded**, which a
tripwire alone would have left open: a multi-line **plain** scalar
(`run: echo` followed by a deeper-indented `'${{ github.event.issue.title }}'`)
folds into one command at runtime, but the continuation line was dropped from the
body entirely — so the interpolation was invisible to the scanner AND to the new
tripwire (the expression closes on its own line, it is the *body extraction* that
was incomplete). Fixed by scanning it: an inline `run:` value now shares the
block scalar's deeper-indented collection loop, since YAML applies the same
indentation rule to both styles. Error direction is safe — over-collecting can
only raise a false alarm, and a sibling `env:`/`with:` key aligns with the `run:`
column and still terminates the scan (pinned by a new test, the inline analog of
the existing block-scalar case).

The mandated ADR-001 §2 adversarial pass then found **four more**, all confirmed
by executing the detector against PyYAML's resolved document as ground truth
(PyYAML is available outside the CI test job, so it can serve as an oracle for
what the guard *should* see without becoming a dependency of the guard):

| Finding | Class | Resolution |
|---|---|---|
| **Quoted mapping key** — `"run": echo '${{ … }}'` resolves to the same `run` key, but both the block and flow matchers hard-required an unquoted `run:` → guard green, injection live | Class 2, **pre-existing** | `_RUN_KEY` now accepts `run` / `"run"` / `'run'` across all three matchers. Not exotic: GitHub's own docs normalize `"on":` for the YAML-1.1 boolean collision, so a quoted key is a plausible style, not a contrived evasion |
| **Explicit-key form** — `- ? run` then `: echo '${{ … }}'` puts key and value on different lines, so the substring `run:` never appears and no line matcher can see it | Class 2, **pre-existing** | Third tripwire, `unscannable_run_keys` — fail closed on the shape, same rationale as the other two |
| **`.yaml` extension** — `_workflow_files()` globbed only `*.yml`, while Actions honours both, so a whole `.yaml` workflow would be silently unscanned | Class 2, **pre-existing** (latent: repo has no `.yaml` workflow) | Glob both extensions; pinned behaviourally against a fixture directory, not by reading this file's own source (that would be the inert shape the AST meta-guard rejects) |
| **Comment false positive** — a `# never do this: ${{ github.event.issue.title }}` warning comment beside an inline `run:` was collected as scalar continuation and scanned as shell | **introduced by this change** | Stop collection at a comment-only line for inline values *only*. This is exact rather than conservative: PyYAML rejects `run: echo` / `# c` / `hi` as a parse error, so a plain scalar cannot resume after a comment. In a block scalar the same line is literal body text and is still collected |

The review also flagged the new sibling-key boundary test as **vacuous** — an
absence-only assertion that also passes when continuation collection is deleted
outright, the same inert shape the AST meta-guard exists to reject. It now pairs
a positive control (a genuine continuation IS collected) with the negative one,
so it fails under that mutant too.

Every change ships a mutation self-test proven non-vacuous **by execution** — six
mutants, each failing exactly its own test(s) and nothing else: neuter
`_expr_unterminated`; restore the early `continue`; revert `_RUN_KEY` to unquoted;
neuter `unscannable_run_keys`; drop the comment-stop; revert the `.yaml` glob.
All are dormant on the real workflows (zero unterminated `${{`, zero inline-`run:`
continuation lines, zero quoted/explicit keys, no `.yaml` file), so none adds a
false positive today.

**Lesson, again:** the first fix left residual holes — the fifth instance of the
pattern ADR-001 predicts. Note the direction: the tripwire this PR set out to add
would NOT have closed the plain-scalar hole or the two key-form holes, because a
tripwire only fires on a shape the extractor already reaches. Banning an
unscannable shape and *verifying the extractor reaches every shape* are separate
obligations.

**Backlog (Class 2 — matcher-completeness / enumeration gaps; require a
deliberate, unusual edit rather than a comment-out, so lower natural-regression
risk — triaged as follow-up, not blocking):**

- `test_ci_no_ere_pipe_regression.py` — misses the `--extended-regexp` long-flag
  form and cross-line variable-indirection of the `\|` ERE bug.
- `test_ci_npm_files.py` — `files[]` glob match is not grammar-complete (`docs/**`
  ships the tree; order-blind to a positive pattern re-added after its negation).
- `test_ci_plugin_skills_cli_parity.py` / `test_ci_provider_labels_sync.py` —
  parse `case` arms into an unordered `set()`, so moving the `*)` catch-all ahead
  of a real arm (runtime-unreachable) still satisfies the presence check.
- `test_ci_cross_os_non_required.py` — `FORBIDDEN_IN_LINT` is a fixed 4-string
  enumeration (bypassed by `macos-14`/`windows-2022` labels); collision check
  omits the `"Lint"` required context.

Both `test_ci_injection_surface.py` rows that were listed here are now **closed**
by shape tripwires rather than deferred — see "split-expression gap closed by
tripwire" above.

### Verified already-guarded during this review (not backlog)

lychee `v0.23.0` pin (`test_ci_gate_topology.py`), the `Security Scan Gate`
CRITICAL `exit 1` severity block (`test_ci_security_gate.py`), CODEOWNERS
coverage, ERE-pipe regressions, prowler provider ordering, coverage floors, npm
`--provenance`, and the cross-OS non-required invariant.

## Adding a new guard

1. Identify a CI invariant whose silent weakening would disable enforcement, and
   name a concrete past or plausible incident (no incident → likely not worth a
   guard; avoid guard sprawl).
2. Add `scanner/tests/test_ci_<thing>.py` following the conventions above.
3. Decide and document the regression **direction** (floor `>=`, pin `==`,
   presence).
4. Prove it is **non-vacuous**: temporarily mutate the workflow (or simulate the
   parse) so the guard fails, then revert.
5. Confirm it passes under `pytest` and `python3 -m unittest`, and that it does
   not import `scanner/lib`.

## References

- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control),
  CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-7 (Insecure System
  Configuration): <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (Secure Software Development Framework, SSDF) — PO.3, PW.4:
  <https://csrc.nist.gov/pubs/sp/800/218/final>
- OWASP Top 10:2021 A08 — Software and Data Integrity Failures:
  <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/>
- In-repo: `.github/workflows/lint.yml`, `.github/workflows/security-scan.yml`,
  `scanner/tests/test_ci_*.py`
- Decision record: [ADR-001 — CI Guard Hardening Discipline & Periodic
  Adversarial Audit](./adr-001-ci-guard-hardening-and-audit-cadence.md)
