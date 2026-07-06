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
| `scanner/tests/test_ci_coverage_thresholds.py` | Coverage floors in `lint.yml` | pytest `--cov-fail-under >= 99`; bash kcov `threshold >= 90.0` | #200 |
| `scanner/tests/test_ci_gate_topology.py` | Enforcement topology of `lint.yml` | every `uses:` across all `.github/workflows/*.yml` is 40-hex SHA-pinned (OWASP A08); every job is in `lint-gate.needs` or a tiny documented allowlist | #201 (allowlist tightened in #203) |
| `scanner/tests/test_ci_security_gate.py` | `Security Scan Gate` + DAST signals | `security-scan-gate` keeps `name`, `if: always()`, `needs: ⊇ {changes, scan, lighthouse}`, pass-set `not in (success, skipped)`; `dast-baseline.yml` keeps its `pull_request` trigger; `dast-full-scan.yml` keeps its `schedule:` trigger | #205, #216 |
| `scanner/tests/test_ci_required_jobs_exist.py` | Existence of security/enforcement jobs in `lint.yml` | `{gitleaks, pii-check, dependency-review, workflow-fork-guard, scanner-unit-tests, scanner-shell-coverage}` are all present — deleting a whole job is a silent control loss the topology guard cannot see | #215 |
| `scanner/tests/test_ci_codeql_single_model.py` | Single CodeQL model (default setup only) | no workflow uses `github/codeql-action/init` or `/analyze` (a repo-level analysis would duplicate the default-setup model); `upload-sarif` is allowed (DAST SARIF upload, not analysis) | #215 |
| `scanner/tests/test_ci_npm_publish.py` | npm release supply-chain integrity + auto-release wiring (`npm-publish.yml`) | every `npm publish` carries `--provenance` (SLSA attestation); workflow-level `permissions:` stays `contents: read` (job-level `id-token: write` + `contents: write` are not flagged); the publish job upgrades npm (`npm install -g npm`, OIDC needs >= 11.5.1 but Node 22 ships npm 10.x); the `on:` block keeps a push-to-`main` trigger (version-bump auto-publish) and a `contents: write` exists for pushing the `vX.Y.Z` tag | #216, #262 |
| `scanner/tests/test_ci_cross_os_non_required.py` | Cross-OS live-runner workflow stays non-required | `cross-os-checks.yml` exists and keeps `workflow_dispatch` (standalone informational lane); `lint.yml` references none of `{cross-os, live-os-checks, macos-latest, windows-latest}` — so the costly/flaky macOS+Windows runs never become a required merge gate | #228 |
| `scanner/tests/test_ci_net005_fail_escalation.py` | NET-005 SSH-open-to-world FAIL escalation (`network/tls.sh`) | NET-005 keeps `fail "NET-005" ... "critical"` and an ERE `(0\.0\.0\.0/0.*22\|port.*22.*0\.0\.0\.0/0)` alternation; no `\|` literal-pipe regression (which silently downgraded it to WARN, fixed in #224) | #228 |
| `scanner/tests/test_ci_dependabot_automerge.py` | Dependabot auto-arm safety (`dependabot-auto-merge.yml`, a `pull_request_target` write-token workflow) | keeps the fork guard (`actor==dependabot[bot]` AND `head.repo.full_name==github.repository`), the hard-exclude path arms (`Dockerfile*`/`.github`/`scanner`/`hooks`/`scripts`), the `semver-patch\|minor`-only update-type allowlist + `semver-major` exclude, the `pip\|docker\|github-actions` ecosystem allowlist, and `gh pr merge --auto`; forbids `--admin` (code-owner bypass) and the `pr review --approve` bot self-approve removed in #249 (OWASP CICD-SEC-1/-4) | #249, #250 |
| `scanner/tests/test_ci_codeowners_invariants.py` | `.github/CODEOWNERS` keeps security-sensitive paths code-owner gated | every required pattern (`*`, `.github/workflows/`, `.github/CODEOWNERS`, `hooks/`, `scanner/`, `scripts/`, `templates/`, `Dockerfile*`, `docker-compose*.yml`) is present AND has a non-empty `@owner`; the global `*` default must have an owner — else those paths merge with NO code-owner review (`require_code_owner_reviews=true` only fires on a matched, owned pattern) | #248 |
| `scanner/tests/test_ci_no_ere_pipe_regression.py` | No literal `\|` in an ERE context in `scanner/checks/**` + `scanner/lib/**` `.sh` | flags `\|` (literal-pipe, NOT alternation) inside `grep -[qnrlc]*E`, the `_code_grep`/`files_contain`/`file_contains` helpers, and bash `[[ =~ ]]` — the silent detection-breaking bug class fixed in #221/#223/#224; two intentional literals (`code/injection.sh` `\|safe`, `solutions.sh` `curl\|sh`) are allowlisted and asserted still present | #244, #246 |
| `scanner/tests/test_ci_prowler_provider_guard_ordering.py` | `_prowler_provider_available` precedes `_prowler_report` per provider (`scanner/checks/prowler/integration.sh`) | within each provider section of the Provider Scans block, `min(guard line) < min(report line)` — reordering would silently regress the #238 build-parity fix (lean image would emit a misleading auth warning instead of an accurate "not in this build" skip); promotes the shell-level `#241` assertion into the pytest CI gate | #242 |
| `scanner/tests/test_ci_catalog_completeness.py` | Completeness of this catalog vs the on-disk guard suite | every `scanner/tests/test_ci_*.py` file has its repo-relative path listed in this catalog (presence) — a new guard added without a Catalog row is silent documentation drift that makes the inventory understate coverage; the meta-guard documents itself so the invariant is uniform | #254 |
| `scanner/tests/test_ci_catalog_no_ghost_rows.py` | No ghost rows in this catalog vs the on-disk guard suite | every concrete `scanner/tests/test_ci_<name>.py` path cited in this catalog resolves to a real file (existence) — the reverse of the completeness guard: a renamed/deleted guard left in the table is a ghost row that makes the inventory overstate coverage. Together the two guards verify a 1:1 catalog↔suite mapping | #255 |
| `scanner/tests/test_ci_branch_protection_codified.py` | Codified branch protection (`scripts/sync-repo-protection.sh`) + its nightly notifier (`protection-drift-watch.yml`) | the desired state keeps `DESIRED_CONTEXTS=["Lint","Security Scan Gate"]` (both required checks — an exact two-sided pin: dropping a context un-requires that aggregator, and silently *adding* a third required context is equally caught, proven by appended+prepended mutation self-tests), `DESIRED_ENFORCE_ADMINS="true"` (admins not exempt — no force-push to main), `strict`/`require_code_owner_reviews` true, `set -euo pipefail`, and the default-arm dry-run; the `DRIFT DETECTED` marker contract holds on both producer (script) and consumer (`grep -q`) sides; the watch keeps `schedule:` + tooling-error `exit 1` and its `on:` block never gains a `pull_request(_target)` trigger (scheduled notifier, must not become a required PR check). Protects the #250/#251 codification | #256 |
| `scanner/tests/test_ci_dependabot_config.py` | `.github/dependabot.yml` update coverage + alpine version freeze | all four ecosystems stay declared (`github-actions`, `npm`, `pip`, `docker`) so no surface silently stops getting update PRs (OWASP CICD-SEC-3); the `docker` `ignore` keeps the `alpine` `semver-minor`+`semver-major` freeze that holds alpine on its py3.12 minor line — loosening it would let Dependabot propose the bump that ships py3.14 and crashes prowler (pydantic v1, incident #220). Distinct from `test_ci_dependabot_automerge.py` (guards the *workflow*, not this *config*) | #256 |
| `scanner/tests/test_ci_prowler_version_pinned.py` | prowler install pin in `Dockerfile` | prowler is installed via an exact `==` pin through the `PROWLER_VERSION` build arg (version-shaped value), never a bare unpinned `pip install ... prowler`. An unpinned spec silently backtracks to ancient prowler 3.11.3 (pydantic v1) on a newer Python and crashes at runtime (incident #237). Pins the *pinning*, so a lockstep version bump stays green | #258 |
| `scanner/tests/test_ci_dockerfile_base_pinned.py` | Container base-image pins (`Dockerfile`, `Dockerfile.nginx`) | every `FROM` carries an `@sha256:` digest (OWASP A08 — no moving-tag swap); the prowler `Dockerfile` holds every `FROM alpine:` on the `alpine:3.20` (py3.12) minor line and resolves site-packages with the version-agnostic `find ... -name 'python3.*'` glob (no hardcoded `python3.<n>/site-packages`, #234). Complements `test_ci_dependabot_config.py` (config freeze policy) by locking the actual image | #258 |
| `scanner/tests/test_ci_npm_files.py` | npm package payload (`package.json` `files[]` allowlist) | `docs/` is NOT in `files[]` (it shipped ~38 MB of `.pptx` not used at runtime — incident #261); the six operator-only scripts keep their `!scripts/<name>` negations (cost-xlsx / license / PC-sheet / full-asset-sync / gsheet-auth×2 — else internal tooling publishes to the public registry); `scripts/` stays included (so the negations have effect) and `CHANGELOG.md` stays shipped. `.npmignore` cannot express these — paths under a `files[]` dir override it (confirmed via `npm publish --dry-run`) | #262 |
| `scanner/tests/test_ci_provenance_verify.py` | Published-package supply-chain monitor (`provenance-verify.yml`) | the workflow keeps a `schedule:` trigger (periodic check of the *published* artifact), keeps a `workflow_run` trigger on "Publish to npm" whose `types:` list still includes `completed` (verifies right after each release — the cadence that maps to when the artifact changes; a `workflow_run` key without `completed` would silently never fire), never gains a `pull_request(_target)` trigger (a zero-dep `npm audit signatures` adds no PR value and must not become a flaky required gate / write-token foot-gun), and still runs `npm audit signatures` (verifies npm registry signature + SLSA provenance, OWASP A08) | #263 |
| `scanner/tests/test_ci_injection_surface.py` | No GitHub Actions script-injection surface in any `.github/workflows/*.yml` | no documented-untrusted `${{ github.event.* }}` context (PR/issue/comment/review/discussion title·body, commit message, `head_ref`, `pages.*.page_name`, …) is interpolated DIRECTLY into a `run:` shell body — the OWASP CICD-SEC-4 / GitHub script-injection RCE class. Scans only `run:` bodies (inline + `\|`/`>` block scalars), threshold at the `run:` column so sibling `env:`/`with:`/`if:` keys aren't slurped; `env:`-block and expression-context (`if:`) interpolation and trusted contexts (`github.sha`, `needs.*`) are NOT flagged. Direction: presence-of-violation; mutation self-tests prove it fires on inline + block-scalar injection and stays quiet on the `env:` safe-fix. Incident: `npm-publish.yml` inline `VERSION=` (hardened #266); `og-meta-verify.yml` is `pull_request`+`pull-requests:write` | #270 |
| `scanner/tests/test_ci_npm_oidc_floor.py` | OIDC npm-CLI floor pin in `npm-publish.yml` + `provenance-verify.yml` | both workflows' `npm install -g npm` self-upgrade pins the trusted-publishing floor `npm@'>=11.5.1'` (version-shaped) and is NOT a bare `npm@latest` — OIDC `npm publish --provenance` / `npm audit signatures` break below npm 11.5.1, and Node 22 ships npm 10.x, so the floor must be a *visible* pin (Dependabot cannot track a runner binary installed by a shell command). Ratcheting the floor up stays green; reverting to `@latest` trips it (OWASP A08; SSDF PW.4) | #264 |
| `scanner/tests/test_ci_docker_image_size_gate.py` | Docker image-size cap in `lint.yml` (`dashboard-regression-check`) | the `max_mb=N` size gate is present, breaches the build (`size_mb -gt max_mb` → `exit 1`), and `N <= 600` MB — locking in the ~513 MB scanner image achieved by prowler-provider stripping (was 1.47 GB, cycle #217-#237, issue #11). Loosening the cap back toward the old 1.8 GB or re-adding a stripped ~700 MB provider would slip through; tightening DOWN stays green (CIS Docker Benchmark — minimal image surface). Comment-evasion-proof | #11 |
| `scanner/tests/test_ci_lighthouse_perf_gate.py` | Lighthouse Performance/SEO/A11y gate (`lighthouserc.json`, consumed by `lighthouse.yml` against live Pages) | each of `categories:{performance,seo,accessibility}` keeps an `error`-level floor `minScore >= 0.9` (demoting to `warn`/`off` or lowering the floor trips it; ratcheting UP stays green), and `collect.numberOfRuns >= 3` so lhci asserts on the MEDIAN run — reverting to a single run re-introduces the cold-vs-warm-CDN variance that would make the hard Performance gate flaky. Adds the Performance floor from issue #19 (live baseline 0.93 cold / 1.00 warm, 2026-06) | #19 |
| `scanner/tests/test_ci_plugin_skills_cli_parity.py` | Marketplace plugin skill ↔ CLI subcommand parity (`.claude-plugin/marketplace.json` ↔ `bin/claudesec-cli.sh`) | every `skills[].command` is `npx claudesec <sub>` where `<sub>` is a real `case` arm in the CLI — a skill pointing at a non-existent/typo'd subcommand would make that installed slash command silently fall through to usage for every user (the manifest and the CLI have no compile-time link); and the `{scan,prowler,compliance,dashboard,setup}` arms stay wired so a CLI refactor cannot silently drop a published surface. Adds the `/prowler` + `/compliance` commands from issue #20 | #20 |
| `scanner/tests/test_ci_lychee_config.py` | lychee link-check exclude allowlist single-source-of-truth (`lychee.toml` ↔ `lint.yml` `link-check`) | `lychee.toml` (undotted, auto-discoverable) exists and the dotted `.lychee.toml` does NOT (a dotted config is never auto-discovered, so it silently goes stale — the original drift); the `link-check` job wires `--config lychee.toml` and carries NO inline `--exclude`/`--exclude-path` flag (so the allowlist cannot drift back into a second copy); `lychee.toml`'s `exclude` includes the release-time `compare/` entry the inline list was missing (the CHANGELOG compare-URL 404 fix) and keeps `node_modules` in `exclude_path`; and `lychee.toml` stays in BOTH the `scanner` and `markdown` change-detection buckets of the `changes` job, so a `lychee.toml`-only PR still triggers this guard AND a live link-check (else the allowlist could change unvalidated at PR time). Comment-stripped + job-scoped; the `v0.23.0` binary pin is owned separately by `test_ci_gate_topology.py` (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_lychee_redirect_sweep.py` | Monthly `lychee-redirect-sweep.yml` stays a scheduled, notifier-only backstop that actually surfaces redirects | workflow exists; `on:` keeps `schedule:`/`cron:` + `workflow_dispatch` and has NO `pull_request` trigger (a broad external-URL fetch on every PR would flake and, once required, block merges — the notifier-only invariant); `permissions: issues: write` (self-healing tracking issue); the lychee run reuses `--config lychee.toml` (single-source excludes) and keeps BOTH teeth — `--max-redirects 0` (report 3xx instead of following to its 200) and strict `--accept '200..=299'` (widening toward the PR job's `100..=599` re-hides rot); `fail: false` (findings become an issue, not a red run); `lycheeVersion: v0.23.0` shared binary pin. Comment-stripped (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_provider_labels_sync.py` | Prowler provider label maps have a single source of truth (`scanner/lib/dashboard_providers.py` ↔ `scanner/lib/output.sh`) | the bash `case` in `output.sh` (`_prowler_dashboard_summary_provider_label`) has EXACTLY the same slug→label pairs as the canonical `PROVIDER_LABELS` — after the refactor consolidated four drifted inline Python dicts into `dashboard_providers.py`, the bash mirror is kept in place for perf (called in a loop) but must not drift; also asserts the shared constants stay complete and consistent (`PROVIDER_LABELS` 16 entries; `PROVIDER_LABELS_SHORT` differs from full ONLY by `kubernetes` → `K8s`, the intentional compact-table distinction; `PROVIDER_SUBTAB_MAP` 7 known keys; `PROWLER_SELECTABLE_ORDER` 7 known keys in the locked selector order). Parser ignores the `*)` default arm and has a mutation self-test | this PR |
| `scanner/tests/test_ci_diagram_gen_canonical_sync.py` | `scanner/lib/diagram-gen.py` single-sources security domains + compliance frameworks | diagram-gen imports `ARCH_DOMAINS` from `dashboard_arch` and `COMPLIANCE_FRAMEWORKS` from `dashboard_compliance`, has NO inline `ARCH_DOMAINS = [` reassignment and NO hand-rolled `frameworks = ["..."]` string list (it derives `frameworks = [f["name"] for f in COMPLIANCE_FRAMEWORKS]`); functional check asserts the loaded module's `ARCH_DOMAINS` IS the canonical object (imported, not copied) — the diagram previously drifted to a stale 6-domain / 6-framework mis-versioned subset (same bug-class as the removed `dashboard_compliance` inline `COMPLIANCE_CONTROL_MAP` fallback). Comment-stripped + mutation self-test (OWASP A08) | this PR |

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
covered by `test_ci_provenance_verify.py`).

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
