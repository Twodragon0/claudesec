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

## Catalog

| Guard | Protects | Key assertions | Landed |
|-------|----------|----------------|--------|
| `scanner/tests/test_ci_coverage_thresholds.py` | Coverage floors in `lint.yml` | pytest `--cov-fail-under >= 99`; bash kcov `threshold >= 90.0` | #200 |
| `scanner/tests/test_ci_gate_topology.py` | Enforcement topology of `lint.yml` | every `uses:` across all `.github/workflows/*.yml` is 40-hex SHA-pinned (OWASP A08); every job is in `lint-gate.needs` or a tiny documented allowlist | #201 (allowlist tightened in #203) |
| `scanner/tests/test_ci_security_gate.py` | `Security Scan Gate` + DAST signals | `security-scan-gate` keeps `name`, `if: always()`, `needs: ⊇ {changes, scan, lighthouse}`, pass-set `not in (success, skipped)`; `dast-baseline.yml` keeps its `pull_request` trigger; `dast-full-scan.yml` keeps its `schedule:` trigger | #205, #216 |
| `scanner/tests/test_ci_required_jobs_exist.py` | Existence of security/enforcement jobs in `lint.yml` | `{gitleaks, pii-check, dependency-review, workflow-fork-guard, scanner-unit-tests, scanner-shell-coverage}` are all present — deleting a whole job is a silent control loss the topology guard cannot see | #215 |
| `scanner/tests/test_ci_codeql_single_model.py` | Single CodeQL model (default setup only) | no workflow uses `github/codeql-action/init` or `/analyze` (a repo-level analysis would duplicate the default-setup model); `upload-sarif` is allowed (DAST SARIF upload, not analysis) | #215 |
| `scanner/tests/test_ci_npm_publish.py` | npm release supply-chain integrity (`npm-publish.yml`) | every `npm publish` carries `--provenance` (SLSA attestation); workflow-level `permissions:` stays `contents: read` (job-level `id-token: write` is not flagged) | #216 |
| `scanner/tests/test_ci_cross_os_non_required.py` | Cross-OS live-runner workflow stays non-required | `cross-os-checks.yml` exists and keeps `workflow_dispatch` (standalone informational lane); `lint.yml` references none of `{cross-os, live-os-checks, macos-latest, windows-latest}` — so the costly/flaky macOS+Windows runs never become a required merge gate | #228 |
| `scanner/tests/test_ci_net005_fail_escalation.py` | NET-005 SSH-open-to-world FAIL escalation (`network/tls.sh`) | NET-005 keeps `fail "NET-005" ... "critical"` and an ERE `(0\.0\.0\.0/0.*22\|port.*22.*0\.0\.0\.0/0)` alternation; no `\|` literal-pipe regression (which silently downgraded it to WARN, fixed in #224) | #228 |
| `scanner/tests/test_ci_dependabot_automerge.py` | Dependabot auto-arm safety (`dependabot-auto-merge.yml`, a `pull_request_target` write-token workflow) | keeps the fork guard (`actor==dependabot[bot]` AND `head.repo.full_name==github.repository`), the hard-exclude path arms (`Dockerfile*`/`.github`/`scanner`/`hooks`/`scripts`), the `semver-patch\|minor`-only update-type allowlist + `semver-major` exclude, the `pip\|docker\|github-actions` ecosystem allowlist, and `gh pr merge --auto`; forbids `--admin` (code-owner bypass) and the `pr review --approve` bot self-approve removed in #249 (OWASP CICD-SEC-1/-4) | #249, #250 |
| `scanner/tests/test_ci_codeowners_invariants.py` | `.github/CODEOWNERS` keeps security-sensitive paths code-owner gated | every required pattern (`*`, `.github/workflows/`, `.github/CODEOWNERS`, `hooks/`, `scanner/`, `scripts/`, `templates/`, `Dockerfile*`, `docker-compose*.yml`) is present AND has a non-empty `@owner`; the global `*` default must have an owner — else those paths merge with NO code-owner review (`require_code_owner_reviews=true` only fires on a matched, owned pattern) | #248 |
| `scanner/tests/test_ci_no_ere_pipe_regression.py` | No literal `\|` in an ERE context in `scanner/checks/**` + `scanner/lib/**` `.sh` | flags `\|` (literal-pipe, NOT alternation) inside `grep -[qnrlc]*E`, the `_code_grep`/`files_contain`/`file_contains`/`file_in` helpers, and bash `[[ =~ ]]` — the silent detection-breaking bug class fixed in #221/#223/#224; two intentional literals (`code/injection.sh` `\|safe`, `solutions.sh` `curl\|sh`) are allowlisted and asserted still present | #244, #246 |
| `scanner/tests/test_ci_prowler_provider_guard_ordering.py` | `_prowler_provider_available` precedes `_prowler_report` per provider (`scanner/checks/prowler/integration.sh`) | within each provider section of the Provider Scans block, `min(guard line) < min(report line)` — reordering would silently regress the #238 build-parity fix (lean image would emit a misleading auth warning instead of an accurate "not in this build" skip); promotes the shell-level `#241` assertion into the pytest CI gate | #242 |
| `scanner/tests/test_ci_catalog_completeness.py` | Completeness of this catalog vs the on-disk guard suite | every `scanner/tests/test_ci_*.py` file has its repo-relative path listed in this catalog (presence) — a new guard added without a Catalog row is silent documentation drift that makes the inventory understate coverage; the meta-guard documents itself so the invariant is uniform | #254 |
| `scanner/tests/test_ci_catalog_no_ghost_rows.py` | No ghost rows in this catalog vs the on-disk guard suite | every concrete `scanner/tests/test_ci_<name>.py` path cited in this catalog resolves to a real file (existence) — the reverse of the completeness guard: a renamed/deleted guard left in the table is a ghost row that makes the inventory overstate coverage. Together the two guards verify a 1:1 catalog↔suite mapping | #255 |
| `scanner/tests/test_ci_branch_protection_codified.py` | Codified branch protection (`scripts/sync-repo-protection.sh`) + its nightly notifier (`protection-drift-watch.yml`) | the desired state keeps `DESIRED_CONTEXTS=["Lint","Security Scan Gate"]` (both required checks), `DESIRED_ENFORCE_ADMINS="true"` (admins not exempt — no force-push to main), `strict`/`require_code_owner_reviews` true, `set -euo pipefail`, and the default-arm dry-run; the `DRIFT DETECTED` marker contract holds on both producer (script) and consumer (`grep -q`) sides; the watch keeps `schedule:` + tooling-error `exit 1` and its `on:` block never gains a `pull_request(_target)` trigger (scheduled notifier, must not become a required PR check). Protects the #250/#251 codification | #256 |
| `scanner/tests/test_ci_dependabot_config.py` | `.github/dependabot.yml` update coverage + alpine version freeze | all four ecosystems stay declared (`github-actions`, `npm`, `pip`, `docker`) so no surface silently stops getting update PRs (OWASP CICD-SEC-3); the `docker` `ignore` keeps the `alpine` `semver-minor`+`semver-major` freeze that holds alpine on its py3.12 minor line — loosening it would let Dependabot propose the bump that ships py3.14 and crashes prowler (pydantic v1, incident #220). Distinct from `test_ci_dependabot_automerge.py` (guards the *workflow*, not this *config*) | #256 |

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
worth a guard, to avoid sprawl). Reviewed 2026-06-19.

### Tier 2 — incident-backed, worth a guard next

| Candidate guard | Invariant | Incident / rationale |
|-----------------|-----------|----------------------|
| `test_ci_prowler_version_pinned.py` | `Dockerfile` keeps the **exact** `prowler==` pin (`PROWLER_VERSION`, currently `5.30.1`) — equality, not a floor | #237: an unpinned prowler drifted; prowler 3.11.3/pydantic-v1 cannot run on py3.13+, so an unpinned bump silently breaks `prowler -v` at runtime. Complements the alpine freeze (`test_ci_dependabot_config.py`) and the provider-ordering guard (`test_ci_prowler_provider_guard_ordering.py`). |
| `test_ci_dockerfile_base_pinned.py` | `Dockerfile`/`Dockerfile.nginx` keep their `alpine:3.20` (py3.12) base pin and stay version-agnostic | #233/#234/#220: a minor alpine bump ships py3.14 and crashes prowler. The dependabot guard locks the *freeze policy* in `dependabot.yml`; this would lock the *actual image* a manual edit could still bump. |

### Tier 3 — monitor only (no guard yet; would be sprawl)

- **Auxiliary scheduled workflows** — `prowler-python-watch.yml`,
  `dashboard-refresh.yml`, `og-meta-verify.yml`: none is a required status check
  and none runs on `pull_request_target` with a write token, so silent weakening
  does not disable a merge gate. Add a guard only if one later gains enforcement
  responsibility (becomes required, or gains a write-token PR trigger).
- **DAST trigger invariants** — `dast-baseline.yml` (`pull_request`) and
  `dast-full-scan.yml` (`schedule:`) triggers are already asserted by
  `test_ci_security_gate.py`; no separate guard needed.

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
