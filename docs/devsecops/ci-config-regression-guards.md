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
| `scanner/tests/test_ci_security_gate.py` | `Security Scan Gate` + DAST signal | `security-scan-gate` keeps `name`, `if: always()`, `needs: ⊇ {changes, scan, lighthouse}`, pass-set `not in (success, skipped)`; `dast-baseline.yml` keeps its `pull_request` trigger | #205 |
| `scanner/tests/test_ci_required_jobs_exist.py` | Existence of security/enforcement jobs in `lint.yml` | `{gitleaks, pii-check, dependency-review, workflow-fork-guard, scanner-unit-tests, scanner-shell-coverage}` are all present — deleting a whole job is a silent control loss the topology guard cannot see | #215 |
| `scanner/tests/test_ci_codeql_single_model.py` | Single CodeQL model (default setup only) | no workflow uses `github/codeql-action/init` or `/analyze` (a repo-level analysis would duplicate the default-setup model); `upload-sarif` is allowed (DAST SARIF upload, not analysis) | #215 |

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
