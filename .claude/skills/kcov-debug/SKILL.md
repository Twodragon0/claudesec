---
name: kcov-debug
description: Diagnose and fix ClaudeSec coverage failures — kcov bash coverage (scanner-shell-coverage job), pytest scanner/lib gate, hangs, "no coverage.json found", and floor-below-threshold errors. Use when a coverage CI job fails, hangs, reports 0%/missing coverage, or when raising a coverage floor.
user-invocable: true
---

# kcov / Coverage Debugging Playbook

Actionable consolidation of ClaudeSec's hard-won coverage knowledge (PRs #116–#193).
Use this when a coverage job fails, hangs, or you need to move a floor. Source of
truth is always the live `.github/workflows/lint.yml`; the numbers below were current
as of PR #193 (2026-06) — re-read the workflow before quoting a threshold.

## Two independent coverage gates

| Gate | Job | Tool | Floor | Path |
|------|-----|------|-------|------|
| Python | `scanner-unit-tests` | pytest + coverage | **99%** (`scanner/lib`) | `test-reports/coverage.xml` |
| Bash | `scanner-shell-coverage` | kcov v42 | **90%** | `kcov-out/merged/` (JSON located via `find`, path unstable — see §2) |

These are separate. A red "coverage" check is one or the other — read the job name first.

## Decision tree

```text
Coverage job is failing/slow?
├── Job HANGS or times out (>30s per test, minutes total)
│     → MISSING OFFLINE GUARD. See §1. Most common kcov failure.
├── "No coverage.json found under kcov-out/"
│     → MERGE-PATH DISCOVERY. See §2.
├── Reports 0% or wildly low bash coverage
│     → KCOV INSTRUMENTATION (wrong target / include-pattern). See §3.
├── "Bash coverage N% is below required threshold 90%"
│     → REAL REGRESSION or floor too high. See §4.
└── Python pytest gate below 99%
      → scanner/lib SUT coverage. See §5.
```

## §1 — Job hangs / per-test timeout (the #190 root cause)

**Symptom**: `scanner-shell-coverage` (or any test calling `generate_html_dashboard`)
runs for minutes; a test hits the `timeout 30` cap (`rc=124`, `::warning::... TIMED OUT`).

**Root cause** (confirmed in #190): un-gated **live GitHub API calls** in
`dashboard-gen.py`, NOT kcov ptrace/xtrace amplification. `test_output_coverage.sh`
alone calls `generate_html_dashboard` 24 times → 24× network round-trips. The earlier
"xtrace/ptrace overhead" hypothesis was wrong.

**Fix**: export `CLAUDESEC_DASHBOARD_OFFLINE=1`.
- CI: `scanner-shell-coverage` sets it at the **job level** (`lint.yml` job `env:`);
  `scanner-unit-tests` sets it on the **pytest step** only — its earlier bash
  steps don't call `generate_html_dashboard`, so they don't need it.
- New tests: self-export it too, belt-and-suspenders.
- Local repro: `CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_output_coverage.sh`
  drops from 120s+ → ~3.7s. Offline output is byte-identical for coverage purposes,
  so measured % is unchanged.

The `timeout 30` cap (tightened 120→30 in #193) is a **defensive backstop**, not a
budget — a test that needs >30s under kcov is a bug, almost always this one.

## §2 — "No coverage.json found" (kcov v42 merge path)

**Symptom**: job is green but prints `WARN: ... coverage.json not found`, or the gate
errors `No coverage.json found under kcov-out/`.

**Root cause**: kcov v42 `--merge kcov-out/merged kcov-out/*/` writes the merged JSON
into a **nested subdir** (observed: `kcov-merged/`, also seen `merged-kcov-output/`),
NOT directly at `kcov-out/merged/coverage.json`. A hard-coded path test silently
missed it (#119→#120), and `continue-on-error` hid the failure.

**Fix** (already in `lint.yml`): discover with `find`, never a fixed path:

```bash
cov_json=$(find kcov-out/merged -name coverage.json -print -quit 2>/dev/null || true)
[ -z "$cov_json" ] && cov_json=$(find kcov-out -name coverage.json -print -quit 2>/dev/null || true)
```

If you touch the merge/summary/gate steps, keep all three using the SAME find-based
discovery so they can't drift apart.

## §3 — 0% / wrong bash coverage (instrumentation)

Two classic kcov v42 traps (#118):

1. **Trace the script, not the interpreter**: use `kcov OUTDIR script.sh`, NOT
   `kcov OUTDIR bash script.sh` (the latter instruments the bash binary, yielding 0%).
2. **Include-pattern is substring matching on the literal sourced path**. Tests source
   via `$SCRIPT_DIR/../lib/checks.sh` (a dynamic path), so canonical
   `--include-path=scanner/lib` fails. Use filename-only:
   `--include-pattern=checks.sh,output.sh`.

Also: Ubuntu's apt kcov (v38 on Jammy) is broken for sourced files. The job builds
**kcov v42 from source** on `ubuntu-latest` (noble) and caches the binary.

## §4 — Bash coverage below 90% floor

The floor is a **one-way ratchet** — it only moves up, and only with observed headroom.
Lineage: 50%(#123) → 65%(#124) → 85% → **90%** (#171/#173/#174 lifted SUT 91.19%→92.36%).

- **Real regression**: a change removed exercised lib lines or added unexercised ones.
  Add/extend a `scanner/tests/test_*.sh` fixture that drives the new `lib/` code, then
  re-measure. Do NOT lower the floor to pass.
- **Raising the floor**: only after ≥2 consecutive clean `main` runs show headroom, and
  never above `(observed baseline − ~2–4pp)` buffer. Lift the *measured* baseline with
  new fixtures first; bump the `threshold` constant in the gate step second.

## §5 — Python pytest gate below 99%

`scanner-unit-tests` runs `pytest scanner/` with a 99% floor on `scanner/lib` (live
~99.12%, #165). Same discipline: add tests covering the uncovered lines (check
`test-reports/coverage.xml` / Codecov PR comment), don't relax the gate.

## Local verification (always offline)

```bash
# Python gate
CLAUDESEC_DASHBOARD_OFFLINE=1 pytest scanner/ --cov=scanner/lib --cov-report=term-missing

# A single shell test under kcov (build/install kcov v42 first if needed)
CLAUDESEC_DASHBOARD_OFFLINE=1 kcov --include-pattern=checks.sh,output.sh \
  kcov-out/one scanner/tests/test_checks_lib_direct.sh

# Merge + read the percentage
kcov --merge kcov-out/merged kcov-out/*/
cov_json=$(find kcov-out/merged -name coverage.json -print -quit)
python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['percent_covered'])" "$cov_json"
```

## Golden rules

1. **Offline first**: if a coverage job is slow, assume a missing
   `CLAUDESEC_DASHBOARD_OFFLINE=1` before anything else (§1).
2. **Find, don't hard-code** the merged `coverage.json` path (§2).
3. **Fix coverage by adding tests, not by lowering floors** (§4, §5).
4. **Re-read `lint.yml`** for current thresholds — numbers here drift; the workflow
   is canonical.

## References

- `.github/workflows/lint.yml` — `scanner-unit-tests` + `scanner-shell-coverage` jobs (canonical)
- `docs/guides/ci-coverage-journey.md` — full historical narrative (#103–#124)
- `docs/reports/session-report-2026-06-01-pm.md` — #190 kcov root-cause writeup
- Project memory: `project_kcov_v42_path`, `project_kcov_test_output_coverage_slow`,
  `project_scanner_lib_coverage_floor`, `project_ci_offline_mode`
