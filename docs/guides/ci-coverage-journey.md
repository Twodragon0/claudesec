---
title: "CI Coverage Journey (2026-04-17 → 04-20)"
description: Retrospective of the four-day CI modernization and coverage campaign that moved ClaudeSec from 64%/xmlrunner to 96%/pytest with Codecov and kcov bash coverage.
tags: [ci, coverage, pytest, kcov, codecov, retrospective]
---

# CI Coverage Journey (2026-04-17 → 04-20)

This retrospective documents the coverage campaign that modernized ClaudeSec's CI pipeline from `xmlrunner` to `pytest` and closed a significant coverage gap using Codecov and kcov bash instrumentation.

## Starting Point (2026-04-17)

On April 17, the scanner Python coverage sat at approximately 64% with 309 tests passing in CI. The root cause was a silent limitation in the test framework: `python3 -m xmlrunner discover` only collected `unittest.TestCase` subclasses and skipped approximately 400 module-level `def test_*()` functions entirely—a hard limit that went unnoticed until coverage analysis revealed the gap.

## Python Coverage Campaign

Seven PRs modernized Python coverage in sequence:

### #103 — Network builders extraction + diagram-gen

- Extracted network builder utilities into a separate module
- Increased `diagram-gen.py` coverage from 25% → 93%

### #104 — dashboard_data_loader.py

- Built out unit tests for data loading pipeline
- Coverage: 57% → 94%

### #105 — dashboard_html_builders.py + gitignore

- Comprehensive HTML builder test suite
- Coverage: 64% → 99%
- Added `.gitignore` entry for Notion sync script

### #106 — dashboard_mapping, html_helpers, audit-points-scan

- `dashboard_mapping`: 100% coverage
- `html_helpers`: 98% coverage
- `audit_points_scan`: 91% coverage

### #107 — dashboard-gen.py

- Main dashboard generator test suite
- Coverage: 70% → 99%

### #108 — dashboard_auth.py, zscaler-api.py, dashboard_template.py

- `dashboard_auth.py`: 100% coverage
- `zscaler-api.py`: 96% coverage (used `sys.modules` stub for `requests` in tests)
- `dashboard_template.py`: 98% coverage
- Fixed nmap IP fixture using RFC 5737 documentation IP range

## CI Pipeline Modernization

### #109 — Switch to pytest

`xmlrunner discover` collected only 619 tests (unittest.TestCase subclasses), while `pytest` collected 1017 + 205 subtests—a 64% increase in test discovery. This switch enabled accurate coverage measurement.

Changes:

- Replaced `python3 -m xmlrunner discover` with `pytest`
- Added `pytest`, `pytest-cov`, `requests`, `Pillow` to `requirements-ci.txt`
- Implemented 90% coverage gate in CI

### #110 — Raise gate to 95%

- Coverage gate raised to 95% (minimum acceptable coverage)
- Dropped `unittest-xml-reporting` from CI dependencies

### #112 — Docstring cleanup

- Updated test docstrings to reflect pytest-centric conventions (removed xmlrunner-specific wording)

## External Coverage Reporting & Bash Coverage

### #113 — Codecov integration + kcov shell tests

- Added Codecov upload step to CI
- Introduced `kcov` job for shell script coverage (informational)

### #115 — Codecov badge + codecov.yml policy

- Added Codecov badge to README
- Created `codecov.yml` with project target 95%, patch target 90%

### #116, #117 — kcov coverage attempts

Two attempts to fix 0% bash coverage:

- Adjusted `--include-pattern` and `--include-path` flags
- Issue: kcov v38 (Ubuntu Jammy default) has broken sourced-file instrumentation

### #118 — kcov v42 from source + real fixes

Built kcov v42 from source on `ubuntu-latest` and fixed two instrumentation bugs:

1. **Include-pattern for sourced files**: Switched from `--include-path=scanner/lib` to `--include-pattern=checks.sh,output.sh`. Because test scripts source via `$SCRIPT_DIR/../lib/checks.sh`, canonical-path patterns fail; filename-only substring matching works.

2. **Invoke kcov correctly**: Changed from `kcov OUTDIR bash script.sh` (traces the bash binary) to `kcov OUTDIR script.sh` (traces script lines directly).

Result: First real bash coverage—**37.05%** (555/1498 lines).

## Lessons: Closing the 95/37 Gap

1. **Verify discovery**: Always confirm the CI runner actually executes the tests you wrote locally. `xmlrunner discover` silently dropped 40% of tests.

2. **Trace the target**: For tools with native-code wrapping (kcov), verify whether you're instrumenting the interpreter (`bash script.sh`) or the script itself (`script.sh`).

3. **Pattern matching semantics**: kcov include-pattern uses substring matching against the literal sourced path. When `source $SCRIPT_DIR/../lib/checks.sh` resolves to a dynamic path, use filename-only patterns.

4. **Build from source**: Ubuntu Jammy's apt kcov (v38) is broken for sourced-file instrumentation. Build ≥v40 from source on `ubuntu-latest` CI images.

## Metrics Snapshot

| Metric | 2026-04-17 start | 2026-04-20 end |
|---|---|---|
| PRs merged | — | 15 |
| Tests running (CI) | 619 (xmlrunner) | 1017 + 205 subtests (pytest) |
| scanner/lib Python coverage | 64% | 96% |
| Python CI coverage gate | none | 95% |
| scanner/lib bash coverage | unmeasured | 37% |
| Codecov integration | none | badge + PR comments |

## Path-discovery bug in kcov v42 merge output (2026-04)

After kcov v42 landed in PR #118, the `scanner-shell-coverage` job silently stopped reporting any bash coverage percentage. The root cause was a path assumption baked into the `Print bash coverage summary` step: it tested for `kcov-out/merged/coverage.json`, but kcov v42's `--merge` writes the merged result into a nested subdirectory directly under the merge target — observed names include `kcov-merged/` and `merged-kcov-output/` — rather than directly under `kcov-out/merged/`. Because `continue-on-error: true` was set on the job, the resulting `WARN: kcov merged coverage.json not found` message produced no visible CI failure and every run appeared green. The actual bash coverage baseline has therefore never been printed, making the "~60%+" figure from the PR #119 commit message a test-count extrapolation, not a measured kcov percentage.

PR #120 (`ci/promote-scanner-shell-coverage`) fixes discovery only:

- Replaces the hard-coded `[ -f kcov-out/merged/coverage.json ]` test with `find kcov-out/merged -name coverage.json -print -quit` plus a broader fallback search.
- Prints the first log line of the form `Bash coverage (merged): <N>%` so the real baseline can be read from the run log after the PR merges to main.
- Does NOT enforce a coverage threshold — that gate will be added in a follow-up PR once the baseline is established.
- Does NOT remove `continue-on-error: true` — the job remains non-blocking until a stable threshold is confirmed.

## Ratchet progress (2026-04)

A "ratchet" here means a one-way gate: the enforced coverage floor only moves up, never down, and each step requires observed headroom before it is approved. The floor stops near 72% rather than chasing the raw observed baseline because the observed numbers include test paths that are not yet stable fixtures; the policy cap of (observed baseline - 4pt) preserves a buffer so that normal CI variance does not trigger a gate failure. Any increase beyond that buffer requires first writing new fixture work to lift the measured baseline itself.

### Ratchet steps

| Step | Floor change | PR | Merged | Status |
|------|-------------|----|--------|--------|
| 0 — initial gate | none → 50% | #123 (`ac5a985`) | 2026-04-21 | done |
| 1 — first raise | 50% → 65% | #124 (`e43603b`) | 2026-04-22 | done |
| 2 — second raise | 65% → 70% | TBD | — | planned |
| 3 — third raise | 70% → 72% | TBD | — | planned |

### Observed baselines

| Date | Run ID | SHA / context | Coverage |
|------|--------|---------------|----------|
| 2026-04-21 | 24700540488 | after #120 path fix | 71.93% |
| 2026-04-21 | 24701523866 | after #121 fixture tests + #123 gate | 76.38% |

### Unlock conditions

- **Step 2 (65% → 70%)**: 2 consecutive clean `main` runs with coverage >= 73% observed while the floor sits at 65%.
- **Step 3 (70% → 72%)**: 2 consecutive clean `main` runs with coverage >= 75% observed while the floor sits at 70%.
- **Stop condition**: do not ratchet above (observed baseline - 4pt) without first lifting coverage via new fixture work.

### Per-step policy

- One threshold number change per PR; do not bundle multiple floor changes.
- Dry-run the enforce step locally before pushing: set `percent_covered = <new floor - 0.01>` (expect fail) then `percent_covered = <new floor>` (expect pass).
- If a ratchet PR fails CI on `main` after merge, revert the PR — do not patch forward within the same ratchet step.

## Session retrospective (2026-04-21 -> 2026-04-22)

### The seven-PR chain

| PR | SHA | Date | Purpose |
|----|-----|------|---------|
| #120 | `e12047a` | 2026-04-21 | kcov v42 path-discovery fix (find-based lookup) |
| #121 | `30f2733` | 2026-04-21 | 55 fixture assertions for `generate_html_dashboard` (36) + `_prowler_dashboard_summary` (19) |
| #123 | `ac5a985` | 2026-04-21 | 50% threshold gate (dropped continue-on-error, added to `lint-gate.needs`) |
| #122 | `5b0037d` | 2026-04-21 | Doc section on the kcov v42 path bug |
| #124 | `e43603b` | 2026-04-22 | Ratchet: 50% -> 65% |
| #125 | `6b442d9` | 2026-04-22 | Ratchet progress table doc |
| #126 | `1abb222` | 2026-04-22 | Ratchet: 65% -> 70% |

### Coverage evolution

Before #120 merged, bash coverage was unobservable. Every `scanner-shell-coverage` run silently hit the `WARN: kcov merged coverage.json not found` branch, masked entirely by `continue-on-error: true`. The "~60%+" figure in the #119 commit message was a test-count extrapolation, not a measured kcov percentage.

Once the path-discovery fix landed, four CI runs established the real baseline:

| Run ID | Context | Coverage |
|--------|---------|----------|
| 24700540488 | after #120 path fix | 71.93% |
| 24701523866 | after #121 fixture tests + #123 gate | 76.38% |
| 24755252996 | on 65% floor after #124/#125 | 76.38% |
| 24756798072 | on 65% floor after #124/#125 | 76.38% |

Run 24700540488 is the first CI-visible bash coverage baseline in the repository's history. The two stable 76.38% reads on the 65% floor satisfied the Step 2 unlock condition, allowing #126 to raise the floor to 70% with 6.38 pt of headroom.

### Lessons learned

**Silent failure modes are expensive.** Setting `continue-on-error: true` on the `scanner-shell-coverage` job turned it into reporting theater for at least four merged PRs (#116-#119). The job continued to appear green while producing no coverage output whatsoever, and the degraded state went unnoticed until a deliberate audit traced the `WARN: kcov merged coverage.json not found` message back to the path assumption. Any job whose sole value is a visible metric must fail visibly when that metric cannot be computed.

**Reviewer verdicts must defer to CI when they conflict.** During review of PR #123, a code-reviewer agent issued a BLOCKING verdict claiming the Python-in-bash heredoc would produce an `IndentationError` due to YAML indentation. The actual CI run demonstrated the step executed correctly, printing `Bash coverage 71.93% meets threshold 50.0%. Bash coverage threshold met.` The root cause of the false verdict is that YAML `run: |` block-scalars strip common leading whitespace before the shell sees anything, making static-read indentation analysis unreliable for YAML-hosted heredocs. When a static analysis verdict conflicts with a passing CI run, the CI run is authoritative.

**Ratchet plans need evidence-based floors.** The original attempt that preceded #120 set a 50% coverage floor before any kcov percentage had been CI-verified. When the path-discovery bug surfaced, that version had to be abandoned and rewritten as discovery-only. The 50% gate was deferred to #123, applied only after run 24700540488 confirmed a 71.93% real baseline. Setting thresholds ahead of measurement inverts the ratchet contract: floors should be derived from observed numbers, not imposed in anticipation of them.

## References

- [pytest documentation](https://docs.pytest.org)
- [pytest-cov coverage plugin](https://pytest-cov.readthedocs.io)
- [Codecov coverage analysis](https://about.codecov.io)
- [kcov bash coverage instrumentation](https://github.com/SimonKagstrom/kcov)
- [NIST SP 800-53 SA-11: Developer Testing and Evaluation](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-11)
