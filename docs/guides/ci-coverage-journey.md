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

## References

- [pytest documentation](https://docs.pytest.org)
- [pytest-cov coverage plugin](https://pytest-cov.readthedocs.io)
- [Codecov coverage analysis](https://about.codecov.io)
- [kcov bash coverage instrumentation](https://github.com/SimonKagstrom/kcov)
- [NIST SP 800-53 SA-11: Developer Testing and Evaluation](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-11)
