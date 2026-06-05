# Testing Rules

## Minimum Test Coverage: 80%

Test Types (ALL required):
1. **Unit Tests** - Individual functions, utilities, components
2. **Integration Tests** - API endpoints, database operations
3. **E2E Tests** - Critical user flows

## Test-Driven Development

MANDATORY workflow:
1. Write test first (RED)
2. Run test - it should FAIL
3. Write minimal implementation (GREEN)
4. Run test - it should PASS
5. Refactor (IMPROVE)
6. Verify coverage (80%+)

## Edge Cases to Test

Every function must be tested with:
- [ ] Null/undefined inputs
- [ ] Empty arrays/strings
- [ ] Invalid types
- [ ] Boundary values (min/max)
- [ ] Error conditions

## Test Quality Checklist

- [ ] Tests are independent (no shared state)
- [ ] Test names describe behavior
- [ ] Mocks used for external dependencies
- [ ] Both happy path and error paths tested
- [ ] No flaky tests

## ClaudeSec-Specific Testing

### Test suites & commands

- **Scanner shell tests**: `bash scanner/tests/test_<name>.sh` (one file per case).
- **Scanner unit tests (Python)**: `pytest scanner/` — `scanner/lib/` has a 99%
  coverage floor (live ~99.12%) enforced in CI.
- **Shell coverage**: `kcov` aggregates coverage; the merged `coverage.json`
  lives in a nested subdir under `kcov-out/merged/` (locate via `find`, not a
  fixed path). Floor is **90%** (baseline ~92%), raised from 85 in #171/#173/#174.
  See the `kcov-debug` skill for the full playbook.
- **Docs**: `markdownlint "**/*.md"` and `lychee "**/*.md"` before any docs PR.

### Offline guard (REQUIRED)

Any test that calls `generate_html_dashboard` MUST export
`CLAUDESEC_DASHBOARD_OFFLINE=1`. Without it, `dashboard-gen.py` makes live GitHub
API calls and the test can hang for minutes (root cause of the kcov slowdown
fixed in #190). The kcov job sets this at the job level; new dashboard tests
should also self-export it.

```bash
CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_generate_html_dashboard.sh
```

### Mocking external dependencies

- Stub the GitHub API via the offline guard rather than hitting the network.
- Tests must be hermetic: no live API, no real repo paths, no machine-specific
  state. Use fixtures and placeholders, never real PII or company paths.

### What "E2E" means here

There is no web app to drive. End-to-end coverage = run the scanner against an
`examples/` fixture project and assert on the generated `scan-report.json` and
dashboard output, all offline.
