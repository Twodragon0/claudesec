#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/cicd/freshness.sh
#
# WHAT IS STUBBED, AND WHY IT HAS TO BE
# CICD-010/011/012 read GitHub Actions run history, so unlike the pipeline.sh
# checks they cannot be driven by fixture files alone. A real `gh` call would
# make the suite non-hermetic, network-dependent, and — worse for a freshness
# check — time-dependent on someone else's repo.
#
# So `gh` is a shell function here, the same technique
# `test_check_cloud_gcp_azure.sh` uses for `gcloud`. Two consequences worth
# stating rather than rediscovering:
#
#   1. `run_with_timeout` is stubbed to exec its command directly. The real one
#      prefers `timeout`/`gtimeout`, which are binaries and cannot exec a shell
#      function — the stubbed `gh` would never be reached.
#   2. Timestamps are generated RELATIVE TO NOW (`iso_ago`), never hardcoded.
#      A literal date would make the stale/fresh cases flip years later, which
#      is precisely the silent-decay failure this check exists to catch.
#
# The four paths the check is most likely to regress on are covered explicitly:
# CLI absent -> skip; failures accumulating after the last success -> fail;
# scan freshness exceeded -> fail; zero alerts without freshness -> fail.
#
# Run: bash scanner/tests/test_check_cicd_freshness.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
FORMAT="text"
QUIET=1
SEVERITY="low"

# Titles are captured, not just IDs: CICD-011's pass message has to name the
# workflow that certified freshness, and that is asserted below.
RESULTS=()
pass()  { RESULTS+=("PASS:$1:$2"); }
fail()  { RESULTS+=("FAIL:$1:${3:-}:$2"); }
warn()  { RESULTS+=("WARN:$1:$2"); }
skip()  { RESULTS+=("SKIP:$1:$2"); }
info()  { :; }

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false r
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}"* ]]; then
      found=true; break
    fi
  done
  if $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

assert_no_result() {
  local desc="$1" unexpected_type="$2" check_id="$3"
  local found=false r
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${unexpected_type}:${check_id}:"* ]]; then
      found=true; break
    fi
  done
  if ! $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (unexpected $unexpected_type:$check_id in: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

assert_fail_severity() {
  local desc="$1" check_id="$2" expected="$3"
  local found=false r
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "FAIL:${check_id}:${expected}:"* ]]; then
      found=true; break
    fi
  done
  if $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected FAIL:$check_id:$expected, got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

# Asserts a result exists AND its title contains $4 — for message content that
# carries meaning a bare verdict cannot, like which workflow certified freshness.
assert_result_mentions() {
  local desc="$1" expected_type="$2" check_id="$3" needle="$4"
  local found=false r
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}:"* && "$r" == *"$needle"* ]]; then
      found=true; break
    fi
  done
  if $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id mentioning '$needle', got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

# ISO-8601 UTC timestamp N days in the past. GNU date takes `-d @epoch`, BSD
# date takes `-r epoch`; try both so the suite runs on CI (Linux) and on macOS.
iso_ago() {
  local secs=$(( $(date -u +%s) - $1 * 86400 ))
  date -u -d "@${secs}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return 0
  date -u -r "${secs}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null && return 0
  return 1
}

# ── Stub state, reset per scenario ───────────────────────────────────────────

STUB_AUTH_RC=0
STUB_DEFAULT_BRANCH="main"
STUB_RUNS_DEPLOY=""
STUB_RUNS_SCAN=""
STUB_ALERTS="0"
# Non-zero makes `gh run list` fail the way a 403 rate limit or a revoked scope
# does: no output AND a non-zero exit. Telling that apart from an empty 200
# response is the whole point of the skip-vs-warn split, so it is stubbed
# separately rather than by blanking STUB_RUNS_* (which is the fork shape).
STUB_RUNS_RC=0

# Fake `gh`. Dispatches on the subcommand, and for `run list` on the exact
# fixture workflow file name so the deploy and scan histories stay independent.
gh() {
  local i j wf=""
  for ((i = 1; i <= $#; i++)); do
    if [[ "${!i}" == "--workflow" ]]; then
      j=$((i + 1)); wf="${!j}"
    fi
  done
  case "$1" in
    auth)
      return "$STUB_AUTH_RC"
      ;;
    run)
      if [[ "$STUB_RUNS_RC" -ne 0 ]]; then
        return "$STUB_RUNS_RC"
      fi
      case "$wf" in
        deploy.yml) printf '%s' "$STUB_RUNS_DEPLOY" ;;
        codeql.yml) printf '%s' "$STUB_RUNS_SCAN" ;;
        *)          printf '' ;;
      esac
      ;;
    api)
      case "$2" in
        *dependabot/alerts*) printf '%s' "$STUB_ALERTS" ;;
        *)                   printf '%s' "$STUB_DEFAULT_BRANCH" ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

# Source the check with `gh` reachable. `has_command` is stubbed true for gh so
# the scenario does not depend on whether the test host happens to have the CLI.
run_check() {
  RESULTS=()
  has_command()    { [[ "$1" == "gh" ]] || command -v "$1" &>/dev/null; }
  is_git_repo()    { return 0; }
  git_remote_url() { echo "https://github.com/example-org/example-repo.git"; }
  run_with_timeout() { shift; "$@"; }
  source "$CHECKS_DIR/cicd/freshness.sh"
  source "$LIB_DIR/checks.sh"
}

# Same, but with `gh` absent from the host.
run_check_no_gh() {
  RESULTS=()
  has_command()    { [[ "$1" != "gh" ]] && command -v "$1" &>/dev/null; }
  is_git_repo()    { return 0; }
  git_remote_url() { echo "https://github.com/example-org/example-repo.git"; }
  run_with_timeout() { shift; "$@"; }
  source "$CHECKS_DIR/cicd/freshness.sh"
  source "$LIB_DIR/checks.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Fixture project: one deployment-shaped workflow, one scan-shaped workflow.
mkdir -p "$tmpdir/repo/.github/workflows"
cat > "$tmpdir/repo/.github/workflows/deploy.yml" <<'YML'
name: Deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
YML
cat > "$tmpdir/repo/.github/workflows/codeql.yml" <<'YML'
name: CodeQL
on:
  schedule:
    - cron: '0 3 * * *'
permissions:
  security-events: write
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - run: echo scanning
YML

# Fixture project with no deployment and no scan workflow.
mkdir -p "$tmpdir/plain/.github/workflows"
cat > "$tmpdir/plain/.github/workflows/lint.yml" <<'YML'
name: Lint
on: push
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo linting
YML

FRESH=$(iso_ago 1)
STALE=$(iso_ago 30)

# ── Path 1: gh CLI absent -> every check skips ───────────────────────────────

echo "=== CICD-010/011/012: gh CLI absent -> skip ==="

STUB_RUNS_DEPLOY=""
STUB_RUNS_SCAN=""
SCAN_DIR="$tmpdir/repo" run_check_no_gh
assert_has_result "gh absent -> skip CICD-010" "SKIP" "CICD-010"
assert_has_result "gh absent -> skip CICD-011" "SKIP" "CICD-011"
assert_has_result "gh absent -> skip CICD-012" "SKIP" "CICD-012"

echo "=== CICD-010/011/012: gh present but logged out -> skip ==="

STUB_AUTH_RC=1
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "logged out -> skip CICD-010" "SKIP" "CICD-010"
assert_has_result "logged out -> skip CICD-011" "SKIP" "CICD-011"
assert_has_result "logged out -> skip CICD-012" "SKIP" "CICD-012"
STUB_AUTH_RC=0

echo "=== CICD-010/011: non-GitHub remote -> skip ==="

run_check_non_github() {
  RESULTS=()
  has_command()    { [[ "$1" == "gh" ]] || command -v "$1" &>/dev/null; }
  is_git_repo()    { return 0; }
  git_remote_url() { echo "https://gitlab.com/example-org/example-repo.git"; }
  run_with_timeout() { shift; "$@"; }
  source "$CHECKS_DIR/cicd/freshness.sh"
  source "$LIB_DIR/checks.sh"
}
SCAN_DIR="$tmpdir/repo" run_check_non_github
assert_has_result "non-GitHub remote -> skip CICD-010" "SKIP" "CICD-010"
assert_has_result "non-GitHub remote -> skip CICD-011" "SKIP" "CICD-011"

echo "=== CICD-010/011: no matching workflow -> skip ==="

STUB_ALERTS="0"
SCAN_DIR="$tmpdir/plain" run_check
assert_has_result "no deploy workflow -> skip CICD-010" "SKIP" "CICD-010"
assert_has_result "no scan workflow -> skip CICD-011" "SKIP" "CICD-011"

# ── Path 2: failures accumulating after the last success -> CICD-010 fail ────

echo "=== CICD-010: failures since last success -> FAIL ==="

# Newest first: two failures, then the last success underneath them.
STUB_RUNS_DEPLOY=$(printf 'failure\t%s\nfailure\t%s\nsuccess\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "failures after last success -> FAIL CICD-010" "FAIL" "CICD-010"
assert_fail_severity "CICD-010 failure is high severity" "CICD-010" "high"

echo "=== CICD-010: newest run is a success -> PASS ==="

STUB_RUNS_DEPLOY=$(printf 'success\t%s\nfailure\t%s\nsuccess\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "newest run succeeded -> PASS CICD-010" "PASS" "CICD-010"

echo "=== CICD-010: cancelled runs do not count as failures -> PASS ==="

STUB_RUNS_DEPLOY=$(printf 'cancelled\t%s\nsuccess\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "cancelled run is not a failure -> PASS CICD-010" "PASS" "CICD-010"

echo "=== CICD-010: never succeeded -> WARN ==="

STUB_RUNS_DEPLOY=$(printf 'failure\t%s\n' "$(iso_ago 1)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "no success ever -> WARN CICD-010" "WARN" "CICD-010"

# ── Path 3: scan freshness exceeded -> CICD-011 fail ─────────────────────────

echo "=== CICD-011: last success older than the threshold -> FAIL ==="

STUB_RUNS_DEPLOY=$(printf 'success\t%s\n' "$(iso_ago 1)")
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$STALE")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "30d-old scan -> FAIL CICD-011" "FAIL" "CICD-011"
assert_fail_severity "CICD-011 staleness is high severity" "CICD-011" "high"

echo "=== CICD-011: last success within the threshold -> PASS ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "1d-old scan -> PASS CICD-011" "PASS" "CICD-011"
# The early exit picks ONE workflow out of however many match, and CICD-011 and
# CICD-012 do not read the same producer. Naming the certifying workflow is the
# only thing that lets a reader notice when the wrong one certified.
assert_result_mentions "PASS message names the certifying workflow" "PASS" "CICD-011" "codeql.yml"

echo "=== CICD-011: threshold is configurable via env -> FAIL at 0 days ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$(iso_ago 2)")
CLAUDESEC_CICD_SCAN_MAX_AGE_DAYS=1 SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "2d-old scan under a 1d threshold -> FAIL CICD-011" "FAIL" "CICD-011"

echo "=== CICD-011: scan workflow that never succeeded -> WARN, not FAIL ==="

# Declared-but-never-run is an absence of evidence, not a defect, and CICD-005
# already fails `high` for missing scan tooling. A `fail` here double-counted.
STUB_RUNS_SCAN=$(printf 'failure\t%s\n' "$(iso_ago 1)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "scan never succeeded -> WARN CICD-011" "WARN" "CICD-011"
assert_no_result "scan never succeeded is not a FAIL" "FAIL" "CICD-011"

# ── Path 4: zero alerts without established freshness -> CICD-012 fail ───────

echo "=== CICD-012: zero alerts + stale scan -> FAIL ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$STALE")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "zero alerts with a stale scan -> FAIL CICD-012" "FAIL" "CICD-012"
assert_fail_severity "CICD-012 unbacked zero is high severity" "CICD-012" "high"

echo "=== CICD-012: zero alerts + fresh scan -> PASS ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "zero alerts backed by a fresh scan -> PASS CICD-012" "PASS" "CICD-012"

echo "=== CICD-012: non-zero alerts -> PASS (nothing absent to explain) ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$STALE")
STUB_ALERTS="1"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "non-zero alerts -> PASS CICD-012" "PASS" "CICD-012"

echo "=== CICD-012: alerts unreadable (no scope / disabled) -> SKIP ==="

STUB_ALERTS=""
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "alert query unavailable -> SKIP CICD-012" "SKIP" "CICD-012"

echo "=== CICD-012: skipped CICD-011 does not certify a zero, but does not damn it either ==="

# No scan workflow at all: CICD-011 skips, so freshness is NOT established. The
# zero must not be accepted as clean — but it must not be graded `high` either,
# because "nobody looked" and "the scan is broken" are different claims and only
# the second is a finding.
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/plain" run_check
assert_has_result "CICD-011 skipped -> skip CICD-011" "SKIP" "CICD-011"
assert_has_result "zero alerts with CICD-011 skipped -> WARN CICD-012" "WARN" "CICD-012"
assert_no_result "CICD-011 skipped does not produce a CICD-012 FAIL" "FAIL" "CICD-012"
assert_no_result "CICD-011 skipped does not certify the zero as PASS" "PASS" "CICD-012"

# ── Fork shape: Actions disabled, so run history is empty everywhere ─────────
#
# GitHub disables Actions on forks by default. This toolkit is meant to be run
# against other people's repositories, so the fork shape is a common input, not
# an edge case — and it must not manufacture `high` findings. An empty history
# is an honest "nothing ran", which is a WARN, never a FAIL.

echo "=== Fork (Actions disabled -> every history empty): no high findings ==="

STUB_RUNS_RC=0
STUB_RUNS_DEPLOY=""
STUB_RUNS_SCAN=""
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "fork: deploy never ran -> WARN CICD-010" "WARN" "CICD-010"
assert_has_result "fork: scan never ran -> WARN CICD-011" "WARN" "CICD-011"
assert_has_result "fork: zero alerts, nothing looked -> WARN CICD-012" "WARN" "CICD-012"
assert_no_result "fork produces no CICD-010 FAIL" "FAIL" "CICD-010"
assert_no_result "fork produces no CICD-011 FAIL" "FAIL" "CICD-011"
assert_no_result "fork produces no CICD-012 FAIL" "FAIL" "CICD-012"

# ── Query failure: a refused question is not an empty answer ─────────────────
#
# A 403 (rate limit, revoked scope) used to be swallowed by `|| echo ""`, which
# made it indistinguishable from "this workflow has no runs" — so a throttled
# scan would have been reported as a never-running one. A failed query is a SKIP.

echo "=== Query failure (403 / rate limit) -> SKIP, not WARN or FAIL ==="

STUB_RUNS_RC=1
STUB_RUNS_DEPLOY=$(printf 'success\t%s\n' "$FRESH")
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "run-list 403 -> SKIP CICD-010" "SKIP" "CICD-010"
assert_has_result "run-list 403 -> SKIP CICD-011" "SKIP" "CICD-011"
assert_no_result "403 is not reported as a never-run WARN on CICD-010" "WARN" "CICD-010"
assert_no_result "403 is not reported as a never-run WARN on CICD-011" "WARN" "CICD-011"
assert_no_result "403 does not fabricate a CICD-010 FAIL" "FAIL" "CICD-010"
# CICD-012's own query still succeeds here, but freshness is unknown, so the
# zero is reported as unexplained rather than graded.
assert_has_result "403 upstream -> CICD-012 WARN (freshness unknown)" "WARN" "CICD-012"
STUB_RUNS_RC=0

# ── Workflow classification: the early exit makes over-matching a FALSE NEGATIVE
#
# CICD-011 stops at the first workflow that proves freshness, and the glob is
# alphabetical, so one wrong match does not merely add noise — it SUPPRESSES the
# real answer. Measured on this repository with the original pattern: a bare
# `depend` matched `dependabot-auto-merge.yml`, which sorts before
# `security-scan.yml`, so a merge-automation bot certified "the security scan is
# fresh". A bare `audit` matched `guard-audit-reminder.yml` the same way.
#
# These names are this repository's real `.github/workflows/` contents plus the
# generic false-friends that broke other repos. Exercised through
# `_cicd_freshness_workflows` — the actual matcher — not a re-implementation.

echo "=== Scan-workflow classification (real workflow names) ==="

# Classify the fixture ONCE; every assertion reads that one result. Re-running
# the matcher per assertion is what made this suite exceed the 30s cap.
assert_classified() {
  local desc="$1" expect="$2" name="$3"
  local got=""
  [[ $'\n'"$WF_MATCHES"$'\n' == *$'\n'"$name"$'\n'* ]] && got="$name"
  if [[ "$expect" == "match" && -n "$got" ]] || [[ "$expect" == "no-match" && -z "$got" ]]; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expect for $name)"; ((TEST_FAILED++))
  fi
}

mkdir -p "$tmpdir/wfnames/.github/workflows"
for _wf in \
  cross-os-checks.yml dashboard-control-smoke.yml dashboard-refresh.yml \
  dast-baseline.yml dast-freshness-watch.yml dast-full-scan.yml \
  dependabot-auto-merge.yml guard-audit-reminder.yml lighthouse.yml lint.yml \
  lychee-redirect-sweep.yml npm-publish.yml og-meta-verify.yml \
  protection-drift-watch.yml provenance-verify.yml prowler-python-watch.yml \
  security-scan.yml \
  dependency-review.yml npm-audit.yml pip-audit.yml codeql-analysis.yml \
  trivy-scan.yml scale-test.yml scaffold.yml escalate-oncall.yml \
  shellcheck-lint.yml; do
  : > "$tmpdir/wfnames/.github/workflows/$_wf"
done
# Load the pattern and the matcher into this shell, then classify once.
SCAN_DIR="$tmpdir/repo" run_check >/dev/null
WF_MATCHES=$(SCAN_DIR="$tmpdir/wfnames" _cicd_freshness_workflows "$CICD_FRESHNESS_SCAN_PATTERN")

# Real scans must survive the narrowing.
assert_classified "security-scan.yml is a scan"        match    security-scan.yml
assert_classified "dast-full-scan.yml is a scan"       match    dast-full-scan.yml
assert_classified "dependency-review.yml is a scan"    match    dependency-review.yml
assert_classified "npm-audit.yml is a scan"            match    npm-audit.yml
assert_classified "pip-audit.yml is a scan"            match    pip-audit.yml
assert_classified "codeql-analysis.yml is a scan"      match    codeql-analysis.yml
assert_classified "trivy-scan.yml is a scan"           match    trivy-scan.yml

# The measured false friends. Each of these previously out-sorted a real scan.
assert_classified "dependabot-auto-merge is NOT a scan" no-match dependabot-auto-merge.yml
assert_classified "guard-audit-reminder is NOT a scan"  no-match guard-audit-reminder.yml
assert_classified "scale-test is NOT a scan"            no-match scale-test.yml
assert_classified "scaffold is NOT a scan"              no-match scaffold.yml
assert_classified "escalate-oncall is NOT a scan"       no-match escalate-oncall.yml
# A linter running constantly must not be allowed to certify scan freshness.
assert_classified "shellcheck-lint is NOT a scan"       no-match shellcheck-lint.yml
assert_classified "lint.yml is NOT a scan"              no-match lint.yml
assert_classified "lighthouse.yml is NOT a scan"        no-match lighthouse.yml

# Monitors. `dast-freshness-watch.yml` matched `dast` and sorts FIRST, so it
# won the early exit and certified freshness — while its own header declares it
# "NOTIFICATION-ONLY". A watcher looks fresh precisely when what it watches is
# dead, which is the worst possible certifier.
assert_classified "dast-freshness-watch is NOT a scan"  no-match dast-freshness-watch.yml
assert_classified "protection-drift-watch is NOT a scan" no-match protection-drift-watch.yml
assert_classified "prowler-python-watch is NOT a scan"  no-match prowler-python-watch.yml
# ...and the real scans it was shadowing are still found.
assert_classified "dast-full-scan survives the monitor filter" match dast-full-scan.yml
assert_classified "dast-baseline survives the monitor filter"  match dast-baseline.yml

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
