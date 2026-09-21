#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# SC2154 ($_cf_skip_reason, $_cf_query_skip_reason "referenced but not
# assigned") is disabled at the two use sites rather than here: they are
# assigned by scanner/checks/cicd/freshness.sh, which this file sources, and
# reading them from there is deliberate — comparing against the production
# string is what makes those assertions survive rewording while still failing
# when a skip is re-routed to a different reason.
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

# Titles AND reason/detail text are captured, not just IDs.
#
# WHY THE MESSAGE IS PART OF THE RECORD
# A bare `SKIP:CICD-010` expectation is satisfied by ANY skip of CICD-010, and
# this check has three different reasons to skip: preconditions unmet, no
# matching workflow, and — the one the 403 cases exist for — a failed query.
# Asserting only the verdict would let the query-failure branch be deleted
# outright while the suite stayed green, because the precondition branch emits
# the same `SKIP:CICD-010`. The same hole applies to `WARN`, where "never ran"
# is indistinguishable by verdict from any warn added later. So the reason
# travels with the result, and the assertions below discriminate on it.
RESULTS=()
pass()  { RESULTS+=("PASS:$1:$2"); }
fail()  { RESULTS+=("FAIL:$1:${3:-}:$2 || ${4:-}"); }
warn()  { RESULTS+=("WARN:$1:$2 || ${3:-}"); }
skip()  { RESULTS+=("SKIP:$1:$2 || ${3:-}"); }
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

# Asserts a result exists AND its message contains $4 — for the cases where a
# bare verdict does not identify which branch produced it.
#
# Prefer passing a PRODUCTION VARIABLE (`$_cf_query_skip_reason`) over a literal
# phrase. Comparing against the live string keeps the assertion immune to
# rewording — both sides change together — while still failing if the branch is
# swapped for a different reason, which is exactly the split needed here.
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

# The complement: a result of this type exists for this id, and it does NOT
# carry $4. Used to identify a branch by ELIMINATION — with three possible skip
# reasons, ruling out two names the third without hardcoding any of its prose.
assert_result_lacks() {
  local desc="$1" expected_type="$2" check_id="$3" needle="$4"
  local seen=false carried=false r
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}:"* ]]; then
      seen=true
      [[ "$r" == *"$needle"* ]] && carried=true
    fi
  done
  if $seen && ! $carried; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  elif ! $seen; then
    echo "  FAIL: $desc (no $expected_type:$check_id at all, got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  else
    echo "  FAIL: $desc (the $expected_type:$check_id carried '$needle')"; ((TEST_FAILED++))
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
# A SECOND scan workflow's history, so a fixture can hold two scan workflows in
# different states. Every broken-scan case used a single-workflow fixture, which
# pinned broken-detection only in the no-sibling case — and a fresh sibling is
# exactly what used to hide it. Only the two-workflow fixture sets this.
STUB_RUNS_SCAN2=""
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
        deploy.yml)           printf '%s' "$STUB_RUNS_DEPLOY" ;;
        release-drafter.yml)  printf '%s' "$STUB_RUNS_DEPLOY" ;;
        deploy-notify.yml)    printf '%s' "$STUB_RUNS_DEPLOY" ;;
        codeql.yml)           printf '%s' "$STUB_RUNS_SCAN" ;;
        trivy-monitor.yml)    printf '%s' "$STUB_RUNS_SCAN" ;;
        trivy-second.yml)     printf '%s' "$STUB_RUNS_SCAN2" ;;
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

# Fixture with TWO scan workflows, so one can be fresh while the other has only
# ever failed. `trivy-second.yml` sorts after `codeql.yml`, which is the order
# that used to make the broken one unreachable behind an early break.
mkdir -p "$tmpdir/twoscan/.github/workflows"
cp "$tmpdir/repo/.github/workflows/codeql.yml" "$tmpdir/twoscan/.github/workflows/codeql.yml"
cat > "$tmpdir/twoscan/.github/workflows/trivy-second.yml" <<'YML'
name: Trivy Second
on:
  schedule:
    - cron: '0 4 * * *'
jobs:
  scan:
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
# The PRECONDITION reason, not the query-failure one: no query was ever made.
# shellcheck disable=SC2154  # both are assigned by the sourced freshness.sh
assert_result_mentions "gh absent cites the precondition" "SKIP" "CICD-010" "$_cf_skip_reason"
# shellcheck disable=SC2154
assert_result_lacks "gh absent does not blame a failed query" "SKIP" "CICD-010" "$_cf_query_skip_reason"

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

# The reason-based assertions below compare against these production strings.
# An EMPTY one would make every `assert_result_mentions` trivially true (a
# substring test against "" matches anything), which is the same vacuity this
# whole section exists to remove — so their non-emptiness is asserted, once,
# rather than assumed.
echo "=== Discriminator strings are non-empty (guards the guards) ==="
for _v in _cf_skip_reason _cf_query_skip_reason; do
  if [[ -n "${!_v:-}" ]]; then
    echo "  PASS: \$$_v is populated"; ((TEST_PASSED++))
  else
    echo "  FAIL: \$$_v is empty — reason assertions would be vacuous"; ((TEST_FAILED++))
  fi
done

echo "=== CICD-010/011: no matching workflow -> skip ==="

STUB_ALERTS="0"
SCAN_DIR="$tmpdir/plain" run_check
assert_has_result "no deploy workflow -> skip CICD-010" "SKIP" "CICD-010"
assert_has_result "no scan workflow -> skip CICD-011" "SKIP" "CICD-011"
# Identify the branch by ELIMINATION: three skip reasons exist, so ruling out
# the other two pins this one without hardcoding its wording. Without this, the
# no-workflow branch could be deleted and the precondition skip would satisfy
# the two assertions above.
assert_result_lacks "no-deploy skip is not the precondition skip" "SKIP" "CICD-010" "$_cf_skip_reason"
assert_result_lacks "no-deploy skip is not the query-failure skip" "SKIP" "CICD-010" "$_cf_query_skip_reason"
assert_result_lacks "no-scan skip is not the precondition skip" "SKIP" "CICD-011" "$_cf_skip_reason"
assert_result_lacks "no-scan skip is not the query-failure skip" "SKIP" "CICD-011" "$_cf_query_skip_reason"

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

# ── ZERO RUNS vs ALL RUNS FAILED — two states, two verdicts ─────────────────
#
# These used to share one branch and one message, which read "no successful run
# exists, so scan freshness is unknown rather than bad". For a scanner that has
# failed every time that sentence is simply false: there is no shortage of
# evidence, the evidence is uniformly bad. It is also the scenario this file's
# header opens with. So the two are split, and both directions are pinned —
# each case asserts it is NOT the other one's verdict.

echo "=== CICD-011: zero runs -> WARN (genuinely unknown) ==="

STUB_RUNS_SCAN=""
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "no runs at all -> WARN CICD-011" "WARN" "CICD-011"
assert_result_mentions "the WARN says it has never RUN" "WARN" "CICD-011" "never run"
assert_result_lacks "the zero-run WARN does not claim staleness" "WARN" "CICD-011" "stale"
assert_no_result "zero runs is not a FAIL" "FAIL" "CICD-011"

echo "=== CICD-011: runs exist and all failed -> FAIL high (broken, not unknown) ==="

STUB_RUNS_SCAN=$(printf 'failure\t%s\nfailure\t%s\nfailure\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "all runs failed -> FAIL CICD-011" "FAIL" "CICD-011"
assert_fail_severity "a scanner that only fails is high severity" "CICD-011" "high"
assert_result_mentions "the FAIL says it has only ever failed" "FAIL" "CICD-011" "only ever failed"
# The discriminator that matters: `broken` must not be told as `unknown`.
assert_result_lacks "the broken FAIL does not call freshness unknown" "FAIL" "CICD-011" "unknown rather than bad"
assert_no_result "all-failed is not downgraded to WARN" "WARN" "CICD-011"
# ...and the failure count reaches the message, so the evidence is visible.
assert_result_mentions "the FAIL reports how many runs failed" "FAIL" "CICD-011" "3 failed"

echo "=== CICD-011: a FRESH sibling must not hide a scan that only ever failed ==="

# The regression this case exists for: `_cf_scan_failing` was consulted only
# when NO successful run existed anywhere, and the loop broke as soon as one
# fresh workflow was found. So a scan workflow that runs and never completes was
# reported only when it had no healthy sibling — the state this file's header
# calls the worst of the four was sort-order dependent, and CICD-011 said PASS.
# Two workflows: codeql.yml fresh, trivy-second.yml three failures and no
# success. Both facts must reach the output.
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
STUB_RUNS_SCAN2=$(printf 'failure\t%s\nfailure\t%s\nfailure\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
SCAN_DIR="$tmpdir/twoscan" run_check
assert_has_result "fresh + never-succeeded sibling -> WARN CICD-011" "WARN" "CICD-011"
assert_no_result "a fresh scan does exist, so this is not a silent PASS" "PASS" "CICD-011"
assert_result_mentions "the WARN names the dead workflow" "WARN" "CICD-011" "trivy-second.yml"
assert_result_mentions "the WARN still names the fresh one" "WARN" "CICD-011" "codeql.yml"
assert_result_mentions "the failure count reaches the message" "WARN" "CICD-011" "3 failed"
# CICD-012 must still see a live producer: freshness IS established, so the zero
# keeps its backing. Downgrading that too would over-correct.
assert_has_result "a live producer still backs the zero" "PASS" "CICD-012"

# The control for the case above: same fixture, sibling HEALTHY -> plain PASS.
# Without this, the WARN could be firing on the two-workflow fixture itself
# rather than on the failing history.
STUB_RUNS_SCAN2=$(printf 'success\t%s\n' "$FRESH")
SCAN_DIR="$tmpdir/twoscan" run_check
assert_has_result "two healthy scan workflows -> PASS CICD-011" "PASS" "CICD-011"
assert_no_result "no WARN when neither workflow is broken" "WARN" "CICD-011"
STUB_RUNS_SCAN2=""

echo "=== CICD-011: cancelled-only history -> WARN, not broken ==="

# `cancelled` is not bad news, and CICD-010 does not count it as a failure
# either. A history of nothing but cancellations is closer to no history at all.
STUB_RUNS_SCAN=$(printf 'cancelled\t%s\ncancelled\t%s\n' "$(iso_ago 1)" "$(iso_ago 2)")
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "cancelled-only -> WARN CICD-011" "WARN" "CICD-011"
assert_no_result "cancelled-only is not graded broken" "FAIL" "CICD-011"

# ── Path 4: zero alerts without established freshness -> CICD-012 fail ───────

echo "=== CICD-012: zero alerts + stale scan -> FAIL ==="

STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$STALE")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "zero alerts with a stale scan -> FAIL CICD-012" "FAIL" "CICD-012"
assert_fail_severity "CICD-012 unbacked zero is high severity" "CICD-012" "high"
# The `stale` branch specifically — this is the one verdict here that stayed a
# `high`, so it must not be reachable by the `unknown` story.
assert_result_mentions "CICD-012 FAIL cites staleness" "FAIL" "CICD-012" "stale"
assert_result_lacks "CICD-012 FAIL is not the unknown-evidence case" "FAIL" "CICD-012" "nothing known to have looked"

echo "=== CICD-012: zero alerts + BROKEN scan -> FAIL high (worse than stale) ==="

# A zero behind a producer that has never once completed is more misleading
# than one behind a producer that is merely late, so it is at least as severe.
STUB_RUNS_SCAN=$(printf 'failure\t%s\nfailure\t%s\n' "$(iso_ago 1)" "$(iso_ago 2)")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/repo" run_check
assert_has_result "zero alerts behind a broken scan -> FAIL CICD-012" "FAIL" "CICD-012"
assert_fail_severity "broken-producer zero is high severity" "CICD-012" "high"
assert_result_mentions "CICD-012 names the never-succeeded producer" "FAIL" "CICD-012" "never succeeded"
assert_no_result "a broken producer is not graded as merely unknown" "WARN" "CICD-012"
assert_no_result "a broken producer does not certify the zero" "PASS" "CICD-012"

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
# The `unknown` branch, not the `stale` one — those are different claims and
# only the second would justify a `high`.
assert_result_mentions "the WARN says nothing is known to have looked" "WARN" "CICD-012" "nothing known to have looked"
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
# Each warn has to tell the "nothing ran" story specifically. An empty history
# and a refused query both yield no data, and only the first is a warn — so the
# warns must not be reachable by the query-failure reason.
assert_result_mentions "fork CICD-010 warn cites never-succeeded" "WARN" "CICD-010" "never succeeded"
# A fork has ZERO runs, so CICD-011's zero-run branch is the correct one — not
# the `broken` branch, which requires observed failures.
assert_result_mentions "fork CICD-011 warn cites never having RUN" "WARN" "CICD-011" "never run"
assert_result_lacks "fork CICD-011 is not graded broken" "WARN" "CICD-011" "only ever failed"
assert_result_mentions "fork CICD-012 warn cites nothing having looked" "WARN" "CICD-012" "nothing known to have looked"
assert_no_result "fork produces no CICD-010 FAIL" "FAIL" "CICD-010"
assert_no_result "fork produces no CICD-011 FAIL" "FAIL" "CICD-011"
assert_no_result "fork produces no CICD-012 FAIL" "FAIL" "CICD-012"
# A fork asks the question successfully and gets "nothing"; it must not be
# reported as a question that could not be asked.
assert_no_result "fork does not skip CICD-010" "SKIP" "CICD-010"
assert_no_result "fork does not skip CICD-011" "SKIP" "CICD-011"

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
# THE LOAD-BEARING PAIR. Preconditions are satisfied in this scenario and the
# workflows exist, so the ONLY correct skip reason is the failed query. Asserted
# against the production string itself, so rewording the message keeps this
# green while re-routing the branch to any other reason turns it red. Without
# these two, deleting the query-failure branch entirely would leave the
# precondition skip satisfying both assertions above.
assert_result_mentions "403 CICD-010 skip cites the failed QUERY" "SKIP" "CICD-010" "$_cf_query_skip_reason"
assert_result_mentions "403 CICD-011 skip cites the failed QUERY" "SKIP" "CICD-011" "$_cf_query_skip_reason"
assert_result_lacks "403 CICD-010 skip is not the precondition skip" "SKIP" "CICD-010" "$_cf_skip_reason"
assert_result_lacks "403 CICD-011 skip is not the precondition skip" "SKIP" "CICD-011" "$_cf_skip_reason"
assert_no_result "403 is not reported as a never-run WARN on CICD-010" "WARN" "CICD-010"
assert_no_result "403 is not reported as a never-run WARN on CICD-011" "WARN" "CICD-011"
assert_no_result "403 does not fabricate a CICD-010 FAIL" "FAIL" "CICD-010"
# This scenario feeds FRESH successful histories, so a 403 that leaked through
# as an empty result would have produced a PASS — the silent direction.
assert_no_result "403 does not pass CICD-010 on unread history" "PASS" "CICD-010"
assert_no_result "403 does not pass CICD-011 on unread history" "PASS" "CICD-011"
# CICD-012's own query still succeeds here, but freshness is unknown, so the
# zero is reported as unexplained rather than graded.
assert_has_result "403 upstream -> CICD-012 WARN (freshness unknown)" "WARN" "CICD-012"
assert_result_mentions "403 upstream CICD-012 warn cites nothing having looked" "WARN" "CICD-012" "nothing known to have looked"
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
  trivy-monitor.yml codeql-watch.yml scan-and-notify.yml gitleaks-alert.yml \
  security-notify.yml deploy-notify.yml promote-and-notify.yml release-alert.yml \
  dependency-review.yml npm-audit.yml pip-audit.yml codeql-analysis.yml \
  trivy-scan.yml scale-test.yml scaffold.yml escalate-oncall.yml \
  shellcheck-lint.yml; do
  : > "$tmpdir/wfnames/.github/workflows/$_wf"
done
# Load the patterns and the matcher into this shell, then classify once.
#
# Three arguments, the same ones CICD-011 passes. Exclusions are no longer baked
# into the shared function: the monitor filter is only justified for the set
# whose loop it protects, so each call site names its own.
SCAN_DIR="$tmpdir/repo" run_check >/dev/null
WF_MATCHES=$(SCAN_DIR="$tmpdir/wfnames" _cicd_freshness_workflows \
  "$CICD_FRESHNESS_SCAN_PATTERN" \
  "$CICD_FRESHNESS_MONITOR_PATTERN" \
  "$CICD_FRESHNESS_SCANNER_TOOL_PATTERN")

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

# An explicit scanner token in the name OUTRANKS the monitor suffix. The bare
# filter discarded these, and `scan-and-notify.yml` is an ordinary real shape —
# a scan that reports its own result. `dast`/`sast` are deliberately NOT
# override tokens (they name scan families, not tools), which is what keeps
# `dast-freshness-watch.yml` — notification-only by its own header — excluded.
assert_classified "trivy-monitor is a scan (tool token wins)"   match trivy-monitor.yml
assert_classified "codeql-watch is a scan (tool token wins)"    match codeql-watch.yml
assert_classified "scan-and-notify is a scan (scan token wins)" match scan-and-notify.yml
assert_classified "gitleaks-alert is a scan (tool token wins)"  match gitleaks-alert.yml
# ...and the override does not re-admit the notification-only watcher.
assert_classified "dast-freshness-watch stays excluded"         no-match dast-freshness-watch.yml
assert_classified "security-notify stays excluded (no tool token)" no-match security-notify.yml

# ── Deploy-workflow classification ───────────────────────────────────────────
#
# Release AUTOMATION is not a release. A failing `release-drafter.yml` would
# otherwise make CICD-010 assert "the declared pipeline is intact but no longer
# ships" about a repo that ships fine — a false `high`.
#
# Recorded because it is the obvious first fix and it does NOT work:
# separator-adjacency (`(^|[-_.])release([-_.]|$)`) still matches both
# `release-drafter` and `release-please`, since `release` leads in each. The
# exclusion vocabulary is what discriminates, and this asserts that.

echo "=== Deploy-workflow classification ==="

assert_deploy() {
  local desc="$1" expect="$2" name="$3"
  local got=""
  [[ $'\n'"$DEPLOY_MATCHES"$'\n' == *$'\n'"$name"$'\n'* ]] && got="$name"
  if [[ "$expect" == "match" && -n "$got" ]] || [[ "$expect" == "no-match" && -z "$got" ]]; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expect for $name)"; ((TEST_FAILED++))
  fi
}

for _wf in release-drafter.yml release-please.yml publish-docs.yml \
           release-notes.yml changelog.yml deploy.yml npm-publish.yml \
           cd.yml release.yml rollout-prod.yml; do
  : > "$tmpdir/wfnames/.github/workflows/$_wf"
done
DEPLOY_MATCHES=$(SCAN_DIR="$tmpdir/wfnames" _cicd_freshness_workflows \
  "$CICD_FRESHNESS_DEPLOY_PATTERN" "$CICD_FRESHNESS_NONDEPLOY_PATTERN")

# Real deployment paths must survive.
assert_deploy "deploy.yml is a deploy path"      match    deploy.yml
assert_deploy "npm-publish.yml is a deploy path" match    npm-publish.yml
assert_deploy "release.yml is a deploy path"     match    release.yml
assert_deploy "cd.yml is a deploy path"          match    cd.yml
assert_deploy "rollout-prod.yml is a deploy path" match   rollout-prod.yml
# Release metadata automation is not.
assert_deploy "release-drafter is NOT a deploy path" no-match release-drafter.yml
assert_deploy "release-please is NOT a deploy path"  no-match release-please.yml
assert_deploy "release-notes is NOT a deploy path"   no-match release-notes.yml
assert_deploy "changelog is NOT a deploy path"       no-match changelog.yml
assert_deploy "publish-docs is NOT a deploy path"    no-match publish-docs.yml

# The MONITOR filter must not reach this set. It lived inside the shared matcher
# and so narrowed both, which deleted these three from CICD-010 — the precise
# "silently drop a real deployment path" outcome the file argues against. A
# deployment that notifies on completion is still a deployment.
assert_deploy "deploy-notify is a deploy path"       match    deploy-notify.yml
assert_deploy "promote-and-notify is a deploy path"  match    promote-and-notify.yml
assert_deploy "release-alert is a deploy path"       match    release-alert.yml

# ── The exclusions are actually WIRED UP, not merely correct ─────────────────
#
# The assertions above call `_cicd_freshness_workflows` directly and pass both
# patterns themselves, so they prove the MATCHER works — and prove nothing
# about whether CICD-010 hands it the exclusion. Measured: dropping
# `$CICD_FRESHNESS_NONDEPLOY_PATTERN` from the production call site left every
# assertion above green. That is the vacuity this repo's guard audit keeps
# finding, so the wiring gets a behavioural case that goes through the check.
#
# A repo whose only deploy-shaped workflow is `release-drafter.yml`, with a
# history of failures piling up after a success: wired correctly the workflow is
# excluded and CICD-010 skips; unwired it becomes a `high` claiming the repo can
# no longer ship.

echo "=== Deploy exclusions are wired into CICD-010, not just into the matcher ==="

mkdir -p "$tmpdir/drafteronly/.github/workflows"
cat > "$tmpdir/drafteronly/.github/workflows/release-drafter.yml" <<'YML'
name: Release Drafter
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  draft:
    runs-on: ubuntu-latest
    steps:
      - run: echo drafting notes
YML
STUB_RUNS_RC=0
STUB_RUNS_DEPLOY=$(printf 'failure\t%s\nfailure\t%s\nsuccess\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
STUB_RUNS_SCAN=""
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/drafteronly" run_check
assert_has_result "drafter-only repo -> CICD-010 skips" "SKIP" "CICD-010"
assert_result_lacks "that skip is the no-workflow one, not the precondition" "SKIP" "CICD-010" "$_cf_skip_reason"
assert_result_lacks "that skip is the no-workflow one, not a query failure" "SKIP" "CICD-010" "$_cf_query_skip_reason"
assert_no_result "a failing release-drafter is not a broken deploy path" "FAIL" "CICD-010"
assert_no_result "a failing release-drafter is not an unproven deploy path" "WARN" "CICD-010"

# ── ...and the OTHER direction: no exclusion the deploy set must not have ─────
#
# The case above only catches an exclusion being REMOVED. Its fixture's single
# workflow is `release-drafter.yml`, which is excluded under either wiring, so
# it cannot reveal an exclusion being ADDED. Measured on this tree: appending
# `|$CICD_FRESHNESS_MONITOR_PATTERN` to CICD-010's exclusion argument lands,
# parses, and leaves all 136 assertions green.
#
# That added direction is the regression FIX-MONITOR-SCOPE exists to prevent —
# someone restoring the monitor filter to the shared path, or bolting it onto
# the deploy call "for consistency". A deployment that notifies on completion is
# still a deployment, so a repo whose only deploy path is `deploy-notify.yml`
# must be JUDGED: wired correctly its accumulating failures are a `high`; with
# the monitor filter applied to deploy it vanishes and CICD-010 skips.
#
# Separate fixture rather than an edit to the one above — each direction needs a
# repo shape that only it can distinguish.

echo "=== No monitor filter on the deploy set — a notifying deploy is still judged ==="

mkdir -p "$tmpdir/notifyonly/.github/workflows"
cat > "$tmpdir/notifyonly/.github/workflows/deploy-notify.yml" <<'YML'
name: Deploy and notify
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo shipping
      - run: echo posting to chat
YML
STUB_RUNS_RC=0
STUB_RUNS_DEPLOY=$(printf 'failure\t%s\nfailure\t%s\nsuccess\t%s\n' \
  "$(iso_ago 1)" "$(iso_ago 2)" "$(iso_ago 3)")
STUB_RUNS_SCAN=""
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/notifyonly" run_check
assert_has_result "notify-suffixed deploy is judged -> FAIL CICD-010" "FAIL" "CICD-010"
assert_fail_severity "and it is high severity" "CICD-010" "high"
# Pin it to THIS workflow and THIS count, so the verdict cannot be satisfied by
# some other deploy match or by the counter being broken.
assert_result_mentions "the FAIL names deploy-notify.yml" "FAIL" "CICD-010" "deploy-notify.yml"
assert_result_mentions "the FAIL reports the accumulated failures" "FAIL" "CICD-010" "2 failed since last success"
# The mutation's actual signature: the workflow disappears and CICD-010 skips.
assert_no_result "a notifying deploy is not excluded into a skip" "SKIP" "CICD-010"
assert_no_result "nor left unproven" "WARN" "CICD-010"
# This fixture has no scan workflow, so CICD-011/012 must not be contributing
# findings that could be mistaken for the verdict under test.
assert_has_result "no scan workflow here -> CICD-011 skips" "SKIP" "CICD-011"
assert_no_result "CICD-011 raises nothing in this fixture" "FAIL" "CICD-011"
assert_no_result "CICD-012 raises nothing in this fixture" "FAIL" "CICD-012"

# ── The SCAN exclusions are wired into CICD-011 too ──────────────────────────
#
# Same reasoning as above, other side. `assert_classified` passes the exclusion
# and override itself, so it proves the matcher and not the call site. A repo
# whose only scan-shaped workflow is the notification-only watcher must find no
# scan at all; unwired, that watcher's fresh success would PASS CICD-011 and
# then certify CICD-012's zero — the original defect, restored silently.

echo "=== Scan exclusions are wired into CICD-011, not just into the matcher ==="

mkdir -p "$tmpdir/watchonly/.github/workflows"
cat > "$tmpdir/watchonly/.github/workflows/dast-freshness-watch.yml" <<'YML'
name: DAST Freshness Watch
on:
  schedule:
    - cron: '0 4 * * *'
permissions:
  contents: read
jobs:
  notify:
    runs-on: ubuntu-latest
    steps:
      - run: echo NOTIFICATION-ONLY, runs no scan
YML
STUB_RUNS_RC=0
STUB_RUNS_DEPLOY=""
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/watchonly" run_check
assert_has_result "watcher-only repo -> CICD-011 skips" "SKIP" "CICD-011"
assert_result_lacks "that skip is the no-workflow one, not the precondition" "SKIP" "CICD-011" "$_cf_skip_reason"
assert_result_lacks "that skip is the no-workflow one, not a query failure" "SKIP" "CICD-011" "$_cf_query_skip_reason"
assert_no_result "a notification-only watcher cannot pass CICD-011" "PASS" "CICD-011"
assert_no_result "and therefore cannot certify CICD-012's zero" "PASS" "CICD-012"
assert_has_result "so CICD-012 reports the zero as unexplained" "WARN" "CICD-012"

# ── The scanner-token OVERRIDE is wired in too ───────────────────────────────
#
# The watcher case above is excluded whether or not the override is passed, so
# it cannot detect the override going missing. Measured: dropping the third
# argument from CICD-011's call site left all 132 other assertions green — the
# same hole as the deploy exclusion had, one layer down. A repo whose only scan
# is `trivy-monitor.yml` must therefore PASS: the tool token in the name
# outranks the monitor suffix, and unwired it would be excluded and skip.

echo "=== The scanner-token override is wired into CICD-011 ==="

mkdir -p "$tmpdir/trivyonly/.github/workflows"
cat > "$tmpdir/trivyonly/.github/workflows/trivy-monitor.yml" <<'YML'
name: Trivy
on:
  schedule:
    - cron: '0 2 * * *'
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: trivy fs .
YML
STUB_RUNS_RC=0
STUB_RUNS_DEPLOY=""
STUB_RUNS_SCAN=$(printf 'success\t%s\n' "$FRESH")
STUB_ALERTS="0"
SCAN_DIR="$tmpdir/trivyonly" run_check
assert_has_result "trivy-monitor.yml certifies freshness -> PASS CICD-011" "PASS" "CICD-011"
assert_result_mentions "and the PASS names it" "PASS" "CICD-011" "trivy-monitor.yml"
assert_no_result "the tool token stops it being excluded as a monitor" "SKIP" "CICD-011"
assert_has_result "so its zero alert count is certified" "PASS" "CICD-012"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
