#!/usr/bin/env bash
# Executes `scripts/gh-merge-ready-pr.sh` against a stubbed `gh` to prove the
# stuck-check probe fires on the WAITING path and nowhere else.
#
# Why executed and not read: this repo has already learned (see the guard-parser
# history around #404) that a static read of a control-flow construct is weaker
# evidence than running it. The probe's whole value is being on exactly one of
# four branches of the wait loop, so each branch is driven here:
#
#   1. checks failing            -> probe runs (report only, exit 10 path)
#   2. checks failing, RERUN=1   -> probe runs and re-runs the workflow (exit 11)
#   3. checks failing, repeated  -> probe runs ONCE, not once per poll (cadence)
#   3b. same, with a fake clock  -> and probes AGAIN once the interval elapses
#   4. checks green, merge fails -> NO probe (merge path)
#   5. checks green, merge lags  -> NO probe (mergeability-lag retry path)
#   6. probe itself errors       -> logged, loop keeps waiting (advisory only)
#   7. workflow still running    -> probe runs and reports nothing stuck
#   8. PR already MERGED         -> NO probe
#   9. STUCK_MINUTES garbage     -> rejected before the loop
#
# Hermetic: a PATH-prepended recording `gh` stub answers every call (pr view /
# pr checks / pr merge / api check-runs / run list / run rerun). No network, no
# real repo, no `gh` auth. Timeouts are 1-3s so the whole file runs in seconds.
# Run: bash scanner/tests/test_gh_merge_ready_stuck_probe.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MERGE_SH="$REPO_ROOT/scripts/gh-merge-ready-pr.sh"
PROBE_LOG="Probing for check-runs stuck"

TEST_PASSED=0
TEST_FAILED=0

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected NOT to contain: $needle"
    echo "    actual: $haystack"
    ((TEST_FAILED++))
  fi
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((TEST_FAILED++))
  fi
}

if [[ ! -f "$MERGE_SH" ]]; then
  echo "FAIL: $MERGE_SH not found"
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STUB_BIN="$WORK/bin"
mkdir -p "$STUB_BIN"

# 30 minutes old, so the check-run crosses the default 20m threshold. Computed
# with python3 because `date -d`/`date -v` differ between GNU and BSD.
STARTED_AT="$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc) - d.timedelta(minutes=30)).isoformat())')"

cat >"$STUB_BIN/gh" <<'STUB'
#!/usr/bin/env bash
# Recording `gh` stub: appends its argv to $GH_LOG, answers from $STUB_* env.
set -uo pipefail
printf '%s\n' "$*" >>"$GH_LOG"
case "${1:-}" in
  pr)
    case "${2:-}" in
      view)
        if [[ "$*" == *headRefOid* ]]; then
          printf '{"headRefOid":"%s"}\n' "$(printf '0%.0s' {1..40})"
        else
          printf '{"state":"%s","mergeStateStatus":"BLOCKED","url":"https://github.com/o/r/pull/424","headRefName":"feat/x","baseRefName":"main"}\n' "${STUB_PR_STATE:-OPEN}"
        fi
        ;;
      checks) exit "${STUB_CHECKS_RC:-1}" ;;
      merge)
        [[ -n "${STUB_MERGE_OUT:-}" ]] && printf '%s\n' "$STUB_MERGE_OUT"
        exit "${STUB_MERGE_RC:-0}"
        ;;
      *) echo "stub gh: unexpected pr subcommand: $*" >&2; exit 99 ;;
    esac
    ;;
  api)
    if [[ "${STUB_API_RC:-0}" != "0" ]]; then
      echo "stub gh api failure" >&2
      exit "${STUB_API_RC:-0}"
    fi
    printf '[{"name":"Lint","status":"in_progress","started_at":"%s","details_url":"https://github.com/o/r/actions/runs/31504280368/job/93821831557"}]\n' "${STUB_STARTED_AT:-}"
    ;;
  run)
    case "${2:-}" in
      list)
        printf '[{"databaseId":31504280368,"status":"%s","conclusion":"success","workflowName":"Lint"}]\n' "${STUB_RUN_STATUS:-completed}"
        ;;
      rerun) echo "stub: re-run requested" ;;
      *) echo "stub gh: unexpected run subcommand: $*" >&2; exit 99 ;;
    esac
    ;;
  *) echo "stub gh: unexpected command: $*" >&2; exit 99 ;;
esac
STUB
chmod +x "$STUB_BIN/gh"

# Opt-in second PATH entry: a `date +%s` that jumps $DATE_STEP seconds per call,
# so the probe interval (600s at the default STUCK_MINUTES) can elapse inside a
# sub-second test. Everything else defers to the real date.
CLOCK_BIN="$WORK/clockbin"
mkdir -p "$CLOCK_BIN"
cat >"$CLOCK_BIN/date" <<'CLOCK'
#!/usr/bin/env bash
set -uo pipefail
if [[ "${1:-}" == "+%s" ]]; then
  now=$(( $(cat "$FAKE_CLOCK") + DATE_STEP ))
  printf '%s\n' "$now" >"$FAKE_CLOCK"
  printf '%s\n' "$now"
  exit 0
fi
exec /bin/date "$@"
CLOCK
chmod +x "$CLOCK_BIN/date"

OUT=""
GH_CALLS=""
RUN_RC=0

reset_env() {
  export STUB_PR_STATE="OPEN"
  export STUB_CHECKS_RC=1
  export STUB_MERGE_RC=0
  export STUB_MERGE_OUT=""
  export STUB_API_RC=0
  export STUB_RUN_STATUS="completed"
  export STUB_STARTED_AT="$STARTED_AT"
  export TIMEOUT_SECONDS=1
  export POLL_SECONDS=0.2
  export STUCK_MINUTES=20
  unset RERUN_STUCK
}

run_merge() {
  local label="$1" extra_path="${2:-}"
  export GH_LOG="$WORK/gh-$label.log"
  : >"$GH_LOG"
  PATH="${extra_path:+$extra_path:}$STUB_BIN:$PATH" \
    bash "$MERGE_SH" 424 >"$WORK/out-$label.log" 2>&1
  RUN_RC=$?
  OUT="$(cat "$WORK/out-$label.log")"
  GH_CALLS="$(cat "$GH_LOG")"
}

count_matches() {
  local needle="$1" haystack="$2"
  grep -c -- "$needle" <<<"$haystack" 2>/dev/null || true
}

echo "== 1. waiting path: stuck check-run detected, report only (default) =="
reset_env
run_merge waiting-report
assert_contains "probe ran on the waiting path" "$OUT" "$PROBE_LOG"
assert_contains "the stuck check-run is named" "$OUT" "STUCK     Lint"
assert_contains "report-only verdict is surfaced" "$OUT" "Stuck check-runs detected (report only)"
assert_contains "the escalation command is printed" "$OUT" "RERUN_STUCK=1"
assert_not_contains "nothing was re-run by default" "$GH_CALLS" "run rerun"
assert_eq "still exits 1 on timeout" "1" "$RUN_RC"
assert_contains "timeout message preserved" "$OUT" "Timed out waiting for PR #424"

echo "== 2. waiting path with RERUN_STUCK=1: the workflow run is re-run =="
reset_env
export RERUN_STUCK=1
run_merge waiting-rerun
assert_contains "probe ran" "$OUT" "$PROBE_LOG"
assert_contains "re-run was reported" "$OUT" "re-running run 31504280368"
assert_contains "caller logged the rerun verdict" "$OUT" "re-ran the owning workflow run(s)"
assert_contains "gh run rerun was invoked" "$GH_CALLS" "run rerun 31504280368"

echo "== 3. cadence: one probe per interval, not one per poll =="
reset_env
export TIMEOUT_SECONDS=2 POLL_SECONDS=0.2
run_merge cadence
polls="$(count_matches "not fully green yet" "$OUT")"
probes="$(count_matches "$PROBE_LOG" "$OUT")"
if [[ "$polls" -ge 3 ]]; then
  echo "  PASS: the loop polled repeatedly (polls=$polls)"
  ((TEST_PASSED++))
else
  echo "  FAIL: expected >=3 polls, got $polls"
  ((TEST_FAILED++))
fi
assert_eq "probed exactly once across those polls" "1" "$probes"

echo "== 3b. cadence: probes again once the interval has elapsed (fake clock) =="
# 301s per `date +%s` call, so the 600s interval (STUCK_MINUTES=20) elapses
# between polls. Without a time-based gate this would print once, and with no
# gate at all it would print on every poll — the assertion below is 2, which
# only a per-interval gate produces.
reset_env
export FAKE_CLOCK="$WORK/clock" DATE_STEP=301
echo 0 >"$FAKE_CLOCK"
export TIMEOUT_SECONDS=1500 POLL_SECONDS=0.1
run_merge cadence-fakeclock "$CLOCK_BIN"
polls="$(count_matches "not fully green yet" "$OUT")"
probes="$(count_matches "$PROBE_LOG" "$OUT")"
assert_eq "polled twice on the fake clock" "2" "$polls"
assert_eq "probed on both polls, 600s apart" "2" "$probes"
unset FAKE_CLOCK DATE_STEP

echo "== 4. merge path: checks green, hard merge failure, NO probe =="
reset_env
export STUB_CHECKS_RC=0 STUB_MERGE_RC=1 STUB_MERGE_OUT="GraphQL: Resource not accessible"
run_merge merge-path
assert_contains "merge was attempted" "$OUT" "Attempting merge"
assert_not_contains "probe did NOT run before the merge attempt" "$OUT" "$PROBE_LOG"
assert_not_contains "no check-runs API call at all" "$GH_CALLS" "check-runs"
assert_eq "merge exit status propagates" "1" "$RUN_RC"

echo "== 5. mergeability-lag retry path: NO probe =="
reset_env
export STUB_CHECKS_RC=0 STUB_MERGE_RC=1
export STUB_MERGE_OUT="Required status checks are expected."
run_merge lag-path
assert_contains "lag was detected" "$OUT" "GitHub mergeability lag detected"
assert_not_contains "probe did NOT run on the lag path" "$OUT" "$PROBE_LOG"
assert_not_contains "no check-runs API call at all" "$GH_CALLS" "check-runs"

echo "== 6. probe failure is advisory: the wait loop continues =="
reset_env
export STUB_API_RC=1 TIMEOUT_SECONDS=2 POLL_SECONDS=0.2
run_merge probe-fails
assert_contains "probe failure is logged" "$OUT" "Stuck-check probe failed (exit 1)"
assert_contains "the loop kept waiting" "$OUT" "Timed out waiting for PR #424"
polls="$(count_matches "not fully green yet" "$OUT")"
if [[ "$polls" -ge 2 ]]; then
  echo "  PASS: loop iterated after the probe failure (polls=$polls)"
  ((TEST_PASSED++))
else
  echo "  FAIL: probe failure aborted the loop (polls=$polls)"
  ((TEST_FAILED++))
fi

echo "== 7. workflow still running: probe reports nothing stuck =="
reset_env
export STUB_RUN_STATUS="in_progress"
run_merge nothing-stuck
assert_contains "probe ran" "$OUT" "$PROBE_LOG"
assert_contains "verdict is 'nothing stuck'" "$OUT" "No stuck check-runs detected."
assert_not_contains "no false STUCK claim" "$OUT" "STUCK     Lint"
assert_not_contains "nothing re-run" "$GH_CALLS" "run rerun"

echo "== 8. already merged: NO probe =="
reset_env
export STUB_PR_STATE="MERGED"
run_merge already-merged
assert_contains "merged short-circuit hit" "$OUT" "PR already merged."
assert_not_contains "probe did NOT run" "$OUT" "$PROBE_LOG"
assert_eq "exits 0" "0" "$RUN_RC"

echo "== 9. STUCK_MINUTES is validated before arithmetic evaluation =="
reset_env
# SC2016 is the point: `$(...)` must reach the script UNexpanded, so that the
# only thing that could expand it is `$(( ))` inside the script under test.
# shellcheck disable=SC2016
export STUCK_MINUTES='a[$(touch '"$WORK"'/pwned)]'
run_merge bad-stuck-minutes
assert_contains "garbage STUCK_MINUTES is rejected" "$OUT" "Invalid STUCK_MINUTES"
assert_eq "exits 1" "1" "$RUN_RC"
if [[ -e "$WORK/pwned" ]]; then
  echo "  FAIL: arithmetic evaluation executed the embedded command"
  ((TEST_FAILED++))
else
  echo "  PASS: no command substitution reached \$(( ))"
  ((TEST_PASSED++))
fi
assert_not_contains "loop never started" "$OUT" "$PROBE_LOG"

echo
echo "Passed: $TEST_PASSED"
echo "Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
