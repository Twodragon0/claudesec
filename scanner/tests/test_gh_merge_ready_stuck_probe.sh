#!/usr/bin/env bash
# Executes `scripts/gh-merge-ready-pr.sh` against a stubbed `gh` to prove the
# stuck-check probe fires on the WAITING path and nowhere else.
#
# Why executed and not read: this repo has already learned (see the guard-parser
# history around #404) that a static read of a control-flow construct is weaker
# evidence than running it. The probe's whole value is being on exactly one
# branch of the wait loop, so each branch is driven here:
#
#   1.  checks failing            -> probe runs (report only, exit 10 path)
#   1b. same, with the REAL date  -> control: the fake clock below hides nothing
#   2.  checks failing, RERUN=1   -> probe runs and re-runs the workflow (11)
#   3.  many polls, one interval  -> exactly ONE probe
#   3b. interval elapses          -> probes AGAIN (bounds the interval ABOVE)
#   3c. shorter gap than 600s     -> does NOT probe (bounds it BELOW; together
#                                    3b+3c pin the `/2` divisor, not just a range)
#   4.  checks green, merge OK    -> merges, NO probe (the primary success path)
#   4b. checks green, merge fails -> NO probe (merge path), status propagates
#   5.  checks green, merge lags  -> NO probe (mergeability-lag retry path)
#   6.  probe itself errors       -> logged, loop keeps waiting (advisory only)
#   7.  workflow still running    -> probe runs and reports nothing stuck
#   8.  PR already MERGED         -> NO probe
#   9.  arithmetic-eval payloads  -> rejected before the loop (STUCK_MINUTES and
#                                    TIMEOUT_SECONDS both reach `$(( ))`)
#   10. overflow-sized threshold  -> rejected (it would INVERT the cadence gate);
#                                    and the accepted bound is FORWARDED to the
#                                    detector, not just printed in the log
#   11. detector file missing     -> reported, loop keeps waiting
#
# DETERMINISM (this test feeds the required `Lint` check, so it may not be
# flaky). The wait loop's budget is wall-clock seconds, which makes every
# "did the loop run N times?" question a race on a loaded machine — and with
# TIMEOUT_SECONDS=1 the loop can legitimately run ZERO times, because
# `date +%s` has one-second granularity. Two earlier revisions of this file
# were flaky for exactly those two reasons (8/10 green under a 4-way CPU load).
#
# So: by default a PATH-prepended fake `date +%s` advances a fixed step per
# call. The script calls it once per loop-condition test and once per probe
# attempt, so the iteration count is arithmetic, not timing —
# TIMEOUT_SECONDS=9 at 1s/call is always exactly 4 polls. Assertions are
# relations (`probes == 1`, `probes < polls`), never "how many iterations fit
# in N seconds". Scenario 1b keeps the REAL `date` as a control and terminates
# on a stub state change instead of a timeout, so nothing here depends on the
# fake clock being faithful.
#
# Countable facts about this file, so no summary has to guess: 15 scenario
# blocks, 18 invocations of the script under test, 67 assertions. Nine of those
# scenarios reach their assertions only because the fake clock walks the deadline
# forward, so every invocation is wrapped in a portable watchdog — a harness
# change that decoupled termination from the clock would otherwise hang until the
# CI job's 6-hour default instead of failing.
#
# Hermetic: a PATH-prepended recording `gh` stub answers every call (pr view /
# pr checks / pr merge / api check-runs / run list / run rerun). No network, no
# real repo, no `gh` auth, no sleep longer than 0.05s.
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

# `actual >= floor`, reporting the observed value either way. Only ever used on
# counts the fake clock fixes by construction.
assert_ge() {
  local label="$1" floor="$2" actual="$3"
  if [[ "$actual" -ge "$floor" ]]; then
    echo "  PASS: $label (observed $actual)"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: >= $floor"
    echo "    actual:   $actual"
    ((TEST_FAILED++))
  fi
}

assert_lt() {
  local label="$1" smaller="$2" larger="$3"
  if [[ "$smaller" -lt "$larger" ]]; then
    echo "  PASS: $label ($smaller < $larger)"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $smaller < $larger"
    ((TEST_FAILED++))
  fi
}

assert_missing_file() {
  local label="$1" path="$2"
  if [[ -e "$path" ]]; then
    echo "  FAIL: $label"
    echo "    arithmetic evaluation executed the embedded command: $path exists"
    ((TEST_FAILED++))
  else
    echo "  PASS: $label"
    ((TEST_PASSED++))
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
          exit 0
        fi
        # Count state queries so a test can terminate the loop on a state
        # CHANGE (nth call reports MERGED) instead of on elapsed time.
        views=$(( $(cat "$STUB_VIEW_COUNT" 2>/dev/null || echo 0) + 1 ))
        printf '%s\n' "$views" >"$STUB_VIEW_COUNT"
        state="${STUB_PR_STATE:-OPEN}"
        if [[ -n "${STUB_MERGED_AFTER:-}" ]] && (( views >= STUB_MERGED_AFTER )); then
          state="MERGED"
        fi
        printf '{"state":"%s","mergeStateStatus":"BLOCKED","url":"https://github.com/o/r/pull/424","headRefName":"feat/x","baseRefName":"main"}\n' "$state"
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

# The deterministic clock. `+%s` jumps $DATE_STEP per call; anything else defers
# to the real date. Prepended to PATH for every scenario except the 1b control.
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

# Fake-clock base: large enough that the first probe's `now - 0` clears any
# interval, exactly as real epoch seconds (~1.7e9) do.
CLOCK_BASE=1000000000
# 1 fake second per call, 2 calls per iteration, deadline 9 -> 4 polls, always.
EXPECTED_POLLS=4

OUT=""
GH_CALLS=""
RUN_RC=0
SCRIPT_UNDER_TEST="$MERGE_SH"
CLOCK_PATH="$CLOCK_BIN"

reset_env() {
  export STUB_PR_STATE="OPEN"
  export STUB_CHECKS_RC=1
  export STUB_MERGE_RC=0
  export STUB_MERGE_OUT=""
  export STUB_API_RC=0
  export STUB_RUN_STATUS="completed"
  export STUB_STARTED_AT="$STARTED_AT"
  export STUB_MERGED_AFTER=""
  export STUB_VIEW_COUNT="$WORK/views"
  : >"$STUB_VIEW_COUNT"
  export TIMEOUT_SECONDS=9
  export POLL_SECONDS=0.05
  export STUCK_MINUTES=20
  unset RERUN_STUCK
  SCRIPT_UNDER_TEST="$MERGE_SH"
  CLOCK_PATH="$CLOCK_BIN"
  export FAKE_CLOCK="$WORK/clock" DATE_STEP=1
  echo "$CLOCK_BASE" >"$FAKE_CLOCK"
}

# Opt out of the fake clock (scenario 1b).
use_real_clock() {
  CLOCK_PATH=""
  unset FAKE_CLOCK DATE_STEP
}

# Per-invocation watchdog. `timeout(1)` is GNU coreutils: present on the CI
# runners (where an unbounded hang would burn the job's 6-hour default) and
# absent from a stock macOS, where a dev can just ^C. `gtimeout` covers macOS
# with coreutils installed. If NEITHER exists the runs are unwrapped — stated
# plainly rather than pretended away.
#
# Two hand-rolled alternatives were measured and rejected, both because this file
# also runs under kcov's 30s per-test cap: a `( sleep 60; kill )` subshell leaves
# the sleep orphaned when the subshell is killed (19 strays outlived one run, and
# kcov ptraces the whole tree, so they held it open -> `elapsed=30s rc=124`), and
# a 1s-polling killer cost ~1s of teardown per invocation (44s total).
WATCHDOG_SECONDS="${WATCHDOG_SECONDS:-60}"
WATCHDOG_BIN=""
for candidate in timeout gtimeout; do
  if command -v "$candidate" >/dev/null 2>&1; then
    WATCHDOG_BIN="$candidate"
    break
  fi
done
# `timeout` reports 124 when it fires.
WATCHDOG_RC=124

run_merge() {
  local label="$1"
  export GH_LOG="$WORK/gh-$label.log"
  : >"$GH_LOG"
  ${WATCHDOG_BIN:+$WATCHDOG_BIN $WATCHDOG_SECONDS} \
    env PATH="${CLOCK_PATH:+$CLOCK_PATH:}$STUB_BIN:$PATH" \
    bash "$SCRIPT_UNDER_TEST" 424 >"$WORK/out-$label.log" 2>&1
  RUN_RC=$?
  OUT="$(cat "$WORK/out-$label.log")"
  GH_CALLS="$(cat "$GH_LOG")"
  if [[ -n "$WATCHDOG_BIN" && "$RUN_RC" -eq "$WATCHDOG_RC" ]]; then
    echo "  FAIL: $label did not terminate within ${WATCHDOG_SECONDS}s (watchdog killed it)"
    ((TEST_FAILED++))
  fi
}

count_matches() {
  local needle="$1" haystack="$2"
  grep -c -- "$needle" <<<"$haystack" 2>/dev/null || true
}

# 1-based line number of the first match, or 0 when absent.
line_of() {
  local needle="$1" haystack="$2" n=""
  n="$(grep -n -- "$needle" <<<"$haystack" 2>/dev/null | head -1 | cut -d: -f1)"
  printf '%s' "${n:-0}"
}

# `first` must appear BEFORE `second`, and both must appear at all: a missing
# needle yields line 0, which would otherwise satisfy `0 < n` and make the
# ordering assertion vacuum-capable.
assert_line_order() {
  local label="$1" haystack="$2" first="$3" second="$4" a="" b=""
  a="$(line_of "$first" "$haystack")"
  b="$(line_of "$second" "$haystack")"
  if [[ "$a" -eq 0 || "$b" -eq 0 ]]; then
    echo "  FAIL: $label"
    echo "    a needle is missing entirely (first=$a second=$b) — ordering is undefined"
    ((TEST_FAILED++))
  elif [[ "$a" -lt "$b" ]]; then
    echo "  PASS: $label (line $a before line $b)"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected line($first)=$a < line($second)=$b"
    ((TEST_FAILED++))
  fi
}

echo "== 1. waiting path: stuck check-run detected, report only (default) =="
reset_env
run_merge waiting-report
assert_contains "probe ran on the waiting path" "$OUT" "$PROBE_LOG"
assert_contains "the stuck check-run is named" "$OUT" "STUCK     Lint"
assert_contains "report-only verdict is surfaced" "$OUT" "Stuck check-runs detected (report only)"
assert_contains "the escalation command is printed" "$OUT" "RERUN_STUCK=1"
assert_not_contains "nothing was re-run by default" "$GH_CALLS" "run rerun"
# The default only REPORTS: it still waits out the budget and exits 1.
assert_eq "still exits 1 at the end of the budget" "1" "$RUN_RC"
assert_contains "timeout message preserved" "$OUT" "Timed out waiting for PR #424"

echo "== 1b. control: the same detection with the REAL date binary =="
# No fake clock at all. Terminates on a stub state change (2nd `pr view` reports
# MERGED), not on elapsed time, so it is deterministic without one.
reset_env
use_real_clock
export STUB_MERGED_AFTER=2 TIMEOUT_SECONDS=60
run_merge real-clock-control
assert_contains "probe ran under the real clock" "$OUT" "$PROBE_LOG"
assert_contains "the stuck check-run is named" "$OUT" "STUCK     Lint"
assert_contains "the loop continued past the probe" "$OUT" "PR already merged."
assert_eq "exits 0" "0" "$RUN_RC"

echo "== 2. waiting path with RERUN_STUCK=1: the workflow run is re-run =="
reset_env
export RERUN_STUCK=1
run_merge waiting-rerun
assert_contains "probe ran" "$OUT" "$PROBE_LOG"
assert_contains "re-run was reported" "$OUT" "re-running run 31504280368"
assert_contains "caller logged the rerun verdict" "$OUT" "re-ran the owning workflow run(s)"
assert_contains "gh run rerun was invoked" "$GH_CALLS" "run rerun 31504280368"
# Pins the `python3 -u` in the caller: with stdout captured into a pipe, python
# block-buffers, so its own "re-running run N" would land AFTER the unbuffered
# child's output — i.e. the log would show the effect before its cause.
assert_line_order "python's line precedes the child gh output it explains" "$OUT" \
  "re-running run 31504280368" "stub: re-run requested"

echo "== 3. cadence: exactly one probe across many polls =="
# The 600s interval cannot elapse in 9 fake seconds, so a time-gated probe fires
# once; an ungated one would fire on all 4 polls.
reset_env
run_merge cadence
polls="$(count_matches "not fully green yet" "$OUT")"
probes="$(count_matches "$PROBE_LOG" "$OUT")"
assert_eq "the loop polled exactly as constructed" "$EXPECTED_POLLS" "$polls"
assert_eq "probed exactly once across those polls" "1" "$probes"
assert_lt "probes are strictly fewer than polls" "$probes" "$polls"

echo "== 3b. cadence: probes again once the interval has elapsed =="
# 301 fake seconds per call, so the 600s interval (STUCK_MINUTES=20) elapses
# between polls. Without a time gate this would print once; with no gate at all,
# on every poll. 2 is what a per-interval gate produces.
reset_env
export DATE_STEP=301 TIMEOUT_SECONDS=1500
run_merge cadence-elapsed
polls="$(count_matches "not fully green yet" "$OUT")"
probes="$(count_matches "$PROBE_LOG" "$OUT")"
assert_eq "polled twice on the fake clock" "2" "$polls"
assert_eq "probed on both polls, 600s apart" "2" "$probes"

echo "== 3c. cadence: a gap SHORTER than the interval does not re-probe =="
# 3b bounds the interval from above (602s elapsed must be enough); this bounds it
# from below (400s elapsed must NOT be). Together they pin the interval to
# (400, 602] at STUCK_MINUTES=20 — i.e. the `/2` divisor specifically, since
# `*60/1`=1200 fails 3b and `*60/3`=400 and `*60/4`=300 both fail here. Without
# this, changing `/2` to `/4` would double `gh` spend and read green, while the
# usage text still promised "at most once per STUCK_MINUTES*60/2".
# 200 fake seconds per call = 400 per iteration; deadline 900 admits 2 polls.
reset_env
export DATE_STEP=200 TIMEOUT_SECONDS=900
run_merge cadence-short-gap
assert_eq "polled twice" "2" "$(count_matches "not fully green yet" "$OUT")"
assert_eq "400s < the 600s interval, so only the first poll probed" "1" \
  "$(count_matches "$PROBE_LOG" "$OUT")"

echo "== 4. merge path: checks green, merge SUCCEEDS, NO probe =="
# The script's primary success path. Nothing else in the repo executes it: both
# its message and its `exit 0` could be changed without any test noticing.
reset_env
export STUB_CHECKS_RC=0 STUB_MERGE_RC=0
export STUB_MERGE_OUT="✓ Merged pull request Twodragon0/claudesec#424 (feat: x)"
run_merge merge-success
assert_contains "merge was attempted" "$OUT" "Attempting merge"
assert_contains "gh's own merge output is surfaced" "$OUT" "Merged pull request"
assert_contains "success is reported" "$OUT" "Merge completed."
assert_eq "exits 0" "0" "$RUN_RC"
assert_not_contains "probe did NOT run on the success path" "$OUT" "$PROBE_LOG"
assert_not_contains "did not fall through to the timeout" "$OUT" "Timed out waiting"

echo "== 4b. merge path: checks green, hard merge failure, NO probe =="
# Merge rc is 3, not 1: a timeout also exits 1, so 1 could not distinguish
# "propagated the merge status" from "fell through to the timeout".
reset_env
export STUB_CHECKS_RC=0 STUB_MERGE_RC=3 STUB_MERGE_OUT="GraphQL: Resource not accessible"
run_merge merge-path
assert_contains "merge was attempted" "$OUT" "Attempting merge"
assert_not_contains "probe did NOT run before the merge attempt" "$OUT" "$PROBE_LOG"
assert_not_contains "no check-runs API call at all" "$GH_CALLS" "check-runs"
assert_eq "the merge exit status itself propagates" "3" "$RUN_RC"
assert_not_contains "did not fall through to the timeout" "$OUT" "Timed out waiting"

echo "== 5. mergeability-lag retry path: NO probe =="
reset_env
export STUB_CHECKS_RC=0 STUB_MERGE_RC=1
export STUB_MERGE_OUT="Required status checks are expected."
run_merge lag-path
assert_contains "lag was detected" "$OUT" "GitHub mergeability lag detected"
assert_not_contains "probe did NOT run on the lag path" "$OUT" "$PROBE_LOG"
assert_not_contains "no check-runs API call at all" "$GH_CALLS" "check-runs"
assert_ge "the lag path retried, as constructed" 2 "$(count_matches "Attempting merge" "$OUT")"

echo "== 6. probe failure is advisory: the wait loop continues =="
reset_env
export STUB_API_RC=1
run_merge probe-fails
assert_contains "probe failure is logged" "$OUT" "Stuck-check probe failed (exit 1)"
assert_contains "the loop kept waiting" "$OUT" "Timed out waiting for PR #424"
assert_eq "the loop iterated again after the failed probe" "$EXPECTED_POLLS" \
  "$(count_matches "not fully green yet" "$OUT")"

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

echo "== 9. arithmetic-eval payloads are rejected before the loop =="
# The payload names `merge_args`, an array the script has ALREADY defined, so
# bash evaluates the subscript and runs the command. The tempting `a[$(...)]`
# shape is USELESS as a test: `a` is unset, so `set -u` aborts first and the
# assertion passes even with the validation deleted (measured). Both variables
# below reach `$(( ))`; POLL_SECONDS does not and is intentionally unvalidated.
reset_env
# SC2016 is the point: `$(...)` must reach the script UNexpanded, so the only
# thing that could expand it is `$(( ))` inside the script under test.
# shellcheck disable=SC2016
export STUCK_MINUTES='merge_args[$(touch '"$WORK"'/pwned-stuck)]'
run_merge bad-stuck-minutes
assert_contains "STUCK_MINUTES payload is rejected" "$OUT" "Invalid STUCK_MINUTES"
assert_eq "exits 1" "1" "$RUN_RC"
assert_missing_file "no command substitution reached \$(( )) via STUCK_MINUTES" "$WORK/pwned-stuck"
assert_not_contains "loop never started" "$OUT" "$PROBE_LOG"

reset_env
# shellcheck disable=SC2016
export TIMEOUT_SECONDS='merge_args[$(touch '"$WORK"'/pwned-timeout)]'
run_merge bad-timeout
assert_contains "TIMEOUT_SECONDS payload is rejected" "$OUT" "Invalid TIMEOUT_SECONDS"
assert_eq "exits 1" "1" "$RUN_RC"
assert_missing_file "no command substitution reached \$(( )) via TIMEOUT_SECONDS" "$WORK/pwned-timeout"

echo "== 10. an overflow-sized STUCK_MINUTES cannot invert the cadence gate =="
# 10^24 minutes passes a digits-only check and then overflows
# `STUCK_MINUTES*60/2` to a NEGATIVE interval, which makes
# `now - last < interval` permanently false: the probe would fire on EVERY poll.
# Rejecting the input is what prevents that, so both halves are asserted.
reset_env
export STUCK_MINUTES=999999999999999999999999
run_merge overflow-stuck-minutes
assert_contains "the overflow value is rejected" "$OUT" "Invalid STUCK_MINUTES"
assert_eq "exits 1" "1" "$RUN_RC"
assert_eq "the gate was never given a negative interval to invert" "0" \
  "$(count_matches "$PROBE_LOG" "$OUT")"

reset_env
export STUCK_MINUTES=100000
run_merge just-over-the-bound
assert_contains "one digit past the bound is rejected" "$OUT" "Invalid STUCK_MINUTES"

reset_env
export STUCK_MINUTES=99999
run_merge at-the-bound
assert_not_contains "the largest accepted value still runs" "$OUT" "Invalid STUCK_MINUTES"
assert_contains "and still probes" "$OUT" "$PROBE_LOG"
# THE PLUMBING, not the log line: the stub's check-run is 30m old, so a 99999m
# threshold must find nothing. If `--stuck-minutes` were dropped from
# `stuck_args` the detector would fall back to its own default of 20 and report
# the 30m check as STUCK — while the log above still announced 99999m and the
# escalation command still printed the operator's value. With RERUN_STUCK=1 that
# re-runs healthy work at a threshold nobody asked for.
assert_contains "the operator's threshold reached the detector" "$OUT" \
  "No stuck check-runs detected."
assert_not_contains "no STUCK verdict at a 99999m threshold" "$OUT" "STUCK     Lint"

echo "== 11. a missing detector is reported, and the loop keeps waiting =="
# The script resolves the detector next to itself, so a copy on its own has none.
mkdir -p "$WORK/lonely"
cp "$MERGE_SH" "$WORK/lonely/gh-merge-ready-pr.sh"
reset_env
SCRIPT_UNDER_TEST="$WORK/lonely/gh-merge-ready-pr.sh"
run_merge no-detector
assert_contains "the missing detector is named" "$OUT" "Stuck-check detector not found"
assert_not_contains "no probe verdict is claimed" "$OUT" "No stuck check-runs detected."
assert_contains "the loop still waited and timed out" "$OUT" "Timed out waiting for PR #424"
assert_eq "exits 1 from the timeout" "1" "$RUN_RC"

echo
echo "Passed: $TEST_PASSED"
echo "Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
