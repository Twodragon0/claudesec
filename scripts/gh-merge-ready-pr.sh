#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PR_NUMBER="${1:-}"
MERGE_METHOD="${MERGE_METHOD:-rebase}"
DELETE_BRANCH="${DELETE_BRANCH:-1}"
ADMIN_MERGE="${ADMIN_MERGE:-1}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
POLL_SECONDS="${POLL_SECONDS:-15}"
RERUN_STUCK="${RERUN_STUCK:-0}"
STUCK_MINUTES="${STUCK_MINUTES:-20}"

STUCK_DETECTOR="$SCRIPT_DIR/gh_rerun_stuck_checks.py"
# Exit codes of the detector (see its module docstring).
STUCK_EXIT_FOUND=10
STUCK_EXIT_RERUN=11

usage() {
  cat <<'EOF'
Usage:
  ./scripts/gh-merge-ready-pr.sh <pr-number>

Environment:
  MERGE_METHOD=rebase|merge|squash   Default: rebase
  DELETE_BRANCH=1|0                  Default: 1
  ADMIN_MERGE=1|0                    Default: 1
  TIMEOUT_SECONDS=<seconds>          Default: 900   (integer, 1..999999)
  POLL_SECONDS=<seconds>             Default: 15    (fractional allowed)
  RERUN_STUCK=1|0                    Default: 0 (detect and report only)
  STUCK_MINUTES=<minutes>            Default: 20    (integer, 1..99999)

Behavior:
  - Waits until `gh pr checks` reports success
  - Retries `gh pr merge` when GitHub still reports required checks as
    "expected" even though checks are already green
  - While waiting, probes for check-runs stuck `in_progress` after their
    workflow run already concluded (scripts/gh_rerun_stuck_checks.py). Such a
    PR stays BLOCKED with nothing left to run, so waiting cannot fix it.
    RERUN_STUCK=0 (default) only NAMES the cause: the wait still runs to
    TIMEOUT_SECONDS and still exits 1. RERUN_STUCK=1 re-runs the owning
    workflow run, which can unblock the PR within the same wait.
  - The probe is advisory: a probe failure never aborts the wait loop, and it
    runs at most once per STUCK_MINUTES*60/2 seconds — a check needs more than
    STUCK_MINUTES to qualify as stuck, so a faster cadence buys no detection
    speed and only spends API budget (the probe costs 3 `gh` calls).
EOF
}

if [[ -z "$PR_NUMBER" || "$PR_NUMBER" == "-h" || "$PR_NUMBER" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi

merge_args=("$PR_NUMBER")
case "$MERGE_METHOD" in
  rebase|merge|squash) merge_args+=("--$MERGE_METHOD") ;;
  *)
    echo "Invalid MERGE_METHOD: $MERGE_METHOD" >&2
    exit 1
    ;;
esac

[[ "$DELETE_BRANCH" == "1" ]] && merge_args+=("--delete-branch")
[[ "$ADMIN_MERGE" == "1" ]] && merge_args+=("--admin")

# Both STUCK_MINUTES and TIMEOUT_SECONDS reach `$(( ))`, where an unvalidated
# string has two distinct failure modes:
#
#   1. Code execution. Bash evaluates array subscripts inside arithmetic, so
#      `TIMEOUT_SECONDS='merge_args[$(cmd)]'` runs `cmd` (an UNSET array name
#      aborts on `set -u` first, which is why the tests use a name that is
#      already defined here). No privilege boundary is crossed — whoever sets
#      the variable can already run commands in that shell — so this is
#      consistency and defence in depth, not a vulnerability fix. It is applied
#      to both because validating one of two identical adjacent surfaces is
#      what produces false assurance.
#   2. Silent overflow. An unbounded digit string wraps to a NEGATIVE value:
#      STUCK_MINUTES=10^24 yielded stuck_probe_interval=-4450678101776531486,
#      which makes the cadence gate always true and probes on EVERY poll — the
#      exact behaviour the gate exists to prevent. Hence an upper bound, not
#      just a digits-only check.
#
# POLL_SECONDS is deliberately NOT validated: it never reaches `$(( ))`, it is
# only passed to `sleep`, and fractional values are useful there.
# CONTRACT: `pattern` is passed to `=~` UNQUOTED, which is required for regex
# semantics — so it must be a single shell word (no whitespace, no glob-ish
# quoting). Both call sites pass a literal single-quoted ERE. `value` is echoed
# back on rejection so the operator can see their own typo; both variables this
# guards are numeric config, never credentials.
validate_int_range() {
  local name="$1" value="$2" pattern="$3" range="$4"
  if ! [[ "$value" =~ $pattern ]]; then
    echo "Invalid $name: $value (expected an integer in $range)" >&2
    exit 1
  fi
}

validate_int_range STUCK_MINUTES "$STUCK_MINUTES" '^[1-9][0-9]{0,4}$' '1..99999'
validate_int_range TIMEOUT_SECONDS "$TIMEOUT_SECONDS" '^[1-9][0-9]{0,5}$' '1..999999'

stuck_args=("$PR_NUMBER" "--stuck-minutes" "$STUCK_MINUTES")
[[ "$RERUN_STUCK" == "1" ]] && stuck_args+=("--rerun")

# Half the stuck threshold: detection can lag a newly-stuck check by at most
# STUCK_MINUTES/2, for at most 2 probes per threshold window. At the defaults
# that is 1 probe / 600s instead of 1 / 15s — 6 `gh` calls per 20 minutes
# instead of 240 — with no loss in what is detectable. No clamp against
# POLL_SECONDS: the smallest interval this can produce is 30s (STUCK_MINUTES=1),
# and the poll itself already bounds the probe rate from below.
stuck_probe_interval=$(( STUCK_MINUTES * 60 / 2 ))
# 0 = never probed, so the first waiting iteration probes: when the operator
# starts this script the checks may ALREADY have been stuck for an hour.
last_stuck_probe=0

deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))

pr_state() {
  gh pr view "$PR_NUMBER" --json state,mergeStateStatus,url,headRefName,baseRefName
}

checks_ok() {
  gh pr checks "$PR_NUMBER" >/dev/null 2>&1
}

merge_once() {
  local output=""
  set +e
  output=$(gh pr merge "${merge_args[@]}" 2>&1)
  local status=$?
  set -e
  printf '%s' "$output"
  return "$status"
}

# Advisory: reports (and with RERUN_STUCK=1 re-runs) check-runs that are stuck
# `in_progress` after their workflow concluded. NEVER fails the caller — the
# loop's job is to wait, and a `gh` hiccup in the probe is not a reason to stop.
probe_stuck_checks() {
  local now
  now=$(date +%s)
  if (( now - last_stuck_probe < stuck_probe_interval )); then
    return 0
  fi
  last_stuck_probe="$now"

  if [[ ! -f "$STUCK_DETECTOR" ]]; then
    echo "[claudesec] Stuck-check detector not found at $STUCK_DETECTOR; skipping probe." >&2
    return 0
  fi

  echo "[claudesec] Probing for check-runs stuck >${STUCK_MINUTES}m after their workflow concluded..."
  local output="" status=0
  set +e
  # -u: with stdout captured into a pipe python block-buffers, so `gh run rerun`
  # output (an unbuffered child) would otherwise print BEFORE the "STUCK ..."
  # lines explaining it.
  output=$(python3 -u "$STUCK_DETECTOR" "${stuck_args[@]}" 2>&1)
  status=$?
  set -e

  case "$status" in
    0)
      echo "[claudesec] No stuck check-runs detected."
      ;;
    "$STUCK_EXIT_FOUND")
      echo "$output"
      echo "[claudesec] Stuck check-runs detected (report only). Re-run with RERUN_STUCK=1, or:"
      echo "[claudesec]   python3 scripts/gh_rerun_stuck_checks.py $PR_NUMBER --stuck-minutes $STUCK_MINUTES --rerun"
      ;;
    "$STUCK_EXIT_RERUN")
      echo "$output"
      echo "[claudesec] Stuck check-runs detected; re-ran the owning workflow run(s)."
      ;;
    *)
      echo "$output" >&2
      echo "[claudesec] Stuck-check probe failed (exit $status); continuing to wait." >&2
      ;;
  esac
  return 0
}

print_status() {
  local payload="$1"
  python3 - "$payload" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
print(
    f"[claudesec] PR {data['url']} state={data['state']} "
    f"mergeStateStatus={data.get('mergeStateStatus', 'unknown')}"
)
PY
}

while (( $(date +%s) < deadline )); do
  state_json="$(pr_state)"
  print_status "$state_json"

  if python3 - "$state_json" <<'PY'
import json
import sys
data = json.loads(sys.argv[1])
raise SystemExit(0 if data["state"] == "MERGED" else 1)
PY
  then
    echo "[claudesec] PR already merged."
    exit 0
  fi

  if ! checks_ok; then
    echo "[claudesec] Required checks not fully green yet; waiting ${POLL_SECONDS}s..."
    # Waiting path only. Not before a merge attempt (checks are green there, so
    # there is nothing stuck to find) and not on the mergeability-lag retry
    # below (that is GitHub's own state lag, a different condition).
    probe_stuck_checks
    sleep "$POLL_SECONDS"
    continue
  fi

  echo "[claudesec] Required checks are green. Attempting merge..."
  merge_output="$(merge_once)" || merge_status=$?
  merge_status="${merge_status:-0}"

  if [[ "$merge_status" -eq 0 ]]; then
    echo "$merge_output"
    echo "[claudesec] Merge completed."
    exit 0
  fi

  echo "$merge_output" >&2

  if grep -qiE "required status checks are expected|not mergeable|base branch policy prohibits" <<<"$merge_output"; then
    echo "[claudesec] GitHub mergeability lag detected; retrying in ${POLL_SECONDS}s..."
    sleep "$POLL_SECONDS"
    unset merge_status
    continue
  fi

  exit "$merge_status"
done

echo "[claudesec] Timed out waiting for PR #$PR_NUMBER to become mergeable." >&2
exit 1
