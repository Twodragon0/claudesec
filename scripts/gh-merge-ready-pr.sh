#!/usr/bin/env bash
set -euo pipefail

PR_NUMBER="${1:-}"
MERGE_METHOD="${MERGE_METHOD:-rebase}"
DELETE_BRANCH="${DELETE_BRANCH:-1}"
ADMIN_MERGE="${ADMIN_MERGE:-1}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
POLL_SECONDS="${POLL_SECONDS:-15}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/gh-merge-ready-pr.sh <pr-number>

Environment:
  MERGE_METHOD=rebase|merge|squash   Default: rebase
  DELETE_BRANCH=1|0                  Default: 1
  ADMIN_MERGE=1|0                    Default: 1
  TIMEOUT_SECONDS=<seconds>          Default: 900
  POLL_SECONDS=<seconds>             Default: 15

Behavior:
  - Waits until `gh pr checks` reports success
  - Retries `gh pr merge` when GitHub still reports required checks as
    "expected" even though checks are already green
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
