#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Regression: collect_datadog_dashboard_artifacts() must emit VALID JSON request
# payloads (intake.json / query.json) even when DD_SERVICE / DD_ENV carry a
# double-quote, backslash, or newline.
#
# Risk #2 of the 2026-07-27 JSON-escaping audit: the intake/query heredocs
# interpolated $dd_service / $dd_env / $dd_query raw, so an env value like
# DD_ENV='a" ,"injected":"1' produced an invalid — or structurally injected —
# request body POSTed to Datadog's API. Fixed by routing those values through
# _json_escape_str (output.sh) before embedding.
#
# The function writes the payloads, POSTs them, then `rm -f`s them at the end,
# so this test CAPTURES each payload inside stubbed network calls (the exact
# bytes that would be sent) rather than reading the deleted files. No network:
# run_with_timeout / curl / datadog_api_request_with_retry are all stubbed.
#
# Run: bash scanner/tests/test_datadog_json_payloads.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"; ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $(printf '%q' "$expected")"
    echo "    actual:   $(printf '%q' "$actual")"
    ((TEST_FAILED++))
  fi
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "  SKIP: python3 not available — datadog JSON payload test skipped"
  echo ""
  echo "=== Results: 0 passed, 0 failed (skipped) ==="
  exit 0
fi

# Color codes + vars the sourced libs consult
RED="" GREEN="" YELLOW="" CYAN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""
FORMAT="json"; QUIET=1; SEVERITY="all"; VERSION="test"

# datadog.sh's header notes it is sourced AFTER output.sh (for _json_escape_str)
# and checks.sh (for run_with_timeout) — replicate that order here.
source "$LIB_DIR/output.sh"
source "$LIB_DIR/checks.sh"
source "$LIB_DIR/datadog.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir"
capture="$tmpdir/captured"
mkdir -p "$capture"

# ── Network stubs: capture each outbound JSON payload (the deleted-after-POST
# files) so we can assert on the exact bytes that would be sent. ───────────────
# intake.json goes out via `run_with_timeout ... curl ... -d @"$dd_dir/intake.json"`.
run_with_timeout() {
  cp "$SCAN_DIR/.claudesec-datadog/intake.json" "$capture/intake.json" 2>/dev/null || true
  return 0
}
curl() { return 0; }
# query.json / signals-query.json are passed as the 4th arg (data_file). Return
# non-zero so the caller writes its valid {"data":[]} fallback (keeps the
# end-of-function sanitizer's input valid).
datadog_api_request_with_retry() {
  local data_file="${4:-}"
  if [[ -n "$data_file" && -f "$data_file" ]]; then
    cp "$data_file" "$capture/$(basename "$data_file")" 2>/dev/null || true
  fi
  return 1
}

export DD_API_KEY="dummy-key" DD_APP_KEY="dummy-app-key"
# Hostile env: DD_ENV attempts structural key injection; DD_SERVICE carries a
# quote + backslash; a newline is thrown in for the C0 path.
export DD_SERVICE=$'svc"\\x' DD_ENV=$'e" ,"injected":"1\nline2'

collect_datadog_dashboard_artifacts >/dev/null 2>&1

# ── intake.json ────────────────────────────────────────────────────────────
echo ""
echo "=== intake.json: valid JSON + no structural injection ==="
assert_eq "intake.json captured" "true" \
  "$([[ -f "$capture/intake.json" ]] && echo true || echo false)"
assert_eq "intake.json is valid JSON" "0" \
  "$(python3 -m json.tool "$capture/intake.json" >/dev/null 2>&1; echo $?)"
# The injected key name must NOT appear as a real top-level key — it must be
# trapped inside the "env" string value.
intake_check="$(python3 - "$capture/intake.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
top = set(d.keys())
ok = "injected" not in top and d.get("env") == 'e" ,"injected":"1\nline2' and d.get("service") == 'svc"\\x'
sys.stdout.write("OK" if ok else "BAD:%s" % sorted(top))
PY
)"
assert_eq "intake.json: no injected key, env/service round-trip" "OK" "$intake_check"

# ── query.json ─────────────────────────────────────────────────────────────
echo ""
echo "=== query.json: valid JSON with hostile query string ==="
assert_eq "query.json captured" "true" \
  "$([[ -f "$capture/query.json" ]] && echo true || echo false)"
assert_eq "query.json is valid JSON" "0" \
  "$(python3 -m json.tool "$capture/query.json" >/dev/null 2>&1; echo $?)"
query_check="$(python3 - "$capture/query.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
q = d.get("filter", {}).get("query", "")
# The hostile service value must survive inside the query string, not break out.
sys.stdout.write("OK" if 'svc"\\x' in q and "injected" not in d and "injected" not in d.get("filter", {}) else "BAD")
PY
)"
assert_eq "query.json: hostile service contained in query string" "OK" "$query_check"

# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
