#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# End-to-end offline regression for the PARALLEL scan path's findings JSON.
#
# This guards the intersection of three fixes that each touched a different
# hop of the same pipeline:
#   * #356 — findings_json.py builds scan-report.json via json.dumps
#            (backslash/quote/control-char safe).
#   * #358 — run_category_checks() parallel mode hands each category subshell's
#            FINDINGS_* arrays back to the parent via a NUL-separated file
#            (_write_findings_file / _merge_findings_file); before it, parallel
#            scans blanked the dashboard findings table.
#   * #359 — append_json()'s _json_escape_str escapes every C0 control char for
#            the --format json / scan-report.json CLI path.
#
# The existing suites cover these hops in ISOLATION but never together:
#   * test_run_category_checks.sh Group 10 proves parallel FINDINGS_* merge —
#     but only with control-char-free values, and only asserts array lengths /
#     packed-entry substrings, never downstream JSON validity.
#   * test_output_functions.sh Group 3b proves a control-char detail survives
#     fail() -> generate_html_dashboard -> valid scan-report.json — but only in
#     SEQUENTIAL mode.
#
# So a regression that corrupts a control-char / multi-line finding SPECIFICALLY
# on the parallel NUL-file merge (e.g. a future switch back to newline-delimited
# records would split a multi-line _format_hits detail into a malformed entry)
# would slip past both. This test closes that gap: a hostile finding is produced
# inside a parallel category subshell, merged back, emitted through the real
# dashboard path, and scan-report.json is asserted VALID JSON with the payload
# round-tripped byte-for-byte. It also pins sequential/parallel output parity.
#
# Run: bash scanner/tests/test_parallel_findings_json_e2e.sh

set -uo pipefail

# Hermetic offline guard (PR #190): generate_html_dashboard() spawns
# dashboard-gen.py, which makes live GitHub API calls without this — hanging
# for minutes. Force offline so the test never touches the network.
export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $(printf '%q' "$expected")"
    echo "    actual:   $(printf '%q' "$actual")"
    ((TEST_FAILED++))
  fi
}

# python3 is required to validate JSON; skip (not fail) the whole suite on a
# minimal host, matching output.sh's own python3 guard.
if ! command -v python3 >/dev/null 2>&1; then
  echo "  SKIP: python3 not available — parallel findings JSON E2E skipped"
  echo ""
  echo "=== Results: 0 passed, 0 failed (skipped) ==="
  exit 0
fi

# Color codes referenced by output.sh/checks.sh
RED="" GREEN="" YELLOW="" CYAN="" DIM="" NC="" BOLD="" BLUE="" MAGENTA=""

# Variables output.sh/checks.sh consult
FORMAT="text"
QUIET=1
SEVERITY="all"
VERSION="test"

source "$LIB_DIR/output.sh"
source "$LIB_DIR/checks.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir"

# ── Fake CHECKS_DIR: one hostile category + one plain category. Two categories
# are required to force run_category_checks() down its parallel branch
# (`${#categories[@]} -gt 1`). ─────────────────────────────────────────────────
CHECKS_DIR="$tmpdir/checks"
mkdir -p "$CHECKS_DIR/cat_hostile" "$CHECKS_DIR/cat_plain"

# The hostile detail carries every class the three fixes must handle together:
#   backslash (Windows path)  → #356/#359 (invalid JSON if unescaped)
#   double-quote              → structural break if unescaped
#   REAL embedded newline     → #358 NUL-delimited merge (newline-delimited read
#                               would truncate the entry) + #359 \n escape
#   tab + ESC(0x1b) + BEL(0x07) → #359 C0 short/\u00XX escapes
# Assembled inside the check with $'...' so the exact bytes reach fail().
cat > "$CHECKS_DIR/cat_hostile/check.sh" <<'EOF'
_hostile=$'C:\\Users\\x "quoted"\nline2\ttab\x1besc\x07bel'
fail "CODE-INJ-777" "hostile \"title\" C:\\x" "critical" "$_hostile" "rotate \"key\"" $'loc\nline2'
warn "CODE-WARN-1" "warn with \"quote\" and back\\slash" $'warn\ndetail'
EOF
cat > "$CHECKS_DIR/cat_plain/check.sh" <<'EOF'
pass "PLAIN-OK" "plain pass" ""
EOF

# The exact payload we expect to survive the whole pipeline, byte-for-byte.
EXPECTED_DETAIL=$'C:\\Users\\x "quoted"\nline2\ttab\x1besc\x07bel'
EXPECTED_LOCATION=$'loc\nline2'

_reset_state() {
  TOTAL_CHECKS=0
  PASSED=0
  FAILED=0
  WARNINGS=0
  SKIPPED=0
  JSON_RESULTS="[]"
  FINDINGS_CRITICAL=()
  FINDINGS_HIGH=()
  FINDINGS_MEDIUM=()
  FINDINGS_LOW=()
  FINDINGS_WARN=()
}

# Extract findings[?id==$2].$3 from a scan-report.json ($1); prints the raw
# field value, or a sentinel on any error / missing key.
_report_field() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, fid, key = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as e:  # noqa: BLE001
    sys.stdout.write("__PARSE_ERR__:%s" % e)
    sys.exit(0)
for f in data.get("findings", []):
    if f.get("id") == fid:
        sys.stdout.write(str(f.get(key, "__MISSING__")))
        break
else:
    sys.stdout.write("__NO_FINDING__")
PY
}

# ==============================================================================
# Group 1: PARALLEL scan -> dashboard -> scan-report.json is VALID JSON with the
# hostile control-char / multi-line payload round-tripped byte-for-byte.
# ==============================================================================
echo ""
echo "=== parallel path: hostile finding survives to valid scan-report.json ==="

_reset_state
run_category_checks 1 0 cat_hostile cat_plain >/dev/null 2>&1

# The parallel subshell must have merged the hostile finding back (the #358 gap
# would leave this empty, blanking the dashboard).
assert_eq "parallel: FINDINGS_CRITICAL merged" "1" "${#FINDINGS_CRITICAL[@]}"
assert_eq "parallel: FINDINGS_WARN merged"     "1" "${#FINDINGS_WARN[@]}"

generate_html_dashboard "$tmpdir/dashboard.html" >/dev/null 2>&1
report="$tmpdir/scan-report.json"

assert_eq "parallel: scan-report.json is valid JSON" "0" \
  "$(python3 -m json.tool "$report" >/dev/null 2>&1; echo $?)"

assert_eq "parallel: dashboard.html produced" "true" \
  "$([[ -s "$tmpdir/dashboard.html" ]] && echo true || echo false)"

# Byte-for-byte round-trip of the hostile detail (backslash + quote + real
# newline + tab + ESC + BEL) through the parallel NUL-merge + json.dumps.
assert_eq "parallel: hostile details round-trips exactly" \
  "$EXPECTED_DETAIL" "$(_report_field "$report" CODE-INJ-777 details)"

# Multi-line location must survive the NUL-delimited merge (a newline-delimited
# read would truncate it at "loc").
assert_eq "parallel: multi-line location round-trips" \
  "$EXPECTED_LOCATION" "$(_report_field "$report" CODE-INJ-777 location)"

# The warn() finding's quote+backslash+newline detail must also survive.
assert_eq "parallel: warn multi-line detail round-trips" \
  $'warn\ndetail' "$(_report_field "$report" CODE-WARN-1 details)"

# ==============================================================================
# Group 2: sequential vs parallel produce the SAME findings JSON for the same
# input — the parallel merge must not reorder, drop, or corrupt fields relative
# to the sequential baseline. Compares the normalized (sorted-by-id) findings.
# ==============================================================================
echo ""
echo "=== sequential/parallel parity: identical findings JSON ==="

_normalized_findings() {
  python3 - "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
findings = sorted(data.get("findings", []), key=lambda f: f.get("id", ""))
sys.stdout.write(json.dumps(findings, ensure_ascii=False, sort_keys=True))
PY
}

_reset_state
run_category_checks 0 0 cat_hostile cat_plain >/dev/null 2>&1
generate_html_dashboard "$tmpdir/dashboard-seq.html" >/dev/null 2>&1
seq_findings="$(_normalized_findings "$tmpdir/scan-report.json")"

_reset_state
run_category_checks 1 0 cat_hostile cat_plain >/dev/null 2>&1
generate_html_dashboard "$tmpdir/dashboard-par.html" >/dev/null 2>&1
par_findings="$(_normalized_findings "$tmpdir/scan-report.json")"

assert_eq "parity: parallel findings == sequential findings" "$seq_findings" "$par_findings"

# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
