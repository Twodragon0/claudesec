#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for checks.sh::run_category_checks() — the shared per-category
# "source each check file, aggregate counters + JSON" loop extracted out of
# scanner/claudesec's run_scan() and run_scan_for_dashboard().
# No network, no real check files — uses fake categories under a temp CHECKS_DIR.
# Run: bash scanner/tests/test_run_category_checks.sh
set -uo pipefail

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
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((TEST_FAILED++))
  fi
}

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

# ── Fake CHECKS_DIR with two categories, each with one trivial check file ──
CHECKS_DIR="$tmpdir/checks"
mkdir -p "$CHECKS_DIR/cat1" "$CHECKS_DIR/cat2"

# Use the real pass() (from output.sh) so JSON_RESULTS merging is realistic
# and distinct per category (checks.sh's append_json escaping/category
# lookup is exercised the same way real check files exercise it).
cat > "$CHECKS_DIR/cat1/check.sh" <<'EOF'
pass "CAT1-CHECK" "Cat1 check" ""
EOF
cat > "$CHECKS_DIR/cat2/check.sh" <<'EOF'
pass "CAT2-CHECK" "Cat2 check" ""
EOF

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

# ==============================================================================
# Group 1: sequential mode aggregation
# ==============================================================================
echo ""
echo "=== sequential mode: counter + JSON aggregation ==="

_reset_state
run_category_checks 0 0 cat1 cat2 >/dev/null 2>&1

assert_eq "sequential: TOTAL_CHECKS=2" "2" "$TOTAL_CHECKS"
assert_eq "sequential: PASSED=2"       "2" "$PASSED"
assert_contains "sequential: JSON has cat1 entry" "$JSON_RESULTS" '"id":"CAT1-CHECK"'
assert_contains "sequential: JSON has cat2 entry" "$JSON_RESULTS" '"id":"CAT2-CHECK"'

# ==============================================================================
# Group 2: parallel mode aggregation
# ==============================================================================
echo ""
echo "=== parallel mode: counter + JSON aggregation ==="

_reset_state
run_category_checks 1 0 cat1 cat2 >/dev/null 2>&1

assert_eq "parallel: TOTAL_CHECKS=2" "2" "$TOTAL_CHECKS"
assert_eq "parallel: PASSED=2"       "2" "$PASSED"
assert_contains "parallel: JSON has cat1 entry" "$JSON_RESULTS" '"id":"CAT1-CHECK"'
assert_contains "parallel: JSON has cat2 entry" "$JSON_RESULTS" '"id":"CAT2-CHECK"'

# ==============================================================================
# Group 3: verbose=1 sequential — section header + PASS output streamed
# ==============================================================================
echo ""
echo "=== verbose=1 sequential: section header emitted ==="

_reset_state
seq_verbose_out="$(run_category_checks 0 1 cat1 cat2 2>&1)"

assert_contains "verbose sequential: section header for cat1" "$seq_verbose_out" "cat1"
assert_contains "verbose sequential: section header for cat2" "$seq_verbose_out" "cat2"
assert_contains "verbose sequential: section delimiter shown" "$seq_verbose_out" "━"

# ==============================================================================
# Group 4: verbose=1 parallel — section header written inside the subshell is
# streamed to stdout via the post-wait `cat "$tmpdir/${cat}.out"` step.
# (Per-check pass()/fail() text itself is NOT expected here: both the original
# and extracted loops always run `source "$check_file" >/dev/null 2>&1`, which
# suppresses a check's own echo output regardless of QUIET/verbose — only the
# section header and any "Check failed to load" warning are visible.)
# ==============================================================================
echo ""
echo "=== verbose=1 parallel: section header streamed via .out cat ==="

_reset_state
par_verbose_out="$(run_category_checks 1 1 cat1 cat2 2>&1)"

assert_contains "verbose parallel: section header for cat1" "$par_verbose_out" "cat1"
assert_contains "verbose parallel: section header for cat2" "$par_verbose_out" "cat2"

# verbose=0 parallel: the same section header must NOT be streamed
_reset_state
par_silent_out="$(run_category_checks 1 0 cat1 cat2 2>&1)"
assert_not_contains "silent parallel: no section header streamed" "$par_silent_out" "━"

# ==============================================================================
# Group 5: unknown category — verbose-gated warning
# ==============================================================================
echo ""
echo "=== unknown category: warning is verbose-gated ==="

# Sequential, verbose=1: warns
_reset_state
seq_unknown_verbose="$(run_category_checks 0 1 does-not-exist 2>&1)"
assert_contains "sequential verbose=1: unknown category warns" "$seq_unknown_verbose" "Unknown category: does-not-exist"

# Sequential, verbose=0: silent
_reset_state
seq_unknown_silent="$(run_category_checks 0 0 does-not-exist 2>&1)"
assert_eq "sequential verbose=0: unknown category is silent" "" "$seq_unknown_silent"

# Parallel, verbose=1: warns (mixed with one valid category to force the
# parallel branch, which requires more than one category)
_reset_state
par_unknown_verbose="$(run_category_checks 1 1 does-not-exist cat1 2>&1)"
assert_contains "parallel verbose=1: unknown category warns" "$par_unknown_verbose" "Unknown category: does-not-exist"

# Parallel, verbose=0: silent
_reset_state
par_unknown_silent="$(run_category_checks 1 0 does-not-exist cat1 2>&1)"
assert_not_contains "parallel verbose=0: unknown category is silent" "$par_unknown_silent" "Unknown category"

# ==============================================================================
# Group 6: json format never prints section headers even when verbose=1
# ==============================================================================
echo ""
echo "=== FORMAT=json: no section header regardless of verbose ==="

_reset_state
OLD_FORMAT="$FORMAT"
FORMAT="json"
json_verbose_out="$(run_category_checks 0 1 cat1 2>&1)"
assert_not_contains "json format: no section delimiter" "$json_verbose_out" "━"
FORMAT="$OLD_FORMAT"

# ==============================================================================
# Group 7: parallel gate is a STRING compare, not numeric -eq. Callers pass the
# raw CLAUDESEC_DASHBOARD_PARALLEL value, which may be a non-numeric truthy
# string ("true"); numeric -eq would abort under `set -u`. Only "1" enables
# parallel — any other value must fall back to sequential without crashing.
# ==============================================================================
echo ""
echo "=== parallel gate: non-numeric truthy value falls back to sequential (no crash) ==="

_reset_state
gate_rc=0
run_category_checks "true" 0 cat1 cat2 >/dev/null 2>&1 || gate_rc=$?
assert_eq "gate 'true': no crash (rc=0)" "0" "$gate_rc"
assert_eq "gate 'true': ran sequentially, TOTAL_CHECKS=2" "2" "$TOTAL_CHECKS"

_reset_state
gate_rc=0
run_category_checks "" 0 cat1 >/dev/null 2>&1 || gate_rc=$?
assert_eq "gate '': no crash (rc=0)" "0" "$gate_rc"
assert_eq "gate '': ran sequentially, TOTAL_CHECKS=1" "1" "$TOTAL_CHECKS"

# ==============================================================================
# Group 8: sequential load-failure path — a check file whose `source` returns
# non-zero triggers the unconditional `Check failed to load` warning.
# ==============================================================================
echo ""
echo "=== sequential: load failure emits 'Check failed to load' warning ==="

mkdir -p "$CHECKS_DIR/cat_bad"
# `false` as the last statement makes `source` return non-zero without any
# side effect on the parent function (unlike `return`, which would unwind it).
cat > "$CHECKS_DIR/cat_bad/check.sh" <<'EOF'
false
EOF

_reset_state
bad_load_out="$(run_category_checks 0 0 cat_bad 2>&1)"
assert_contains "load failure: warning emitted" "$bad_load_out" "Check failed to load: check.sh"

# ==============================================================================
# Group 9: JSON merge is structurally valid (not just substring-present).
# Guards the `${JSON_RESULTS%]},$inner]` bracket/comma splicing against a future
# regression that produces a substring-matching but malformed array.
# ==============================================================================
echo ""
echo "=== JSON merge: output parses as a 2-element array ==="

if command -v python3 >/dev/null 2>&1; then
  for _mode in 0 1; do
    _reset_state
    run_category_checks "$_mode" 0 cat1 cat2 >/dev/null 2>&1
    _n="$(printf '%s' "$JSON_RESULTS" | python3 -c 'import sys,json; a=json.load(sys.stdin); print(len(a) if isinstance(a,list) else "notlist")' 2>&1)"
    assert_eq "JSON merge (mode=$_mode): valid list of 2 entries" "2" "$_n"
  done
else
  echo "  SKIP: python3 not available for structural JSON validation"
fi

# ==============================================================================
# Group 10: parallel mode merges FINDINGS_* arrays back to the parent.
# Regression for the writeback gap where each category subshell populated its
# own FINDINGS_CRITICAL/HIGH/MEDIUM/LOW/WARN but only counters + JSON_RESULTS
# crossed the subshell boundary — leaving the parent arrays empty, so the
# summary "Severity Breakdown"/"Recommended Fixes" and the dashboard findings
# table (both driven by FINDINGS_* lengths) rendered blank in parallel mode
# even with a correct non-zero FAILED count.
# ==============================================================================
echo ""
echo "=== parallel mode: FINDINGS_* arrays merged back to parent ==="

mkdir -p "$CHECKS_DIR/cat_sev"
cat > "$CHECKS_DIR/cat_sev/check.sh" <<'EOF'
fail "SEV-CRIT" "crit finding" "critical" "fix-crit" "detail-crit" "/f/crit"
fail "SEV-HIGH" "high finding" "high" "fix-high" "detail-high" "/f/high"
fail "SEV-MED"  "med finding"  "medium"   "fix-med"  "detail-med"  "/f/med"
fail "SEV-LOW"  "low finding"  "low"      "fix-low"  "detail-low"  "/f/low"
warn "SEV-WARN" "warn finding" "warn detail"
EOF

# Baseline: sequential mode already populates the arrays
_reset_state
run_category_checks 0 0 cat_sev >/dev/null 2>&1
assert_eq "seq: FINDINGS_CRITICAL=1" "1" "${#FINDINGS_CRITICAL[@]}"
assert_eq "seq: FINDINGS_HIGH=1"     "1" "${#FINDINGS_HIGH[@]}"
assert_eq "seq: FINDINGS_MEDIUM=1"   "1" "${#FINDINGS_MEDIUM[@]}"
assert_eq "seq: FINDINGS_LOW=1"      "1" "${#FINDINGS_LOW[@]}"
assert_eq "seq: FINDINGS_WARN=1"     "1" "${#FINDINGS_WARN[@]}"

# Parallel mode MUST merge the same findings back (2 categories force the
# parallel branch, which requires >1 category)
_reset_state
run_category_checks 1 0 cat_sev cat1 >/dev/null 2>&1
assert_eq "parallel: FINDINGS_CRITICAL merged=1" "1" "${#FINDINGS_CRITICAL[@]}"
assert_eq "parallel: FINDINGS_HIGH merged=1"     "1" "${#FINDINGS_HIGH[@]}"
assert_eq "parallel: FINDINGS_MEDIUM merged=1"   "1" "${#FINDINGS_MEDIUM[@]}"
assert_eq "parallel: FINDINGS_LOW merged=1"      "1" "${#FINDINGS_LOW[@]}"
assert_eq "parallel: FINDINGS_WARN merged=1"     "1" "${#FINDINGS_WARN[@]}"
# Content integrity: the packed \x1f entry survives the file round-trip
assert_contains "parallel: crit entry id preserved"   "${FINDINGS_CRITICAL[0]:-}" "SEV-CRIT"
assert_contains "parallel: high entry remediation"    "${FINDINGS_HIGH[0]:-}"     "fix-high"

# ==============================================================================
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
