#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/saas/audit-points.sh
#
# WHY THIS TEST IS NARROW:
# audit-points.sh (AUDIT-001) delegates all product detection and checklist
# fetching to scanner/lib/audit-points-scan.py. The shell check only:
#   1. Invokes the Python helper (requires python3 + LIB_DIR/audit-points-scan.py)
#   2. Parses the JSON response
#   3. Emits pass/skip based on the 'detected' list
#
# NOT OFFLINE-TESTABLE:
#   AUDIT-001 pass/warn when products are detected — requires audit-points-scan.py
#     to fetch the upstream audit-points catalog (network) and scan SCAN_DIR.
#
# WHAT IS TESTABLE OFFLINE:
#   AUDIT-001 SKIP when LIB_DIR/audit-points-scan.py is absent or python3 is not
#     available — the early-exit guard fires before any network call.
#   AUDIT-001 PASS when the Python helper returns an empty 'detected' list —
#     simulated by injecting a stub python3 that emits the "no products" JSON.
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_saas_audit_points.sh
set -uo pipefail

export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
FORMAT="text"
QUIET=1
SEVERITY="low"

RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"
    ((TEST_FAILED++))
  fi
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── AUDIT-001: LIB_DIR absent -> SKIP ────────────────────────────────────────
# Simulates the case where audit-points-scan.py does not exist (missing LIB_DIR).

echo "=== AUDIT-001: audit-points-scan.py absent -> SKIP ==="

RESULTS=()
SCAN_DIR="$tmpdir"
# Point LIB_DIR at a directory that has no audit-points-scan.py
LIB_DIR_ORIG="$LIB_DIR"
LIB_DIR="$tmpdir/nonexistent_lib"
source "$CHECKS_DIR/saas/audit-points.sh" 2>/dev/null || true
LIB_DIR="$LIB_DIR_ORIG"

local_found=false
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  if [[ "$r" == "SKIP:AUDIT-001"* ]]; then
    local_found=true
    break
  fi
done
if $local_found; then
  echo "  PASS: audit-points-scan.py absent -> SKIP AUDIT-001"
  ((TEST_PASSED++))
else
  echo "  FAIL: audit-points-scan.py absent -> expected SKIP AUDIT-001, got: ${RESULTS[*]:-none}"
  ((TEST_FAILED++))
fi

# ── AUDIT-001: python3 absent -> SKIP ────────────────────────────────────────
# Simulates the case where python3 is not installed. The check guards on both
# LIB_DIR/audit-points-scan.py presence AND the python3 call succeeding.

echo "=== AUDIT-001: python3 absent (stub returns empty) -> SKIP ==="

RESULTS=()
SCAN_DIR="$tmpdir"
# Stub python3 to exit non-zero so _audit_scan_json stays empty
python3() { return 1; }
export -f python3
source "$CHECKS_DIR/saas/audit-points.sh" 2>/dev/null || true
unset -f python3 2>/dev/null || true

local_found=false
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  if [[ "$r" == "SKIP:AUDIT-001"* ]]; then
    local_found=true
    break
  fi
done
if $local_found; then
  echo "  PASS: python3 absent -> SKIP AUDIT-001"
  ((TEST_PASSED++))
else
  echo "  FAIL: python3 absent -> expected SKIP AUDIT-001, got: ${RESULTS[*]:-none}"
  ((TEST_FAILED++))
fi

# ── AUDIT-001: stub python3 returns no-products JSON -> PASS ─────────────────
# Simulates audit-points-scan.py returning {"detected":[],"item_count":0}.

echo "=== AUDIT-001: stub returns no-products JSON -> PASS ==="

RESULTS=()
SCAN_DIR="$tmpdir"

# Make sure the path audit-points-scan.py exists so the check doesn't exit early
mkdir -p "$tmpdir/stub_lib"
printf '#!/usr/bin/env python3\nimport json; print(json.dumps({"detected":[],"item_count":0}))\n' \
  > "$tmpdir/stub_lib/audit-points-scan.py"

# Stub python3 to emit the no-products JSON for the scan call, then delegate
# list/parse calls to real python3
_real_python3="$(command -v python3 2>/dev/null || echo "")"
python3() {
  # The check passes "$LIB_DIR/audit-points-scan.py" as the first positional arg
  if [[ "${1:-}" == *"audit-points-scan.py"* ]]; then
    printf '{"detected":[],"item_count":0}\n'
    return 0
  fi
  # Delegate all other calls (json parsing) to real python3
  if [[ -n "$_real_python3" ]]; then
    "$_real_python3" "$@"
  else
    return 1
  fi
}
export -f python3
LIB_DIR_ORIG="$LIB_DIR"
LIB_DIR="$tmpdir/stub_lib"
source "$CHECKS_DIR/saas/audit-points.sh" 2>/dev/null || true
LIB_DIR="$LIB_DIR_ORIG"
unset -f python3 2>/dev/null || true

local_found=false
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  if [[ "$r" == "PASS:AUDIT-001"* ]]; then
    local_found=true
    break
  fi
done
if $local_found; then
  echo "  PASS: no-products JSON -> PASS AUDIT-001"
  ((TEST_PASSED++))
else
  echo "  FAIL: no-products JSON -> expected PASS AUDIT-001, got: ${RESULTS[*]:-none}"
  ((TEST_FAILED++))
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
