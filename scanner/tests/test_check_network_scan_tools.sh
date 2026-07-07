#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/network/scan-tools.sh
#
# WHY THIS TEST IS NARROW:
# scan-tools.sh unconditionally runs five internal functions in sequence:
# _trivy_run, _nmap_run, _sslscan_run, _http_headers_run, and
# _normalize_network_report. The only functions that emit pass/fail/warn/skip
# results (the "checks" this scanner records) are:
#
#   _trivy_run:  TRIVY-001 (scan ran / disabled / not installed / failed),
#                TRIVY-CRIT / TRIVY-HIGH / TRIVY-MED (severity counts parsed
#                from the Trivy JSON report via python3).
#   _nmap_run:   NMAP-001 (skip only, when scanning is enabled with targets
#                but nmap is not installed). When nmap IS installed the
#                function intentionally emits no pass/fail (dashboard reads
#                the raw XML instead) — not assertable via RESULTS.
#
# _sslscan_run, _http_headers_run, and _normalize_network_report never call
# pass/fail/warn/skip at all (they only write files under
# .claudesec-network/ for the dashboard/diagram generator to consume later),
# so there is no check-ID behavior to assert there — testing them here would
# be a hollow, non-check-verifying test. This file therefore focuses on the
# two functions that actually produce scanner findings.
#
# OFFLINE STRATEGY:
#   Override has_command per-scenario to control exactly which external
#   tools appear "installed" (real python3 is left available since the
#   Trivy JSON parser and the network-report normalizer both require it and
#   neither makes a network call). Override run_with_timeout to bypass the
#   real timeout wrapper (this repo has no `timeout`/`gtimeout` binary
#   available in every environment) and stub the `trivy` CLI directly so no
#   real scan, network access, or filesystem walk of the real repo happens.
#
# Run: bash scanner/tests/test_check_network_scan_tools.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture result calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { :; }

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

run_check() {
  RESULTS=()
  source "$CHECKS_DIR/network/scan-tools.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
mkdir -p "$tmpdir/scan"

# ── TRIVY-001: disabled via config ──────────────────────────────────────────

echo "=== TRIVY-001: disabled in config -> skip ==="

has_command() {
  case "$1" in
    python3) return 0 ;;
    *) return 1 ;;
  esac
}
export CLAUDESEC_TRIVY_ENABLED=0
SCAN_DIR="$tmpdir/scan" run_check
assert_has_result "Trivy disabled in config -> SKIP TRIVY-001" "SKIP" "TRIVY-001"
unset CLAUDESEC_TRIVY_ENABLED

# ── TRIVY-001: not installed ─────────────────────────────────────────────────

echo "=== TRIVY-001: trivy not installed -> skip ==="

has_command() {
  case "$1" in
    trivy) return 1 ;;
    python3) return 0 ;;
    *) return 1 ;;
  esac
}
SCAN_DIR="$tmpdir/scan" run_check
assert_has_result "Trivy not installed -> SKIP TRIVY-001" "SKIP" "TRIVY-001"

# ── TRIVY-001/CRIT/HIGH/MED: scan completes with findings ──────────────────

echo "=== TRIVY-001: scan completes -> pass + severity findings ==="

has_command() {
  case "$1" in
    trivy) return 0 ;;
    python3) return 0 ;;
    *) return 1 ;;
  esac
}
run_with_timeout() {
  shift
  "$@" 2>/dev/null
}
trivy() {
  local mode="$1"
  shift
  local out=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
      out="$2"
    fi
    shift
  done
  case "$mode" in
    fs)
      cat > "$out" <<'JSON'
{"Results":[{"Vulnerabilities":[{"Severity":"CRITICAL"},{"Severity":"HIGH"},{"Severity":"HIGH"},{"Severity":"MEDIUM"}]}]}
JSON
      ;;
    config)
      echo '{"Misconfigurations":[]}' > "$out"
      ;;
  esac
  return 0
}
SCAN_DIR="$tmpdir/scan" run_check
assert_has_result "Trivy scan completed -> PASS TRIVY-001" "PASS" "TRIVY-001"
assert_has_result "1 CRITICAL vulnerability parsed -> FAIL TRIVY-CRIT" "FAIL" "TRIVY-CRIT"
assert_has_result "2 HIGH vulnerabilities parsed -> FAIL TRIVY-HIGH" "FAIL" "TRIVY-HIGH"
assert_has_result "1 MEDIUM finding parsed -> WARN TRIVY-MED" "WARN" "TRIVY-MED"

# ── TRIVY-001: scan fails / times out ───────────────────────────────────────

echo "=== TRIVY-001: scan fails -> warn ==="

trivy() { return 1; }
SCAN_DIR="$tmpdir/scan" run_check
assert_has_result "Trivy scan failure -> WARN TRIVY-001" "WARN" "TRIVY-001"
unset -f trivy run_with_timeout

# ── NMAP-001: enabled with targets but nmap not installed ──────────────────

echo "=== NMAP-001: nmap not installed -> skip ==="

has_command() {
  case "$1" in
    python3) return 0 ;;
    nmap) return 1 ;;
    curl) return 1 ;;
    sslscan) return 1 ;;
    testssl.sh) return 1 ;;
    trivy) return 1 ;;
    *) return 1 ;;
  esac
}
export CLAUDESEC_NETWORK_SCAN_ENABLED=1
export CLAUDESEC_NETWORK_SCAN_TARGETS="example.invalid"
SCAN_DIR="$tmpdir/scan" run_check
assert_has_result "nmap not installed -> SKIP NMAP-001" "SKIP" "NMAP-001"
unset CLAUDESEC_NETWORK_SCAN_ENABLED CLAUDESEC_NETWORK_SCAN_TARGETS
unset -f has_command

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
