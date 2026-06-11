#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2034
# Live integration test for scanner/checks/macos/cis-security.sh
#
# PURPOSE:
#   Run on a real macOS runner (macos-latest).  Asserts STRUCTURE only:
#   every check ID (MAC-001..010, CIS-001..010) emits exactly one result
#   and the verdict type is one of PASS|FAIL|WARN|SKIP.  FAILs must carry
#   a severity in {critical,high,medium,low}.  Specific verdicts are NOT
#   asserted — runner security state is uncontrolled.
#
#   CIS-005 may legitimately SKIP when Homebrew is absent.
#   CIS-006 is guaranteed to emit exactly one result because we plant a
#   strong-cipher $HOME/.ssh/config so ssh_config_checked=1, ssh_ciphers_ok=1.
#
# HERMETIC GUARDS:
#   - SCAN_DIR  → fresh tmpdir (no real project files)
#   - HOME      → fresh tmpdir (no runner dotfiles; .ssh/config planted below)
#   This file is intentionally NOT listed in scanner-unit-tests in lint.yml
#   (it is macOS-only); the offline SKIP test is registered there instead.
#
# Run: bash scanner/tests/test_check_macos_cis_security_live.sh
export CLAUDESEC_DASHBOARD_OFFLINE=1
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes (checks.sh uses these for output formatting)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture pass/fail/warn/skip calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${3:-unknown}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

# shellcheck source=../lib/checks.sh
source "$LIB_DIR/checks.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

assert_exactly_one_result() {
  local check_id="$1"
  local count=0
  local verdict=""
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == PASS:"${check_id}"* || "$r" == FAIL:"${check_id}"* || \
          "$r" == WARN:"${check_id}"* || "$r" == SKIP:"${check_id}"* ]]; then
      ((count++))
      verdict="$r"
    fi
  done

  if [[ "$count" -eq 1 ]]; then
    echo "  PASS: $check_id emitted exactly one result ($verdict)"
    ((TEST_PASSED++))
  elif [[ "$count" -eq 0 ]]; then
    echo "  FAIL: $check_id emitted NO result (expected exactly 1)"
    ((TEST_FAILED++))
    return
  else
    echo "  FAIL: $check_id emitted $count results (expected exactly 1): ${RESULTS[*]:-}"
    ((TEST_FAILED++))
    return
  fi

  # Assert verdict type is one of PASS|FAIL|WARN|SKIP
  local vtype="${verdict%%:*}"
  case "$vtype" in
    PASS|FAIL|WARN|SKIP)
      echo "  PASS: $check_id verdict type '$vtype' is valid"
      ((TEST_PASSED++))
      ;;
    *)
      echo "  FAIL: $check_id verdict type '$vtype' is not PASS|FAIL|WARN|SKIP"
      ((TEST_FAILED++))
      return
      ;;
  esac

  # If FAIL, assert severity is in {critical,high,medium,low}
  if [[ "$vtype" == "FAIL" ]]; then
    # RESULTS format: FAIL:<id>:<severity>
    local severity="${verdict#"FAIL:${check_id}:"}"
    case "$severity" in
      critical|high|medium|low)
        echo "  PASS: $check_id FAIL severity '$severity' is valid"
        ((TEST_PASSED++))
        ;;
      *)
        echo "  FAIL: $check_id FAIL severity '$severity' not in {critical,high,medium,low}"
        ((TEST_FAILED++))
        ;;
    esac
  fi
}

# ---------------------------------------------------------------------------
# Setup: isolated SCAN_DIR and HOME
# ---------------------------------------------------------------------------

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

SCAN_DIR="$tmpdir/scan"
mkdir -p "$SCAN_DIR"

# Override HOME so no runner dotfiles (e.g. ~/.ssh/config) are read.
# Plant a strong-cipher ~/.ssh/config so CIS-006 reaches the PASS branch:
#   ssh_config_checked=1, ssh_ciphers_ok=1 → one result (PASS)
fake_home="$tmpdir/home"
mkdir -p "$fake_home/.ssh"
cat > "$fake_home/.ssh/config" <<'SSHCONF'
Host *
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
SSHCONF
export HOME="$fake_home"

# ---------------------------------------------------------------------------
# Run the live macOS CIS check
# ---------------------------------------------------------------------------

if [[ "$(uname)" != "Darwin" ]]; then
  echo "ERROR: this test requires macOS (Darwin). Current uname: $(uname)"
  echo "Run it on a macos-latest GitHub Actions runner or a local Mac."
  exit 1
fi

echo "=== Running live macOS CIS check on $(uname -r) ==="
echo "    SCAN_DIR=$SCAN_DIR"
echo "    HOME=$HOME"
echo ""

RESULTS=()
# shellcheck source=../checks/macos/cis-security.sh
source "$CHECKS_DIR/macos/cis-security.sh"

echo ""
echo "=== Raw RESULTS array ==="
for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
  echo "  $r"
done
echo ""

# ---------------------------------------------------------------------------
# Structural assertions: exactly one result per ID, valid type, valid severity
# ---------------------------------------------------------------------------

echo "=== Structural assertions: MAC-001..010 ==="
for id in MAC-001 MAC-002 MAC-003 MAC-004 MAC-005 \
           MAC-006 MAC-007 MAC-008 MAC-009 MAC-010; do
  assert_exactly_one_result "$id"
done

echo ""
echo "=== Structural assertions: CIS-001..010 ==="
for id in CIS-001 CIS-002 CIS-003 CIS-004 CIS-005 \
           CIS-006 CIS-007 CIS-008 CIS-009 CIS-010; do
  assert_exactly_one_result "$id"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
