#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/network/tls.sh
# Run: bash scanner/tests/test_check_network_tls.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

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
      found=true; break
    fi
  done
  if $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

run_check() {
  RESULTS=()
  source "$CHECKS_DIR/network/tls.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── NET-001: HTTPS enforcement ──

echo "=== NET-001: HTTPS enforcement ==="

# Test: Source with http:// URL -> WARN
mkdir -p "$tmpdir/http_url"
cat > "$tmpdir/http_url/app.py" <<'PY'
import requests
r = requests.get("http://api.example.com/data")
PY
SCAN_DIR="$tmpdir/http_url" run_check
assert_has_result "HTTP URL in source warns" "WARN" "NET-001"

# Test: Source with only https:// -> PASS
mkdir -p "$tmpdir/https_only"
cat > "$tmpdir/https_only/app.py" <<'PY'
import requests
r = requests.get("https://api.example.com/data")
PY
SCAN_DIR="$tmpdir/https_only" run_check
assert_has_result "HTTPS-only source passes" "PASS" "NET-001"

# Test: No source files -> SKIP
mkdir -p "$tmpdir/no_src"
echo "readme" > "$tmpdir/no_src/README.md"
SCAN_DIR="$tmpdir/no_src" run_check
assert_has_result "No source files skips NET-001" "SKIP" "NET-001"

# ── NET-002: TLS configuration ──

echo "=== NET-002: TLS configuration ==="

# Test: nginx with only TLS 1.3 -> PASS
mkdir -p "$tmpdir/tls13"
cat > "$tmpdir/tls13/nginx.conf" <<'CONF'
server {
    listen 443 ssl;
    ssl_protocols TLSv1.3;
}
CONF
SCAN_DIR="$tmpdir/tls13" run_check
assert_has_result "TLS 1.3 only configured passes" "PASS" "NET-002"

# Test: nginx with deprecated TLS 1.0 -> FAIL
mkdir -p "$tmpdir/tls10"
cat > "$tmpdir/tls10/nginx.conf" <<'CONF'
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
}
CONF
SCAN_DIR="$tmpdir/tls10" run_check
assert_has_result "Deprecated TLS 1.0 fails" "FAIL" "NET-002"

# Test: No web server config -> SKIP
mkdir -p "$tmpdir/no_web"
echo "hello" > "$tmpdir/no_web/app.py"
SCAN_DIR="$tmpdir/no_web" run_check
assert_has_result "No web server config skips NET-002" "SKIP" "NET-002"

# ── NET-004: CORS ──

echo "=== NET-004: CORS ==="

# Test: JS with CORS wildcard -> WARN
mkdir -p "$tmpdir/cors_wild"
cat > "$tmpdir/cors_wild/server.js" <<'JS'
const cors = require("cors");
app.use(cors({ origin: "*" }));
JS
SCAN_DIR="$tmpdir/cors_wild" run_check
assert_has_result "CORS wildcard origin warns" "WARN" "NET-004"

# Test: JS with restricted CORS -> PASS
mkdir -p "$tmpdir/cors_ok"
cat > "$tmpdir/cors_ok/server.js" <<'JS'
const cors = require("cors");
app.use(cors({ origin: "https://example.com" }));
JS
SCAN_DIR="$tmpdir/cors_ok" run_check
assert_has_result "Restricted CORS passes" "PASS" "NET-004"

# ── Summary ──

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
