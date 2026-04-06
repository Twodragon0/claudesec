#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/access-control/secrets-scan.sh
# Run: bash scanner/tests/test_check_access_control.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
FORMAT="text"
QUIET=1
SEVERITY="low"

# Capture results
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }

# Stub JSON functions from output.sh
append_json() { :; }
_emit_finding_json() { :; }
JSON_RESULTS=""
TOTAL_CHECKS=0
PASSED_COUNT=0
FAILED_COUNT=0
WARNINGS=0
SKIPPED=0

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
  ENV_SCAN_FILES=()
  source "$CHECKS_DIR/access-control/secrets-scan.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── SECRETS-001: Hardcoded credentials in source code ──

echo "=== SECRETS-001: Hardcoded credentials in source ==="

# Test: File with AWS key pattern -> FAIL
mkdir -p "$tmpdir/aws_leak/src"
cat > "$tmpdir/aws_leak/src/config.py" <<'PY'
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
PY
SCAN_DIR="$tmpdir/aws_leak" run_check
assert_has_result "AWS key in source detected" "FAIL" "SECRETS-001"

# Test: File with GitHub token -> FAIL
mkdir -p "$tmpdir/gh_leak/src"
cat > "$tmpdir/gh_leak/src/deploy.sh" <<'SH'
#!/bin/bash
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
SH
SCAN_DIR="$tmpdir/gh_leak" run_check
assert_has_result "GitHub token in source detected" "FAIL" "SECRETS-001"

# Test: Clean source code -> PASS
mkdir -p "$tmpdir/clean/src"
cat > "$tmpdir/clean/src/app.py" <<'PY'
import os
api_key = os.environ.get("API_KEY")
PY
SCAN_DIR="$tmpdir/clean" run_check
assert_has_result "Clean code passes credential scan" "PASS" "SECRETS-001"

# ── SECRETS-002: .env file credentials ──

echo "=== SECRETS-002: .env file credentials ==="

# Test: .env with real-looking value in non-allowlisted path -> FAIL (real risk)
mkdir -p "$tmpdir/env_real"
cat > "$tmpdir/env_real/.env" <<'ENV'
DATADOG_KEY=abcdef1234567890abcdef1234567890
API_KEY=real_key_value_12345
ENV
cat > "$tmpdir/env_real/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/env_real" run_check
assert_has_result ".env with real values fails in non-allowlisted path" "FAIL" "SECRETS-002"

# Test: .env with real-looking value in allowlisted templates path -> WARN
mkdir -p "$tmpdir/env_allowlisted/templates"
cat > "$tmpdir/env_allowlisted/templates/.env" <<'ENV'
API_KEY=real_key_value_12345
CLIENT_SECRET=client_secret_live_value
NPM_TOKEN=npm_live_token_1234567890
ENV
cat > "$tmpdir/env_allowlisted/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/env_allowlisted" run_check
assert_has_result ".env with real values warns in allowlisted path" "WARN" "SECRETS-002"

# Test: .env with placeholder values -> PASS
mkdir -p "$tmpdir/env_placeholder"
cat > "$tmpdir/env_placeholder/.env" <<'ENV'
API_KEY=YOUR_API_KEY_HERE
TOKEN=CHANGE_ME
ENV
cat > "$tmpdir/env_placeholder/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/env_placeholder" run_check
assert_has_result ".env with placeholders passes" "PASS" "SECRETS-002"

# Test: No .env file at all -> SKIP
mkdir -p "$tmpdir/no_env"
cat > "$tmpdir/no_env/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/no_env" run_check
assert_has_result "No .env file skips SECRETS-002" "SKIP" "SECRETS-002"

# ── SECRETS-004: Credential file path references ──

echo "=== SECRETS-004: Credential file path references ==="

# Test: Credential path in source code (non-allowlisted) -> FAIL
mkdir -p "$tmpdir/cred_risk/src"
cat > "$tmpdir/cred_risk/src/main.sh" <<'SH'
#!/usr/bin/env bash
AWS_SHARED_CREDENTIALS_FILE="$HOME/.aws/credentials"
SH
SCAN_DIR="$tmpdir/cred_risk" run_check
assert_has_result "Credential path in source fails" "FAIL" "SECRETS-004"

# Test: Credential path in allowlisted template file -> WARN
mkdir -p "$tmpdir/cred_allowlisted/templates"
cat > "$tmpdir/cred_allowlisted/templates/guide.yml" <<'YAML'
aws_credentials_file: ~/.aws/credentials
YAML
SCAN_DIR="$tmpdir/cred_allowlisted" run_check
assert_has_result "Credential path in template warns" "WARN" "SECRETS-004"

# Test: No credential path references -> PASS
mkdir -p "$tmpdir/cred_clean/src"
cat > "$tmpdir/cred_clean/src/main.py" <<'PY'
print("clean")
PY
SCAN_DIR="$tmpdir/cred_clean" run_check
assert_has_result "No credential path references pass" "PASS" "SECRETS-004"

# ── Summary ──

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
