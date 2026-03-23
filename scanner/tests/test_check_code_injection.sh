#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/code/injection.sh
# Run: bash scanner/tests/test_check_code_injection.sh
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

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]}"; do
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

assert_no_result() {
  local desc="$1" unexpected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]}"; do
    if [[ "$r" == "${unexpected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if ! $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (unexpected $unexpected_type:$check_id found)"
    ((TEST_FAILED++))
  fi
}

run_check() {
  RESULTS=()
  source "$CHECKS_DIR/code/injection.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── No source code -> all skip ──

echo "=== CODE-INJ: No source code ==="

mkdir -p "$tmpdir/empty"
echo "# readme" > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "No code files -> skip CODE-INJ-001" "SKIP" "CODE-INJ-001"
assert_has_result "No code files -> skip CODE-INJ-002" "SKIP" "CODE-INJ-002"
assert_has_result "No code files -> skip CODE-INJ-003" "SKIP" "CODE-INJ-003"

# ── CODE-INJ-001: SQL Injection ──

echo "=== CODE-INJ-001: SQL Injection ==="

# Test: Python with f-string SQL -> FAIL
mkdir -p "$tmpdir/sqli"
cat > "$tmpdir/sqli/app.py" <<'PY'
import sqlite3
def get_user(name):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
PY
SCAN_DIR="$tmpdir/sqli" run_check
assert_has_result "Python f-string SQL injection detected" "FAIL" "CODE-INJ-001"

# Test: Python with parameterized query -> PASS
mkdir -p "$tmpdir/safe_sql"
cat > "$tmpdir/safe_sql/app.py" <<'PY'
import sqlite3
def get_user(name):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()
PY
SCAN_DIR="$tmpdir/safe_sql" run_check
assert_has_result "Parameterized SQL query passes" "PASS" "CODE-INJ-001"

# ── CODE-INJ-002: Command Injection ──

echo "=== CODE-INJ-002: Command Injection ==="

# Test: Python os.system with f-string (user input concat) -> FAIL
mkdir -p "$tmpdir/cmdi"
cat > "$tmpdir/cmdi/run.py" <<'PY'
import os
def execute(user_input):
    os.system(f"echo {user_input}")
PY
SCAN_DIR="$tmpdir/cmdi" run_check
assert_has_result "os.system with f-string detected" "FAIL" "CODE-INJ-002"

# Test: Python subprocess.run with shell=True -> FAIL
mkdir -p "$tmpdir/cmdi2"
cat > "$tmpdir/cmdi2/run.py" <<'PY'
import subprocess
def execute(cmd):
    subprocess.run(cmd, shell=True)
PY
SCAN_DIR="$tmpdir/cmdi2" run_check
assert_has_result "shell=True detected as command injection" "FAIL" "CODE-INJ-002"

# Test: Python subprocess with list args (safe) -> PASS
mkdir -p "$tmpdir/safe_cmd"
cat > "$tmpdir/safe_cmd/run.py" <<'PY'
import subprocess
def execute(args):
    subprocess.run(["ls", "-la"], check=True)
PY
SCAN_DIR="$tmpdir/safe_cmd" run_check
assert_has_result "subprocess.run with list args passes" "PASS" "CODE-INJ-002"

# ── CODE-INJ-003: XSS ──

echo "=== CODE-INJ-003: XSS ==="

# Test: JS with innerHTML assignment -> FAIL
mkdir -p "$tmpdir/xss"
cat > "$tmpdir/xss/app.js" <<'JS'
function render(input) {
  document.getElementById("output").innerHTML = input;
}
JS
SCAN_DIR="$tmpdir/xss" run_check
assert_has_result "innerHTML assignment detected as XSS" "FAIL" "CODE-INJ-003"

# ── CODE-INJ-004: Path Traversal ──

echo "=== CODE-INJ-004: Path Traversal ==="

# Test: Python with request-based path traversal -> FAIL
mkdir -p "$tmpdir/pathtr"
cat > "$tmpdir/pathtr/serve.py" <<'PY'
from flask import request
import os
def read_file():
    path = os.path.join("/data", request.args.get("file"))
    return open(path).read()
PY
SCAN_DIR="$tmpdir/pathtr" run_check
assert_has_result "os.path.join with request input detected" "FAIL" "CODE-INJ-004"

# ── Summary ──

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
