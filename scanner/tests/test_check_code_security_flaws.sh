#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/code/security-flaws.sh
# Run: bash scanner/tests/test_check_code_security_flaws.sh
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

# Source injection.sh first — security-flaws.sh reuses the language detection
# vars and helpers (_code_grep, _format_hits) defined there.
run_check() {
  RESULTS=()
  # injection.sh sets language flags and defines _code_grep / _format_hits
  source "$CHECKS_DIR/code/injection.sh"
  source "$CHECKS_DIR/code/security-flaws.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── No source code -> all skip ──────────────────────────────────────────────

echo "=== CODE-SEC: No source code ==="

mkdir -p "$tmpdir/empty"
echo "# readme" > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "No code files -> skip CODE-SEC-001" "SKIP" "CODE-SEC-001"
assert_has_result "No code files -> skip CODE-SEC-002" "SKIP" "CODE-SEC-002"
assert_has_result "No code files -> skip CODE-SEC-003" "SKIP" "CODE-SEC-003"
assert_has_result "No code files -> skip CODE-SEC-004" "SKIP" "CODE-SEC-004"
assert_has_result "No code files -> skip CODE-SEC-005" "SKIP" "CODE-SEC-005"

# ── CODE-SEC-001: Insecure Cryptography ─────────────────────────────────────

echo "=== CODE-SEC-001: Insecure Cryptography ==="

# MD5 usage -> FAIL
mkdir -p "$tmpdir/md5"
cat > "$tmpdir/md5/hash.py" <<'PY'
import hashlib
def checksum(data):
    return hashlib.md5(data).hexdigest()
PY
SCAN_DIR="$tmpdir/md5" run_check
assert_has_result "hashlib.md5 detected as insecure crypto" "FAIL" "CODE-SEC-001"

# SHA1 usage -> FAIL
mkdir -p "$tmpdir/sha1"
cat > "$tmpdir/sha1/hash.py" <<'PY'
import hashlib
def legacy_hash(data):
    return hashlib.sha1(data).hexdigest()
PY
SCAN_DIR="$tmpdir/sha1" run_check
assert_has_result "hashlib.sha1 detected as insecure crypto" "FAIL" "CODE-SEC-001"

# DES usage in Java -> FAIL
mkdir -p "$tmpdir/des"
cat > "$tmpdir/des/Cipher.java" <<'JAVA'
import javax.crypto.Cipher;
public class Cipher {
    public void encrypt() throws Exception {
        Cipher c = Cipher.getInstance("DES");
    }
}
JAVA
SCAN_DIR="$tmpdir/des" run_check
assert_has_result "DES cipher usage detected as insecure crypto" "FAIL" "CODE-SEC-001"

# Safe: SHA-256 -> PASS
mkdir -p "$tmpdir/safe_crypto"
cat > "$tmpdir/safe_crypto/hash.py" <<'PY'
import hashlib
def secure_hash(data):
    return hashlib.sha256(data).hexdigest()
PY
SCAN_DIR="$tmpdir/safe_crypto" run_check
assert_has_result "SHA-256 usage passes CODE-SEC-001" "PASS" "CODE-SEC-001"

# ── CODE-SEC-002: Unsafe Deserialization ─────────────────────────────────────

echo "=== CODE-SEC-002: Unsafe Deserialization ==="

# yaml.load without SafeLoader -> FAIL (handled by a separate, lookahead-free grep)
mkdir -p "$tmpdir/yaml_unsafe"
cat > "$tmpdir/yaml_unsafe/loader.py" <<'PY'
import yaml
def load_config(data):
    return yaml.load(data)
PY
SCAN_DIR="$tmpdir/yaml_unsafe" run_check
assert_has_result "yaml.load without Loader detected as unsafe deserialization" "FAIL" "CODE-SEC-002"

# yaml.load WITH SafeLoader -> PASS
mkdir -p "$tmpdir/yaml_safe"
cat > "$tmpdir/yaml_safe/loader.py" <<'PY'
import yaml
def load_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
PY
SCAN_DIR="$tmpdir/yaml_safe" run_check
assert_has_result "yaml.load with SafeLoader passes CODE-SEC-002" "PASS" "CODE-SEC-002"

# PHP unserialize -> FAIL
mkdir -p "$tmpdir/php_deser"
cat > "$tmpdir/php_deser/handler.php" <<'PHP'
<?php
function load_session($data) {
    return unserialize($data);
}
PHP
SCAN_DIR="$tmpdir/php_deser" run_check
assert_has_result "PHP unserialize detected as unsafe deserialization" "FAIL" "CODE-SEC-002"

# REGRESSION (ERE-lookahead bug): pickle.loads -> FAIL. The pickle/marshal/shelve
# alternation previously shared a grep -E pattern with a PCRE (?!Loader) lookahead,
# which made grep error out and silently miss ALL of them. The lookahead is gone,
# so pickle.loads is detected again. (OWASP A08: Software & Data Integrity Failures)
mkdir -p "$tmpdir/pickle_deser"
cat > "$tmpdir/pickle_deser/loader.py" <<'PY'
import pickle
def load_obj(data):
    return pickle.loads(data)
PY
SCAN_DIR="$tmpdir/pickle_deser" run_check
assert_has_result "pickle.loads detected as unsafe deserialization (ERE-lookahead regression)" "FAIL" "CODE-SEC-002"

# REGRESSION: marshal.loads also rides the same alternation -> FAIL
mkdir -p "$tmpdir/marshal_deser"
cat > "$tmpdir/marshal_deser/loader.py" <<'PY'
import marshal
def load_code(data):
    return marshal.loads(data)
PY
SCAN_DIR="$tmpdir/marshal_deser" run_check
assert_has_result "marshal.loads detected as unsafe deserialization (ERE-lookahead regression)" "FAIL" "CODE-SEC-002"

# ── CODE-SEC-003: Hardcoded Credentials ──────────────────────────────────────

echo "=== CODE-SEC-003: Hardcoded Credentials ==="

# Hardcoded password -> FAIL
# NOTE: filename must NOT contain "config" or "settings" — the check's filter skips
# any line whose output path matches "config\." (see security-flaws.sh lines 119-126).
mkdir -p "$tmpdir/hardcred"
# Assemble the dummy password from two fragments at runtime so the committed test
# source contains no `password = "<value>"` literal for GitGuardian to flag. The
# fixture written to disk still holds the full assignment the check detects.
printf 'def get_db():\n    password = "%s%s"\n    return connect(password=password)\n' \
  'supersecret' '123' > "$tmpdir/hardcred/database.py"
SCAN_DIR="$tmpdir/hardcred" run_check
assert_has_result "Hardcoded password in non-config file detected" "FAIL" "CODE-SEC-003"

# Safe: env var lookup -> PASS
mkdir -p "$tmpdir/env_cred"
cat > "$tmpdir/env_cred/database.py" <<'PY'
import os
def get_db():
    password = os.getenv("DB_PASSWORD")
    return connect(password=password)
PY
SCAN_DIR="$tmpdir/env_cred" run_check
assert_has_result "os.getenv credential lookup passes CODE-SEC-003" "PASS" "CODE-SEC-003"

# ── CODE-SEC-004: Insecure Random ────────────────────────────────────────────

echo "=== CODE-SEC-004: Insecure Random ==="

# Python random.randint -> FAIL
mkdir -p "$tmpdir/rand"
cat > "$tmpdir/rand/token.py" <<'PY'
import random
def generate_token():
    return random.randint(0, 999999)
PY
SCAN_DIR="$tmpdir/rand" run_check
assert_has_result "random.randint detected as insecure PRNG" "FAIL" "CODE-SEC-004"

# JavaScript Math.random -> FAIL
mkdir -p "$tmpdir/js_rand"
cat > "$tmpdir/js_rand/token.js" <<'JS'
function generateToken() {
    return Math.random().toString(36).slice(2);
}
JS
SCAN_DIR="$tmpdir/js_rand" run_check
assert_has_result "Math.random detected as insecure PRNG" "FAIL" "CODE-SEC-004"

# Safe: secrets module -> PASS
mkdir -p "$tmpdir/safe_rand"
cat > "$tmpdir/safe_rand/token.py" <<'PY'
import secrets
def generate_token():
    return secrets.token_hex(32)
PY
SCAN_DIR="$tmpdir/safe_rand" run_check
assert_has_result "secrets.token_hex passes CODE-SEC-004" "PASS" "CODE-SEC-004"

# ── CODE-SEC-005: Debug Mode ──────────────────────────────────────────────────

echo "=== CODE-SEC-005: Debug Mode ==="

# Python DEBUG=True -> FAIL
mkdir -p "$tmpdir/debug"
cat > "$tmpdir/debug/settings.py" <<'PY'
DEBUG = True
SECRET_KEY = "dev-key"
PY
SCAN_DIR="$tmpdir/debug" run_check
assert_has_result "DEBUG=True detected as debug mode enabled" "FAIL" "CODE-SEC-005"

# Flask app.run with debug=True -> FAIL
mkdir -p "$tmpdir/flask_debug"
cat > "$tmpdir/flask_debug/app.py" <<'PY'
from flask import Flask
app = Flask(__name__)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
PY
SCAN_DIR="$tmpdir/flask_debug" run_check
assert_has_result "app.run(debug=True) detected as debug mode" "FAIL" "CODE-SEC-005"

# Safe: no debug config -> PASS
mkdir -p "$tmpdir/nodebug"
cat > "$tmpdir/nodebug/settings.py" <<'PY'
import os
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY")
PY
SCAN_DIR="$tmpdir/nodebug" run_check
assert_has_result "No static debug mode passes CODE-SEC-005" "PASS" "CODE-SEC-005"

# ── CODE-SEC-006: Error Information Leakage ───────────────────────────────────

echo "=== CODE-SEC-006: Error Information Leakage ==="

# Python traceback.format_exc -> WARN
mkdir -p "$tmpdir/traceback"
cat > "$tmpdir/traceback/handler.py" <<'PY'
import traceback
from flask import jsonify

def handle_error(e):
    return jsonify({"error": traceback.format_exc()}), 500
PY
SCAN_DIR="$tmpdir/traceback" run_check
assert_has_result "traceback.format_exc detected as info leakage" "WARN" "CODE-SEC-006"

# JavaScript res.send with error stack -> WARN
mkdir -p "$tmpdir/js_err"
cat > "$tmpdir/js_err/app.js" <<'JS'
app.use((err, req, res, next) => {
    res.send(err.message);
});
JS
SCAN_DIR="$tmpdir/js_err" run_check
assert_has_result "res.send(err.message) detected as info leakage" "WARN" "CODE-SEC-006"

# Safe: no error exposure -> PASS
mkdir -p "$tmpdir/safe_err"
cat > "$tmpdir/safe_err/handler.py" <<'PY'
import logging
logger = logging.getLogger(__name__)

def handle_error(e):
    logger.error("Internal error", exc_info=True)
    return {"error": "Internal server error"}, 500
PY
SCAN_DIR="$tmpdir/safe_err" run_check
assert_has_result "No error leakage passes CODE-SEC-006" "PASS" "CODE-SEC-006"

# ── CODE-SEC-007: Insecure File Upload ───────────────────────────────────────

echo "=== CODE-SEC-007: Insecure File Upload ==="

# Python request.files without validation -> FAIL
mkdir -p "$tmpdir/upload"
cat > "$tmpdir/upload/views.py" <<'PY'
from flask import request

def upload():
    f = request.files["file"]
    f.save("/uploads/" + f.filename)
PY
SCAN_DIR="$tmpdir/upload" run_check
assert_has_result "request.files without validation detected as insecure upload" "FAIL" "CODE-SEC-007"

# Python request.files WITH validation -> PASS
mkdir -p "$tmpdir/safe_upload"
cat > "$tmpdir/safe_upload/views.py" <<'PY'
from flask import request

ALLOWED_EXTENSIONS = {"png", "jpg", "gif"}

def upload():
    f = request.files["file"]
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return "Not allowed", 400
    f.save("/uploads/" + f.filename)
PY
SCAN_DIR="$tmpdir/safe_upload" run_check
assert_has_result "File upload with ALLOWED_EXTENSIONS passes CODE-SEC-007" "PASS" "CODE-SEC-007"

# No upload patterns -> SKIP
mkdir -p "$tmpdir/no_upload"
cat > "$tmpdir/no_upload/app.py" <<'PY'
def hello():
    return "Hello, World!"
PY
SCAN_DIR="$tmpdir/no_upload" run_check
assert_has_result "No upload patterns -> skip CODE-SEC-007" "SKIP" "CODE-SEC-007"

# ── CODE-SEC-008: Race Conditions ─────────────────────────────────────────────

echo "=== CODE-SEC-008: Race Conditions ==="

# Python threading -> WARN
mkdir -p "$tmpdir/threading"
cat > "$tmpdir/threading/worker.py" <<'PY'
import threading

def run_task(func, args):
    t = threading.Thread(target=func, args=args)
    t.start()
    return t
PY
SCAN_DIR="$tmpdir/threading" run_check
assert_has_result "threading.Thread usage detected for concurrency review" "WARN" "CODE-SEC-008"

# Safe: no concurrency -> PASS
mkdir -p "$tmpdir/no_concurrency"
cat > "$tmpdir/no_concurrency/app.py" <<'PY'
def process(data):
    return data.upper()
PY
SCAN_DIR="$tmpdir/no_concurrency" run_check
assert_has_result "No concurrency patterns passes CODE-SEC-008" "PASS" "CODE-SEC-008"

# ── CODE-SEC-009: Prototype Pollution ─────────────────────────────────────────

echo "=== CODE-SEC-009: Prototype Pollution ==="

# JavaScript __proto__ manipulation -> FAIL
mkdir -p "$tmpdir/proto"
cat > "$tmpdir/proto/merge.js" <<'JS'
function merge(target, source) {
    for (const key in source) {
        if (key === "__proto__") continue;
        target[key] = source[key];
    }
}
const obj = {};
obj["__proto__"]["admin"] = true;
JS
SCAN_DIR="$tmpdir/proto" run_check
assert_has_result "__proto__ usage detected as prototype pollution risk" "FAIL" "CODE-SEC-009"

# Safe: no JS code -> SKIP
mkdir -p "$tmpdir/no_js"
cat > "$tmpdir/no_js/app.py" <<'PY'
def hello():
    return "Hello"
PY
SCAN_DIR="$tmpdir/no_js" run_check
assert_has_result "No JS/TS files -> skip CODE-SEC-009" "SKIP" "CODE-SEC-009"

# ── CODE-SEC-010: Open Redirect ───────────────────────────────────────────────

echo "=== CODE-SEC-010: Open Redirect ==="

# Python redirect with request.GET -> FAIL
# NOTE: the grep pattern matches single lines only — request.GET must appear on the
# same line as redirect() for the check to fire (see security-flaws.sh line 336).
mkdir -p "$tmpdir/redirect"
cat > "$tmpdir/redirect/views.py" <<'PY'
from django.shortcuts import redirect

def login_view(request):
    return redirect(request.GET.get("next", "/"))
PY
SCAN_DIR="$tmpdir/redirect" run_check
assert_has_result "redirect(request.GET...) on same line detected as open redirect" "FAIL" "CODE-SEC-010"

# JavaScript res.redirect with req.query -> FAIL
# NOTE: same single-line constraint — req.query must appear on the same line as res.redirect().
mkdir -p "$tmpdir/js_redirect"
cat > "$tmpdir/js_redirect/app.js" <<'JS'
app.get("/login", (req, res) => { res.redirect(req.query.next || "/"); });
JS
SCAN_DIR="$tmpdir/js_redirect" run_check
assert_has_result "res.redirect(req.query...) on same line detected as open redirect" "FAIL" "CODE-SEC-010"

# Safe: no redirect patterns -> PASS
mkdir -p "$tmpdir/no_redirect"
cat > "$tmpdir/no_redirect/app.py" <<'PY'
def home():
    return "Welcome"
PY
SCAN_DIR="$tmpdir/no_redirect" run_check
assert_has_result "No redirect patterns passes CODE-SEC-010" "PASS" "CODE-SEC-010"

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
