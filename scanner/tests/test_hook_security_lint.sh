#!/usr/bin/env bash
# Unit tests for hooks/security-lint.sh — the Claude Code PreToolUse security hook.
# Run: bash scanner/tests/test_hook_security_lint.sh
#
# Contract under test (https://code.claude.com/docs/en/hooks; field names verified
# against the shipped @anthropic-ai/claude-code SDK tool schema):
#   - The hook receives the PreToolUse event as JSON on STDIN (NOT positional args).
#   - The written text lives in tool_input.content (Write) / tool_input.new_string
#     (Edit); tool_input.file_path is the operation's own (always absolute) target
#     and must NOT be scanned, or every real write would be blocked.
#   - BLOCK = exit code 2 (stderr shown to Claude); ALLOW = exit code 0.
#
# Regression guards:
#   - An earlier version read $1/$2 positional args, so $CONTENT was always empty
#     and the hook silently exited 0 — never blocking anything.
#   - A follow-up regression scanned file_path too, blocking EVERY write whose
#     target sat under /Users/… or /home/… (i.e. essentially all real writes).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../../hooks/security-lint.sh"

TEST_PASSED=0
TEST_FAILED=0

if ! command -v jq >/dev/null 2>&1; then
  echo "FATAL: jq is required to build JSON payloads for this test." >&2
  exit 1
fi

# Build a PreToolUse Write event JSON. Args: file_path, content.
write_payload() {
  jq -nc --arg fp "$1" --arg c "$2" \
    '{tool_name: "Write", tool_input: {file_path: $fp, content: $c}}'
}
# Build a PreToolUse Edit event JSON. Args: file_path, new_string.
edit_payload() {
  jq -nc --arg fp "$1" --arg s "$2" \
    '{tool_name: "Edit", tool_input: {file_path: $fp, old_string: "x", new_string: $s}}'
}

# Run the hook with a payload on stdin; echo its exit code (never aborts the suite).
run_hook() {
  printf '%s' "$1" | bash "$HOOK" >/dev/null 2>&1
  printf '%s' "$?"
}

# Run the hook with jq hidden from PATH, to exercise the raw-stdin fallback.
# The shim PATH holds symlinks to the real coreutils the hook needs (cat/sed/grep)
# but deliberately no jq, so `command -v jq` fails and the fallback path runs.
run_hook_no_jq() {
  local shim b real; shim="$(mktemp -d)"
  for b in cat sed grep; do
    real="$(command -v "$b" 2>/dev/null)" && [[ -n "$real" ]] && ln -s "$real" "$shim/$b"
  done
  printf '%s' "$1" | PATH="$shim" /bin/bash "$HOOK" >/dev/null 2>&1
  local rc=$?
  rm -rf "$shim"
  printf '%s' "$rc"
}

assert_exit() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected exit $expected, got $actual)"; ((TEST_FAILED++))
  fi
}

# Secret-shaped strings are assembled from fragments so no contiguous credential
# pattern lands in this source file (repo push-protection / gitleaks would block it).
aws_key="AKIA""IOSFODNN7EXAMPLE"                      # AKIA + 16 chars, split in source
pk_hdr="-----BEGIN"" RSA PRIVATE KEY-----"            # private-key header, split in source
pw_line='password = "hunter2hunter2"'                 # hardcoded password pattern

# Absolute paths are assembled from this leading fragment so the literal
# "/Users/<name>/" pattern never appears in this source (repo pii-check flags
# it); the runtime value still exercises the hook's personal-path detector.
U="/Users/"
personal_in_body="DATA_DIR = \"${U}alice/secret/data\""   # personal path inside content

# A realistic absolute target path (the shape Claude Code actually sends).
ABS="${U}dev/project/src/app.py"

echo "== hooks/security-lint.sh (PreToolUse stdin contract) =="

# --- BLOCKING cases (exit 2): secret is in the WRITTEN content ---
assert_exit "Write content with AWS access key blocks" 2 "$(run_hook "$(write_payload "$ABS" "$aws_key")")"
assert_exit "Write content with private key header blocks" 2 "$(run_hook "$(write_payload "$ABS" "$pk_hdr")")"
assert_exit "Write content with hardcoded password blocks" 2 "$(run_hook "$(write_payload "$ABS" "$pw_line")")"
assert_exit "Write content with personal path in body blocks" 2 "$(run_hook "$(write_payload "$ABS" "$personal_in_body")")"
assert_exit "Edit new_string with AWS key blocks" 2 "$(run_hook "$(edit_payload "$ABS" "$aws_key")")"

# --- ALLOW cases (exit 0) ---
# CRITICAL regression guard: an absolute target path with clean content must NOT
# block. file_path is /Users/... — if it were scanned, this would wrongly block.
assert_exit "absolute file_path + clean content is allowed" 0 \
  "$(run_hook "$(write_payload "$ABS" 'def add(a, b):
    return a + b
')")"
assert_exit "clean Edit under /home is allowed" 0 \
  "$(run_hook "$(edit_payload "/home/runner/work/repo/repo/x.py" "return 42")")"
assert_exit "warning-only pattern (http://) does not block" 0 \
  "$(run_hook "$(write_payload "$ABS" 'See http://example.com for the legacy portal.')")"
assert_exit "payload with no writable content is allowed" 0 \
  "$(run_hook "$(jq -nc '{tool_name:"Write", tool_input:{file_path:"/x/empty.txt"}}')")"

# --- Fallback path (jq absent): must still fail-closed on secrets ---
# JSON-escapes \" around the value; the fallback de-escapes so the pattern matches.
assert_exit "no-jq fallback still blocks hardcoded password" 2 \
  "$(run_hook_no_jq "$(write_payload "$ABS" "$pw_line")")"
assert_exit "no-jq fallback still blocks AWS key" 2 \
  "$(run_hook_no_jq "$(write_payload "$ABS" "$aws_key")")"
assert_exit "no-jq fallback allows clean content" 0 \
  "$(run_hook_no_jq "$(write_payload "$ABS" "just some clean text here")")"

echo ""
echo "Passed: $TEST_PASSED  Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]]
