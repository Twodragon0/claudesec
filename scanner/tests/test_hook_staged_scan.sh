#!/usr/bin/env bash
# Unit tests for the STAGED-MODE contract of hooks/secret-check.sh and
# hooks/pii-check.sh — the pre-commit gates ClaudeSec installs into other repos
# (hooks/README.md documents `cp secret-check.sh .git/hooks/pre-commit`, and
# scripts/setup.sh copies both into $TARGET_DIR/.claude/hooks/).
# Run: bash scanner/tests/test_hook_staged_scan.sh
#
# Contract under test
#   - With NO arguments the hook scans what `git commit` is about to write, i.e.
#     the STAGED BLOB (`git show :<path>`) — not the working-tree copy.
#   - With arguments it scans the given paths as-is (the CI path in lint.yml and
#     the pre-commit-framework path in .pre-commit-config.yaml, both of which
#     hand it a clean checkout / stashed tree).
#   - Detected -> exit 1; clean -> exit 0.
#
# Regression guards (the defect this file was written for, measured 2026-08-26)
#   Both hooks read the PATH in staged mode, so they greped the working tree:
#     - staged secret + secret edited out of the working tree -> exit 0. The
#       secret went into the commit with the gate reporting success
#       (OWASP A07 Identification & Authentication Failures / CWE-798
#       Use of Hard-coded Credentials).
#     - staged content clean + secret only in an UNSTAGED edit -> exit 1, i.e.
#       a blocked commit that contained nothing to block.
#   Wrong in both directions, from one root cause. Both directions are pinned
#   below, so a revert to path-scanning fails two named tests rather than
#   silently restoring a gate that cannot see the commit.
#
# Positive controls: each hook also gets a same-content case that MUST be
# detected, so a regex that stops matching anything fails here instead of
# reading green over a clean repo (the lint.yml `pii-check` job runs the hook
# against this repo's own files, where finding nothing is the expected result —
# that job cannot distinguish a working detector from a broken one).
#
# Hermetic: builds throwaway git repos under $TMPDIR. No network, no fixtures
# outside this file, nothing written inside the ClaudeSec checkout.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRET_HOOK="$SCRIPT_DIR/../../hooks/secret-check.sh"
PII_HOOK="$SCRIPT_DIR/../../hooks/pii-check.sh"

TEST_PASSED=0
TEST_FAILED=0

# Secret-shaped strings are assembled from fragments so no contiguous credential
# pattern lands in this source file (repo push-protection / gitleaks would block
# it). The runtime value still exercises the hooks' detectors.
AWS_KEY="AKIA""IOSFODNN7EXAMPLE"                 # AKIA + 16 chars, split in source
SECRET_BAD="aws_key = \"${AWS_KEY}\""
SECRET_OK='aws_key = "REDACTED"'

# The leading fragment is kept separate so the literal "/Users/<name>/" pattern
# never appears in this source (the repo's own pii-check scans it in CI).
U="/Users/"
PII_BAD="DATA_DIR = \"${U}alice/private/data\""
PII_OK='DATA_DIR = "~/data"'

assert_exit() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$actual" == "$expected" ]]; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected exit $expected, got $actual)"
    ((TEST_FAILED++))
  fi
}

# ONE throwaway repo, reset between cases. A repo per case cost 14 `git init`s
# and ran ~15s — the kcov job caps a single test at 30s, so a per-case repo would
# have sat one instrumentation slowdown away from a cap-hit.
REPO="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-hooktest.XXXXXX")"
trap 'rm -rf "$REPO"' EXIT
git -C "$REPO" init -q .
git -C "$REPO" config user.email "test@example.com"
git -C "$REPO" config user.name "test"
git -C "$REPO" config commit.gpgsign false
printf 'baseline\n' >"$REPO/f.txt"
git -C "$REPO" add f.txt
git -C "$REPO" commit -q -m baseline --no-verify

# Back to the baseline commit with a clean index and working tree.
reset_repo() {
  git -C "$REPO" reset -q --hard HEAD
}

# Stage $2 as f.txt, then leave $3 in the working tree, then run hook $1 in
# staged mode (no arguments). Echoes the exit code; never aborts the suite.
run_staged() {
  local hook="$1" staged="$2" worktree="$3" rc
  reset_repo
  printf '%s\n' "$staged" >"$REPO/f.txt"
  git -C "$REPO" add f.txt
  printf '%s\n' "$worktree" >"$REPO/f.txt"
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  printf '%s' "$rc"
}

# Run hook $1 in staged mode with a staged DELETION pending (no blob to read).
run_staged_deletion() {
  local hook="$1" rc
  reset_repo
  git -C "$REPO" rm -q f.txt
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  printf '%s' "$rc"
}

# Run hook $1 with an explicit path argument holding $2 (the CI / pre-commit-
# framework invocation, which must keep scanning the file it is handed).
run_with_arg() {
  local hook="$1" body="$2" rc
  reset_repo
  printf '%s\n' "$body" >"$REPO/f.txt"
  (cd "$REPO" && bash "$hook" f.txt >/dev/null 2>&1)
  rc=$?
  printf '%s' "$rc"
}

echo "== hooks/secret-check.sh + hooks/pii-check.sh (staged-mode contract) =="

# --- REGRESSION: the false-negative direction (a secret in the commit) ---
assert_exit "secret-check: staged secret, cleaned worktree, is detected" 1 \
  "$(run_staged "$SECRET_HOOK" "$SECRET_BAD" "$SECRET_OK")"
assert_exit "pii-check: staged PII, cleaned worktree, is detected" 1 \
  "$(run_staged "$PII_HOOK" "$PII_BAD" "$PII_OK")"

# --- REGRESSION: the false-alarm direction (blocked with nothing staged) ---
assert_exit "secret-check: secret only in an unstaged edit is allowed" 0 \
  "$(run_staged "$SECRET_HOOK" "$SECRET_OK" "$SECRET_BAD")"
assert_exit "pii-check: PII only in an unstaged edit is allowed" 0 \
  "$(run_staged "$PII_HOOK" "$PII_OK" "$PII_BAD")"

# --- POSITIVE CONTROLS: the detector must actually detect ---
assert_exit "secret-check: AWS key staged and in worktree is detected" 1 \
  "$(run_staged "$SECRET_HOOK" "$SECRET_BAD" "$SECRET_BAD")"
assert_exit "pii-check: personal path staged and in worktree is detected" 1 \
  "$(run_staged "$PII_HOOK" "$PII_BAD" "$PII_BAD")"

# --- Clean input must pass ---
assert_exit "secret-check: clean staged content is allowed" 0 \
  "$(run_staged "$SECRET_HOOK" "$SECRET_OK" "$SECRET_OK")"
assert_exit "pii-check: clean staged content is allowed" 0 \
  "$(run_staged "$PII_HOOK" "$PII_OK" "$PII_OK")"

# --- A staged deletion has no blob: skip it, do not fail the commit ---
assert_exit "secret-check: staged deletion does not fail the commit" 0 \
  "$(run_staged_deletion "$SECRET_HOOK")"
assert_exit "pii-check: staged deletion does not fail the commit" 0 \
  "$(run_staged_deletion "$PII_HOOK")"

# --- Argument mode is unchanged: it scans the path it is given ---
assert_exit "secret-check: argument mode still scans the given file" 1 \
  "$(run_with_arg "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: argument mode still scans the given file" 1 \
  "$(run_with_arg "$PII_HOOK" "$PII_BAD")"
assert_exit "secret-check: argument mode allows a clean file" 0 \
  "$(run_with_arg "$SECRET_HOOK" "$SECRET_OK")"
assert_exit "pii-check: argument mode allows a clean file" 0 \
  "$(run_with_arg "$PII_HOOK" "$PII_OK")"

echo ""
echo "Passed: $TEST_PASSED  Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]]
