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
# SECOND ROUND — the fix's own fail-opens
#   Adversarial review of the first version of the fix found THREE fail-open
#   paths that `main` did not have, and mutation-testing this file showed why
#   they survived: removing `--diff-filter=ACMR` or `|| continue` left it at
#   14/14. The assertions could not see the constructs that caused the bugs.
#   Each is now pinned to its construct:
#     - TYPE CHANGE (`T`): `ACMR` omits it, so a symlink replaced by a real file
#       carrying a secret was never scanned. Filter is now `d` (exclude
#       deletions).
#     - `:<path>` STAGE SPEC: a staged `0:notes.txt` is parsed as *stage 0 of
#       notes.txt*, so the hook either skipped it or scanned an unrelated decoy
#       and read clean. The blob is now addressed by OID from `--raw`.
#     - UNWRITABLE TMPDIR: `mktemp` failed, `pii-check.sh` has no `set -e`, and
#       the gate exited 0 having scanned nothing. Both hooks now fail closed, as
#       does an unreadable staged blob.
#   Also pinned forward, not as a regression: a RENAME's raw record carries TWO
#   paths and the DESTINATION is the one entering the commit. Verified by
#   mutation (dropping the second-path read makes both rename cases fail).
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

# --- the three fail-opens adversarial review found in the FIRST version of this
# --- fix, each pinned to the construct responsible ------------------------------

# TYPE CHANGE (status `T`): a symlink in HEAD, staged as a regular file carrying
# $2. Pins `--diff-filter=d` (exclude deletions) against the original
# `--diff-filter=ACMR`, which omits `T` and never scanned this at all.
run_staged_typechange() {
  local hook="$1" body="$2" rc
  reset_repo
  ln -sf f.txt "$REPO/lnk.txt"
  git -C "$REPO" add lnk.txt
  git -C "$REPO" commit -q -m symlink --no-verify
  rm -f "$REPO/lnk.txt"
  printf '%s\n' "$body" >"$REPO/lnk.txt"
  git -C "$REPO" add lnk.txt
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  # Drop the symlink commit so later cases reset to the plain baseline.
  git -C "$REPO" reset -q --hard HEAD~1
  printf '%s' "$rc"
}

# STAGE-SPEC AMBIGUITY: a path literally named `0:notes.txt`, with a decoy
# `notes.txt` also staged. `git show ":0:notes.txt"` (and `cat-file blob` on the
# same string) parses that as *stage 0 of notes.txt* and returns the DECOY's
# content, so the gate read clean. Pins addressing the blob by OID.
run_staged_colon_path() {
  local hook="$1" body="$2" rc
  reset_repo
  printf '%s\n' "$body" >"$REPO/0:notes.txt"
  printf 'nothing to see here\n' >"$REPO/notes.txt"
  git -C "$REPO" add -- '0:notes.txt' notes.txt
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  reset_repo
  rm -f "$REPO/0:notes.txt" "$REPO/notes.txt"
  printf '%s' "$rc"
}

# RENAME (status `R`, TWO paths in the raw record): the DESTINATION is the path
# entering the commit and the one that must be reported. Pins the second-path
# read; without it the parser desynchronises and mis-pairs metadata with paths.
run_staged_rename() {
  local hook="$1" body="$2" rc out
  reset_repo
  printf '%s\n' "$body" >"$REPO/src.txt"
  git -C "$REPO" add src.txt
  git -C "$REPO" commit -q -m rename-src --no-verify
  git -C "$REPO" mv src.txt dst.txt
  out="$(cd "$REPO" && bash "$hook" 2>&1)"
  rc=$?
  git -C "$REPO" reset -q --hard HEAD~1
  rm -f "$REPO/src.txt" "$REPO/dst.txt"
  # Report the exit code only when the DESTINATION path was named.
  case "$out" in
    *dst.txt*) printf '%s' "$rc" ;;
    *) printf 'reported-wrong-path' ;;
  esac
}

# UNWRITABLE TMPDIR: `mktemp` fails. pii-check.sh has no `set -e`, so the
# redirect failed per file, the loop swallowed it, and the gate exited 0 having
# scanned nothing — a full or read-only /tmp turned the whole gate off, green.
# Pins the explicit mktemp check. MUST fail closed.
run_staged_no_tmpdir() {
  local hook="$1" body="$2" rc ro
  reset_repo
  printf '%s\n' "$body" >"$REPO/f.txt"
  git -C "$REPO" add f.txt
  ro="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-ro.XXXXXX")"
  chmod 500 "$ro"
  (cd "$REPO" && TMPDIR="$ro/" bash "$hook" >/dev/null 2>&1)
  rc=$?
  chmod 700 "$ro"
  rm -rf "$ro"
  printf '%s' "$rc"
}

# UNREADABLE BLOB: the index references an object that is gone, so
# `git cat-file blob <oid>` fails. The original `|| continue` skipped the file
# silently; a file that could not be scanned must BLOCK, not pass.
run_staged_missing_object() {
  local hook="$1" body="$2" rc oid objpath
  reset_repo
  printf '%s\n' "$body" >"$REPO/f.txt"
  git -C "$REPO" add f.txt
  oid="$(git -C "$REPO" rev-parse :f.txt)"
  objpath="$REPO/.git/objects/${oid:0:2}/${oid:2}"
  # A packed object would not be at that path; this repo is loose-only.
  if [ ! -f "$objpath" ]; then
    printf 'no-loose-object'
    return
  fi
  rm -f "$objpath"
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
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

# --- The three fail-opens review found in the first version of the fix ---------
# Each is pinned to the construct responsible, because mutation testing showed
# the assertions above survive removing `--diff-filter=ACMR` and `|| continue`
# untouched: 14/14 either way. An assertion set that cannot see a construct is
# not coverage of it.

assert_exit "secret-check: symlink->file TYPE CHANGE with a secret is detected" 1 \
  "$(run_staged_typechange "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: symlink->file TYPE CHANGE with PII is detected" 1 \
  "$(run_staged_typechange "$PII_HOOK" "$PII_BAD")"

assert_exit "secret-check: a '0:'-prefixed path is not read as stage 0 of a decoy" 1 \
  "$(run_staged_colon_path "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: a '0:'-prefixed path is not read as stage 0 of a decoy" 1 \
  "$(run_staged_colon_path "$PII_HOOK" "$PII_BAD")"

assert_exit "secret-check: a RENAME reports the destination path" 1 \
  "$(run_staged_rename "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: a RENAME reports the destination path" 1 \
  "$(run_staged_rename "$PII_HOOK" "$PII_BAD")"

assert_exit "secret-check: an unwritable TMPDIR fails CLOSED" 1 \
  "$(run_staged_no_tmpdir "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: an unwritable TMPDIR fails CLOSED" 1 \
  "$(run_staged_no_tmpdir "$PII_HOOK" "$PII_BAD")"

assert_exit "secret-check: an unreadable staged blob fails CLOSED" 1 \
  "$(run_staged_missing_object "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: an unreadable staged blob fails CLOSED" 1 \
  "$(run_staged_missing_object "$PII_HOOK" "$PII_BAD")"

echo ""
echo "Passed: $TEST_PASSED  Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]]
