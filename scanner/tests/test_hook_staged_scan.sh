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

# GITLINK (submodule, mode 160000): has no blob. Pins the mode skip, which is
# load-bearing in the OTHER direction from everything else here — dropping it
# makes every submodule commit hit the unreadable-blob branch and be FALSELY
# BLOCKED, and review measured the suite staying 24/24 green while it did.
# Set up ONCE and run both hooks against the same staged gitlink: a submodule
# cannot be re-added at the same path after removal (`.git/modules/<name>`
# survives), and building the fixture twice also doubled the cost of the
# slowest case in the file. Sets SUB_SECRET_RC and SUB_PII_RC.
SUB_SECRET_RC=""
SUB_PII_RC=""
setup_submodule_case() {
  local sub
  reset_repo
  sub="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-sub.XXXXXX")"
  git -C "$sub" init -q .
  git -C "$sub" config user.email "test@example.com"
  git -C "$sub" config user.name "test"
  printf 'inner\n' >"$sub/inner.txt"
  git -C "$sub" add inner.txt
  git -C "$sub" commit -q -m inner --no-verify
  # -c protocol.file.allow=always: git >=2.38 refuses file:// submodules by
  # default (CVE-2022-39253). Local fixture, no network.
  if ! git -C "$REPO" -c protocol.file.allow=always \
    submodule add -q "$sub" mysub >/dev/null 2>&1; then
    rm -rf "$sub"
    SUB_SECRET_RC="submodule-add-unavailable"
    SUB_PII_RC="submodule-add-unavailable"
    return
  fi
  (cd "$REPO" && bash "$SECRET_HOOK" >/dev/null 2>&1)
  SUB_SECRET_RC=$?
  (cd "$REPO" && bash "$PII_HOOK" >/dev/null 2>&1)
  SUB_PII_RC=$?
  git -C "$REPO" submodule deinit -qf mysub >/dev/null 2>&1
  git -C "$REPO" rm -qf mysub >/dev/null 2>&1
  rm -rf "$sub" "$REPO/.gitmodules"
  reset_repo
}

# NOT INSIDE A REPOSITORY: the enumeration would come back empty and the hook
# would exit 0 having scanned nothing — the last fail-open in the staged path.
run_staged_outside_repo() {
  local hook="$1" rc dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-norepo.XXXXXX")"
  (cd "$dir" && GIT_CEILING_DIRECTORIES="$dir" bash "$hook" >/dev/null 2>&1)
  rc=$?
  rm -rf "$dir"
  printf '%s' "$rc"
}

# PARTIAL CLONE (`--filter=blob:none`), the case that makes the local-probe /
# bounded-fetch split load-bearing. A staged OID whose blob was never fetched is
# legitimately non-local with NOTHING corrupted, so:
#   - remote reachable   -> the hook must hydrate it and NOT block a clean commit
#   - remote unreachable -> it must fail closed
# Review found that refusing unconditionally (`GIT_NO_LAZY_FETCH=1` on the read
# itself) false-blocked the reachable case, which is the standard large-monorepo
# setup. Order matters: the unreachable runs go FIRST, because a successful run
# caches the object and a later offline test would then pass for the wrong
# reason. Transport is `file://` — local, no network.
# Sets PC_OFFLINE_SECRET_RC / PC_OFFLINE_PII_RC / PC_ONLINE_SECRET_RC /
# PC_ONLINE_PII_RC.
PC_OFFLINE_SECRET_RC=""
PC_OFFLINE_PII_RC=""
PC_ONLINE_SECRET_RC=""
PC_ONLINE_PII_RC=""
setup_partial_clone_case() {
  local src clone i
  src="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-pcsrc.XXXXXX")"
  git -C "$src" init -q .
  git -C "$src" config user.email "test@example.com"
  git -C "$src" config user.name "test"
  git -C "$src" config uploadpack.allowFilter true
  # The OLD revision is CLEAN: "must not block" is then unambiguous.
  printf 'old but clean\n' >"$src/h.txt"
  git -C "$src" add h.txt
  git -C "$src" commit -q -m v0 --no-verify
  for i in 1 2 3; do
    printf 'newer %s\n' "$i" >"$src/h.txt"
    git -C "$src" add h.txt
    git -C "$src" commit -q -m "v$i" --no-verify
  done

  clone="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-pcclone.XXXXXX")"
  rmdir "$clone"
  # -c protocol.file.allow=always for the same reason the submodule fixture needs
  # it: a hardened config makes the clone fail and turns four assertions into
  # loud FAILs for environmental reasons. It covers `protocol.file.allow=never`
  # AND `protocol.allow=never` — `protocol.<name>.allow` takes precedence over
  # `protocol.allow`, verified with a real `GIT_CONFIG_GLOBAL`: without the -c the
  # clone dies in ~1s with `fatal: transport 'file' not allowed`, with it the
  # clone succeeds. (An earlier note here claimed that config HANGS; that was an
  # artifact of the probe harness measuring it, not git. Corrected rather than
  # left, because a recorded phantom is something a future reader plans around.)
  # It does NOT rescue a restrictive `GIT_ALLOW_PROTOCOL` env var, which no -c can
  # override; that fails fast and loud.
  if ! git -c protocol.file.allow=always clone -q --filter=blob:none \
    --no-local "file://$src" "$clone" 2>/dev/null; then
    rm -rf "$src"
    PC_OFFLINE_SECRET_RC="partial-clone-unavailable"
    PC_OFFLINE_PII_RC="partial-clone-unavailable"
    PC_ONLINE_SECRET_RC="partial-clone-unavailable"
    PC_ONLINE_PII_RC="partial-clone-unavailable"
    return
  fi
  git -C "$clone" config user.email "test@example.com"
  git -C "$clone" config user.name "test"
  git -C "$clone" restore --staged --source=HEAD~3 -- h.txt

  # Confirm the fixture is actually exercising an absent object; if the blob is
  # local, both directions collapse and the assertions would be vacuous.
  local oid
  oid="$(git -C "$clone" rev-parse :h.txt)"
  if GIT_NO_LAZY_FETCH=1 git -C "$clone" cat-file -e "$oid" 2>/dev/null; then
    rm -rf "$src" "$clone"
    PC_OFFLINE_SECRET_RC="blob-unexpectedly-local"
    PC_OFFLINE_PII_RC="blob-unexpectedly-local"
    PC_ONLINE_SECRET_RC="blob-unexpectedly-local"
    PC_ONLINE_PII_RC="blob-unexpectedly-local"
    return
  fi

  # --- unreachable FIRST (no caching side effect from a successful read) ---
  git -C "$clone" remote set-url origin "file:///nonexistent-promisor-$$"
  (cd "$clone" && bash "$SECRET_HOOK" >/dev/null 2>&1)
  PC_OFFLINE_SECRET_RC=$?
  (cd "$clone" && bash "$PII_HOOK" >/dev/null 2>&1)
  PC_OFFLINE_PII_RC=$?

  # --- now reachable ---
  git -C "$clone" remote set-url origin "file://$src"
  (cd "$clone" && bash "$SECRET_HOOK" >/dev/null 2>&1)
  PC_ONLINE_SECRET_RC=$?
  (cd "$clone" && bash "$PII_HOOK" >/dev/null 2>&1)
  PC_ONLINE_PII_RC=$?

  rm -rf "$src" "$clone"
}

# RE-PROBE branch (`READ_UNDECODABLE` reached through the FALLBACK path): the
# object is absent, the lazy fetch LANDS it, and the read then fails anyway — so
# the failure is a decode, not an absence, and the advice must say so. Recipe
# from review, and the trick is that it needs no corruption and no network: a
# `--filter=tree:0` clone leaves TREES absent, and an absent tree oid staged at
# mode 100644 fetches fine and then fails on TYPE.
#
# Caveat worth knowing: the cause here is a type mismatch rather than a damaged
# store, so the message is generically right rather than precisely right. The
# input is a hand-crafted index state nobody reaches by accident; the branch is
# what is under test.
# Echoes "<rc>:<which advice>" so a collapse of rc 2 into rc 1 is visible.
run_staged_fetched_then_undecodable() {
  local hook="$1" donor clone old_tree out rc
  donor="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-t0donor.XXXXXX")"
  git -C "$donor" init -q .
  git -C "$donor" config user.email "test@example.com"
  git -C "$donor" config user.name "test"
  git -C "$donor" config uploadpack.allowFilter true
  mkdir -p "$donor/sub"
  printf 'old subtree\n' >"$donor/sub/f.txt"
  git -C "$donor" add sub/f.txt
  git -C "$donor" commit -q -m v1 --no-verify
  old_tree="$(git -C "$donor" rev-parse HEAD:sub)"
  printf 'new subtree\n' >"$donor/sub/f.txt"
  git -C "$donor" add sub/f.txt
  git -C "$donor" commit -q -m v2 --no-verify

  clone="$(mktemp -d "${TMPDIR:-/tmp}/claudesec-t0clone.XXXXXX")"
  rmdir "$clone"
  if ! git -c protocol.file.allow=always clone -q --filter=tree:0 \
    --no-local "file://$donor" "$clone" 2>/dev/null; then
    rm -rf "$donor"
    printf 'tree-filter-clone-unavailable'
    return
  fi
  git -C "$clone" config user.email "test@example.com"
  git -C "$clone" config user.name "test"
  # Vacuity guard: if the old tree is already local, the fetch never happens and
  # this exercises the probe-succeeded branch instead.
  if GIT_NO_LAZY_FETCH=1 git -C "$clone" cat-file -e "$old_tree" 2>/dev/null; then
    rm -rf "$donor" "$clone"
    printf 'tree-unexpectedly-local'
    return
  fi
  git -C "$clone" update-index --add --cacheinfo "100644,$old_tree,fake.txt"
  out="$(cd "$clone" && bash "$hook" 2>&1)"
  rc=$?
  rm -rf "$donor" "$clone"
  case "$out" in
    *"damaged object store"*) printf '%s:corrupt-advice' "$rc" ;;
    *"does NOT hydrate"*) printf '%s:absent-advice' "$rc" ;;
    *) printf '%s:no-advice' "$rc" ;;
  esac
}

# SKIP_PATTERNS was entirely unpinned across three rounds: making should_skip
# always return false left the suite green. $2 lands in a path the patterns
# exclude, so a detection here means the skip list stopped working.
run_staged_skipped_path() {
  local hook="$1" body="$2" rc
  reset_repo
  printf '%s\n' "$body" >"$REPO/deps.lock"
  git -C "$REPO" add deps.lock
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  reset_repo
  rm -f "$REPO/deps.lock"
  printf '%s' "$rc"
}

# A SKIPPED path whose blob is missing must not block: the skip decision is made
# on the path BEFORE extraction, so there is nothing to read and nothing to
# report. This is the one observable difference the pre-extraction skip makes.
run_staged_skipped_missing_object() {
  local hook="$1" rc oid objpath
  reset_repo
  printf 'anything\n' >"$REPO/deps.lock"
  git -C "$REPO" add deps.lock
  oid="$(git -C "$REPO" rev-parse :deps.lock)"
  objpath="$REPO/.git/objects/${oid:0:2}/${oid:2}"
  if [ ! -f "$objpath" ]; then
    printf 'no-loose-object'
    return
  fi
  rm -f "$objpath"
  (cd "$REPO" && bash "$hook" >/dev/null 2>&1)
  rc=$?
  reset_repo
  rm -f "$REPO/deps.lock"
  printf '%s' "$rc"
}

# CORRUPT object: PRESENT but undecodable. `cat-file -e` returns 0 (it does not
# inflate) while `cat-file blob` returns 128 — so this takes the probe-succeeded
# branch, and the advice for the ABSENT case would tell the user to run
# `git cat-file -e`, which succeeds and changes nothing. Echoes "rc:<has the
# absent-case advice>" so the assertion pins both the exit code and the fact that
# the two failures do not share a message.
run_staged_corrupt_object() {
  local hook="$1" body="$2" rc oid objpath out
  reset_repo
  printf '%s\n' "$body" >"$REPO/f.txt"
  git -C "$REPO" add f.txt
  oid="$(git -C "$REPO" rev-parse :f.txt)"
  objpath="$REPO/.git/objects/${oid:0:2}/${oid:2}"
  if [ ! -f "$objpath" ]; then
    printf 'no-loose-object'
    return
  fi
  chmod u+w "$objpath"
  printf 'not zlib at all' >"$objpath"
  out="$(cd "$REPO" && bash "$hook" 2>&1)"
  rc=$?
  reset_repo
  case "$out" in
    *"does NOT hydrate"*) printf '%s:absent-advice' "$rc" ;;
    *"damaged object store"*) printf '%s:corrupt-advice' "$rc" ;;
    *) printf '%s:no-advice' "$rc" ;;
  esac
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

# --- round 3: the mode skip is load-bearing in the FALSE-BLOCK direction -------
# Review's mutation matrix: dropping the `160000|000000` skip left the suite at
# 24/24 while false-blocking every submodule commit. These two are the only
# assertions that can see it.
setup_submodule_case
assert_exit "secret-check: a staged submodule (gitlink) does not block" 0 "$SUB_SECRET_RC"
assert_exit "pii-check: a staged submodule (gitlink) does not block" 0 "$SUB_PII_RC"

assert_exit "secret-check: outside a git repository, fails CLOSED" 1 \
  "$(run_staged_outside_repo "$SECRET_HOOK")"
assert_exit "pii-check: outside a git repository, fails CLOSED" 1 \
  "$(run_staged_outside_repo "$PII_HOOK")"

# --- round 4: the partial-clone split, and SKIP_PATTERNS ------------------------
# Both directions of the local-probe / bounded-fetch design. Refusing an absent
# object outright (the round-3 shape) false-blocks the reachable case; fetching
# unconditionally (round 2) has no bound. These four are the only assertions that
# can tell the three designs apart.
setup_partial_clone_case
assert_exit "secret-check: partial clone, remote unreachable, fails CLOSED" 1 "$PC_OFFLINE_SECRET_RC"
assert_exit "pii-check: partial clone, remote unreachable, fails CLOSED" 1 "$PC_OFFLINE_PII_RC"
assert_exit "secret-check: partial clone, remote reachable, clean commit is NOT blocked" 0 "$PC_ONLINE_SECRET_RC"
assert_exit "pii-check: partial clone, remote reachable, clean commit is NOT blocked" 0 "$PC_ONLINE_PII_RC"

assert_exit "secret-check: a SKIP_PATTERNS path is not scanned" 0 \
  "$(run_staged_skipped_path "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: a SKIP_PATTERNS path is not scanned" 0 \
  "$(run_staged_skipped_path "$PII_HOOK" "$PII_BAD")"

assert_exit "secret-check: a skipped path with a missing blob does not block" 0 \
  "$(run_staged_skipped_missing_object "$SECRET_HOOK")"
assert_exit "pii-check: a skipped path with a missing blob does not block" 0 \
  "$(run_staged_skipped_missing_object "$PII_HOOK")"

# A corrupt object is PRESENT but undecodable, so it must fail closed with the
# damaged-store advice, NOT the partial-clone advice whose suggested command
# succeeds and fixes nothing.
assert_exit "secret-check: a corrupt object fails CLOSED with damaged-store advice" \
  "1:corrupt-advice" "$(run_staged_corrupt_object "$SECRET_HOOK" "$SECRET_BAD")"
assert_exit "pii-check: a corrupt object fails CLOSED with damaged-store advice" \
  "1:corrupt-advice" "$(run_staged_corrupt_object "$PII_HOOK" "$PII_BAD")"

# The same READ_UNDECODABLE code reached through the FALLBACK path — absent, then
# fetched, then still unreadable. This was the one branch the previous round
# admitted it could not pin.
assert_exit "secret-check: fetched-then-undecodable gets damaged-store advice" \
  "1:corrupt-advice" "$(run_staged_fetched_then_undecodable "$SECRET_HOOK")"
assert_exit "pii-check: fetched-then-undecodable gets damaged-store advice" \
  "1:corrupt-advice" "$(run_staged_fetched_then_undecodable "$PII_HOOK")"

echo ""
echo "Passed: $TEST_PASSED  Failed: $TEST_FAILED"
[[ "$TEST_FAILED" -eq 0 ]]
