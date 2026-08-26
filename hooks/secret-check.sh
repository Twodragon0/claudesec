#!/bin/bash
# ClaudeSec - Secret Detection Hook
# Prevents committing files that contain secrets
#
# Usage: Add as a pre-commit hook or Claude Code hook

set -euo pipefail

RED='\033[0;31m'
NC='\033[0m'

# Files to skip
SKIP_PATTERNS="(\.lock$|\.svg$|\.png$|\.jpg$|\.woff$|/node_modules/|/\.git/)"

FOUND=0

# Write the staged blob for OID $1 into $_blob. Non-zero when it cannot.
#
# Two-step on purpose. `GIT_NO_LAZY_FETCH=1` alone was WRONG: in a partial clone
# or a sparse checkout an out-of-cone blob is legitimately non-local with nothing
# corrupted, and hard-refusing it FALSE-BLOCKS a clean commit — the "gate nobody
# can get past" shape, whose only exit is `--no-verify`, i.e. the gate off.
# Fetching unconditionally was also wrong: a promisor fetch has no timeout, so a
# hanging remote hangs the commit.
#
# So: probe locally first, and only an object that is genuinely absent is allowed
# to go to the promisor — bounded by `timeout` where that exists. The common path
# (every object you just staged) is provably network-free. NOTE the honest limit:
# macOS ships neither `timeout` nor `gtimeout`, and `GIT_NO_LAZY_FETCH` predates
# git 2.36, so on those the absent-object read is unbounded, exactly as it was
# before this guard. The claim is "the common path never dials out", not "nothing
# ever can".
# Return contract — the codes are load-bearing and each maps to DIFFERENT advice:
#   0  READ_OK           blob is in "$_blob"
#   1  READ_ABSENT       not local, and could not be fetched
#   2  READ_UNDECODABLE  present locally, but git cannot output it
#
# The two failures need DIFFERENT advice — measured on a loose object overwritten
# with non-zlib bytes, `cat-file -e` returns 0 while `cat-file blob` returns 128
# with 0 bytes written, so telling that user to run `cat-file -e` (the advice for
# the absent case) sends them to a command that succeeds and changes nothing.
# That is the same dead-end shape as the earlier `git fetch` advice, one path
# over.
read_staged_blob() {
  local oid="$1"
  if GIT_NO_LAZY_FETCH=1 git cat-file -e "$oid" 2>/dev/null; then
    GIT_NO_LAZY_FETCH=1 git cat-file blob "$oid" >"$_blob" 2>/dev/null || return 2
    return 0
  fi
  local rc=0
  if command -v timeout >/dev/null 2>&1; then
    timeout 30 git cat-file blob "$oid" >"$_blob" 2>/dev/null || rc=$?
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout 30 git cat-file blob "$oid" >"$_blob" 2>/dev/null || rc=$?
  else
    git cat-file blob "$oid" >"$_blob" 2>/dev/null || rc=$?
  fi
  [ "$rc" -eq 0 ] && return 0
  # The fetch may have LANDED and the decode still failed. Re-probe: if the
  # object is local now, this is a decode problem and deserves the damaged-store
  # advice, not "missing locally, run cat-file -e" — which would succeed and fix
  # nothing. PINNED via a `--filter=tree:0` clone plus an absent TREE oid staged
  # at mode 100644: the fetch lands the object and the read then fails on TYPE,
  # which drives this branch with no corruption and no network.
  if GIT_NO_LAZY_FETCH=1 git cat-file -e "$oid" 2>/dev/null; then
    return 2
  fi
  return 1
}

# True when the PATH is one we never scan. Split out of scan_file so staged mode
# can decide BEFORE extracting a blob — otherwise a skipped 200MB .png is copied
# into $TMPDIR only to be discarded.
should_skip() {
  echo "$1" | grep -qE "$SKIP_PATTERNS"
}

scan_file() {
  local file="$1"
  # Content to grep. Defaults to the path itself (argument / CI mode, where the
  # working tree IS what gets checked); staged mode passes the extracted blob.
  local content="${2:-$1}"

  # Skip binary and irrelevant files
  if should_skip "$file"; then
    return
  fi

  # AWS keys
  if grep -qE "(AKIA|ASIA)[A-Z0-9]{16}" "$content" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} AWS key in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Generic secrets in env-like assignments
  if grep -qE "^[A-Z_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z_]*\s*=\s*['\"]?[A-Za-z0-9/+=]{8,}" "$content" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} Possible secret assignment in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Private keys
  if grep -q "BEGIN.*PRIVATE KEY" "$content" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} Private key in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Connection strings with passwords
  if grep -qE "(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@" "$content" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} Connection string with credentials in: $file"
    FOUND=$((FOUND + 1))
  fi
}

# Scan staged files (for git hook) or provided files
if [ $# -gt 0 ]; then
  for file in "$@"; do
    [ -f "$file" ] && scan_file "$file"
  done
else
  # Staged mode. Grep the STAGED BLOB, not the path: the working-tree copy is not
  # what `git commit` is about to write. Reading the path let a secret that was
  # staged and then edited out of the working tree commit with the hook exiting 0,
  # and blocked a commit whose staged content was clean when the secret existed
  # only in an unstaged edit. Wrong in both directions, and the false-negative
  # direction is a secret in a commit (OWASP A07 / CWE-798).
  #
  # The blob is addressed by OID, from `--raw`, and NOT by a `:<path>` pathspec.
  # A first version used `git show ":$file"` with `--diff-filter=ACMR`, and
  # adversarial review found that both halves of that opened NEW fail-open paths:
  #
  #   * `:<path>` is parsed as `:<stage>:<path>` when the path starts with a
  #     digit 0-3 and a colon. A staged `0:notes.txt` was therefore either
  #     SKIPPED (`fatal: path 'notes.txt' does not exist`) or, with an unrelated
  #     `notes.txt` also staged, scanned as THAT FILE's content — the gate read
  #     clean on a decoy. `git cat-file blob ":$f"` is identically affected, so
  #     this is not a show-vs-cat-file choice; only an OID avoids the parse.
  #   * `ACMR` omits `T`, a TYPE CHANGE. Replacing a symlinked config with a real
  #     file carrying a secret was never scanned, and the exclusion bought
  #     nothing — a `T` entry has a perfectly readable blob.
  #
  # `--diff-filter=d` (lowercase: EXCLUDE) drops only deletions, so `T` stays in.
  # Renames and copies carry TWO paths; the second is the destination, which is
  # the one entering the commit. A gitlink (160000) or an absent/unmerged entry
  # (000000) has no blob and is skipped by mode, explicitly rather than by a
  # failed read. Process substitution keeps FOUND in the parent shell.
  #
  # Every remaining failure FAILS CLOSED: no repository, no temp file and no
  # readable blob all mean "this commit was not scanned", which for a secret gate
  # must block, not pass. An unwritable TMPDIR silently turning the gate off was
  # the third fail-open found in review. NOTE: the mktemp guard below is defence
  # in depth, not the only thing standing there — with `$_blob` empty the
  # redirect fails and the unreadable-blob branch also blocks. It is kept for the
  # clearer message.
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo -e "${RED}[SECRET]${NC} not inside a git repository — refusing to pass an unscanned commit" >&2
    exit 1
  fi
  _blob=$(mktemp "${TMPDIR:-/tmp}/claudesec-secret-check.XXXXXX") || {
    echo -e "${RED}[SECRET]${NC} cannot create a temp file — refusing to pass an unscanned commit" >&2
    exit 1
  }
  trap 'rm -f "$_blob"' EXIT
  while IFS= read -r -d '' _meta; do
    IFS= read -r -d '' file || break
    # :<srcmode> <dstmode> <srcsha> <dstsha> <status>
    read -r _ _dstmode _ _dstsha _status <<<"${_meta#:}"
    case "$_status" in
      R* | C*) IFS= read -r -d '' file || break ;;
    esac
    # A gitlink (submodule) and an absent/unmerged entry have no blob. Skipping
    # them BY MODE is load-bearing: without it every submodule commit hits the
    # unreadable-blob branch below and is FALSELY BLOCKED.
    case "$_dstmode" in
      160000 | 000000) continue ;;
    esac
    # Skip decided on the PATH before extracting, so a skipped large binary is
    # never copied into $TMPDIR at all.
    if should_skip "$file"; then
      continue
    fi
    # `|| _read_rc=$?` not a bare call: under `set -e` a function returning 2
    # aborts the script before the message is printed (measured — secret-check
    # exited 2 silently while pii-check, which has no `set -e`, was fine).
    _read_rc=0
    read_staged_blob "$_dstsha" || _read_rc=$?
    if [ "$_read_rc" -eq 2 ]; then
      echo -e "${RED}[SECRET]${NC} cannot read the staged blob for: $file (not scanned)"
      echo "  The object EXISTS but could not be decoded — a damaged object store."
      echo "  Run 'git fsck' to locate it (or 'git commit --no-verify' to accept the risk)."
      FOUND=$((FOUND + 1))
      continue
    elif [ "$_read_rc" -ne 0 ]; then
      echo -e "${RED}[SECRET]${NC} cannot read the staged blob for: $file (not scanned)"
      echo "  The object is missing locally and could not be fetched."
      echo "  'git fetch' does NOT hydrate it — the clone filter still applies."
      echo "  Run: git cat-file -e $_dstsha   (or 'git commit --no-verify' to accept the risk)"
      FOUND=$((FOUND + 1))
      continue
    fi
    scan_file "$file" "$_blob"
  done < <(git diff --cached --raw -z --no-abbrev --diff-filter=d 2>/dev/null)
fi

if [ $FOUND -gt 0 ]; then
  echo ""
  echo "$FOUND secret(s) detected. Remove secrets and use environment variables."
  exit 1
fi

exit 0
