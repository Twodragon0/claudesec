#!/bin/bash
# ClaudeSec - PII / Personal Information Detection Hook
# Prevents committing files that contain personal or company information
#
# Usage: Add as a pre-commit hook or Claude Code hook
#   cp hooks/pii-check.sh .git/hooks/pre-commit-pii && chmod +x .git/hooks/pre-commit-pii

set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

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
  # Content to grep. Defaults to the path itself (argument / CI / pre-commit-
  # framework mode, where the working tree IS what gets checked); staged mode
  # passes the extracted blob.
  local content="${2:-$1}"

  if should_skip "$file"; then
    return
  fi

  # Hardcoded macOS/Linux user paths (exposes usernames)
  if grep -qE "/Users/[a-zA-Z][a-zA-Z0-9_-]+/" "$content" 2>/dev/null; then
    echo -e "${RED}[PII]${NC} Hardcoded user path in: $file"
    grep -nE "/Users/[a-zA-Z][a-zA-Z0-9_-]+/" "$content" 2>/dev/null | head -3
    FOUND=$((FOUND + 1))
  fi

  # AWS Account IDs (12-digit in context)
  if grep -qE "(account|aws)[_\"':-].*[0-9]{12}" "$content" 2>/dev/null; then
    echo -e "${RED}[PII]${NC} Possible AWS account ID in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Google Sheet / Notion IDs hardcoded (not placeholders)
  if grep -qE "(SHEET_ID|NOTION_DB_ID|NOTION_TOKEN)\s*=\s*['\"]?[A-Za-z0-9_-]{25,}" "$content" 2>/dev/null; then
    echo -e "${RED}[PII]${NC} Possible service ID hardcoded in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Internal email addresses (not example.com or placeholder)
  if grep -qE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(io|co|com|net|org)" "$content" 2>/dev/null; then
    # Exclude common safe patterns
    if ! grep -qE "@(example\.com|anthropic\.com|users\.noreply\.github\.com|your-domain\.com)" "$content" 2>/dev/null; then
      local real_emails
      real_emails=$(grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(io|co|com|net|org)" "$content" 2>/dev/null | grep -vE "@(example|anthropic|noreply|your-domain|openssh|libssh|openbsd)" | head -3)
      if [ -n "$real_emails" ]; then
        echo -e "${YELLOW}[PII]${NC} Possible real email in: $file"
        echo "  $real_emails"
        FOUND=$((FOUND + 1))
      fi
    fi
  fi

  # Internal IP addresses (private ranges with specific octets, not documentation)
  if grep -qE "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "$content" 2>/dev/null; then
    if echo "$file" | grep -qvE "(\.md|\.txt)$"; then
      echo -e "${YELLOW}[PII]${NC} Internal IP address in: $file"
      FOUND=$((FOUND + 1))
    fi
  fi
}

# Scan staged files (for git hook) or provided files
if [ $# -gt 0 ]; then
  for file in "$@"; do
    [ -f "$file" ] && scan_file "$file"
  done
else
  # Staged mode. Grep the STAGED BLOB, not the path: the working-tree copy is not
  # what `git commit` is about to write. Reading the path let PII that was staged
  # and then edited out of the working tree commit with the hook exiting 0, and
  # blocked a commit whose staged content was clean when the PII existed only in
  # an unstaged edit. Wrong in both directions.
  #
  # The blob is addressed by OID, from `--raw`, and NOT by a `:<path>` pathspec —
  # `:<path>` is parsed as `:<stage>:<path>` for a path like `0:notes.txt`, which
  # either skips the file or scans an unrelated `notes.txt` instead. `T` (type
  # change) must stay in the set, so the filter EXCLUDES deletions
  # (`--diff-filter=d`, lowercase) rather than listing `ACMR`. See the long
  # comment in secret-check.sh for the three fail-opens this shape closes.
  #
  # Renames/copies carry TWO paths; the second is the destination. A gitlink
  # (160000) or absent/unmerged entry (000000) has no blob and is skipped by mode.
  # Process substitution keeps FOUND in the parent shell.
  #
  # Fails CLOSED on no repository, a missing temp file, or an unreadable blob.
  # This script has no `set -e`, so an unwritable TMPDIR previously turned the
  # whole gate off while still exiting 0 — the failure had to become explicit
  # rather than inherited. The mktemp guard is defence in depth: with `$_blob`
  # empty the redirect fails and the unreadable-blob branch blocks too.
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo -e "${RED}[PII]${NC} not inside a git repository — refusing to pass an unscanned commit" >&2
    exit 1
  fi
  _blob=$(mktemp "${TMPDIR:-/tmp}/claudesec-pii-check.XXXXXX") || {
    echo -e "${RED}[PII]${NC} cannot create a temp file — refusing to pass an unscanned commit" >&2
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
      echo -e "${RED}[PII]${NC} cannot read the staged blob for: $file (not scanned)"
      echo "  The object EXISTS but could not be decoded — a damaged object store."
      echo "  Run 'git fsck' to locate it (or 'git commit --no-verify' to accept the risk)."
      FOUND=$((FOUND + 1))
      continue
    elif [ "$_read_rc" -ne 0 ]; then
      echo -e "${RED}[PII]${NC} cannot read the staged blob for: $file (not scanned)"
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
  echo "$FOUND PII issue(s) detected. Use environment variables or placeholders instead."
  exit 1
fi

exit 0
