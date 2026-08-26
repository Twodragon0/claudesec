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

scan_file() {
  local file="$1"
  # Content to grep. Defaults to the path itself (argument / CI mode, where the
  # working tree IS what gets checked); staged mode passes the extracted blob.
  local content="${2:-$1}"

  # Skip binary and irrelevant files
  if echo "$file" | grep -qE "$SKIP_PATTERNS"; then
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
  # Every remaining failure FAILS CLOSED: no temp file and no readable blob both
  # mean "this commit was not scanned", which for a secret gate must block, not
  # pass. An unwritable TMPDIR silently turning the gate off was the third
  # fail-open found in review.
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
    case "$_dstmode" in
      160000 | 000000) continue ;;
    esac
    if ! git cat-file blob "$_dstsha" >"$_blob" 2>/dev/null; then
      echo -e "${RED}[SECRET]${NC} cannot read the staged blob for: $file (not scanned)"
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
