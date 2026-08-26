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
  # --diff-filter=ACMR drops deletions, which have no blob to read.
  # Process substitution keeps FOUND in the parent shell.
  _blob=$(mktemp "${TMPDIR:-/tmp}/claudesec-secret-check.XXXXXX")
  trap 'rm -f "$_blob"' EXIT
  while IFS= read -r -d '' file; do
    git show ":$file" >"$_blob" 2>/dev/null || continue
    scan_file "$file" "$_blob"
  done < <(git diff --cached --name-only --diff-filter=ACMR -z 2>/dev/null)
fi

if [ $FOUND -gt 0 ]; then
  echo ""
  echo "$FOUND secret(s) detected. Remove secrets and use environment variables."
  exit 1
fi

exit 0
