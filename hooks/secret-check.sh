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

  # Skip binary and irrelevant files
  if echo "$file" | grep -qE "$SKIP_PATTERNS"; then
    return
  fi

  # AWS keys
  if grep -qE "(AKIA|ASIA)[A-Z0-9]{16}" "$file" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} AWS key in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Generic secrets in env-like assignments
  if grep -qE "^[A-Z_]*(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z_]*\s*=\s*['\"]?[A-Za-z0-9/+=]{8,}" "$file" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} Possible secret assignment in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Private keys
  if grep -q "BEGIN.*PRIVATE KEY" "$file" 2>/dev/null; then
    echo -e "${RED}[SECRET]${NC} Private key in: $file"
    FOUND=$((FOUND + 1))
  fi

  # Connection strings with passwords
  if grep -qE "(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@" "$file" 2>/dev/null; then
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
  # Scan staged files (process substitution to keep FOUND in parent shell)
  while IFS= read -r -d '' file; do
    [ -f "$file" ] && scan_file "$file"
  done < <(git diff --cached --name-only -z 2>/dev/null)
fi

if [ $FOUND -gt 0 ]; then
  echo ""
  echo "$FOUND secret(s) detected. Remove secrets and use environment variables."
  exit 1
fi

exit 0
