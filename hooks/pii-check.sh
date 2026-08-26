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

scan_file() {
  local file="$1"
  # Content to grep. Defaults to the path itself (argument / CI / pre-commit-
  # framework mode, where the working tree IS what gets checked); staged mode
  # passes the extracted blob.
  local content="${2:-$1}"

  if echo "$file" | grep -qE "$SKIP_PATTERNS"; then
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
  # --diff-filter=ACMR drops deletions, which have no blob to read.
  # Process substitution keeps FOUND in the parent shell.
  _blob=$(mktemp "${TMPDIR:-/tmp}/claudesec-pii-check.XXXXXX")
  trap 'rm -f "$_blob"' EXIT
  while IFS= read -r -d '' file; do
    git show ":$file" >"$_blob" 2>/dev/null || continue
    scan_file "$file" "$_blob"
  done < <(git diff --cached --name-only --diff-filter=ACMR -z 2>/dev/null)
fi

if [ $FOUND -gt 0 ]; then
  echo ""
  echo "$FOUND PII issue(s) detected. Use environment variables or placeholders instead."
  exit 1
fi

exit 0
