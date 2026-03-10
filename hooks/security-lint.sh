#!/bin/bash
# ClaudeSec - Security Lint Hook for Claude Code
# Runs before Write/Edit operations to catch common security issues
#
# Usage: Add to .claude/settings.json hooks.PreToolUse
# {
#   "matcher": "Write|Edit",
#   "command": "bash hooks/security-lint.sh"
# }

set -euo pipefail

FILE="${1:-}"
CONTENT="${2:-}"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ISSUES=0

check_pattern() {
  local pattern="$1"
  local message="$2"
  local severity="$3"

  if echo "$CONTENT" | grep -qiE "$pattern"; then
    if [ "$severity" = "error" ]; then
      echo -e "${RED}[BLOCKED]${NC} $message"
      ISSUES=$((ISSUES + 1))
    else
      echo -e "${YELLOW}[WARNING]${NC} $message"
    fi
  fi
}

# Critical: Hardcoded secrets
check_pattern "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}" \
  "Possible hardcoded password detected" "error"

check_pattern "(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}" \
  "Possible hardcoded API key detected" "error"

check_pattern "(AKIA|ASIA)[A-Z0-9]{16}" \
  "Possible AWS access key detected" "error"

check_pattern "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" \
  "Private key detected in source code" "error"

# High: Injection vulnerabilities
check_pattern "eval\s*\(" \
  "eval() usage detected — potential code injection" "warning"

check_pattern "innerHTML\s*=" \
  "innerHTML assignment — potential XSS vulnerability" "warning"

check_pattern "(exec|spawn|execSync|spawnSync)\s*\(" \
  "Shell command execution — verify input sanitization" "warning"

check_pattern "document\.write\s*\(" \
  "document.write() — potential XSS vulnerability" "warning"

# Medium: SQL injection
check_pattern "(query|execute)\s*\(\s*['\"].*\\\$\{" \
  "Possible SQL injection — use parameterized queries" "warning"

check_pattern "query\s*\(\s*['\"].*\+\s*" \
  "String concatenation in query — use parameterized queries" "warning"

# Low: Security best practices
check_pattern "http://" \
  "Non-HTTPS URL detected — use HTTPS where possible" "warning"

check_pattern "TODO.*security|FIXME.*security|HACK.*security" \
  "Security-related TODO/FIXME found" "warning"

if [ $ISSUES -gt 0 ]; then
  echo ""
  echo "Security lint found $ISSUES blocking issue(s)."
  echo "Fix the issues above or mark as false positive."
  exit 1
fi

exit 0
