#!/bin/bash
# ClaudeSec - Security Lint Hook for Claude Code (PreToolUse)
#
# Reads the PreToolUse event as JSON on STDIN and blocks Write/Edit operations
# that would introduce hardcoded secrets, private keys, or personal absolute
# paths. Injection/XSS/SQL patterns are surfaced as non-blocking warnings.
#
# Contract: https://code.claude.com/docs/en/hooks
#   - Input : JSON on stdin (fields: tool_name, tool_input, ...).
#   - Block : exit code 2 (stderr is shown back to Claude).
#   - Allow : exit code 0.
#
# Register in .claude/settings.json (nested-hooks schema):
#   {
#     "hooks": {
#       "PreToolUse": [
#         {
#           "matcher": "Write|Edit",
#           "hooks": [
#             { "type": "command", "command": "bash hooks/security-lint.sh" }
#           ]
#         }
#       ]
#     }
#   }

set -euo pipefail

INPUT="$(cat)"

# Extract the text this operation would WRITE. Field names are the real Claude
# Code tool_input schema: Write -> content, Edit -> new_string, Bash -> command.
# We deliberately do NOT scan tool_input.file_path: it is always the operation's
# own absolute target path (e.g. /Users/<name>/… or /home/runner/…), so scanning
# it against the personal-path pattern would block virtually every legitimate
# write. The personal-path check instead runs against the written body, catching
# a personal path hardcoded *inside* the content.
#
# If jq is unavailable or the payload is not JSON, fall back to scanning the raw
# stdin blob (de-escaping \" so quote-adjacent secret patterns still match), so a
# missing jq degrades fail-closed rather than re-introducing a silent pass.
#
# JQ_OK records whether we isolated the written body (jq) or are scanning the raw
# event (fallback). The personal-path check only runs when JQ_OK=1: the raw event
# always contains the operation's own absolute file_path, which would otherwise
# make that check block every real write.
if command -v jq >/dev/null 2>&1 && CONTENT="$(printf '%s' "$INPUT" | jq -r '
      [ .tool_input.content?,
        .tool_input.new_string?,
        .tool_input.command? ]
      | map(select(. != null and . != ""))
      | join("\n")' 2>/dev/null)"; then
  JQ_OK=1
else
  JQ_OK=0
  CONTENT="$(printf '%s' "$INPUT" | sed 's/\\"/"/g')"
fi

ISSUES=0

check_pattern() {
  local pattern="$1"
  local message="$2"
  local severity="$3"

  if printf '%s' "$CONTENT" | grep -qiE -- "$pattern"; then
    if [ "$severity" = "error" ]; then
      echo "[BLOCKED] $message" >&2
      ISSUES=$((ISSUES + 1))
    else
      echo "[WARNING] $message" >&2
    fi
  fi
}

# Critical: Hardcoded secrets (blocking)
check_pattern "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}" \
  "Possible hardcoded password detected" "error"

check_pattern "(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}" \
  "Possible hardcoded API key detected" "error"

check_pattern "(AKIA|ASIA)[A-Z0-9]{16}" \
  "Possible AWS access key detected" "error"

check_pattern "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" \
  "Private key detected in source code" "error"

# Personal-path check runs only on jq-isolated content — the raw fallback event
# always carries an absolute file_path that would false-positive here.
if [ "$JQ_OK" -eq 1 ]; then
  check_pattern "(/Users/[A-Za-z0-9._-]+/|/home/[A-Za-z0-9._-]+/|[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+\\\\)" \
    "Possible personal absolute path detected — use env vars/placeholders" "error"
fi

# High: Injection vulnerabilities (warning)
check_pattern "eval\s*\(" \
  "eval() usage detected — potential code injection" "warning"

check_pattern "innerHTML\s*=" \
  "innerHTML assignment — potential XSS vulnerability" "warning"

check_pattern "(exec|spawn|execSync|spawnSync)\s*\(" \
  "Shell command execution — verify input sanitization" "warning"

check_pattern "document\.write\s*\(" \
  "document.write() — potential XSS vulnerability" "warning"

# Medium: SQL injection (warning)
check_pattern "(query|execute)\s*\(\s*['\"].*\\\$\{" \
  "Possible SQL injection — use parameterized queries" "warning"

check_pattern "query\s*\(\s*['\"].*\+\s*" \
  "String concatenation in query — use parameterized queries" "warning"

# Low: Security best practices (warning)
check_pattern "http://" \
  "Non-HTTPS URL detected — use HTTPS where possible" "warning"

check_pattern "TODO.*security|FIXME.*security|HACK.*security" \
  "Security-related TODO/FIXME found" "warning"

if [ "$ISSUES" -gt 0 ]; then
  {
    echo ""
    echo "Security lint blocked this write: $ISSUES issue(s) above."
    echo "Remove the secret/path, use environment variables or placeholders, then retry."
  } >&2
  # Exit 2: PreToolUse blocks the tool call and shows stderr to Claude.
  exit 2
fi

exit 0
