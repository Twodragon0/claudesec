---
title: ClaudeSec Hooks
description: Security hooks for Claude Code integration
---

# ClaudeSec Hooks

## Available Hooks

| Hook | Trigger | Purpose |
|------|---------|---------|
| `security-lint.sh` | PreToolUse (Write/Edit) | Catches hardcoded secrets, injection patterns, insecure code |
| `secret-check.sh` | Pre-commit | Prevents committing files containing secrets |

## Installation

### Claude Code Hooks

Add to your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "bash .claude/hooks/security-lint.sh"
      }
    ]
  }
}
```

### Git Pre-Commit

```bash
cp secret-check.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Creating Custom Hooks

Hooks are bash scripts that:
1. Receive file path and content as arguments
2. Exit `0` to allow the operation
3. Exit `1` to block the operation (with error message)

```bash
#!/bin/bash
# custom-hook.sh
FILE="$1"
CONTENT="$2"

# Your security check here
if echo "$CONTENT" | grep -q "DANGEROUS_PATTERN"; then
  echo "Blocked: dangerous pattern detected"
  exit 1
fi

exit 0
```
