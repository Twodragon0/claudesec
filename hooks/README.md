---
title: ClaudeSec Hooks
description: Security hooks for Claude Code integration
---

# ClaudeSec Hooks

## Available Hooks

| Hook | Trigger | Purpose |
|------|---------|---------|
| `security-lint.sh` | PreToolUse (Write/Edit) | Catches hardcoded secrets, personal absolute paths, injection patterns, insecure code |
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
        "hooks": [
          { "type": "command", "command": "bash .claude/hooks/security-lint.sh" }
        ]
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

PreToolUse hooks are commands that:

1. Receive the tool event as **JSON on stdin** — not positional args
   (fields: `tool_name`, `tool_input`, …; the written text is in
   `tool_input.content` for Write and `tool_input.new_string` for Edit).
2. Exit `0` to allow the operation.
3. Exit `2` to block it — stderr is shown back to Claude as the reason.

See the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) for
the full event schema.

```bash
#!/bin/bash
# custom-hook.sh
set -euo pipefail

INPUT="$(cat)"                                   # PreToolUse event JSON on stdin
CONTENT="$(printf '%s' "$INPUT" | jq -r '
  [ .tool_input.content?, .tool_input.new_string? ]
  | map(select(. != null)) | join("\n")')"

# Your security check here
if printf '%s' "$CONTENT" | grep -q "DANGEROUS_PATTERN"; then
  echo "Blocked: dangerous pattern detected" >&2
  exit 2
fi

exit 0
```
