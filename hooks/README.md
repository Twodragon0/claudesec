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
| `pii-check.sh` | Pre-commit | Prevents committing personal paths, account IDs, real emails, internal IPs |

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

With no arguments (the shape above), `secret-check.sh` and `pii-check.sh` scan
the **staged blob** of each staged file — what `git commit` is about to write —
not the working-tree copy. That distinction is load-bearing in both directions:
a secret staged and then edited out of the working tree still blocks the commit,
and a secret that exists only in an unstaged edit does not. Given file arguments
instead, both scan those paths as-is, which is what CI and the `pre-commit`
framework want (they hand the hook a clean tree).

Two consequences of scanning the staged blob rather than the path:

- A staged **symlink** is scanned as its own content, which is the *target path
  text* — not the target's bytes. That is deliberate: committing a link does not
  commit what it points at.
- A staged **submodule** (gitlink) has no blob and is skipped.

In staged mode both hooks **fail closed**: if the object store cannot produce a
staged blob, if `$TMPDIR` is unwritable, or if the hook is somehow run outside a
repository, they block the commit and say so rather than passing something they
could not read.

Objects are probed locally first, so the common path — everything you just
staged — never touches the network. Only an object that is genuinely absent
(partial clone, sparse checkout) is fetched from the promisor remote, bounded by
`timeout` where the system provides it. If that fetch fails, the hook blocks and
prints the object id: note that **`git fetch` does not hydrate a filtered blob**
— the clone filter still applies — so the way to materialise it is
`git cat-file -e <oid>`, or `git commit --no-verify` if you accept the risk.

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
