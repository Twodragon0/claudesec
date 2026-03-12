---
title: Shell Lint Policy
description: Defines aligned local and CI ShellCheck scope and failure policy
tags: [ci-cd, shellcheck, security]
---

# Shell Lint Policy

ClaudeSec uses the same shell lint scope in local development and CI to reduce mismatch.

## CI policy

- Workflow: `.github/workflows/lint.yml`
- Action: `ludeeus/action-shellcheck` pinned by commit SHA
- ShellCheck engine version: `v0.11.0`
- Failure threshold: `severity: warning` (warning and above fail)
- Scan scope:
  - `scandir: ./scripts`
  - `additional_files: run`
  - `check_together: 'yes'`

## Local policy

- Command: `./scripts/lint-shell.sh`
- Scan scope:
  - `scripts/*.sh`
  - `run`
- Resolution order:
  1. Use local `shellcheck` binary when available.
  2. Fallback to pinned Docker image `koalaman/shellcheck-alpine:v0.10.0`.

## Verification command

```bash
./scripts/lint-shell.sh
```
