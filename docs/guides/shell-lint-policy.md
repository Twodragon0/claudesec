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
- Global options: `SHELLCHECK_OPTS=-x`
- Scan scope:
  - `scandir: ./scripts`
  - `additional_files: run`
  - `check_together: 'yes'`

### Option policy (`SHELLCHECK_OPTS`)

- Default baseline is fixed at `-x` to resolve sourced file paths consistently.
- Any future exception (for example, `-e SC1090`) must be added in both places:
  1. `.github/workflows/lint.yml` (`SHELLCHECK_OPTS`)
  2. this document (`Shell Lint Policy`)

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

See also: [CI Operations Playbook](../github/ci-operations-playbook.md)

## References

- [NIST SP 800-53 SA-11: Developer Testing and Evaluation](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element=SA-11)
- [CIS Controls v8 Control 16: Application Software Security](https://www.cisecurity.org/controls/application-software-security)
