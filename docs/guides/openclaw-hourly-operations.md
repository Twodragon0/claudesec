---
title: OpenClaw Hourly Operations with OpenCode
description: Configure hourly cron automation for repository sync and continuous security improvement
tags: [openclaw, opencode, cron, automation, devsecops]
---

# OpenClaw Hourly Operations with OpenCode

## Goal

Run ClaudeSec hourly with cron so the repository stays synced and improvement artifacts are continuously refreshed.

## What Gets Automated

1. Repository sync via central manager `git pull --ff-only` (through OpenCode when available)
2. Centralized scheduler management from Desktop root
3. Single source of truth for OpenClaw prompt and repo inventory
4. Append-only operations log at `/Users/namyongkim/Desktop/.twodragon0/logs/`

## Setup

```bash
bash /Users/namyongkim/Desktop/.twodragon0/bin/install-system-cron.sh
bash /Users/namyongkim/Desktop/.twodragon0/bin/setup-openclaw-cron.sh
bash /Users/namyongkim/Desktop/.twodragon0/bin/setup-gws-cli.sh
bash /Users/namyongkim/Desktop/.twodragon0/bin/finalize-gws-auth-and-verify.sh
```

## Verification

```bash
crontab -l
openclaw cron list --json --all
tail -n 50 ~/.twodragon0-runtime/logs/hourly-opencode-git-pull.log
```

## Optional Runtime Variables

- `repos.list`: central repository registry
- `openclaw_ultrawork_prompt.md`: centralized improvement prompt
- `logs/*`: centralized run logs
- `GWS_ENABLED=true`: enable optional gws integration in hourly runner
- `GWS_COMMAND='<gws command>'`: execute gws command per repository (with `REPO_PATH`)

## Improvement Operation Model

- Track recurring findings in per-repo `MEMORY.md` while scheduling remains centralized.
- Run `/ralph-loop` for autonomous backlog reduction cycles.
- Run `/ulw-loop` when intensive implementation on top-priority items is required.

## Security and Reliability Notes

- Use least privilege for the cron execution account.
- Keep pull mode as `--ff-only` to avoid accidental merge commits.
- Keep logs and scan artifacts for audit and trend analysis.

## References

- OWASP SAMM: [https://owaspsamm.org/](https://owaspsamm.org/)
- NIST SP 800-92 (Guide to Computer Security Log Management): [https://csrc.nist.gov/publications/detail/sp/800-92/final](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- CIS Controls v8: [https://www.cisecurity.org/controls/v8](https://www.cisecurity.org/controls/v8)
