---
title: OpenCode Operations Profile
description: Operational defaults for using OpenCode in ClaudeSec hourly automation
tags: [opencode, operations, automation]
---

# OpenCode Operations Profile

## Purpose

Use OpenCode as an automation operator for repetitive repository maintenance, especially hourly `git pull --ff-only` execution and concise operational reporting.

## Baseline Settings

- Binary path: `opencode`
- Primary manager: `/Users/REDACTED_USER/Desktop/.twodragon0`
- Non-interactive automation command: `/Users/REDACTED_USER/Desktop/.twodragon0/bin/hourly-opencode-git-pull.sh`
- Fallback if OpenCode fails: direct `git pull --ff-only` is handled inside the central manager

## Safety Rules

- Only use fast-forward pulls (`--ff-only`) to avoid hidden merge commits.
- Run with least privilege and dedicated service account where possible.
- Keep logs in `/Users/REDACTED_USER/Desktop/.twodragon0/logs/` for auditability and incident review.

## Continuous Improvement Loop

- Pull latest security updates hourly.
- Execute scanner checks and dashboard generation after each pull.
- Review dashboard deltas and scanner failures to prioritize fixes.
