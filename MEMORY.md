---
title: Continuous Improvement Memory
description: Persistent improvement backlog and operating memory for ClaudeSec automation
tags: [memory, operations, quality, continuous-improvement]
---

# Continuous Improvement Memory

## Operating Cadence

- Hourly: central manager runs `git pull --ff-only` from `/Users/REDACTED_USER/Desktop/.twodragon0`.
- Daily: triage new findings and failures from `docs/reports/hourly-scan.json`.
- Weekly: trend review across security, performance, code quality, and documentation quality.

## Improvement Buckets

- Security: unresolved high/critical findings, dependency risk, secret exposure paths.
- Performance and Optimization: repeated slow checks, scanner runtime drift, noisy failures.
- Monitoring and Operations: alert coverage, log quality, runbook freshness, backup of reports.
- Code and Content Quality: false positives, stale docs, missing source citations, broken links.
- UI/UX and Design: dashboard readability, navigation clarity, mobile rendering checks.

## Ralph and Ultrawork Trigger Policy

- Use `/ralph-loop` for autonomous improvement cycles when backlog depth increases.
- Use `/ulw-loop` for high-focus implementation bursts on prioritized items.
- Record decisions and deltas in this file after each focused cycle.

## Authoritative Review Anchors

- OWASP SAMM (continuous security governance)
- NIST SP 800-92 (log management and monitoring)
- CIS Controls v8 (continuous vulnerability management and secure configuration)
