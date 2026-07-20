---
title: "Injection Guard Fork-Sync Policy — Preventing Drift Across Repos"
description: "정책. claudesec의 CWE-94 python -c 인젝션 회귀 가드를 타 레포로 self-contained 포크할 때 원본과의 드리프트를 막는 규칙"
tags:
  - policy
  - security
  - guard
  - cwe-94
---

# Injection Guard Fork-Sync Policy

## Context

The canonical CWE-94 / OWASP A03:2021 (Injection) regression guard lives at
`scanner/tests/test_ci_no_code_injection_regression.py` in this repo. It flags
any double-quoted `python3 -c "..."` / `python -c "..."` body containing an
unescaped `$`, unquoted-heredoc-into-interpreter, and best-effort
quote-concatenation.

To keep other workspace repos hermetic (no shared dependency, no cross-repo
import), the guard is **copy-forked** into each consuming repo as a
self-contained, stdlib-only test file rather than published as a package:

| Repo | Fork path | Ported in |
| --- | --- | --- |
| `investing` | `tests/test_injection_guard.py` | PR #1053 |
| `KIS` | `tests/test_ci_injection_guard.py` | PR #293 |

Forking trades a shared-dependency's automatic updates for portability and
zero-coupling. The cost is **drift**: when the canonical detector gains
coverage (e.g. the special-parameter and heredoc/quote-concat detections added
in claudesec #349/#350), the forks silently lag and give a false sense of
protection. This policy bounds that risk.

## Non-negotiables

1. **Canonical source of truth.** The detection logic is owned by
   `scanner/tests/test_ci_no_code_injection_regression.py`. Forks are
   downstream copies; behavioural changes land here first.
2. **Provenance header (required in every fork).** Each forked file MUST begin
   its module docstring with a line recording origin + synced commit:

   ```python
   # Forked from claudesec scanner/tests/test_ci_no_code_injection_regression.py
   # @ <short-sha> (<YYYY-MM-DD>). Self-contained; see docs/plans/injection-guard-fork-sync-policy.md
   ```

   The `<short-sha>` is the claudesec commit whose detector this copy matches.
   A fork with no provenance line is non-conformant.
3. **Self-contained only.** Forks MUST NOT import `_ci_guard_util` or any
   claudesec module — inline the helpers (`strip_comment_lines`,
   `has_unescaped_dollar`). Forks MUST NOT import the consuming repo's product
   source, so coverage gates (`--cov=<pkg> --cov-fail-under=N`) stay neutral.
4. **Empty baseline is the default.** `KNOWN_INJECTION_SITES = set()` with an
   EQUALS assertion. A non-empty baseline is allowed only to pin a documented,
   deferred site — never to silence a fresh finding.

## Sync trigger and procedure

Re-sync a fork ONLY when the canonical detector's **behaviour** changes
(new construct detected, false-negative fixed, false-positive removed) —
not for comment/style edits.

1. When merging a behavioural change to the canonical guard, list the fork
   paths in the PR description under a `Fork-sync required:` line.
2. For each fork: port the logic change, refresh the provenance `<short-sha>`,
   re-run that repo's test + lint, confirm the baseline stays empty, open a PR
   titled `test(ci): sync injection guard @ <short-sha>`.
3. A fork whose provenance sha is older than the canonical file's last
   behavioural commit is **stale** — track it as an open item until synced.

## Drift audit (lightweight, periodic)

There is no automated cross-repo enforcement (repos are independent, no shared
CI). A quarterly manual check is sufficient given the guard changes rarely:

- Compare each fork's provenance sha against the canonical file's last
  behavioural commit (`git log --oneline -- scanner/tests/test_ci_no_code_injection_regression.py`).
- Run each fork locally; confirm its self-tests still pass and baseline is empty.
- Record fork paths + last-synced sha in the workspace security backlog.

## Out of scope

- Promoting the guard to a published pip package with a shared version. That
  removes drift but adds a release/coupling burden disproportionate to a
  ~400-line stdlib test; revisit only if the fork count grows large.
- Cross-repo CI that fails claudesec when a fork drifts (no shared control
  plane across these repos today).

## References

- OWASP Top 10:2021 A03 — Injection: <https://owasp.org/Top10/A03_2021-Injection/>
- CWE-94 — Improper Control of Generation of Code: <https://cwe.mitre.org/data/definitions/94.html>
