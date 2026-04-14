---
title: "세션 성과 보고서 2026-04-11"
description: "Docker 대시보드 감사, 스캐너 튜닝, 보안 잠금 설정 세션 요약"
tags:
  - session-report
  - dashboard
  - scanner
  - security
  - devsecops
---

# 세션 성과 보고서 — 2026-04-11

## 세션 개요

- **Date**: 2026-04-11
- **Duration**: ~2 hours
- **Scope**: Docker dashboard audit → scanner tuning → security lockdown

## 대시보드 상태 (Docker 기반)

- **Container**: claudesec-dashboard-1, port 11777, healthy
- **Routes verified**: `/` (PDCA, 101KB), `/scan.html` (scan, 230KB), `/scan-report.json` (OK)
- Blue theme (`#0ea5e9`) migration complete, purple (`#6c5ce7`) removed
- CSP nonce injection via nginx `sub_filter` working (0 leaks)
- Triage-first hero, Immediate Priorities, Investigation Lanes, Coverage Snapshot sections rendered

## 스캐너 개선 (v0.7.0)

### Before → After 비교

| Metric | Before | After |
|---|---|---|
| Score / Grade | 78 / C | 85 / B |
| Failures | 7 | 4 |
| Warnings | 10 | 6 |
| Pytest | 163/163 | 163/163 |

### Fixed false positives

1. **SECRETS-001** (critical→pass): GCP SA docstring placeholder cleanup in `asset-gsheet-sync.py`
2. **CODE-INJ-008** (critical→pass): XXE regex narrowed to exclude `xml.sax.saxutils` (pure escape helper)
3. **SECRETS-004** (high→warn): Correctly allowlisted template references
4. **CODE-SEC-008** (warn→pass): Concurrency check now requires actual threading/multiprocessing/asyncio primitives
5. **AI-003/005/008/009** (4 warnings→skip): Root cause — `.omc/state/*.json` triggering `has_ai` gate. Fix: added `.omc/.claude/.claudesec-*` to `files_contain` exclusions
6. **`.env.example`** updated with all 11 keys from `.env` + 3 Notion optional keys

### Remaining 4 failures (host-state, not code)

- **SECRETS-002**: 6 live credentials in `.env` (user must rotate)
- **MAC-005**: macOS auto-update disabled
- **CIS-002**: auditd not running
- **CIS-005**: 14 outdated Homebrew packages
- Created `scripts/dev-machine-hardening.sh` (dry-run default, `--apply` to execute)

## 커밋 히스토리

### main에 직접 (push 이전)

| SHA | Message |
|---|---|
| 20a4af2 | fix(scanner): eliminate AI/NET/concurrency false positives via path exclusions |
| 706c5a4 | fix(secrets): clean up false-positive triggers and complete .env.example template |
| dc3a79f | feat(scripts): add dry-run macOS dev machine hardening helper |

### PR #82 (feature/pre-push-hook)

| SHA | Message |
|---|---|
| 805628a | chore(git): add client-side pre-push hook blocking direct main pushes |
| 0bad569 | chore(setup): auto-install pre-push hook during project setup |
| 549fd51 | docs(guides): add emergency hotfix process guide |

## 보안 잠금 설정

| Layer | Status | Mechanism |
|---|---|---|
| Client (local) | ✅ | `scripts/pre-push.sh` → `.git/hooks/pre-push` symlink |
| Server (GitHub) | ✅ | `enforce_admins: true` + PR required + 2 required checks |
| Process (docs) | ✅ | `docs/guides/emergency-hotfix-process.md` — hotfix PR flow + 30min SLA |

## CI 검증

All 20 checks passing on both main and PR #82:

CodeQL, Security Scan, Docker Dashboard Smoke Test, Lighthouse, DAST, scanner-unit-tests, gitleaks, GitGuardian, dependency-review, npm-audit, pip-audit, markdown-lint, link-check, frontmatter-check, pii-check, shell-lint, dashboard-regression-check

## 파일 변경 요약 (총 10 파일)

1. `scanner/lib/checks.sh` — `files_contain`/`count_files` `.omc/.claude` exclusion
2. `scanner/checks/code/injection.sh` — XXE `saxutils` exclusion
3. `scanner/checks/code/security-flaws.sh` — CODE-SEC-008 concurrency primitives
4. `scanner/checks/network/tls.sh` — NET-001 path exclusions
5. `scripts/asset-gsheet-sync.py` — docstring placeholder cleanup
6. `.env.example` — Zscaler/COST_XLSX keys added
7. `scripts/dev-machine-hardening.sh` — NEW: macOS hardening dry-run helper
8. `scripts/pre-push.sh` — NEW: client-side main push guard
9. `scripts/setup.sh` — pre-push hook auto-install
10. `docs/guides/emergency-hotfix-process.md` — NEW: hotfix process guide
