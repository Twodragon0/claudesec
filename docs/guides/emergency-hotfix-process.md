---
title: "Emergency Hotfix Process"
description: "ClaudeSec 프로젝트의 긴급 보안 패치(hotfix) 절차 — main 브랜치 직접 푸시 금지 정책 하에서 PR을 통한 긴급 머지 프로세스 가이드"
tags:
  - hotfix
  - incident-response
  - security
  - git-workflow
  - devSecOps
---

# 긴급 핫픽스 프로세스 / Emergency Hotfix Process

## 개요 / Overview

ClaudeSec 저장소는 `main` 브랜치에 대한 **직접 푸시(force-push 포함)를 완전히 차단**합니다.
긴급 보안 취약점이 발견된 경우에도 예외는 없으며, 반드시 Pull Request를 통해 머지해야 합니다.

This repository enforces a **complete push block on `main`** (including force-push). Even in emergencies, all changes must flow through a Pull Request. This policy aligns with NIST SP 800-218 (Secure Software Development Framework) Secure Code Review practices and OWASP's recommendation for mandatory peer review on security-critical changes.

> **SLA 목표 / SLA Target**: 취약점 발견 → PR 머지 **30분 이내**

---

## 핫픽스 절차 / Hotfix Flow

### 1단계: 핫픽스 브랜치 생성 / Step 1 — Create Hotfix Branch

```bash
git switch main
git pull origin main
git switch -c hotfix/CVE-YYYY-NNNNN
```

브랜치 명명 규칙: `hotfix/<CVE-ID>` 또는 `hotfix/<short-description>`
Branch naming convention: `hotfix/<CVE-ID>` or `hotfix/<short-description>`

---

### 2단계: 수정 및 커밋 / Step 2 — Fix and Commit

최소한의 변경만 적용합니다. 관련 없는 리팩터링이나 스타일 수정을 포함하지 마십시오.
Apply the minimal viable change. Do not include unrelated refactors or style fixes.

```bash
# 수정 후 / After fixing
git add <changed-files>
git commit -m "fix(security): CVE-YYYY-NNNNN <short description>"
```

커밋 타입은 반드시 `fix(security):` 접두사를 사용합니다 (conventional commits 규칙).
Always use the `fix(security):` prefix per conventional commits convention.

---

### 3단계: 푸시 / Step 3 — Push Branch

```bash
git push -u origin hotfix/CVE-YYYY-NNNNN
```

---

### 4단계: PR 생성 / Step 4 — Create Pull Request

```bash
gh pr create \
  --title "fix(security): CVE-YYYY-NNNNN <short description>" \
  --label "hotfix" \
  --reviewer @security-team \
  --body "$(cat <<'EOF'
## Summary
- CVE: CVE-YYYY-NNNNN
- Severity: [Critical/High/Medium]
- Affected component: <component>
- Fix: <one-line description>

## Impact
<describe affected versions, surfaces, or data>

## Test plan
- [ ] scanner-unit-tests pass
- [ ] No regression in related paths
- [ ] Reviewed by security-team
EOF
)"
```

**hotfix 레이블이 부여된 PR은 self-approve가 허용됩니다** (정책 결정 매트릭스 참조).
PRs with the `hotfix` label are permitted for self-approval (see policy matrix below).

---

### 5단계: CI 통과 후 즉시 머지 / Step 5 — Merge Immediately After CI Passes

5개의 필수 CI 체크가 모두 통과하면 즉시 머지합니다. 불필요한 리뷰 대기 없이 진행합니다.
Merge immediately once all 5 required CI checks pass. Do not wait for non-blocking reviews.

```bash
gh pr merge --squash --delete-branch
```

---

### 6단계: 태그 생성 / Step 6 — Create Security Tag

```bash
git fetch origin main
git switch main
git pull origin main
git tag -a "security/CVE-YYYY-NNNNN" -m "Patch for CVE-YYYY-NNNNN"
git push origin "security/CVE-YYYY-NNNNN"
```

---

### 7단계: Slack 보안 채널 공지 / Step 7 — Post to Slack #security

```
[HOTFIX MERGED] CVE-YYYY-NNNNN
- PR: <PR URL>
- Tag: security/CVE-YYYY-NNNNN
- Severity: <severity>
- Merged at: <timestamp>
- Reviewer: <name>
```

---

## 정책 결정 매트릭스 / Policy Decision Matrix

| 항목 / Item | 정책 / Policy |
|---|---|
| Self-approve | `hotfix` 레이블 부여 시 self-approve 허용 / Permitted when `hotfix` label is applied |
| CI 우회 / CI skip | **불가** — `scanner-unit-tests` 최소 필수 / **Not allowed** — `scanner-unit-tests` must pass at minimum |
| Bypass actors | **없음 (완전 잠금)** / None — branch protection is absolute |
| 사후 감사 / Post-audit trail | PR 기록 + Git blame + Slack 로그 / PR history + Git blame + Slack logs |
| 비상 에스케이프 핵 / Emergency escape hatch | `ALLOW_MAIN_PUSH=1` — 아래 섹션 참조 / See section below |

> **참고 / Note**: CIS Control 16 (Application Software Security) 및 OWASP SAMM 거버넌스 지침에 따라 모든 보안 변경은 감사 추적이 가능한 경로로 처리되어야 합니다.
> Per CIS Control 16 and OWASP SAMM governance guidance, all security changes must be processed through an auditable path.

---

## 프리-푸시 훅 우회 (비권장) / Pre-push Hook Bypass (Not Recommended)

`ALLOW_MAIN_PUSH=1` 환경 변수는 pre-push 훅을 우회하는 **비상 전용 탈출구**입니다.
The `ALLOW_MAIN_PUSH=1` environment variable is an **emergency-only escape hatch** that bypasses the pre-push hook.

**이 경로는 권장하지 않습니다. 항상 PR을 사용하십시오.**
**This path is NOT the recommended path. Always use a PR.**

이 옵션을 사용할 경우:
If this option must be used:

- 사용 전 보안팀 승인을 받아야 합니다 / Requires security-team approval before use
- 사용 즉시 Slack #security 에 공지해야 합니다 / Must be announced in Slack #security immediately
- 사후 감사 리뷰가 의무입니다 / Post-use audit review is mandatory
- PR 없이 main에 직접 머지된 커밋은 다음 스프린트에서 소급 리뷰합니다 / Commits merged directly without PR are subject to retroactive review

```bash
# 비상 시에만 / Emergency use only — requires prior approval
ALLOW_MAIN_PUSH=1 git push origin main
```

> 이 경로를 사용하면 NIST SP 800-218 SR2.2 (변경 통제) 요건이 수동으로 처리되어야 합니다.
> Using this path means NIST SP 800-218 SR2.2 (change control) requirements must be addressed manually.

---

## 사후 처리 체크리스트 / Post-Incident Checklist

머지 완료 후 다음 항목을 순서대로 처리합니다.
After merge, complete the following items in order.

### CVE 및 취약점 관리 / CVE and Vulnerability Management

- [ ] NVD(국가 취약점 데이터베이스) 또는 관련 DB에 CVE 등록 확인 / Confirm CVE registration in NVD or relevant database
- [ ] GitHub Security Advisory 생성 / Create GitHub Security Advisory
- [ ] 내부 취약점 관리 시스템에 기록 / Log in internal vulnerability management system

### 영향 분석 / Impact Analysis

- [ ] 영향 받는 버전 범위 확정 / Confirm affected version range
- [ ] 익스플로잇 가능 여부 및 실제 악용 흔적 조사 / Investigate exploitability and evidence of active exploitation
- [ ] 관련 시스템 및 의존성 파악 / Identify affected systems and dependencies

### 고객 통보 / Customer Notification

- [ ] 고객 통보 필요 여부 결정 (GDPR 72시간 규정 고려) / Determine whether customer notification is required (consider GDPR 72-hour rule)
- [ ] 통보 대상 및 채널 확정 / Confirm notification targets and channels
- [ ] 공개 보안 공지(Security Advisory) 게시 여부 결정 / Decide whether to publish a public Security Advisory

### 재발 방지 / Recurrence Prevention

- [ ] 근본 원인 분석(RCA) 문서 작성 / Write Root Cause Analysis (RCA) document
- [ ] 동일 패턴의 취약점이 코드베이스에 존재하는지 스캐너로 확인 / Run scanner to check for same vulnerability pattern across codebase
- [ ] 재발 방지를 위한 자동화 탐지 규칙 추가 / Add automated detection rule to prevent recurrence
- [ ] 핫픽스 프로세스 개선 사항이 있으면 이 문서에 반영 / Update this document if hotfix process improvements are identified

---

## 참고 자료 / References

- [NIST SP 800-218 — Secure Software Development Framework (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [OWASP SAMM — Incident Management](https://owaspsamm.org/model/operations/incident-management/)
- [CIS Control 16 — Application Software Security](https://www.cisecurity.org/controls/application-software-security)
- [GitHub — Managing security vulnerabilities](https://docs.github.com/en/code-security/security-advisories)
- [OWASP — Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
# CVE-2026-0000 Mock Drill (2026-04-11T10:27:59Z)
# This line simulates a security patch applied during a drill.
