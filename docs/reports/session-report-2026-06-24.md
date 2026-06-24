---
title: "세션 성과 보고서 2026-06-24"
description: "CI 가드 comment-evasion 하드닝 캠페인 + 공급망 운영 (PR #264–#279) 종합 회고"
tags:
  - session-report
  - ci-cd
  - supply-chain
  - testing
  - devsecops
---

# 세션 성과 보고서 — 2026-06-24

CI 설정 회귀 가드(`scanner/tests/test_ci_*.py`)의 **comment-evasion false-negative
클래스**를 발견·제거하고, npm provenance/공급망 운영을 강화한 멀티-PR 캠페인 요약.
모든 변경은 PR별 코드오너 승인 + CI green 후 squash-merge 되었다.

## 머지된 PR

| PR | 내용 | 핵심 결과 |
|----|------|-----------|
| #264 | provenance-verify cadence + OIDC npm floor | `workflow_run`(publish 직후)+daily 스케줄; `npm@'>=11.5.1'` 핀 + 가드 |
| #270 | injection-surface 가드 신설 | `run:` 본문 untrusted `${{ github.event.* }}` 탐지 (OWASP CICD-SEC-4). 적대적 리뷰 2회가 각각 CRITICAL 발견 → 문법-완전 규칙으로 해결 |
| #271 | comment-evasion 하드닝 (CRITICAL+3 HIGH) | security-gate `exit 1` 머지차단 우회 등 4개 가드 수정 |
| #272 | pytest 9.1.0→9.1.1 (Dependabot) | 안전 patch, auto-merge |
| #273 | nginx digest bump (Dependabot) | alpine 태그 불변, 코드오너 승인 머지 |
| #274 | actions group: checkout v6→v7, cache v5→v6, junit patch (Dependabot) | 전부 SHA-핀; checkout v7 fork-PR 차단 보안 강화 |
| #275 | audit 백로그 F-5/F-6/F-7 | needs-scoping, upgrade-ordering, `extract_on_block` inline-comment + util 첫 직접 테스트 |
| #276 | npm-publish dry-run 버그 수정 | 이미 게시된 버전 dry-run "cannot publish over" 에러 차단 |
| #277 | audit 백로그 F-8/F-9 | prowler-ordering comment-strip + DAST on-block 공유 파서 |
| #278 | ADR-001 | 가드 하드닝 규율 결정 기록 (repo 첫 ADR) |
| #279 | ADR-001 운영화 | 분기 guard-audit 리마인더 워크플로 + ADR 인덱스 |

## 핵심 발견과 교훈

1. **Comment-evasion false-negative 클래스.** substring/regex 가드는 보호 토큰이
   `#` 주석에만 남아도 통과 → 머지차단 게이트가 조용히 무력화될 수 있다(OWASP
   CICD-SEC-1). 공유 `_ci_guard_util` comment-stripper 경유로 일괄 해결.
2. **2-pass 적대적 리뷰.** injection 가드(#270)와 전수 감사(#271) **모두 1차 리뷰
   후에도 잔존 CRITICAL hole이 있었다.** substring/parse 가드는 머지 전 2회
   적대적 리뷰가 필요하다.
3. **문법-완전 규칙 > 폼 열거.** block-scalar 헤더(`|2-`, `| # comment`)를 열거식
   정규식으로 잡으려다 두 번 뚫렸고, "`|`/`>`로 시작하면 block scalar"라는 문법
   규칙으로 전환해 클래스 전체를 종결.
4. **provenance e2e는 프로덕션에서 확인.** `workflow_run` 트리거가 main push마다
   실제 발동(5+회 success)함을 run 이력으로 검증.
5. **dry-run latent 버그.** `npm publish --dry-run`은 이미 게시된 버전에서도
   레지스트리 pre-check로 실패 → dispatch 경로가 깨졌었다(#276 수정).

이 결정들은 [ADR-001](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md)로
codify 되었고, 분기 적대적 감사는 `guard-audit-reminder.yml`로 자동 리마인드된다.

## 검증 지표

- `scanner/tests/test_ci_*.py` + `test__ci_guard_util.py` → **202 passed** (pytest + `python3 -m unittest` 양 러너).
- `scanner/lib` 커버리지 **99.12%** (≥99% floor 유지 — 가드는 `scanner/lib` 미import).
- kcov bash floor 90% CI 강제 (live ~91.74%).
- audit 백로그 **F-1..F-9 전부 클리어**; verifier sweep PASS, 카탈로그 1:1(22 가드).
- 가드 파일 22개 `test_ci_*.py` + 1개 `test__ci_guard_util.py`.

## 후속 관찰 항목

- **checkout v7 fork-PR 동작.** #274로 전 워크플로가 `actions/checkout` v7로 전환됨
  (fork-PR checkout을 `pull_request_target`/`workflow_run`에서 차단). 단일-오너
  레포라 fork PR 부재 → 첫 외부 fork PR / `dependency-review` 실행에서 정상 동작 확인 필요.
- **버전 주석 불일치(경미).** #274 Dependabot bump가 일부 `actions/checkout` 라인에
  `# v4.2.2`(stale) 주석을 남겼다 — SHA는 정확(v7.0.0), gate-topology 가드는 40-hex만
  검사하므로 기능 영향 없음. 주석 정리 권장(저우선).

## 참고

- [CI Config Regression Guards 카탈로그](../devsecops/ci-config-regression-guards.md)
- [ADR-001](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md) ·
  [ADR 인덱스](../devsecops/adr-index.md)
- OWASP Top 10 CI/CD Security Risks: <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (SSDF): <https://csrc.nist.gov/pubs/sp/800/218/final>
