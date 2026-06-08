---
title: "세션 성과 보고서 2026-06-08 — CI 게이트 강화"
description: "CI 설정 회귀 가드 4종 도입, fork-guard·CRITICAL 머지 차단 격상, kcov-debug 스킬·rules 정비, 그리고 lychee v0.24.2 회귀(#204) 적발·복구(#210)까지 (#197–#211)"
tags:
  - session-report
  - ci-cd
  - branch-protection
  - supply-chain
  - regression-guard
  - devsecops
  - github-actions
---

# 세션 성과 보고서 — 2026-06-08 (CI 게이트 강화)

## 세션 개요

ClaudeSec CI의 **집행 무결성(enforcement integrity)** 을 체계적으로 강화했다.
핵심은 "게이트가 조용히 약화되는" 실패 유형(OWASP CICD-SEC-1 Insufficient Flow
Control, CICD-SEC-7 Insecure System Configuration)을 코드로 막는 **회귀 가드**의
도입이다. 부수적으로 직접 도입한 버전 업그레이드가 회귀를 일으켰고, CI가 이를
잡아내 즉시 복구·가드화한 과정을 함께 기록한다.

## 머지 타임라인

| PR | 내용 | 분류 |
|----|------|------|
| #197 | `.claude/rules/` 5개 `[CUSTOMIZE]` 섹션을 claudesec 실제 규칙으로 작성 | 정비 |
| #198 | `kcov-debug` 스킬(커버리지 게이트 디버깅 플레이북) | 도구 |
| #199 | kcov-debug §4 현재 baseline + hourly-ops 트러블슈팅 링크 | 문서 |
| #200 | `test_ci_coverage_thresholds.py` — 커버리지 floor 가드(pytest 99%, kcov 90%) | **가드** |
| #201 | `test_ci_gate_topology.py` — 전 워크플로우 SHA 핀 + lint-gate.needs 완전성 | **가드** |
| #203 | `workflow-fork-guard`를 lint-gate.needs에 편입(머지 차단 격상) | **게이트** |
| #204 | lycheeVersion v0.23.0→v0.24.2 업그레이드 | ⚠️ 회귀 유발 |
| #205 | `test_ci_security_gate.py` — Security Scan Gate 토폴로지 + dast PR 트리거 | **가드** |
| #206 | scan 잡: CRITICAL finding에 `exit 1`(머지 차단) | **게이트** |
| #207 | `docs/devsecops/ci-config-regression-guards.md` 카탈로그 | 문서 |
| #208 | scan CRITICAL `exit 1` 회귀 가드(invariant E) | **가드** |
| #210 | lycheeVersion v0.24.2→v0.23.0 복구(회귀 hotfix) | 🔴 hotfix |
| #211 | `lycheeVersion == v0.23.0` 핀 회귀 가드 | **가드** |

## CI 설정 회귀 가드 스위트

`scanner/tests/test_ci_*.py` — stdlib 전용(PyYAML은 `requirements-ci.txt`에 없음),
`scanner-unit-tests` 잡에서 실행되며 `scanner/lib`를 import하지 않아 99% 커버리지
게이트에 영향을 주지 않는다. 방향성은 명시적이다(floor는 `>=`, 핀은 `==`, 트리거는
존재 검사). 도입한 8개 단언:

1. pytest `--cov-fail-under >= 99`
2. bash kcov `threshold >= 90.0`
3. 전 `.github/workflows/*.yml`의 `uses:` 40-hex SHA 핀(OWASP A08)
4. `lint-gate.needs` 완전성(allowlist = `{lint-gate}`만)
5. `lycheeVersion == v0.23.0`(의도적 업그레이드 차단 — 아래 회귀 참조)
6. `security-scan-gate`의 `always()` + `needs ⊇ {changes,scan,lighthouse}` + pass-set
7. `dast-baseline.yml`의 `pull_request` 트리거 유지
8. scan 잡의 CRITICAL `exit 1` 유지(HIGH는 비차단)

### non-vacuous 일괄 검증 (2026-06-08)

각 단언을 임시 복사본에 의도적으로 변조(예: floor 99→80, SHA→`@v4`, needs에서 잡
제거, `exit 1` 삭제)한 뒤 가드를 실행해 **8/8 모두 정확히 실패**함을 확인했다.
실제 워크플로우 파일은 무손상(monkeypatch + 임시 파일), 원본 대상 17개 테스트는
정상 통과.

## 게이트 격상

- **#203 — fork-guard 머지 차단화**: `workflow-fork-guard`(pull_request_target
  fork-guard 감사, OWASP A08)는 매 PR 실행되지만 `lint-gate.needs`에도 필수 체크에도
  없어 red여도 merge를 막지 못했다. needs에 편입해 차단으로 격상. 토폴로지 가드(#201)가
  적발.
- **#206 — CRITICAL 머지 차단화**: scan 잡 헤더는 "CRITICAL에 fail"이라 했으나 코드는
  `::warning::`만 출력했다(문서-코드 모순). 메인테이너 결정으로 `exit 1`을 추가해 실제
  차단으로 일치시킴(HIGH는 경고 유지). 도입 시점 스캔이 `Critical: 0`이라 현행 CI 비파괴,
  PR 자체 scan 잡이 clean tree 통과를 in-CI 확인.

## 회귀 사후분석 — lychee #204 → #210

- **무엇**: #204에서 `lycheeVersion`을 v0.23.0→v0.24.2로 올렸다. 자산 **파일명**은
  v0.24.1+에서 flat로 복구됐음을 확인했으나, **tarball 내부 레이아웃**까지는 검증하지
  못했다. v0.24.x는 바이너리를 `lychee-<triple>/` 하위에 **중첩**시키는데, 핀된
  lychee-action installer는 루트의 바이너리를 기대 →
  `install: cannot stat '.../lychee-download/lychee'`로 링크 검사 전에 실패.
- **적발**: link-check는 `\.md$`에 path-gating되어 워크플로우-only PR(#204)에서는
  실행되지 않았고, **첫 markdown PR(#207)** 에서 비로소 실패로 드러났다.
- **복구**: #210에서 v0.23.0으로 되돌리고, 두 버전 tarball을 직접 받아 레이아웃 차이
  (v0.23.0=루트, v0.24.x=중첩)를 실증. #207을 복구된 main 위로 rebase해 link-check가
  v0.23.0으로 통과함을 in-CI 확인.
- **재발 방지**: #211에서 `lycheeVersion == v0.23.0` equality 가드 추가. upstream
  lychee-action 자신도 동일 이유로 default를 v0.23.0으로 유지한다.

## 교훈

1. **소비자의 end-to-end 경로를 검증하라**: 산출물의 존재/이름만이 아니라 그것을 쓰는
   쪽(여기선 action installer)의 전 경로를 확인해야 한다. 파일명 ✓ 만으로 레이아웃 ✗ 를
   놓쳤다.
2. **path-gating은 양날의 검**: 비용을 줄이지만, 워크플로우-only 변경은 그 게이트를
   in-PR에서 실증하지 못하게 만든다(link-check, scan 모두). 변경을 실제로 행사하는 PR이
   필요하다.
3. **transient는 재실행**: #206 재검증 중 Docker Hub `alpine:3.20` i/o timeout(36초
   조기 실패)은 정책대로 재실행으로 해소(가짜 실패를 회귀로 오인하지 않음).
4. **게이트는 코드로 지켜라**: 조용한 약화를 막는 회귀 가드는 incident가 실재할 때
   가장 가치 있다(가드 남발 금지). 각 가드는 구체적 incident를 근거로 한다.

## 참고

- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1, CICD-SEC-3, CICD-SEC-7:
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- OWASP Top 10:2021 A08 — Software and Data Integrity Failures:
  <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/>
- NIST SP 800-218 (SSDF) — PO.3, PW.4:
  <https://csrc.nist.gov/pubs/sp/800/218/final>
- 가드 카탈로그: `docs/devsecops/ci-config-regression-guards.md`
- 가드 구현: `scanner/tests/test_ci_coverage_thresholds.py`,
  `scanner/tests/test_ci_gate_topology.py`, `scanner/tests/test_ci_security_gate.py`
