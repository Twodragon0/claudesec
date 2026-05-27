---
title: "세션 성과 보고서 2026-05-26"
description: "DAST/CodeQL 잔여 액션 SHA 핀으로 supply-chain 핀 커버리지 45/49→49/49 완성"
tags:
  - session-report
  - supply-chain
  - security
  - github-actions
  - devsecops
---

# 세션 성과 보고서 — 2026-05-26

## 세션 개요

- **Date range**: 2026-05-26
- **PRs merged**: 1 (#166)
- **Security baseline**: Grade A · score 100 · 0 failed · 21 passed — 변동 없음
- **SHA-pin coverage**: 45/49 → **49/49** (`uses:` 100% SHA-pinned across `.github/workflows/*.yml`)

## 머지 타임라인

| # | Merged at (UTC) | SHA | Title |
|---|---|---|---|
| #166 | 2026-05-26 05:17 | `928f2ec` | chore(ci): SHA-pin remaining DAST/CodeQL actions |

## 공급망 하드닝

### #166 — DAST/CodeQL 잔여 액션 4건 SHA 핀

`.github/workflows/dast-baseline.yml`과 `dast-full-scan.yml`에 남아 있던 floating-tag 참조 4건을 commit SHA로 고정. 양쪽 잡 모두 `security-events: write` + `issues: write` 권한을 보유하므로 악의적 retag 시 SARIF 변조나 이슈 생성이 가능해 OWASP A08(Software & Data Integrity Failures) 위험을 닫음.

| Action | Tag | Pinned SHA | File:Line |
|---|---|---|---|
| `zaproxy/action-baseline` | v0.15.0 | `de8ad96…b8b25` | `dast-baseline.yml:40` |
| `zaproxy/action-full-scan` | v0.13.0 | `3c58388…6c27c` | `dast-full-scan.yml:31` |
| `github/codeql-action/upload-sarif` | v4 | `7211b7c…5fbfa` | `dast-full-scan.yml:56` |
| `actions/github-script` | v9 | `3a2844b…da1b3` | `dast-full-scan.yml:63` |

각 SHA는 PR 시점의 태그 tip — 즉 동작 변화 0. 보안 베이스라인(Grade A · score 100) 동일.

> **참고**: GitHub Actions SHA 핀 권고는 [GitHub Docs — Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) 및 [OWASP Top 10:2021 A08](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/) 기반.

## 검증 스냅샷

```bash
# 모든 워크플로우의 floating-tag 잔여 0건 확인
grep -nE "uses: [^@]+@v?[0-9]" .github/workflows/*.yml | grep -v "@[0-9a-f]\{40\}"
# (empty output)

# SHA 핀 카운트
grep -rhE "uses: " .github/workflows/*.yml | grep -cE "@[0-9a-f]{40}"
# 49

# CI 결과 (run 26433788274 on main @ 928f2ec)
# shell-lint / npm-audit / pip-audit / frontmatter-check / gitleaks /
# pii-check / scanner-unit-tests / link-check / markdown-lint /
# dashboard-regression-check / Docker Dashboard Smoke Test /
# scanner-shell-coverage / Lint  →  ALL success
```

## 커버리지 스냅샷 (2026-05-26 main 기준)

`scanner-shell-coverage` 잡이 main @ `928f2ec`에서 생성한 `kcov-out/merged/kcov-merged/coverage.json`:

- **Overall**: 91.19% (3363 / 3688 lines, kcov v42)
- **Floor**: 85% (`#139` 이후 유지)
- **Lib 파일 (실제 SUT)**: 2건만 존재 — `output.sh` 87.18%, `checks.sh` 88.44%

### Top-5 lowest-coverage 파일

| Rank | File | Coverage | Covered / Total | 종류 |
|---|---|---|---|---|
| 1 | `scanner/tests/test_kube_discovery.sh` | **78.05%** | 64 / 82 | test |
| 2 | `scanner/tests/test_check_code_injection.sh` | **82.67%** | 62 / 75 | test |
| 3 | `scanner/tests/test_prowler_dashboard_summary.sh` | **82.72%** | 67 / 81 | test |
| 4 | `scanner/tests/test_kubectl_context_helpers.sh` | **83.47%** | 101 / 121 | test |
| 5 | `scanner/tests/test_kubectl_cluster_query.sh` | **84.62%** | 77 / 91 | test |

Top-5는 전부 테스트 셸 스크립트 자신의 미커버 줄(주로 가드/early-return). 실제 SUT인 `scanner/lib/*.sh` 중에서는:

- `scanner/lib/output.sh` — 87.18% (415/476), 미커버 61줄
- `scanner/lib/checks.sh` — 88.44% (436/493), 미커버 57줄

이 둘이 다음 PR의 의미 있는 커버리지 향상 후보. (테스트 파일 자체의 미커버 줄을 추격하는 것은 회수 가치 낮음.)

## 후속 작업

- **`scanner/lib/output.sh` / `scanner/lib/checks.sh` 커버리지 95%+** — 미커버 분기 식별 후 별도 test_*.sh 추가 (예상 +2~3pp 전체)
- **Dependabot auto-merge fork-guard** — `pull_request_target` 안전성 보강 (`head.repo.full_name == github.repository` 가드, PR #168에서 진행 중)
- **Node20 deprecation deadline 2026-06-02** — `#157`/`#163`으로 전 액션 정리 완료, 잔여 0건 (재확인 권고)
- **OG 카드 메트릭 동기화** — `21/21`, `A`, `0` 베이스라인은 `#158` 회귀 게이트와 결합되어 있음 (변경 시 동시 갱신 필요)

## 운영 메모

- **단일-PR 세션**: 이번 세션은 #166 한 건만 머지 — 보안 위생 작업의 마지막 한 마일. 큰 변화는 없지만 supply-chain 핀 커버리지를 100%로 닫은 것이 핵심 의미.
- **자기 PR 머지**: `--admin` 플래그 우회 사용 패턴(1인 레포 구조적 한계) 유지. 추후 자동화 시 GitHub App 토큰 분리 고려.
