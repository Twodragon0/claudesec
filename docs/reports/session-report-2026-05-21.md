---
title: "세션 성과 보고서 2026-05-21"
description: "보안 베이스라인 유지 가운데 7건 PR 머지 — 의존성 위생, 회귀 게이트, OG 브랜드, 커버리지, DAST 스캐폴딩"
tags:
  - session-report
  - dependencies
  - security
  - coverage
  - devsecops
---

# 세션 성과 보고서 — 2026-05-21

## 세션 개요

- **Date range**: 2026-05-19 → 2026-05-21
- **PRs merged**: 7 (#156, #157, #158, #159, #141, #101, #160)
- **PRs closed (superseded)**: 1 (#58)
- **Security baseline**: Grade A · score 100 · 0 failed · 21 passed — 변동 없음
- **Test count**: 1022 → 1076 passed (+54: #101 +40, #158 +5, #161 진행 중 +19)

## 머지 타임라인

| # | Merged at (UTC) | SHA | Title |
|---|---|---|---|
| #156 | 2026-05-19 05:36 | `b731fb9` | ci: bump pip to 26.1+ in pip-audit to clear CVE-2026-6357 |
| #158 | 2026-05-19 05:43 | `b6ea779` | test: lock scan-report.json grade-A baseline against regression |
| #159 | 2026-05-19 05:54 | `4342768` | feat(brand): rebalance OG card right panel with live security metrics |
| #157 | 2026-05-19 06:07 | `4531861` | chore(deps): bump the actions group across 1 directory with 4 updates |
| #141 | 2026-05-19 07:41 | `5595f45` | chore(deps): bump the pip-deps group across 1 directory with 4 updates |
| #101 | 2026-05-19 07:46 | `64f1cc6` | test: add unit tests for dashboard_api_client with urlopen mocked |
| #160 | 2026-05-21 01:34 | `849169b` | feat(dast): add docker-compose.staging.yml reference target |

## 의존성 위생

### #156 — pip 26.1+ in pip-audit

`actions/setup-python@a309ff8`가 제공하는 기본 pip 26.0.1이 CVE-2026-6357(self-update wheel-import 순서 결함)에 노출. `pip-audit --strict`가 러너 자신의 pip를 fail로 잡으면서 신규 PR이 줄줄이 막혔던 원인. `.github/workflows/lint.yml`의 pip-audit 잡 install 단계에 `pip install --upgrade 'pip>=26.1'`을 추가해 해결. `--ignore-vuln`은 늘리지 않음. 부수로 `.gitignore`에 `.coverage`, `htmlcov/` 추가.

### #157 — actions group bump (4 updates)

`.github/workflows/lint.yml`의 액션 SHA 핀 4건 갱신:

| Action | From | To | 비고 |
|---|---|---|---|
| `actions/dependency-review-action` | v4.9.0 | v5.0.0 | major bump |
| `codecov/codecov-action` | v6.0.0 | v6.0.1 | patch |
| `mikepenz/action-junit-report` | v6.4.0 | v6.4.1 | patch |
| `DavidAnson/markdownlint-cli2-action` | v23 SHA | v23 SHA refresh | tag-stable SHA 갱신 |

dependency-review-action major bump 때문에 dependabot 자동머지가 skip. 코드 오너 승인 후 일반 squash 머지.

### #141 — pip-deps group bump (4 updates)

`requirements-ci.txt`:

| Package | From | To |
|---|---|---|
| pytest | >=7.0 | >=9.0.3 |
| pytest-cov | >=4.0 | >=7.1.0 |
| requests | >=2.28 | >=2.33.1 |
| Pillow | >=10.0 | >=12.2.0 |

pytest·pytest-cov가 메이저 점프라 머지 전 별도 venv에서 회귀 1회 실행 — `scanner/tests/` **1022 passed, 205 subtests** 무손실 확인 후 진행.

## 품질 게이트

### #158 — scan-report.json baseline 회귀 테스트

`scanner/tests/test_scan_report_baseline.py` 신규 (5 assertions):

```
summary.grade == "A"
summary.failed == 0
summary.score >= 100
summary.passed >= 21
모든 results[*].status != "fail"
```

`scan-report.json` 부재 시(fresh clone) `@unittest.skipIf`로 우아하게 스킵하고, CI에서는 scanner 실행 후 pytest가 검증. 향후 어떤 변경이든 베이스라인을 떨어뜨리면 CI가 차단.

### #101 — dashboard_api_client 단위 테스트

`scanner/lib/dashboard_api_client.py` 커버리지 **44.5% → 89%** (측정치, 목표 70% 초과 19pp). `urllib.request.urlopen`을 전부 mock해 네트워크 호출 0회. 40 테스트, GitHub API 경유 함수 전반 커버: `_github_api_json`, `_fetch_audit_points_from_github`, `_fetch_repo_focus_files`, `_fetch_microsoft_best_practices_from_github`, `_fetch_saas_best_practices_from_github`, `_fetch_markdown_preview`.

> **진행 중**: PR #161이 잔여 22 statement 에러 폴백 브랜치까지 채워 **100% 커버리지** 도달, CI 대기 중.

## 브랜드 / SEO

### #159 — OG 카드 우측 패널 리밸런스

이전 1200×630 카드의 우측 절반(`x=760..1200`)은 다크-온-다크 (`#1e293b` on `#111827`, 명도비 ~1.1:1) 마스코트라 SNS 미리보기에서 비어 보이는 문제. 마스코트를 세 가지 라이브 보안 지표 카드로 교체:

- **21/21** OWASP Top 10 checks
- **A** grade · score 100
- **0** critical findings

다크/라이트 SVG 변형 양쪽 동기화 + `rsvg-convert`로 PNG 재생성(약 70KB). 라이브 검증: HTTP 200, `last-modified` 새 빌드 시각, etag 갱신 확인. 카카오/페북 캐시는 외부 디버거 UI에서 강제 갱신 필요.

## DAST 스캐폴딩

### #160 — docker-compose.staging.yml 신규 (37 lines)

`docs/devsecops/dast-testing.md:139,161`이 참조하던 누락 파일을 보강:

- `app` 서비스: `APP_IMAGE` / `APP_PORT` 환경변수로 파라미터화, `/health` healthcheck
- `zap-config` 사이드카: `templates/zap-rules.tsv`를 ZAP 룰 경로로 마운트
- 전용 `dast-net` 브리지 네트워크

GitHub Actions 워크플로우가 직접 참조하지는 않음 — DAST 가이드를 따라가는 사용자를 위한 문서급 스캐폴딩.

#### #58 종료 처리

`feat: DAST 워크플로우, 슬래시 커맨드 확장, 소스 인용 보완` (2026-03-24 작성) — 23개 파일 중 19개가 그 이후 main에서 독립적으로 갱신됨(`.github/workflows/lint.yml` 한 파일만 26회 충돌 커밋). 리베이스 비용 대비 회수 가치가 낮아 close. 진짜 net-new였던 `docker-compose.staging.yml`만 #160으로 분리해 살림.

## 검증 스냅샷

세션 마지막 확인값:

```
PYTHONPATH=. CLAUDESEC_DASHBOARD_OFFLINE=1 pytest scanner/tests/ -q
# → 1062 passed, 205 subtests in 3.27s (main HEAD)

./scanner/claudesec scan --category code --format json | jq .summary
# {
#   "total": 24, "passed": 21, "failed": 0,
#   "warnings": 0, "skipped": 3,
#   "score": 100, "grade": "A"
# }

PYTHONPATH=scanner/lib CLAUDESEC_DASHBOARD_OFFLINE=1 pytest \
  scanner/tests/test_dashboard_api_client_unit.py \
  --cov=dashboard_api_client --cov-report=term-missing
# → 40 passed, 89% coverage (22 missing — addressed in #161)
```

OG 라이브 검증 — `https://twodragon0.github.io/claudesec/assets/claudesec-og-card.png` HTTP/2 200, 새 PNG `last-modified` 2026-05-19 06:08:01 GMT, `og:image` / `twitter:image` 메타 정상.

## 운영 메모

- **자기 PR 머지 제약**: `#101`은 작성자(Twodragon0)와 머지 실행자가 동일해 GraphQL `Review Can not approve your own pull request` 차단. `--admin` 플래그로 우회. CODEOWNERS가 단일인 1인 레포의 구조적 한계.
- **Dependabot rebase 연쇄**: 같은 파일(`lint.yml`)을 건드리는 PR이 직렬로 머지되며 `#155 → #157 → #141`이 매번 `BEHIND`가 되어 `@dependabot rebase`를 두 번 호출. `#155`는 결국 dependabot이 PR을 자체 폐기하고 `#157`로 재생성.
- **OG 메트릭 신뢰성**: 카드에 박힌 `21/21`, `A`, `0`은 #158 회귀 게이트가 떨어지면 거짓이 됨. 향후 베이스라인 변경 시 OG 카드도 같이 갱신해야 함을 명시.

## 후속 작업

- **PR #161** (dashboard_api_client 100% 커버리지) — CI 대기, 그린 시 머지
- **Node20 deprecation deadline 2026-06-02** — 잔여 액션 점검 필요(이번 #157의 `dependency-review-action` v5.0.0 업그레이드로 1건 해소)
- **`scanner/lib/dashboard_utils.py` 등 잔여 모듈 커버리지** — 동일한 mocked-urlopen 패턴으로 확장 가능
- **카카오/페북 OG 캐시 강제 갱신** — 외부 디버거 UI 작업 (developers.kakao.com/tool/debugger/sharing, developers.facebook.com/tools/debug)
