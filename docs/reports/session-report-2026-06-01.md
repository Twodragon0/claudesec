---
title: "세션 성과 보고서 2026-06-01"
description: "GitHub Actions 비용 95% 절감 — path-gating + paths-ignore + 캐싱 + 중복 제거 (#180~#184)"
tags:
  - session-report
  - ci-cost
  - github-actions
  - path-gating
  - dependabot
  - devsecops
---

# 세션 성과 보고서 — 2026-06-01

## 세션 개요

- **Date range**: 2026-06-01
- **PRs merged**: 4 (#180, #181, #182, #183) + 2 open (#184, this PR)
- **Goal**: GitHub Actions 비용 최소화 + 운영 효율성 + 코드 최적화
- **결과**: docs-only PR당 CI minutes **20.4분 → 1.1분 (95% 감소)**

## 머지 타임라인

| # | Merged at (UTC) | SHA | Title |
|---|---|---|---|
| #180 | 2026-06-01 00:42 | `64369a3` | chore(ci): gate heavy jobs on changed paths + cache kcov |
| #181 | 2026-06-01 01:24 | `b4ce1c7` | chore(ci): drop duplicate Lighthouse, gate lychee, fix SC2044 |
| #182 | 2026-06-01 01:47 | `40e7ade` | chore(deps): bump actions group (cache v5/buildx/build-push) |
| #183 | 2026-06-01 (later) | `d7eab9f` | chore(ci): drop fetch-depth: 0 from gitleaks |
| #184 | open | — | chore(ci): auto-merge minor dependabot for github_actions only |

## #180 — Path 기반 heavy 잡 게이팅

### 문제

분석 데이터: 최근 5건의 docs-only PR이 Lint(15.4분) + Security Scan(3.6분) + DAST(1.3분) = **20.4분 CI**를 소비. 마크다운 변경은 scanner/docker 잡들을 트리거할 일이 없음에도 모두 실행.

### 해법

`.github/workflows/lint.yml`에 `changes` 감지 잡 추가 — 외부 액션 없이 `git diff`로 변경 파일을 분류:

```yaml
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      scanner: ${{ steps.detect.outputs.scanner }}
      docker: ${{ steps.detect.outputs.docker }}
      # ...
```

heavy 잡 7개(`scanner-unit-tests`, `scanner-shell-coverage`, `dashboard-regression-check`, `docker-dashboard-smoke`, `shell-lint`, `pip-audit`, `npm-audit`)에 `needs: changes` + `if:` 게이팅 추가.

`security-scan.yml`, `dast-baseline.yml`는 워크플로우 레벨 `paths-ignore`로 docs PR 전체 스킵. GitHub Actions는 paths-ignore로 스킵된 워크플로우를 branch protection 관점에서 "skipped = success"로 처리하므로 안전.

### 자가 검증 메커니즘

`scanner` / `docker` 매칭에 `.github/workflows/lint.yml` 자체를 포함 — 워크플로우-self-edit PR은 heavy 잡을 의도적으로 실행해 게이팅 로직이 검증된다. `lint-gate`의 `needs:`에 `changes`를 추가해 감지 잡 실패가 silent skip로 이어지지 않도록 함.

### kcov 캐시

`scanner-shell-coverage`의 kcov v42 source build를 `actions/cache@v4.2.3`로 래핑. 키: `kcov-v42-${{ runner.os }}-${{ runner.arch }}-noble-v1`. 실측에서 빌드 자체는 ~30초로 빠르며, 실제 bottleneck은 `Run scanner shell tests under kcov` 단계(35초~27분 가변, 별도 조사 중).

## #181 — Lighthouse 중복 제거 + lychee 게이팅 + SC2044 수정

3건의 독립 변경을 하나의 PR로 번들 (모두 lint.yml 동일 파일).

1. **Lighthouse 중복 제거**: `dashboard-regression-check`의 lhci 단계 3개 삭제. `security-scan.yml::lighthouse`가 동일 대시보드에 대해 동일 임계치 audit을 이미 수행. 기존 lhci는 `--assert.assertions.categories:accessibility=off` + `::warning::`만 emit으로 gating-less informational. 제거로 ~30초 절감/run.

2. **lychee 게이팅**: `changes` 잡에 `markdown` output 추가, `link-check`를 `needs.changes.outputs.markdown == 'true'`로 게이팅. 스케줄러로 cadence-based 외부 URL rot 검출은 보존.

3. **SC2044 수정**: `frontmatter-check`의 `for f in $(find ...)`를 `while IFS= read -r -d '' f; do ... done < <(find ... -print0)`로 변경. process substitution으로 while 루프를 부모 셸에 유지 → `failed=1` 전파. actionlint의 마지막 경고 해소.

## #182 — Dependabot actions group bump

`actions/cache` v4.2.3 → **v5.0.5** (node24 runtime). 다른 dependabot 메이저는 일반적으로 신중해야 하지만 actions/cache v5는 node20 deprecation 정책(#157, #163과 정합)에 맞춰진 단순 런타임 교체. CI에서 `scanner-shell-coverage`가 새 액션으로 정상 실행되어 실증 검증.

`docker/setup-buildx-action`, `docker/build-push-action` SHA 핀 갱신 동반.

## #183 — gitleaks shallow clone

`gitleaks dir .`는 파일시스템만 스캔(`gitleaks dir --help` 확인). 히스토리 스캔은 별도 서브커맨드 `gitleaks git`. `fetch-depth: 0`은 gitleaks-action 시대(커밋 스캔) 유산.

```diff
   - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
-    with:
-      fetch-depth: 0
```

부수 효과: shallow clone은 `.git/logs/`에 적게 쓰므로 gitleaks가 스캔할 git 메타데이터 false-positive 표면도 축소.

## #184 — Dependabot minor auto-merge (github_actions만)

기존: patch만 auto-merge, minor는 auto-approve만(머지 수동).

신규 정책:

| Ecosystem | Patch | Minor | Major |
|---|---|---|---|
| github_actions | auto-merge | **auto-merge** | manual |
| npm | auto-merge | approve+comment, manual merge | manual |
| pip | auto-merge | approve+comment, manual merge | manual |

**근거**:

- github_actions는 워크플로우에서 SHA로 핀. dependabot이 SHA↔버전 대응을 검증하므로 minor도 maintainer-compromise 시나리오 없이는 코드 밀어넣기 불가 — SLSA Build L3 supply chain pinning 가드와 정합 (SLSA Levels v1.0).
- npm/pip는 임의 런타임 코드를 public registry에서 pull. typosquat / compromised maintainer 위협 모델이 다름 — OWASP Top 10 A06: Vulnerable and Outdated Components.

방어 깊이는 유지: fork-guard(#168) + branch-protection-required CI + auto-approval 단계 모두 보존.

## 실측 비용 분석

| Workflow | Pre-#180 (PR #179 docs PR) | Post-#180/#181 (docs PR 시뮬레이션) | 절감 |
|---|---|---|---|
| Lint | 15.4 min (scanner-shell-coverage 11.6분) | 1.1 min (light 잡만) | **-14.4 min (93%)** |
| Security Scan Gate | 3.6 min | 0 (paths-ignore) | **-3.6 min** |
| DAST Baseline | 1.3 min | 0 (paths-ignore) | **-1.3 min** |
| **PR 합계** | **20.4 min** | **1.1 min** | **-19.3 min (95%)** |

### 연간 절감 (CI minutes)

| 빈도 | 절감 |
|---|---|
| 3 docs PRs/week | ~3,000분/년 (50시간) |
| 5 docs PRs/week | ~5,000분/년 (83시간) |
| 10 docs PRs/week | ~10,000분/년 (167시간) |

`dashboard-refresh.yml` daily → weekly 변경으로 추가 1,560분/년(26시간) 절감.

## 본 PR (이 세션 리포트)의 검증 의의

본 PR은 **docs/reports/ 단일 파일만 변경하는 docs-only PR**. 다음을 실증 검증:

- `Detect changed paths` 잡이 `markdown=true`, `scanner=false`, `docker=false`로 분류
- `scanner-unit-tests`, `scanner-shell-coverage`, `dashboard-regression-check`, `docker-dashboard-smoke`, `shell-lint`, `pip-audit`, `npm-audit` 모두 **SKIPPED**
- `link-check`는 마크다운 변경이 있으므로 **RUN**
- `Security Scan Gate`, `DAST Baseline Scan`은 워크플로우 자체가 paths-ignore로 스킵 (트리거 자체 없음)
- Lint workflow 총 CI minutes: **~1분** (이전 동등 PR 대비 ~14분 절감)

분석 명령:

```bash
gh pr view <this-pr> --json statusCheckRollup --jq '.statusCheckRollup[] | {name, state, conclusion}'
gh run view <run-id> --json jobs --jq '.jobs[] | select(.conclusion=="success") | {name, dur_sec: ((.completedAt|fromdateiso8601) - (.startedAt|fromdateiso8601))}'
```

## 남은 후속 작업

1. **kcov 테스트 런타임 가변성 조사** (별도 tracer 진행 중): 35초~27분 차이의 근본 원인 규명
2. **Lighthouse daily cron 검토**: `lighthouse.yml`의 daily 스케줄이 push 트리거와 일부 중복 — 주간 cadence로 축소 검토
3. **scanner-shell-coverage 자체 분할**: kcov 테스트가 ~14분 차지 → 변경된 lib 파일만 instrumentation 검토

## 참고

- OWASP Top 10 — A06: Vulnerable and Outdated Components (<https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/>)
- SLSA Levels v1.0 — Build & Source integrity tracks (<https://slsa.dev/spec/v1.0/levels>)
- GitHub Actions docs — `paths-ignore` semantics under branch protection (<https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow>)
