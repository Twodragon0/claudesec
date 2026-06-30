---
title: "세션 성과 보고서 2026-06-01 (PM)"
description: "kcov 27분 stall 근본원인 규명 — 100% 네트워크 대기(0% CPU), H2(ptrace/xtrace) 최종 배제, OFFLINE env + hermetic 가드 (#190, #191)"
tags:
  - session-report
  - kcov
  - root-cause-analysis
  - ci-cost
  - github-actions
  - devsecops
---

# 세션 성과 보고서 — 2026-06-01 (PM)

## 세션 개요

- **Date range**: 2026-06-01 PM ~ 2026-06-02
- **PRs merged**: 2 (#190, #191)
- **Goal**: `scanner-shell-coverage`(kcov) 잡의 만성 stall(35초~27분 가변) 근본원인 규명 및 영구 제거
- **결과**: `test_output_coverage.sh` kcov 런타임 **120s 타임아웃 캡 히트 → 2초**, 잡 전체 **최대 27분 → ~1분**, 커버리지 91.74% 불변

이 세션은 [AM 리포트](session-report-2026-06-01.md)의 "남은 후속 작업" #1(kcov 런타임 가변성 조사)과 #3(scanner-shell-coverage 분할)을 모두 종결한다 — 분할은 불필요로 판명되었고, 가변성의 근본원인이 규명되었다.

## 머지 타임라인

| # | Merged at (UTC) | SHA | Title |
|---|---|---|---|
| #190 | 2026-06-01 07:37 | `fcca46b` | fix(ci): set CLAUDESEC_DASHBOARD_OFFLINE=1 for kcov shell-coverage job |
| #191 | 2026-06-02 00:30 | `ca37382` | test(scanner): hermetic offline guard in generate_html_dashboard tests |

## 배경 — 기존 가설과 그 한계

이전 세션들은 kcov stall을 다음 순서로 추적했다:

1. **#187** — per-test `::group::` + `elapsed=Ns rc=X` 타이밍 로깅 + `timeout 120` 방어 캡 추가. 어떤 테스트가 느린지 가시화.
2. **#189** — H2 가설: `$(fail ... 2>&1)` 캡처로 xtrace가 누출되어 kcov ptrace 증폭을 유발한다. 모든 캡처에 `set +x` strip 적용.
3. 그러나 #189 적용 후에도 `test_output_coverage`는 **120s 캡을 그대로 히트**. H2는 **경험적으로 반증**되었고, 당시 결론은 "timeout 캡이 유일한 실질 방어책, 근본원인 미상"이었다.

핵심 미해결 관측: 동일 테스트의 wall-clock이 **35초 ~ 27분**으로 극단적으로 가변. 이 가변성 자체가 단서였다.

## 근본원인 규명 (이번 세션)

### 1. 비용 집중 지점 식별

`test_output_coverage.sh`는 `generate_html_dashboard()`를 **24회** 호출한다 — Group 2에서 1회 + Group 3(`_id_to_category` 전체 분기 매트릭스)에서 23회. `output.sh::generate_html_dashboard()`는 매 호출마다 `python3 dashboard-gen.py`를 spawn한다 (`scanner/lib/output.sh:743`).

### 2. 네트워크 의존 발견

`dashboard-gen.py`는 `CLAUDESEC_DASHBOARD_OFFLINE`이 truthy가 아니면 GitHub API 라이브 호출을 수행한다 (`dashboard_data_loader.py:172, 210, 248`에서 게이팅). 그런데:

- `CLAUDESEC_DASHBOARD_OFFLINE: "1"`은 `scanner-unit-tests` 잡의 pytest 스텝(`lint.yml:188`)에만 설정되어 있었고,
- kcov가 도는 **`scanner-shell-coverage` 잡에는 설정되어 있지 않았다.**

즉 kcov 루프에서 24회의 `generate_html_dashboard` 호출이 각각 python을 spawn하고 라이브 GitHub API I/O를 수행했다.

### 3. 결정적 실증 — 100% 네트워크 대기, kcov 무관

**kcov를 전혀 사용하지 않은** 순수 bash 실행(OFFLINE 미설정):

```text
6.83s user  1.92s system  0% cpu  27:08.69 total
=== Results: 76 passed, 0 failed ===
```

- **wall-clock 27분 8초**, 그러나 **user+sys = 8.75초 CPU, 0% cpu**.
- 27분 전체가 네트워크 I/O 블로킹(대기). CPU 작업은 9초 미만.
- kcov가 개입하지 않았는데도 메모리에 기록된 "27분 worst case"를 정확히 재현.

이로써 **ptrace/xtrace 증폭은 원인이 아님이 확정**된다. H2는 최종 배제. 가변성(35초~27분)의 정체는 **GitHub API 응답 지연/타임아웃 변동**이었다.

### 4. OFFLINE 효과 측정

```text
CLAUDESEC_DASHBOARD_OFFLINE=1  →  3.676s, 76 passed / 0 failed
```

순수 bash 기준 27분 8초 → 3.7초, **~440배**.

## #190 — 근본 수정: kcov 잡에 OFFLINE env

`scanner-shell-coverage` 잡에 잡 레벨 `env:` 한 줄 추가 (모든 스텝, kcov 루프 포함 적용):

```yaml
env:
  CLAUDESEC_DASHBOARD_OFFLINE: "1"
```

### 커버리지가 불변인 이유

네트워크 호출은 **python(`dashboard-gen.py`)** 안에 있고, kcov는 `--include-pattern=checks.sh,output.sh`로 **bash만** 측정한다. 따라서 네트워크 호출은 측정 대상 bash 커버리지에 **0 기여** — 순수 낭비였다. OFFLINE 모드는 `output.sh`의 python 호출 경로를 동일하게 유지한다(python 실행, exit 0, 출력 파일 작성 → `output.sh:745-747`의 `return 0` 경로 그대로). 로컬에서 `generate_html_dashboard` rc=0 + dashboard HTML + scan-report.json 모두 작성 확인.

### CI 실증 (PR #190)

| 항목 | 이전 | 이후 |
|---|---|---|
| `test_output_coverage` (kcov) | 120s 캡 히트 / 27분 stall | **2초, rc=0** |
| 잡 전체 | 최대 27분 | **1분 0초** |
| TIMED OUT 경고 | 발생 | **0건** |
| 병합 bash 커버리지 | 91.74% | **91.74% (불변, 90% 통과)** |

## #191 — 회귀 방지: hermetic 가드

PR #190은 **잡 레벨**에서 OFFLINE을 설정하므로, env 항목이 제거되거나 테스트가 다른 컨텍스트에서 실행되면 다시 행이 걸릴 수 있다. 이를 막기 위해 `generate_html_dashboard`를 호출하는 3개 테스트에 자가 설정을 추가:

```bash
export CLAUDESEC_DASHBOARD_OFFLINE=1
```

대상: `test_output_coverage.sh`, `test_generate_html_dashboard.sh`, `test_output_functions.sh`.

### fail-fast 대신 자가 설정(hermetic)을 택한 이유

순수 fail-fast 가드(`미설정 시 exit 1`)는 로컬 `bash scanner/tests/test_*.sh` 실행을 깨뜨린다. 자가 설정은 동일한 회귀 보호(절대 행 안 걸림)를 제공하면서 로컬 실행을 매끄럽게 유지한다.

### 검증 (env `env -u`로 명시적 제거 = 잡 env 누락 시뮬레이션)

| Test | 결과 |
|---|---|
| test_output_coverage | **4.3s, 76 passed / 0 failed** (가드 전 27분 행) |
| test_generate_html_dashboard | **0.12s, 36 passed / 0 failed** |
| test_output_functions | **0.42s, 225 passed / 0 failed** |

`shellcheck -S error`: clean. CI(PR #191) kcov 잡에서 세 테스트 모두 0~2초, 커버리지 91.74% 유지.

## 분할(원래 계획)을 기각한 이유

AM 리포트의 후속 작업 #3은 "scanner-shell-coverage 자체 분할"이었고, 이번 세션의 초기 요청도 `test_output_coverage.sh`를 기능별로 분할하는 것이었다. 그러나:

- kcov 루프(`lint.yml:316`, `for sh in scanner/tests/test_*.sh`)는 **단일 러너에서 순차 실행**된다. 한 파일을 N개로 쪼개도 같은 순차 루프에 N개 항목이 생길 뿐, **병렬 러너로 분산되지 않는다.**
- 진짜 레버는 네트워크 제거였다. OFFLINE 수정이 120s 캡 → 2초로 떨어뜨려 **분할의 필요성 자체를 제거**했다.

## 교훈

- **`0% cpu` + 긴 wall-clock = I/O 대기**의 결정적 시그니처. 프로파일링 시 CPU 시간과 wall-clock을 분리해서 봐야 한다. 본 건은 이 한 줄이 ptrace 가설을 즉시 배제했다.
- **커버리지 측정 범위 밖의 부수 효과(네트워크)가 측정 대상의 런타임을 지배**할 수 있다. kcov include-pattern이 bash만 측정하므로 python 네트워크 호출은 순수 오버헤드였다.
- **테스트 env 일관성**: 한 잡(pytest)에만 OFFLINE을 설정하고 다른 잡(kcov)에는 누락한 것이 근본 결함. hermetic 가드(#191)로 테스트 자체가 env에 비의존적이 되도록 강화.
- 경험적 반증("H2 refuted")이 곧 근본원인 규명은 아니다. #189는 H2를 옳게 배제했지만 진짜 원인은 다른 곳에 있었고, 가변성 단서를 끝까지 추적해야 했다.

## 남은 후속 작업

1. **timeout 120 캡 적정값 재산정**: 근본원인 제거로 모든 테스트가 ≤2초 안에 완료. 120s 캡을 ≤30s로 강화해 향후 네트워크 의존 회귀를 조기에 fail-fast시킬지 검토.
2. **per-test soft-warn**: kcov 잡에 per-test 30s 경고를 추가해, 향후 OFFLINE 미설정 등으로 네트워크에 의존하는 신규 테스트를 조기 탐지.
3. **OFFLINE 의존 신규 테스트 가드 자동화**: `generate_html_dashboard`를 호출하는 신규 테스트가 OFFLINE 가드 없이 추가되는 것을 lint/리뷰 단계에서 검출하는 메커니즘 검토.

## 참고

- kcov v42 — `--include-pattern` 및 ptrace 기반 instrumentation (<https://github.com/SimonKagstrom/kcov>)
- GitHub Actions docs — job-level `env` 컨텍스트 (<https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-variables>)
- OWASP DevSecOps — 테스트 격리(hermetic tests)와 외부 의존성 제거 원칙 (<https://owasp.org/www-project-devsecops-guideline/>)
