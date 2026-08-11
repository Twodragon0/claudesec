---
title: "CI 가드 YAML-형태 스윕 회고 — 2026-08-06 (PR #391/#392/#393/#394)"
description: "ADR-001 Q3 감사의 '의도적 비수정' 1건을 닫으려다 가드 8개 파일에서 우회를 발견한 스윕 회고 — 트립와이어와 추출기 커버리지의 분리, 인용 키/explicit 키, 파일 열거 실명, green≠ran, red≠load-bearing"
tags:
  - session-report
  - security
  - ci-cd
  - supply-chain
  - devsecops
  - testing
---

# CI 가드 YAML-형태 스윕 회고 — 2026-08-06

## 1. 개요 (Context)

[ADR-001 Q3 감사](./adr-001-q3-audit-retrospective.md)는 Class-2 백로그를 하나만
남기고 닫혔다: `test_ci_injection_surface.py`의 **줄 분할 `${{ }}`** — stdlib-only /
no-PyYAML 제약에 묶인 "의도적 비수정".

이 세션은 그 한 항목을 닫으려고 시작했다. 결과는 훑은 약 20개 가드 중
**8개 파일에서 확인된 우회**와, 구조적으로 다른 **결함 1건**이었다
(`injection_surface`, `gate_topology`, `pr_trigger_scope`, `provenance_verify`,
`_ci_guard_util`, `codeql_single_model`, `cross_os_non_required`, `npm_publish`). 모든 발견은 뮤턴트를 만들어 가드를 **실행**해
"통제는 사라졌는데 가드는 green"임을 확인한 것이며, 정적 읽기로 주장한 것은 없다.

| PR | 상태 | 내용 | 스위트 |
|---|---|---|---|
| [#391](https://github.com/Twodragon0/claudesec/pull/391) | MERGED | `injection_surface`: 트립와이어 3개 + 인용 키 + 연속 줄 + composite action | 1699 → 1712 |
| [#392](https://github.com/Twodragon0/claudesec/pull/392) | MERGED | fork-guard PyYAML 핀·audit 범위 + `setuptools` PYSEC-2026-3447 | — |
| [#393](https://github.com/Twodragon0/claudesec/pull/393) | MERGED | 공유 YAML-형태 primitive + HIGH 5건 | 1712 → 1725 |
| [#394](https://github.com/Twodragon0/claudesec/pull/394) | OPEN | 스윕 잔여분 + `lint.yml` dead schedule arm + 신규 가드 | 1725 → 1742 |

## 2. 발견 계보 — 1건이 8개 가드로 번진 경로

각 단계가 **다음 단계의 질문을 만들었다**. 이것이 이 세션의 핵심 구조다.

```
목표 1건:  block scalar 안에서 줄 분할된 ${{ }}
   ↓ 구현 중
  +1:  다중 행 plain scalar `run:`의 연속 줄이 본문 추출에서 누락
       → 트립와이어로는 안 잡힌다(표현식이 자기 줄에서 닫힘). 감사에 없던 홀.
   ↓ ADR-001 §2 적대 리뷰
  +4:  인용 키 "run": (CRITICAL) / explicit ? run (CRITICAL)
       / *.yml 전용 glob (HIGH) / 주석 오탐 (MEDIUM, 내 첫 커밋이 유발)
  +1:  새로 쓴 sibling-key 테스트가 vacuous
   ↓ "이 형태가 다른 가드에도 있나?" → 가드 20개 전수 스윕
 +10:  gate_topology ×3, pr_trigger_scope, provenance_verify ×2,
       _ci_guard_util.top_level_jobs, codeql ×2, cross_os ×2
  +1:  #391 자신도 composite action(.github/actions/**/action.yml)을 못 읽음
       → 심어둔 실제 RCE에 강화판 가드가 green
   ↓ 스윕 중 별건으로 드러남
  +1:  lint.yml에 schedule: 트리거가 없어 7개 잡의 안전망이 죽어 있음
```

`.yaml` 확장자 하나를 고친 것이 "그럼 이 가드는 **어떤 파일 집합을** 열거하는가?"를
물었고, 그 질문이 composite action을 찾아냈다. 인용 `"run":` 하나를 고친 것이
"이 형태가 다른 가드에도 있나?"를 물었고, 그 질문이 10건을 찾아냈다.

## 3. 근본 원인 테마

### 3.1 트립와이어는 추출기가 **도달한** 형태에만 발화한다

가장 값비싼 교훈이다. #391이 추가하려던 트립와이어는 목표 갭을 닫았지만,
**plain scalar 연속 줄 홀도, 두 키-형태 홀도 닫지 못했다** — 트립와이어는 본문
추출기가 이미 읽은 줄에서만 발화하기 때문이다. 추출기가 파일이나 줄을 아예 보지
못하면 트립와이어도 침묵한다.

> **스캔 불가 형태를 금지하는 것**과 **추출기가 모든 형태에 도달하는지 검증하는 것**은
> 별개의 의무다.

composite action이 같은 교훈의 극단적 사례였다. `${{ github.event.pull_request.title }}`
계열의 살아있는 RCE를 실제 composite action에 심었을 때:

| 픽스처 | 폴드 전 | 폴드 후 |
|---|---|---|
| composite `action.yml`의 RCE | `30 passed` (green) | `2 failed` |
| `.yaml` 워크플로의 RCE (대조군) | `2 failed` | `2 failed` |

즉 **이미 두 번 강화된 가드**가, 자기 존재 이유인 CICD-SEC-4 RCE를, 이 저장소에
이미 존재하는 파일 집합에서 못 보고 있었다.

### 3.2 인용 키는 회피가 아니라 표준 표기다

`"uses": x`는 어떤 YAML 파서에도 `uses: x`와 동일한 문서로 해석된다(PyYAML로 확인).
이것이 억지 구성이 아니라는 근거는 생태계 자체에 있다: **bare `on:`은 YAML-1.1의
불리언 `True`로 해석되므로 GitHub 공식 문서가 `"on":`을 정규 표기로 쓴다.**

그래서 `key\s*:`를 손으로 쓴 매처는 전부 우회 가능했다 — `uses:`, `branches:`,
`pull_request_target:`, `runs-on:`, `name:`, 잡 키, `jobs:` 헤더까지 8개 가드.
explicit-key(`? key` / `: value`)는 더 나쁘다: **리터럴 `key:`가 파일 어디에도
나타나지 않으므로** 어떤 라인 매처로도 도달 불가 — 스캔이 아니라 fail-close할
대상이다.

### 3.3 "green"과 "실행됐다"는 다른 질문

`pip-audit`는 path gate 뒤에서 오래 `skipped`였다. 그래서 requirements 파일을 처음
건드린 PR에서 즉시 실패했는데, 원인은 그 PR의 diff가 아니라 러너 툴캐시의
`setuptools 79.0.1`(PYSEC-2026-3447)이었다. **게이트가 환경 드리프트를 가리고 있었다.**

같은 병이 더 심한 형태로 `lint.yml`에 있었다. 7개 잡이
`|| github.event_name == 'schedule'`을 주기적 안전망으로 달고 있었지만
**워크플로에 `schedule:` 트리거가 아예 없었다** — 파일 파싱과 실행 이력 양쪽으로 확인
(1118런: `pull_request` 654 + `push` 464 + `schedule` **0**).

측정된 결과:

- `npm-audit`: **7주 / main 커밋 117개 동안 실제 실행 0회.** 버킷
  (`package*.json`/`.nvmrc`) 최종 변경은 `e5b9bbb`(2026-06-19).
- `dast-full-scan.yml`: `vars.DAST_TARGET_URL`이 비어 42일 연속 나이틀리가
  `skipped`. 레포에 Actions 변수 0개·시크릿 0개(개인 계정이라 org 폴백도 없음).
- `protection-drift-watch.yml`: 시크릿 부재로 매일 no-op 분기를 타면서 `success` 보고.

> **`skipped`/no-op 잡은 초록으로 읽힌다.** 경보가 없다는 것이 통제가 있다는 뜻은 아니다.

### 3.4 "테스트가 red"와 "수정이 load-bearing"은 다른 질문

`npm_publish`의 최소권한 검사가 이 함정의 교과서적 사례였다.

1. write-grant 스캔 `:\s*write\b`가 **인용된 값**을 놓쳤다 —
   `packages: "write"`에서 `write_grants`가 **빈 리스트**로 나왔다. 즉 권한이
   살아있는데 스캔은 "위반 없음"을 보고했다.
2. 스캔을 고쳤다. 테스트는 여전히 red였다. **하지만 실패한 것은 무관한 전체-블록
   앵커였고, 고친 스캔의 메시지는 나타나지 않았다**(`matches=0`).
3. 앵커가 앞에 있는 한 스캔은 결코 보고자가 될 수 없으므로 그 정확성은 **관측
   불가**였다. 순서를 뒤집어 스캔이 먼저 실행되고 `packages: "write"`를 이름까지
   지목하게 했다. 앵커는 스캔이 분류하지 못하는 추가 키를 위한 구조적 catch-all로 남겼다.

이전 감사는 이 앵커를 "우연히 살려준 것"으로 기록했다. 우연에 기대는 것을 멈추는
수정은 스캔을 고치는 것만으로 끝나지 않고, **누가 보고하는지**까지 바꿔야 했다.

### 3.5 형태 열거는 또 졌다 (ADR-001 §5, 6번째)

신규 가드 `test_ci_dead_schedule_arm.py`의 검출기 자체가 이 교훈을 즉석에서 복습했다.
첫 버전은 비교 형태를 열거했다(`==`, 역순, `contains(...)`). `contains` 패턴은
바로 실패했다:

```
contains(fromJSON('["schedule","push"]'), github.event_name)
```

`[^)]*`가 `fromJSON(...)` 내부의 `)`를 넘지 못한다. 모든 표기에서 성립하는 불변식으로
교체했다 — **한 줄에 `github.event_name`과 인용된 `schedule` 토큰이 동시출현**.
오류 방향도 안전하다(과다보고 = 거짓 경보, 우회 아님).

10곳이 나온 것도 오타 10개가 아니라 같은 실패다. 그래서 #393은 가드별 정규식 대신
**공유 primitive**를 만들었다:

```python
yaml_key_pattern(key)          # 키는 bare 또는 quoted, 조합 가능한 fragment
explicit_key_lines(text, *k)   # `? key` / `: value`에 fail-closed
workflow_and_action_files()    # 양쪽 확장자 + composite action 엔트리포인트
```

카탈로그 규약에 **"손으로 `key\s*:`를 쓰지 말고 `yaml_key_pattern`을 조합하라"**를
명시해 9번째 가드가 같은 실수를 반복하지 못하게 했다.

## 4. 방법론에서 효과가 있었던 것

### 4.1 PyYAML을 **CI 테스트 잡 밖의** ground-truth oracle로 쓰기

가드는 stdlib-only여야 한다(`requirements-ci.txt`에 PyYAML 없음). 하지만 *검증*에는
PyYAML을 쓸 수 있다 — 별도 venv에서 "실제 파서는 이 문서를 무엇으로 해석하는가"를
물으면, 가드의 제약을 깨지 않고 우회를 확정할 수 있다.

```
case                   yaml run value                            scanner  trip  VERDICT
F1 explicit key        echo '${{ github.event.issue.title }}'          0     1   CAUGHT
F2 quoted key block    echo '${{ github.event.issue.title }}'          1     0   CAUGHT
F4 comment FP          echo hi                                        0     0   clean
```

이 oracle이 없었다면 "인용 키가 실제로 같은 문서인가"는 추측이었을 것이다. 특히
**주석 오탐의 정확한 수정 방향**을 알려준 것이 결정적이었다: PyYAML은
`run: echo` / `# c` / `hi`를 **파싱 에러**로 거부한다 → plain scalar는 주석 줄
이후 재개될 수 없다 → 주석에서 수집을 멈추는 것은 보수적 근사가 아니라 **정확**하다.

### 4.2 적대 리뷰는 값을 냈고, 리뷰어 주장은 재검증했다

ADR-001 §2가 의무화한 리뷰 패스가 #391에서 CRITICAL 2건을 찾았다. 동시에 리뷰의
5번째 주장(내 sibling-key 테스트가 vacuous)은 **범주 오류에 가까웠지만 결과적으로
옳았다** — 부재 단정은 메타 가드가 면제하는 형태이지만, 연속 줄 수집을 통째로
삭제해도 통과하는 것은 사실이었다. positive control을 짝지어 양방향을 고정했다.

거꾸로 리뷰가 놓친 것도 있었다. 그래서 4건 전부를 PyYAML oracle로 직접 재현한 뒤에
반영했다. **리뷰어 보고는 입력이지 결론이 아니다.**

### 4.3 뮤테이션 증명을 매 수정마다, 그리고 "어느 테스트가 red인지"까지

PR #391에서 6개, #393에서 8개 우회, #394에서 4개 + npm 1개 — 각 뮤턴트가 **자기 테스트만**
red가 되는지 확인했다. `m2`가 `test_fires_on_multiline_plain_scalar_continuation`과
`test_inline_run_body_stops_at_sibling_key` **둘 다** red로 만든 것이 vacuity 해소의
증거였다.

신규 dead-schedule 가드는 **합성 픽스처가 아니라 실제 수정 전 `lint.yml`**로 검증했다.

## 5. 운영에서 배운 것

- **스택 PR을 피했다.** `.claude/rules/git-workflow.md`의 base 삭제 자동-CLOSE 함정
  때문에 #393은 #391에 스택하지 않고 `main`에서 분기했다. 대가는 카탈로그 문서 충돌
  1건이었고, 이는 예측 가능하고 국소적이었다.
- **문서 충돌 해소 방법.** 겹치는 두 hunk를 손으로 병합하지 않고 **main 버전을 통째로
  취한 뒤 #393의 편집 5곳만 재적용**했다. 먼저 머지된 PR의 내용이 바이트 단위로
  보존되고, 재적용은 각 anchor의 존재를 assert하므로 조용한 유실이 불가능하다.
- **카탈로그 메타 가드가 제 일을 했다.** 신규 가드 파일을 추가하자
  `test_ci_catalog_completeness.py`가 먼저 실패하며 카탈로그 행을 요구했다. #389가
  이 메타 가드에 mutation self-test를 붙여둔 것이 여기서 값을 냈다.
- **path-gate 잡은 자기 검증이 안 된다**는 기존 규칙이 이번엔 **역방향**으로 나타났다:
  잡이 오래 안 돌면 그 환경이 조용히 낡는다.

## 6. 잔여 / 범위 외

- **DAST 나이틀리 커버리지** — `vars.DAST_TARGET_URL` 미설정으로 42일간 실질 커버리지
  0. 복구는 **권한이 확인된 실제 타깃**을 요구하므로 제품 결정이며 임의로 진행하지
  않았다. 복구하지 않는다면 워크플로 이름/주석의 "Nightly" 약속을 제거해 커버리지
  착시를 없애야 한다.
- **`REPO_ADMIN_TOKEN`** 부재로 `protection-drift-watch.yml`이 여전히 매일 no-op.
  자기문서화된 기존 갭이지만, `success`로 보고되는 점이 문제다.
- **인용 값(value) 방향**은 `npm_publish` 1건만 모델링했다. 다른 가드가 값을 매칭하는
  곳에 같은 형태가 있는지는 이번 스윕 범위가 아니었다(키 방향만 전수했다).
- `_ci_guard_util`의 `explicit_key_lines`는 `? key`만 본다. flow 매핑 안의
  explicit key(`{? key: v}`)는 다루지 않으며, 현 저장소에 사례가 없다.

## 7. 체크리스트 (다음 가드 작업에 그대로 쓸 것)

- [ ] 매처를 쓰기 전에 **`_ci_guard_util`의 primitive를 조합**하라. `key\s*:`를 손으로
      쓰는 순간 인용 키 우회가 생긴다.
- [ ] "이 가드는 **어떤 파일 집합**을 열거하는가?"를 명시적으로 물어라. `*.yml` 전용
      glob, `.github/actions/**` 누락, 단일 경로 하드코딩 — 셋 다 조용하다.
- [ ] 스캔 불가 형태는 **fail-close**하라. 단, 트립와이어는 추출기가 도달한 것만
      본다는 사실을 함께 확인하라.
- [ ] 뮤테이션 증명 시 **어느 assertion이 red인지** 확인하라. 다른 단정이 먼저
      실패하면 당신의 수정은 관측되지 않았다.
- [ ] 부재(negative) 단정에는 **positive control을 짝지어라**. 기능을 통째로 삭제해도
      통과하는 테스트는 vacuous하다.
- [ ] 잡의 게이트를 볼 때 `|| github.event_name == 'schedule'`이 있으면 **워크플로에
      `schedule:`이 실제로 있는지** 확인하라(이제 가드가 강제한다).
- [ ] 검증에는 PyYAML을 oracle로 써라 — 가드 자체의 stdlib-only 제약과 무관하다.

## 8. 관련 문서

- [ADR-001 — CI 가드 하드닝과 감사 주기](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md)
- [CI Config Regression Guards 카탈로그](../devsecops/ci-config-regression-guards.md)
- [ADR-001 Q3 감사 회고 (#297)](./adr-001-q3-audit-retrospective.md)
