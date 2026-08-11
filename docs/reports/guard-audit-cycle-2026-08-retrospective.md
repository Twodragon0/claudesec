---
title: "가드 감사 사이클 회고 — 2026-08-08 ~ 08-11 (코드 9 PR + 문서 2 PR, 보론 3건)"
description: "감사가 만든 체크리스트가 그 감사의 회고를 세 번 반증했다 — 산출물 사슬(가드 → 회고 → 체크리스트 → 발견)이 어떻게 작동했고 어디서 썩었는지에 대한 ClaudeSec 회고"
tags:
  - session-report
  - devsecops
  - ci
  - github-actions
  - regression-guard
  - retrospective
---

# 가드 감사 사이클 회고 — 2026-08-08 ~ 08-11

## 1. 개요

2026-08-08부터 08-11까지 나흘 동안 CI 가드에 **11개 PR(코드 9 + 문서 2)** 이
머지됐다. [필수 체크 무력화 3연속 사이클 회고](./runner-key-audit-retrospective.md)
는 이 중 앞부분(#404 → #406 → #407 → #408)의 **기술 클래스**를 다룬다. 이 문서는
같은 사건을 다시 설명하지 않는다. 다루는 대상이 다르다:

> **산출물 사슬** — 가드가 회고를 만들고, 회고가 체크리스트를 만들고, 체크리스트가
> 다음 발견을 만들고, 그 발견이 **회고 자체를 반증했다.** 세 번 — 세 번째는 이
> 문서(2.4절)를 반증했다.

즉 이 사이클의 주인공은 특정 취약점이 아니라, "감사 결과를 문서로 남기는 행위"가
실제로 통제로 작동했는지 여부다. 결론부터: 작동했다. 그리고 작동한 방식은
**앞 문서가 틀렸음을 증명하는 것**이었다.

| # | 머지 | PR | 한 줄 | 스위트 |
|---|---|---|---|---|
| 1 | 08-08 15:08 | [#404](https://github.com/Twodragon0/claudesec/pull/404) `170d456` | 심각도 게이트를 **실행**해서 증명, 텍스트 스캐너 폐기 | 1853 passed |
| 2 | 08-08 15:55 | [#406](https://github.com/Twodragon0/claudesec/pull/406) `a8beb28` | 포섭된 텍스트 가드 **삭제** (+91 / −192) | 1866 passed |
| 3 | 08-10 09:58 | [#407](https://github.com/Twodragon0/claudesec/pull/407) `ec4b6eb` | 실행이 못 보는 **러너 소비 키** (그래프 20잡, 보호된 건 1스텝) | 1881 passed |
| 4 | 08-10 13:09 | [#408](https://github.com/Twodragon0/claudesec/pull/408) `0a6301f` | 감사 백로그 3건 — 그중 1건은 실제 false negative | 1912 passed |
| 5 | 08-10 13:14 | [#409](https://github.com/Twodragon0/claudesec/pull/409) `ea678f8` | **문서** — 회고 + 다음 감사용 체크리스트 | — |
| 6 | 08-10 15:44 | [#410](https://github.com/Twodragon0/claudesec/pull/410) `cc0f363` | 한 모듈에 테스트 파일 둘 → 하나로, 미검증 프리미티브 5개 | 1945 passed |
| 7 | 08-10 17:38 | [#412](https://github.com/Twodragon0/claudesec/pull/412) `8097229` | 체크리스트 1차 발견 — **REDIRECT 키** (`working-directory:`) | 1945 → 9 failed |
| 8 | 08-10 17:52 | [#411](https://github.com/Twodragon0/claudesec/pull/411) `710ee09` | **문서** — 백로그 8건 중 7건은 이미 해결돼 있었다 | 1945 (불변) |
| 9 | 08-10 18:04 | [#413](https://github.com/Twodragon0/claudesec/pull/413) `1682fc7` | 체크리스트 2차 발견 — **세 번째 스코프 실패** | 1952 → 1 failed |
| 10 | 08-10 18:49 | [#414](https://github.com/Twodragon0/claudesec/pull/414) `e98adc1` | 손으로 쓴 블록 파서 2개, 하나는 **우회 가능** | 1972 passed |
| 11 | 08-11 09:25 | [#415](https://github.com/Twodragon0/claudesec/pull/415) `b8e4a09` | `templates/` 는 **남의 레포로 나가는데** 아무 가드도 안 읽었다 | 1981 passed |
| 후속 | 08-11 | [#416](https://github.com/Twodragon0/claudesec/pull/416) `00f02f5` | `re.sub` 픽스처도 무음 실패한다 (4절) | 1989 passed |
| 후속 | 08-11 | [#417](https://github.com/Twodragon0/claudesec/pull/417) `066d782` | templates 핀 정책 결정 + `uses:` 인용 **값** 우회 (6절) | 2006 passed |
| 후속 | 08-11 | [#419](https://github.com/Twodragon0/claudesec/pull/419) `170c78e` | **2.4절** — 블록 추출기 우회 3건 + 철자 스윕 | 2036 passed |
| 후속 | 08-11 | [#420](https://github.com/Twodragon0/claudesec/pull/420) `7df8fff` | "무영향" 판정을 면역 근거까지 확정 | 2038 passed |

스위트는 감사 사슬(#404 → #415) 동안 **1853 → 1981**로 늘었고, 같은 세션에서
이어진 후속 PR까지 머지된 뒤의 `main`은 **#416·#417 기준 2014**, **#419 기준 2036**,
**#420 기준 2038 passed, 5 skipped**다(각각 직접 측정). 각 PR의 수치는 그 PR
브랜치에서 측정된 값이므로 서로 더해지지 않는다는 점에 주의.
숫자는 각 PR 본문에서 인용했고,
모든 발견은 뮤턴트를 실제 파일에 적용해 "통제는 사라졌는데 가드는 green"을 확인한
뒤에 기록됐다. 정적 읽기만으로 주장한 발견은 이 사이클에 없다.

---

## 2. 중심 구조 — 체크리스트가 자기 회고를 세 번 반증했다

PR #409는 회고 문서 하나와, `guard-audit-reminder.yml`의 분기 체크리스트에 들어갈
규칙 몇 줄을 남겼다(#410에서 실제 등록). 그 규칙이 처음 돌자마자 **자기를 만든
회고의 두 절을 무효화**했다. 2.4절은 세 번째이며, 반증 대상이 이 문서다 — 사슬은
아직 돌고 있다.

### 2.1 반증 1 — 사각지대에는 skip 계열만 있는 게 아니었다 (#412)

새 규칙: *"무언가를 실행해서 불변식을 증명하는 가드는, 그 실행 프로세스가 볼 수
없는 텍스트를 나열하라."*

회고 §4.4의 표는 실행이 못 보는 키를 전부 **SKIP 계열**(`if:`,
`continue-on-error:`)로 분류하고 있었다. 규칙을 그대로 적용해 보니 다른 계열이
있었다 — 스텝을 **건너뛰는** 게 아니라 **딴 데로 보내는** 키다.

```text
security-scan.yml, `Check for critical/high failures` 스텝에 한 줄:
    working-directory: docs

  적용 전: 1945 passed, 0 failed   ← 필수 체크가 CRITICAL을 더 이상 막지 못함
  적용 후:    9 failed
```

기제는 이국적이지 않고 산술적이다. 게이트는 cwd 기준으로 `scan-output.txt`를
grep하고, 없는 파일에 대한 grep 실패는 `|| true`가 삼키고, `CRITS`는 빈 문자열이
되고, `[ "" -gt 0 ]`은 에러를 낸다 — 그런데 실패한 `[`는 **조건**이므로 `bash -e`가
의도적으로 치명적으로 다루지 않는다. `exit 1`은 실행되지 않는다.

```text
cwd = repo root -> "Critical: 1" -> exit 1   (막는다)
cwd = docs/     -> "Critical: "  -> exit 0   (조용히 통과)
```

REDIRECT가 SKIP보다 **나쁘다**는 점이 이 반증의 핵심이다. 건너뛴 스텝은 UI에서
회색이고, 리다이렉트된 스텝은 **초록 체크**다. §4.4는 이 계열을 담지 않은 상태로
"실행형 증명의 사각지대"를 설명하고 있었으므로, 표가 불완전한 게 아니라
**분류 자체가 틀려** 있었다.

### 2.2 반증 2 — 규모 추정은 세 번째로 틀렸다 (#413)

새 규칙: *"필수 체크 가드의 범위는 눈앞의 잡이 아니라 `needs:` 이행 폐쇄로 잡아라."*

회고 §4.5는 "잘못된 규모 추정"을 **한 실수의 두 방향**으로 정리해 놓았다(대상을
너무 작게 잡은 #404, 모집단을 엉뚱하게 잡은 #407). 규칙을 적용하니 **세 번째**가
이미 레포에 있었다. `test_ci_gate_topology.test_every_job_is_gated_or_allowlisted`
가 `lint.yml` 하나에 하드코딩돼 있었다.

```text
security-scan.yml 에 `run: exit 1` 잡을 추가하고 security-scan-gate.needs 에서 누락:
  적용 전: 1952 passed, 0 failed
  적용 후:    1 failed  (두 워크플로 모두 검사)
```

같은 카탈로그 문서가 "애그리게이터에 연결되지 않은 잡은 머지를 막지 못한다 —
정확히 토폴로지 가드가 잡는 공백"이라고 **적어 두고** 있었다. 그 문장은 두 필수
워크플로 중 하나에 대해서만 참이었다.

세 번 모두 해법이 같았다: **범위를 이름으로 쓰지 말고 파생시켜라.** `#407`은
`DESIRED_CONTEXTS`에서 그래프를 걸었고, `#413`은 같은 코드에서 애그리게이터를
resolve했고, 이번 사이클 말미의 `#417`은 설치 대상 템플릿 목록을 `setup.sh`의
`cp` 줄에서 파생시켰다.

### 2.3 반증이 성공 신호인 이유

두 반증은 #414에서 회고 문서에 되돌려 반영됐다(§4.4·§4.5 보론). 여기서 얻을 규칙은
"회고를 더 잘 쓰자"가 아니다:

- **회고를 검증 가능한 규칙으로 환원하지 않으면 반증될 수 없다.** #409가 "실행에도
  사각지대가 있다"는 통찰로 끝났다면 아무 일도 일어나지 않았다. "볼 수 없는 텍스트를
  **나열하라**"라는 실행 가능한 지시가 됐기 때문에 `working-directory:`가 목록에
  올랐다.
- **반증된 회고는 실패한 회고가 아니다.** 반증 가능한 형태로 쓰였다는 뜻이다. 이
  사이클에서 문서를 갱신한 PR(#411, #413, #414)은 모두 "앞 문서가 이 지점에서
  틀렸다"를 본문에 명시했다.

### 2.4 반증 3 — 이 문서가 "닫혔다"고 적은 클래스가 열려 있었다 (#419)

2.1·2.2절은 실행형 증명이 못 보는 **키**를 다뤘다. 이 문서는 그 두 절로 러너 소비
키 클래스를 정리된 것으로 서술했고, 5절은 "파서는 없앨 것"이라며 손으로 쓴 파서가
공유 프리미티브로 흡수된 목록을 자랑했다. 둘 다 **추출기 자체는 검사하지 않았다.**

3·4절이 남긴 규칙("하네스를 먼저 공격하라")을 추출기에 적용한 결과, 주석 한 줄로
블록이 절단되고 그 뒤 모든 키가 사라진다. PyYAML을 사실 기준으로 삼아 측정:

```text
매핑        a:\n  x: 1\n# c\n  y: 2   ->  {'a': {'x': 1, 'y': 2}}   주석은 아무것도 끝내지 않는다
블록 스칼라  a:\n  run: |\n ... # c ...  ->  ParserError               스칼라를 살려 두지도 않는다
```

수집기는 어느 쪽을 읽는지에 따라 달라야 하는데, 전부 같은 규칙("공백이 아니고 열이
임계값 이하면 끝")을 썼다. 라이브 우회 3건:

| 뮤테이션 (주석 한 줄) | PyYAML 사실 | 가드 |
|---|---|---|
| `npm-publish.yml`, `permissions:` 아래 컬럼-0 주석 | `{'contents': 'read', 'packages': 'write'}` | `12 passed` |
| `security-scan.yml`, 게이트 **스텝** dash 컬럼 주석 | 스텝 키 `['continue-on-error', 'name', 'run']` | `61 passed` |
| `security-scan.yml`, `scan` **잡** 키 컬럼 주석 | `jobs.scan.continue-on-error = True` | `61 passed` |

뒤 두 개는 **그 키를 잡으려고 쓴 가드**를 무력화한다 — #404의
`test_gate_step_does_not_swallow_its_exit_code`와 #407의 그래프 전수 규칙. 그러니까
2.1·2.2절이 닫았다고 서술한 클래스가, 그 절들이 만든 가드를 통해 그대로 열려 있었다.
첫 번째는 최소권한 단정 두 개를 동시에 무너뜨렸고, 그중 하나는 가드 자신이
"write-grant 스캔이 분류하지 못하는 키까지 걸러내는 구조적 catch-all"이라고 적어 둔
것이다 — **추출기가 반환한 범위 안에서만** catch-all이었고, 절단된 블록은 실제로
정확히 `contents: read`였다.

**이 절이 앞 절들과 다른 점: 반증 대상이 남의 문서가 아니라 이 문서다.** 2.3절은
"반증된 회고는 실패한 회고가 아니다"라고 썼는데, 그 문장을 자기에게 적용할 기회가
사흘이 아니라 몇 시간 만에 왔다.

#### 이 반증이 추가한 규칙 세 개

1. **파싱하는 대상의 문법을 측정하고 나서 수집기를 쓴다.** 매핑과 스칼라에서 주석의
   의미가 반대라서, 한 규칙을 두 곳에 쓰면 한쪽은 반드시 틀린다. `extract_run_block`이
   주석에서 끊는 현재 동작은 **옳고**, 그걸 "일관성"을 이유로 고치면 워크플로 밖 셸을
   과다 캡처한다 — 5절이 자랑한 실행형 증명의 안전장치가 무너지는 경로다.
2. **수정이 만드는 2차 결함은 리뷰가 아니라 기존 뮤테이션 테스트가 잡는다.** 주석이
   블록 안에 살게 되자 `min(indent)` 컬럼 도출 5곳이 전부 오염됐다. 그중 하나는
   `graph_violations` 인라인이었고, `28 passed`가 `1 failed`로 바뀌며 정확히 그
   지점을 가리켰다. 정적 리뷰로는 찾지 못했을 것이다.
3. **프로브 배치가 판정을 뒤집는다.** 같은 주석을 잡 **시작**에 넣으면 `steps:`까지
   잘려 무관한 단정이 깨지고 "잡혔다"로 읽힌다 — 가드가 아니라 프로브의 false
   negative다. 4절의 #411 교훈이 같은 사이클 안에서 두 번 재현됐다.

또 하나: 인용 키/값 렌즈로 전 핀·존재 가드를 훑은 결과 **추가 우회는 0건**이었고,
그 0이 유용한 결과다. 방향이 판정을 정한다 — 위반 검사(`assert offenders == []`)에서
놓친 줄은 존재하지 않았던 위반이 되어 **조용한 우회**가 되고(그게 #417의 `uses:`였다),
존재·핀 검사에서 놓친 줄은 사라진 통제로 읽혀 **fail-closed 오탐**이 된다. 오탐 5건은
그래도 고쳤다(#414의 근거: 평범한 작성 스타일에 깨지는 가드는 수리되지 않고 약화된다).

---

## 3. 문서도 통제다 — 그리고 문서는 썩는다

이 사이클은 **문서 부패**를 세 번 서로 다른 형태로 잡았다. 가드 코드가 아니라
문서가 결함의 소재지였던 사례들이다.

| PR | 부패 형태 | 실제 상태 | 비용 |
|---|---|---|---|
| [#411](https://github.com/Twodragon0/claudesec/pull/411) | 백로그 8건이 "열림"으로 등재 | **7건은 이미 닫혀** 있었다 (각 우회를 실제 파일에 적용해 가드가 FAIL함을 확인) | 재발견 1사이클 + "그건 알려진 공백이야"라는 잘못된 면허 |
| [#413](https://github.com/Twodragon0/claudesec/pull/413) | "이미 가드됨" 8개 판정에 클래스·근거·날짜 없음 | 그중 **1개가 거짓**이 돼 있었다 — CRITICAL `exit 1` 담당을 `test_ci_security_gate.py`로 적고 있었지만 #406이 그 검사를 삭제했고 남은 건 독스트링 산문 한 줄 | 한 달 이상 "통제 있음"으로 오독 |
| [#415](https://github.com/Twodragon0/claudesec/pull/415) → [#417](https://github.com/Twodragon0/claudesec/pull/417) | "핀 정책은 미결로 남긴다"가 결정 후에도 두 곳에 잔존 | 정책은 08-11에 결정됨 | 다음 독자가 미결로 재논의 |

PR #411의 방법론에서 나온 부수 규칙이 하나 더 있고, 이게 이 사이클에서 가장 재사용
가치가 높다:

> **하네스를 먼저 공격하라.** #411의 provider-labels 프로브는 처음 "공백 있음"으로
> 보고했다. 뮤테이션이 틀렸다 — `aws)` arm을 `*)` catch-all **바로 앞**으로 옮겼는데,
> 거기서는 arm이 여전히 완벽히 도달 가능하다. 가드가 green인 게 옳았다. 카탈로그에
> 거짓 발견을 적기 직전이었다.

## 4. 자기검증 도구 자체가 결함원이었다

위 문장은 일회성 사고가 아니었다. 같은 클래스가 사이클 내내 반복됐다.

- **#415** — 그 감사에서 **다섯 개의 프로브가 같은 방식으로 틀렸다**: (1) `case` arm을
  `*)` 바로 앞으로 이동(여전히 도달 가능), (2) 항목 대신 **섹션 헤더**를 수정,
  (3) 파일 끝 케이스만 만든 `job_block` 프로브, (4) 주석이 원문을 그대로 인용하고
  있는 게이트에서 `if: always()` 삭제, (5) `setUpClass`가 디스크에서 덮어쓰는
  TestCase 속성에 텍스트 주입. 각각이 **정상 가드를 "수정"할 뻔했다.** 그래서
  `apply_mutation` / `assert_disables`가 `_ci_guard_util`로 들어갔다 — 치환 대상이
  없으면, 또는 결과가 원본과 같으면 **실수 지점에서** AssertionError를 던진다.
- **#414 F-5b** — 손으로 쓴 파서를 공유 `job_block`으로 교체할 때, 등가성을 파싱된
  `needs:` 집합으로 비교했다. 양쪽 동일. 그런데 옛 파서는 각 줄의 후행 `#` 주석을
  제거했고 `job_block`은 원문을 반환한다. 이 차이는 happy path에서 보이지 않는다.
  `test_passset_surviving_only_in_comment_does_not_satisfy`가 즉시 잡았다.
  → **"해피 패스에서 같다"는 등가성이 아니다.**
- **[#416](https://github.com/Twodragon0/claudesec/pull/416)** MERGED `00f02f5` — #415가 리터럴
  치환 픽스처 6개를 `apply_mutation`으로 이관하면서 `re.sub` 기반은 "부분 문자열
  API에 억지로 넣지 않는다"는 이유로 남겼다. 남은 구멍이 바로 그것이었다: `re.sub`도
  **미스 시 무음으로 원본을 반환**한다. `apply_regex_mutation`이 같은 두 검사에
  하나를 더 얹는다 — **`count`보다 매치가 많으면 에러.** 부분 문자열은 눈으로
  세지만 패턴은 못 센다.

이관 과정에서 드러난 실제 결함 둘:

1. `test_gate_wrapped_in_an_unreachable_branch`는 치환 **후에 텍스트를 덧붙인다**
   (`\nfi\n`). 그래서 치환이 미스해도 뮤턴트는 원본과 다르고, 무음-픽스처 감시
   (F7)가 **구조적으로 못 본다.** 낡은 앵커는 세 단계 뒤 `bash: syntax error near
   unexpected token 'fi'`(exit 2)로 나타났고, 메시지는 "게이트를 무력화해야 하는데
   안 됐다"였다.
2. `test_gate_bound_moved_out_of_reach`는 `-gt 0 ]; then`에 앵커를 걸었는데 이 문자열은
   **두 번** 나온다(`$HIGHS` 경고 분기까지). 카운트 없는 `str.replace`가 둘 다
   바꿨고, 테스트 이름과 메시지는 게이트를 겨눴다고 말하고 있었다.

## 5. 파서는 한 번 더 손볼 게 아니라 없앨 것

ADR-001 §4("열거에 대한 세 번째 패치는 재설계 신호")가 이 사이클에서 다섯 번
적용됐다.

```text
PR #404  텍스트 스캐너(1형태 → 4형태 → 6형태 패배) → run: 본문을 실행
PR #406  포섭된 텍스트 가드 삭제 (+91 / −192, strip-order 예외 0)
PR #413  _lint_gate_needs 삭제 → 공유 job_block / job_needs
PR #414  gate_block_from · _extract_job_block 삭제 → 같은 공유 프리미티브
      (앞의 것은 우회 가능했다: 종단 조건 `^  [A-Za-z0-9_-]+:` 가 인용된 형제 잡
       `  "post-gate-notify":` 를 못 만나 블록이 끝나지 않았고, 그래서 자기
       `if: always()` 를 잃은 게이트가 test_gate_runs_always 를 통과했다)
PR #417  uses: 매처 → _ci_guard_util.uses_refs
```

`#417`은 같은 매처가 **세 번** 고쳐진 사례로 이 절의 결론을 재확인한다: 인용된 키
(2026-08-06 스윕), 콜론 앞 공백, 그리고 **인용된 값**. 마지막 것은 라이브였다 —
값 문자 클래스가 따옴표를 배제하고 선행 따옴표 허용이 없어서
`uses: "actions/checkout@main"`은 **아예 매치되지 않았다.**

```console
# 실제 lint.yml 한 줄 (필수 워크플로의 mutable BRANCH ref)
$ python3 -m pytest scanner/tests/test_ci_gate_topology.py -q
15 passed
```

**매치되지 않은 줄은 준수한 줄과 똑같이 읽힌다.** 부재는 침묵이고, 침묵은 green이다.

## 6. 사각지대는 이동한다 — 우리 CI 밖으로 (#415)

이 사이클의 마지막 발견은 클래스가 아니라 **표면**의 확장이었다. `scripts/setup.sh`
는 `templates/codeql.yml`과 `templates/dependency-review.yml`을 사용자 레포의
`.github/workflows/`로 **그대로 복사**한다. 즉 그 파일들은 **남의 토큰으로 실행되는
워크플로**이며, 우리 CI보다 폭발 반경이 크다. 그런데
`workflow_and_action_files()`는 18개 파일을 돌려주고 있었고 그중 `templates/`는
없었다. **아무도 보고 있지 않았다.**

PR #415는 인젝션 스캔만 확장하고 핀 정책은 "제품 결정"으로 명시적으로 남겼다. 그
결정은 08-11에 내려졌다([#417](https://github.com/Twodragon0/claudesec/pull/417),
열림): 두 반쪽은 서로 다른 산출물이다.

| 반쪽 | 정책 | 이유 |
|---|---|---|
| **설치되는** `codeql.yml`, `dependency-review.yml` | 40-hex SHA, 우리 레포 ref와 parity | 사용자가 한 줄도 고르지 않은 채 실행된다. 태그는 공격자 코드로 재지향 가능(`tj-actions/changed-files`, 2025) |
| **예시** `prowler` · `sbom` · `scorecard` · `security-scan-suite` | 태그 유지 + "도입 전 SHA 핀" 명시 | ClaudeSec이 그 액션들을 실행하지 않으므로 미러링할 ref가 없다 |

갈림의 기준은 미감이 아니라 **누가 핀을 신선하게 유지할 수 있는가**다. Dependabot의
`github-actions` 생태계는 `.github/workflows/`(및 `.github/actions/`)만 스캔하고
임의 디렉터리는 보지 않는다. 그 대가는 이미 지불돼 있었다: 두 설치 템플릿이
`actions/checkout@b4ffde65  # v4.1.1`을 손으로 박아 둔 동안 우리 워크플로는
`# v7.0.1`로 올라갔다. **메이저 3개, 조용한 부패, 모든 `setup.sh` 사용자에게 배송.**
그래서 설치 반쪽은 우리 ref와 **일치해야** 하고(가드가 강제), 예시 반쪽은
**유지 못 할 핀을 받지 않는다.**

## 7. 이번 사이클이 남긴 규칙

앞 회고의 체크리스트에 더할 것들. 모두 이 사이클에서 실제로 발견을 만들었거나,
발견을 놓치게 만들었던 항목이다.

1. **하네스를 먼저 공격하라.** 프로브가 "공백"이라고 하면, 코드를 의심하기 전에
   프로브가 정말 통제를 무력화했는지 확인한다(#411 거짓 발견 직전, #415 다섯 개).
2. **픽스처는 헬퍼로 만든다.** `str.replace`/`re.sub`를 직접 쓰면 미스가 무음이다.
   치환 후 텍스트를 덧붙이는 픽스처는 자기 결과로 적용 여부를 증명할 수 없다(#416).
3. **등가성은 해피 패스로 증명되지 않는다.** 교체 전후를 비교할 때, 그 가드가 막던
   **하드닝 케이스**로 비교한다(#414 F-5b).
4. **범위는 파생시킨다.** 필수 체크는 `needs:` 이행 폐쇄에서, 설치 대상은 설치
   스크립트에서. 이름을 쓰면 세 번째 스코프 실패가 온다(#407·#412·#413·#417).
5. **모집단을 세고 나서 흔하다/드물다를 말한다.** #407의 첫 초안은 스텝 `if:`를
   "흔하다"는 이유로 제외했다. 그래프 안에서는 105스텝 중 7개, 그중 5개가 bare
   `always()`였다. 세는 데 1분 걸렸고 결정이 뒤집혔다.
6. **판정에는 클래스·근거·날짜를 붙인다.** 무한정 유효한 "이건 괜찮음"은 한 달 뒤
   거짓이 된다(#413).
7. **실행형 증명에는 "실행 프로세스가 볼 수 없는 텍스트" 목록을 붙인다.** 그리고 그
   목록에 SKIP 계열만 넣지 않는다 — REDIRECT가 더 나쁘다(#412).
8. **레포 밖으로 나가는 파일을 나열한다.** 설치 스크립트가 복사하는 것, 패키지가
   배포하는 것. 우리 CI 파일 집합보다 폭발 반경이 크다(#415).
9. **매처가 아니라 추출기를 공격한다.** 키 철자를 다 맞춰도 블록이 잘리면 그 뒤는
   보이지 않는다. 수집기가 읽는 문법(매핑 vs 스칼라)에서 주석의 의미를 먼저
   측정한다(#419, 2.4절).
10. **수정 뒤 기존 뮤테이션 테스트를 반드시 다시 돌린다.** 2차 결함은 리뷰가 아니라
    거기서 나온다 — `min(indent)` 5곳 오염이 그렇게 잡혔다(#419).
11. **판정에 "무영향"을 쓰지 않는다.** 측정 결과를 서술한 것일 뿐 이유가 없으면 다음
    감사가 재조사한다. 이유까지 찾으면 면역이 어디에 있는지가 드러나고, 그 지점을
    핀으로 고정할 수 있다(#420: 면역은 수집기가 아니라 `setUpClass`의 한 줄이었다).

## 8. 검증 근거

| 항목 | 근거 |
|---|---|
| PR 표의 스위트 수치 | 각 머지 커밋 본문에서 인용 (`git log -1 --format=%b <sha>`) — 1853(#404) → 1866(#406) → 1881(#407) → 1912(#408) → 1945(#410·#411) → 1972(#414) → 1981(#415) |
| #412 REDIRECT | 실제 `security-scan.yml`에 `working-directory: docs` 적용: 1945 passed → 9 failed. cwd별 실행 확인: root → `Critical: 1` → exit 1 / `docs/` → `Critical:`(빈 값) → exit 0 |
| #413 스코프 | 실제 `security-scan.yml`에 `run: exit 1` 잡 추가 + `needs:` 누락: 1952 passed → 1 failed |
| #414 우회 | 인용된 형제 잡을 심은 뒤 옛 파서 복원: 4개 뮤테이션 중 2개 FAIL |
| #411 문서 전용 | 프로브 8개 적용·복원 후 `pytest scanner/ -q` 전후 동일 (1945 passed, 5 skipped), `git status --short`에 문서만 |
| [#416](https://github.com/Twodragon0/claudesec/pull/416) MERGED `00f02f5` | 1989 passed, 5 skipped; 두 러너 145 tests OK; 앵커를 낡게 만들어 실패 메시지 채집 후 복원 |
| [#417](https://github.com/Twodragon0/claudesec/pull/417) MERGED `066d782` | 2006 passed, 5 skipped; 4개 가드 179 tests `python3 -m unittest` OK; `uses: "actions/checkout@main"` 를 실제 `lint.yml`에 적용 → 수정 전 15 passed / 수정 후 `lint.yml:66: actions/checkout@main` |
| [#419](https://github.com/Twodragon0/claudesec/pull/419) MERGED `170c78e` | 2036 passed, 5 skipped; 주석-절단 프로브 3 BYPASS → 6 CAUGHT (PyYAML 사실 기준), 철자 프로브 10건 5 FALSE-ALARM → 전부 정상; 10개 가드 `python3 -m unittest` OK |
| [#420](https://github.com/Twodragon0/claudesec/pull/420) MERGED `7df8fff` | 2038 passed, 5 skipped; `harness_step_block(RAW) -> None` vs `(STRIPPED) -> 캡 유지` 양방향 측정 후 핀 |

PR #416·#417은 이 문서의 **초안 시점에는 열린 상태**였고, 그 상태로 본문에
기록됐다가 같은 세션에서 머지(`00f02f5`, `066d782`)된 뒤 이 갱신으로 정정됐다.
3절이 말하는 문서 부패를 이 문서 자신이 몇 시간 만에 재현한 셈이므로, 숨기지 않고
남긴다 — **회고에 "현재 열려 있음"이라고 쓰는 순간 그 문장은 만료 시한이 붙는다.**
갱신 시점의 상태는 `gh pr view <n> --json state,mergedAt`으로 재확인 가능하다.

## 9. 관련 문서

- [필수 체크 무력화 3연속 사이클 회고 (#404 → #408, 보론 #412·#413)](./runner-key-audit-retrospective.md)
  — 이 사이클 앞부분의 기술 클래스와, 이 문서가 말하는 두 반증의 대상
- [CI 설정 회귀 가드 카탈로그](../devsecops/ci-config-regression-guards.md)
  — 가드별 행, 백로그, 핀 정책 결정 기록
- [ADR-001: CI 가드 하드닝과 감사 주기](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md)
- [가드 YAML-형태 스윕 회고 (#391–#394)](./guard-yaml-shape-sweep-retrospective.md)
  — 인용 키 블라인드 클래스의 출발점
- [ADR-001 Q3 감사 회고](./adr-001-q3-audit-retrospective.md)
- 카탈로그의 **블록 수집기 전수 판정표**(2026-08-11) — 2.4절이 만든 열거이며,
  수집기별로 fixed / correct-as-is / fails-closed / immune 판정이 근거와 함께 있다

## 10. 참고 기준

- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control),
  CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-4 (Poisoned Pipeline Execution)
- NIST SP 800-218 (SSDF) — PO.3, PW.4
- OWASP Top 10:2021 A08 — Software and Data Integrity Failures
