---
title: "green-while-dead 사이클 회고 (#513 → #522)"
description: "green인 job 안의 ##[error]는 보이지 않는다 — 아홉 개의 죽은 통제를 찾은 두 가지 방법이 서로를 대체하지 못한 이유, 그리고 false clean을 만든 positive control의 범위 착각"
tags:
  - session-report
  - devsecops
  - ci
  - github-actions
  - regression-guard
  - retrospective
---

# green-while-dead 사이클 회고 — 2026-09-01 → 09-03

## 1. 개요

이 사이클의 결함은 전부 한 문장으로 요약된다: **선언된 능력과 관측된 동작이
서로 다른 주장인데, 아무도 둘을 대조하지 않았다.** 통제는 초록이었고, 하는 일은
없었다.

시작은 사소했다. Dependabot PR #511의 red 체크 3건을 고치려다 `templates/`
codeql pin 누락(#478→#483의 재발)을 발견했고, 그 과정에서 옆 스텝이 **green인
main push에서도** `##[error]` 두 줄을 뱉고 있는 것을 봤다. 거기서부터 같은
모양을 훑었다.

핵심은 diff가 아니라 **방법**이다. 이 클래스는 정적 분석으로도, 로그 실증으로도
각각 절반만 보인다. 그리고 이 회고를 쓰게 만든 가장 값비싼 실수는 결함이 아니라
**내 스윕이 만든 false clean**이었다.

## 2. 찾은 것 — 아홉 개

| # | 결함 | 왜 안 보였나 | PR |
|---|---|---|---|
| 1 | junit 리포터가 체크런을 **한 번도** 만든 적 없음 | `checks: write` 없이 API 호출 → 403. `fail_on_failure`/`fail_on_parse_error` 기본값이 `false`라 비치명적 | #513 |
| 2 | 같은 스텝이 Cobertura `coverage.xml`을 JUnit 파서에 먹임 | `report_paths` 글롭이 커버리지 파일까지 매칭 | #513 |
| 3 | **`pii-check`가 `find`만 실행. 7일간 PII 스캔 0** | `\` continuation 뒤의 `#`가 명령을 절단. 기본 셸 `bash -e`에 pipefail이 없어 파이프 왼쪽의 127이 오른쪽의 0에 가림 | #518 |
| 4 | `templates/security-scan-suite.yml`이 **로드 불가** | 잡 레벨 `if:`의 `secrets` 컨텍스트. codeql·semgrep·trivy·gitleaks·osv 전부 사망 | #519 |
| 5 | `templates/prowler.yml` 동일 결함 (스텝 레벨) | 위와 같음, 범위만 좁음 | #519 |
| 6 | Lighthouse 리포트가 **한 번도** 업로드된 적 없음 | `.lighthouseci/`가 hidden dir + `include-hidden-files` 기본 false + `if-no-files-found: ignore` | #519 |
| 7 | Codecov 업로드가 **23일 이상** 거부 | 레포 시크릿 0개 → 토큰 없음 → tokenless 업로드 거부. 배지는 `unknown` | #520 |
| 8 | lychee sweep의 `error` state를 아무도 소비 안 함 / prowler watch가 "no verdict"와 "frozen"을 구별 못 함 | 출력만 쓰고 `if:`가 없음 / `result_code` 캡처 후 미사용 | #521 |
| 9 | **auto-merge hard-exclude가 fail-OPEN** | 문서화된 "Fail-closed" 주석이 거짓. 빈 경로 목록이 exclusion 루프를 그냥 통과 | #522 |

3번과 9번은 required 게이트와 권한 경계에 있었다. 나머지는 리포팅이었지만,
"리포팅이라 괜찮다"는 판단은 **측정한 뒤에** 할 말이다.

## 3. 주제 1 — 두 방법은 대체재가 아니라 보완재다

이 사이클에서 두 가지 스윕을 돌렸고, **각각이 상대가 구조적으로 볼 수 없는 것을
찾았다.**

**정적 분석(권한 vs API 호출 대조)이 볼 수 없는 것.** 1번 결함의 `checks.create`
호출은 워크플로 YAML에 **문자열로 존재하지 않는다.** 서드파티 액션 내부의
호출이다. 전 워크플로 30개에 대해 API write와 필요 스코프를 기계 대조했고
실질 불일치는 0건이었는데, 그 스윕은 우리가 이미 고친 결함을 **원리적으로**
찾을 수 없었다.

**로그 실증이 볼 수 없는 것.** 4·5번은 `templates/`에 있다. 이 레포에서 실행되지
않으므로 로그가 없다. 4번은 심지어 GitHub가 파일을 거부해서 **실행 자체가 없다** —
관측할 로그가 존재할 수 없는 결함이다. 이건 `actionlint`라는 세 번째 도구가
찾았다.

결론: "스윕했다"는 말은 **어떤 관측면을 봤는지** 함께 말하지 않으면 의미가 없다.

## 4. 주제 2 — 내 positive control이 false clean을 만들었다

이게 이 회고에서 가장 중요한 부분이다.

로그 스윕을 돌리기 전에 이 레포의 규칙대로 positive control을 먼저 했다. 이미
아는 결함(수정 전 run 33578709890)에 grep을 돌려 `##[error]` 두 줄이 잡히는 것을
확인했다. 통과했다. 그 다음 37개 잡을 훑어 **0건**을 보고했다.

**틀렸다.** 같은 범위에서 다른 에이전트가 4건의 REAL을 찾았다.

원인은 grep 패턴이 아니다. **추론의 범위**다.

> positive control은 그것이 행사한 마커에 대해서만 탐지를 검증한다.
> "탐지가 작동한다"를 검증하지 않는다.

내 control은 `##[error]` 탐지를 검증했고, 나는 그것을 **모든 실패 마커에 대한
clean 주장**으로 일반화했다. 놓친 것:

- `"error - "` — Codecov 자체 로거. 소문자, `##[error]` 아님 → 7번을 통째로 놓침
- `No files were found with the provided path` — → 6번을 통째로 놓침
- 셸 레벨 삼킴 — 내 정적 스윕은 토큰↔API만 봤다 → 3번을 놓침

**가장 이전 가능한 관찰**: `outcome=failure`는 61개 잡 로그 어디에서도 **0회**
매칭됐다. 삼켜진 실패를 찾는 가장 그럴듯한 마커인데, `fail_ci_if_error: false`가
액션을 exit 0으로 만들기 때문에 기록된 outcome은 `success`이고 정작 그 액션의
로거는 error 레벨로 쓴다. **annotation 기반 또는 outcome 기반 스윕만으로는 이
클래스를 덮을 수 없다.**

이 숫자는 넘겨받은 값이 아니라 **직접 재도출했다** — 회고의 숫자를 재도출 없이
믿지 말라는 것이 ADR-001 감사가 남긴 규칙이기 때문이다. 최신 green `main` Lint
런(`33745520620`)의 잡 18개 전체를 다시 훑어 `outcome=failure` 발생 **0회**를
확인했고, 61개 로그 측정과 일치한다.

## 5. 주제 3 — path gating은 최신 런만 보면 안 보인다

`lint.yml`은 잡이 18개인데 최신 green 런 하나에는 전부 나타나지 않는다. path
gate로 스킵된 잡은 로그가 없다. 최신 런 1개만 훑었다면 잡별 커버리지가
비었을 것이다.

green 런 6개로 넓혀 108개 job-log를 훑고서야 **선언된 18개 잡 전부**를 덮었다.
`project-ci-path-gating`이 기록한 그대로다: **게이트는 드리프트를 감춘다. 돌지
않은 잡은 아무것도 못 찾은 잡과 로그상 구별되지 않는다.**

## 6. 주제 4 — 수정이 클래스를 만든다

세 번 반복됐다.

**(1) 수정을 설명하려 쓴 주석이 명령을 깼다.** 3번 결함은 #496이 도입했고,
그 PR의 목적은 *바로 그 명령의* `xargs` 모드 전환을 고치는 것이었다. 고친 이유를
설명하려고 쓴 주석이 `\` continuation 뒤에 놓이면서 `find`를 절단했다.

**(2) 내 첫 수정이 불완전했고, 뮤테이션이 두 번째 하위 형태를 드러냈다.**
`set -euo pipefail`을 추가하면 끝인 줄 알았다. 뮤테이션 테스트가 재현한 것은
다른 형태였다:

| 주석 위치 | 고아 조각 | pipefail이 잡나? |
|---|---|---|
| 마지막 continuation 뒤 (실제 사고) | `-print0 \| xargs …` | ✅ 127 |
| 앞쪽 continuation 뒤 | `! -path … -print0 \| xargs …` | ❌ bash `!`가 파이프라인 **부정** → exit 0 |

`set -euo pipefail`은 절반만 덮는다. 그래서 `find`를 **한 줄로 합쳐** continuation
자체를 없앴다 — 탐지보다 강한 건 배열이 불가능해지는 것이다.

**(3) 내가 방금 넣은 규칙에 결함이 있었다.** #516에 "브랜치 생성 후
`gh pr merge` 출력 파일 목록을 대조하라"를 넣었다. `--delete-branch`는 main으로
옮겨 pull하므로 그 출력은 **로컬 캐치업 diff**다. #515·#516 두 번 연속 헛경보가
났고 #517로 고쳤다. 매 머지마다 늑대를 외치는 점검은 무시당하고, 그러면 애초에
그 규칙이 막으려던 탐지를 잃는다 — #505가 DAST 트래커에 대해 기록한 것과 같은
모양이다.

## 7. 주제 5 — 실패한 뮤테이션은 갭이 아닐 수 있다

9번(#522)의 non-vacuity 테스트에서 `PATHS_KNOWN` 게이트만 제거했는데 구멍이
재현되지 **않았다**. 형제 게이트(`path_count -eq 0`)가 같은 입력을 막았기
때문이다.

이건 defence in depth이지 실패한 탐지가 아니다. 가드 자신의 실패 메시지 —
*"the mutation did NOT actually disable the control. Check the SECOND
possibility FIRST"* — 가 그걸 드러냈다. 재현은 둘 다 제거하도록 고치고, 각
게이트의 독립적 충분성을 별도 케이스로 **측정**해 남겼다.

`probe-harness-lies`가 기록한 규칙("두 측정이 모순하면 먼저 내 프로브를
의심하라")이 실제로 값을 한 사례다.

## 8. 왜 설정 형태 검사로는 못 잡았나 — 그리고 왜 실행이 답인가

3번이 가장 명확한 사례다. 문자열 `hooks/pii-check.sh`는 **내내 정상적으로
존재했다.** `assertIn("hooks/pii-check.sh", body)` 가드가 있었다면 통제가 죽은
7일 내내 초록이었을 것이다. 결함은 루프가 **무엇을 매칭하는가**가 아니라
**무엇을 받는가**에 있었다.

9번도 같다. 모든 `case` arm이 정확히 존재했다. 문제는 루프에 들어가는 입력이
비어 있었다는 것이다.

그래서 이번 사이클의 새 가드 5개 중 3개는 **대상을 실행한다** (ADR-001 §4 / #404):

- `test_ci_pii_check_executes.py` — 스텝 본문을 tmpdir에서 `bash -e`로 실행하고
  **hook 자신의 판정줄**이 나오는지 본다. 종료 코드만 보는 건 함정이다:
  pipefail 하에서는 깨진 버전도 non-zero라 상태만 보는 단언은 바로 그 회귀에서
  통과한다
- `test_ci_dependabot_auto_merge_fail_closed.py` — `gh`를 스텁으로 두고 `pr merge`가
  실제로 호출됐는지로 판정. 6케이스 중 정당한 pip patch 1건만 arm 되는 것을 확인
- `test_ci_watcher_states_consumed.py` — 워처가 계산한 state에 소비자가 있는지

## 9. 범위를 좁힌 것도 결정이다

`test_ci_watcher_states_consumed.py`는 일반 데이터플로 분석기가 **되지 않기로**
했다. 전 워크플로 서베이가 `npm-publish.yml`에서 4건의 "미소비"를 보고했는데
전부 false positive였다 — 잡 레벨 `outputs:`로 재수출돼 `needs.detect.outputs.*`로
소비되고, 하나는 `if:`가 아니라 `run:` 본문에서 쓰인다.

그 간접 참조를 일반적으로 쫓으면 헛경보를 사고, **싸워야 하는 가드는 수리되지
않고 약화된다**(#414). 그래서 state enum을 워처별로 선언하고, 종단 state는 사유와
함께 allowlist에 **동등성으로** 고정했다 — 원래 결함을 잡았을 규율은 바로 그것이다.
누군가 `error`에 소비자가 없는 이유를 적어야 했을 테니까.

## 10. 반복 가능한 체크리스트

1. **positive control의 범위를 적는다.** "control 통과"가 아니라 "control은
   마커 X에 대해 통과했다". 다른 마커에 대한 clean은 그 control이 보증하지 않는다.
2. **마커 집합을 액션의 로거까지 넓힌다.** `##[error]`만으로 부족하다. 최소한
   `"error - "`, `ERROR:`, `No files were found`, `Resource not accessible`,
   `HttpError`, `403`/`401`. `outcome=failure`는 이 클래스에서 **쓸모없다**.
3. **정적 + 로그 실증을 둘 다 돌린다.** 서드파티 액션 내부 호출은 정적으로,
   실행되지 않는 `templates/`는 로그로 안 보인다. `actionlint`는 세 번째 면이다.
4. **최신 런 하나로 판단하지 않는다.** path-gated 잡을 덮으려면 여러 런이 필요하다.
   덮은 잡 목록을 선언된 잡 목록과 대조해 숫자로 말한다.
5. **"조용함"을 성공으로 읽지 않는다.** 통제가 돌고 0건인 것과 안 돌아서 0건인
   것은 구별되지 않는다. 통제가 **실행됐다는 별도 증거**를 댄다.
6. **수정 후 새 버전을 그 자체 조건으로 다시 공격한다.** 옛 버전의 알려진 갭만
   확인하는 것으로는 부족하다 — `!` 부정 형태가 그렇게 나왔다.
7. **뮤테이션이 안 잡히면 가드보다 프로브를 먼저 의심한다.** defence in depth일
   수 있다.
8. **`templates/`를 스윕에 포함한다.** 여기서 안 보이고 어댑터에게 전파된다
   (#415/#417 클래스).

## 11. 검증 근거

| 항목 | 값 |
|---|---|
| PR | #513, #518, #519, #520, #521, #522 (+ 규칙 #516/#517) |
| 신규 가드 | 5개 (`test_ci_junit_reporter_live`, `test_ci_pii_check_executes`, `test_ci_no_secrets_in_if`, `test_ci_watcher_states_consumed`, `test_ci_dependabot_auto_merge_fail_closed`) |
| 가드 카탈로그 행 | 62 → 67 |
| `unittest discover 'test_ci_*.py'` | 1088 → **1126** OK |
| `pytest scanner/tests/` | 2760 → **2797** passed, `scanner/lib` 99.43% (floor 99) |
| `actionlint` `secrets`-in-`if` | 4건 / 2파일 → **0** |
| Lighthouse 아티팩트 | 6개 런 모두 0개 → **1,735,459 바이트** |
| kcov 캐시 | `Cannot mkdir` → `Failed to restore` → `Cache restored successfully`, 잡 ~5분 → ~75초 |
| pii-check 노출 | 전체 tracked 파일 재스캔 **0건** (positive control로 검증) |

## 12. 남은 것

- **#405** — `REPO_ADMIN_TOKEN` 미설정. 이번에 레포 시크릿이 **0개**임을 확인해
  근본 원인이 확정됐다. 코드 수정 불가
- `required_approving_review_count` 0 상향 — 협업자 1명 + `enforce_admins: true`
  에서는 소유자 본인 PR이 영구 머지 불가가 된다. `sync-repo-protection.sh`의
  revisit trigger("두 번째 사람이 write 권한을 얻는 순간")가 아직 안 켜졌다
- `vars.GITHUB_*` 죽은 knob (LOW), `templates/`의 로컬 액션 참조

## 13. 관련 문서

- `docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md` — §1(주석/인용
  상태), §4(파싱 대신 실행)
- `docs/devsecops/ci-config-regression-guards.md` — 가드 카탈로그 + block-collector 표
- `docs/reports/runner-key-audit-retrospective.md` — 실행형 증명의 사각지대
- `.claude/rules/git-workflow.md` — 브랜치 시작점 규칙 (#516/#517)

## 14. 참고 기준

- OWASP CICD-SEC-1 (Insufficient Flow Control), CICD-SEC-4 (Poisoned Pipeline
  Execution), CICD-SEC-7 (Insecure System Configuration)
- NIST SP 800-218 (SSDF) PO.3, PW.4, PW.7
- CIS Controls v8 — 안전한 구성 및 지속적 취약점 관리
