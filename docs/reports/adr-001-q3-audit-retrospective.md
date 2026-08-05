---
title: "ADR-001 분기 감사 회고 — #297 (PR #376/#378/#379/#383/#385/#386/#389)"
description: "ADR-001 §2 반복 적대 검증으로 CI 가드 파싱 검출기의 잔여 우회를 찾은 #297 분기 감사 회고 — 5-패스 체인, Class-1/2 구분, 양방향 정규식, 무력 단정의 메타 가드화, 스택 PR 트리거 갭"
tags:
  - session-report
  - security
  - ci-cd
  - supply-chain
  - devsecops
  - testing
---

# ADR-001 분기 감사 회고 — #297 (PR #376/#378/#379/#383/#385/#386/#389)

## 1. 개요 (Context)

ClaudeSec의 CI 보안/품질 게이트는 `scanner/tests/test_ci_*.py`의 stdlib-only
"config regression guard"들이 지킨다. 이들은 워크플로 YAML / 셸 / Dockerfile을
**텍스트로** 읽어 각 불변식(커버리지 하한, 액션 SHA 핀, `Security Scan Gate`
심각도 차단, npm provenance 등)이 유지되는지 검사한다. 텍스트/부분문자열/정규식
매처이기 때문에 **거짓 음성(false-negative)** 클래스를 공유한다: 실제 통제는
제거되었는데 보호 토큰이 `#` 주석(또는 파서가 인식 못 하는 문법 형태)에만 살아남아
가드가 **green**으로 남는 것. 이는 공급망 흐름 제어 위험 **OWASP CICD-SEC-1
(Insufficient Flow Control)** 이자 **NIST SSDF (SP 800-218) PO.3 / PW.4** 무결성
기대에 해당한다. 조용히 발화하지 않는 가드는 리뷰어에게 거짓 확신을 주므로
무가드보다 나쁘다.

[ADR-001](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md)은 이
클래스에 대해 **substring/parse 가드의 2-pass 적대 리뷰**와 **정기 종합 감사**를
규정한다. 본 문서는 그 정기 감사(#297)에서 세 PR의 새 파싱 검출기를 대상으로 한
**§2 2차(반복) 적대 패스**의 회고다.

## 2. 대상 PR과 수정 요약

| PR | 검출기 | 잔여 우회 (2차 패스에서 발견) | 수정 |
|---|---|---|---|
| **#376** | `strip_inline_comment_sh` (공유 primitive) | **CRITICAL** — ANSI-C `$'...'` under-strip | escape-aware `$'...'` 분기 |
| **#378** | `cli_case_arms` / `_parse_bash_case` | deeper-indent `*)` + 공백 `* )` | indent→`case`/`esac` **depth** 스코핑 |
| **#379** | `_OS_RUNNER_RE` / `_GREP_E_RE` | 대소문자 미탐 + charset 오탐 + `egrep` 미탐 | runs-on 컨텍스트 스코프 + IGNORECASE; `\begrep\b` |

세 PR 모두 수정마다 **non-vacuous mutation test**(수정 전 로직에서 RED임을
증명)를 동반했고, 실제 파일 positive control은 green을 유지했다.

### 2.1 감사가 열어젖힌 후속 (#383 → #389)

PR #376의 primitive를 기준으로 나머지 가드를 훑자 감사 범위가 **더 나쁜 클래스**로
확장됐다. 아래는 모두 머지됨.

| PR | 내용 | 클래스 |
|---|---|---|
| **#383** | `provenance_verify`의 `npm audit signatures`(워크플로 자체 주석 4곳 + `echo "::error::…"` 2곳으로 충족), `docker_image_size_gate`의 `exit 1`(무관한 12개 라인으로 충족), 스모크 하네스의 스텝별 `timeout-minutes`(job 레벨 키로 충족) | **무력(inert)** — 회피조차 필요 없음, 평문 삭제도 못 잡음 |
| **#385** | Class-B 3건 + #383이 자기 자신에 기록해 둔 size-gate 갭을 `strip_inline_comment_sh`로 라우팅; **무력 단정을 AST 메타 가드로 승격** | Class-1 + 메타 |
| **#386** | 두 필수 워크플로의 `pull_request:` 트리거 언스코프 + 트리거-범위 가드 | 인프라 |
| **#389** | 카탈로그 메타 가드 2개에 mutation self-test + `<!-- -->` 스트립 | Class-2 (마지막) |

### 2.2 무력 단정(inert assertion) — 손 트리아지를 메타 가드로

PR #383이 손으로 찾은 두 무력 가드는 **같은 형태**였다: *보호 대상 파일의 raw 전체
텍스트에 대한 존재 단정*. 통제를 주석 처리해도 토큰은 파일에 남으므로 가드는 green을
유지한다. 손 트리아지는 40개 가드로 확장되지 않고 신규 가드에는 아예 돌지 않는다.

이를 `test_ci_guard_assertion_scoping.py`(stdlib `ast`)로 코드화하자 **7건이 더**
나왔고 각각 주석 처리한 아티팩트로 실행 확인했다 — 수정 전 green, 수정 후 red,
mutant는 동일하고 haystack만 다름:

- `branch_protection_codified` ×4 — `DESIRED_CONTEXTS`(필수 머지 컨텍스트 2개),
  `DESIRED_ENFORCE_ADMINS="true"`, `DRIFT DETECTED` 마커 계약 양단
- `cross_os_non_required` ×1 — `macos-latest` 러너 카나리
- `npm_publish` ×2 — push `branches: [main]` 자동 릴리스 트리거

메타 가드는 무력이 **아닌** 두 형태를 의도적으로 면제한다: 부정 단정(raw 스캔은
과다보고만 하므로 우회가 아니라 거짓 경보)과 행-앵커 정규식(`(?m)^\s*token` —
주석 사본이 매치 불가). 베이스라인은 **빈 채로** 출하되고 집합 동등성으로 고정돼
낡은 예외도 새 위반과 똑같이 실패한다.

**교훈:** 반복해서 손으로 찾는 형태가 있다면, 그 트리아지 자체가 가드가 될 수 있는지
물어라. 여기서는 2건의 손 발견이 7건의 자동 발견으로 이어졌다.

### 2.3 감사 도중 드러난 인프라 갭 — 스택 PR에 필수 체크가 안 돈다

감사 후속을 스택 PR로 올리다 발견했다. `on.pull_request.branches`는 PR의 **base
ref**를 필터링하므로, `branches: [main]`이 걸린 `lint.yml`/`security-scan.yml`은
base가 피처 브랜치인 PR에서 **아예 트리거되지 않았다**.

| PR | base | 체크 수 | `Lint` | `Security Scan Gate` |
|---|---|---|---|---|
| #384 | 피처 브랜치 | **3** | 부재 | 부재 |
| #385 | `main` (동일 브랜치 재지정) | **28** | SUCCESS | SUCCESS |
| #387 (일회용 실증, #386 이후) | 피처 브랜치 | **23** | SUCCESS | SUCCESS |

즉 감사 기간 내내 후속 PR들이 **CI로 검증 불가능한 상태**였고, 근거는 로컬 실행뿐이었다.
PR #386이 필터를 제거했고 #387이 사후 실증했다.

이것은 #186 `paths-ignore` 실패 모드가 **아니며 될 수도 없다**. #186은 `main`을
대상으로 하는 PR에서 필수 체크가 보고되지 않아 머지가 영구 차단된 사건이다.
`branches:` 제거는 **순증**이다 — base=`main` PR의 동작은 비트 단위로 동일하고
(필터가 항상 매치했으므로), 보호 규칙이 없는 브랜치만 커버리지를 얻는다.
PR #386은 같은 근본 원인(필수 체크에 걸린 워크플로 레벨 트리거 필터)의 **양방향**을
가드로 고정했다 — `branches:`와 `paths-ignore:`. 후자는 그때까지 규칙 문서와
가드 docstring의 **산문으로만** 존재했고 실제로 고정된 적이 없었다.

**교훈:** 감사는 가드의 로직만이 아니라 **가드가 실제로 실행되는지**도 확인해야 한다.
완벽한 가드도 트리거되지 않으면 0의 가치다.

## 3. 근본 원인 테마

### 3.1 Class-1 vs Class-2

- **Class-1 (comment/quote-state)** — 보호 토큰이 셸 주석에 숨는 흐름. 위험이
  높다(요구 게이트 우회). #376이 이 클래스이며, 과거 #271 F-1(`# exit 1`이
  Security-Scan-Gate 병합 차단을 만족)과 동일 계열이다.
- **Class-2 (matcher-completeness / enumeration gap)** — 파서가 규칙을 모델링하지
  않고 몇 가지 형태만 열거해, 의도적이지만 그럴듯한 편집이 빠져나가는 흐름.
  #378(케이스 순서)·#379(러너 라벨/`egrep`)가 이 클래스다.

### 3.2 #376 — "over-strip일 뿐"이라는 주장의 반증 (Class-1)

`strip_inline_comment_sh`는 bash 단어 경계 뒤의 `#`를 주석으로 인식하는
quote-aware primitive다. 초기 4-패스 체인(공백 필요 → `;#` metachar → 공유 primitive
→ backtick)은 남은 한계들을 **모두 over-strip(거짓 경보) 방향, 절대 우회 아님**이라
문서화했다. 그러나 그 단정은 **틀렸다**:

- ANSI-C `$'\''`는 **하나의** 문자열이다(`\'`는 이스케이프된 리터럴 따옴표).
  single-quote 분기에 이스케이프 인식이 없어, 파서는 뒤따르는 `'`에서 따옴표를
  다시 연 것으로 착각하고 줄 끝까지 "따옴표 안"으로 달려, 뒤의 `#`를 **벗기지
  못한다.** 이것은 over-strip이 아니라 **under-strip(거짓 음성)** 이다.
- 실증: `: $'\'' #exit 1`로 `exit 1`을 대체하면 bash는 `#exit 1`을 실제 주석으로
  처리(`CRITS=3`에서 exit code 0, 게이트 미차단)하지만, `conditional_body_from`은
  벗기지 못한 body에서 `exit 1`을 찾아 `test_critical_block_exits_nonzero`가
  **green**으로 남는다 → **요구되는 Security Scan Gate 병합 차단이 조용히 무력화.**
- 수정: `$` 뒤의 `'`는 escape-aware 문자열을 열도록 모델링. ANSI-C를 "over-strip
  한계"에서 "모델링됨"으로 재분류하고, "boundary set PROVEN COMPLETE / bash와 정확히
  일치"라는 문구를 실제에 맞게 정정했다(경계 문자 집합 자체는 완전했다 — 버그는
  집합이 아니라 인용 상태였다).

이는 ADR-001이 예측한 **"첫 수정이 잔여 구멍을 남긴다"** 패턴의 5번째 사례다:
4-패스 체인조차 5번째 구멍을 남겼고, 2차 적대 패스가 그것을 잡았다.

### 3.3 #378 — 프록시가 아니라 문법을 모델링하라 (Class-2, ADR §4)

`cli_case_arms`는 케이스 중첩의 **프록시로 들여쓰기**를 썼다. bash `case`는
들여쓰기와 무관하게 중첩(`case`/`esac`)으로 arm 소속을 결정하므로, 첫 arm보다 더
깊게 들여쓴 최상위 `*)`가 indent 필터에 걸러져 수집을 끝내지 못했고, 그 아래로
강등된 서브커맨드가 실행상 dead임에도 dispatched로 집계됐다. 수정은
**`case`/`esac` depth 스코핑**(문법적으로 완전). 곁들여, 기존 nested-case
self-test가 **vacuous**(인라인 `*) s ;;`가 bare-arm 정규식에 안 걸려 스코핑을 전혀
실행 안 함)임을 확인해 bare-style로 교체했고, `_parse_bash_case`는 유효한 공백
catch-all `* )`(bash에서 검증)를 놓쳐 `\*\s*\)`로 확장했다.

### 3.4 #379 — 정규식이 양방향으로 틀릴 수 있다 (Class-2)

`_OS_RUNNER_RE = \b(?:macos|windows)-[a-z0-9.]+\b`는 **동시에 두 방향으로** 틀렸다:

- **너무 좁음(미탐)** — 대소문자 구분이라 GitHub 실제 표기 `macOS-14` /
  `[self-hosted, macOS-latest]`가 required-Lint OS-러너 가드를 우회.
- **너무 넓음(오탐)** — `run:`/`name:`의 실제 `windows-1252`(charset)·
  `macos-universal`(arch)에 오작동.

핵심 함정: **단순 `re.IGNORECASE`만 추가하면 오탐이 악화된다** — `windows-1252`
(charset)와 `windows-2022`(version)는 형태가 동일해 토큰 정규식만으로 구분 불가.
올바른 수정은 매치를 **`runs-on:`/matrix `os:` 컨텍스트로 스코프**(스칼라·flow
배열·block 리스트)하고 IGNORECASE를 더하는 것. 또 `_GREP_E_RE`의 `\bgrep\b`는
`egrep`(단어 경계 없음, 게다가 ERE 암시로 `-E` 플래그도 없음)을 못 잡아
`egrep 'a\|b'` 리터럴-파이프 버그를 놓쳤다 → `\begrep\b` 대안 추가.

## 4. 반복 적대 검증(iterated adversarial verify) 패턴

ADR-001 §2의 "1차가 CRITICAL을 찾으면 2차 패스"를 이번엔 **관점이 다른 두 리뷰어
병렬 + 상충 지점 독립 재검증**으로 구현했다.

- **bypass-hunter** (false-negative 렌즈): 통제를 제거해도 가드가 green인 실행 가능
  PoC를 구성.
- **correctness-critic** (false-positive / vacuous-test / crash / claim 렌즈): 정상
  편집 오탐, vacuous mutation test, 파서 크래시, docstring 주장 재검증.
- 두 리뷰어가 **#376 ANSI-C의 방향(over-strip vs under-strip)에서 정면 충돌**했다.
  critic은 `$()` 케이스만 깊게 봤고 `$'...'`는 docstring 주장을 신뢰했다.
  **결정적 충돌은 편들지 말고 직접 실행 증거로 판정**했다: bash 실행 + 실제 소비자
  가드(`conditional_body_from`) 실행으로 bypass-hunter가 옳음을 확정.

교훈: 서로 다른 실패 모드를 노리는 관점-다양 검증이 중복 검증보다 낫고, **리뷰어가
충돌하면 승인이 아니라 실증으로 끊는다.** self-approval 금지는 승인 패스에 적용되며,
사실 확인(독립 재현)은 오히려 필수다.

## 5. 견고함을 만든 것 — 실증 & 회귀 가드

- **모든 finding은 실행 증거 기반** — bash 동작(통제 무력화) + 가드 함수 실행(불변식
  "유지" 반환)을 모두 제시. 추론만으로는 보고하지 않음.
- **모든 수정에 non-vacuous mutation test** — 수정 전 로직으로 되돌려 RED임을 증명
  (예: deeper-indent가 `{prowler,scan}` 수집, egrep가 `[]`, ANSI-C가 `exit 1` 잔존).
- **vacuous test 적발** — #378 nested-case 테스트가 스코핑을 전혀 실행하지 않음을
  확인해 교체. ADR §3 "거짓 확신은 무가드보다 나쁘다"의 직접 적용.
- **positive control** — 실제 `bin/claudesec-cli.sh`(필수 서브커맨드)·`output.sh`
  (16 provider)·`lint.yml`(러너 없음)가 계속 green.

## 6. 하드 공격에도 CLEAN

- #376 flow-style `run:` 추출기 + `unscannable_flow_runs` 트립와이어 — split
  `${{ }}`, bare/quoted/multi-line flow scalar 모두 시도, 우회 구성 실패.
- #379 `_is_shipped` npm resolver — 현재 입력(flat `scripts/*.py` + exact `!neg`)에선
  우회 없음(nested-operator `!scripts/*` 경로가 추가되면 재검토 — 코드 주석 권장).
- `strip_inline_comment_sh` 경계 문자 집합 `" \t;&|()<>` `` ` ``"` 자체는 완전
  (ASCII 전수 재확인). 구멍은 집합이 아니라 인용 상태 모델링이었다.

## 7. 잔여 / 범위 외

- `no_ere_pipe_regression`의 **변수 간접(cross-line indirection)** — `PATTERN=...`과
  `grep -E "$PATTERN"`이 다른 줄에 있는 경우. 라인 스캐너로는 dataflow 없이
  잡을 수 없고, 잡으려면 격차보다 나쁜 오탐 규칙이 필요 → 문서화된 알려진 한계.
- `strip_inline_comment_sh`의 over-strip(거짓 경보, 우회 아님) 한계 — cross-line
  인용, heredoc 본문, 단어 내 `$(...)` 종료 — 현재 스캔 블록에서 트리거되지 않아
  모델링 대신 문서화.
- `injection_surface`의 줄 분할 `${{ }}` — stdlib-only / no-PyYAML 제약에 묶인
  **의도적 비수정**. 취약한 bracket-depth 휴리스틱으로 반쯤 닫는 대신 추적한다.
  이것이 Class-2 백로그의 유일한 잔여 항목이며, 나머지는 #378/#379/#389로 비웠다.
- **스택 PR 운영 함정** — `--delete-branch`(필수 자세)가 base ref를 지우면 스택 PR이
  자동 CLOSE되고, 닫힌 PR은 base 변경도 재오픈도 불가하다. 리베이스 + 새 PR로만
  복구되며 리뷰 스레드를 잃는다(#384 → #385). 코드가 아닌 **프로세스** 문제라
  `.claude/rules/git-workflow.md`에 규칙으로 기록했다.

## 8. 교훈 / 체크리스트

- [ ] 구조화된 입력을 매칭할 땐 **형태를 열거하지 말고 문법을 모델링**하라
      (indent→case depth, `$'...'` 인용 상태). 세 번째 열거 패치는 재설계 신호다.
- [ ] "완전함이 증명됨 / 절대 우회 아님" 같은 **안전성 단정은 실증으로 검증**하라.
      이번엔 그 단정 자체가 CRITICAL을 가리고 있었다.
- [ ] 정규식은 **양방향(미탐+오탐)** 으로 검사하라. 한 방향 수정(IGNORECASE)이
      다른 방향(charset 오탐)을 악화시킬 수 있다 → 컨텍스트 스코프가 정답일 때가 있다.
- [ ] **관점-다양 적대 검증**을 쓰고, 리뷰어가 충돌하면 **직접 실행 증거로 판정**하라.
- [ ] 모든 검출기는 **수정 전 로직에서 RED임을 증명한 mutation test**를 동반하라.
      vacuous test는 거짓 확신을 준다.
- [ ] 가드의 **haystack이 raw 원문인지** 확인하라. 존재 단정이 주석 처리를 견디면
      그 가드는 무력이다 — 이번엔 손으로 2건, 메타 가드로 7건이 더 나왔다.
- [ ] 반복해서 손으로 찾는 형태는 **트리아지 자체를 가드로 승격**할 수 있는지 물어라.
- [ ] 가드 로직뿐 아니라 **가드가 실제로 실행되는지**도 감사하라. 트리거되지 않는
      가드는 완벽해도 가치가 0이고, 이번엔 감사 후속 전체가 그 상태였다.
- [ ] 실증 하네스 자체를 의심하라. 첫 무력 측정은 `setUpClass` 재실행이 주입값을
      실제 파일로 덮어써 **전부 green**으로 나왔다 — 결론이 아니라 하네스가 틀렸다.

## 참고

- [ADR-001: CI Guard Hardening & Periodic Adversarial Audit](../devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md)
- [CI Config Regression Guards 카탈로그](../devsecops/ci-config-regression-guards.md)
- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control):
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (SSDF) — PO.3 / PW.4: <https://csrc.nist.gov/pubs/sp/800/218/final>
