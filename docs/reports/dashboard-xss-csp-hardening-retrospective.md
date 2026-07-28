---
title: "Dashboard XSS/CSP 하드닝 시리즈 회고 (#361–#370)"
description: "ClaudeSec 대시보드 출력 싱크 XSS 방어 + CSP 컨트롤 마이그레이션(PR #361–#370)의 근본 원인, 수정 내역, 회귀 가드 종합 회고"
tags:
  - session-report
  - security
  - xss
  - csp
  - dashboard
  - devsecops
---

# Dashboard XSS/CSP 하드닝 시리즈 회고 — #361–#370

## 1. 개요 (Context)

ClaudeSec 대시보드(`scanner/lib/dashboard-gen.py` + `dashboard-template.html` +
`dashboard_html_*.py` 빌더 모듈)는 스캔 결과를 정적 HTML로 렌더링한다. 입력의
상당 부분은 **공격자 영향권**에 있다: Prowler OCSF 파일명·필드, 스캐너 finding의
title/category/details, GitHub·Prowler API 응답, remediation 참조 URL 등.

방어의 두 축은 다음과 같다.

1. **컨텍스트별 출력 인코딩** — 값이 놓이는 위치(HTML 텍스트/속성, URL 스킴,
   JS 문자열, JSON, URL 쿼리)에 맞는 이스케이핑을 적용한다. OWASP는 컨텍스트별
   출력 인코딩과 URL 스킴 허용목록을 XSS의 1차 방어로 규정한다.[^owasp-xss][^owasp-dom]
2. **CSP(심층 방어)** — `dashboard-template.html`의 meta CSP는
   `script-src 'nonce-{{CSP_NONCE}}' 'strict-dynamic'`이며 `'unsafe-inline'`/
   `'unsafe-hashes'`가 **없다**. CSP Level 3에서 이 정책은 인라인 이벤트 핸들러
   (`onclick=` 등)와 `javascript:` URI 실행을 차단한다.[^csp3]

핵심 이스케이핑 헬퍼:

- `dashboard_utils.h()` — HTML 이스케이프(텍스트 + 따옴표 속성 컨텍스트). JS 문자열
  이나 URL 스킴 컨텍스트에는 **불충분**하다.
- `dashboard_utils.safe_url()` — URL 스킴 허용목록(`http`/`https`/`mailto` +
  protocol-relative + fragment/relative → 그 외 `#`).
- Bash: `output_prowler.sh`의 `_prowler_html_escape`, `datadog.sh`의 `_url_encode`,
  `output.sh`/`datadog.sh`의 JSON 이스케이핑.

## 2. 타임라인 — PR별 수정 내역

| PR | 커밋 | 싱크 컨텍스트 | 근본 원인 | 수정 |
|----|------|---------------|-----------|------|
| #361 | `8644396` | JSON (bash) | 손수 조립한 JSON에 `SCAN_DIR`·Datadog `service`/`env`가 이스케이프 없이 보간 | `output.sh`/`datadog.sh`에서 JSON 이스케이프 |
| #362 | `96221c0` | HTML 텍스트 (bash) | Prowler provider **label**이 raw로 렌더 | `_prowler_html_escape`로 HTML 이스케이프 |
| #363 | `f12a79c` | URL 쿼리 (bash) | Datadog `ddtags` URL 쿼리 값 미인코딩 | 순수 bash `_url_encode`로 percent-encode |
| #364 | `af01d4b` | (가드) | 위 bash 싱크의 raw 보간 회귀 방지 부재 | 소스핀 CI 가드 `test_ci_no_raw_output_interpolation.py` |
| #365 | `19ec444` | HTML 텍스트/속성 (py) | provider **name**(OCSF 파일명 유래)이 카드/표에 raw 렌더 → 저장형 XSS | 빌더/섹션 3곳을 `h()`로 래핑 |
| #366 | `247aad9` | JS 문자열 / URL 스킴 (py) | `onclick="switchTab('…','{cat}')"`에서 `h()`가 이스케이프한 `'`가 속성 토크나이저에 의해 라이브 `'`로 복원되어 브레이크아웃; 참조 `href`가 `javascript:` 허용 | 값을 `data-action` 위임으로 이동 + `safe_url()` 스킴 게이트 도입 |
| #367 | `9173ca5` | JS 문자열 / CSP | 48개 인라인 핸들러가 CSP에 막혀 **컨트롤 사망**(OWASP/Arch/Compliance 확장, 설정 모달 등) | 전량 `data-action`/`data-change`/`data-input` 위임으로 마이그레이션 |
| #368 | `d47997a` | (테스트/CodeQL) | CodeQL `py/incomplete-url-substring-sanitization` 오탐(테스트 assertion) | assertion을 완전한 HTML 프래그먼트로 구분하여 규칙 미발화 |
| #369 | `037b68d` | URL 스킴 (py) | policies·audit-points/MS/SaaS 소스 `href`가 `h()`만 있고 `safe_url()` 부재 | `h(safe_url(...))`로 스킴 게이트(심층 방어 일관성) + 소스핀 가드 확장 |
| #370 | `285db96` | (가드) | `data-action`↔디스패처 불일치는 소스핀이 못 잡음 | headless-Chrome 컨트롤 라이브니스 스모크 CI 잡 + config 가드 |

## 3. 근본 원인 테마

### 3.1 컨텍스트별 출력 인코딩

같은 값이라도 놓이는 위치마다 필요한 이스케이핑이 다르다. `h()`(HTML 엔티티
이스케이프)는 텍스트/따옴표 속성에서는 충분하지만:

- **JS 문자열 컨텍스트**(`onclick="fn('…')"`)에서는 무력하다. 브라우저 HTML 파서가
  `&#x27;`를 파싱 단계에서 라이브 `'`로 되돌린 뒤에야 인라인 스크립트가 컴파일되기
  때문이다(#366). 올바른 방어는 값을 실행 컨텍스트 밖(따옴표 `data-*` 속성)으로
  옮기고 위임 핸들러가 읽게 하는 것이다.
- **URL 스킴 컨텍스트**(`href="…"`)에서는 스킴 검증이 필요하다. `h()`는
  `javascript:`/`vbscript:`/`data:`를 걸러내지 못한다(#366/#369). 허용목록 방식
  (`safe_url()`)이 정답이며, 이는 OWASP의 URL 스킴 허용목록 권고와 일치한다.[^owasp-dom]

### 3.2 손수 조립한 직렬화(JSON/URL)의 위험

`output.sh`/`datadog.sh`는 문자열 연결로 JSON과 URL 쿼리를 만든다. 라이브러리
직렬화기 대신 수동 조립을 쓸 때는 각 값에 대해 명시적 이스케이핑(JSON escape,
percent-encode)이 반드시 뒤따라야 한다(#361/#363).

### 3.3 심층 방어와 그 부작용

meta CSP는 `onclick`/`javascript:` 실행 벡터를 원천 차단하는 심층 방어다(#366의
소스 수정과 중복이지만 유효). 그러나 정책이 인라인 핸들러를 막는다는 것은,
소스가 여전히 인라인 핸들러를 뿜으면 그 컨트롤이 **조용히 죽는다**는 뜻이기도
하다(#367). 즉 CSP 강화와 `data-action` 마이그레이션은 한 쌍으로 완결되어야 했다.

## 4. 견고함을 만든 것 — 회귀 가드 & 실증 검증

- **소스핀 가드** `test_ci_no_raw_output_interpolation.py`(#364) — 3개 bash 싱크에
  raw 보간이 재도입되면 CI 실패.
- **인라인 핸들러 가드** `test_dashboard_no_inline_handlers.py`(#367) — 10개
  빌더/템플릿에 인라인 `on*=`이 다시 생기면 실패(fail-injection 검증됨).
- **`safe_url()` 소스핀** `test_dashboard_utils_safe_url.py`의 하드닝 핀
  (#366/#369) — 참조/소스 `href`의 스킴 게이트 제거를 차단.
- **컨트롤 라이브니스 스모크**(#370) — 실제 headless Chrome로 컨트롤을 구동해
  `data-action`↔디스패처 **불일치**를 잡는다. 소스핀은 인라인 핸들러 유무만 보고
  이 불일치는 못 잡으므로 상보적이다. 구조적 CSS 셀렉터로 트리거를 고른다.
- **실증 브라우저 검증** — CSP 강제와 컨트롤 동작을 정적 읽기가 아니라 실제
  브라우저(Chrome 150, `--headless=new`)로 확인. 3개 공격 프로브(인라인 onclick,
  `javascript:` href, nonce 없는 `<script>`)가 모두 차단되고, 정상 컨트롤은
  동작하며 CSP self-violation은 0.

## 5. 조사 후 기각된 발견

- **`dashboard_template.py`의 `.replace()` 토큰 충돌 — 무해(기각).** 유일한
  `<script>` 컨텍스트 플레이스홀더 `{{HISTORY_JSON}}`은 숫자/타임스탬프/컴플라이언스
  카운트만 담고 finding 자유 텍스트를 담지 않는다. finding 필드는 본문 텍스트
  플레이스홀더에만 놓이므로, 리터럴 `{{HISTORY_JSON}}`을 담은 finding은 그 토큰이
  안전한 blob으로 치환될 뿐 공격자 텍스트가 스크립트 슬롯으로 들어가지 않는다.
  스크립트 임베드 브레이크아웃 가드(`</`→`<\/`)도 별도로 존재한다.
- **CSP 강제 — 실증 확인.** meta CSP가 실제로 인라인 핸들러·`javascript:`·nonce
  없는 스크립트를 차단함을 브라우저로 확인.
- **출력 싱크 회귀 감사 — 신규 갭 없음.** #361–#370 이후 스캔 대상 유래 데이터가
  닿는 싱크는 모두 올바른 컨텍스트 이스케이퍼를 거친다.

## 6. 잔여 / 범위 외

- **Audit Points 섹션의 죽은 렌더 배선** — 이 섹션은 `aa234cf`("streamline
  DevSecOps dashboard UI/UX")에서 의도적으로 제거되어 ISMS 대시보드로 이관됐다.
  `{{AUDIT_POINTS_HTML}}` 토큰은 사라졌으나 렌더 배선(빌더 호출 + `_TEMPLATE_KEYS`
  항목)이 남아 결과가 조용히 버려지고 있었다. 이는 별도 정리 PR에서 배선만 제거했다
  (섹션 복원이 아니라 죽은 코드 제거 — 제품 결정을 되돌리지 않음). 스캐너 체크
  `scanner/checks/saas/audit-points.sh`와 데이터 로더는 계속 사용되므로 유지.

## 7. 교훈 / 체크리스트

대시보드 출력 코드를 작성·리뷰할 때:

- [ ] 이 값의 **출력 컨텍스트**는? (HTML 텍스트/속성 → `h()`, URL 스킴 →
      `safe_url()` 후 `h()`, JS 실행 → 인라인 금지·`data-*` 위임, JSON/URL 쿼리 →
      전용 이스케이퍼)
- [ ] 값이 **공격자 영향권**인가? (OCSF 파일명, finding 필드, 외부 API 텍스트,
      remediation 참조 URL)
- [ ] 손수 조립한 JSON/URL인가? → 각 값에 명시적 이스케이핑.
- [ ] 인라인 `on*=`/`javascript:`를 새로 도입하지 않았는가? → CSP 하에서 죽는다.
- [ ] 회귀 가드(소스핀/브라우저 스모크)가 이 싱크/컨트롤을 덮는가?
- [ ] 정적 읽기가 아니라 **실제 브라우저**로 실행 벡터/컨트롤을 확인했는가?

[^owasp-xss]: OWASP, "Cross Site Scripting Prevention Cheat Sheet." <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
[^owasp-dom]: OWASP, "DOM based XSS Prevention Cheat Sheet." <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
[^csp3]: W3C, "Content Security Policy Level 3." <https://www.w3.org/TR/CSP3/>
