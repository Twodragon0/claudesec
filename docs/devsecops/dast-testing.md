---
title: DAST (동적 애플리케이션 보안 테스팅) 가이드
description: OWASP ZAP 기반 DAST 자동화, CI/CD 파이프라인 통합, OWASP Top 10 기반 체크리스트
tags: [dast, owasp-zap, ci-cd, dynamic-testing, appsec, owasp-top10]
---

# DAST (동적 애플리케이션 보안 테스팅) 가이드

## 개요

DAST(Dynamic Application Security Testing)는 실행 중인 애플리케이션을 외부에서 공격하여 취약점을 탐지하는 블랙박스 테스팅 기법이다. 소스 코드 없이 HTTP 요청/응답을 분석하므로 런타임에서만 드러나는 취약점을 발견할 수 있다.

**참조 표준**

- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [NIST SP 800-53 SA-11](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — Developer Testing and Evaluation
- [CIS Controls v8](https://www.cisecurity.org/controls/v8) — Control 16: Application Software Security

---

## DAST와 SAST 비교

| 항목 | SAST (정적) | DAST (동적) |
|------|------------|------------|
| 분석 대상 | 소스 코드 | 실행 중인 애플리케이션 |
| 시점 | 빌드 전/중 | 배포 후 (스테이징/프로덕션) |
| 언어 의존성 | 있음 | 없음 (언어 무관) |
| 오탐(False Positive) | 상대적으로 높음 | 낮음 (실제 동작 기반) |
| 발견 가능 취약점 | 코드 결함, 인젝션 패턴 | 런타임 인젝션, 인증/인가 결함, 설정 오류 |
| 발견 불가 취약점 | 런타임 설정 오류 | 소스 내 하드코딩 자격 증명 |
| OWASP Testing Guide 매핑 | OTG-CODE | OTG-INPVAL, OTG-AUTHN, OTG-AUTHZ |

DAST는 SAST를 대체하지 않는다. NIST SP 800-53 SA-11은 두 방법을 함께 적용하는 계층적 테스팅을 권장한다.

```text
개발 단계:  [SAST] ──── 코드 결함 탐지
스테이징:   [DAST] ──── 런타임 취약점 탐지
프로덕션:   [RASP/WAF] ─ 런타임 보호
```

---

## OWASP ZAP 설치 및 기본 설정

### Docker 기반 설치 (권장)

```bash
# ZAP 최신 안정 버전 풀
docker pull ghcr.io/zaproxy/zaproxy:stable

# 기본 스파이더 스캔 실행 (빠른 검증용)
docker run --rm ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t https://staging.example.com \
  -r zap-baseline-report.html
```

### ZAP 스캔 모드 비교

| 모드 | 명령 | 소요 시간 | 권장 용도 |
|------|------|----------|----------|
| Baseline | `zap-baseline.py` | 2–5분 | PR 검증, 빠른 피드백 |
| Full Scan | `zap-full-scan.py` | 20–60분 | 스테이징 정기 스캔 |
| API Scan | `zap-api-scan.py` | 5–15분 | REST/GraphQL API |

### ZAP 규칙 설정 파일

프로젝트 루트의 `.zap/rules.tsv`로 스캔 규칙을 제어한다.

```tsv
# .zap/rules.tsv
# 형식: rule_id  IGNORE|WARN|FAIL  이유
10202  IGNORE  개발 환경 부재 헤더
10038  WARN    CSP 헤더 미적용 (경고만)
40012  FAIL    반사형 XSS — 즉시 차단
40014  FAIL    지속형 XSS — 즉시 차단
40018  FAIL    SQL Injection — 즉시 차단
90019  FAIL    서버 사이드 코드 인젝션
```

### ZAP 컨텍스트 설정 (인증 필요 엔드포인트)

```yaml
# .zap/context.yaml
context:
  name: "MyApp Authenticated Scan"
  includePaths:
    - "https://staging.example.com/api/.*"
    - "https://staging.example.com/app/.*"
  excludePaths:
    - "https://staging.example.com/logout"
    - "https://staging.example.com/admin/.*"
  authentication:
    method: form
    loginUrl: "https://staging.example.com/auth/login"
    loginRequestData: "username={%username%}&password={%password%}"
    loggedInIndicator: "\\QDashboard\\E"
    loggedOutIndicator: "\\QSign In\\E"
  users:
    - name: "test-user"
      credentials:
        username: "${ZAP_TEST_USER}"
        password: "${ZAP_TEST_PASSWORD}"
```

---

## CI/CD 파이프라인 통합 (GitHub Actions)

### 기본 DAST 워크플로우 — Baseline Scan

```yaml
# .github/workflows/dast-baseline.yml
name: DAST Baseline Scan

on:
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

jobs:
  dast-baseline:
    runs-on: ubuntu-latest
    permissions:
      issues: write
      security-events: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Start application (docker-compose)
        run: |
          docker compose -f docker-compose.staging.yml up -d
          # 애플리케이션 기동 대기
          timeout 60 bash -c 'until curl -sf http://localhost:8080/health; do sleep 2; done'

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: "http://localhost:8080"
          rules_file_name: ".zap/rules.tsv"
          cmd_options: "-a"  # 능동 스캔 포함
          fail_action: true  # FAIL 등급 발견 시 워크플로우 실패

      - name: Upload ZAP Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: zap-baseline-report
          path: report_html.html
          retention-days: 30

      - name: Teardown
        if: always()
        run: docker compose -f docker-compose.staging.yml down
```

### Full Scan — 스테이징 정기 스캔

```yaml
# .github/workflows/dast-full-scan.yml
name: DAST Full Scan (Nightly)

on:
  schedule:
    - cron: "0 2 * * *"  # 매일 오전 2시 (UTC)
  workflow_dispatch:
    inputs:
      target_url:
        description: "스캔 대상 URL"
        required: true
        default: "https://staging.example.com"

jobs:
  dast-full:
    runs-on: ubuntu-latest
    environment: staging
    permissions:
      issues: write
      security-events: write
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: ${{ github.event.inputs.target_url || 'https://staging.example.com' }}
          rules_file_name: ".zap/rules.tsv"
          cmd_options: >-
            -z "-config scanner.maxScanDurationInMins=30"
          token: ${{ secrets.GITHUB_TOKEN }}
          issue_title: "ZAP Full Scan Report"

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: "DAST"

      - name: Notify on Critical Findings
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '[DAST] Critical vulnerability detected - ' + new Date().toISOString().split('T')[0],
              labels: ['security', 'dast', 'critical'],
              body: 'DAST Full Scan에서 Critical 취약점이 발견되었습니다. Artifacts를 확인하세요.'
            })
```

### API Scan — REST/OpenAPI 대상

```yaml
# .github/workflows/dast-api-scan.yml
name: DAST API Scan

on:
  push:
    paths:
      - "openapi.yaml"
      - "src/api/**"

jobs:
  dast-api:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Start API server
        run: |
          docker compose up -d api
          timeout 30 bash -c 'until curl -sf http://localhost:3000/api/health; do sleep 2; done'

      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.7.0
        with:
          target: "http://localhost:3000/api/openapi.yaml"
          format: openapi
          rules_file_name: ".zap/rules.tsv"
          cmd_options: "-a -j"  # 능동 스캔 + Ajax Spider

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: zap-api-report
          path: |
            report_html.html
            report_json.json
```

---

## DAST 체크리스트 (OWASP Top 10 기반)

OWASP Testing Guide v4.2 기반으로 각 취약점 카테고리별 DAST 검증 항목을 정리한다.

### A01: Broken Access Control

- [ ] **IDOR 검증**: 다른 사용자의 리소스 ID로 직접 접근 시도 (`/api/users/123` → 타 사용자 ID)
- [ ] **수직적 권한 상승**: 일반 사용자 토큰으로 관리자 엔드포인트 접근 시도
- [ ] **HTTP 메서드 변조**: GET만 허용된 엔드포인트에 POST/PUT/DELETE 시도
- [ ] **경로 탐색**: `../` 시퀀스로 파일 시스템 접근 시도
- [ ] **JWT 조작**: `alg: none` 또는 서명 변조 후 재사용

```bash
# IDOR 빠른 검증 예시 (curl)
# 사용자 A 토큰으로 사용자 B 리소스 접근
curl -H "Authorization: Bearer ${USER_A_TOKEN}" \
  https://staging.example.com/api/users/${USER_B_ID}/profile
# 기대 응답: 403 Forbidden
```

### A02: Security Misconfiguration

- [ ] **HTTP 보안 헤더 검증**: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] **서버 정보 노출**: Server, X-Powered-By 헤더 제거 확인
- [ ] **디버그 엔드포인트**: `/actuator`, `/debug`, `/_debug`, `/phpinfo.php` 접근 차단 확인
- [ ] **디렉터리 목록**: 정적 파일 서버 디렉터리 목록 노출 여부
- [ ] **CORS 설정**: `Access-Control-Allow-Origin: *` 여부 및 자격 증명 포함 요청 처리

```bash
# 보안 헤더 일괄 검사
curl -I https://staging.example.com | grep -Ei \
  "strict-transport|content-security|x-frame|x-content-type|referrer-policy"
```

### A03: Supply Chain Failures

- [ ] **의존성 취약점 엔드포인트**: 알려진 취약 라이브러리가 노출하는 엔드포인트 접근 차단
- [ ] **업로드 파일 검증**: 악성 파일 업로드 후 실행 여부 (웹셸 업로드 시도)

### A04: Cryptographic Failures

- [ ] **TLS 버전**: TLS 1.0/1.1 비활성화 확인 (TLS 1.2+ 강제)
- [ ] **HTTP → HTTPS 리디렉션**: 모든 HTTP 요청이 HTTPS로 리디렉션되는지 확인
- [ ] **혼합 콘텐츠(Mixed Content)**: HTTPS 페이지에서 HTTP 리소스 로드 여부
- [ ] **민감 데이터 URL 노출**: 토큰, 비밀번호가 쿼리스트링에 포함되는지 확인

```bash
# SSL/TLS 설정 점검 (testssl.sh)
docker run --rm drwetter/testssl.sh \
  --severity HIGH \
  --quiet \
  https://staging.example.com
```

### A05: Injection

- [ ] **SQL Injection**: 파라미터에 `' OR 1=1--`, `'; DROP TABLE--` 삽입
- [ ] **OS Command Injection**: `; ls -la`, `| whoami`, `` `id` `` 시도
- [ ] **SSTI (서버 사이드 템플릿 인젝션)**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` 삽입
- [ ] **XXE**: XML 파싱 엔드포인트에 외부 엔티티 참조 삽입
- [ ] **반사형 XSS**: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`

### A07: Authentication Failures

- [ ] **무차별 대입(Brute Force)**: 로그인 엔드포인트 계정 잠금 정책 (5회 실패 시 잠금)
- [ ] **세션 고정(Session Fixation)**: 로그인 전/후 세션 ID 변경 확인
- [ ] **세션 만료**: 비활성 세션 자동 만료 및 로그아웃 후 토큰 무효화
- [ ] **비밀번호 재설정 토큰**: 단일 사용, 만료 시간(15분 이내), 예측 불가능성

### A09: Security Logging & Alerting Failures

- [ ] **에러 응답 정보 노출**: 500 에러에서 스택 트레이스, DB 쿼리, 내부 경로 노출 여부
- [ ] **인증 실패 로깅**: 잘못된 자격 증명 시도가 로그에 기록되는지 확인

---

## 결과 분석 및 대응 가이드

### ZAP 결과 심각도 분류

| 심각도 | 색상 | 대응 SLA | 예시 취약점 |
|--------|------|---------|-----------|
| Critical (High) | 빨강 | 즉시 (24시간 내) | SQL Injection, RCE, 인증 우회 |
| High | 주황 | 3일 내 | XSS, IDOR, 민감 데이터 노출 |
| Medium | 노랑 | 7일 내 | CSRF, 보안 헤더 누락, 정보 노출 |
| Low | 파랑 | 스프린트 내 | 쿠키 속성 누락, 캐시 설정 |
| Informational | 회색 | 백로그 | 서버 정보, 주석 내 민감 정보 |

CIS Controls v8 Control 16.13: 고위험 취약점은 72시간 내, 중간 위험은 30일 내 해결을 권장한다.

### 결과 리포트 파싱 자동화

```python
#!/usr/bin/env python3
# scripts/parse-zap-report.py
# ZAP JSON 리포트를 파싱하여 심각도별 요약 출력

import json
import sys
from collections import defaultdict

def parse_zap_report(report_path: str) -> dict:
    with open(report_path) as f:
        report = json.load(f)

    findings = defaultdict(list)
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert["riskdesc"].split(" ")[0]  # High, Medium, Low, Informational
            findings[risk].append({
                "name": alert["name"],
                "url": alert["instances"][0]["uri"] if alert.get("instances") else "N/A",
                "solution": alert.get("solution", ""),
            })

    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage: parse-zap-report.py <report.json>")
        sys.exit(1)

    findings = parse_zap_report(sys.argv[1])
    critical_count = len(findings.get("High", []))

    print(f"\n=== ZAP Scan Summary ===")
    for risk in ["High", "Medium", "Low", "Informational"]:
        items = findings.get(risk, [])
        print(f"{risk}: {len(items)} findings")
        for item in items[:3]:  # 상위 3개만 출력
            print(f"  - {item['name']} @ {item['url']}")

    if critical_count > 0:
        print(f"\n[FAIL] Critical/High 취약점 {critical_count}개 발견 — 즉시 조치 필요")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

```bash
# GitHub Actions에서 리포트 파싱 및 게이트 적용
- name: Parse ZAP Results
  run: python3 scripts/parse-zap-report.py report_json.json
```

### 취약점 유형별 대응 가이드

**SQL Injection 발견 시**

```sql
-- 취약한 코드 패턴
SELECT * FROM users WHERE id = '" + userId + "'

-- 수정: 파라미터화된 쿼리 사용
SELECT * FROM users WHERE id = $1
```

**XSS 발견 시**

```typescript
// 취약한 코드 패턴
element.innerHTML = userInput;

// 수정: 텍스트 노드 사용 또는 DOMPurify 적용
element.textContent = userInput;
// 또는 HTML이 필요한 경우
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

**보안 헤더 누락 발견 시 (nginx)**

```nginx
# nginx/security-headers.conf
add_header Content-Security-Policy
  "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
  always;
add_header Strict-Transport-Security
  "max-age=63072000; includeSubDomains; preload"
  always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy
  "camera=(), microphone=(), geolocation=(), payment=()"
  always;
server_tokens off;
```

### 재스캔 및 검증 프로세스

```text
취약점 발견
    │
    ▼
개발팀 티켓 생성 (GitHub Issue + security 라벨)
    │
    ▼
수정 구현 → PR 생성
    │
    ▼
ZAP Baseline Scan (PR 단계) — 동일 취약점 재발 확인
    │
    ├── 취약점 잔존 → PR 머지 차단
    │
    └── 취약점 해결 → 스테이징 배포 → Full Scan 재실행
                                              │
                                              └── 통과 → 프로덕션 배포
```

---

## DAST 성숙도 수준

NIST SP 800-53 SA-11 기반 조직 성숙도 단계:

| 수준 | 설명 | DAST 활동 |
|------|------|----------|
| Level 1 | 임시(Ad-hoc) | 수동 ZAP GUI 스캔, 비정기 실행 |
| Level 2 | 반복 가능 | CI/CD Baseline Scan, PR 게이트 |
| Level 3 | 정의됨 | Full Scan + API Scan, SARIF 연동, SLA 정의 |
| Level 4 | 관리됨 | 인증 스캔, 커버리지 측정, 트렌드 분석 |
| Level 5 | 최적화 | 자동 재스캔 검증, 취약점 인텔리전스 연동 |

---

## 참조

- [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP ZAP GitHub Actions](https://github.com/zaproxy/action-full-scan)
- [NIST SP 800-53 Rev. 5 — SA-11](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [CIS Controls v8 — Control 16](https://www.cisecurity.org/controls/v8)
- [OWASP Top 10:2025](https://owasp.org/Top10/)
- [DevSecOps Pipeline Guide](pipeline.md)
- [OWASP Top 10 2025 상세 가이드](owasp-top10-2025.md)
