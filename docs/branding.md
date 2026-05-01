---
title: ClaudeSec Branding
description: Logo, colors, and visual identity for ClaudeSec.
tags:
  - branding
  - logo
  - design
---

# ClaudeSec Branding

Visual identity and assets for the ClaudeSec project.

## Logo

| Asset | Path | Use |
|-------|------|-----|
| Primary logo (source) | [assets/claudesec-logo.png](../assets/claudesec-logo.png) | Source file, future exports |
| Optimized docs logo | [assets/claudesec-logo-512.png](../assets/claudesec-logo-512.png) | README/docs embedding |

- **Style**: Shield + lock motif, dark navy and cyan/teal accent.
- **Format**: PNG (source + optimized variant for docs usage).

## Colors

Aligned with the scanner dashboard and dark-first UI:

| Name | Hex | Use |
|------|-----|-----|
| Background | `#0f172a` | Primary background |
| Surface | `#1e293b` | Cards, panels |
| Border | `#334155` | Dividers, borders |
| Text | `#e2e8f0` | Primary text |
| Muted | `#94a3b8` | Secondary text, captions |
| **Accent** | `#38bdf8` | Links, highlights, CTA |

## Typography

- **Headers**: System UI stack (e.g. `-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif`).
- **Code**: Monospace for IDs, commands, and file paths.

## Usage

- Use the logo in README, docs, and official communications.
- Prefer dark backgrounds when showing the logo for contrast.
- Do not alter logo proportions or add unapproved effects.

## SNS 링크 공유 미리보기 (KakaoTalk · Slack · Facebook · LinkedIn · Twitter/X)

ClaudeSec의 공개 URL을 채팅·SNS에 붙여 넣을 때 large card 형식의 미리보기가 정상 노출되도록 메타태그·이미지·캐시 정책을 정리합니다. KakaoTalk과 Slack/FB/LinkedIn은 동일한 Open Graph 표준을 읽지만 캐시 동작이 서로 달라 별도 무효화 절차가 필요합니다.

### 메타태그 우선순위

크롤러(특히 KakaoTalk)는 `<head>` 상위 ~30KB만 파싱합니다. 따라서 다음 순서를 권장합니다:

1. `charset` / `viewport`
2. `<title>` + `<meta name="description">` — 텍스트 fallback
3. `<link rel="canonical">` — 중복 제거
4. **Open Graph 블록** — `og:type` / `og:site_name` / `og:locale`을 먼저, 이어 `og:url` / `og:title` / `og:description` / `og:image{,:secure_url,:type,:width,:height,:alt}`
5. **Twitter Card** — `twitter:card=summary_large_image` + `twitter:image` + `twitter:image:alt`
6. `theme-color`, favicon
7. CSP (`Content-Security-Policy`)는 가장 마지막 — 크롤러 파싱 순서에 영향을 주지 않도록

### og:image 요건

| 항목 | 값 |
|------|----|
| 절대 URL (필수) | `https://twodragon0.github.io/claudesec/assets/claudesec-logo.png` |
| 권장 크기 | 1200×630 (1.91:1 표준) — 현재 1376×768로 호환 가능 |
| 최소 크기 (KakaoTalk) | 200×200 (square) 또는 800×400 (rectangle) |
| 최대 파일 크기 | 5MB (KakaoTalk·Facebook 공통) |
| 포맷 | PNG / JPG (WebP는 KakaoTalk에서 미지원 사례 있음) |
| Pages 서빙 경로 | Jekyll safe mode가 `/docs/` 외부를 못 따라가므로 `docs/assets/` 안에 사본 필요 |

### Jekyll 사이트 기본값 (`docs/_config.yml`)

```yaml
locale: ko_KR
image:
  path: /assets/claudesec-logo.png
  height: 768
  width: 1376
  alt: ClaudeSec DevSecOps logo
twitter:
  card: summary_large_image
plugins:
  - jekyll-seo-tag
```

### 페이지별 오버라이드 (`docs/index.md` 프론트매터)

```yaml
---
title: ClaudeSec — DevSecOps 통합 보안 대시보드
description: 200자 이내 SNS 친화 카피
image:
  path: /assets/claudesec-logo.png
  width: 1376
  height: 768
  alt: 페이지별 alt
---
```

### 캐시 무효화 절차

OG 메타나 이미지를 변경한 뒤에는 각 SNS 캐시를 명시적으로 갱신해야 이미 공유한 URL의 미리보기가 새 내용으로 바뀝니다.

| 플랫폼 | 도구 | 절차 |
|--------|------|------|
| KakaoTalk | [Kakao 공유 디버거](https://developers.kakao.com/tool/debugger/sharing) | 카카오 로그인 → URL 입력 → **확인** → **초기화** 클릭 |
| Facebook · Slack · LinkedIn | [Facebook Sharing Debugger](https://developers.facebook.com/tools/debug/) | URL 입력 → **Scrape Again** 클릭 (Slack/LinkedIn은 FB OG 데이터를 신뢰) |
| Twitter/X | (자동 재크롤) | `cards-dev.twitter.com` 폐쇄됨 — 새 URL을 트윗하면 자동 갱신 |

### 검증 체크리스트

새 페이지 추가나 OG 메타 수정 후:

- [ ] `curl -I <og:image URL>` → `HTTP/2 200` + `content-type: image/png|jpeg`
- [ ] `curl -s <page URL> | grep -E '(og:|twitter:)' | head -20` 출력 검토
- [ ] Kakao 공유 디버거에서 large card 미리보기 정상 렌더 확인
- [ ] Facebook Sharing Debugger의 **Open Graph Object Debugger** 결과에 `og:image` 정상 등록
- [ ] (선택) 본인 KakaoTalk 채팅에 URL 전송 후 카드 시각 확인

### 자동 검증 (CI hook)

`docs/_config.yml`, `docs/index.md`, `docs/assets/claudesec-og-card.*`, `docs/assets/claudesec-logo*.png`, `claudesec-asset-dashboard.html`, `scanner/lib/dashboard-template.html` 중 하나라도 변경된 PR은 `OG Meta Verify` 워크플로우(`.github/workflows/og-meta-verify.yml`)가 자동 실행되어 PR 본문에 sticky 코멘트로 다음을 첨부합니다:

- `og:image` URL 200/404 + `content-type` 헤더
- 배포된 페이지의 `og:*` / `twitter:*` 메타 (현재 main 기준)
- 페이지가 광고하는 og:image URL이 기대값과 일치하는지 ✅/⚠️
- 머지 후 캐시 갱신 단축 링크 (KakaoTalk · Facebook 디버거)

⚠️ 이 검증은 **현재 배포된** Pages 상태를 대상으로 하므로, PR이 머지되어 Pages가 재배포되기 전까지는 PR diff 내용이 반영되지 않습니다. 코멘트가 그 점을 명시합니다.

로컬에서 동일 검증 실행:

```bash
PAGE_URL=https://twodragon0.github.io/claudesec/ \
IMAGE_URL=https://twodragon0.github.io/claudesec/assets/claudesec-og-card.png \
  ./scripts/og-meta-verify.sh --no-comment
```

### 참고

- Open Graph Protocol — <https://ogp.me/>
- Jekyll SEO Tag — <https://github.com/jekyll/jekyll-seo-tag/blob/master/docs/usage.md>
- KakaoTalk 공유 메시지 가이드 — <https://developers.kakao.com/docs/latest/ko/message/og-tag>

### 라이트 모드 OG 카드 (`claudesec-og-card-light`)

다크 카드와 동일한 레이아웃(좌 760px 텍스트 컬럼 / 우 440px 마스코트)·콘텐츠를 유지하면서 팔레트만 밝은 배경용으로 전환한 대체 에셋입니다. 기본 OG 이미지(다크 카드)를 교체하지 않으며, 라이트 테마 문서 페이지·프레젠테이션 슬라이드·라이트 스타일 랜딩 페이지에 수동으로 지정할 때만 사용합니다.

| 에셋 | 경로 |
|------|------|
| SVG (소스) | `docs/assets/claudesec-og-card-light.svg` |
| PNG (래스터, 1200×630) | `docs/assets/claudesec-og-card-light.png` |

**라이트 팔레트 요약**

| 역할 | 다크 카드 | 라이트 카드 |
|------|-----------|------------|
| 배경 | `#0f172a` (slate-900) | `#f8fafc` (slate-50) |
| 서피스 / 마스코트 채우기 | `#1e293b` (slate-800) | `#ffffff` |
| 테두리 / 구분선 | `#334155` (slate-700) | `#e2e8f0` (slate-200) |
| 기본 텍스트 | `#e2e8f0` (slate-200) | `#0f172a` (slate-900) |
| 보조 텍스트 | `#94a3b8` (slate-400) | `#64748b` (slate-500) |
| 액센트 ("Sec", 밑줄, URL) | `#38bdf8` (sky-400) | `#0284c7` (sky-600) |

라이트 배경에서는 sky-400보다 sky-600이 명도 대비(WCAG)를 더 잘 충족하므로 액센트 색상을 한 단계 진하게 적용했습니다.

**사용 시점**

- 흰 배경 Docs 페이지에 삽입하는 인라인 이미지
- 흰 슬라이드 덱에 포함하는 미리보기 카드
- 라이트 스타일 랜딩 페이지에서 `front matter`로 OG 이미지를 수동 지정하는 경우

**Jekyll 프론트매터 페이지별 오버라이드**

라이트 카드를 특정 페이지의 OG 이미지로 지정하려면 해당 페이지의 프론트매터에 다음을 추가합니다.

```yaml
---
image:
  path: /assets/claudesec-og-card-light.png
  width: 1200
  height: 630
  alt: ClaudeSec DevSecOps 라이트 모드 OG 카드
---
```

**주의 — SNS 크롤러는 사용자 테마를 인식하지 않습니다**

KakaoTalk·Facebook·Twitter/X 등 SNS 크롤러는 `og:image`를 한 번만 수집하고 캐시합니다. 사용자 기기의 다크/라이트 모드와 무관하게 동일한 이미지를 모든 이에게 노출합니다. 전역 기본값은 다크 카드(`docs/_config.yml` → `image.path`)로 유지하고, 라이트 카드는 페이지별 수동 오버라이드로만 사용하세요.
