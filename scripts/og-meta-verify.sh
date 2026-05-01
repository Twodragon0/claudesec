#!/usr/bin/env bash
#
# og-meta-verify.sh — fetch the deployed page's OG/Twitter meta + image
# headers, format a markdown report, and sticky-comment it on a PR so
# contributors can see what KakaoTalk/FB/Slack will see *before* they
# request review.
#
# Usage (CI):
#   PR_NUMBER=42 PAGE_URL=https://twodragon0.github.io/claudesec/ \
#     IMAGE_URL=https://twodragon0.github.io/claudesec/assets/claudesec-og-card.png \
#     scripts/og-meta-verify.sh
#
# Usage (local sanity check, no comment):
#   PAGE_URL=https://twodragon0.github.io/claudesec/ \
#     IMAGE_URL=https://twodragon0.github.io/claudesec/assets/claudesec-og-card.png \
#     scripts/og-meta-verify.sh --no-comment
#
# Note: this verifies the **currently deployed** state, not the contents
# of the PR diff. KakaoTalk/FB read absolute URLs, so we have to point at
# the live origin. For unmerged changes, the report will reflect main
# until the PR merges and Pages redeploys.

set -euo pipefail

NO_COMMENT=0
if [[ "${1:-}" == "--no-comment" ]]; then
  NO_COMMENT=1
fi

PAGE_URL="${PAGE_URL:-https://twodragon0.github.io/claudesec/}"
IMAGE_URL="${IMAGE_URL:-https://twodragon0.github.io/claudesec/assets/claudesec-og-card.png}"
MARKER="<!-- og-meta-verify:v1 -->"

tmp_report="$(mktemp)"
trap 'rm -f "$tmp_report"' EXIT

# Image headers — keep status line, content-type, content-length
img_headers="$(curl -sI --max-time 10 "$IMAGE_URL" | head -10 | tr -d '\r')"
img_status="$(printf '%s\n' "$img_headers" | head -1)"

# Page meta tags — pull og:* and twitter:* lines
page_html="$(curl -s --max-time 15 "$PAGE_URL")"
og_meta="$(printf '%s\n' "$page_html" | grep -E 'og:|twitter:' | head -20 || true)"

# Detect the og:image URL the page actually advertises
advertised_image="$(printf '%s\n' "$og_meta" | grep -m1 'og:image"' | sed -E 's/.*content="([^"]+)".*/\1/' || true)"

# Status badges
img_ok="❌"
if printf '%s' "$img_status" | grep -q '200'; then
  img_ok="✅"
fi

advertised_match="❌"
if [[ -n "$advertised_image" && "$advertised_image" == "$IMAGE_URL" ]]; then
  advertised_match="✅"
elif [[ -n "$advertised_image" ]]; then
  advertised_match="⚠️ (deployed advertises a different URL — check if PR changes the og:image path)"
fi

cat > "$tmp_report" <<EOF
${MARKER}
## 🖼️ OG Meta Verification — KakaoTalk · Slack · Facebook · LinkedIn · X

Verifies the **currently deployed** \`${PAGE_URL}\` (Pages reflects \`main\`; this PR's edits land after merge).

### og:image reachability ${img_ok}

\`\`\`
${img_headers}
\`\`\`

- Expected URL: \`${IMAGE_URL}\`
- Page advertises: \`${advertised_image:-<not found>}\` ${advertised_match}

### Deployed page meta

\`\`\`html
${og_meta:-<no og: or twitter: meta found>}
\`\`\`

### After merge — refresh platform caches

| Platform | Tool |
|----------|------|
| KakaoTalk | <https://developers.kakao.com/tool/debugger/sharing> → URL → **초기화** |
| Facebook (+ Slack, LinkedIn) | <https://developers.facebook.com/tools/debug/> → URL → **Scrape Again** |
| Twitter/X | New tweet auto-recrawls (cards-dev.twitter.com retired) |

Reference: [docs/branding.md § SNS 링크 공유 미리보기](../docs/branding.md#sns-링크-공유-미리보기-kakaotalk--slack--facebook--linkedin--twitterx)
EOF

# Local mode: just print, do not comment
if [[ "$NO_COMMENT" -eq 1 ]]; then
  cat "$tmp_report"
  exit 0
fi

: "${PR_NUMBER:?PR_NUMBER env required (set by CI from github.event.pull_request.number)}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY env required}"
: "${GH_TOKEN:?GH_TOKEN env required (use \${{ secrets.GITHUB_TOKEN }} in CI)}"

# Sticky-comment: find prior bot comment by marker, edit it; otherwise create
existing_id="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
  --jq "[.[] | select(.body | startswith(\"${MARKER}\"))][0].id" 2>/dev/null || echo '')"

body="$(cat "$tmp_report")"

if [[ -n "$existing_id" && "$existing_id" != "null" ]]; then
  echo "Updating existing comment ${existing_id}…"
  gh api --method PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${existing_id}" \
    -f body="$body" >/dev/null
  echo "✅ Comment updated"
else
  echo "Creating new comment on PR #${PR_NUMBER}…"
  gh pr comment "${PR_NUMBER}" --repo "${GITHUB_REPOSITORY}" --body "$body" >/dev/null
  echo "✅ Comment posted"
fi
