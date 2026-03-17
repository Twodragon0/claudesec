#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Google Sheets 자산관리 연동 실행 스크립트
#
# 사용법:
#   ./scripts/run-asset-sync.sh                    # 통합 리포트 (기본)
#   ./scripts/run-asset-sync.sh read               # 시트 구조 읽기
#   ./scripts/run-asset-sync.sh sync               # 스캔 결과 동기화
#   ./scripts/run-asset-sync.sh report             # 통합 리포트 생성
#   ./scripts/run-asset-sync.sh --docker sync      # Docker로 실행
#   ./scripts/run-asset-sync.sh --scan-first sync  # 스캔 후 동기화
#
# 환경변수:
#   ASSET_SHEET_ID                 — Google Sheets ID (기본: vuddy.io 자산관리)
#   GOOGLE_SERVICE_ACCOUNT_JSON    — 서비스 계정 JSON 경로
# ============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SHEET_ID="${ASSET_SHEET_ID:-YOUR_SHEET_ID}"
ACTION="report"
USE_DOCKER=0
SCAN_FIRST=0

usage() {
  cat <<'EOF'
Usage: ./scripts/run-asset-sync.sh [options] [action]

Actions:
  read      Google Sheets에서 자산 목록 읽기
  sync      ClaudeSec 스캔 결과를 시트에 동기화
  report    자산 현황 + 보안 스캔 통합 리포트 (기본)

Options:
  --docker        Docker 컨테이너에서 실행
  --scan-first    스캔을 먼저 실행한 후 동기화
  --sheet-id ID   Google Sheets ID 지정
  -h, --help      도움말
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker)     USE_DOCKER=1; shift ;;
    --scan-first) SCAN_FIRST=1; shift ;;
    --sheet-id)   SHEET_ID="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    read|sync|report) ACTION="$1"; shift ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ClaudeSec 자산관리 연동"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  시트 ID: ${SHEET_ID:0:20}..."
echo "  작업: $ACTION"
echo "  Docker: $USE_DOCKER"
echo ""

# 스캔 먼저 실행 (옵션)
if [[ "$SCAN_FIRST" == "1" ]]; then
  echo "▶ ClaudeSec 스캔 실행 중..."
  if [[ "$USE_DOCKER" == "1" ]]; then
    cd "$ROOT_DIR" && docker compose --profile scan up scanner
  else
    "$ROOT_DIR/scanner/claudesec" scan -d "$ROOT_DIR" -c all
  fi
  echo ""
fi

# 자산 연동 실행
if [[ "$USE_DOCKER" == "1" ]]; then
  echo "▶ Docker로 자산 연동 실행 중..."
  cd "$ROOT_DIR"
  ASSET_SHEET_ID="$SHEET_ID" ASSET_ACTION="$ACTION" \
    docker compose --profile asset-sync up asset-sync
else
  echo "▶ 로컬에서 자산 연동 실행 중..."

  # Python 의존성 확인
  if ! python3 -c "import gspread" 2>/dev/null; then
    echo "  gspread 패키지 설치 중..."
    pip3 install --quiet gspread google-auth google-auth-oauthlib
  fi

  python3 "$ROOT_DIR/scripts/asset-gsheet-sync.py" \
    --sheet-id "$SHEET_ID" \
    --action "$ACTION" \
    --scan-dir "$ROOT_DIR"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  완료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 리포트 생성 시 결과 파일 안내
if [[ "$ACTION" == "report" ]]; then
  REPORT_FILE="$ROOT_DIR/.claudesec-assets/asset-summary.json"
  if [[ -f "$REPORT_FILE" ]]; then
    echo ""
    echo "  리포트 파일: $REPORT_FILE"
    echo "  대시보드에서 확인: http://localhost:11777"
  fi
fi
