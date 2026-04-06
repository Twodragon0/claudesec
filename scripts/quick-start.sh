#!/usr/bin/env bash
# ============================================================================
# ClaudeSec Quick Start — 원커맨드 대시보드 실행
#
# 사용법:
#   ./scripts/quick-start.sh                # 스캔 + 대시보드 서빙
#   ./scripts/quick-start.sh --scan-only    # 스캔만 실행
#   ./scripts/quick-start.sh --serve        # 기존/신규 대시보드 서빙
#   ./scripts/quick-start.sh --docker-only  # Docker 강제 (미실행 시 에러)
#
# 동작:
#   - 기본: Docker 우선 실행
#   - Docker 미설치/미실행: 로컬 스캐너 경로로 자동 폴백
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${BLUE}▶${NC} $1"; }
ok()  { echo -e "${GREEN}✓${NC} $1"; }
warn(){ echo -e "${YELLOW}⚠${NC} $1"; }
err() { echo -e "${RED}✗${NC} $1"; exit 1; }

MODE="${1:-full}"
DOCKER_ONLY=0
PORT="${CLAUDESEC_PORT:-11777}"
SAFE_SCRIPT="$ROOT_DIR/scripts/run-dashboard-safe.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ClaudeSec Quick Start"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "$MODE" = "--docker-only" ]; then
  DOCKER_ONLY=1
  MODE="full"
fi

if [ ! -x "$SAFE_SCRIPT" ]; then
  err "필수 스크립트를 찾을 수 없습니다: $SAFE_SCRIPT"
fi

safe_args=()
case "$MODE" in
  "--scan-only")
    safe_args+=("--no-serve")
    ;;
  "--serve"|full)
    ;;
  *)
    err "알 수 없는 옵션입니다: $MODE (지원: --scan-only, --serve, --docker-only)"
    ;;
esac

docker_ready=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker_ready=1
fi

if [ "$docker_ready" -ne 1 ]; then
  if [ "$DOCKER_ONLY" -eq 1 ]; then
    err "Docker 강제 모드입니다. Docker Desktop 실행 후 다시 시도하세요."
  fi

  warn "Docker를 사용할 수 없어 로컬 모드로 전환합니다."
  exec "$SAFE_SCRIPT" "${safe_args[@]}" --host 127.0.0.1 --port "$PORT"
fi
ok "Docker 확인"

# ── Build images if needed ───────────────────────────────────────────
log "Docker 이미지 확인..."
if ! docker image inspect claudesec:local >/dev/null 2>&1; then
  log "claudesec:local 빌드 중... (최초 1회, ~2분)"
  docker build -t claudesec:local . 2>&1 | tail -3
fi
ok "claudesec:local 준비"

if [ -f "Dockerfile.nginx" ] && ! docker image inspect claudesec-dashboard:local >/dev/null 2>&1; then
  log "nginx 대시보드 이미지 빌드..."
  docker build -f Dockerfile.nginx -t claudesec-dashboard:local . 2>&1 | tail -3
fi
ok "대시보드 이미지 준비"

# ── Scan ─────────────────────────────────────────────────────────────
if [ "$MODE" != "--serve" ]; then
  log "보안 스캔 실행 중..."
  docker run --rm \
    -v "$(pwd):/workspace" -w /workspace \
    -e SCAN_DIR=/workspace \
    claudesec:local scan -d /workspace -c all 2>&1 | tail -10
  ok "스캔 완료"

  log "대시보드 생성 중..."
  docker run --rm \
    -v "$(pwd):/workspace" -w /workspace \
    -e SCAN_DIR=/workspace \
    claudesec:local dashboard -d /workspace -c all --no-serve 2>&1 | tail -5
  ok "scan.html 생성 완료"

  if [ "$MODE" = "--scan-only" ]; then
    echo ""
    ok "스캔 완료. 결과: claudesec-dashboard.html"
    echo "  open claudesec-dashboard.html"
    exit 0
  fi
fi

# ── Serve ────────────────────────────────────────────────────────────
log "대시보드 서빙 시작 (port $PORT)..."

# Stop existing container if running
docker compose down 2>/dev/null || docker stop claudesec-dashboard 2>/dev/null || true

if [ -f "docker-compose.yml" ]; then
  docker compose up dashboard -d 2>&1 | tail -3
else
  # Fallback: direct nginx run
  docker run -d --rm --name claudesec-dashboard \
    -p "$PORT:8080" \
    -v "$(pwd)/claudesec-dashboard.html:/usr/share/nginx/html/scan.html:ro" \
    claudesec-dashboard:local 2>/dev/null || \
  docker run -d --rm --name claudesec-dashboard \
    -p "$PORT:8080" \
    nginx:alpine 2>/dev/null
fi

# Wait for server
sleep 2
if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/" | grep -q "200"; then
  ok "대시보드 서빙 중"
else
  warn "서버 시작 대기 중..."
  sleep 3
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  대시보드 준비 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  자산관리 대시보드: http://localhost:$PORT/"
echo "  스캔 대시보드:     http://localhost:$PORT/scan.html"
echo ""
echo "  중지: docker compose down"
echo ""

# Auto-open browser
if command -v open >/dev/null 2>&1; then
  open "http://localhost:$PORT/"
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:$PORT/"
fi
