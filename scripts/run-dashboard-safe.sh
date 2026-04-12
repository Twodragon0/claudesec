#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="${CLAUDESEC_SCANNER:-$ROOT_DIR/scanner/claudesec}"
DOCKER_SCRIPT="${CLAUDESEC_DOCKER_DASHBOARD_SCRIPT:-$ROOT_DIR/scripts/run-dashboard-docker.sh}"
SCAN_DIR="${CLAUDESEC_SCAN_DIR:-$ROOT_DIR}"

MODE="full"
HOST="127.0.0.1"
PORT="11777"
FALLBACK_MAX="20"
KILL_PORT=0
REUSE_EXISTING=0
DOCKER_MODE=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-dashboard-safe.sh [options]

Options:
  --quick            Quick scan categories only (access-control,cicd,code)
  --no-serve         Generate dashboard only (no local server)
  --docker           Run dashboard workflow in Docker
  --host <host>      Host for serving (default: 127.0.0.1)
  --port <port>      Preferred serve port (default: 11777)
  --kill-port        Kill process occupying target port before start
  --reuse-existing   If target port is in use, reuse existing endpoint and exit 0
  --fallback-max <n> Number of fallback ports to probe (default: 20)
  -h, --help         Show this help

Examples:
  ./scripts/run-dashboard-safe.sh
  ./scripts/run-dashboard-safe.sh --quick
  ./scripts/run-dashboard-safe.sh --kill-port
  ./scripts/run-dashboard-safe.sh --port 11777 --fallback-max 50
EOF
}

port_pids() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null || true
}

port_bindable() {
  local host="$1"
  local port="$2"
  local py_bin=""

  if command -v python3 >/dev/null 2>&1; then
    py_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    py_bin="python"
  else
    return 0
  fi

  "$py_bin" - "$host" "$port" <<'PY' 2>/dev/null
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind((host, port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
raise SystemExit(0)
PY
}

dashboard_reachable() {
  local host="$1"
  local port="$2"
  local py_bin=""

  if command -v python3 >/dev/null 2>&1; then
    py_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    py_bin="python"
  else
    return 1
  fi

  "$py_bin" - "$host" "$port" <<'PY' 2>/dev/null
import sys
import urllib.request

host = sys.argv[1]
port = sys.argv[2]
urls = [
    f"http://{host}:{port}/claudesec-dashboard.html",
    f"http://{host}:{port}/",
]

for url in urls:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "claudesec/run-dashboard-safe"})
        with urllib.request.urlopen(req, timeout=2) as response:
            body = response.read(4096).decode("utf-8", errors="ignore").lower()
            if response.status < 400 and ("claudesec" in body or "dashboard" in body):
                raise SystemExit(0)
    except Exception:
        continue

raise SystemExit(1)
PY
}

port_in_use() {
  local port="$1"
  [[ -n "$(port_pids "$port")" ]] && return 0
  ! port_bindable "$HOST" "$port"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE="quick"; shift ;;
    --no-serve) MODE="no-serve"; shift ;;
    --docker) DOCKER_MODE=1; shift ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --kill-port) KILL_PORT=1; shift ;;
    --reuse-existing) REUSE_EXISTING=1; shift ;;
    --fallback-max) FALLBACK_MAX="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$DOCKER_MODE" == "1" ]]; then
  if [[ ! -f "$DOCKER_SCRIPT" ]]; then
    echo "Error: docker dashboard script not found at $DOCKER_SCRIPT" >&2
    exit 1
  fi
  docker_args=()
  if [[ "$MODE" == "quick" ]]; then
    docker_args+=("--quick")
  elif [[ "$MODE" == "no-serve" ]]; then
    docker_args+=("--no-serve")
  fi
  docker_args+=("--host" "$HOST" "--port" "$PORT")
  exec "$DOCKER_SCRIPT" "${docker_args[@]}"
fi

if [[ ! -x "$SCANNER" ]]; then
  chmod +x "$SCANNER" 2>/dev/null || true
fi

if [[ ! -f "$SCANNER" ]]; then
  echo "Error: scanner not found at $SCANNER" >&2
  exit 1
fi

cd "$ROOT_DIR"

if [[ "$MODE" == "no-serve" ]]; then
  exec "$SCANNER" dashboard -d "$SCAN_DIR" --all
fi

TARGET_PORT="$PORT"
if port_in_use "$TARGET_PORT"; then
  if [[ "$REUSE_EXISTING" == "1" ]]; then
    if dashboard_reachable "$HOST" "$TARGET_PORT"; then
      echo "[claudesec] Reusing existing dashboard endpoint: http://$HOST:$TARGET_PORT/claudesec-dashboard.html"
      exit 0
    fi
  fi

  if [[ "$KILL_PORT" == "1" ]]; then
    PIDS="$(port_pids "$TARGET_PORT")"
    if [[ -n "$PIDS" ]]; then
      echo "[claudesec] Terminating process(es) on port $TARGET_PORT: $PIDS"
      for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
      done
      sleep 1
    fi
  fi

  if port_in_use "$TARGET_PORT"; then
    found=0
    for ((i = 1; i <= FALLBACK_MAX; i++)); do
      candidate=$((PORT + i))
      if ! port_in_use "$candidate"; then
        TARGET_PORT="$candidate"
        found=1
        echo "[claudesec] Port $PORT busy; using fallback port $TARGET_PORT"
        break
      fi
    done
    if [[ "$found" == "0" ]]; then
      echo "[claudesec] Failed to find available port in range $PORT-$((PORT + FALLBACK_MAX))" >&2
      exit 1
    fi
  fi
fi

if [[ "$MODE" == "quick" ]]; then
  exec "$SCANNER" dashboard -d "$SCAN_DIR" -c access-control,cicd,code --serve --host "$HOST" --port "$TARGET_PORT"
fi

exec "$SCANNER" dashboard -d "$SCAN_DIR" --serve --host "$HOST" --port "$TARGET_PORT"
