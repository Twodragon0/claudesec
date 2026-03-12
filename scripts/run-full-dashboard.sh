#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Full scan + dashboard and serve on http://localhost:11777
# ============================================================================
# One-command run (oh-my-claudecode style). Default: all categories + serve.
#
# Usage:
#   ./scripts/run-full-dashboard.sh              # full scan + dashboard + serve
#   ./scripts/run-full-dashboard.sh --no-serve   # full scan + dashboard only
#   ./scripts/run-full-dashboard.sh --quick      # quick (3 categories) + serve
# ============================================================================

set -euo pipefail

CLAUDESEC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="$CLAUDESEC_DIR/scanner/claudesec"
SCANNER="${CLAUDESEC_SCANNER:-$SCANNER}"
SCAN_DIR="${CLAUDESEC_SCAN_DIR:-$CLAUDESEC_DIR}"

if [[ ! -x "$SCANNER" ]]; then
  chmod +x "$SCANNER" 2>/dev/null || true
fi

if [[ ! -f "$SCANNER" ]]; then
  echo "Error: scanner not found at $SCANNER" >&2
  exit 1
fi

cd "$CLAUDESEC_DIR"
export SCAN_DIR

MODE="full"
SERVE=1
HOST="127.0.0.1"
PORT="11777"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      MODE="quick"
      shift
      ;;
    --no-serve)
      SERVE=0
      shift
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage:
  ./scripts/run-full-dashboard.sh [options]

Options:
  --quick            Quick scan categories only (access-control,cicd,code)
  --no-serve         Generate dashboard only (no local server)
  --host <host>      Host for serving (default: 127.0.0.1)
  --port <port>      Port for serving (default: 11777)
  -h, --help         Show this help
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

cmd=("$SCANNER" dashboard -d "$SCAN_DIR")

if [[ "$MODE" == "quick" ]]; then
  cmd+=("-c" "access-control,cicd,code")
fi

if [[ "$SERVE" == "1" ]]; then
  cmd+=("--serve" "--host" "$HOST" "--port" "$PORT")
elif [[ "$MODE" != "quick" ]]; then
  cmd+=("--all")
fi

exec "${cmd[@]}"
