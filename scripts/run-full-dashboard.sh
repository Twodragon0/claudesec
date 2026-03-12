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

set -uo pipefail

CLAUDESEC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="$CLAUDESEC_DIR/scanner/claudesec"
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

case "${1:-}" in
  --no-serve)
    exec "$SCANNER" dashboard -d "$SCAN_DIR" --all
    ;;
  --quick)
    # Quick: 3 categories only, then serve (faster for try-out)
    exec "$SCANNER" dashboard -d "$SCAN_DIR" -c access-control,cicd,code --serve
    ;;
  *)
    # Full: all categories + serve
    exec "$SCANNER" dashboard -d "$SCAN_DIR" --serve
    ;;
esac
