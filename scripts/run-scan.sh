#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Run scanner from repo root
# ============================================================================
# Usage:
#   ./scripts/run-scan.sh                    # full scan (current dir = repo root)
#   ./scripts/run-scan.sh -c access-control   # single category
#   ./scripts/run-scan.sh -c infra -c cicd -f json
#   ./scripts/run-scan.sh -c prowler --aws-profile myprofile
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
exec "$SCANNER" scan -d "${SCAN_DIR}" "$@"
