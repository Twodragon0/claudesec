#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Scan + Dashboard Sync Pipeline
# ============================================================================
# Runs ClaudeSec scan, updates scan-report.json, then rebuilds
# dashboard-data.json and regenerates the HTML dashboard.
#
# Usage:
#   ./scripts/sync-scan-to-dashboard.sh           # full pipeline
#   ./scripts/sync-scan-to-dashboard.sh --skip-scan  # rebuild dashboard only
# ============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCANNER="$ROOT/scanner/claudesec"
SCAN_REPORT="$ROOT/scan-report.json"
DASHBOARD_HTML="$ROOT/claudesec-dashboard.html"
BUILD_SCRIPT="$ROOT/scripts/build-dashboard.py"
DASHGEN_SCRIPT="$ROOT/scanner/lib/dashboard-gen.py"

echo "=== ClaudeSec Scan → Dashboard Sync ==="
echo "  Root: $ROOT"
echo ""

# Step 1: Run scan (unless --skip-scan)
if [[ "${1:-}" != "--skip-scan" ]]; then
  echo "[1/3] Running ClaudeSec scan..."
  # Run scan in text mode (for console output) and capture JSON separately
  bash "$SCANNER" scan -d "$ROOT" 2>&1 || true
  echo ""
  # Generate JSON report (scanner may include ANSI codes; clean and normalize)
  bash "$SCANNER" scan -d "$ROOT" -f json 2>/dev/null | sed -n '/^{$/,/^}$/p' | \
    python3 -c "
import json,sys,re
raw = sys.stdin.read()
clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
d = json.loads(clean, strict=False)
d['score'] = d['summary']['score']
d['grade'] = d['summary']['grade']
for k in ('passed','failed','warnings','skipped','total'):
    d[k] = d['summary'][k]
d['duration'] = d.get('duration_seconds', 0)
d['findings'] = d.pop('results', [])
json.dump(d, open('$SCAN_REPORT', 'w'), indent=2, ensure_ascii=False)
print('  ✓ scan-report.json updated — score:', d['score'], 'grade:', d['grade'])
" || echo "  ⚠ JSON parse failed, keeping existing scan-report.json"
else
  echo "[1/3] Skipping scan (--skip-scan)"
fi

# Step 2: Rebuild dashboard-data.json (for main dashboard)
echo ""
echo "[2/3] Rebuilding dashboard-data.json..."
if [[ -f "$BUILD_SCRIPT" ]]; then
  python3 "$BUILD_SCRIPT" 2>&1 | tail -3
  echo "  ✓ dashboard-data.json updated"
else
  echo "  ⚠ build-dashboard.py not found, skipping"
fi

# Step 3: Regenerate scan.html dashboard
echo ""
echo "[3/3] Regenerating scan dashboard HTML..."
if [[ -f "$SCAN_REPORT" ]]; then
  CLAUDESEC_SCAN_JSON="$SCAN_REPORT" \
  CLAUDESEC_DASHBOARD_OFFLINE="${CLAUDESEC_DASHBOARD_OFFLINE:-0}" \
  python3 "$DASHGEN_SCRIPT" "$DASHBOARD_HTML" 2>&1 | tail -3
  echo "  ✓ $DASHBOARD_HTML regenerated"
else
  echo "  ⚠ scan-report.json not found, skipping HTML generation"
fi

# Step 4: Reload nginx if running in Docker
echo ""
echo "[4/4] Reloading dashboard nginx..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'claudesec-dashboard'; then
  docker exec "$(docker ps --filter name=claudesec-dashboard --format '{{.Names}}' | head -1)" nginx -s reload 2>/dev/null \
    && echo "  ✓ nginx reloaded" \
    || echo "  ⚠ nginx reload failed (container may not support reload)"
else
  echo "  ⚠ claudesec-dashboard container not running, skipping reload"
fi

echo ""
echo "=== Sync complete ==="
echo "  Main dashboard: http://localhost:11777/"
echo "  Scan dashboard: http://localhost:11777/scan.html"
