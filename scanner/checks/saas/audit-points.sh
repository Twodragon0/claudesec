#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Audit Points scan (QueryPie)
# Detects products relevant to this project (Jenkins, Harbor, Nexus, etc.) and
# reports checklist items from https://github.com/querypie/audit-points for
# review. Results are written to .claudesec-audit-points/detected.json for the
# dashboard "Audit Points" tab (project-relevant checklist).
# ============================================================================

# Run audit-points scan: ensure cache, detect products, write detected.json
_audit_scan_json=""
if [[ -n "${LIB_DIR:-}" && -f "${LIB_DIR}/audit-points-scan.py" ]]; then
  _audit_scan_json=$(SCAN_DIR="$SCAN_DIR" python3 "$LIB_DIR/audit-points-scan.py" 2>/dev/null || true)
fi

if [[ -z "$_audit_scan_json" ]]; then
  skip "AUDIT-001" "Audit Points (QueryPie) scan" "Python or audit-points-scan.py not available"
  return 0 2>/dev/null || exit 0
fi

# Parse JSON output
_detected_list=""
_item_count="0"
if command -v python3 &>/dev/null; then
  _detected_list=$(echo "$_audit_scan_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('detected',[])))" 2>/dev/null || true)
  _item_count=$(echo "$_audit_scan_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('item_count',0))" 2>/dev/null || true)
fi

if [[ -z "$_detected_list" ]]; then
  pass "AUDIT-001" "Audit Points: no relevant products detected" \
    "No Jenkins/Harbor/Nexus/Okta/Scalr/IDEs indicators in this project; nothing to check against QueryPie audit points."
  return 0 2>/dev/null || exit 0
fi

_repo_url="https://github.com/querypie/audit-points"
pass "AUDIT-001" "Audit Points: $_detected_list ($_item_count checklist items)" \
  "Review checklist: $_repo_url — see dashboard Audit Points tab for links per product."
