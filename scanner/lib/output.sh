#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Output formatting library
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# JSON results array
JSON_RESULTS="[]"

# Findings tracking for dashboard
declare -a FINDINGS_CRITICAL=()
declare -a FINDINGS_HIGH=()
declare -a FINDINGS_MEDIUM=()
declare -a FINDINGS_LOW=()
declare -a FINDINGS_WARN=()

print_banner() {
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}ClaudeSec Scanner${NC} v${VERSION}                              ${BOLD}${CYAN}║${NC}"
  echo -e "${BOLD}${CYAN}║${NC}  AI Security Best Practices Scanner                     ${BOLD}${CYAN}║${NC}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "  ${DIM}Scan directory: ${SCAN_DIR}${NC}"
  echo -e "  ${DIM}Categories:     ${CATEGORY}${NC}"
  echo -e "  ${DIM}Severity:       ${SEVERITY}${NC}"
  echo ""
}

section() {
  local title="$1"
  echo ""
  echo -e "${BOLD}${BLUE}━━━ $title ━━━${NC}"
  echo ""
}

category_label() {
  case "$1" in
    infra)          echo "Infrastructure Security" ;;
    ai)             echo "AI / LLM Security" ;;
    network)        echo "Network Security" ;;
    cloud)          echo "Cloud Security (AWS/GCP/Azure)" ;;
    access-control) echo "Access Control & IAM" ;;
    cicd)           echo "CI/CD Pipeline Security" ;;
    code)           echo "Code Vulnerability Analysis (SAST)" ;;
    macos)          echo "macOS / CIS Benchmark Security" ;;
    saas)           echo "SaaS & Solutions Security" ;;
    windows)        echo "Windows Security (KISA)" ;;
    prowler)        echo "Prowler Deep Scan (Multi-Cloud)" ;;
    *)              echo "$1" ;;
  esac
}

# Result functions
pass() {
  local id="$1" title="$2" details="${3:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  PASSED=$((PASSED + 1))

  if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
    echo -e "  ${GREEN}✓ PASS${NC}  ${DIM}[$id]${NC} $title"
    [[ -n "$details" ]] && echo -e "         ${DIM}$details${NC}"
  fi
  append_json "$id" "$title" "pass" "$details" ""
}

fail() {
  local id="$1" title="$2" severity="${3:-high}" details="${4:-}" remediation="${5:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FAILED=$((FAILED + 1))

  local entry="$id|$title|$severity|$remediation|$details"
  case "$severity" in
    critical) FINDINGS_CRITICAL+=("$entry") ;;
    high)     FINDINGS_HIGH+=("$entry") ;;
    medium)   FINDINGS_MEDIUM+=("$entry") ;;
    low)      FINDINGS_LOW+=("$entry") ;;
  esac

  if should_report "$severity"; then
    if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
      local color="$RED"
      [[ "$severity" == "medium" ]] && color="$YELLOW"
      [[ "$severity" == "low" ]] && color="$DIM"
      echo -e "  ${color}✗ FAIL${NC}  ${DIM}[$id]${NC} $title ${DIM}(${severity})${NC}"
      [[ -n "$details" ]] && echo -e "         ${DIM}$details${NC}"
      [[ -n "$remediation" ]] && echo -e "         ${CYAN}→ $remediation${NC}"
    fi
  fi
  append_json "$id" "$title" "fail" "$details" "$severity"
}

warn() {
  local id="$1" title="$2" details="${3:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  WARNINGS=$((WARNINGS + 1))

  FINDINGS_WARN+=("$id|$title|medium||$details")

  if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
    echo -e "  ${YELLOW}⚠ WARN${NC}  ${DIM}[$id]${NC} $title"
    [[ -n "$details" ]] && echo -e "         ${DIM}$details${NC}"
  fi
  append_json "$id" "$title" "warning" "$details" "medium"
}

skip() {
  local id="$1" title="$2" reason="${3:-Not applicable}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  SKIPPED=$((SKIPPED + 1))

  if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
    echo -e "  ${DIM}○ SKIP  [$id] $title — $reason${NC}"
  fi
}

info() {
  [[ "$FORMAT" == "text" ]] && echo -e "  ${BLUE}ℹ${NC} $1"
}

success() {
  echo -e "  ${GREEN}✓${NC} $1"
}

warning() {
  echo -e "  ${YELLOW}⚠${NC} $1"
}

error() {
  echo -e "  ${RED}✗${NC} $1" >&2
}

should_report() {
  local severity="$1"
  [[ "$SEVERITY" == "all" ]] && return 0
  case "$SEVERITY" in
    critical) [[ "$severity" == "critical" ]] ;;
    high) [[ "$severity" == "critical" || "$severity" == "high" ]] ;;
    medium) [[ "$severity" != "low" ]] ;;
    low) return 0 ;;
  esac
}

html_escape() {
  local s="$1"
  s="${s//&/\&amp;}"
  s="${s//</\&lt;}"
  s="${s//>/\&gt;}"
  s="${s//\"/\&quot;}"
  echo "$s"
}

append_json() {
  local id="$1" title="$2" status="$3" details="$4" severity="${5:-}"
  # Escape JSON strings
  title="${title//\\/\\\\}"; title="${title//\"/\\\"}"
  details="${details//\\/\\\\}"; details="${details//\"/\\\"}"
  local entry="{\"id\":\"$id\",\"status\":\"$status\",\"title\":\"$title\""
  [[ -n "$severity" ]] && entry+=",\"severity\":\"$severity\""
  [[ -n "$details" ]] && entry+=",\"details\":\"$details\""
  entry+="}"
  if [[ "$JSON_RESULTS" == "[]" ]]; then
    JSON_RESULTS="[$entry]"
  else
    JSON_RESULTS="${JSON_RESULTS%]},${entry}]"
  fi
}

_print_findings() {
  local -n arr=$1
  local label="$2" show_fix="${3:-true}"
  for entry in "${arr[@]+"${arr[@]}"}"; do
    IFS='|' read -r f_id f_title _ f_fix <<< "$entry"
    echo -e "  ${label}${NC}  ${DIM}[$f_id]${NC} $f_title"
    [[ "$show_fix" == "true" && -n "$f_fix" ]] && echo -e "          ${CYAN}→ $f_fix${NC}"
  done
}

print_summary() {
  local duration="$1"

  # Calculate score (skip doesn't count)
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  if [[ $active -gt 0 ]]; then
    score=$(( (PASSED * 100) / active ))
  fi

  local grade_color="$RED" grade="F"
  if [[ $score -ge 90 ]]; then grade="A"; grade_color="$GREEN"
  elif [[ $score -ge 80 ]]; then grade="B"; grade_color="$GREEN"
  elif [[ $score -ge 70 ]]; then grade="C"; grade_color="$YELLOW"
  elif [[ $score -ge 60 ]]; then grade="D"; grade_color="$YELLOW"
  fi

  echo ""
  echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║                   SCAN DASHBOARD                        ║${NC}"
  echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Score + progress bar
  local bar_width=30
  local filled=$(( (score * bar_width) / 100 ))
  local empty=$((bar_width - filled))
  local bar=""
  for ((i=0; i<filled; i++)); do bar+="█"; done
  for ((i=0; i<empty; i++)); do bar+="░"; done

  echo -e "  ${BOLD}Security Score${NC}  ${grade_color}${BOLD}${score}${NC}/100  ${grade_color}${bar}${NC}  Grade: ${grade_color}${BOLD}${grade}${NC}"
  echo ""

  # Stats row
  printf "  ${GREEN}● Passed${NC} %-6s" "$PASSED"
  printf "${RED}● Failed${NC} %-6s" "$FAILED"
  printf "${YELLOW}● Warn${NC} %-6s" "$WARNINGS"
  printf "${DIM}○ Skip${NC} %-6s" "$SKIPPED"
  printf "${DIM}Total${NC} %s\n" "$TOTAL_CHECKS"
  echo ""

  # Severity breakdown
  local n_crit=${#FINDINGS_CRITICAL[@]}
  local n_high=${#FINDINGS_HIGH[@]}
  local n_med=${#FINDINGS_MEDIUM[@]}
  local n_low=${#FINDINGS_LOW[@]}
  local n_warn=${#FINDINGS_WARN[@]}

  if [[ $((n_crit + n_high + n_med + n_low + n_warn)) -gt 0 ]]; then
    echo -e "  ${BOLD}Severity Breakdown${NC}"
    echo -e "  ──────────────────────────────────────────────────────"
    [[ $n_crit -gt 0 ]] && echo -e "  ${RED}${BOLD}  CRITICAL  ${n_crit}${NC}  ████  Immediate action required"
    [[ $n_high -gt 0 ]] && echo -e "  ${RED}  HIGH      ${n_high}${NC}  ███░  Fix before next release"
    [[ $n_med -gt 0 ]]  && echo -e "  ${YELLOW}  MEDIUM    ${n_med}${NC}  ██░░  Plan to address"
    [[ $n_low -gt 0 ]]  && echo -e "  ${DIM}  LOW       ${n_low}${NC}  █░░░  Consider fixing"
    [[ $n_warn -gt 0 ]] && echo -e "  ${YELLOW}  WARNING   ${n_warn}${NC}  ░░░░  Best practice recommendations"
    echo ""

    # Findings table — Critical and High first
    if [[ $((n_crit + n_high)) -gt 0 ]]; then
      echo -e "  ${RED}${BOLD}▸ Action Required${NC}"
      echo -e "  ──────────────────────────────────────────────────────"
      _print_findings FINDINGS_CRITICAL "${RED}${BOLD}■ CRIT" true
      _print_findings FINDINGS_HIGH "${RED}■ HIGH" true
      echo ""
    fi

    # Medium findings
    if [[ $n_med -gt 0 ]]; then
      echo -e "  ${YELLOW}${BOLD}▸ Recommended Fixes${NC}"
      echo -e "  ──────────────────────────────────────────────────────"
      _print_findings FINDINGS_MEDIUM "${YELLOW}▪ MED " false
      echo ""
    fi

    # Warnings (collapsed)
    if [[ $n_warn -gt 0 ]]; then
      echo -e "  ${DIM}${BOLD}▸ Warnings (${n_warn})${NC}"
      echo -e "  ──────────────────────────────────────────────────────"
      _print_findings FINDINGS_WARN "${DIM}▫ WARN" false
      echo ""
    fi
  fi

  local duration_str
  if [[ $duration -ge 60 ]]; then
    duration_str="$((duration / 60))m $((duration % 60))s"
  else
    duration_str="${duration}s"
  fi
  echo -e "  ${DIM}Scanned in ${duration_str} · $(date '+%Y-%m-%d %H:%M:%S') · claudesec v${VERSION}${NC}"
  echo ""
}

print_json_summary() {
  local duration="$1"
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))
  cat <<EOF
{
  "version": "$VERSION",
  "scan_directory": "$SCAN_DIR",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $duration,
  "summary": {
    "total": $TOTAL_CHECKS,
    "passed": $PASSED,
    "failed": $FAILED,
    "warnings": $WARNINGS,
    "skipped": $SKIPPED,
    "score": $score,
    "grade": "$(if [[ $score -ge 90 ]]; then echo A; elif [[ $score -ge 80 ]]; then echo B; elif [[ $score -ge 70 ]]; then echo C; elif [[ $score -ge 60 ]]; then echo D; else echo F; fi)"
  },
  "results": $JSON_RESULTS
}
EOF
}

# ── Scan History ─────────────────────────────────────────────────────────────

HISTORY_MAX=30

# Save current scan result to history
save_scan_history() {
  local HISTORY_DIR="${SCAN_DIR:-.}/.claudesec-history"
  mkdir -p "$HISTORY_DIR" 2>/dev/null || return 0
  local ts
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))
  local n_crit=${#FINDINGS_CRITICAL[@]}
  local n_high=${#FINDINGS_HIGH[@]}
  local n_med=${#FINDINGS_MEDIUM[@]}
  local n_low=${#FINDINGS_LOW[@]}
  local n_warn=${#FINDINGS_WARN[@]}

  cat > "${HISTORY_DIR}/scan-${ts}.json" <<HIST_EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","score":${score},"passed":${PASSED},"failed":${FAILED},"warnings":${WARNINGS},"skipped":${SKIPPED},"total":${TOTAL_CHECKS},"critical":${n_crit},"high":${n_high},"medium":${n_med},"low":${n_low},"warn":${n_warn}}
HIST_EOF

  # Prune old entries beyond HISTORY_MAX
  local count
  count=$(find "$HISTORY_DIR" -name 'scan-*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$count" -gt "$HISTORY_MAX" ]]; then
    find "$HISTORY_DIR" -name 'scan-*.json' 2>/dev/null | sort | head -n $(( count - HISTORY_MAX )) | xargs rm -f 2>/dev/null || true
  fi
}

# Load history entries (newest last), output as JSON array
load_scan_history() {
  local HISTORY_DIR="${SCAN_DIR:-.}/.claudesec-history"
  [[ -d "$HISTORY_DIR" ]] || { echo "[]"; return; }
  local entries=""
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local content
    content=$(cat "$f" 2>/dev/null) || continue
    [[ -z "$content" ]] && continue
    if [[ -n "$entries" ]]; then
      entries="${entries},${content}"
    else
      entries="$content"
    fi
  done < <(find "$HISTORY_DIR" -name 'scan-*.json' 2>/dev/null | sort)
  echo "[${entries}]"
}

# Compute trend delta vs previous scan
compute_trend() {
  local HISTORY_DIR="${SCAN_DIR:-.}/.claudesec-history"
  [[ -d "$HISTORY_DIR" ]] || return
  local prev_file
  prev_file=$(find "$HISTORY_DIR" -name 'scan-*.json' 2>/dev/null | sort | tail -1)
  [[ -z "$prev_file" || ! -f "$prev_file" ]] && return

  local prev_score prev_failed prev_crit prev_high
  prev_score=$(grep -o '"score":[0-9]*' "$prev_file" | cut -d: -f2)
  prev_failed=$(grep -o '"failed":[0-9]*' "$prev_file" | cut -d: -f2)
  prev_crit=$(grep -o '"critical":[0-9]*' "$prev_file" | cut -d: -f2)
  prev_high=$(grep -o '"high":[0-9]*' "$prev_file" | cut -d: -f2)

  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))
  local n_crit=${#FINDINGS_CRITICAL[@]}
  local n_high=${#FINDINGS_HIGH[@]}

  export TREND_SCORE_DELTA=$(( score - ${prev_score:-0} ))
  export TREND_FAILED_DELTA=$(( FAILED - ${prev_failed:-0} ))
  export TREND_CRIT_DELTA=$(( n_crit - ${prev_crit:-0} ))
  export TREND_HIGH_DELTA=$(( n_high - ${prev_high:-0} ))
  export TREND_PREV_SCORE="${prev_score:-0}"
  export TREND_HAS_PREV="true"
}

_html_findings_rows() {
  local -n arr=$1
  local sev_class="$2" badge_class="$3" badge_text="$4"
  for entry in "${arr[@]+"${arr[@]}"}"; do
    IFS='|' read -r f_id f_title _ f_fix f_details <<< "$entry"
    f_title="$(html_escape "$f_title")"
    f_fix="$(html_escape "$f_fix")"
    f_details="$(html_escape "$f_details")"
    # Convert literal \n to <br> for HTML display
    f_title="${f_title//\\n/<br>}"
    f_fix="${f_fix//\\n/<br>}"
    f_details="${f_details//\\n/<br>}"

    local detail_html=""
    if [[ -n "$f_details" ]]; then
      detail_html="<tr class=\"detail-row ${sev_class}\" style=\"display:none\"><td colspan=\"4\"><div class=\"detail-content\">${f_details}</div></td></tr>"
      findings_html+="<tr class=\"${sev_class} clickable\" onclick=\"toggleDetail(this)\"><td><span class=\"badge ${badge_class}\">${badge_text}</span></td><td class=\"mono\">$f_id</td><td>$f_title <span class=\"expand-icon\">▸</span></td><td class=\"fix\">$f_fix</td></tr>${detail_html}"
    else
      findings_html+="<tr class=\"${sev_class}\"><td><span class=\"badge ${badge_class}\">${badge_text}</span></td><td class=\"mono\">$f_id</td><td>$f_title</td><td class=\"fix\">$f_fix</td></tr>"
    fi
  done
}

generate_html_dashboard() {
  local output_file="$1"
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))

  # Compute trend vs previous scan
  compute_trend 2>/dev/null || true

  # Load history for chart
  local history_json
  history_json=$(load_scan_history 2>/dev/null)

  local grade="F" grade_color="#ef4444"
  if [[ $score -ge 90 ]]; then grade="A"; grade_color="#22c55e"
  elif [[ $score -ge 80 ]]; then grade="B"; grade_color="#22c55e"
  elif [[ $score -ge 70 ]]; then grade="C"; grade_color="#eab308"
  elif [[ $score -ge 60 ]]; then grade="D"; grade_color="#eab308"
  fi

  local n_crit=${#FINDINGS_CRITICAL[@]}
  local n_high=${#FINDINGS_HIGH[@]}
  local n_med=${#FINDINGS_MEDIUM[@]}
  local n_low=${#FINDINGS_LOW[@]}
  local n_warn=${#FINDINGS_WARN[@]}

  # Build findings HTML
  local findings_html=""
  _html_findings_rows FINDINGS_CRITICAL "sev-critical" "critical" "CRITICAL"
  _html_findings_rows FINDINGS_HIGH "sev-high" "high" "HIGH"
  _html_findings_rows FINDINGS_MEDIUM "sev-medium" "medium" "MEDIUM"
  _html_findings_rows FINDINGS_WARN "sev-warn" "warn" "WARN"
  _html_findings_rows FINDINGS_LOW "sev-low" "low" "LOW"

  cat > "$output_file" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="ClaudeSec v${VERSION}">
<title>ClaudeSec AI Security Dashboard</title>
<style>
  :root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
  header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
  header h1 { font-size: 1.5rem; font-weight: 700; }
  header h1 span { color: var(--accent); }
  .meta { color: var(--muted); font-size: 0.85rem; }

  .score-section { display: flex; gap: 2rem; margin-bottom: 2rem; }
  .score-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; flex: 1; text-align: center; }
  .score-ring { width: 120px; height: 120px; margin: 0 auto 0.75rem; position: relative; }
  .score-ring svg { transform: rotate(-90deg); }
  .score-ring .value { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; font-weight: 800; }
  .score-ring .grade { position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); }

  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: 800; line-height: 1; }
  .stat .label { font-size: 0.8rem; color: var(--muted); margin-top: 0.35rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat.pass .num { color: #22c55e; }
  .stat.fail .num { color: #ef4444; }
  .stat.warn .num { color: #eab308; }
  .stat.skip .num { color: var(--muted); }

  .severity-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin-bottom: 2rem; background: var(--border); }
  .severity-bar div { height: 100%; }
  .sev-crit-bar { background: #dc2626; }
  .sev-high-bar { background: #ef4444; }
  .sev-med-bar { background: #eab308; }
  .sev-warn-bar { background: #f59e0b; }
  .sev-low-bar { background: #6b7280; }
  .sev-pass-bar { background: #22c55e; }

  .findings { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  .findings h2 { padding: 1rem 1.25rem; font-size: 1rem; border-bottom: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.6rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); border-bottom: 1px solid var(--border); }
  td { padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; white-space: nowrap; }
  .fix { color: var(--accent); font-size: 0.8rem; max-width: 350px; }

  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; }
  .badge.critical { background: #dc2626; color: #fff; }
  .badge.high { background: #991b1b; color: #fca5a5; }
  .badge.medium { background: #854d0e; color: #fde68a; }
  .badge.warn { background: #78350f; color: #fcd34d; }
  .badge.low { background: #374151; color: #9ca3af; }

  .sev-critical { border-left: 3px solid #dc2626; }
  .sev-high { border-left: 3px solid #ef4444; }
  .sev-medium { border-left: 3px solid #eab308; }
  .sev-warn { border-left: 3px solid #f59e0b; }
  .sev-low { border-left: 3px solid #6b7280; }

  .clickable { cursor: pointer; transition: background 0.15s; }
  .clickable:hover { background: #ffffff08; }
  .expand-icon { color: var(--muted); font-size: 0.7rem; margin-left: 0.4rem; transition: transform 0.2s; display: inline-block; }
  .clickable.expanded .expand-icon { transform: rotate(90deg); }
  .detail-row td { padding: 0; border-left-width: 3px; border-left-style: solid; }
  .detail-content { padding: 0.75rem 1rem 0.75rem 3.5rem; background: #0f172a; font-size: 0.82rem; line-height: 1.7; color: var(--muted); border-top: 1px dashed var(--border); max-height: 400px; overflow-y: auto; }
  .detail-content br { margin-bottom: 0.15rem; }
  .detail-content::-webkit-scrollbar { width: 6px; }
  .detail-content::-webkit-scrollbar-track { background: transparent; }
  .detail-content::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .detail-summary { font-weight: 600; color: var(--text); margin-bottom: 0.75rem; font-size: 0.85rem; }
  .detail-services { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.75rem; }
  .detail-svc-chip { background: var(--border); padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-family: 'SF Mono','Fira Code',monospace; }
  .detail-findings-list { display: flex; flex-direction: column; gap: 0.5rem; max-height: 350px; overflow-y: auto; }
  .detail-finding { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.8rem; }
  .detail-finding .df-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; }
  .detail-finding .df-sev { font-size: 0.65rem; font-weight: 700; padding: 0.1rem 0.35rem; border-radius: 3px; text-transform: uppercase; }
  .detail-finding .df-sev.crit { background: #dc2626; color: #fff; }
  .detail-finding .df-sev.hig { background: #991b1b; color: #fca5a5; }
  .detail-finding .df-sev.med { background: #854d0e; color: #fde68a; }
  .detail-finding .df-sev.low { background: #374151; color: #9ca3af; }
  .detail-finding .df-code { font-family: 'SF Mono','Fira Code',monospace; color: var(--accent); font-size: 0.75rem; }
  .detail-finding .df-msg { font-size: 0.82rem; color: var(--text); line-height: 1.4; }
  .detail-finding .df-meta { margin-top: 0.35rem; border-top: 1px dashed var(--border); padding-top: 0.3rem; }
  .detail-finding .df-meta div { font-size: 0.78rem; color: var(--muted); padding: 0.05rem 0; line-height: 1.4; }
  .detail-finding .df-meta .ml { color: var(--accent); font-weight: 600; }
  .detail-plain { font-size: 0.82rem; line-height: 1.6; color: var(--muted); }
  .detail-plain .dp-line { padding: 0.1rem 0; }
  .detail-plain .dp-kv { color: var(--text); }
  .detail-plain .dp-kv .dp-key { color: var(--accent); font-weight: 600; }

  .cat-summary { display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0.75rem 1.25rem; border-bottom: 1px solid var(--border); }
  .cat-chip { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.4rem 0.75rem; display: flex; align-items: center; gap: 0.5rem; cursor: pointer; transition: border-color 0.15s; }
  .cat-chip:hover { border-color: var(--accent); }
  .cat-chip.active { border-color: var(--accent); background: #38bdf810; }
  .cat-chip .cc-icon { font-size: 0.9rem; }
  .cat-chip .cc-name { font-size: 0.78rem; font-weight: 600; }
  .cat-chip .cc-count { font-size: 0.85rem; font-weight: 800; color: var(--accent); }

  .env-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0; }
  .env-item { display: flex; align-items: flex-start; gap: 0.75rem; padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); border-right: 1px solid var(--border); }
  .env-item:nth-child(2n) { border-right: none; }
  .env-item:nth-last-child(-n+2) { border-bottom: none; }
  .env-icon { font-size: 1.4rem; line-height: 1; min-width: 1.5rem; text-align: center; }
  .env-details { flex: 1; }
  .env-title { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.25rem; }
  .env-meta { font-size: 0.78rem; color: var(--muted); line-height: 1.5; }
  .env-status { font-size: 0.78rem; font-weight: 600; white-space: nowrap; }
  .env-status.connected { color: #22c55e; }
  .env-status.disconnected { color: var(--muted); }
  .env-badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.65rem; font-weight: 700; background: var(--accent); color: var(--bg); letter-spacing: 0.04em; margin-left: 0.4rem; vertical-align: middle; }
  .env-connected .env-icon { opacity: 1; }
  .env-disconnected .env-icon { opacity: 0.4; }
  .env-disconnected .env-title { color: var(--muted); }

  .trend-section { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
  .trend-section h2 { font-size: 1rem; margin-bottom: 1rem; }
  .trend-deltas { display: flex; gap: 1.5rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
  .trend-delta { display: flex; align-items: center; gap: 0.5rem; }
  .trend-delta .arrow { font-size: 1.1rem; font-weight: 700; }
  .trend-delta .arrow.up-good { color: #22c55e; }
  .trend-delta .arrow.down-good { color: #22c55e; }
  .trend-delta .arrow.up-bad { color: #ef4444; }
  .trend-delta .arrow.down-bad { color: #ef4444; }
  .trend-delta .arrow.neutral { color: var(--muted); }
  .trend-delta .label { font-size: 0.82rem; color: var(--muted); }
  .trend-delta .val { font-weight: 700; font-size: 0.9rem; }
  .trend-chart { width: 100%; height: 120px; position: relative; }
  .trend-chart canvas { width: 100% !important; height: 120px !important; }
  .trend-no-history { color: var(--muted); font-size: 0.85rem; text-align: center; padding: 1rem; }

  .empty { padding: 2rem; text-align: center; color: #22c55e; font-size: 1.1rem; }

  footer { text-align: center; padding: 2rem 0 1rem; color: var(--muted); font-size: 0.8rem; }

  @media (max-width: 768px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .score-section { flex-direction: column; }
    .fix { max-width: 200px; }
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>◆</span> ClaudeSec Dashboard</h1>
    <div class="meta">Scanned: $(date '+%Y-%m-%d %H:%M') · v${VERSION} · ${SCAN_DURATION:-0}s</div>
  </header>

  <div class="stats">
    <div class="stat pass"><div class="num">${PASSED}</div><div class="label">Passed</div></div>
    <div class="stat fail"><div class="num">${FAILED}</div><div class="label">Failed</div></div>
    <div class="stat warn"><div class="num">${WARNINGS}</div><div class="label">Warnings</div></div>
    <div class="stat skip"><div class="num">${SKIPPED}</div><div class="label">Skipped</div></div>
  </div>

  <div class="severity-bar">
    <div class="sev-pass-bar" style="width:$(( active > 0 ? (PASSED * 100) / active : 0 ))%"></div>
    <div class="sev-crit-bar" style="width:$(( active > 0 ? (n_crit * 100) / active : 0 ))%"></div>
    <div class="sev-high-bar" style="width:$(( active > 0 ? (n_high * 100) / active : 0 ))%"></div>
    <div class="sev-med-bar" style="width:$(( active > 0 ? (n_med * 100) / active : 0 ))%"></div>
    <div class="sev-warn-bar" style="width:$(( active > 0 ? (n_warn * 100) / active : 0 ))%"></div>
    <div class="sev-low-bar" style="width:$(( active > 0 ? (n_low * 100) / active : 0 ))%"></div>
  </div>

  <div class="score-section">
    <div class="score-card">
      <div class="score-ring">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="52" fill="none" stroke="${grade_color}22" stroke-width="10"/>
          <circle cx="60" cy="60" r="52" fill="none" stroke="${grade_color}" stroke-width="10"
            stroke-dasharray="$(( score * 327 / 100 )) 327" stroke-linecap="round"/>
        </svg>
        <div class="value" style="color:${grade_color}">${score}</div>
        <div class="grade">Grade ${grade}</div>
      </div>
      <div style="color:var(--muted);font-size:0.85rem">${active} active checks (${SKIPPED} skipped)</div>
    </div>
    <div class="score-card" style="display:flex;flex-direction:column;justify-content:center;gap:0.75rem">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted);font-size:0.85rem">Critical</span>
        <span style="font-weight:700;color:#dc2626">${n_crit}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted);font-size:0.85rem">High</span>
        <span style="font-weight:700;color:#ef4444">${n_high}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted);font-size:0.85rem">Medium</span>
        <span style="font-weight:700;color:#eab308">${n_med}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted);font-size:0.85rem">Warnings</span>
        <span style="font-weight:700;color:#f59e0b">${n_warn}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="color:var(--muted);font-size:0.85rem">Low</span>
        <span style="font-weight:700;color:#6b7280">${n_low}</span>
      </div>
    </div>
  </div>

  $(
    # Build Environment Info section
    _env_items=""
    if [[ "${CLAUDESEC_ENV_K8S_CONNECTED:-false}" == "true" ]]; then
      _k8s_type_badge="${CLAUDESEC_ENV_K8S_TYPE:-generic}"
      _k8s_type_upper=$(echo "$_k8s_type_badge" | tr '[:lower:]' '[:upper:]')
      _env_items+="<div class=\"env-item env-connected\"><div class=\"env-icon\">☸</div><div class=\"env-details\"><div class=\"env-title\">Kubernetes <span class=\"env-badge\">${_k8s_type_upper}</span></div>"
      _env_items+="<div class=\"env-meta\">Context: ${CLAUDESEC_ENV_K8S_CONTEXT:-unknown}</div>"
      _env_items+="<div class=\"env-meta\">Server: ${CLAUDESEC_ENV_K8S_SERVER:-unknown}</div>"
      _env_items+="<div class=\"env-meta\">Version: ${CLAUDESEC_ENV_K8S_VERSION:-unknown}</div>"
      [[ -n "${CLAUDESEC_ENV_K8S_KUBECONFIG:-}" ]] && _env_items+="<div class=\"env-meta\">Kubeconfig: ${CLAUDESEC_ENV_K8S_KUBECONFIG}</div>"
      [[ -n "${CLAUDESEC_ENV_K8S_NAMESPACE:-}" ]] && _env_items+="<div class=\"env-meta\">Namespace: ${CLAUDESEC_ENV_K8S_NAMESPACE}</div>"
      _env_items+="</div><div class=\"env-status connected\">● Connected</div></div>"
    else
      _env_items+="<div class=\"env-item env-disconnected\"><div class=\"env-icon\">☸</div><div class=\"env-details\"><div class=\"env-title\">Kubernetes</div><div class=\"env-meta\">Not connected — use --kubeconfig or --kubecontext</div></div><div class=\"env-status disconnected\">○ Disconnected</div></div>"
    fi

    if [[ "${CLAUDESEC_ENV_AWS_CONNECTED:-false}" == "true" ]]; then
      _env_items+="<div class=\"env-item env-connected\"><div class=\"env-icon\">☁</div><div class=\"env-details\"><div class=\"env-title\">AWS</div>"
      _env_items+="<div class=\"env-meta\">Account: ${CLAUDESEC_ENV_AWS_ACCOUNT:-unknown}</div>"
      [[ -n "${CLAUDESEC_ENV_AWS_PROFILE:-}" ]] && _env_items+="<div class=\"env-meta\">Profile: ${CLAUDESEC_ENV_AWS_PROFILE}</div>"
      _env_items+="</div><div class=\"env-status connected\">● Connected</div></div>"
    else
      _env_items+="<div class=\"env-item env-disconnected\"><div class=\"env-icon\">☁</div><div class=\"env-details\"><div class=\"env-title\">AWS</div><div class=\"env-meta\">Not configured — use --aws-profile</div></div><div class=\"env-status disconnected\">○ Disconnected</div></div>"
    fi

    if [[ "${CLAUDESEC_ENV_GCP_CONNECTED:-false}" == "true" ]]; then
      _env_items+="<div class=\"env-item env-connected\"><div class=\"env-icon\">◈</div><div class=\"env-details\"><div class=\"env-title\">GCP</div>"
      _env_items+="<div class=\"env-meta\">Account: ${CLAUDESEC_ENV_GCP_ACCOUNT:-unknown}</div>"
      _env_items+="<div class=\"env-meta\">Project: ${CLAUDESEC_ENV_GCP_PROJECT:-unknown}</div>"
      _env_items+="</div><div class=\"env-status connected\">● Connected</div></div>"
    else
      _env_items+="<div class=\"env-item env-disconnected\"><div class=\"env-icon\">◈</div><div class=\"env-details\"><div class=\"env-title\">GCP</div><div class=\"env-meta\">Not configured — gcloud auth login</div></div><div class=\"env-status disconnected\">○ Disconnected</div></div>"
    fi

    if [[ "${CLAUDESEC_ENV_AZ_CONNECTED:-false}" == "true" ]]; then
      _env_items+="<div class=\"env-item env-connected\"><div class=\"env-icon\">◇</div><div class=\"env-details\"><div class=\"env-title\">Azure</div>"
      _env_items+="<div class=\"env-meta\">Subscription: ${CLAUDESEC_ENV_AZ_SUBSCRIPTION:-unknown}</div>"
      _env_items+="</div><div class=\"env-status connected\">● Connected</div></div>"
    else
      _env_items+="<div class=\"env-item env-disconnected\"><div class=\"env-icon\">◇</div><div class=\"env-details\"><div class=\"env-title\">Azure</div><div class=\"env-meta\">Not configured — az login</div></div><div class=\"env-status disconnected\">○ Disconnected</div></div>"
    fi

    echo "<div class=\"findings\" style=\"margin-bottom:2rem\"><h2 style=\"padding:1rem 1.25rem;font-size:1rem;border-bottom:1px solid var(--border)\">Environment</h2><div class=\"env-grid\">${_env_items}</div></div>"
  )

  <div class="trend-section">
    <h2>Scan Trend</h2>
    $(if [[ "${TREND_HAS_PREV:-}" == "true" ]]; then
      # Score delta
      local s_arrow="→" s_class="neutral" s_prefix=""
      if [[ $TREND_SCORE_DELTA -gt 0 ]]; then s_arrow="▲"; s_class="up-good"; s_prefix="+"; fi
      if [[ $TREND_SCORE_DELTA -lt 0 ]]; then s_arrow="▼"; s_class="down-bad"; s_prefix=""; fi
      # Failed delta (lower is better)
      local f_arrow="→" f_class="neutral" f_prefix=""
      if [[ $TREND_FAILED_DELTA -gt 0 ]]; then f_arrow="▲"; f_class="up-bad"; f_prefix="+"; fi
      if [[ $TREND_FAILED_DELTA -lt 0 ]]; then f_arrow="▼"; f_class="down-good"; f_prefix=""; fi
      # Critical delta (lower is better)
      local c_arrow="→" c_class="neutral" c_prefix=""
      if [[ $TREND_CRIT_DELTA -gt 0 ]]; then c_arrow="▲"; c_class="up-bad"; c_prefix="+"; fi
      if [[ $TREND_CRIT_DELTA -lt 0 ]]; then c_arrow="▼"; c_class="down-good"; c_prefix=""; fi
      # High delta
      local h_arrow="→" h_class="neutral" h_prefix=""
      if [[ $TREND_HIGH_DELTA -gt 0 ]]; then h_arrow="▲"; h_class="up-bad"; h_prefix="+"; fi
      if [[ $TREND_HIGH_DELTA -lt 0 ]]; then h_arrow="▼"; h_class="down-good"; h_prefix=""; fi

      echo "<div class=\"trend-deltas\">"
      echo "  <div class=\"trend-delta\"><span class=\"arrow ${s_class}\">${s_arrow}</span><span class=\"val\">${s_prefix}${TREND_SCORE_DELTA}</span><span class=\"label\">Score (prev: ${TREND_PREV_SCORE})</span></div>"
      echo "  <div class=\"trend-delta\"><span class=\"arrow ${f_class}\">${f_arrow}</span><span class=\"val\">${f_prefix}${TREND_FAILED_DELTA}</span><span class=\"label\">Failures</span></div>"
      echo "  <div class=\"trend-delta\"><span class=\"arrow ${c_class}\">${c_arrow}</span><span class=\"val\">${c_prefix}${TREND_CRIT_DELTA}</span><span class=\"label\">Critical</span></div>"
      echo "  <div class=\"trend-delta\"><span class=\"arrow ${h_class}\">${h_arrow}</span><span class=\"val\">${h_prefix}${TREND_HIGH_DELTA}</span><span class=\"label\">High</span></div>"
      echo "</div>"
    else
      echo "<div class=\"trend-no-history\">No previous scan data. Run dashboard again to start tracking trends.</div>"
    fi)
    <div class="trend-chart"><canvas id="trendChart"></canvas></div>
  </div>

  <div class="findings">
    <div style="display:flex;align-items:center;justify-content:space-between;padding:1rem 1.25rem;border-bottom:1px solid var(--border)">
      <h2 style="padding:0;border:none;margin:0">Findings ($(( n_crit + n_high + n_med + n_warn + n_low )))</h2>
      <div style="display:flex;gap:0.5rem;align-items:center">
        <input type="text" id="findingSearch" placeholder="Filter findings..." oninput="filterFindings()" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:0.35rem 0.7rem;border-radius:6px;font-size:0.8rem;width:180px">
        <select id="sevFilter" onchange="filterFindings()" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:0.35rem 0.5rem;border-radius:6px;font-size:0.8rem">
          <option value="all">All Severities</option>
          <option value="sev-critical">Critical</option>
          <option value="sev-high">High</option>
          <option value="sev-medium">Medium</option>
          <option value="sev-warn">Warning</option>
          <option value="sev-low">Low</option>
        </select>
        <button onclick="toggleAllDetails()" style="background:var(--bg);border:1px solid var(--border);color:var(--accent);padding:0.35rem 0.7rem;border-radius:6px;font-size:0.8rem;cursor:pointer">Expand All</button>
      </div>
    </div>
    <div id="catSummary" class="cat-summary"></div>
    $(if [[ -n "$findings_html" ]]; then
      echo "<div style=\"max-height:70vh;overflow-y:auto\"><table><thead><tr><th style=\"width:90px\">Severity</th><th style=\"width:140px\">ID</th><th>Finding</th><th style=\"width:280px\">Remediation</th></tr></thead><tbody>${findings_html}</tbody></table></div>"
    else
      echo "<div class=\"empty\">✓ No findings — all checks passed!</div>"
    fi)
  </div>

  <footer>Generated by ClaudeSec Scanner v${VERSION} · $(date '+%Y-%m-%d %H:%M:%S')</footer>
</div>
<script>
function toggleDetail(row) {
  var detail = row.nextElementSibling;
  if (!detail || !detail.classList.contains('detail-row')) return;
  var show = detail.style.display === 'none';
  detail.style.display = show ? 'table-row' : 'none';
  row.classList.toggle('expanded', show);
}
function filterFindings() {
  var q = (document.getElementById('findingSearch').value || '').toLowerCase();
  var sev = document.getElementById('sevFilter').value;
  var rows = document.querySelectorAll('tbody tr');
  rows.forEach(function(row) {
    if (row.classList.contains('detail-row')) {
      // detail rows follow their parent visibility
      return;
    }
    var text = row.textContent.toLowerCase();
    var matchQ = !q || text.indexOf(q) !== -1;
    var matchSev = sev === 'all' || row.classList.contains(sev);
    var visible = matchQ && matchSev;
    row.style.display = visible ? '' : 'none';
    var detail = row.nextElementSibling;
    if (detail && detail.classList.contains('detail-row')) {
      detail.style.display = 'none';
      row.classList.remove('expanded');
    }
  });
}
// Trend chart
(function() {
  var canvas = document.getElementById('trendChart');
  if (!canvas) return;
  var history = ${history_json:-[]};
  // Append current scan
  history.push({timestamp:"$(date -u +%Y-%m-%dT%H:%M:%SZ)",score:${score},failed:${FAILED},critical:${n_crit},high:${n_high}});
  if (history.length < 2) { canvas.parentElement.innerHTML = '<div class="trend-no-history">Chart available after 2+ scans</div>'; return; }

  var ctx = canvas.getContext('2d');
  var W = canvas.parentElement.offsetWidth;
  var H = 120;
  canvas.width = W * 2; canvas.height = H * 2;
  canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
  ctx.scale(2, 2);

  var pad = {t:10, r:10, b:25, l:35};
  var cw = W - pad.l - pad.r;
  var ch = H - pad.t - pad.b;
  var n = history.length;

  // Draw grid
  ctx.strokeStyle = '#334155'; ctx.lineWidth = 0.5;
  for (var g = 0; g <= 100; g += 25) {
    var gy = pad.t + ch - (g / 100) * ch;
    ctx.beginPath(); ctx.moveTo(pad.l, gy); ctx.lineTo(W - pad.r, gy); ctx.stroke();
    ctx.fillStyle = '#94a3b8'; ctx.font = '9px system-ui'; ctx.textAlign = 'right';
    ctx.fillText(g, pad.l - 4, gy + 3);
  }

  // X labels (dates)
  ctx.fillStyle = '#94a3b8'; ctx.font = '8px system-ui'; ctx.textAlign = 'center';
  var step = Math.max(1, Math.floor(n / 6));
  for (var xi = 0; xi < n; xi += step) {
    var xp = pad.l + (xi / (n - 1)) * cw;
    var dt = history[xi].timestamp || '';
    ctx.fillText(dt.substring(5, 10), xp, H - 5);
  }

  function drawLine(data, key, color, maxVal) {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    for (var i = 0; i < data.length; i++) {
      var x = pad.l + (i / (n - 1)) * cw;
      var v = data[i][key] || 0;
      var y = pad.t + ch - (v / maxVal) * ch;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.stroke();
    // Dot on last point
    var lx = pad.l + cw;
    var lv = data[data.length - 1][key] || 0;
    var ly = pad.t + ch - (lv / maxVal) * ch;
    ctx.fillStyle = color; ctx.beginPath(); ctx.arc(lx, ly, 3, 0, Math.PI * 2); ctx.fill();
  }

  drawLine(history, 'score', '#38bdf8', 100);

  // Legend
  ctx.fillStyle = '#38bdf8'; ctx.font = '9px system-ui'; ctx.textAlign = 'left';
  ctx.fillText('● Score', pad.l + 5, pad.t + 10);
})();

function toggleAllDetails() {
  var rows = document.querySelectorAll('tbody tr.clickable');
  var anyCollapsed = false;
  rows.forEach(function(row) {
    if (row.style.display === 'none') return;
    var detail = row.nextElementSibling;
    if (detail && detail.classList.contains('detail-row') && detail.style.display === 'none') {
      anyCollapsed = true;
    }
  });
  rows.forEach(function(row) {
    if (row.style.display === 'none') return;
    var detail = row.nextElementSibling;
    if (detail && detail.classList.contains('detail-row')) {
      detail.style.display = anyCollapsed ? 'table-row' : 'none';
      row.classList.toggle('expanded', anyCollapsed);
    }
  });
}

// Build category summary chips from findings table
(function buildCategorySummary() {
  var container = document.getElementById('catSummary');
  if (!container) return;
  var rows = document.querySelectorAll('tbody tr:not(.detail-row)');
  var cats = {};
  var icons = {'PROWLER-AWS':'☁','PROWLER-GH':'⚙','PROWLER-K8S':'☸','PROWLER-AZ':'◇','PROWLER-GCP':'◈','PROWLER-IAC':'📄','INFRA':'🏗','NET':'🌐','CLOUD':'☁','CICD':'⚡','AI':'🤖','ACCESS':'🔑','CODE':'📝','SAAS':'🔌','PROWLER-M365':'📧','PROWLER-CF':'🌐','PROWLER-MONGO':'🍃','PROWLER-OCI':'☁','PROWLER-LLM':'🤖','PROWLER-IMG':'📦'};
  rows.forEach(function(row) {
    var idCell = row.querySelector('.mono');
    if (!idCell) return;
    var id = idCell.textContent.trim();
    var prefix = id.replace(/-\d+$/, '');
    if (!cats[prefix]) cats[prefix] = 0;
    cats[prefix]++;
  });
  var keys = Object.keys(cats).sort();
  if (keys.length === 0) { container.style.display = 'none'; return; }
  keys.forEach(function(cat) {
    var icon = icons[cat] || '●';
    // Try shorter prefix match
    if (!icons[cat]) { for (var k in icons) { if (cat.indexOf(k) === 0) { icon = icons[k]; break; } } }
    var chip = document.createElement('div');
    chip.className = 'cat-chip';
    chip.setAttribute('data-cat', cat);
    chip.innerHTML = '<span class="cc-icon">' + icon + '</span><span class="cc-name">' + cat + '</span><span class="cc-count">' + cats[cat] + '</span>';
    chip.onclick = function() {
      var isActive = this.classList.contains('active');
      document.querySelectorAll('.cat-chip').forEach(function(c) { c.classList.remove('active'); });
      if (!isActive) {
        this.classList.add('active');
        filterByCategory(cat);
      } else {
        filterByCategory(null);
      }
    };
    container.appendChild(chip);
  });
})();

function filterByCategory(cat) {
  var rows = document.querySelectorAll('tbody tr');
  rows.forEach(function(row) {
    if (row.classList.contains('detail-row')) { row.style.display = 'none'; return; }
    if (!cat) { row.style.display = ''; return; }
    var idCell = row.querySelector('.mono');
    if (!idCell) { row.style.display = ''; return; }
    var id = idCell.textContent.trim();
    var prefix = id.replace(/-\d+$/, '');
    row.style.display = (prefix === cat) ? '' : 'none';
    row.classList.remove('expanded');
  });
}

// Transform raw detail-content text into structured HTML
(function formatDetails() {
  document.querySelectorAll('.detail-content').forEach(function(el) {
    var raw = el.innerHTML;
    var lines = raw.split(/<br\s*\/?>/).map(function(l) { return l.trim(); }).filter(Boolean);
    if (lines.length < 2) {
      // Simple non-Prowler detail: format as clean lines
      if (lines.length === 1) {
        el.innerHTML = '<div class="detail-plain"><div class="dp-line">' + lines[0] + '</div></div>';
      }
      return;
    }

    var result = '';
    var summaryLine = lines[0];
    var services = [];
    var findings = [];
    var currentFinding = null;
    var plainLines = [];

    for (var i = 1; i < lines.length; i++) {
      var line = lines[i];
      // Service grouping: "service: N finding(s)"
      var svcMatch = line.match(/^([\w][\w\-]*): (\d+) finding/);
      if (svcMatch) { services.push({name: svcMatch[1], count: parseInt(svcMatch[2])}); continue; }
      // Finding header: "[Severity] (code) message"
      var findMatch = line.match(/^\[(\w+)\]\s*\(([^)]+)\)\s*(.*)/);
      if (findMatch) {
        if (currentFinding) findings.push(currentFinding);
        currentFinding = {sev: findMatch[1], code: findMatch[2], msg: findMatch[3], meta: []};
        continue;
      }
      // Meta lines: "Risk:", "Fix:", "Ref:", "Resource:"
      var metaMatch = line.match(/^(Risk|Fix|Ref|Reference|Resource|Remediation):\s*(.*)/);
      if (metaMatch && currentFinding) {
        currentFinding.meta.push({label: metaMatch[1], value: metaMatch[2]});
        continue;
      }
      if (currentFinding) { currentFinding.meta.push({label: '', value: line}); }
      else { plainLines.push(line); }
    }
    if (currentFinding) findings.push(currentFinding);

    // If no structured data found, format as clean plain text
    if (services.length === 0 && findings.length === 0) {
      result = '<div class="detail-plain">';
      result += '<div class="dp-line">' + summaryLine + '</div>';
      for (var p = 0; p < plainLines.length; p++) {
        var pl = plainLines[p];
        var kvMatch = pl.match(/^([A-Za-z][\w\s]*?):\s+(.*)/);
        if (kvMatch) {
          result += '<div class="dp-kv"><span class="dp-key">' + kvMatch[1] + ':</span> ' + kvMatch[2] + '</div>';
        } else {
          result += '<div class="dp-line">' + pl + '</div>';
        }
      }
      result += '</div>';
      el.innerHTML = result;
      return;
    }

    // Structured Prowler-style output
    result += '<div class="detail-summary">' + summaryLine + '</div>';

    if (services.length > 0) {
      // Sort by count descending
      services.sort(function(a,b) { return b.count - a.count; });
      result += '<div class="detail-services">';
      services.forEach(function(s) {
        result += '<span class="detail-svc-chip">' + s.name + ': ' + s.count + '</span>';
      });
      result += '</div>';
    }

    if (findings.length > 0) {
      result += '<div class="detail-findings-list">';
      var maxShow = 20;
      var shown = Math.min(findings.length, maxShow);
      for (var fi = 0; fi < shown; fi++) {
        var f = findings[fi];
        var sl = f.sev.toLowerCase();
        var sevClass = sl === 'critical' ? 'crit' : sl.substring(0,3);
        result += '<div class="detail-finding">';
        result += '<div class="df-header"><span class="df-sev ' + sevClass + '">' + f.sev + '</span><span class="df-code">' + f.code + '</span></div>';
        result += '<div class="df-msg">' + f.msg + '</div>';
        if (f.meta.length > 0) {
          result += '<div class="df-meta">';
          f.meta.forEach(function(m) {
            if (m.label === 'Ref' || m.label === 'Reference') {
              result += '<div><span class="ml">' + m.label + ':</span> <a href="' + m.value + '" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:underline">' + m.value.replace(/^https?:\/\//, '').substring(0,60) + '</a></div>';
            } else if (m.label) {
              result += '<div><span class="ml">' + m.label + ':</span> ' + m.value + '</div>';
            } else {
              result += '<div>' + m.value + '</div>';
            }
          });
          result += '</div>';
        }
        result += '</div>';
      }
      if (findings.length > maxShow) {
        result += '<div style="text-align:center;padding:0.5rem;color:var(--muted);font-size:0.8rem">... and ' + (findings.length - maxShow) + ' more findings</div>';
      }
      result += '</div>';
    }

    el.innerHTML = result;
  });
})();
</script>
</body>
</html>
HTMLEOF
}
