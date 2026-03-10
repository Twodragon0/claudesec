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
  echo -e "${BOLD}${CYAN}║${NC}  DevSecOps Security Best Practices Scanner              ${BOLD}${CYAN}║${NC}"
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
    macos)          echo "macOS / CIS Benchmark Security" ;;
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

  local entry="$id|$title|$severity|$remediation"
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

  FINDINGS_WARN+=("$id|$title|medium|$details")

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

_html_findings_rows() {
  local -n arr=$1
  local sev_class="$2" badge_class="$3" badge_text="$4"
  for entry in "${arr[@]+"${arr[@]}"}"; do
    IFS='|' read -r f_id f_title _ f_fix <<< "$entry"
    f_title="$(html_escape "$f_title")"
    f_fix="$(html_escape "$f_fix")"
    findings_html+="<tr class=\"${sev_class}\"><td><span class=\"badge ${badge_class}\">${badge_text}</span></td><td class=\"mono\">$f_id</td><td>$f_title</td><td class=\"fix\">$f_fix</td></tr>"
  done
}

generate_html_dashboard() {
  local output_file="$1"
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))

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
<title>ClaudeSec Dashboard</title>
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

  <div class="findings">
    <h2>Findings ($(( n_crit + n_high + n_med + n_warn + n_low )))</h2>
    $(if [[ -n "$findings_html" ]]; then
      echo "<table><thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Remediation</th></tr></thead><tbody>${findings_html}</tbody></table>"
    else
      echo "<div class=\"empty\">✓ No findings — all checks passed!</div>"
    fi)
  </div>

  <footer>Generated by ClaudeSec Scanner v${VERSION} · $(date '+%Y-%m-%d %H:%M:%S')</footer>
</div>
</body>
</html>
HTMLEOF
}
