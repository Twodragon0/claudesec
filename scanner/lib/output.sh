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
# shellcheck disable=SC2034
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
  local id="$1" title="$2" severity="${3:-high}" details="${4:-}" remediation="${5:-}" location="${6:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  FAILED=$((FAILED + 1))

  local entry="$id|$title|$severity|$remediation|$details|$location"
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
      [[ -n "$location" ]] && echo -e "         ${DIM}📍 $location${NC}"
    fi
  fi
  append_json "$id" "$title" "fail" "$details" "$severity" "$location"
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

_finding_ref_url() {
  case "$1" in
    CODE-INJ-*) echo "https://owasp.org/Top10/A03_2021-Injection/" ;;
    CODE-SEC-001) echo "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" ;;
    CODE-SEC-002) echo "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/" ;;
    CODE-SEC-003|SECRETS-*) echo "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" ;;
    CODE-SEC-*) echo "https://owasp.org/Top10/" ;;
    CICD-*) echo "https://owasp.org/www-project-top-10-ci-cd-security-risks/" ;;
    AI-*|LLM-*) echo "https://owasp.org/www-project-top-10-for-large-language-model-applications/" ;;
    IAM-*) echo "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" ;;
    NET-*|TLS-*) echo "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" ;;
    INFRA-*|DOCKER-*) echo "https://www.cisecurity.org/benchmark/docker" ;;
    MAC-*|CIS-*) echo "https://www.cisecurity.org/benchmark/apple_os" ;;
    WIN-*|KISA-*) echo "https://www.kisa.or.kr/2060305/form?postSeq=12" ;;
    CLOUD-*|AWS-*) echo "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html" ;;
    SAAS-ZIA-*) echo "https://help.zscaler.com/zia/about-zscaler-internet-access" ;;
    SAAS-API-*|SAAS-*) echo "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" ;;
    TRIVY-*) echo "https://aquasecurity.github.io/trivy/" ;;
    PROWLER-*) echo "https://hub.prowler.com/" ;;
    *) echo "" ;;
  esac
}

append_json() {
  local id="$1" title="$2" status="$3" details="$4" severity="${5:-}" location="${6:-}"
  # Escape JSON strings
  title="${title//\\/\\\\}"; title="${title//\"/\\\"}"
  details="${details//\\/\\\\}"; details="${details//\"/\\\"}"
  location="${location//\\/\\\\}"; location="${location//\"/\\\"}"
  local category ref_url
  category="$(_finding_id_to_category "$id")"
  ref_url="$(_finding_ref_url "$id")"
  local entry="{\"id\":\"$id\",\"status\":\"$status\",\"title\":\"$title\""
  [[ -n "$severity" ]] && entry+=",\"severity\":\"$severity\""
  [[ -n "$category" ]] && entry+=",\"category\":\"$category\""
  [[ -n "$details" ]] && entry+=",\"details\":\"$details\""
  [[ -n "$location" ]] && entry+=",\"location\":\"$location\""
  [[ -n "$ref_url" ]] && entry+=",\"ref_url\":\"$ref_url\""
  entry+="}"
  if [[ "$JSON_RESULTS" == "[]" ]]; then
    JSON_RESULTS="[$entry]"
  else
    JSON_RESULTS="${JSON_RESULTS%]},${entry}]"
  fi
}

# Map check id prefix to category for "where" (location) in summary
_finding_id_to_category() {
  local prefix="${1%%-*}"
  case "$prefix" in
    IAM)      echo "access-control" ;;
    INFRA)    echo "infra" ;;
    NET|TLS)  echo "network" ;;
    CICD)     echo "cicd" ;;
    CODE|SAST) echo "code" ;;
    AI|LLM)   echo "ai" ;;
    CLOUD|AWS|GCP|AZURE) echo "cloud" ;;
    MAC|CIS)  echo "macos" ;;
    SAAS)     echo "saas" ;;
    WIN|KISA) echo "windows" ;;
    PROWLER)  echo "prowler" ;;
    SECRETS|TRIVY) echo "code" ;;
    DOCKER)   echo "infra" ;;
    *)        echo "other" ;;
  esac
}

_print_findings() {
  local -n arr=$1
  local label="$2" show_fix="${3:-true}"
  for entry in "${arr[@]+"${arr[@]}"}"; do
    IFS='|' read -r f_id f_title _ f_fix <<< "$entry"
    local f_cat; f_cat=$(_finding_id_to_category "$f_id")
    echo -e "  ${label}${NC}  ${DIM}[$f_id]${NC} ${DIM}(${f_cat})${NC} $f_title"
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

    # Findings table — Critical and High first (with category so user sees where each finding is from)
    if [[ $((n_crit + n_high)) -gt 0 ]]; then
      echo -e "  ${RED}${BOLD}▸ Action Required (critical/high by category)${NC}"
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

  # Build compliance summary from prowler OCSF results if available
  local compliance_json=""
  local prowler_dir="${SCAN_DIR:-.}/.claudesec-prowler"
  local _has_ocsf=0
  if [[ -d "$prowler_dir" ]]; then
    for _f in "$prowler_dir"/prowler-*.ocsf.json; do
      [[ -f "$_f" ]] && _has_ocsf=1 && break
    done
  fi
  if [[ "$_has_ocsf" == "1" ]] && command -v python3 &>/dev/null; then
    compliance_json=$(timeout 10 python3 -c "
import json, glob, os, importlib.util
pdir = '$prowler_dir'
findings = []
for fp in glob.glob(os.path.join(pdir, 'prowler-*.ocsf.json')):
    try:
        with open(fp, encoding='utf-8') as f:
            raw = f.read().strip()
        data = json.loads(raw) if raw.startswith('[') else [json.loads(l) for l in raw.splitlines() if l.strip()]
        for item in data:
            if item.get('status_code') != 'FAIL': continue
            findings.append({'check': item.get('metadata',{}).get('event_code',''),
                'title': item.get('finding_info',{}).get('title',''),
                'message': item.get('message',''),
                'compliance': item.get('unmapped',{}).get('compliance',{})})
    except Exception: pass
if not findings: exit(0)
spec = importlib.util.spec_from_file_location('cm', '$(dirname "${BASH_SOURCE[0]}")/compliance-map.py')
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)
print(json.dumps(cm.compliance_summary(cm.map_compliance(findings)), separators=(',', ':')))
" 2>/dev/null) || compliance_json=""
  fi

  local comp_field=""
  if [[ -n "$compliance_json" && "$compliance_json" != "{}" ]]; then
    comp_field=",\"compliance\":${compliance_json}"
  fi

  cat > "${HISTORY_DIR}/scan-${ts}.json" <<HIST_EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","score":${score},"passed":${PASSED},"failed":${FAILED},"warnings":${WARNINGS},"skipped":${SKIPPED},"total":${TOTAL_CHECKS},"critical":${n_crit},"high":${n_high},"medium":${n_med},"low":${n_low},"warn":${n_warn}${comp_field}}
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

# Build Prowler report summary HTML from .claudesec-prowler/*.ocsf.json (for dashboard)
_prowler_dashboard_summary() {
  local prowler_dir="${SCAN_DIR:-.}/.claudesec-prowler"
  [[ -d "$prowler_dir" ]] || return 0
  local files
  files=$(find "$prowler_dir" -maxdepth 1 -name "prowler-*.ocsf.json" 2>/dev/null | sort)
  [[ -z "$files" ]] && return 0

  echo "<div class=\"findings prowler-report\" style=\"margin-bottom:2rem\">"
  echo "  <h2 style=\"padding:1rem 1.25rem;font-size:1rem;border-bottom:1px solid var(--border)\">☁ Prowler 클라우드 리포트 (프로바이더별 요약)</h2>"
  echo "  <div style=\"padding:1rem 1.25rem\">"
  echo "  <table style=\"width:100%;border-collapse:collapse\">"
  echo "  <thead><tr><th style=\"text-align:left;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">프로바이더</th><th style=\"text-align:right;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">전체</th><th style=\"text-align:right;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">치명적</th><th style=\"text-align:right;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">높음</th><th style=\"text-align:right;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">중간</th><th style=\"text-align:right;padding:0.5rem 0.75rem;font-size:0.7rem;color:var(--muted);border-bottom:1px solid var(--border)\">낮음</th></tr></thead>"
  echo "  <tbody>"
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local provider label total c h m l
    provider=$(basename "$f" .ocsf.json | sed 's/^prowler-//')
    case "$provider" in
      aws) label="AWS" ;;
      kubernetes) label="Kubernetes" ;;
      azure) label="Azure" ;;
      gcp) label="GCP" ;;
      github) label="GitHub" ;;
      googleworkspace) label="Google Workspace" ;;
      m365) label="Microsoft 365" ;;
      cloudflare) label="Cloudflare" ;;
      nhn) label="NHN Cloud" ;;
      iac) label="IaC" ;;
      llm) label="LLM" ;;
      image) label="Container Image" ;;
      oraclecloud) label="Oracle Cloud" ;;
      alibabacloud) label="Alibaba Cloud" ;;
      openstack) label="OpenStack" ;;
      mongodbatlas) label="MongoDB Atlas" ;;
      *) label="$provider" ;;
    esac
    total=$(grep -c '"status_code": *"FAIL"' "$f" 2>/dev/null || echo 0)
    read c h m l <<< "$(awk '
      BEGIN { c=0; h=0; m=0; l=0 }
      /"severity":/ { gsub(/.*"severity": *"/,""); gsub(/".*/, ""); sev=$0 }
      /"status_code": *"FAIL"/ {
        if (sev=="Critical") c++; else if (sev=="High") h++; else if (sev=="Medium") m++; else if (sev=="Low") l++
      }
      END { print c+0, h+0, m+0, l+0 }
    ' "$f" 2>/dev/null)"
    c=${c:-0}; h=${h:-0}; m=${m:-0}; l=${l:-0}
    echo "  <tr><td style=\"padding:0.5rem 0.75rem;border-bottom:1px solid var(--border)\">$label</td><td style=\"text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border)\">$total</td><td style=\"text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);color:#dc2626\">$c</td><td style=\"text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);color:#ef4444\">$h</td><td style=\"text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);color:#eab308\">$m</td><td style=\"text-align:right;padding:0.5rem 0.75rem;border-bottom:1px solid var(--border);color:var(--muted)\">$l</td></tr>"
  done <<< "$files"
  echo "  </tbody></table>"
  echo "  <p style=\"margin-top:0.75rem;font-size:0.78rem;color:var(--muted)\">원본 리포트 파일: <code>.claudesec-prowler/prowler-*.ocsf.json</code> (JSON-OCSF). 최신 상태로 갱신하려면 <code>claudesec scan -c prowler</code> 또는 <code>claudesec dashboard -c prowler</code>를 다시 실행하세요.</p>"
  echo "  </div></div>"
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

_html_findings_rows_limited() {
  local outvar="$1"
  local -n arr=$2
  local sev_class="$3" badge_class="$4" badge_text="$5"
  local max="${6:-0}"

  local count=0
  local current="${!outvar}"

  for entry in "${arr[@]+"${arr[@]}"}"; do
    if [[ "$max" -gt 0 && "$count" -ge "$max" ]]; then
      break
    fi
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
      current+="<tr class=\"${sev_class} clickable\" onclick=\"toggleDetail(this)\"><td><span class=\"badge ${badge_class}\">${badge_text}</span></td><td class=\"mono\">$f_id</td><td>$f_title <span class=\"expand-icon\">▸</span></td><td class=\"fix\">$f_fix</td></tr>${detail_html}"
    else
      current+="<tr class=\"${sev_class}\"><td><span class=\"badge ${badge_class}\">${badge_text}</span></td><td class=\"mono\">$f_id</td><td>$f_title</td><td class=\"fix\">$f_fix</td></tr>"
    fi

    count=$((count + 1))
  done

  printf -v "$outvar" '%s' "$current"
}

generate_html_dashboard_legacy() {
  # Legacy bash-only generator kept as fallback (v0.2.0)
  local output_file="$1"
  echo "<html><body><h1>ClaudeSec Dashboard (fallback)</h1><p>Install Python 3 for the full v0.5.0 dashboard.</p></body></html>" > "$output_file"
}

generate_html_dashboard() {
  local output_file="$1"
  local active=$((TOTAL_CHECKS - SKIPPED))
  local score=0
  [[ $active -gt 0 ]] && score=$(( (PASSED * 100) / active ))

  local grade="F"
  if [[ $score -ge 90 ]]; then grade="A"
  elif [[ $score -ge 80 ]]; then grade="B"
  elif [[ $score -ge 70 ]]; then grade="C"
  elif [[ $score -ge 60 ]]; then grade="D"
  fi

  local n_crit=${#FINDINGS_CRITICAL[@]}
  local n_high=${#FINDINGS_HIGH[@]}
  local n_med=${#FINDINGS_MEDIUM[@]}
  local n_low=${#FINDINGS_LOW[@]}
  local n_warn=${#FINDINGS_WARN[@]}

  _id_to_category() {
    local prefix="${1%%-*}"
    case "$prefix" in
      IAM)      echo "access-control" ;;
      INFRA)    echo "infra" ;;
      NET|TLS)  echo "network" ;;
      CICD)     echo "cicd" ;;
      CODE|SAST|SECRETS|TRIVY) echo "code" ;;
      AI|LLM)   echo "ai" ;;
      CLOUD|AWS|GCP|AZURE) echo "cloud" ;;
      MAC|CIS)  echo "macos" ;;
      SAAS)     echo "saas" ;;
      WIN|KISA) echo "windows" ;;
      PROWLER)  echo "prowler" ;;
      DOCKER)   echo "infra" ;;
      *)        echo "other" ;;
    esac
  }

  # Build findings JSON for Python generator
  local findings_json="["
  local first=true

  _emit_finding_json() {
    local f_sev_label="$1"
    local f_id f_title _f_sev f_fix f_details f_loc
    IFS='|' read -r f_id f_title _f_sev f_fix f_details f_loc <<< "$2"
    f_title="${f_title//\"/\\\"}"
    f_fix="${f_fix//\"/\\\"}"
    f_loc="${f_loc//\"/\\\"}"
    local f_cat; f_cat=$(_id_to_category "$f_id")
    [[ "$first" == "true" ]] && first=false || findings_json+=","
    local loc_field=""
    [[ -n "$f_loc" ]] && loc_field=",\"location\":\"$f_loc\""
    findings_json+="{\"id\":\"$f_id\",\"title\":\"$f_title\",\"severity\":\"$f_sev_label\",\"details\":\"$f_fix\",\"category\":\"$f_cat\"${loc_field}}"
  }

  for entry in "${FINDINGS_CRITICAL[@]+"${FINDINGS_CRITICAL[@]}"}"; do
    _emit_finding_json "critical" "$entry"
  done
  for entry in "${FINDINGS_HIGH[@]+"${FINDINGS_HIGH[@]}"}"; do
    _emit_finding_json "high" "$entry"
  done
  for entry in "${FINDINGS_MEDIUM[@]+"${FINDINGS_MEDIUM[@]}"}"; do
    _emit_finding_json "medium" "$entry"
  done
  for entry in "${FINDINGS_WARN[@]+"${FINDINGS_WARN[@]}"}"; do
    _emit_finding_json "warning" "$entry"
  done
  for entry in "${FINDINGS_LOW[@]+"${FINDINGS_LOW[@]}"}"; do
    _emit_finding_json "low" "$entry"
  done
  findings_json+="]"

  # Persist scan summary for diagrams/docs (no identifiers by design).
  # Consumers: scanner/lib/diagram-gen.py, docs/architecture assets, local dashboards.
  local scan_report_path="${SCAN_DIR:-.}/scan-report.json"
  cat > "$scan_report_path" <<SCAN_REPORT_EOF
{"passed":${PASSED:-0},"failed":${FAILED:-0},"warnings":${WARNINGS:-0},"skipped":${SKIPPED:-0},"total":${TOTAL_CHECKS:-0},"score":${score:-0},"grade":"${grade:-F}","duration":${SCAN_DURATION:-0},"findings":${findings_json}}
SCAN_REPORT_EOF

  # Generate draw.io + SVG architecture diagrams from scanned data (best-effort).
  # Disable with: CLAUDESEC_GENERATE_DIAGRAMS=0
  if [[ "${CLAUDESEC_GENERATE_DIAGRAMS:-1}" != "0" ]]; then
    local diagram_script="$LIB_DIR/diagram-gen.py"
    local diagram_out="${SCAN_DIR:-.}/docs/architecture"
    if command -v python3 >/dev/null 2>&1 && [[ -f "$diagram_script" ]]; then
      mkdir -p "$diagram_out" 2>/dev/null || true
      CLAUDESEC_SCAN_DIR="${SCAN_DIR:-.}" python3 "$diagram_script" "$diagram_out" 2>/dev/null || true
    fi
  fi

  local py_script="$LIB_DIR/dashboard-gen.py"

  if command -v python3 >/dev/null 2>&1 && [[ -f "$py_script" ]]; then
    # Use Python v0.5.0 generator
    # Ensure dashboard-gen can resolve artifacts under the scan directory,
    # even when the HTML output is generated from another working directory
    # or when Prowler artifacts are absent.
    CLAUDESEC_SCAN_DIR="${SCAN_DIR:-.}" \
    CLAUDESEC_PASSED="$PASSED" \
    CLAUDESEC_FAILED="$FAILED" \
    CLAUDESEC_WARNINGS="$WARNINGS" \
    CLAUDESEC_SKIPPED="$SKIPPED" \
    CLAUDESEC_TOTAL="$TOTAL_CHECKS" \
    CLAUDESEC_SCORE="$score" \
    CLAUDESEC_GRADE="$grade" \
    CLAUDESEC_DURATION="${SCAN_DURATION:-0}" \
    CLAUDESEC_FINDINGS_JSON="$findings_json" \
    CLAUDESEC_PROWLER_DIR="${SCAN_DIR:-.}/.claudesec-prowler" \
    CLAUDESEC_HISTORY_DIR="${SCAN_DIR:-.}/.claudesec-history" \
    CLAUDESEC_NETWORK_DIR="${SCAN_DIR:-.}/.claudesec-network" \
    python3 "$py_script" "$output_file" 2>/dev/null

    if [[ $? -eq 0 && -f "$output_file" ]]; then
      return 0
    fi
  fi

  # Fallback to legacy bash generator
  generate_html_dashboard_legacy "$output_file"
}
