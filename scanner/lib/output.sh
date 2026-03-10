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

  if should_report "$severity"; then
    if [[ "$FORMAT" == "text" ]]; then
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

append_json() {
  local id="$1" title="$2" status="$3" details="$4" severity="${5:-}"
  # JSON building is simplified — full implementation would use jq
  :
}

print_summary() {
  local duration="$1"
  echo ""
  echo -e "${BOLD}━━━ Summary ━━━${NC}"
  echo ""
  echo -e "  Total checks:  ${BOLD}$TOTAL_CHECKS${NC}"
  echo -e "  ${GREEN}Passed:${NC}        $PASSED"
  echo -e "  ${RED}Failed:${NC}        $FAILED"
  echo -e "  ${YELLOW}Warnings:${NC}      $WARNINGS"
  echo -e "  ${DIM}Skipped:${NC}       $SKIPPED"
  echo ""

  if [[ $TOTAL_CHECKS -gt 0 ]]; then
    local score=$(( (PASSED * 100) / TOTAL_CHECKS ))
    local grade_color="$RED"
    local grade="F"
    if [[ $score -ge 90 ]]; then grade="A"; grade_color="$GREEN"
    elif [[ $score -ge 80 ]]; then grade="B"; grade_color="$GREEN"
    elif [[ $score -ge 70 ]]; then grade="C"; grade_color="$YELLOW"
    elif [[ $score -ge 60 ]]; then grade="D"; grade_color="$YELLOW"
    fi

    echo -e "  Security Score: ${grade_color}${BOLD}$score/100 ($grade)${NC}"
  fi

  echo -e "  ${DIM}Duration: ${duration}s${NC}"
  echo ""

  if [[ $FAILED -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}$FAILED security issue(s) found. Review and remediate.${NC}"
  else
    echo -e "  ${GREEN}${BOLD}All checks passed!${NC}"
  fi
  echo ""
}

print_json_summary() {
  local duration="$1"
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
    "score": $(( TOTAL_CHECKS > 0 ? (PASSED * 100) / TOTAL_CHECKS : 0 ))
  }
}
EOF
}
