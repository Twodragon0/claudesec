#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Prowler dashboard summary (split out of output.sh)
# ============================================================================
# Provider-label mapping + the per-provider Prowler HTML summary table used by
# the dashboard. Sourced by output.sh. The label `case` mirrors PROVIDER_LABELS
# in scanner/lib/dashboard_providers.py and is kept in sync by
# scanner/tests/test_ci_provider_labels_sync.py.

# Map a prowler provider slug (from filename) to a human-readable label.
# Pure: deterministic string → string mapping, no I/O.
_prowler_dashboard_summary_provider_label() {
  case "$1" in
    aws) echo "AWS" ;;
    kubernetes) echo "Kubernetes" ;;
    azure) echo "Azure" ;;
    gcp) echo "GCP" ;;
    github) echo "GitHub" ;;
    googleworkspace) echo "Google Workspace" ;;
    m365) echo "Microsoft 365" ;;
    cloudflare) echo "Cloudflare" ;;
    nhn) echo "NHN Cloud" ;;
    iac) echo "IaC" ;;
    llm) echo "LLM" ;;
    image) echo "Container Image" ;;
    oraclecloud) echo "Oracle Cloud" ;;
    alibabacloud) echo "Alibaba Cloud" ;;
    openstack) echo "OpenStack" ;;
    mongodbatlas) echo "MongoDB Atlas" ;;
    *) echo "$1" ;;
  esac
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
    label="$(_prowler_dashboard_summary_provider_label "$provider")"
    total=$(grep -c '"status_code": *"FAIL"' "$f" 2>/dev/null || echo 0)
    read -r c h m l <<< "$(awk '
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

# Build a compact compliance-summary JSON from .claudesec-prowler/*.ocsf.json
# (embedded into the scan-history entry by save_scan_history in output.sh).
# Echoes the JSON object on success, or nothing when there are no OCSF artifacts,
# no FAIL findings, or python3 is unavailable. The parsing + compliance-mapping
# logic lives in prowler_compliance_summary.py, a sibling module resolved
# relative to this file's directory (same scanner/lib/ dir as when this lived
# inline in output.sh); it in turn loads compliance-map.py the same way.
_prowler_compliance_summary_json() {
  local prowler_dir="${SCAN_DIR:-.}/.claudesec-prowler"
  local _has_ocsf=0 _f
  if [[ -d "$prowler_dir" ]]; then
    for _f in "$prowler_dir"/prowler-*.ocsf.json; do
      [[ -f "$_f" ]] && _has_ocsf=1 && break
    done
  fi
  [[ "$_has_ocsf" == "1" ]] || return 0
  command -v python3 &>/dev/null || return 0
  timeout 10 python3 "$(dirname "${BASH_SOURCE[0]}")/prowler_compliance_summary.py" "$prowler_dir" 2>/dev/null || true
}
