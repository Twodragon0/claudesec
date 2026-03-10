#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Prowler Integration
# Leverages prowler-cloud/prowler for deep security scanning across:
#   AWS, Azure, GCP, Kubernetes, GitHub, M365, Cloudflare, IaC, LLM,
#   OpenStack, NHN, OCI, and more (15+ providers)
# ============================================================================

# Check if prowler is installed
if ! has_command prowler; then
  skip "PROWLER-001" "Prowler cloud security scan" "Prowler not installed (pip install prowler)"
  return 0 2>/dev/null || exit 0
fi

_prowler_version=$(prowler -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
info "Prowler v${_prowler_version} detected"

# ── Configuration ──────────────────────────────────────────────────────────

PROWLER_OUTPUT_DIR="${SCAN_DIR}/.claudesec-prowler"
PROWLER_SEVERITY="${PROWLER_SEVERITY:-high critical}"
PROWLER_TIMEOUT="${PROWLER_TIMEOUT:-600}"
PROWLER_MAX_FINDINGS="${PROWLER_MAX_FINDINGS:-50}"

mkdir -p "$PROWLER_OUTPUT_DIR" 2>/dev/null || true

# ── Helper: Run prowler and parse JSON-OCSF output ────────────────────────

_prowler_scan() {
  local provider="$1"
  shift
  local extra_args=("$@")
  local output_file="${PROWLER_OUTPUT_DIR}/prowler-${provider}.json"

  # Run prowler with JSON-OCSF output, no banner, severity filter
  # Note: prowler writes output only on completion, so we allow full execution
  if has_command timeout; then
    timeout "$PROWLER_TIMEOUT" prowler "$provider" \
      -M json-ocsf \
      -F "prowler-${provider}" \
      -o "$PROWLER_OUTPUT_DIR" \
      --severity $PROWLER_SEVERITY \
      --status FAIL \
      -b \
      --no-color \
      "${extra_args[@]}" &>/dev/null || true
  elif has_command gtimeout; then
    gtimeout "$PROWLER_TIMEOUT" prowler "$provider" \
      -M json-ocsf \
      -F "prowler-${provider}" \
      -o "$PROWLER_OUTPUT_DIR" \
      --severity $PROWLER_SEVERITY \
      --status FAIL \
      -b \
      --no-color \
      "${extra_args[@]}" &>/dev/null || true
  else
    prowler "$provider" \
      -M json-ocsf \
      -F "prowler-${provider}" \
      -o "$PROWLER_OUTPUT_DIR" \
      --severity $PROWLER_SEVERITY \
      --status FAIL \
      -b \
      --no-color \
      "${extra_args[@]}" &>/dev/null || true
  fi

  # Find the output file (prowler names it: prowler-{provider}.ocsf.json)
  local json_file="${PROWLER_OUTPUT_DIR}/prowler-${provider}.ocsf.json"

  if [[ ! -f "$json_file" ]]; then
    # Try alternate naming pattern (prowler may append account/date info)
    json_file=$(find "$PROWLER_OUTPUT_DIR" -name "prowler-${provider}*.ocsf.json" 2>/dev/null | sort -r | head -1 || true)
  fi
  if [[ -z "$json_file" ]]; then
    json_file=$(find "$PROWLER_OUTPUT_DIR" -name "*${provider}*.json" -not -name "*.csv" 2>/dev/null | sort -r | head -1 || true)
  fi

  echo "$json_file"
}

# Parse prowler JSON-OCSF findings and report via ClaudeSec
_prowler_report() {
  local provider="$1" json_file="$2" check_id_prefix="$3"
  local total=0 critical=0 high=0 medium=0

  if [[ ! -f "$json_file" || ! -s "$json_file" ]]; then
    warn "${check_id_prefix}-000" "Prowler ${provider} scan produced no output" \
      "Check authentication and permissions for ${provider}"
    return
  fi

  # Count findings by severity using grep (handles pretty-printed JSON)
  total=$(grep -c '"status_code": *"FAIL"' "$json_file" 2>/dev/null || echo 0)

  # For severity, find FAIL blocks and count nearby severity lines
  # Use awk to pair status_code with severity within each finding object
  local sev_counts
  sev_counts=$(awk '
    /"severity":/ { sev=$0; gsub(/.*"severity": *"/, "", sev); gsub(/".*/, "", sev); current_sev=sev }
    /"status_code": *"FAIL"/ { if (current_sev) counts[current_sev]++ }
    END { for (s in counts) print s, counts[s] }
  ' "$json_file" 2>/dev/null || true)

  critical=$(echo "$sev_counts" | awk '/^Critical / {print $2}')
  high=$(echo "$sev_counts" | awk '/^High / {print $2}')
  medium=$(echo "$sev_counts" | awk '/^Medium / {print $2}')
  critical=${critical:-0}
  high=${high:-0}
  medium=${medium:-0}

  if [[ $total -eq 0 ]]; then
    pass "${check_id_prefix}-001" "Prowler ${provider}: No high/critical findings"
    return
  fi

  # Report summary
  local severity="high"
  [[ $critical -gt 0 ]] && severity="critical"

  local details="Prowler found ${total} issue(s): ${critical} critical, ${high} high, ${medium} medium"

  # Extract top findings for remediation advice (handles pretty-printed JSON)
  # Use literal \n (not real newlines) so pipe-delimited storage works correctly
  local top_findings=""
  top_findings=$(awk '
    /"event_code":/ { gsub(/.*"event_code": *"/, ""); gsub(/".*/, ""); code=$0 }
    /"severity":/ { gsub(/.*"severity": *"/, ""); gsub(/".*/, ""); sev=$0 }
    /"message":/ { gsub(/.*"message": *"/, ""); gsub(/".*/, ""); msg=$0 }
    /"status_code": *"FAIL"/ {
      if (count < 15 && msg != "") {
        if (code != "") printf "\\n    [%s] (%s) %s", sev, code, msg
        else printf "\\n    [%s] %s", sev, msg
        count++
      }
    }
  ' "$json_file" 2>/dev/null || true)

  fail "${check_id_prefix}-001" "Prowler ${provider}: ${total} security finding(s)" "$severity" \
    "${details}${top_findings}" \
    "Run: prowler ${provider} --severity ${PROWLER_SEVERITY} for full details"
}

# ── Provider Scans ─────────────────────────────────────────────────────────

# Touch a marker file for finding newly created output files
touch "$PROWLER_OUTPUT_DIR/.scan-marker" 2>/dev/null || true

# ── PROWLER AWS ────────────────────────────────────────────────────────────

if has_aws_credentials 2>/dev/null; then
  info "Prowler: Scanning AWS (profile: ${AWS_PROFILE:-default})"
  _aws_json=$(_prowler_scan "aws" ${AWS_PROFILE:+--profile "$AWS_PROFILE"})
  _prowler_report "AWS" "$_aws_json" "PROWLER-AWS"
elif [[ -f "${AWS_CONFIG_FILE:-$HOME/.aws/config}" ]]; then
  skip "PROWLER-AWS-001" "Prowler AWS scan" "AWS credentials not configured (use --aws-profile or --aws-sso)"
else
  skip "PROWLER-AWS-001" "Prowler AWS scan" "AWS not configured"
fi

# ── PROWLER Azure ──────────────────────────────────────────────────────────

if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
  info "Prowler: Scanning Azure"
  _azure_json=$(_prowler_scan "azure" --sp-env-auth)
  _prowler_report "Azure" "$_azure_json" "PROWLER-AZ"
elif has_command az && az account show &>/dev/null; then
  info "Prowler: Scanning Azure (CLI auth)"
  _azure_json=$(_prowler_scan "azure" --az-cli-auth)
  _prowler_report "Azure" "$_azure_json" "PROWLER-AZ"
else
  skip "PROWLER-AZ-001" "Prowler Azure scan" "Azure not configured (az login or set AZURE_CLIENT_ID)"
fi

# ── PROWLER GCP ────────────────────────────────────────────────────────────

if has_gcp_credentials 2>/dev/null; then
  info "Prowler: Scanning GCP"
  _gcp_json=$(_prowler_scan "gcp")
  _prowler_report "GCP" "$_gcp_json" "PROWLER-GCP"
elif [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  info "Prowler: Scanning GCP (service account)"
  _gcp_json=$(_prowler_scan "gcp")
  _prowler_report "GCP" "$_gcp_json" "PROWLER-GCP"
else
  skip "PROWLER-GCP-001" "Prowler GCP scan" "GCP not configured (gcloud auth or set GOOGLE_APPLICATION_CREDENTIALS)"
fi

# ── PROWLER Kubernetes ─────────────────────────────────────────────────────

if has_kubectl_access 2>/dev/null; then
  _k8s_ctx=$(kubectl_current_context)
  info "Prowler: Scanning Kubernetes (context: ${_k8s_ctx})"
  _k8s_args=()
  [[ -n "$_k8s_ctx" ]] && _k8s_args+=(--context "$_k8s_ctx")
  _k8s_json=$(_prowler_scan "kubernetes" "${_k8s_args[@]}")
  _prowler_report "Kubernetes" "$_k8s_json" "PROWLER-K8S"
else
  skip "PROWLER-K8S-001" "Prowler Kubernetes scan" "kubectl not connected"
fi

# ── PROWLER GitHub ─────────────────────────────────────────────────────────

if [[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]]; then
  _gh_prowler_args=()
  # Detect org from git remote
  if is_git_repo; then
    _gh_remote=$(git_remote_url)
    if [[ "$_gh_remote" =~ github\.com[:/]([^/]+)/ ]]; then
      _gh_org="${BASH_REMATCH[1]}"
      _gh_prowler_args+=(--organization "$_gh_org")
      info "Prowler: Scanning GitHub org ${_gh_org}"
    fi
  fi
  _gh_json=$(_prowler_scan "github" "${_gh_prowler_args[@]}")
  _prowler_report "GitHub" "$_gh_json" "PROWLER-GH"
elif has_command gh && gh auth status &>/dev/null 2>&1; then
  # Try to get a token from gh CLI for prowler
  _gh_token=$(gh auth token 2>/dev/null || echo "")
  if [[ -n "$_gh_token" ]]; then
    export GITHUB_PERSONAL_ACCESS_TOKEN="$_gh_token"
    _gh_prowler_args=()
    if is_git_repo; then
      _gh_remote=$(git_remote_url)
      if [[ "$_gh_remote" =~ github\.com[:/]([^/]+)/ ]]; then
        _gh_org="${BASH_REMATCH[1]}"
        _gh_prowler_args+=(--organization "$_gh_org")
        info "Prowler: Scanning GitHub org ${_gh_org} (via gh CLI token)"
      fi
    fi
    _gh_json=$(_prowler_scan "github" "${_gh_prowler_args[@]}")
    _prowler_report "GitHub" "$_gh_json" "PROWLER-GH"
    unset GITHUB_PERSONAL_ACCESS_TOKEN
  else
    skip "PROWLER-GH-001" "Prowler GitHub scan" "Set GITHUB_PERSONAL_ACCESS_TOKEN or gh auth login"
  fi
else
  skip "PROWLER-GH-001" "Prowler GitHub scan" "GitHub auth not configured"
fi

# ── PROWLER Microsoft 365 ─────────────────────────────────────────────────

if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" ]]; then
  info "Prowler: Scanning Microsoft 365"
  _m365_json=$(_prowler_scan "m365" --sp-env-auth)
  _prowler_report "M365" "$_m365_json" "PROWLER-M365"
elif has_command az && az account show &>/dev/null; then
  info "Prowler: Scanning Microsoft 365 (CLI auth)"
  _m365_json=$(_prowler_scan "m365" --az-cli-auth)
  _prowler_report "M365" "$_m365_json" "PROWLER-M365"
else
  skip "PROWLER-M365-001" "Prowler M365 scan" "Set AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET"
fi

# ── PROWLER Cloudflare ─────────────────────────────────────────────────────

if [[ -n "${CLOUDFLARE_API_TOKEN:-}" || ( -n "${CLOUDFLARE_API_KEY:-}" && -n "${CLOUDFLARE_API_EMAIL:-}" ) ]]; then
  info "Prowler: Scanning Cloudflare"
  _cf_json=$(_prowler_scan "cloudflare")
  _prowler_report "Cloudflare" "$_cf_json" "PROWLER-CF"
elif [[ -n "${CF_API_TOKEN:-}" ]]; then
  # ClaudeSec uses CF_API_TOKEN, prowler expects CLOUDFLARE_API_TOKEN
  export CLOUDFLARE_API_TOKEN="${CF_API_TOKEN}"
  info "Prowler: Scanning Cloudflare"
  _cf_json=$(_prowler_scan "cloudflare")
  _prowler_report "Cloudflare" "$_cf_json" "PROWLER-CF"
  unset CLOUDFLARE_API_TOKEN
else
  skip "PROWLER-CF-001" "Prowler Cloudflare scan" "Set CLOUDFLARE_API_TOKEN or CF_API_TOKEN"
fi

# ── PROWLER IaC ────────────────────────────────────────────────────────────

# Check for IaC files in the scan directory
_has_iac=false
if [[ -n "$(find "$SCAN_DIR" -maxdepth 3 \( -name '*.tf' -o -name '*.yaml' -o -name '*.yml' -o -name 'Dockerfile' -o -name '*.template' \) \
  -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]]; then
  _has_iac=true
fi

if [[ "$_has_iac" == "true" ]]; then
  info "Prowler: Scanning IaC in ${SCAN_DIR}"
  _iac_json=$(_prowler_scan "iac" --scan-path "$SCAN_DIR")
  _prowler_report "IaC" "$_iac_json" "PROWLER-IAC"
else
  skip "PROWLER-IAC-001" "Prowler IaC scan" "No IaC files found (Terraform, K8s YAML, Dockerfile)"
fi

# ── PROWLER LLM ────────────────────────────────────────────────────────────

if has_command promptfoo && [[ -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" ]]; then
  info "Prowler: Running LLM red-team checks"
  _llm_json=$(_prowler_scan "llm")
  _prowler_report "LLM" "$_llm_json" "PROWLER-LLM"
else
  skip "PROWLER-LLM-001" "Prowler LLM red-team" "Requires promptfoo + OPENAI_API_KEY or ANTHROPIC_API_KEY"
fi

# ── PROWLER OpenStack ──────────────────────────────────────────────────────

if [[ -n "${OS_AUTH_URL:-}" || -f "$HOME/.config/openstack/clouds.yaml" ]]; then
  info "Prowler: Scanning OpenStack"
  _os_args=()
  if [[ -f "$HOME/.config/openstack/clouds.yaml" ]]; then
    _os_cloud=$(grep -oE '^  [a-zA-Z0-9_-]+:' "$HOME/.config/openstack/clouds.yaml" 2>/dev/null | head -1 | tr -d ' :' || echo "")
    [[ -n "$_os_cloud" ]] && _os_args+=(--clouds-yaml-cloud "$_os_cloud")
  fi
  _os_json=$(_prowler_scan "openstack" "${_os_args[@]}")
  _prowler_report "OpenStack" "$_os_json" "PROWLER-OS"
else
  skip "PROWLER-OS-001" "Prowler OpenStack scan" "Set OS_AUTH_URL or configure clouds.yaml"
fi

# ── PROWLER NHN Cloud ──────────────────────────────────────────────────────

# NHN Cloud uses OpenStack-compatible APIs
if [[ -n "${NHN_API_URL:-}" || -n "${OS_AUTH_URL:-}" ]] && \
   [[ "${OS_AUTH_URL:-}" == *"nhncloud"* || "${OS_AUTH_URL:-}" == *"toast"* || -n "${NHN_API_URL:-}" ]]; then
  info "Prowler: Scanning NHN Cloud (via OpenStack provider)"
  _nhn_args=()
  [[ -n "${NHN_API_URL:-}" ]] && export OS_AUTH_URL="$NHN_API_URL"
  if [[ -f "$HOME/.config/openstack/clouds.yaml" ]]; then
    _nhn_cloud=$(grep -B1 -A5 'nhn\|toast\|nhncloud' "$HOME/.config/openstack/clouds.yaml" 2>/dev/null | \
      grep -oE '^  [a-zA-Z0-9_-]+:' | head -1 | tr -d ' :' || echo "")
    [[ -n "$_nhn_cloud" ]] && _nhn_args+=(--clouds-yaml-cloud "$_nhn_cloud")
  fi
  _nhn_json=$(_prowler_scan "openstack" "${_nhn_args[@]}")
  _prowler_report "NHN Cloud" "$_nhn_json" "PROWLER-NHN"
else
  skip "PROWLER-NHN-001" "Prowler NHN Cloud scan" "Set OS_AUTH_URL (NHN Cloud endpoint) or configure clouds.yaml"
fi

# ── Authentication Status Summary ─────────────────────────────────────────

if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
  echo ""
  echo -e "  ${DIM}──── Prowler Provider Status ────${NC}"

  _prowler_providers=(
    "aws:AWS:AWS_PROFILE or aws credentials"
    "azure:Azure:AZURE_CLIENT_ID or az login"
    "gcp:GCP:gcloud auth or GOOGLE_APPLICATION_CREDENTIALS"
    "kubernetes:K8s:kubectl context"
    "github:GitHub:GITHUB_PERSONAL_ACCESS_TOKEN or gh auth"
    "m365:M365:AZURE_CLIENT_ID + TENANT_ID + SECRET"
    "cloudflare:Cloudflare:CLOUDFLARE_API_TOKEN or CF_API_TOKEN"
    "iac:IaC:Terraform/K8s/Docker files in scan dir"
    "llm:LLM:promptfoo + OPENAI_API_KEY"
    "openstack:OpenStack:OS_AUTH_URL or clouds.yaml"
    "nhn:NHN Cloud:OS_AUTH_URL (NHN endpoint) or clouds.yaml"
  )

  for entry in "${_prowler_providers[@]}"; do
    IFS=':' read -r _prov _label _hint <<< "$entry"
    _status_icon="${DIM}○"
    case "$_prov" in
      aws) has_aws_credentials 2>/dev/null && _status_icon="${GREEN}●" ;;
      azure) [[ -n "${AZURE_CLIENT_ID:-}" ]] || (has_command az && az account show &>/dev/null) && _status_icon="${GREEN}●" ;;
      gcp) has_gcp_credentials 2>/dev/null && _status_icon="${GREEN}●" ;;
      kubernetes) has_kubectl_access 2>/dev/null && _status_icon="${GREEN}●" ;;
      github) [[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]] || (has_command gh && gh auth status &>/dev/null 2>&1) && _status_icon="${GREEN}●" ;;
      m365) [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" ]] && _status_icon="${GREEN}●" ;;
      cloudflare) [[ -n "${CLOUDFLARE_API_TOKEN:-}${CF_API_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      iac) [[ "$_has_iac" == "true" ]] && _status_icon="${GREEN}●" ;;
      llm) has_command promptfoo && [[ -n "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      openstack) [[ -n "${OS_AUTH_URL:-}" || -f "$HOME/.config/openstack/clouds.yaml" ]] && _status_icon="${GREEN}●" ;;
      nhn) [[ "${OS_AUTH_URL:-}" == *"nhn"* || "${OS_AUTH_URL:-}" == *"toast"* || -n "${NHN_API_URL:-}" ]] && _status_icon="${GREEN}●" ;;
    esac
    printf "  ${_status_icon}${NC} %-12s ${DIM}%s${NC}\n" "$_label" "$_hint"
  done
  echo ""
fi

# Clean up old scan marker
rm -f "$PROWLER_OUTPUT_DIR/.scan-marker" 2>/dev/null || true
