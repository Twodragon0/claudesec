#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Prowler Integration (Full)
# Leverages prowler-cloud/prowler for deep security scanning across 16 providers:
#   AWS, Azure, GCP, Kubernetes, GitHub, M365, Google Workspace, Cloudflare,
#   MongoDB Atlas, Oracle Cloud, Alibaba Cloud, OpenStack, NHN Cloud,
#   IaC, LLM, Image
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
PROWLER_SEVERITY="${PROWLER_SEVERITY:-medium high critical}"
PROWLER_TIMEOUT="${PROWLER_TIMEOUT:-600}"
PROWLER_MAX_FINDINGS="${PROWLER_MAX_FINDINGS:-0}"  # 0 = unlimited

mkdir -p "$PROWLER_OUTPUT_DIR" 2>/dev/null || true

# ── Helper: Run prowler scan ──────────────────────────────────────────────

_prowler_scan() {
  local provider="$1"
  shift
  local extra_args=("$@")
  local output_file="${PROWLER_OUTPUT_DIR}/prowler-${provider}.json"

  # Run prowler with JSON-OCSF output, severity filter, FAIL only
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

  # Find the output file
  local json_file="${PROWLER_OUTPUT_DIR}/prowler-${provider}.ocsf.json"

  if [[ ! -f "$json_file" ]]; then
    json_file=$(find "$PROWLER_OUTPUT_DIR" -name "prowler-${provider}*.ocsf.json" 2>/dev/null | sort -r | head -1 || true)
  fi
  if [[ -z "$json_file" ]]; then
    json_file=$(find "$PROWLER_OUTPUT_DIR" -name "*${provider}*.json" -not -name "*.csv" 2>/dev/null | sort -r | head -1 || true)
  fi

  echo "$json_file"
}

# ── Helper: Parse JSON-OCSF and report ALL findings with full details ─────

_prowler_report() {
  local provider="$1" json_file="$2" check_id_prefix="$3"
  local total=0 critical=0 high=0 medium=0 low=0

  if [[ ! -f "$json_file" || ! -s "$json_file" ]]; then
    warn "${check_id_prefix}-000" "Prowler ${provider} scan produced no output" \
      "Check authentication and permissions for ${provider}"
    return
  fi

  # Count total FAIL findings
  total=$(grep -c '"status_code": *"FAIL"' "$json_file" 2>/dev/null || echo 0)

  # Count by severity
  local sev_counts
  sev_counts=$(awk '
    /"severity":/ { sev=$0; gsub(/.*"severity": *"/, "", sev); gsub(/".*/, "", sev); current_sev=sev }
    /"status_code": *"FAIL"/ { if (current_sev) counts[current_sev]++ }
    END { for (s in counts) print s, counts[s] }
  ' "$json_file" 2>/dev/null || true)

  critical=$(echo "$sev_counts" | awk '/^Critical / {print $2}')
  high=$(echo "$sev_counts" | awk '/^High / {print $2}')
  medium=$(echo "$sev_counts" | awk '/^Medium / {print $2}')
  low=$(echo "$sev_counts" | awk '/^Low / {print $2}')
  critical=${critical:-0}; high=${high:-0}; medium=${medium:-0}; low=${low:-0}

  if [[ $total -eq 0 ]]; then
    pass "${check_id_prefix}-001" "Prowler ${provider}: No findings above threshold"
    return
  fi

  # Determine overall severity
  local severity="medium"
  [[ $high -gt 0 ]] && severity="high"
  [[ $critical -gt 0 ]] && severity="critical"

  # Extract ALL findings with full details from JSON-OCSF
  # Fields: event_code, severity, message, risk_details, remediation, resources, compliance
  # Uses literal \n (printf "\\n") to keep pipe-delimited storage intact
  local max_limit="${PROWLER_MAX_FINDINGS:-0}"
  local all_findings=""
  all_findings=$(awk -v max="$max_limit" '
    BEGIN { count=0; code=""; sev=""; msg=""; risk=""; remed_text=""; remed_url=""; res=""; compliance="" }

    /"event_code":/ { gsub(/.*"event_code": *"/, ""); gsub(/".*/, ""); code=$0 }
    /"severity":/ { gsub(/.*"severity": *"/, ""); gsub(/".*/, ""); sev=$0 }
    /"message":/ { gsub(/.*"message": *"/, ""); gsub(/".*/, ""); msg=$0 }

    # risk_details
    /"risk_details":/ { gsub(/.*"risk_details": *"/, ""); gsub(/".*/, ""); risk=$0 }

    # remediation recommendation & url
    /"recommendation":/ { gsub(/.*"recommendation": *"/, ""); gsub(/".*/, ""); remed_text=$0 }
    /"url":/ {
      if (remed_text != "" && remed_url == "") {
        gsub(/.*"url": *"/, ""); gsub(/".*/, ""); remed_url=$0
      }
    }

    # resource uid
    /"uid":/ {
      if (res == "") { gsub(/.*"uid": *"/, ""); gsub(/".*/, ""); res=$0 }
    }

    # compliance frameworks (inside unmapped)
    /"compliance":/ { gsub(/.*"compliance": */, ""); gsub(/[{}\[\]]/, ""); compliance=$0 }

    /"status_code": *"FAIL"/ {
      if (msg != "" && (max == 0 || count < max)) {
        # Build detail block with literal \n separators
        printf "\\n    [%s] (%s) %s", sev, code, msg
        if (risk != "") printf "\\n      Risk: %s", risk
        if (remed_text != "") printf "\\n      Fix: %s", remed_text
        if (remed_url != "") printf "\\n      Ref: %s", remed_url
        if (res != "") printf "\\n      Resource: %s", res
        count++
      }
      # Reset for next finding
      code=""; sev=""; msg=""; risk=""; remed_text=""; remed_url=""; res=""; compliance=""
    }
  ' "$json_file" 2>/dev/null || true)

  # Build service grouping summary
  local service_summary=""
  service_summary=$(awk '
    /"event_code":/ { gsub(/.*"event_code": *"/, ""); gsub(/".*/, ""); code=$0 }
    /"severity":/ { gsub(/.*"severity": *"/, ""); gsub(/".*/, ""); sev=$0 }
    /"status_code": *"FAIL"/ {
      if (code != "") {
        # Group by service prefix (e.g., iam, s3, ec2, lambda)
        split(code, parts, "_")
        service = parts[1]
        svc_count[service]++
        svc_sev[service][sev]++
      }
      code=""; sev=""
    }
    END {
      n = asorti(svc_count, sorted)
      for (i = 1; i <= n; i++) {
        s = sorted[i]
        printf "\\n    %s: %d finding(s)", s, svc_count[s]
      }
    }
  ' "$json_file" 2>/dev/null || true)

  local details="Prowler ${provider}: ${total} finding(s) — ${critical} critical, ${high} high, ${medium} medium, ${low} low"
  [[ -n "$service_summary" ]] && details="${details}${service_summary}"
  details="${details}${all_findings}"

  fail "${check_id_prefix}-001" "Prowler ${provider}: ${total} security finding(s)" "$severity" \
    "${details}" \
    "Run: prowler ${provider} --severity ${PROWLER_SEVERITY} for full report"
}

# ── Provider Scans ─────────────────────────────────────────────────────────

touch "$PROWLER_OUTPUT_DIR/.scan-marker" 2>/dev/null || true

# ── AWS ────────────────────────────────────────────────────────────────────

if has_aws_credentials 2>/dev/null; then
  info "Prowler: Scanning AWS (profile: ${AWS_PROFILE:-default})"
  _aws_json=$(_prowler_scan "aws" ${AWS_PROFILE:+--profile "$AWS_PROFILE"})
  _prowler_report "AWS" "$_aws_json" "PROWLER-AWS"
elif [[ -f "${AWS_CONFIG_FILE:-$HOME/.aws/config}" ]]; then
  skip "PROWLER-AWS-001" "Prowler AWS scan" "AWS credentials not configured (use --aws-profile or --aws-sso)"
else
  skip "PROWLER-AWS-001" "Prowler AWS scan" "AWS not configured"
fi

# ── Azure ──────────────────────────────────────────────────────────────────

if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" ]]; then
  info "Prowler: Scanning Azure (service principal)"
  _azure_json=$(_prowler_scan "azure" --sp-env-auth)
  _prowler_report "Azure" "$_azure_json" "PROWLER-AZ"
elif has_command az && az account show &>/dev/null; then
  info "Prowler: Scanning Azure (CLI auth)"
  _azure_json=$(_prowler_scan "azure" --az-cli-auth)
  _prowler_report "Azure" "$_azure_json" "PROWLER-AZ"
else
  skip "PROWLER-AZ-001" "Prowler Azure scan" "Azure not configured (az login or set AZURE_CLIENT_ID)"
fi

# ── GCP ────────────────────────────────────────────────────────────────────

if has_gcp_credentials 2>/dev/null; then
  info "Prowler: Scanning GCP (gcloud auth)"
  _gcp_json=$(_prowler_scan "gcp")
  _prowler_report "GCP" "$_gcp_json" "PROWLER-GCP"
elif [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
  info "Prowler: Scanning GCP (service account key)"
  _gcp_json=$(_prowler_scan "gcp")
  _prowler_report "GCP" "$_gcp_json" "PROWLER-GCP"
else
  skip "PROWLER-GCP-001" "Prowler GCP scan" "GCP not configured (gcloud auth login or set GOOGLE_APPLICATION_CREDENTIALS)"
fi

# ── Kubernetes ─────────────────────────────────────────────────────────────

# Attempt credential refresh if not connected
if ! has_kubectl_access 2>/dev/null; then
  kubectl_ensure_access 2>/dev/null || true
fi

if has_kubectl_access 2>/dev/null; then
  _k8s_ctx=$(kubectl_current_context)
  _k8s_cluster_type=$(kubectl_detect_cluster_type "$_k8s_ctx")
  _k8s_server_ver=$(kubectl_server_version 2>/dev/null)
  _k8s_server=$($(_kubectl_cmd) config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo "unknown")

  info "Prowler: Scanning Kubernetes"
  info "  Context: ${_k8s_ctx} (${_k8s_cluster_type})"
  info "  Server: ${_k8s_server}"
  info "  Version: ${_k8s_server_ver}"

  _k8s_args=()
  [[ -n "$_k8s_ctx" ]] && _k8s_args+=(--context "$_k8s_ctx")

  # Pass kubeconfig if custom path is set
  if [[ -n "${KUBECONFIG:-}" && -f "${KUBECONFIG}" ]]; then
    _k8s_args+=(--kubeconfig "$KUBECONFIG")
    info "  Kubeconfig: ${KUBECONFIG}"
  fi

  # Namespace filter
  if [[ -n "${CLAUDESEC_KUBE_NAMESPACE:-}" ]]; then
    _k8s_args+=(--namespace "$CLAUDESEC_KUBE_NAMESPACE")
    info "  Namespace: ${CLAUDESEC_KUBE_NAMESPACE}"
  fi

  _k8s_json=$(_prowler_scan "kubernetes" "${_k8s_args[@]}")
  _prowler_report "Kubernetes" "$_k8s_json" "PROWLER-K8S"
else
  # Detailed skip message with auth guidance
  _k8s_skip_msg="kubectl not connected."

  # Check if kubectl is installed
  if ! has_command kubectl; then
    _k8s_skip_msg="kubectl not installed. Install: brew install kubectl"
  else
    # Show available kubeconfigs
    _k8s_configs=$(kubectl_discover_kubeconfigs 2>/dev/null || true)
    _k8s_contexts=$(kubectl_list_contexts 2>/dev/null || true)

    if [[ -n "$_k8s_contexts" ]]; then
      _ctx_list=$(echo "$_k8s_contexts" | head -5 | tr '\n' ', ' | sed 's/,$//')
      _k8s_skip_msg="kubectl not connected. Available contexts: ${_ctx_list}. Use --kubecontext <name>"
    elif [[ -n "$_k8s_configs" ]]; then
      _k8s_skip_msg="kubectl found but no contexts configured. Kubeconfig files found — use --kubeconfig <path>"
    else
      _k8s_skip_msg="kubectl found but no kubeconfig. Run: aws eks update-kubeconfig / gcloud container clusters get-credentials / az aks get-credentials"
    fi
  fi

  skip "PROWLER-K8S-001" "Prowler Kubernetes scan" "$_k8s_skip_msg"
fi

# ── GitHub ─────────────────────────────────────────────────────────────────

_gh_token_resolved=""
if [[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]]; then
  _gh_token_resolved="$GITHUB_PERSONAL_ACCESS_TOKEN"
elif has_command gh && gh auth status &>/dev/null 2>&1; then
  _gh_token_resolved=$(gh auth token 2>/dev/null || echo "")
fi

if [[ -n "$_gh_token_resolved" ]]; then
  export GITHUB_PERSONAL_ACCESS_TOKEN="$_gh_token_resolved"
  _gh_prowler_args=()
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
  # Restore original value
  if [[ -z "${GITHUB_PERSONAL_ACCESS_TOKEN_ORIG:-}" ]]; then
    unset GITHUB_PERSONAL_ACCESS_TOKEN
  fi
else
  skip "PROWLER-GH-001" "Prowler GitHub scan" "Set GITHUB_PERSONAL_ACCESS_TOKEN or run gh auth login"
fi

# ── Microsoft 365 ──────────────────────────────────────────────────────────

if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" ]]; then
  info "Prowler: Scanning Microsoft 365 (service principal)"
  _m365_json=$(_prowler_scan "m365" --sp-env-auth)
  _prowler_report "M365" "$_m365_json" "PROWLER-M365"
elif has_command az && az account show &>/dev/null; then
  info "Prowler: Scanning Microsoft 365 (CLI auth)"
  _m365_json=$(_prowler_scan "m365" --az-cli-auth)
  _prowler_report "M365" "$_m365_json" "PROWLER-M365"
else
  skip "PROWLER-M365-001" "Prowler M365 scan" "Set AZURE_CLIENT_ID + AZURE_TENANT_ID + AZURE_CLIENT_SECRET or az login"
fi

# ── Google Workspace ───────────────────────────────────────────────────────

if [[ -n "${GOOGLE_WORKSPACE_CUSTOMER_ID:-}" ]] && \
   { has_gcp_credentials 2>/dev/null || [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; }; then
  info "Prowler: Scanning Google Workspace (customer: ${GOOGLE_WORKSPACE_CUSTOMER_ID})"
  _gws_args=()
  [[ -n "${GOOGLE_WORKSPACE_CUSTOMER_ID:-}" ]] && _gws_args+=(--customer-id "$GOOGLE_WORKSPACE_CUSTOMER_ID")
  _gws_json=$(_prowler_scan "googleworkspace" "${_gws_args[@]}")
  _prowler_report "Google Workspace" "$_gws_json" "PROWLER-GWS"
elif has_gcp_credentials 2>/dev/null; then
  skip "PROWLER-GWS-001" "Prowler Google Workspace scan" "Set GOOGLE_WORKSPACE_CUSTOMER_ID (Google OAuth detected)"
else
  skip "PROWLER-GWS-001" "Prowler Google Workspace scan" "Requires Google OAuth (gcloud auth) + GOOGLE_WORKSPACE_CUSTOMER_ID"
fi

# ── Cloudflare ─────────────────────────────────────────────────────────────

if [[ -n "${CLOUDFLARE_API_TOKEN:-}" || ( -n "${CLOUDFLARE_API_KEY:-}" && -n "${CLOUDFLARE_API_EMAIL:-}" ) ]]; then
  info "Prowler: Scanning Cloudflare (API token)"
  _cf_json=$(_prowler_scan "cloudflare")
  _prowler_report "Cloudflare" "$_cf_json" "PROWLER-CF"
elif [[ -n "${CF_API_TOKEN:-}" ]]; then
  export CLOUDFLARE_API_TOKEN="${CF_API_TOKEN}"
  info "Prowler: Scanning Cloudflare (CF_API_TOKEN)"
  _cf_json=$(_prowler_scan "cloudflare")
  _prowler_report "Cloudflare" "$_cf_json" "PROWLER-CF"
  unset CLOUDFLARE_API_TOKEN
else
  skip "PROWLER-CF-001" "Prowler Cloudflare scan" "Set CLOUDFLARE_API_TOKEN or CF_API_TOKEN"
fi

# ── MongoDB Atlas ──────────────────────────────────────────────────────────

if [[ -n "${MONGODB_ATLAS_PUBLIC_KEY:-}" && -n "${MONGODB_ATLAS_PRIVATE_KEY:-}" ]]; then
  info "Prowler: Scanning MongoDB Atlas"
  _mongo_args=()
  [[ -n "${MONGODB_ATLAS_ORG_ID:-}" ]] && _mongo_args+=(--organization-id "$MONGODB_ATLAS_ORG_ID")
  _mongo_json=$(_prowler_scan "mongodbatlas" "${_mongo_args[@]}")
  _prowler_report "MongoDB Atlas" "$_mongo_json" "PROWLER-MONGO"
else
  skip "PROWLER-MONGO-001" "Prowler MongoDB Atlas scan" "Set MONGODB_ATLAS_PUBLIC_KEY + MONGODB_ATLAS_PRIVATE_KEY"
fi

# ── Oracle Cloud (OCI) ────────────────────────────────────────────────────

if [[ -f "$HOME/.oci/config" || -n "${OCI_CLI_AUTH:-}" ]]; then
  info "Prowler: Scanning Oracle Cloud (OCI)"
  _oci_json=$(_prowler_scan "oraclecloud")
  _prowler_report "Oracle Cloud" "$_oci_json" "PROWLER-OCI"
elif [[ -n "${OCI_TENANCY:-}" && -n "${OCI_USER:-}" && -n "${OCI_FINGERPRINT:-}" ]]; then
  info "Prowler: Scanning Oracle Cloud (env auth)"
  _oci_json=$(_prowler_scan "oraclecloud")
  _prowler_report "Oracle Cloud" "$_oci_json" "PROWLER-OCI"
else
  skip "PROWLER-OCI-001" "Prowler Oracle Cloud scan" "Configure ~/.oci/config or set OCI_TENANCY + OCI_USER + OCI_FINGERPRINT"
fi

# ── Alibaba Cloud ─────────────────────────────────────────────────────────

if [[ -n "${ALIBABA_CLOUD_ACCESS_KEY_ID:-}" && -n "${ALIBABA_CLOUD_ACCESS_KEY_SECRET:-}" ]]; then
  info "Prowler: Scanning Alibaba Cloud"
  _ali_json=$(_prowler_scan "alibabacloud")
  _prowler_report "Alibaba Cloud" "$_ali_json" "PROWLER-ALI"
elif [[ -f "$HOME/.aliyun/config.json" ]]; then
  info "Prowler: Scanning Alibaba Cloud (CLI config)"
  _ali_json=$(_prowler_scan "alibabacloud")
  _prowler_report "Alibaba Cloud" "$_ali_json" "PROWLER-ALI"
else
  skip "PROWLER-ALI-001" "Prowler Alibaba Cloud scan" "Set ALIBABA_CLOUD_ACCESS_KEY_ID + ALIBABA_CLOUD_ACCESS_KEY_SECRET"
fi

# ── OpenStack ──────────────────────────────────────────────────────────────

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

# ── NHN Cloud ──────────────────────────────────────────────────────────────

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

# ── IaC (Infrastructure as Code) ──────────────────────────────────────────

_has_iac=false
if [[ -n "$(find "$SCAN_DIR" -maxdepth 3 \( -name '*.tf' -o -name '*.yaml' -o -name '*.yml' -o -name 'Dockerfile' -o -name '*.template' -o -name '*.bicep' -o -name '*.cfn' \) \
  -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]]; then
  _has_iac=true
fi

if [[ "$_has_iac" == "true" ]]; then
  info "Prowler: Scanning IaC files in ${SCAN_DIR}"
  _iac_json=$(_prowler_scan "iac" --scan-path "$SCAN_DIR")
  _prowler_report "IaC" "$_iac_json" "PROWLER-IAC"
else
  skip "PROWLER-IAC-001" "Prowler IaC scan" "No IaC files found (Terraform, K8s YAML, Dockerfile, Bicep)"
fi

# ── LLM (AI Red-Team via promptfoo) ──────────────────────────────────────

if has_command promptfoo && [[ -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" ]]; then
  info "Prowler: Running LLM red-team checks"
  _llm_json=$(_prowler_scan "llm")
  _prowler_report "LLM" "$_llm_json" "PROWLER-LLM"
else
  skip "PROWLER-LLM-001" "Prowler LLM red-team" "Requires promptfoo + OPENAI_API_KEY or ANTHROPIC_API_KEY"
fi

# ── Container Image Scan ─────────────────────────────────────────────────

_scan_image="${PROWLER_IMAGE:-}"
if [[ -z "$_scan_image" ]]; then
  # Auto-detect from Dockerfile
  if [[ -f "${SCAN_DIR}/Dockerfile" ]]; then
    _scan_image=$(grep -oE '^FROM\s+\S+' "${SCAN_DIR}/Dockerfile" 2>/dev/null | tail -1 | awk '{print $2}' || echo "")
  fi
fi

if [[ -n "$_scan_image" ]]; then
  info "Prowler: Scanning container image ${_scan_image}"
  _img_json=$(_prowler_scan "image" --image "$_scan_image")
  _prowler_report "Image" "$_img_json" "PROWLER-IMG"
else
  skip "PROWLER-IMG-001" "Prowler Image scan" "Set PROWLER_IMAGE or add Dockerfile to scan dir"
fi

# ── Authentication Status Summary ─────────────────────────────────────────

if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
  echo ""
  echo -e "  ${DIM}──── Prowler Provider Status ────${NC}"

  _prowler_providers=(
    "aws:AWS:AWS_PROFILE or aws credentials"
    "azure:Azure:AZURE_CLIENT_ID or az login"
    "gcp:GCP:gcloud auth or GOOGLE_APPLICATION_CREDENTIALS"
    "kubernetes:K8s:kubectl context (--kubeconfig, --kubecontext)"
    "github:GitHub:GITHUB_PERSONAL_ACCESS_TOKEN or gh auth"
    "m365:M365:AZURE_CLIENT_ID + TENANT_ID + SECRET"
    "googleworkspace:G-Workspace:Google OAuth + GOOGLE_WORKSPACE_CUSTOMER_ID"
    "cloudflare:Cloudflare:CLOUDFLARE_API_TOKEN or CF_API_TOKEN"
    "mongodbatlas:MongoDB:MONGODB_ATLAS_PUBLIC_KEY + PRIVATE_KEY"
    "oraclecloud:OCI:~/.oci/config or OCI_TENANCY"
    "alibabacloud:Alibaba:ALIBABA_CLOUD_ACCESS_KEY_ID"
    "openstack:OpenStack:OS_AUTH_URL or clouds.yaml"
    "nhn:NHN Cloud:OS_AUTH_URL (NHN endpoint) or clouds.yaml"
    "iac:IaC:Terraform/K8s/Docker files in scan dir"
    "llm:LLM:promptfoo + OPENAI_API_KEY"
    "image:Image:PROWLER_IMAGE or Dockerfile"
  )

  for entry in "${_prowler_providers[@]}"; do
    IFS=':' read -r _prov _label _hint <<< "$entry"
    _status_icon="${DIM}○"
    case "$_prov" in
      aws) has_aws_credentials 2>/dev/null && _status_icon="${GREEN}●" ;;
      azure) { [[ -n "${AZURE_CLIENT_ID:-}" ]] || { has_command az && az account show &>/dev/null; }; } && _status_icon="${GREEN}●" ;;
      gcp) { has_gcp_credentials 2>/dev/null || [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; } && _status_icon="${GREEN}●" ;;
      kubernetes) has_kubectl_access 2>/dev/null && _status_icon="${GREEN}●" ;;
      github) { [[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ]] || { has_command gh && gh auth status &>/dev/null 2>&1; }; } && _status_icon="${GREEN}●" ;;
      m365) [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" ]] && _status_icon="${GREEN}●" ;;
      googleworkspace) [[ -n "${GOOGLE_WORKSPACE_CUSTOMER_ID:-}" ]] && { has_gcp_credentials 2>/dev/null || [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; } && _status_icon="${GREEN}●" ;;
      cloudflare) [[ -n "${CLOUDFLARE_API_TOKEN:-}${CF_API_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      mongodbatlas) [[ -n "${MONGODB_ATLAS_PUBLIC_KEY:-}" && -n "${MONGODB_ATLAS_PRIVATE_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      oraclecloud) { [[ -f "$HOME/.oci/config" ]] || [[ -n "${OCI_CLI_AUTH:-}" ]] || [[ -n "${OCI_TENANCY:-}" ]]; } && _status_icon="${GREEN}●" ;;
      alibabacloud) { [[ -n "${ALIBABA_CLOUD_ACCESS_KEY_ID:-}" ]] || [[ -f "$HOME/.aliyun/config.json" ]]; } && _status_icon="${GREEN}●" ;;
      openstack) [[ -n "${OS_AUTH_URL:-}" || -f "$HOME/.config/openstack/clouds.yaml" ]] && _status_icon="${GREEN}●" ;;
      nhn) [[ "${OS_AUTH_URL:-}" == *"nhn"* || "${OS_AUTH_URL:-}" == *"toast"* || -n "${NHN_API_URL:-}" ]] && _status_icon="${GREEN}●" ;;
      iac) [[ "$_has_iac" == "true" ]] && _status_icon="${GREEN}●" ;;
      llm) has_command promptfoo && [[ -n "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      image) [[ -n "${PROWLER_IMAGE:-}" || -f "${SCAN_DIR}/Dockerfile" ]] && _status_icon="${GREEN}●" ;;
    esac
    printf "  ${_status_icon}${NC} %-12s ${DIM}%s${NC}\n" "$_label" "$_hint"
  done
  echo ""
fi

# Clean up
rm -f "$PROWLER_OUTPUT_DIR/.scan-marker" 2>/dev/null || true
