#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Check helper library
# ============================================================================

# Check if a command exists
has_command() {
  command -v "$1" &>/dev/null
}

# Check if a file exists in the scan directory
has_file() {
  [[ -f "$SCAN_DIR/$1" ]]
}

# Check if a directory exists
has_dir() {
  [[ -d "$SCAN_DIR/$1" ]]
}

# Search for a pattern in files
file_contains() {
  local file="$1" pattern="$2"
  if [[ -f "$SCAN_DIR/$file" ]]; then
    grep -qE "$pattern" "$SCAN_DIR/$file" 2>/dev/null
    return $?
  fi
  return 1
}

# Search for pattern across files matching a glob
files_contain() {
  local glob="$1" pattern="$2" result
  if [[ "$glob" == */* ]]; then
    result=$(find "$SCAN_DIR" -path "$SCAN_DIR/$glob" -not -path "*/node_modules/*" -not -path "*/.git/*" \
      -exec grep -lE "$pattern" {} \; 2>/dev/null | head -1 || true)
  else
    result=$(find "$SCAN_DIR" -name "$glob" -not -path "*/node_modules/*" -not -path "*/.git/*" \
      -exec grep -lE "$pattern" {} \; 2>/dev/null | head -1 || true)
  fi
  [[ -n "$result" ]]
}

# Count files matching a pattern
count_files() {
  local glob="$1"
  find "$SCAN_DIR" -name "$glob" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' '
}

# Check if running in a git repo
is_git_repo() {
  git -C "$SCAN_DIR" rev-parse --is-inside-work-tree &>/dev/null
}

# Get git remote URL
git_remote_url() {
  git -C "$SCAN_DIR" remote get-url origin 2>/dev/null || echo ""
}

# ── AWS credential helpers ──────────────────────────────────────────────────

# Check AWS credentials availability (STS call)
has_aws_credentials() {
  has_command aws && aws sts get-caller-identity &>/dev/null
}

# Attempt AWS SSO login if configured but session expired
aws_sso_ensure_login() {
  has_command aws || return 1

  local profile="${AWS_PROFILE:-}"

  # 1. Already authenticated — nothing to do
  if aws sts get-caller-identity &>/dev/null; then
    return 0
  fi

  # 2. Discover SSO profiles from AWS config
  local config_file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  [[ -f "$config_file" ]] || return 1

  local sso_profiles
  sso_profiles=$(grep -E '^\[profile ' "$config_file" 2>/dev/null | \
    while read -r line; do
      local p
      p=$(echo "$line" | sed 's/\[profile //;s/\]//')
      if grep -A20 "^\[profile $p\]" "$config_file" 2>/dev/null | grep -q 'sso_start_url\|sso_session'; then
        echo "$p"
      fi
    done || true)

  # Also check [default] for SSO config
  if grep -A10 '^\[default\]' "$config_file" 2>/dev/null | grep -q 'sso_start_url\|sso_session'; then
    sso_profiles="default${sso_profiles:+ $sso_profiles}"
  fi

  [[ -z "$sso_profiles" ]] && return 1

  # 3. If AWS_PROFILE is set and is an SSO profile, try login
  if [[ -n "$profile" ]]; then
    echo -e "  ${YELLOW}⟳${NC} AWS SSO session expired for profile ${BOLD}$profile${NC}"
    echo -e "  ${DIM}Running: aws sso login --profile $profile${NC}"
    if aws sso login --profile "$profile"; then
      export AWS_DEFAULT_PROFILE="$profile"
      echo -e "  ${GREEN}✓${NC} AWS SSO login successful (profile: $profile)"
      return 0
    fi
    return 1
  fi

  # 4. No profile set — offer available SSO profiles
  echo -e "  ${YELLOW}⟳${NC} AWS credentials not found. Available SSO profiles:"
  local first_profile=""
  for p in $sso_profiles; do
    local sso_url
    if [[ "$p" == "default" ]]; then
      sso_url=$(grep -A10 '^\[default\]' "$config_file" | grep 'sso_start_url' | head -1 | awk '{print $NF}' || true)
    else
      sso_url=$(grep -A20 "^\[profile $p\]" "$config_file" | grep 'sso_start_url' | head -1 | awk '{print $NF}' || true)
    fi
    echo -e "    ${CYAN}▸${NC} $p ${DIM}($sso_url)${NC}"
    [[ -z "$first_profile" ]] && first_profile="$p"
  done

  # Auto-login with the first SSO profile
  if [[ -n "$first_profile" ]]; then
    echo -e "  ${DIM}Running: aws sso login --profile $first_profile${NC}"
    if aws sso login --profile "$first_profile" 2>/dev/null; then
      export AWS_PROFILE="$first_profile"
      echo -e "  ${GREEN}✓${NC} AWS SSO login successful (profile: $first_profile)"
      return 0
    fi
  fi

  return 1
}

# Get AWS identity info for display
aws_identity_info() {
  local identity
  identity=$(aws sts get-caller-identity --output json 2>/dev/null || echo "{}")
  local account arn
  account=$(echo "$identity" | grep -o '"Account"[^,]*' | cut -d'"' -f4 || true)
  arn=$(echo "$identity" | grep -o '"Arn"[^,]*' | cut -d'"' -f4 || true)
  echo "${account:-unknown}|${arn:-unknown}"
}

# ── GCP credential helpers ─────────────────────────────────────────────────

# Check GCP credentials
has_gcp_credentials() {
  has_command gcloud && gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .
}

# ── Azure credential helpers ───────────────────────────────────────────────

# Check Azure credentials
has_azure_credentials() {
  has_command az && az account show &>/dev/null
}

# ── Kubernetes credential helpers ───────────────────────────────────────────

# Check kubectl access (tries current context)
has_kubectl_access() {
  has_command kubectl && kubectl cluster-info &>/dev/null
}

# List available kubeconfig contexts
kubectl_list_contexts() {
  has_command kubectl || return 1
  kubectl config get-contexts -o name 2>/dev/null || true
}

# Get current kubectl context name
kubectl_current_context() {
  has_command kubectl || return 1
  kubectl config current-context 2>/dev/null || echo ""
}

# Ensure kubectl has a valid connection; attempt credential refresh if needed
kubectl_ensure_access() {
  has_command kubectl || return 1

  # 1. Already connected
  if kubectl cluster-info &>/dev/null; then
    return 0
  fi

  local current_ctx
  current_ctx=$(kubectl_current_context)

  # 2. Discover available contexts from kubeconfig
  local kubeconfig="${KUBECONFIG:-$HOME/.kube/config}"
  if [[ ! -f "$kubeconfig" ]]; then
    # Check for split kubeconfig files
    local kube_dir="$HOME/.kube"
    if [[ -d "$kube_dir" ]]; then
      local kube_files
      kube_files=$(find "$kube_dir" -name '*.yaml' -o -name '*.yml' -o -name 'config*' 2>/dev/null | head -10 || true)
      if [[ -n "$kube_files" ]]; then
        echo -e "  ${DIM}Found kubeconfig files in $kube_dir${NC}"
      fi
    fi
  fi

  local contexts
  contexts=$(kubectl_list_contexts)
  [[ -z "$contexts" ]] && return 1

  echo -e "  ${YELLOW}⟳${NC} kubectl not connected. Available contexts:"
  local ctx_count=0
  while IFS= read -r ctx; do
    [[ -z "$ctx" ]] && continue
    ctx_count=$((ctx_count + 1))
    local marker="  "
    [[ "$ctx" == "$current_ctx" ]] && marker="→ "
    echo -e "    ${CYAN}${marker}${NC}$ctx"
  done <<< "$contexts"

  # 3. Try current context first — refresh credentials
  if [[ -n "$current_ctx" ]]; then
    echo -e "  ${DIM}Attempting to connect to context: $current_ctx${NC}"

    # AWS EKS: refresh kubeconfig if context looks like EKS
    if echo "$current_ctx" | grep -qiE 'eks|arn:aws'; then
      local cluster_name region
      cluster_name=$(echo "$current_ctx" | sed 's/.*\///' | sed 's/arn:aws:eks:[^:]*:[^:]*:cluster\///' || true)
      region=$(echo "$current_ctx" | grep -oE '[a-z]+-[a-z]+-[0-9]+' | head -1 || true)
      if [[ -n "$cluster_name" ]]; then
        echo -e "  ${DIM}Refreshing EKS credentials: $cluster_name${NC}"
        aws eks update-kubeconfig --name "$cluster_name" ${region:+--region "$region"} &>/dev/null || true
      fi
    fi

    # GKE: refresh if context looks like GKE
    if echo "$current_ctx" | grep -qiE 'gke_'; then
      local gke_project gke_zone gke_cluster
      IFS='_' read -r _ gke_project gke_zone gke_cluster <<< "$current_ctx"
      if [[ -n "$gke_cluster" ]]; then
        echo -e "  ${DIM}Refreshing GKE credentials: $gke_cluster${NC}"
        gcloud container clusters get-credentials "$gke_cluster" \
          --zone "$gke_zone" --project "$gke_project" &>/dev/null || true
      fi
    fi

    # Test again after refresh
    if kubectl cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $current_ctx)"
      return 0
    fi
  fi

  # 4. Try other contexts
  while IFS= read -r ctx; do
    [[ -z "$ctx" || "$ctx" == "$current_ctx" ]] && continue
    kubectl config use-context "$ctx" &>/dev/null || continue
    if kubectl cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $ctx)"
      return 0
    fi
  done <<< "$contexts"

  # Restore original context
  [[ -n "$current_ctx" ]] && kubectl config use-context "$current_ctx" &>/dev/null || true
  return 1
}

# Get cluster info for display
kubectl_cluster_info() {
  local ctx server
  ctx=$(kubectl_current_context)
  server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)
  echo "${ctx:-unknown}|${server:-unknown}"
}

# Map check ID to compliance frameworks
compliance_map() {
  local id="$1"
  # Returns compliance mappings for a check ID
  # Format: "NIST:AC-2|ISO:A.9.2|ISMS-P:2.5.1|SOC2:CC6.1"
  case "$id" in
    IAM-*) echo "NIST:AC-2,IA-2|ISO:A.9|ISMS-P:2.5|SOC2:CC6.1" ;;
    NET-*) echo "NIST:SC-7,SC-8|ISO:A.13|ISMS-P:2.6|SOC2:CC6.6" ;;
    CLOUD-*) echo "NIST:CM-6,AC-3|ISO:A.12,A.14|ISMS-P:2.10|SOC2:CC6.1" ;;
    CICD-*) echo "NIST:SA-11,CM-2|ISO:A.14|ISMS-P:2.9|SOC2:CC8.1" ;;
    AI-*) echo "NIST-AI:MAP,MEASURE|ISO42001:6,7|ISMS-P:2.9" ;;
    INFRA-*) echo "NIST:CM-6,CM-7|ISO:A.12,A.14|ISMS-P:2.10|SOC2:CC6.6" ;;
    MAC-*|CIS-*) echo "CIS:macOS-Benchmark|NIST:CM-6,CM-7|ISO:A.8.9" ;;
    SECRETS-*) echo "NIST:IA-5,SC-28|ISO:A.8.4,A.8.24|ISMS-P:2.5,2.7|SOC2:CC6.1,CC6.7" ;;
    *) echo "" ;;
  esac
}
