#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Check helper library
# ============================================================================

# Check if a command exists
has_command() {
  command -v "$1" &>/dev/null
}

# Run a command with timeout (default 15s)
run_with_timeout() {
  local timeout_sec="${1:-15}"
  shift
  if has_command timeout; then
    timeout "$timeout_sec" "$@" 2>/dev/null
  elif has_command gtimeout; then
    gtimeout "$timeout_sec" "$@" 2>/dev/null
  else
    "$@" 2>/dev/null
  fi
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
  has_command aws && run_with_timeout 10 aws sts get-caller-identity &>/dev/null
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
  has_command gcloud && run_with_timeout 10 gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .
}

# ── Azure credential helpers ───────────────────────────────────────────────

# Check Azure credentials
has_azure_credentials() {
  has_command az && run_with_timeout 10 az account show
}

# ── Kubernetes credential helpers ───────────────────────────────────────────

# Build kubectl command with kubeconfig/context overrides
_kubectl_cmd() {
  local cmd=(kubectl)
  [[ -n "${KUBECONFIG:-}" ]] && cmd+=(--kubeconfig "$KUBECONFIG")
  [[ -n "${CLAUDESEC_KUBECONTEXT:-}" ]] && cmd+=(--context "$CLAUDESEC_KUBECONTEXT")
  echo "${cmd[@]}"
}

# Check kubectl access (tries current context with overrides)
has_kubectl_access() {
  has_command kubectl || return 1
  local cmd
  cmd=$(_kubectl_cmd)
  run_with_timeout 10 $cmd cluster-info &>/dev/null
}

# List available kubeconfig contexts
kubectl_list_contexts() {
  has_command kubectl || return 1
  local cmd
  cmd=$(_kubectl_cmd)
  $cmd config get-contexts -o name 2>/dev/null || true
}

# Get current kubectl context name
kubectl_current_context() {
  has_command kubectl || return 1
  if [[ -n "${CLAUDESEC_KUBECONTEXT:-}" ]]; then
    echo "$CLAUDESEC_KUBECONTEXT"
    return 0
  fi
  local cmd
  cmd=$(_kubectl_cmd)
  $cmd config current-context 2>/dev/null || echo ""
}

# Detect kubeconfig files and list them
kubectl_discover_kubeconfigs() {
  local configs=()
  local kube_dir="$HOME/.kube"

  # Standard kubeconfig
  [[ -f "$HOME/.kube/config" ]] && configs+=("$HOME/.kube/config")

  # Split kubeconfig files
  if [[ -d "$kube_dir" ]]; then
    while IFS= read -r f; do
      [[ "$f" == "$HOME/.kube/config" ]] && continue
      configs+=("$f")
    done < <(find "$kube_dir" \( -name '*.yaml' -o -name '*.yml' -o -name '*.conf' \) 2>/dev/null | sort)
  fi

  # KUBECONFIG env may have colon-separated paths
  if [[ -n "${KUBECONFIG:-}" ]]; then
    IFS=':' read -ra kc_paths <<< "$KUBECONFIG"
    for p in "${kc_paths[@]}"; do
      [[ -f "$p" ]] && configs+=("$p")
    done
  fi

  # Rancher desktop
  [[ -f "$HOME/.rd/kubeconfig" ]] && configs+=("$HOME/.rd/kubeconfig")
  # Docker desktop
  [[ -f "$HOME/.docker/contexts/meta" ]] && configs+=("(docker-desktop built-in)")

  # De-duplicate
  printf '%s\n' "${configs[@]}" | sort -u
}

# Detect cluster type from context name
kubectl_detect_cluster_type() {
  local ctx="$1"
  case "$ctx" in
    *eks*|*arn:aws*) echo "eks" ;;
    gke_*) echo "gke" ;;
    *aks*|*azure*|*azmk*) echo "aks" ;;
    docker-desktop*) echo "docker-desktop" ;;
    minikube*) echo "minikube" ;;
    kind-*) echo "kind" ;;
    rancher-desktop*|*rd*) echo "rancher-desktop" ;;
    *) echo "generic" ;;
  esac
}

# Ensure kubectl has a valid connection; attempt credential refresh if needed
# Sets _KUBECTL_ENSURE_ACCESS_DONE=1 after first run to prevent duplicate output
kubectl_ensure_access() {
  has_command kubectl || return 1

  # Prevent duplicate auth guide output across categories
  if [[ "${_KUBECTL_ENSURE_ACCESS_DONE:-}" == "1" ]]; then
    # Already ran — just return cached result
    has_kubectl_access 2>/dev/null
    return $?
  fi
  export _KUBECTL_ENSURE_ACCESS_DONE=1

  # Apply user-specified context if set via CLI
  if [[ -n "${CLAUDESEC_KUBECONTEXT:-}" ]]; then
    local cmd
    cmd=$(_kubectl_cmd)
    if run_with_timeout 10 $cmd cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: ${CLAUDESEC_KUBECONTEXT})"
      return 0
    fi
    echo -e "  ${YELLOW}⚠${NC} Specified context '${CLAUDESEC_KUBECONTEXT}' is not reachable"
  fi

  # 1. Already connected
  if run_with_timeout 10 $(_kubectl_cmd) cluster-info &>/dev/null; then
    return 0
  fi

  local current_ctx
  current_ctx=$(kubectl_current_context)

  # 2. Show kubeconfig discovery info
  local kubeconfig_file="${KUBECONFIG:-$HOME/.kube/config}"
  if [[ -f "$kubeconfig_file" ]]; then
    echo -e "  ${DIM}Kubeconfig: $kubeconfig_file${NC}"
  else
    echo -e "  ${YELLOW}⚠${NC} Kubeconfig not found: $kubeconfig_file"
    local discovered
    discovered=$(kubectl_discover_kubeconfigs)
    if [[ -n "$discovered" ]]; then
      echo -e "  ${DIM}Discovered kubeconfig files:${NC}"
      while IFS= read -r kf; do
        echo -e "    ${CYAN}▸${NC} $kf"
      done <<< "$discovered"
      echo -e "  ${DIM}Use --kubeconfig <path> to specify${NC}"
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
    local cluster_type
    cluster_type=$(kubectl_detect_cluster_type "$ctx")
    echo -e "    ${CYAN}${marker}${NC}$ctx ${DIM}(${cluster_type})${NC}"
  done <<< "$contexts"

  # 3. Try current context first — refresh credentials
  if [[ -n "$current_ctx" ]]; then
    echo -e "  ${DIM}Attempting to connect to context: $current_ctx${NC}"
    local ctype
    ctype=$(kubectl_detect_cluster_type "$current_ctx")

    # AWS EKS: refresh kubeconfig
    if [[ "$ctype" == "eks" ]]; then
      local cluster_name region
      cluster_name=$(echo "$current_ctx" | sed 's/.*\///' | sed 's/arn:aws:eks:[^:]*:[^:]*:cluster\///' || true)
      region=$(echo "$current_ctx" | grep -oE '[a-z]+-[a-z]+-[0-9]+' | head -1 || true)
      if [[ -n "$cluster_name" ]]; then
        echo -e "  ${DIM}Refreshing EKS credentials: $cluster_name${NC}"
        aws eks update-kubeconfig --name "$cluster_name" ${region:+--region "$region"} &>/dev/null || true
      fi
    fi

    # GKE: refresh credentials
    if [[ "$ctype" == "gke" ]]; then
      local gke_project gke_zone gke_cluster
      IFS='_' read -r _ gke_project gke_zone gke_cluster <<< "$current_ctx"
      if [[ -n "$gke_cluster" ]]; then
        echo -e "  ${DIM}Refreshing GKE credentials: $gke_cluster${NC}"
        gcloud container clusters get-credentials "$gke_cluster" \
          --zone "$gke_zone" --project "$gke_project" &>/dev/null || true
      fi
    fi

    # AKS: refresh credentials
    if [[ "$ctype" == "aks" ]]; then
      local aks_rg aks_name
      aks_name=$(echo "$current_ctx" | grep -oE '[a-zA-Z0-9_-]+' | tail -1 || true)
      if [[ -n "$aks_name" ]] && has_command az; then
        echo -e "  ${DIM}Refreshing AKS credentials: $aks_name${NC}"
        aks_rg=$(az aks list --query "[?name=='$aks_name'].resourceGroup" -o tsv 2>/dev/null | head -1 || true)
        if [[ -n "$aks_rg" ]]; then
          az aks get-credentials --resource-group "$aks_rg" --name "$aks_name" --overwrite-existing &>/dev/null || true
        fi
      fi
    fi

    # Test again after refresh
    if run_with_timeout 10 $(_kubectl_cmd) cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $current_ctx)"
      return 0
    fi
  fi

  # 4. Try other contexts
  while IFS= read -r ctx; do
    [[ -z "$ctx" || "$ctx" == "$current_ctx" ]] && continue
    kubectl config use-context "$ctx" &>/dev/null || continue
    if run_with_timeout 10 $(_kubectl_cmd) cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $ctx)"
      return 0
    fi
  done <<< "$contexts"

  # 5. Show authentication guide
  echo ""
  echo -e "  ${YELLOW}━━━ Kubernetes Authentication Guide ━━━${NC}"
  echo -e "  ${DIM}No reachable cluster found. To connect:${NC}"
  echo ""
  echo -e "  ${BOLD}EKS (AWS):${NC}"
  echo -e "    aws eks update-kubeconfig --name <cluster> --region <region>"
  echo -e "    claudesec scan --aws-profile <profile> --kubecontext <ctx>"
  echo ""
  echo -e "  ${BOLD}GKE (GCP):${NC}"
  echo -e "    gcloud container clusters get-credentials <cluster> --zone <zone>"
  echo ""
  echo -e "  ${BOLD}AKS (Azure):${NC}"
  echo -e "    az aks get-credentials --resource-group <rg> --name <cluster>"
  echo ""
  echo -e "  ${BOLD}Custom kubeconfig:${NC}"
  echo -e "    claudesec scan --kubeconfig /path/to/kubeconfig"
  echo -e "    KUBECONFIG=/path/to/config claudesec scan"
  echo ""
  echo -e "  ${BOLD}Context selection:${NC}"
  echo -e "    claudesec scan --kubecontext <context-name>"
  echo -e "    kubectl config use-context <context-name>"
  echo ""

  # Restore original context
  [[ -n "$current_ctx" ]] && kubectl config use-context "$current_ctx" &>/dev/null || true
  return 1
}

# Get cluster info for display
kubectl_cluster_info() {
  local cmd ctx server
  cmd=$(_kubectl_cmd)
  ctx=$(kubectl_current_context)
  server=$($cmd config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)
  echo "${ctx:-unknown}|${server:-unknown}"
}

# Get K8s cluster version
kubectl_server_version() {
  local cmd
  cmd=$(_kubectl_cmd)
  $cmd version -o json 2>/dev/null | grep -o '"gitVersion":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "unknown"
}

# ── Environment info collector (for dashboard) ────────────────────────────

# Collect environment info into CLAUDESEC_ENV_* variables
collect_environment_info() {
  # Kubernetes
  if has_kubectl_access 2>/dev/null; then
    local kinfo ctx server ctype ver
    kinfo=$(kubectl_cluster_info)
    ctx=$(echo "$kinfo" | cut -d'|' -f1)
    server=$(echo "$kinfo" | cut -d'|' -f2)
    ctype=$(kubectl_detect_cluster_type "$ctx")
    ver=$(kubectl_server_version 2>/dev/null)
    export CLAUDESEC_ENV_K8S_CONNECTED="true"
    export CLAUDESEC_ENV_K8S_CONTEXT="$ctx"
    export CLAUDESEC_ENV_K8S_SERVER="$server"
    export CLAUDESEC_ENV_K8S_TYPE="$ctype"
    export CLAUDESEC_ENV_K8S_VERSION="$ver"
    [[ -n "${KUBECONFIG:-}" ]] && export CLAUDESEC_ENV_K8S_KUBECONFIG="$KUBECONFIG"
    [[ -n "${CLAUDESEC_KUBE_NAMESPACE:-}" ]] && export CLAUDESEC_ENV_K8S_NAMESPACE="$CLAUDESEC_KUBE_NAMESPACE"
  else
    export CLAUDESEC_ENV_K8S_CONNECTED="false"
  fi

  # AWS
  if has_aws_credentials 2>/dev/null; then
    local aws_info
    aws_info=$(aws_identity_info 2>/dev/null)
    export CLAUDESEC_ENV_AWS_CONNECTED="true"
    export CLAUDESEC_ENV_AWS_ACCOUNT=$(echo "$aws_info" | cut -d'|' -f1)
    export CLAUDESEC_ENV_AWS_ARN=$(echo "$aws_info" | cut -d'|' -f2)
    [[ -n "${AWS_PROFILE:-}" ]] && export CLAUDESEC_ENV_AWS_PROFILE="$AWS_PROFILE"
  else
    export CLAUDESEC_ENV_AWS_CONNECTED="false"
  fi

  # GCP
  if has_gcp_credentials 2>/dev/null; then
    export CLAUDESEC_ENV_GCP_CONNECTED="true"
    export CLAUDESEC_ENV_GCP_ACCOUNT=$(gcloud config get-value account 2>/dev/null || echo "unknown")
    export CLAUDESEC_ENV_GCP_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "unknown")
  else
    export CLAUDESEC_ENV_GCP_CONNECTED="false"
  fi

  # Azure
  if has_command az && az account show &>/dev/null 2>&1; then
    export CLAUDESEC_ENV_AZ_CONNECTED="true"
    export CLAUDESEC_ENV_AZ_SUBSCRIPTION=$(az account show --query name -o tsv 2>/dev/null || echo "unknown")
  else
    export CLAUDESEC_ENV_AZ_CONNECTED="false"
  fi
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
    MAC-*|CIS-*) echo "CIS:macOS-Benchmark|NIST:CM-6,CM-7|ISO:A.8.9|KISA-PC:PC-01~PC-19" ;;
    SECRETS-*) echo "NIST:IA-5,SC-28|ISO:A.8.4,A.8.24|ISMS-P:2.5,2.7|SOC2:CC6.1,CC6.7" ;;
    SAAS-*|SAAS-API-*) echo "NIST:AC-2,CM-6|ISO:A.9,A.12|ISMS-P:2.5,2.10|SOC2:CC6.1,CC6.6" ;;
    WIN-*) echo "KISA-W:W-01~W-84|NIST:CM-6,AC-2,IA-5|ISO:A.8,A.9|ISMS-P:2.5,2.10" ;;
    PROWLER-*) echo "NIST:AC,CM,IA,SC|ISO:A.8,A.9,A.12,A.14|CIS:Benchmark|SOC2:CC6,CC7,CC8" ;;
    *) echo "" ;;
  esac
}
