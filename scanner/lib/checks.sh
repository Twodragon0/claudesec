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
  elif has_command python3; then
    python3 -c 'import subprocess, sys
timeout=float(sys.argv[1])
cmd=sys.argv[2:]
try:
  p=subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
  raise SystemExit(p.returncode)
except subprocess.TimeoutExpired:
  raise SystemExit(124)
' "$timeout_sec" "$@"
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

# Search for pattern across files matching a glob.
#
# Excludes vendored/ephemeral/state directories that are not part of the
# audited application code. Without these exclusions, tool state files under
# `.omc/`, `.claude/`, `.claudesec-*`, `dist/`, `build/`, and cache dirs can
# trigger heuristic checks (e.g. AI-002..AI-009, NET-001) even when the real
# application code contains no match. Keep this list in sync with count_files().
files_contain() {
  local glob="$1" pattern="$2" result
  if [[ "$glob" == */* ]]; then
    result=$(find "$SCAN_DIR" -path "$SCAN_DIR/$glob" \
      -not -path "*/node_modules/*" -not -path "*/.git/*" \
      -not -path "*/.venv*/*" -not -path "*/venv/*" \
      -not -path "*/.omc/*" -not -path "*/.claude/*" \
      -not -path "*/.claudesec-*" -not -path "*/dist/*" \
      -not -path "*/build/*" -not -path "*/__pycache__/*" \
      -not -path "*/.cache/*" -not -path "*/.mypy_cache/*" -not -path "*/.pytest_cache/*" \
      -exec grep -lE "$pattern" {} \; 2>/dev/null | head -1 || true)
  else
    result=$(find "$SCAN_DIR" -name "$glob" \
      -not -path "*/node_modules/*" -not -path "*/.git/*" \
      -not -path "*/.venv*/*" -not -path "*/venv/*" \
      -not -path "*/.omc/*" -not -path "*/.claude/*" \
      -not -path "*/.claudesec-*" -not -path "*/dist/*" \
      -not -path "*/build/*" -not -path "*/__pycache__/*" \
      -not -path "*/.cache/*" -not -path "*/.mypy_cache/*" -not -path "*/.pytest_cache/*" \
      -exec grep -lE "$pattern" {} \; 2>/dev/null | head -1 || true)
  fi
  [[ -n "$result" ]]
}

# Count files matching a pattern
count_files() {
  local glob="$1"
  find "$SCAN_DIR" -name "$glob" \
    -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -not -path "*/.venv*/*" -not -path "*/venv/*" \
    -not -path "*/.omc/*" -not -path "*/.claude/*" \
    -not -path "*/.claudesec-*" -not -path "*/dist/*" \
    -not -path "*/build/*" -not -path "*/__pycache__/*" \
    2>/dev/null | wc -l | tr -d ' '
}

# Check if running in a git repo
is_git_repo() {
  git -C "$SCAN_DIR" rev-parse --is-inside-work-tree &>/dev/null
}

# Get git remote URL
git_remote_url() {
  git -C "$SCAN_DIR" remote get-url origin 2>/dev/null || echo ""
}


# ── Cloud credential & auth helpers (AWS/GCP/Datadog/GitHub/Okta/Azure) ──────
# Split into a sibling file to keep checks.sh focused; sourced here — AFTER the
# generic has_command/run_with_timeout helpers they depend on, and BEFORE the
# kubectl helpers and collect_environment_info below that call them. Resolved by
# BASH_SOURCE-relative path so it works however checks.sh is sourced.
# shellcheck source=scanner/lib/checks_credentials.sh
source "$(dirname "${BASH_SOURCE[0]}")/checks_credentials.sh"


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
  run_with_timeout 10 "$cmd" cluster-info &>/dev/null
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

# Try conventional paths relative to base_dir (default .) and return first existing path.
# Use when KUBECONFIG is unset to discover project kubeconfig without hardcoding paths.
kubectl_auto_find_kubeconfig() {
  local base_dir="${1:-.}"
  local tried=(
    "$base_dir/configs/dev/kubeconfig"
    "$base_dir/configs/staging/kubeconfig"
    "$base_dir/configs/prod/kubeconfig"
    "$base_dir/kubeconfig"
    "$base_dir/config/kubeconfig"
  )
  local p
  for p in "${tried[@]}"; do
    [[ -f "$p" ]] && echo "$p" && return 0
  done
  # First match under configs/*/kubeconfig
  if [[ -d "$base_dir/configs" ]]; then
    while IFS= read -r p; do
      [[ -f "$p" ]] && echo "$p" && return 0
    done < <(find "$base_dir/configs" -maxdepth 2 -name 'kubeconfig' -type f 2>/dev/null | head -1)
  fi
  return 1
}

# Detect kubeconfig files and list them
kubectl_discover_kubeconfigs() {
  local configs=()
  local kube_dir="$HOME/.kube"
  local base_dir="${SCAN_DIR:-.}"

  # Auto-discovered conventional paths (relative to CWD/SCAN_DIR)
  local auto_path
  auto_path=$(kubectl_auto_find_kubeconfig "$base_dir" 2>/dev/null)
  [[ -n "$auto_path" && -f "$auto_path" ]] && configs+=("$auto_path")

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

# Detect if current context uses exec-based OIDC (e.g. kubectl oidc-login)
# Used to trigger a longer-timeout kubectl run so the user can complete browser OAuth.
kubectl_current_context_uses_oidc_exec() {
  has_command kubectl || return 1
  local cmd json
  cmd=$(_kubectl_cmd)
  json=$($cmd config view --minify -o json 2>/dev/null) || return 1
  echo "$json" | grep -qE '"command"[[:space:]]*:[[:space:]]*"[^"]*oidc-login' && return 0
  return 1
}

# Ensure kubectl has a valid connection; attempt credential refresh if needed
# Sets _KUBECTL_ENSURE_ACCESS_DONE=1 after first run to prevent duplicate output
kubectl_ensure_access() {
  has_command kubectl || return 1

  # In non-interactive modes (e.g. dashboard generation), avoid slow auth refresh
  # and context switching unless the user explicitly provided K8s settings.
  if [[ "${CLAUDESEC_NONINTERACTIVE:-}" == "1" ]]; then
    if [[ -z "${CLAUDESEC_KUBECONTEXT:-}" && -z "${KUBECONFIG:-}" ]]; then
      return 1
    fi
  fi

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
    if run_with_timeout 10 "$cmd" cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: ${CLAUDESEC_KUBECONTEXT})"
      return 0
    fi
    echo -e "  ${YELLOW}⚠${NC} Specified context '${CLAUDESEC_KUBECONTEXT}' is not reachable"
  fi

  # 1. Already connected
  if run_with_timeout 10 "$(_kubectl_cmd)" cluster-info &>/dev/null; then
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
        run_with_timeout 15 aws eks update-kubeconfig --name "$cluster_name" ${region:+--region "$region"} &>/dev/null || true
      fi
    fi

    # GKE: refresh credentials
    if [[ "$ctype" == "gke" ]]; then
      local gke_project gke_zone gke_cluster
      IFS='_' read -r _ gke_project gke_zone gke_cluster <<< "$current_ctx"
      if [[ -n "$gke_cluster" ]]; then
        echo -e "  ${DIM}Refreshing GKE credentials: $gke_cluster${NC}"
        run_with_timeout 15 gcloud container clusters get-credentials "$gke_cluster" \
          --zone "$gke_zone" --project "$gke_project" &>/dev/null || true
      fi
    fi

    # AKS: refresh credentials
    if [[ "$ctype" == "aks" ]]; then
      local aks_rg aks_name
      aks_name=$(echo "$current_ctx" | grep -oE '[a-zA-Z0-9_-]+' | tail -1 || true)
      if [[ -n "$aks_name" ]] && has_command az; then
        echo -e "  ${DIM}Refreshing AKS credentials: $aks_name${NC}"
        aks_rg=$(run_with_timeout 15 az aks list --query "[?name=='$aks_name'].resourceGroup" -o tsv 2>/dev/null | head -1 || true)
        if [[ -n "$aks_rg" ]]; then
          run_with_timeout 15 az aks get-credentials --resource-group "$aks_rg" --name "$aks_name" --overwrite-existing &>/dev/null || true
        fi
      fi
    fi

    # Test again after refresh
    if run_with_timeout 10 "$(_kubectl_cmd)" cluster-info &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $current_ctx)"
      return 0
    fi

    # OIDC/exec auth (e.g. kubectl oidc-login): run once with longer timeout so user can complete browser sign-in
    if kubectl_current_context_uses_oidc_exec 2>/dev/null; then
      echo -e "  ${DIM}Context uses OIDC login; a browser may open for sign-in. Waiting up to 45s…${NC}"
      if run_with_timeout 45 "$(_kubectl_cmd)" cluster-info &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Connected to cluster (context: $current_ctx)"
        return 0
      fi
    fi
  fi

  # 4. Try other contexts
  while IFS= read -r ctx; do
    [[ -z "$ctx" || "$ctx" == "$current_ctx" ]] && continue
    kubectl config use-context "$ctx" &>/dev/null || continue
    if run_with_timeout 10 "$(_kubectl_cmd)" cluster-info &>/dev/null; then
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
  echo -e "    Or set kubeconfig in .claudesec.yml; conventional paths (configs/dev/kubeconfig, ./kubeconfig) are auto-discovered."
  echo ""
  echo -e "  ${BOLD}OIDC / Okta login:${NC}"
  echo -e "    If your kubeconfig uses kubectl oidc-login, run \`kubectl get nodes\` once to complete browser sign-in, then re-run claudesec."
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
  # Whether the generated HTML dashboard should include potentially identifying
  # information (cloud account, email, subscription names, kube server URL).
  # Default is "false" to reduce accidental leakage when sharing/committing.
  if [[ "${CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS:-0}" == "1" ]]; then
    export CLAUDESEC_ENV_SHOW_IDENTIFIERS="true"
  else
    export CLAUDESEC_ENV_SHOW_IDENTIFIERS="false"
  fi

  # Discover and set profile/API key when not set (find and verify)
  aws_ensure_profile_found 2>/dev/null || true
  gcp_ensure_credentials_found 2>/dev/null || true

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
  export CLAUDESEC_ENV_AWS_SSO_CONFIGURED="false"
  export CLAUDESEC_ENV_AWS_SSO_SESSION="unknown"
  if [[ -n "${AWS_PROFILE:-}" ]] && aws_profile_is_sso "${AWS_PROFILE}" 2>/dev/null; then
    export CLAUDESEC_ENV_AWS_SSO_CONFIGURED="true"
  fi

  if has_aws_credentials 2>/dev/null; then
    local aws_info
    aws_info=$(aws_identity_info 2>/dev/null)
    export CLAUDESEC_ENV_AWS_CONNECTED="true"
    local aws_account aws_arn
    aws_account=$(echo "$aws_info" | cut -d'|' -f1)
    aws_arn=$(echo "$aws_info" | cut -d'|' -f2)
    export CLAUDESEC_ENV_AWS_ACCOUNT="$aws_account"
    export CLAUDESEC_ENV_AWS_ARN="$aws_arn"
    [[ -n "${AWS_PROFILE:-}" ]] && export CLAUDESEC_ENV_AWS_PROFILE="$AWS_PROFILE"
    if [[ "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-false}" == "true" ]]; then
      export CLAUDESEC_ENV_AWS_SSO_SESSION="valid"
    fi
  else
    export CLAUDESEC_ENV_AWS_CONNECTED="false"
    if [[ "${CLAUDESEC_ENV_AWS_SSO_CONFIGURED:-false}" == "true" ]]; then
      export CLAUDESEC_ENV_AWS_SSO_SESSION="expired"
    fi
  fi

  # GCP
  if has_gcp_credentials 2>/dev/null; then
    export CLAUDESEC_ENV_GCP_CONNECTED="true"
    local gcp_account gcp_project
    gcp_account=$(gcloud config get-value account 2>/dev/null || echo "unknown")
    gcp_project=$(gcloud config get-value project 2>/dev/null || echo "unknown")
    export CLAUDESEC_ENV_GCP_ACCOUNT="$gcp_account"
    export CLAUDESEC_ENV_GCP_PROJECT="$gcp_project"
  else
    export CLAUDESEC_ENV_GCP_CONNECTED="false"
  fi

  # Azure
  if has_command az && az account show &>/dev/null; then
    export CLAUDESEC_ENV_AZ_CONNECTED="true"
    local az_sub
    az_sub=$(az account show --query name -o tsv 2>/dev/null || echo "unknown")
    export CLAUDESEC_ENV_AZ_SUBSCRIPTION="$az_sub"
  else
    export CLAUDESEC_ENV_AZ_CONNECTED="false"
  fi

  # ── Prowler extended providers (for dashboard environment section) ─────────

  # Microsoft 365 (Prowler m365): SP env auth OR Azure CLI auth
  if [[ -n "${AZURE_CLIENT_ID:-}" && -n "${AZURE_TENANT_ID:-}" && -n "${AZURE_CLIENT_SECRET:-}" ]] || \
     { has_command az && az account show &>/dev/null; }; then
    export CLAUDESEC_ENV_M365_CONNECTED="true"
  else
    export CLAUDESEC_ENV_M365_CONNECTED="false"
  fi

  # Google Workspace (Prowler googleworkspace): Google OAuth + customer id
  if [[ -n "${GOOGLE_WORKSPACE_CUSTOMER_ID:-}" ]] && \
     { has_gcp_credentials 2>/dev/null || [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; }; then
    export CLAUDESEC_ENV_GWS_CONNECTED="true"
    if [[ "${CLAUDESEC_ENV_SHOW_IDENTIFIERS:-false}" == "true" ]]; then
      export CLAUDESEC_ENV_GWS_CUSTOMER_ID="${GOOGLE_WORKSPACE_CUSTOMER_ID}"
    fi
  else
    export CLAUDESEC_ENV_GWS_CONNECTED="false"
  fi

  # Cloudflare (Prowler cloudflare): API token (preferred) or legacy key+email
  if [[ -n "${CLOUDFLARE_API_TOKEN:-}${CF_API_TOKEN:-}" ]] || \
     [[ -n "${CLOUDFLARE_API_KEY:-}" && -n "${CLOUDFLARE_API_EMAIL:-}" ]]; then
    export CLAUDESEC_ENV_CF_CONNECTED="true"
  else
    export CLAUDESEC_ENV_CF_CONNECTED="false"
  fi

  # NHN Cloud (Prowler openstack provider): OS_AUTH_URL includes NHN/TOAST or NHN_API_URL
  if [[ "${OS_AUTH_URL:-}" == *"nhncloud"* || "${OS_AUTH_URL:-}" == *"toast"* || -n "${NHN_API_URL:-}" ]]; then
    export CLAUDESEC_ENV_NHN_CONNECTED="true"
  else
    export CLAUDESEC_ENV_NHN_CONNECTED="false"
  fi

  # LLM (Prowler llm): promptfoo + LLM API key
  if has_command promptfoo && [[ -n "${OPENAI_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]]; then
    export CLAUDESEC_ENV_LLM_CONNECTED="true"
  else
    export CLAUDESEC_ENV_LLM_CONNECTED="false"
  fi

  # Datadog: a configured API key (DD_API_KEY or DATADOG_API_KEY) marks Datadog
  # "connected". We intentionally do NOT gate this on datadog_validate_api_key()
  # here: both branches used to set "true" anyway (so the ~8s validation round-trip
  # per scan had no effect), and gating would let a transient API error / rate-limit
  # hide a correctly-configured key. The validation helper is still exercised
  # directly by the cloud-credential-probe tests.
  if has_datadog_api_key 2>/dev/null; then
    export CLAUDESEC_ENV_DATADOG_CONNECTED="true"
  else
    export CLAUDESEC_ENV_DATADOG_CONNECTED="false"
  fi

  if has_github_credentials 2>/dev/null; then
    export CLAUDESEC_ENV_GITHUB_CONNECTED="true"
  else
    export CLAUDESEC_ENV_GITHUB_CONNECTED="false"
  fi

  if has_okta_credentials 2>/dev/null; then
    export CLAUDESEC_ENV_OKTA_CONNECTED="true"
  else
    export CLAUDESEC_ENV_OKTA_CONNECTED="false"
  fi
}

# ── Category check runner (shared by run_scan / run_scan_for_dashboard) ─────

# Runs each category's check files, aggregating global TOTAL_CHECKS/PASSED/FAILED/
# WARNINGS/SKIPPED and JSON_RESULTS. Mutates those globals in place.
#   $1 parallel  — "1" to run categories concurrently (when >1), else sequential
#   $2 verbose   — "1" to print section headers, unknown-category warnings, and
#                  stream per-category output to stdout; "0" for silent (dashboard)
#   $3.. categories — category names
#
# shellcheck disable=SC2034,SC1090,SC2030,SC2031
# SC2034: FINDINGS_* arrays are populated by sourced check files, not this scope.
# SC1090: check files are sourced dynamically ($check_file is not a constant).
# SC2030/SC2031: subshell counter resets are intentional — each category subshell
# writes counters to a temp file that the parent re-reads and aggregates.
# (These were suppressed file-wide in scanner/claudesec before the extraction.)
run_category_checks() {
  local parallel="$1" verbose="$2"; shift 2
  local categories=("$@")

  # String compare (not numeric -eq): callers pass the raw CLAUDESEC_DASHBOARD_PARALLEL
  # value, which may be a non-numeric truthy string ("true"); numeric -eq would abort
  # under `set -u`. Only the literal "1" enables parallel, matching both callers' originals.
  if [[ "$parallel" == "1" && ${#categories[@]} -gt 1 ]]; then
    # Parallel mode: run each category in a subshell, merge results
    local tmpdir
    tmpdir=$(mktemp -d)
    local pids=()
    local cat
    for cat in "${categories[@]}"; do
      local check_dir="$CHECKS_DIR/$cat"
      if [[ ! -d "$check_dir" ]]; then
        [[ "$verbose" -eq 1 ]] && warning "Unknown category: $cat"
        continue
      fi
      (
        # Relax pipefail in subshells so a single check crash cannot
        # prevent counter/JSON files from being written.
        set +o pipefail
        # Each subshell resets its own counters and JSON state
        TOTAL_CHECKS=0; PASSED=0; FAILED=0; WARNINGS=0; SKIPPED=0
        JSON_RESULTS="[]"
        FINDINGS_CRITICAL=(); FINDINGS_HIGH=(); FINDINGS_MEDIUM=(); FINDINGS_LOW=()
        FINDINGS_WARN=()
        if [[ "$verbose" -eq 1 && "$FORMAT" == "text" ]]; then
          section "$(category_label "$cat")"
        fi
        for check_file in "$check_dir"/*.sh; do
          [[ -f "$check_file" ]] || continue
          source "$check_file" >/dev/null 2>&1 || true
        done
        # Write counters to temp file for aggregation
        printf '%d %d %d %d %d\n' "$TOTAL_CHECKS" "$PASSED" "$FAILED" "$WARNINGS" "$SKIPPED" \
          > "$tmpdir/${cat}.counters"
        # Write JSON results for merging
        echo "$JSON_RESULTS" > "$tmpdir/${cat}.json"
      ) > "$tmpdir/${cat}.out" 2>&1 &
      pids+=($!)
    done
    # Wait for all and collect
    local pid
    for pid in "${pids[@]}"; do
      wait "$pid" 2>/dev/null || true
    done
    # Output results in category order and aggregate counters + JSON
    for cat in "${categories[@]}"; do
      if [[ "$verbose" -eq 1 ]]; then
        [[ -f "$tmpdir/${cat}.out" ]] && cat "$tmpdir/${cat}.out"
      fi
      if [[ -f "$tmpdir/${cat}.counters" ]]; then
        local tc pa fa wa sk
        read -r tc pa fa wa sk < "$tmpdir/${cat}.counters"
        TOTAL_CHECKS=$((TOTAL_CHECKS + tc))
        PASSED=$((PASSED + pa))
        FAILED=$((FAILED + fa))
        WARNINGS=$((WARNINGS + wa))
        SKIPPED=$((SKIPPED + sk))
      fi
      # Merge JSON results from subshell
      if [[ -f "$tmpdir/${cat}.json" ]]; then
        local cat_json
        cat_json=$(<"$tmpdir/${cat}.json")
        if [[ "$cat_json" != "[]" ]]; then
          # Strip outer brackets and append to main JSON_RESULTS
          local inner="${cat_json#[}"
          inner="${inner%]}"
          if [[ "$JSON_RESULTS" == "[]" ]]; then
            JSON_RESULTS="[${inner}]"
          else
            JSON_RESULTS="${JSON_RESULTS%]},$inner]"
          fi
        fi
      fi
    done
    rm -rf "$tmpdir"
  else
    # Sequential mode (default)
    local cat
    for cat in "${categories[@]}"; do
      local check_dir="$CHECKS_DIR/$cat"
      if [[ ! -d "$check_dir" ]]; then
        [[ "$verbose" -eq 1 ]] && warning "Unknown category: $cat"
        continue
      fi

      if [[ "$verbose" -eq 1 && "$FORMAT" == "text" ]]; then
        section "$(category_label "$cat")"
      fi

      # Source and run each check file
      for check_file in "$check_dir"/*.sh; do
        [[ -f "$check_file" ]] || continue
        if ! source "$check_file" >/dev/null 2>&1; then
          warning "Check failed to load: $(basename "$check_file")"
        fi
      done
    done
  fi
}
