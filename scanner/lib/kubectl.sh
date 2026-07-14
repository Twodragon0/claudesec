#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — kubectl / kubeconfig helper library
# ============================================================================
#
# Holds the kubectl / kubeconfig discovery and cluster-access helpers,
# extracted from checks.sh to keep that file focused. This module depends on
# the generic helpers in checks.sh (has_command, run_with_timeout, has_file,
# has_dir) being sourced into the same shell BEFORE any kubectl_* function
# below is invoked.
#
# No `set -euo pipefail` here — this is a sourced lib, mirroring checks.sh
# which has no `set` line after the shebang.

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
