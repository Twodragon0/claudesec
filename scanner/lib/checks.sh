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

# ── AWS credential helpers ──────────────────────────────────────────────────

# List AWS profile names from ~/.aws/credentials ([default], [profile name])
# Output: one profile name per line; "default" first if present.
aws_list_profiles() {
  local creds="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
  [[ ! -f "$creds" ]] && return 0
  awk '
    /^\[/ {
      gsub(/^\[|\]$/, ""); gsub(/^profile +/, "", $0); name = $0
      if (name == "default") def = 1; else others = others (others ? "\n" : "") name
    }
    END {
      if (def) print "default"
      if (others != "") print others
    }
  ' "$creds" 2>/dev/null || true
}

# List AWS SSO profile names from ~/.aws/config (profiles with sso_session or sso_start_url)
# Output: one profile name per line.
aws_list_sso_profiles() {
  local config_file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  [[ -f "$config_file" ]] || return 0
  awk '
    /^\[profile / {
      gsub(/^\[profile |\]$/, ""); current = $0; next
    }
    /^\[default\]/ { current = "default"; next }
    /^\[/ { current = ""; next }
    /sso_start_url|sso_session/ && current != "" {
      if (!seen[current]++) print current
    }
  ' "$config_file" 2>/dev/null || true
}

aws_sso_login_with_timeout() {
  local profile="${1:-}"
  local timeout_sec="${AWS_SSO_LOGIN_TIMEOUT:-90}"
  [[ -z "$profile" ]] && return 1

  if has_command timeout; then
    timeout "$timeout_sec" aws sso login --profile "$profile"
    return $?
  elif has_command gtimeout; then
    gtimeout "$timeout_sec" aws sso login --profile "$profile"
    return $?
  fi

  aws sso login --profile "$profile"
}

# Login to ALL SSO profiles from ~/.aws/config.
# Returns 0 if at least one profile was successfully authenticated.
# Skips profiles that already have valid sessions.
# Usage: aws_sso_login_all_profiles   (interactive — opens browser)
aws_sso_login_all_profiles() {
  has_command aws || return 1

  # Avoid interactive SSO flows in non-interactive modes
  if [[ "${CLAUDESEC_NONINTERACTIVE:-}" == "1" ]]; then
    return 1
  fi

  # Not a TTY: cannot open browser for SSO; print clear instructions
  if [[ ! -t 0 ]]; then
    echo -e "  ${YELLOW}AWS SSO login requires an interactive terminal (browser).${NC}"
    echo -e "  ${DIM}Run in a terminal: claudesec scan --aws-sso-all${NC}"
    echo -e "  ${DIM}Or: aws sso login --profile <profile> for each profile${NC}"
    return 1
  fi

  local config_file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  [[ -f "$config_file" ]] || return 1

  local sso_profiles
  sso_profiles=$(aws_list_sso_profiles)
  [[ -z "$sso_profiles" ]] && return 1

  local any_success=false
  local already_auth=0 newly_auth=0 failed_auth=0 timeout_skipped=0

  while IFS= read -r profile; do
    [[ -z "$profile" ]] && continue

    # Check if already authenticated
    if AWS_PROFILE="$profile" aws sts get-caller-identity &>/dev/null; then
      already_auth=$((already_auth + 1))
      echo -e "  ${GREEN}✓${NC} ${profile}: already authenticated"
      any_success=true
      continue
    fi

    # Attempt SSO login
    echo -e "  ${YELLOW}⟳${NC} ${profile}: logging in via SSO..."
    if aws_sso_login_with_timeout "$profile" 2>/dev/null; then
      newly_auth=$((newly_auth + 1))
      echo -e "  ${GREEN}✓${NC} ${profile}: SSO login successful"
      any_success=true
    else
      local rc=$?
      if [[ "$rc" == "124" ]]; then
        timeout_skipped=$((timeout_skipped + 1))
        echo -e "  ${YELLOW}⚠${NC} ${profile}: login timed out (${AWS_SSO_LOGIN_TIMEOUT:-90}s), skipped"
      else
        failed_auth=$((failed_auth + 1))
        echo -e "  ${RED}✗${NC} ${profile}: SSO login failed"
      fi
    fi
  done <<< "$sso_profiles"

  echo -e "  ${DIM}SSO summary: ${already_auth} already auth, ${newly_auth} newly auth, ${failed_auth} failed, ${timeout_skipped} timeout-skipped${NC}"
  $any_success
}

# Print first available AWS profile (default or first from credentials)
aws_default_or_first_profile() {
  aws_list_profiles | head -1
}

# Ensure AWS_PROFILE is set from discovery when empty (from config/credentials)
aws_ensure_profile_found() {
  [[ -n "${AWS_PROFILE:-}" ]] && return 0
  local first
  first=$(aws_default_or_first_profile)
  if [[ -n "$first" ]]; then
    export AWS_PROFILE="$first"
    export AWS_DEFAULT_PROFILE="$first"
    return 0
  fi
  return 1
}

# Check AWS credentials availability (STS call)
has_aws_credentials() {
  has_command aws && run_with_timeout 10 aws sts get-caller-identity &>/dev/null
}

# Check if an API key env var is set (non-empty); does not print the value
api_key_found() {
  local var_name="$1"
  local val="${!var_name:-}"
  [[ -n "$val" ]]
}

# Attempt AWS SSO login if configured but session expired
aws_sso_ensure_login() {
  has_command aws || return 1

  local profile="${AWS_PROFILE:-}"

  # Avoid interactive SSO flows in non-interactive modes (e.g. dashboard generation).
  if [[ "${CLAUDESEC_NONINTERACTIVE:-}" == "1" ]]; then
    return 1
  fi

  # Not a TTY: cannot open browser for SSO; print clear instructions.
  if [[ ! -t 0 ]]; then
    echo -e "  ${YELLOW}AWS SSO requires an interactive terminal (browser login).${NC}"
    echo -e "  ${DIM}Run in a terminal: aws sso login --profile <profile>${NC}"
    echo -e "  ${DIM}Or: claudesec scan --aws-sso (or --aws-profile <name>)${NC}"
    return 1
  fi

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
    echo -e "  ${DIM}Running: aws sso login --profile $profile (timeout: ${AWS_SSO_LOGIN_TIMEOUT:-90}s)${NC}"
    aws_sso_login_with_timeout "$profile" 2>/dev/null
    local rc=$?
    if [[ $rc -eq 0 ]]; then
      export AWS_DEFAULT_PROFILE="$profile"
      echo -e "  ${GREEN}✓${NC} AWS SSO login successful (profile: $profile)"
      return 0
    fi
    if [[ $rc -eq 124 ]]; then
      echo -e "  ${YELLOW}⚠${NC} AWS SSO login timed out for profile ${BOLD}$profile${NC}; skipping"
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
    echo -e "  ${DIM}Running: aws sso login --profile $first_profile (timeout: ${AWS_SSO_LOGIN_TIMEOUT:-90}s)${NC}"
    aws_sso_login_with_timeout "$first_profile" 2>/dev/null
    local rc2=$?
    if [[ $rc2 -eq 0 ]]; then
      export AWS_PROFILE="$first_profile"
      echo -e "  ${GREEN}✓${NC} AWS SSO login successful (profile: $first_profile)"
      return 0
    fi
    if [[ $rc2 -eq 124 ]]; then
      echo -e "  ${YELLOW}⚠${NC} AWS SSO login timed out for profile ${BOLD}$first_profile${NC}; skipping"
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

# Determine whether a given AWS profile is configured for SSO.
aws_profile_is_sso() {
  local profile="${1:-}"
  local config_file="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  [[ -z "$profile" || ! -f "$config_file" ]] && return 1

  if [[ "$profile" == "default" ]]; then
    grep -A20 '^\[default\]' "$config_file" 2>/dev/null | grep -q 'sso_start_url\|sso_session'
    return $?
  fi
  grep -A30 "^\[profile ${profile}\]" "$config_file" 2>/dev/null | grep -q 'sso_start_url\|sso_session'
}

# ── GCP credential helpers ─────────────────────────────────────────────────

# Check GCP credentials (gcloud CLI or ADC file)
has_gcp_credentials() {
  if has_command gcloud && run_with_timeout 10 gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .; then
    return 0
  fi
  if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" && -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]]; then
    return 0
  fi
  return 1
}

# Ensure GCP credentials discoverable (GOOGLE_APPLICATION_CREDENTIALS file exists when set)
gcp_ensure_credentials_found() {
  has_gcp_credentials 2>/dev/null && return 0
  if [[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]]; then
    [[ -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]] && return 0
  fi
  return 1
}

# ── Datadog API key helpers (best practices: scoped keys, env vars) ─────────

# Check if Datadog API key is configured (DD_API_KEY or DATADOG_API_KEY)
has_datadog_api_key() {
  [[ -n "${DD_API_KEY:-}${DATADOG_API_KEY:-}" ]]
}

has_github_credentials() {
  if [[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]]; then
    return 0
  fi
  if has_command gh && run_with_timeout 8 gh auth status >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

has_okta_credentials() {
  [[ -n "${OKTA_API_TOKEN:-}${OKTA_OAUTH_TOKEN:-}" ]]
}

# Validate Datadog API key with a lightweight API call (optional)
datadog_validate_api_key() {
  local key="${DD_API_KEY:-${DATADOG_API_KEY:-}}"
  local site="${DD_SITE:-datadoghq.com}"
  local base_url="https://api.datadoghq.com"
  [[ -z "$key" ]] && return 1
  case "$site" in
    datadoghq.eu) base_url="https://api.datadoghq.eu" ;;
    us3.datadoghq.com) base_url="https://api.us3.datadoghq.com" ;;
    us5.datadoghq.com) base_url="https://api.us5.datadoghq.com" ;;
    ddog-gov.com) base_url="https://api.ddog-gov.com" ;;
  esac
  if has_command curl; then
    run_with_timeout 8 curl -sS -f -o /dev/null -w "%{http_code}" \
      -H "DD-API-KEY: $key" \
      "${base_url}/api/v1/validate" 2>/dev/null | grep -q 200
    return $?
  fi
  # No curl: consider key "found" only
  return 0
}

# ── Azure credential helpers ───────────────────────────────────────────────

# Check Azure credentials
has_azure_credentials() {
  has_command az && run_with_timeout 10 az account show &>/dev/null
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

  # Datadog: API key (DD_API_KEY or DATADOG_API_KEY); validate when possible
  if has_datadog_api_key 2>/dev/null; then
    if datadog_validate_api_key 2>/dev/null; then
      export CLAUDESEC_ENV_DATADOG_CONNECTED="true"
    else
      # Key present but validation failed (e.g. network or invalid key)
      export CLAUDESEC_ENV_DATADOG_CONNECTED="true"
    fi
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
    SAAS-API-*) echo "NIST:AC-2,CM-6|ISO:A.9,A.12|ISMS-P:2.5,2.10|SOC2:CC6.1,CC6.6" ;;
    SAAS-*) echo "NIST:AC-2,CM-6|ISO:A.9,A.12|ISMS-P:2.5,2.10|SOC2:CC6.1,CC6.6" ;;
    WIN-*) echo "KISA-W:W-01~W-84|NIST:CM-6,AC-2,IA-5|ISO:A.8,A.9|ISMS-P:2.5,2.10" ;;
    PROWLER-*) echo "NIST:AC,CM,IA,SC|ISO:A.8,A.9,A.12,A.14|CIS:Benchmark|SOC2:CC6,CC7,CC8" ;;
    *) echo "" ;;
  esac
}
