#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Cloud credential & auth helpers (split out of checks.sh)
# ============================================================================
# AWS (profiles, SSO login), GCP, Datadog, GitHub, Okta and Azure credential
# detection / login helpers. Sourced by checks.sh after the generic file/command
# helpers it depends on (has_command, run_with_timeout). No behavior change vs
# when these lived inline in checks.sh.

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
