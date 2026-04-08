#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — SaaS Live API Security Checks
# Authenticates via CLI tools / OAuth / API tokens to scan real configurations
# ============================================================================

# ── Helper: SaaS API request with timeout ──────────────────────────────────

_saas_api() {
  local url="$1" token="$2" method="${3:-GET}"
  run_with_timeout 15 curl -sSf -X "$method" \
    -H "Authorization: Bearer $token" \
    -H "Accept: application/json" \
    "$url" 2>/dev/null || echo ""
}

_saas_api_header() {
  local url="$1" header="$2" method="${3:-GET}"
  run_with_timeout 15 curl -sSf -X "$method" \
    -H "$header" \
    -H "Accept: application/json" \
    "$url" 2>/dev/null || echo ""
}

# ── SAAS-API-001: GitHub Live Security Check (gh CLI / OAuth) ─────────────

if has_command gh && is_git_repo; then
  # gh CLI handles OAuth automatically — will prompt login if needed
  _gh_auth=$(gh auth status 2>&1 || true)

  if echo "$_gh_auth" | grep -q "Logged in"; then
    _gh_remote=$(git_remote_url)
    _gh_repo=""

    # Extract owner/repo from remote URL
    if [[ "$_gh_remote" =~ github\.com[:/]([^/]+/[^/.]+) ]]; then
      _gh_repo="${BASH_REMATCH[1]}"
      _gh_repo="${_gh_repo%.git}"
    fi

    if [[ -n "$_gh_repo" ]]; then
      info "GitHub: Scanning ${_gh_repo} via API"

      _gh_api_issues=0
      _gh_api_details=""

      # ── Single GraphQL query to fetch repo metadata + vulnerability alerts ──
      # Replaces 7+ sequential REST calls with one round-trip.
      IFS='/' read -r _gh_owner _gh_name <<< "$_gh_repo"
      _gh_gql=$(gh api graphql -f query='
        query($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            defaultBranchRef { name }
            visibility
            vulnerabilityAlerts(states: OPEN, first: 100) { totalCount
              nodes { securityVulnerability { severity } }
            }
          }
        }' -f owner="$_gh_owner" -f name="$_gh_name" 2>/dev/null || echo "")

      _default_branch=""
      if [[ -n "$_gh_gql" ]]; then
        _default_branch=$(echo "$_gh_gql" | grep -o '"defaultBranchRef":{[^}]*"name":"[^"]*"' | grep -o '"name":"[^"]*"' | cut -d'"' -f4 || echo "")

        # Parse Dependabot vulnerability alerts from GraphQL
        _dep_total=$(echo "$_gh_gql" | grep -o '"totalCount":[0-9]*' | head -1 | grep -oE '[0-9]+' || echo "0")
        if [[ "$_dep_total" -gt 0 ]]; then
          _critical_alerts=$(echo "$_gh_gql" | grep -o '"severity":"CRITICAL"' | wc -l | tr -d ' ')
          _high_alerts=$(echo "$_gh_gql" | grep -o '"severity":"HIGH"' | wc -l | tr -d ' ')
          if [[ "$_critical_alerts" -gt 0 ]]; then
            _gh_api_issues=$((_gh_api_issues + 1))
            _gh_api_details="${_gh_api_details}\n    ${_critical_alerts} critical Dependabot alert(s) open"
          fi
          if [[ "$_high_alerts" -gt 0 ]]; then
            _gh_api_issues=$((_gh_api_issues + 1))
            _gh_api_details="${_gh_api_details}\n    ${_high_alerts} high Dependabot alert(s) open"
          fi
        fi
      fi

      # ── Branch protection (REST — not available in GraphQL without admin scope) ──
      if [[ -n "$_default_branch" ]]; then
        _bp=$(gh api "repos/${_gh_repo}/branches/${_default_branch}/protection" 2>/dev/null || echo "")
        if [[ -z "$_bp" || "$_bp" == *"Not Found"* || "$_bp" == *"Branch not protected"* ]]; then
          _gh_api_issues=$((_gh_api_issues + 1))
          _gh_api_details="${_gh_api_details}\n    Branch protection not enabled on ${_default_branch}"
        else
          _require_reviews=$(echo "$_bp" | grep -o '"required_approving_review_count":[0-9]*' | grep -oE '[0-9]+' || echo "0")
          if [[ "$_require_reviews" -lt 1 ]]; then
            _gh_api_details="${_gh_api_details}\n    No required PR reviews on ${_default_branch}"
          fi

          _status_checks=$(echo "$_bp" | grep -o '"strict":true' || echo "")
          if [[ -z "$_status_checks" ]]; then
            _gh_api_details="${_gh_api_details}\n    Status checks not strict on ${_default_branch}"
          fi
        fi
      fi

      # ── Remaining REST calls (no GraphQL equivalent) — run in parallel ──
      local _tmpdir_gh
      _tmpdir_gh=$(mktemp -d)

      gh api "repos/${_gh_repo}/code-scanning/alerts?state=open&per_page=100" --jq 'length' \
        > "$_tmpdir_gh/code_alerts" 2>/dev/null &
      local _pid_code=$!

      gh api "repos/${_gh_repo}/secret-scanning/alerts?state=open&per_page=100" --jq 'length' \
        > "$_tmpdir_gh/secret_alerts" 2>/dev/null &
      local _pid_secret=$!

      gh api "repos/${_gh_repo}/actions/permissions" \
        > "$_tmpdir_gh/actions_perms" 2>/dev/null &
      local _pid_actions=$!

      wait "$_pid_code" 2>/dev/null || true
      wait "$_pid_secret" 2>/dev/null || true
      wait "$_pid_actions" 2>/dev/null || true

      _code_alerts=$(<"$_tmpdir_gh/code_alerts" 2>/dev/null || echo "")
      if [[ -n "$_code_alerts" && "$_code_alerts" =~ ^[0-9]+$ && "$_code_alerts" -gt 0 ]]; then
        _gh_api_issues=$((_gh_api_issues + 1))
        _gh_api_details="${_gh_api_details}\n    ${_code_alerts} open code scanning alert(s)"
      fi

      _secret_alerts=$(<"$_tmpdir_gh/secret_alerts" 2>/dev/null || echo "")
      if [[ -n "$_secret_alerts" && "$_secret_alerts" =~ ^[0-9]+$ && "$_secret_alerts" -gt 0 ]]; then
        _gh_api_issues=$((_gh_api_issues + 1))
        _gh_api_details="${_gh_api_details}\n    ${_secret_alerts} open secret scanning alert(s)"
      fi

      _actions_perms=$(<"$_tmpdir_gh/actions_perms" 2>/dev/null || echo "")
      _allowed_actions=$(echo "$_actions_perms" | grep -o '"allowed_actions":"[^"]*"' | cut -d'"' -f4 || echo "")
      if [[ "$_allowed_actions" == "all" ]]; then
        _gh_api_details="${_gh_api_details}\n    All GitHub Actions are allowed (consider restricting)"
      fi

      rm -rf "$_tmpdir_gh"

      if [[ $_gh_api_issues -eq 0 && -z "$_gh_api_details" ]]; then
        pass "SAAS-API-001" "GitHub repository security fully configured (${_gh_repo})"
      elif [[ $_gh_api_issues -eq 0 ]]; then
        warn "SAAS-API-001" "GitHub minor recommendations for ${_gh_repo}${_gh_api_details}" \
          "Review branch protection and Actions permissions"
      else
        fail "SAAS-API-001" "GitHub security issues found (${_gh_repo})" "high" \
          "${_gh_api_issues} issue(s) detected${_gh_api_details}" \
          "Fix open alerts and enable branch protection"
      fi
    else
      skip "SAAS-API-001" "GitHub API scan" "Could not determine repository"
    fi
  else
    info "GitHub CLI not authenticated — run 'gh auth login' for live scanning"
    skip "SAAS-API-001" "GitHub API scan" "Not authenticated (gh auth login)"
  fi
else
  skip "SAAS-API-001" "GitHub API scan" "gh CLI not installed or not a git repo"
fi

# ── SAAS-API-002: GitHub Actions Workflow Runs Security ───────────────────

if has_command gh && [[ -n "${_gh_repo:-}" ]] && echo "${_gh_auth:-}" | grep -q "Logged in"; then
  # Check for failed workflow runs (potential security issues) — parallel fetch
  local _tmpdir_wf
  _tmpdir_wf=$(mktemp -d)

  gh api "repos/${_gh_repo}/actions/runs?status=failure&per_page=5" --jq '.workflow_runs | length' \
    > "$_tmpdir_wf/failures" 2>/dev/null &
  gh api "repos/${_gh_repo}/actions/runs?per_page=20" --jq '.total_count' \
    > "$_tmpdir_wf/total" 2>/dev/null &
  wait

  _recent_failures=$(<"$_tmpdir_wf/failures" 2>/dev/null || echo "")
  _total_runs=$(<"$_tmpdir_wf/total" 2>/dev/null || echo "0")
  rm -rf "$_tmpdir_wf"

  if [[ -n "$_total_runs" && "$_total_runs" -gt 0 ]]; then
    # Check for workflows using deprecated/vulnerable actions
    _workflow_files=$(gh api "repos/${_gh_repo}/actions/workflows" --jq '.workflows[].path' 2>/dev/null || echo "")

    _wf_issues=0
    _wf_details=""

    if [[ -n "$_recent_failures" && "$_recent_failures" -gt 3 ]]; then
      _wf_details="${_wf_details}\n    ${_recent_failures}/5 recent workflow runs failed"
    fi

    if [[ $_wf_issues -eq 0 && -z "$_wf_details" ]]; then
      pass "SAAS-API-002" "GitHub Actions workflows healthy (${_total_runs} total runs)"
    else
      warn "SAAS-API-002" "GitHub Actions concerns${_wf_details}" \
        "Review failed workflows and update deprecated actions"
    fi
  else
    skip "SAAS-API-002" "GitHub Actions runs" "No workflow runs found"
  fi
else
  skip "SAAS-API-002" "GitHub Actions runs" "GitHub API not available"
fi

# ── SAAS-API-003: Datadog Live Check ──────────────────────────────────────

if [[ -n "${DD_API_KEY:-}" && -n "${DD_APP_KEY:-}" ]]; then
  info "Datadog: Scanning via API"

  # Validate API key
  _dd_validate=$(_saas_api_header \
    "https://api.datadoghq.com/api/v1/validate" \
    "DD-API-KEY: ${DD_API_KEY}" 2>/dev/null || echo "")

  if echo "$_dd_validate" | grep -q '"valid":true'; then
    _dd_api_issues=0
    _dd_api_details=""

    # Check for active monitors
    _dd_monitors=$(_saas_api_header \
      "https://api.datadoghq.com/api/v1/monitor?page_size=1" \
      "DD-API-KEY: ${DD_API_KEY}" 2>/dev/null || echo "")

    # Check security monitoring rules
    _dd_sec_rules=$(run_with_timeout 15 curl -sSf \
      -H "DD-API-KEY: ${DD_API_KEY}" \
      -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
      "https://api.datadoghq.com/api/v2/security_monitoring/rules?page[size]=1" 2>/dev/null || echo "")

    if echo "$_dd_sec_rules" | grep -q '"data":\[\]'; then
      _dd_api_issues=$((_dd_api_issues + 1))
      _dd_api_details="${_dd_api_details}\n    No security monitoring rules configured"
    fi

    if [[ $_dd_api_issues -eq 0 ]]; then
      pass "SAAS-API-003" "Datadog security monitoring is configured"
    else
      warn "SAAS-API-003" "Datadog security gaps${_dd_api_details}" \
        "Enable Cloud Security Management and configure detection rules"
    fi
  else
    warn "SAAS-API-003" "Datadog API key validation failed" \
      "Check DD_API_KEY and DD_APP_KEY environment variables"
  fi
elif has_command datadog-agent; then
  _dd_status=$(datadog-agent status 2>/dev/null | head -5 || true)
  if [[ -n "$_dd_status" ]]; then
    pass "SAAS-API-003" "Datadog agent is running locally"
  else
    skip "SAAS-API-003" "Datadog live check" "Agent installed but not running"
  fi
else
  skip "SAAS-API-003" "Datadog live check" "Set DD_API_KEY + DD_APP_KEY for live scan"
fi

# ── SAAS-API-004: Cloudflare Live Check ──────────────────────────────────

if [[ -n "${CF_API_TOKEN:-}" ]]; then
  info "Cloudflare: Scanning via API"

  _cf_verify=$(_saas_api "https://api.cloudflare.com/client/v4/user/tokens/verify" "${CF_API_TOKEN}")

  if echo "$_cf_verify" | grep -q '"success":true'; then
    _cf_api_issues=0
    _cf_api_details=""

    # List zones and check SSL settings
    _cf_zones=$(_saas_api "https://api.cloudflare.com/client/v4/zones?per_page=5" "${CF_API_TOKEN}")
    _zone_count=$(echo "$_cf_zones" | grep -o '"count":[0-9]*' | head -1 | grep -oE '[0-9]+' || echo "0")

    if [[ "$_zone_count" -gt 0 ]]; then
      # Check each zone's SSL mode
      _zone_ids=$(echo "$_cf_zones" | grep -oE '"id":"[a-f0-9]{32}"' | head -5 | cut -d'"' -f4 || true)
      for _zid in $_zone_ids; do
        _ssl_setting=$(_saas_api "https://api.cloudflare.com/client/v4/zones/${_zid}/settings/ssl" "${CF_API_TOKEN}")
        _ssl_mode=$(echo "$_ssl_setting" | grep -o '"value":"[^"]*"' | cut -d'"' -f4 || echo "")
        if [[ "$_ssl_mode" == "off" || "$_ssl_mode" == "flexible" ]]; then
          _cf_api_issues=$((_cf_api_issues + 1))
          _cf_api_details="${_cf_api_details}\n    Zone uses SSL mode '${_ssl_mode}' (use full/strict)"
        fi

        # Check WAF status
        _waf=$(_saas_api "https://api.cloudflare.com/client/v4/zones/${_zid}/settings/waf" "${CF_API_TOKEN}")
        _waf_val=$(echo "$_waf" | grep -o '"value":"[^"]*"' | cut -d'"' -f4 || echo "")
        if [[ "$_waf_val" == "off" ]]; then
          _cf_api_details="${_cf_api_details}\n    WAF is disabled on a zone"
        fi
      done
    fi

    if [[ $_cf_api_issues -eq 0 && -z "$_cf_api_details" ]]; then
      pass "SAAS-API-004" "Cloudflare security configuration verified (${_zone_count} zone(s))"
    else
      warn "SAAS-API-004" "Cloudflare security issues${_cf_api_details}" \
        "Enable Full/Strict SSL and WAF on all zones"
    fi
  else
    warn "SAAS-API-004" "Cloudflare API token invalid or expired" \
      "Regenerate token at dash.cloudflare.com/profile/api-tokens"
  fi
elif has_command cloudflared; then
  skip "SAAS-API-004" "Cloudflare live check" "cloudflared found — set CF_API_TOKEN for full scan"
else
  skip "SAAS-API-004" "Cloudflare live check" "Set CF_API_TOKEN for live scan"
fi

# ── SAAS-API-005: Vercel Live Check ──────────────────────────────────────

if [[ -n "${VERCEL_TOKEN:-}" ]]; then
  info "Vercel: Scanning via API"

  _vercel_user=$(_saas_api "https://api.vercel.com/v2/user" "${VERCEL_TOKEN}")

  if echo "$_vercel_user" | grep -q '"id"'; then
    _v_issues=0
    _v_details=""
    _v_username=$(echo "$_vercel_user" | grep -o '"username":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # Check projects for security headers
    _v_projects=$(_saas_api "https://api.vercel.com/v9/projects?limit=10" "${VERCEL_TOKEN}")
    _v_proj_count=$(echo "$_v_projects" | grep -o '"id":"[^"]*"' | wc -l | tr -d ' ' || echo "0")

    # Check for environment variable leakage
    _v_proj_ids=$(echo "$_v_projects" | grep -oE '"id":"[^"]*"' | head -5 | cut -d'"' -f4 || true)
    for _pid in $_v_proj_ids; do
      _v_envs=$(_saas_api "https://api.vercel.com/v9/projects/${_pid}/env" "${VERCEL_TOKEN}")
      _plain_envs=$(echo "$_v_envs" | grep -c '"type":"plain"' || echo "0")
      if [[ "$_plain_envs" -gt 0 ]]; then
        _v_details="${_v_details}\n    Project has ${_plain_envs} plain-text env var(s) (use 'secret' type)"
      fi
    done

    if [[ $_v_issues -eq 0 && -z "$_v_details" ]]; then
      pass "SAAS-API-005" "Vercel configuration verified (${_v_proj_count} project(s), user: ${_v_username})"
    else
      warn "SAAS-API-005" "Vercel security issues${_v_details}" \
        "Use 'secret' or 'encrypted' type for sensitive env vars"
    fi
  else
    warn "SAAS-API-005" "Vercel API token invalid" "Regenerate at vercel.com/account/tokens"
  fi
elif has_command vercel; then
  _vc_whoami=$(vercel whoami 2>/dev/null || echo "")
  if [[ -n "$_vc_whoami" ]]; then
    pass "SAAS-API-005" "Vercel CLI authenticated as ${_vc_whoami}"
  else
    skip "SAAS-API-005" "Vercel live check" "Run 'vercel login' or set VERCEL_TOKEN"
  fi
else
  skip "SAAS-API-005" "Vercel live check" "Set VERCEL_TOKEN for live scan"
fi

# ── SAAS-API-006: Sentry Live Check ──────────────────────────────────────

if [[ -n "${SENTRY_AUTH_TOKEN:-}" ]]; then
  info "Sentry: Scanning via API"

  _sentry_orgs=$(_saas_api "https://sentry.io/api/0/organizations/" "${SENTRY_AUTH_TOKEN}")

  if echo "$_sentry_orgs" | grep -q '"slug"'; then
    _s_issues=0
    _s_details=""

    _org_slug=$(echo "$_sentry_orgs" | grep -o '"slug":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
    if [[ -n "$_org_slug" ]]; then
      # Check for unresolved issues with high priority
      _sentry_issues=$(_saas_api "https://sentry.io/api/0/organizations/${_org_slug}/issues/?query=is:unresolved+level:fatal&limit=5" "${SENTRY_AUTH_TOKEN}")
      _fatal_count=$(echo "$_sentry_issues" | grep -c '"level":"fatal"' || echo "0")
      if [[ "$_fatal_count" -gt 0 ]]; then
        _s_issues=$((_s_issues + 1))
        _s_details="${_s_details}\n    ${_fatal_count} unresolved fatal issue(s) in Sentry"
      fi

      # Check 2FA enforcement
      _org_detail=$(_saas_api "https://sentry.io/api/0/organizations/${_org_slug}/" "${SENTRY_AUTH_TOKEN}")
      _require_2fa=$(echo "$_org_detail" | grep -o '"require2FA":[a-z]*' | cut -d: -f2 || echo "")
      if [[ "$_require_2fa" == "false" ]]; then
        _s_details="${_s_details}\n    2FA not enforced for organization"
      fi
    fi

    if [[ $_s_issues -eq 0 && -z "$_s_details" ]]; then
      pass "SAAS-API-006" "Sentry security configured (org: ${_org_slug})"
    else
      warn "SAAS-API-006" "Sentry issues${_s_details}" \
        "Resolve fatal errors and enforce 2FA"
    fi
  else
    warn "SAAS-API-006" "Sentry auth token invalid" "Regenerate at sentry.io/settings/auth-tokens/"
  fi
else
  skip "SAAS-API-006" "Sentry live check" "Set SENTRY_AUTH_TOKEN for live scan"
fi

# ── SAAS-API-007: Okta Live Check ────────────────────────────────────────

if [[ -n "${OKTA_ORG_URL:-}" && ( -n "${OKTA_OAUTH_TOKEN:-}" || -n "${OKTA_API_TOKEN:-}" ) ]]; then
  info "Okta: Scanning via API"

  _okta_auth_header=""
  _okta_auth_mode=""
  _okta_auth_warning=""
  _okta_missing_scopes=()
  _okta_unchecked_scopes=()
  _okta_required_scopes=()
  _okta_users=""
  _okta_pwd_policies=""
  _okta_required_scope_csv="${CLAUDESEC_OKTA_REQUIRED_SCOPES:-okta.users.read,okta.policies.read,okta.logs.read}"
  _strict_okta_scopes="${CLAUDESEC_STRICT_OKTA_SCOPES:-0}"
  _strict_okta_scopes="$(printf '%s' "$_strict_okta_scopes" | tr '[:upper:]' '[:lower:]')"
  _strict_okta_scopes_enabled=0
  _require_users_scope=0
  _require_policies_scope=0
  _require_logs_scope=0
  if [[ "$_strict_okta_scopes" == "1" || "$_strict_okta_scopes" == "true" || "$_strict_okta_scopes" == "yes" || "$_strict_okta_scopes" == "on" ]]; then
    _strict_okta_scopes_enabled=1
  fi

  IFS=',' read -r -a _okta_scope_tokens <<< "$_okta_required_scope_csv"
  for _raw_scope in "${_okta_scope_tokens[@]}"; do
    _scope="${_raw_scope//[[:space:]]/}"
    [[ -z "$_scope" ]] && continue
    _already=0
    for _existing in "${_okta_required_scopes[@]}"; do
      if [[ "$_existing" == "$_scope" ]]; then
        _already=1
        break
      fi
    done
    [[ $_already -eq 0 ]] && _okta_required_scopes+=("$_scope")
  done
  if [[ ${#_okta_required_scopes[@]} -eq 0 ]]; then
    _okta_required_scopes=("okta.users.read" "okta.policies.read" "okta.logs.read")
  fi
  for _scope in "${_okta_required_scopes[@]}"; do
    case "$_scope" in
      okta.users.read) _require_users_scope=1 ;;
      okta.policies.read) _require_policies_scope=1 ;;
      okta.logs.read) _require_logs_scope=1 ;;
      *) _okta_unchecked_scopes+=("$_scope") ;;
    esac
  done

  if [[ ${#_okta_unchecked_scopes[@]} -gt 0 ]]; then
    # nosemgrep: bash.lang.security.ifs-tampering — IFS change is scoped to subshell
    _unchecked_scope_list="$(IFS=', '; echo "${_okta_unchecked_scopes[*]}")"
    if [[ $_strict_okta_scopes_enabled -eq 1 ]]; then
      fail "SAAS-API-022" "Okta required scope mapping is incomplete (strict mode)" "medium" \
        "Unmapped scopes in CLAUDESEC_OKTA_REQUIRED_SCOPES: ${_unchecked_scope_list}" \
        "Map these scopes to concrete API checks or remove them from CLAUDESEC_OKTA_REQUIRED_SCOPES"
      exit 1
    fi
    warn "SAAS-API-022" "Okta required scope mapping is incomplete" \
      "Unmapped scopes: ${_unchecked_scope_list}" \
      "Map scopes to API checks to track policy coverage"
  fi
  if [[ -n "${OKTA_OAUTH_TOKEN:-}" ]]; then
    _okta_auth_header="Authorization: Bearer ${OKTA_OAUTH_TOKEN}"
    _okta_auth_mode="OAuth token"

    _okta_users_probe=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
      -H "${_okta_auth_header}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/users?limit=1" 2>/dev/null || echo "")
    _okta_users_code="${_okta_users_probe##*$'\n'}"
    _okta_users_body="${_okta_users_probe%$'\n'*}"
    if [[ "$_okta_users_code" == "403" || "$_okta_users_code" == "401" ]]; then
      if [[ $_require_users_scope -eq 1 ]]; then
        _okta_missing_scopes+=("okta.users.read")
      fi
    elif [[ "$_okta_users_code" =~ ^2 ]]; then
      _okta_users="$_okta_users_body"
    fi

    _okta_policy_probe=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
      -H "${_okta_auth_header}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/policies?type=PASSWORD&limit=1" 2>/dev/null || echo "")
    _okta_policy_code="${_okta_policy_probe##*$'\n'}"
    _okta_policy_body="${_okta_policy_probe%$'\n'*}"
    if [[ "$_okta_policy_code" == "403" || "$_okta_policy_code" == "401" ]]; then
      if [[ $_require_policies_scope -eq 1 ]]; then
        _okta_missing_scopes+=("okta.policies.read")
      fi
    elif [[ "$_okta_policy_code" =~ ^2 ]]; then
      _okta_pwd_policies="$_okta_policy_body"
    fi

    if [[ $_require_logs_scope -eq 1 ]]; then
      _okta_logs_probe=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
        -H "${_okta_auth_header}" \
        -H "Accept: application/json" \
        "${OKTA_ORG_URL}/api/v1/logs?limit=1" 2>/dev/null || echo "")
      _okta_logs_code="${_okta_logs_probe##*$'\n'}"
      if [[ "$_okta_logs_code" == "403" || "$_okta_logs_code" == "401" ]]; then
        _okta_missing_scopes+=("okta.logs.read")
      fi
    fi

    if [[ $_strict_okta_scopes_enabled -eq 1 && ${#_okta_missing_scopes[@]} -gt 0 ]]; then
      # nosemgrep: bash.lang.security.ifs-tampering
      _missing_scope_list="$(IFS=', '; echo "${_okta_missing_scopes[*]}")"
      fail "SAAS-API-007" "Okta OAuth scope validation failed (strict mode)" "high" \
        "Missing required scopes: ${_missing_scope_list}" \
        "Grant required OAuth scopes to the service app"
      exit 1
    fi
  else
    _okta_auth_header="Authorization: SSWS ${OKTA_API_TOKEN}"
    _okta_auth_mode="API token"
    _okta_auth_warning="\n    SSWS API token used (OAuth access token preferred for automation)"
    _okta_users=$(_saas_api_header \
      "${OKTA_ORG_URL}/api/v1/users?limit=1" \
      "${_okta_auth_header}")
  fi

  if echo "$_okta_users" | grep -q '"id"'; then
    _o_issues=0
    _o_details="${_okta_auth_warning}"

    if [[ "$_okta_auth_mode" == "API token" ]]; then
      if [[ ${#OKTA_API_TOKEN} -ne 42 ]]; then
        _o_details="${_o_details}\n    Invalid SSWS token length (expected 42 chars)"
      fi
    fi

    if [[ "$_okta_auth_mode" == "OAuth token" && ${#_okta_missing_scopes[@]} -gt 0 ]]; then
      _o_issues=$((_o_issues + 1))
      # nosemgrep: bash.lang.security.ifs-tampering
      _o_details="${_o_details}\n    Missing OAuth scopes: $(IFS=', '; echo "${_okta_missing_scopes[*]}")"
    fi

    _no_mfa=$(run_with_timeout 15 curl -sSf \
      -H "${_okta_auth_header}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" 2>/dev/null | \
      grep -c '"status":"ACTIVE"' || echo "0")

    _mfa_enrolled=$(run_with_timeout 15 curl -sSf \
      -H "${_okta_auth_header}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/users?search=profile.mfaEnabled+eq+true&limit=200" 2>/dev/null | \
      grep -c '"id"' || echo "0")

    if [[ -z "$_okta_pwd_policies" ]]; then
      _okta_pwd_policies=$(_saas_api_header \
        "${OKTA_ORG_URL}/api/v1/policies?type=PASSWORD" \
        "${_okta_auth_header}")
    fi
    if echo "$_okta_pwd_policies" | grep -q '"minLength"'; then
      _min_len=$(echo "$_okta_pwd_policies" | grep -o '"minLength":[0-9]*' | head -1 | grep -oE '[0-9]+' || echo "0")
      if [[ "$_min_len" -lt 12 ]]; then
        _o_details="${_o_details}\n    Password minimum length is ${_min_len} (recommended: ≥12)"
      fi
    fi

    if [[ $_o_issues -eq 0 && -z "$_o_details" ]]; then
      pass "SAAS-API-007" "Okta security configuration verified (${_okta_auth_mode})"
    else
      warn "SAAS-API-007" "Okta security issues${_o_details}" \
        "Enforce MFA for all users, set minimum password length to 12+"
    fi
  else
    if [[ "$_okta_auth_mode" == "OAuth token" && ${#_okta_missing_scopes[@]} -gt 0 ]]; then
      warn "SAAS-API-007" "Okta OAuth token is missing required scopes" \
        "Missing: $(IFS=', '; echo "${_okta_missing_scopes[*]}")" # nosemgrep: bash.lang.security.ifs-tampering -- subshell scoped
    else
      warn "SAAS-API-007" "Okta API connection failed" "Check OKTA_ORG_URL and OKTA_OAUTH_TOKEN (preferred) or OKTA_API_TOKEN"
    fi
  fi
else
  skip "SAAS-API-007" "Okta live check" "Set OKTA_ORG_URL + OKTA_OAUTH_TOKEN (preferred) or OKTA_API_TOKEN"
fi
# ── SAAS-API-008: SendGrid Live Check ───────────────────────────────────

if [[ -n "${SENDGRID_API_KEY:-}" ]]; then
  info "SendGrid: Scanning via API"

  _sg_user=$(_saas_api "https://api.sendgrid.com/v3/user/profile" "${SENDGRID_API_KEY}")

  if echo "$_sg_user" | grep -q '"username"'; then
    _sg_api_issues=0
    _sg_api_details=""

    # Check API key scopes (should be restricted)
    _sg_scopes=$(_saas_api "https://api.sendgrid.com/v3/scopes" "${SENDGRID_API_KEY}")
    _scope_count=$(echo "$_sg_scopes" | grep -c '"scope"' || echo "0")
    if [[ "$_scope_count" -gt 20 ]]; then
      _sg_api_details="${_sg_api_details}\n    API key has ${_scope_count} scopes (use minimal permissions)"
    fi

    # Check for 2FA
    _sg_2fa=$(_saas_api "https://api.sendgrid.com/v3/user/settings/enforced_tls" "${SENDGRID_API_KEY}")

    # Check sender authentication
    _sg_auth=$(_saas_api "https://api.sendgrid.com/v3/whitelabel/domains" "${SENDGRID_API_KEY}")
    if [[ -z "$_sg_auth" || "$_sg_auth" == "[]" ]]; then
      _sg_api_issues=$((_sg_api_issues + 1))
      _sg_api_details="${_sg_api_details}\n    No domain authentication (SPF/DKIM) configured"
    fi

    if [[ $_sg_api_issues -eq 0 && -z "$_sg_api_details" ]]; then
      pass "SAAS-API-008" "SendGrid security configured"
    else
      warn "SAAS-API-008" "SendGrid security issues${_sg_api_details}" \
        "Configure domain authentication (SPF/DKIM) and use restricted API keys"
    fi
  else
    warn "SAAS-API-008" "SendGrid API key invalid" "Check SENDGRID_API_KEY"
  fi
else
  skip "SAAS-API-008" "SendGrid live check" "Set SENDGRID_API_KEY for live scan"
fi

# ── SAAS-API-020: Harbor Live Check (Registry posture quick scan) ───────────
#
# Minimal, non-invasive checks (no listing of projects/repos by default).
# Env:
#   HARBOR_URL (e.g. https://harbor.example.com)
#   HARBOR_USERNAME + HARBOR_PASSWORD  (basic auth) OR HARBOR_AUTH_HEADER (custom)
#
# References:
# - Harbor API v2.0: https://goharbor.io/docs/

if [[ -n "${HARBOR_URL:-}" ]]; then
  if [[ "${HARBOR_URL}" != https://* ]]; then
    warn "SAAS-API-020" "Harbor URL is not HTTPS" \
      "Set HARBOR_URL to an https:// endpoint (TLS required for registry auth)"
  fi

  _harbor_auth_header=""
  if [[ -n "${HARBOR_AUTH_HEADER:-}" ]]; then
    _harbor_auth_header="${HARBOR_AUTH_HEADER}"
  elif [[ -n "${HARBOR_USERNAME:-}" && -n "${HARBOR_PASSWORD:-}" ]]; then
    _basic=$(printf "%s:%s" "${HARBOR_USERNAME}" "${HARBOR_PASSWORD}" | base64 2>/dev/null | tr -d '\n' || echo "")
    [[ -n "$_basic" ]] && _harbor_auth_header="Authorization: Basic ${_basic}"
  fi

  info "Harbor: Scanning via API"

  _ping=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
    -H "Accept: application/json" \
    "${HARBOR_URL%/}/api/v2.0/ping" 2>/dev/null || echo "")
  _ping_code="${_ping##*$'\n'}"

  if [[ "$_ping_code" =~ ^2 ]]; then
    _hb_issues=0
    _hb_details=""

    # Auth check (optional): request systeminfo (requires auth)
    if [[ -n "$_harbor_auth_header" ]]; then
      _sys=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
        -H "Accept: application/json" \
        -H "${_harbor_auth_header}" \
        "${HARBOR_URL%/}/api/v2.0/systeminfo" 2>/dev/null || echo "")
      _sys_code="${_sys##*$'\n'}"
      if [[ "$_sys_code" =~ ^2 ]]; then
        pass "SAAS-API-020" "Harbor reachable and authenticated API access works"
      else
        warn "SAAS-API-020" "Harbor reachable but auth failed (${_sys_code})" \
          "Provide HARBOR_USERNAME/HARBOR_PASSWORD or HARBOR_AUTH_HEADER with sufficient permissions"
      fi
    else
      warn "SAAS-API-020" "Harbor reachable (ping ok) but no credentials provided" \
        "Set HARBOR_USERNAME + HARBOR_PASSWORD (or HARBOR_AUTH_HEADER) for deeper checks"
    fi
  else
    warn "SAAS-API-020" "Harbor API ping failed (${_ping_code})" \
      "Check HARBOR_URL reachability and allow /api/v2.0/ping"
  fi
else
  skip "SAAS-API-020" "Harbor live check" "Set HARBOR_URL (and credentials for deeper scan)"
fi

# ── SAAS-API-021: Jenkins Live Check (surface hardening signals) ────────────
#
# Env:
#   JENKINS_URL (e.g. https://jenkins.example.com)
#   Optional for authenticated checks: JENKINS_USER + JENKINS_API_TOKEN
#
# References:
# - Jenkins security docs: https://www.jenkins.io/doc/book/security/

if [[ -n "${JENKINS_URL:-}" ]]; then
  info "Jenkins: Scanning via API"

  _j_url="${JENKINS_URL%/}"
  _auth_args=()
  if [[ -n "${JENKINS_USER:-}" && -n "${JENKINS_API_TOKEN:-}" ]]; then
    _auth_args=(-u "${JENKINS_USER}:${JENKINS_API_TOKEN}")
  fi

  _j_issues=0
  _j_details=""

  # 1) Anonymous surface: whoAmI without auth should not disclose user identity
  _who=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
    -H "Accept: application/json" \
    "${_j_url}/whoAmI/api/json" 2>/dev/null || echo "")
  _who_code="${_who##*$'\n'}"
  _who_body="${_who%$'\n'*}"
  if [[ "$_who_code" =~ ^2 ]] && echo "$_who_body" | grep -q '"authenticated"[[:space:]]*:[[:space:]]*true'; then
    _j_issues=$((_j_issues + 1))
    _j_details="${_j_details}\n    whoAmI indicates authenticated=true without credentials (anonymous access too permissive?)"
  fi

  # 2) CSRF crumbs should be enabled (crumbIssuer endpoint should exist)
  _crumb=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
    -H "Accept: application/json" \
    "${_j_url}/crumbIssuer/api/json" 2>/dev/null || echo "")
  _crumb_code="${_crumb##*$'\n'}"
  if [[ "$_crumb_code" == "404" || "$_crumb_code" == "403" ]]; then
    # 403 can be ok if auth required, but 404 suggests crumb issuer disabled/unavailable.
    if [[ "$_crumb_code" == "404" ]]; then
      _j_issues=$((_j_issues + 1))
      _j_details="${_j_details}\n    crumbIssuer endpoint not found (CSRF protection may be disabled)"
    else
      _j_details="${_j_details}\n    crumbIssuer requires auth (good), provide JENKINS_USER/JENKINS_API_TOKEN for confirmation"
    fi
  fi

  # 3) If authenticated creds provided, validate basic API access
  if [[ ${#_auth_args[@]} -gt 0 ]]; then
    _me=$(run_with_timeout 15 curl -sS -w "\n%{http_code}" \
      "${_auth_args[@]}" \
      -H "Accept: application/json" \
      "${_j_url}/user/${JENKINS_USER}/api/json" 2>/dev/null || echo "")
    _me_code="${_me##*$'\n'}"
    if [[ "$_me_code" =~ ^2 ]]; then
      : # ok
    else
      _j_details="${_j_details}\n    Authenticated API call failed (${_me_code})"
    fi
  else
    _j_details="${_j_details}\n    No Jenkins credentials provided (set JENKINS_USER + JENKINS_API_TOKEN for deeper scan)"
  fi

  if [[ $_j_issues -eq 0 ]]; then
    if [[ -z "$_j_details" ]]; then
      pass "SAAS-API-021" "Jenkins basic hardening signals look OK"
    else
      warn "SAAS-API-021" "Jenkins recommendations${_j_details}" \
        "Review anonymous access, confirm CSRF protection (crumb issuer), and scan with API token for deeper checks"
    fi
  else
    fail "SAAS-API-021" "Jenkins security issues detected" "high" \
      "${_j_issues} issue(s)${_j_details}" \
      "Restrict anonymous access and ensure CSRF protection is enabled"
  fi
else
  skip "SAAS-API-021" "Jenkins live check" "Set JENKINS_URL (and optionally JENKINS_USER + JENKINS_API_TOKEN)"
fi

# ── Summary: SaaS Authentication Status ──────────────────────────────────

if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
  echo ""
  echo -e "  ${DIM}──── SaaS Live Scan Authentication ────${NC}"

  # GitHub
  if has_command gh && echo "${_gh_auth:-}" | grep -q "Logged in"; then
    echo -e "  ${GREEN}●${NC} GitHub      ${DIM}gh CLI (OAuth)${NC}"
  else
    echo -e "  ${DIM}○${NC} GitHub      ${DIM}Run: gh auth login${NC}"
  fi

  # AWS
  if has_aws_credentials 2>/dev/null; then
    echo -e "  ${GREEN}●${NC} AWS         ${DIM}SSO / credentials${NC}"
  else
    echo -e "  ${DIM}○${NC} AWS         ${DIM}Run: aws sso login or --aws-sso flag${NC}"
  fi

  # Datadog
  if [[ -n "${DD_API_KEY:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Datadog     ${DIM}API key${NC}"
  else
    echo -e "  ${DIM}○${NC} Datadog     ${DIM}Set: DD_API_KEY + DD_APP_KEY${NC}"
  fi

  # Cloudflare
  if [[ -n "${CF_API_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Cloudflare  ${DIM}API token${NC}"
  else
    echo -e "  ${DIM}○${NC} Cloudflare  ${DIM}Set: CF_API_TOKEN${NC}"
  fi

  # Vercel
  if [[ -n "${VERCEL_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Vercel      ${DIM}API token${NC}"
  elif has_command vercel && vercel whoami &>/dev/null; then
    echo -e "  ${GREEN}●${NC} Vercel      ${DIM}CLI auth${NC}"
  else
    echo -e "  ${DIM}○${NC} Vercel      ${DIM}Set: VERCEL_TOKEN or run: vercel login${NC}"
  fi

  # Sentry
  if [[ -n "${SENTRY_AUTH_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Sentry      ${DIM}Auth token${NC}"
  else
    echo -e "  ${DIM}○${NC} Sentry      ${DIM}Set: SENTRY_AUTH_TOKEN${NC}"
  fi

  # Okta
  if [[ -n "${OKTA_OAUTH_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Okta        ${DIM}OAuth token${NC}"
  elif [[ -n "${OKTA_API_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Okta        ${DIM}API token (fallback)${NC}"
  else
    echo -e "  ${DIM}○${NC} Okta        ${DIM}Set: OKTA_ORG_URL + OKTA_OAUTH_TOKEN (or OKTA_API_TOKEN)${NC}"
  fi

  # SendGrid
  if [[ -n "${SENDGRID_API_KEY:-}" ]]; then
    echo -e "  ${GREEN}●${NC} SendGrid    ${DIM}API key${NC}"
  else
    echo -e "  ${DIM}○${NC} SendGrid    ${DIM}Set: SENDGRID_API_KEY${NC}"
  fi

  echo ""
fi
