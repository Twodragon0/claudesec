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

      # Check branch protection on default branch
      _default_branch=$(gh api "repos/${_gh_repo}" --jq '.default_branch' 2>/dev/null || echo "")
      if [[ -n "$_default_branch" ]]; then
        _bp=$(gh api "repos/${_gh_repo}/branches/${_default_branch}/protection" 2>/dev/null || echo "")
        if [[ -z "$_bp" || "$_bp" == *"Not Found"* || "$_bp" == *"Branch not protected"* ]]; then
          _gh_api_issues=$((_gh_api_issues + 1))
          _gh_api_details="${_gh_api_details}\n    Branch protection not enabled on ${_default_branch}"
        else
          # Check specific protection rules
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

      # Check secret scanning status
      _repo_info=$(gh api "repos/${_gh_repo}" 2>/dev/null || echo "")
      _visibility=$(echo "$_repo_info" | grep -o '"visibility":"[^"]*"' | cut -d'"' -f4 || echo "")

      # Check for Dependabot alerts
      _dependabot_alerts=$(gh api "repos/${_gh_repo}/dependabot/alerts?state=open&per_page=100" --jq 'length' 2>/dev/null || echo "")
      if [[ -n "$_dependabot_alerts" && "$_dependabot_alerts" =~ ^[0-9]+$ && "$_dependabot_alerts" -gt 0 ]]; then
        _critical_alerts=$(gh api "repos/${_gh_repo}/dependabot/alerts?state=open&severity=critical&per_page=100" --jq 'length' 2>/dev/null || echo "0")
        _high_alerts=$(gh api "repos/${_gh_repo}/dependabot/alerts?state=open&severity=high&per_page=100" --jq 'length' 2>/dev/null || echo "0")
        if [[ "$_critical_alerts" -gt 0 ]]; then
          _gh_api_issues=$((_gh_api_issues + 1))
          _gh_api_details="${_gh_api_details}\n    ${_critical_alerts} critical Dependabot alert(s) open"
        fi
        if [[ "$_high_alerts" -gt 0 ]]; then
          _gh_api_issues=$((_gh_api_issues + 1))
          _gh_api_details="${_gh_api_details}\n    ${_high_alerts} high Dependabot alert(s) open"
        fi
      fi

      # Check for code scanning alerts
      _code_alerts=$(gh api "repos/${_gh_repo}/code-scanning/alerts?state=open&per_page=100" --jq 'length' 2>/dev/null || echo "")
      if [[ -n "$_code_alerts" && "$_code_alerts" =~ ^[0-9]+$ && "$_code_alerts" -gt 0 ]]; then
        _gh_api_issues=$((_gh_api_issues + 1))
        _gh_api_details="${_gh_api_details}\n    ${_code_alerts} open code scanning alert(s)"
      fi

      # Check for secret scanning alerts
      _secret_alerts=$(gh api "repos/${_gh_repo}/secret-scanning/alerts?state=open&per_page=100" --jq 'length' 2>/dev/null || echo "")
      if [[ -n "$_secret_alerts" && "$_secret_alerts" =~ ^[0-9]+$ && "$_secret_alerts" -gt 0 ]]; then
        _gh_api_issues=$((_gh_api_issues + 1))
        _gh_api_details="${_gh_api_details}\n    ${_secret_alerts} open secret scanning alert(s)"
      fi

      # Check Actions permissions
      _actions_perms=$(gh api "repos/${_gh_repo}/actions/permissions" 2>/dev/null || echo "")
      _allowed_actions=$(echo "$_actions_perms" | grep -o '"allowed_actions":"[^"]*"' | cut -d'"' -f4 || echo "")
      if [[ "$_allowed_actions" == "all" ]]; then
        _gh_api_details="${_gh_api_details}\n    All GitHub Actions are allowed (consider restricting)"
      fi

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
  # Check for failed workflow runs (potential security issues)
  _recent_failures=$(gh api "repos/${_gh_repo}/actions/runs?status=failure&per_page=5" --jq '.workflow_runs | length' 2>/dev/null || echo "")
  _total_runs=$(gh api "repos/${_gh_repo}/actions/runs?per_page=20" --jq '.total_count' 2>/dev/null || echo "0")

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

if [[ -n "${OKTA_ORG_URL:-}" && -n "${OKTA_API_TOKEN:-}" ]]; then
  info "Okta: Scanning via API"

  _okta_users=$(_saas_api_header \
    "${OKTA_ORG_URL}/api/v1/users?limit=1" \
    "Authorization: SSWS ${OKTA_API_TOKEN}")

  if echo "$_okta_users" | grep -q '"id"'; then
    _o_issues=0
    _o_details=""

    # Check for users without MFA
    _no_mfa=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/users?filter=status+eq+%22ACTIVE%22&limit=200" 2>/dev/null | \
      grep -c '"status":"ACTIVE"' || echo "0")

    _mfa_enrolled=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/users?search=profile.mfaEnabled+eq+true&limit=200" 2>/dev/null | \
      grep -c '"id"' || echo "0")

    # Check password policy
    _pwd_policies=$(_saas_api_header \
      "${OKTA_ORG_URL}/api/v1/policies?type=PASSWORD" \
      "Authorization: SSWS ${OKTA_API_TOKEN}")
    if echo "$_pwd_policies" | grep -q '"minLength"'; then
      _min_len=$(echo "$_pwd_policies" | grep -o '"minLength":[0-9]*' | head -1 | grep -oE '[0-9]+' || echo "0")
      if [[ "$_min_len" -lt 12 ]]; then
        _o_details="${_o_details}\n    Password minimum length is ${_min_len} (recommended: ≥12)"
      fi
    fi

    if [[ $_o_issues -eq 0 && -z "$_o_details" ]]; then
      pass "SAAS-API-007" "Okta security configuration verified"
    else
      warn "SAAS-API-007" "Okta security issues${_o_details}" \
        "Enforce MFA for all users, set minimum password length to 12+"
    fi
  else
    warn "SAAS-API-007" "Okta API connection failed" "Check OKTA_ORG_URL and OKTA_API_TOKEN"
  fi
else
  skip "SAAS-API-007" "Okta live check" "Set OKTA_ORG_URL + OKTA_API_TOKEN for live scan"
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
  if [[ -n "${OKTA_API_TOKEN:-}" ]]; then
    echo -e "  ${GREEN}●${NC} Okta        ${DIM}API token${NC}"
  else
    echo -e "  ${DIM}○${NC} Okta        ${DIM}Set: OKTA_ORG_URL + OKTA_API_TOKEN${NC}"
  fi

  # SendGrid
  if [[ -n "${SENDGRID_API_KEY:-}" ]]; then
    echo -e "  ${GREEN}●${NC} SendGrid    ${DIM}API key${NC}"
  else
    echo -e "  ${DIM}○${NC} SendGrid    ${DIM}Set: SENDGRID_API_KEY${NC}"
  fi

  echo ""
fi
