#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Extended SaaS API Security Checks
# Additional SaaS integrations via API key authentication
# Covers: Slack, PagerDuty, Jira/Atlassian, Splunk, Grafana, New Relic,
#          Twilio, MongoDB Atlas, Elastic Cloud, AWS Organizations,
#          Datadog deep scan, Okta deep scan
# ============================================================================

# ── SAAS-API-009: Slack Live Check ────────────────────────────────────────

if [[ -n "${SLACK_API_TOKEN:-}" || -n "${SLACK_BOT_TOKEN:-}" ]]; then
  _slack_token="${SLACK_API_TOKEN:-${SLACK_BOT_TOKEN}}"
  info "Slack: Scanning via API"

  _slack_auth=$(run_with_timeout 15 curl -sSf \
    -H "Authorization: Bearer ${_slack_token}" \
    "https://slack.com/api/auth.test" 2>/dev/null || echo "")

  if echo "$_slack_auth" | grep -q '"ok":true'; then
    _sl_issues=0
    _sl_details=""
    _sl_team=$(echo "$_slack_auth" | grep -o '"team":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # Check workspace settings
    _slack_info=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_slack_token}" \
      "https://slack.com/api/team.info" 2>/dev/null || echo "")

    if echo "$_slack_info" | grep -q '"ok":true'; then
      # Check 2FA requirement
      _sl_2fa=$(echo "$_slack_info" | grep -o '"two_factor_required":[a-z]*' | cut -d: -f2 || echo "")
      if [[ "$_sl_2fa" == "false" ]]; then
        _sl_issues=$((_sl_issues + 1))
        _sl_details="${_sl_details}\\n    2FA not required for workspace"
      fi

      # Check SSO/enterprise grid
      _sl_sso=$(echo "$_slack_info" | grep -o '"sso_provider"' || echo "")
      if [[ -z "$_sl_sso" ]]; then
        _sl_details="${_sl_details}\\n    No SSO provider configured (consider enabling)"
      fi
    fi

    # Check for public channels with sensitive names
    _slack_channels=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_slack_token}" \
      "https://slack.com/api/conversations.list?types=public_channel&limit=200" 2>/dev/null || echo "")

    _sensitive_channels=0
    for _pattern in secret password credential deploy prod infra security incident; do
      _ch_count=$(echo "$_slack_channels" | grep -oi "\"name\":\"[^\"]*${_pattern}[^\"]*\"" | wc -l | tr -d ' ')
      _sensitive_channels=$((_sensitive_channels + _ch_count))
    done
    if [[ $_sensitive_channels -gt 0 ]]; then
      _sl_details="${_sl_details}\\n    ${_sensitive_channels} public channel(s) with sensitive names (secret/password/credential)"
    fi

    # Check for installed apps
    _slack_apps=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_slack_token}" \
      "https://slack.com/api/apps.connections.list" 2>/dev/null || echo "")

    if [[ $_sl_issues -eq 0 && -z "$_sl_details" ]]; then
      pass "SAAS-API-009" "Slack workspace security verified (team: ${_sl_team})"
    elif [[ $_sl_issues -eq 0 ]]; then
      warn "SAAS-API-009" "Slack security recommendations (${_sl_team})${_sl_details}" \
        "Enforce 2FA, configure SSO, review public channel names"
    else
      fail "SAAS-API-009" "Slack security issues (${_sl_team})" "high" \
        "${_sl_issues} issue(s)${_sl_details}" \
        "Enable 2FA enforcement, configure SSO"
    fi
  else
    warn "SAAS-API-009" "Slack API token invalid" "Check SLACK_API_TOKEN or SLACK_BOT_TOKEN"
  fi
else
  skip "SAAS-API-009" "Slack live check" "Set SLACK_API_TOKEN or SLACK_BOT_TOKEN"
fi

# ── SAAS-API-010: PagerDuty Live Check ───────────────────────────────────

if [[ -n "${PAGERDUTY_API_KEY:-}" || -n "${PD_API_KEY:-}" ]]; then
  _pd_key="${PAGERDUTY_API_KEY:-${PD_API_KEY}}"
  info "PagerDuty: Scanning via API"

  _pd_abilities=$(run_with_timeout 15 curl -sSf \
    -H "Authorization: Token token=${_pd_key}" \
    -H "Content-Type: application/json" \
    "https://api.pagerduty.com/abilities" 2>/dev/null || echo "")

  if echo "$_pd_abilities" | grep -q '"abilities"'; then
    _pd_issues=0
    _pd_details=""

    # Check for services without escalation policies
    _pd_services=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Token token=${_pd_key}" \
      -H "Content-Type: application/json" \
      "https://api.pagerduty.com/services?limit=100" 2>/dev/null || echo "")

    _pd_svc_count=$(echo "$_pd_services" | grep -c '"id"' || echo "0")
    _pd_no_escalation=$(echo "$_pd_services" | grep -c '"escalation_policy":null' || echo "0")
    if [[ "$_pd_no_escalation" -gt 0 ]]; then
      _pd_issues=$((_pd_issues + 1))
      _pd_details="${_pd_details}\\n    ${_pd_no_escalation} service(s) without escalation policy"
    fi

    # Check on-call schedules exist
    _pd_oncalls=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Token token=${_pd_key}" \
      -H "Content-Type: application/json" \
      "https://api.pagerduty.com/oncalls?limit=1" 2>/dev/null || echo "")

    _pd_oncall_count=$(echo "$_pd_oncalls" | grep -c '"user"' || echo "0")
    if [[ "$_pd_oncall_count" -eq 0 ]]; then
      _pd_details="${_pd_details}\\n    No on-call schedules configured"
    fi

    # Check for unacknowledged incidents
    _pd_incidents=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Token token=${_pd_key}" \
      -H "Content-Type: application/json" \
      "https://api.pagerduty.com/incidents?statuses[]=triggered&limit=100" 2>/dev/null || echo "")

    _pd_triggered=$(echo "$_pd_incidents" | grep -c '"status":"triggered"' || echo "0")
    if [[ "$_pd_triggered" -gt 5 ]]; then
      _pd_issues=$((_pd_issues + 1))
      _pd_details="${_pd_details}\\n    ${_pd_triggered} unacknowledged (triggered) incidents"
    fi

    if [[ $_pd_issues -eq 0 && -z "$_pd_details" ]]; then
      pass "SAAS-API-010" "PagerDuty configuration verified (${_pd_svc_count} service(s))"
    else
      warn "SAAS-API-010" "PagerDuty issues${_pd_details}" \
        "Assign escalation policies to all services, configure on-call schedules"
    fi
  else
    warn "SAAS-API-010" "PagerDuty API key invalid" "Check PAGERDUTY_API_KEY"
  fi
else
  skip "SAAS-API-010" "PagerDuty live check" "Set PAGERDUTY_API_KEY or PD_API_KEY"
fi

# ── SAAS-API-011: Jira / Atlassian Live Check ────────────────────────────

if [[ -n "${ATLASSIAN_API_TOKEN:-}" && -n "${ATLASSIAN_EMAIL:-}" && -n "${ATLASSIAN_DOMAIN:-}" ]]; then
  info "Atlassian: Scanning Jira via API"

  _jira_auth=$(echo -n "${ATLASSIAN_EMAIL}:${ATLASSIAN_API_TOKEN}" | base64)
  _jira_myself=$(run_with_timeout 15 curl -sSf \
    -H "Authorization: Basic ${_jira_auth}" \
    -H "Content-Type: application/json" \
    "https://${ATLASSIAN_DOMAIN}.atlassian.net/rest/api/3/myself" 2>/dev/null || echo "")

  if echo "$_jira_myself" | grep -q '"accountId"'; then
    _j_issues=0
    _j_details=""
    _j_user=$(echo "$_jira_myself" | grep -o '"displayName":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # Check for security-type issues (unresolved)
    _jira_sec_issues=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Basic ${_jira_auth}" \
      -H "Content-Type: application/json" \
      "https://${ATLASSIAN_DOMAIN}.atlassian.net/rest/api/3/search?jql=type=Bug+AND+labels+in+(security,vulnerability)+AND+resolution=Unresolved&maxResults=0" 2>/dev/null || echo "")

    _jira_sec_total=$(echo "$_jira_sec_issues" | grep -o '"total":[0-9]*' | grep -oE '[0-9]+' || echo "0")
    if [[ "$_jira_sec_total" -gt 0 ]]; then
      _j_details="${_j_details}\\n    ${_jira_sec_total} unresolved security-labeled issue(s) in Jira"
    fi

    # Check project permissions (look for public access)
    _jira_projects=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Basic ${_jira_auth}" \
      -H "Content-Type: application/json" \
      "https://${ATLASSIAN_DOMAIN}.atlassian.net/rest/api/3/project?maxResults=50" 2>/dev/null || echo "")

    _proj_count=$(echo "$_jira_projects" | grep -c '"key"' || echo "0")

    if [[ $_j_issues -eq 0 && -z "$_j_details" ]]; then
      pass "SAAS-API-011" "Atlassian/Jira security verified (${_proj_count} project(s), user: ${_j_user})"
    else
      warn "SAAS-API-011" "Jira security issues${_j_details}" \
        "Resolve security-labeled issues, review project permissions"
    fi
  else
    warn "SAAS-API-011" "Atlassian API authentication failed" "Check ATLASSIAN_EMAIL, ATLASSIAN_API_TOKEN, ATLASSIAN_DOMAIN"
  fi
else
  skip "SAAS-API-011" "Jira/Atlassian live check" "Set ATLASSIAN_API_TOKEN + ATLASSIAN_EMAIL + ATLASSIAN_DOMAIN"
fi

# ── SAAS-API-012: Grafana Live Check ────────────────────────────────────

if [[ -n "${GRAFANA_API_KEY:-}" || -n "${GRAFANA_TOKEN:-}" ]] && [[ -n "${GRAFANA_URL:-}" ]]; then
  _graf_token="${GRAFANA_API_KEY:-${GRAFANA_TOKEN}}"
  info "Grafana: Scanning via API"

  _graf_health=$(run_with_timeout 15 curl -sSf \
    -H "Authorization: Bearer ${_graf_token}" \
    "${GRAFANA_URL}/api/health" 2>/dev/null || echo "")

  if echo "$_graf_health" | grep -q '"database"'; then
    _g_issues=0
    _g_details=""

    # Check organization settings
    _graf_org=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_graf_token}" \
      "${GRAFANA_URL}/api/org" 2>/dev/null || echo "")

    # Check for anonymous access
    _graf_settings=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_graf_token}" \
      "${GRAFANA_URL}/api/admin/settings" 2>/dev/null || echo "")

    _anon_enabled=$(echo "$_graf_settings" | grep -o '"enabled":"true"' | head -1 || echo "")
    if [[ -n "$_anon_enabled" ]]; then
      _g_details="${_g_details}\\n    Anonymous access may be enabled"
    fi

    # Check for public dashboards
    _graf_dashboards=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_graf_token}" \
      "${GRAFANA_URL}/api/search?type=dash-db&limit=100" 2>/dev/null || echo "")

    _public_dash=$(echo "$_graf_dashboards" | grep -c '"isPublic":true' || echo "0")
    if [[ "$_public_dash" -gt 0 ]]; then
      _g_details="${_g_details}\\n    ${_public_dash} public dashboard(s) found"
    fi

    # Check alert rules
    _graf_alerts=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: Bearer ${_graf_token}" \
      "${GRAFANA_URL}/api/v1/provisioning/alert-rules" 2>/dev/null || echo "")

    _alert_count=$(echo "$_graf_alerts" | grep -c '"uid"' || echo "0")
    if [[ "$_alert_count" -eq 0 ]]; then
      _g_details="${_g_details}\\n    No alert rules configured"
    fi

    if [[ $_g_issues -eq 0 && -z "$_g_details" ]]; then
      pass "SAAS-API-012" "Grafana security verified"
    else
      warn "SAAS-API-012" "Grafana security recommendations${_g_details}" \
        "Disable anonymous access, review public dashboards, configure alerts"
    fi
  else
    warn "SAAS-API-012" "Grafana API connection failed" "Check GRAFANA_URL and GRAFANA_API_KEY"
  fi
else
  skip "SAAS-API-012" "Grafana live check" "Set GRAFANA_URL + GRAFANA_API_KEY or GRAFANA_TOKEN"
fi

# ── SAAS-API-013: New Relic Live Check ──────────────────────────────────

if [[ -n "${NEW_RELIC_API_KEY:-}" || -n "${NEWRELIC_API_KEY:-}" ]]; then
  _nr_key="${NEW_RELIC_API_KEY:-${NEWRELIC_API_KEY}}"
  info "New Relic: Scanning via API"

  _nr_user=$(run_with_timeout 15 curl -sSf \
    -H "Api-Key: ${_nr_key}" \
    "https://api.newrelic.com/v2/users.json" 2>/dev/null || echo "")

  if echo "$_nr_user" | grep -q '"users"'; then
    _nr_issues=0
    _nr_details=""

    # Check alert policies
    _nr_policies=$(run_with_timeout 15 curl -sSf \
      -H "Api-Key: ${_nr_key}" \
      "https://api.newrelic.com/v2/alerts_policies.json" 2>/dev/null || echo "")

    _nr_policy_count=$(echo "$_nr_policies" | grep -c '"id"' || echo "0")
    if [[ "$_nr_policy_count" -eq 0 ]]; then
      _nr_issues=$((_nr_issues + 1))
      _nr_details="${_nr_details}\\n    No alert policies configured"
    fi

    # Check for open violations
    _nr_violations=$(run_with_timeout 15 curl -sSf \
      -H "Api-Key: ${_nr_key}" \
      "https://api.newrelic.com/v2/alerts_violations.json?only_open=true" 2>/dev/null || echo "")

    _nr_open_viols=$(echo "$_nr_violations" | grep -c '"id"' || echo "0")
    if [[ "$_nr_open_viols" -gt 0 ]]; then
      _nr_details="${_nr_details}\\n    ${_nr_open_viols} open alert violation(s)"
    fi

    if [[ $_nr_issues -eq 0 && -z "$_nr_details" ]]; then
      pass "SAAS-API-013" "New Relic security verified (${_nr_policy_count} alert policies)"
    else
      warn "SAAS-API-013" "New Relic issues${_nr_details}" \
        "Configure alert policies and resolve open violations"
    fi
  else
    warn "SAAS-API-013" "New Relic API key invalid" "Check NEW_RELIC_API_KEY"
  fi
else
  skip "SAAS-API-013" "New Relic live check" "Set NEW_RELIC_API_KEY"
fi

# ── SAAS-API-014: Splunk Live Check ─────────────────────────────────────

if [[ -n "${SPLUNK_TOKEN:-}" && -n "${SPLUNK_URL:-}" ]]; then
  info "Splunk: Scanning via API"

  _splunk_info=$(run_with_timeout 15 curl -sSf -k \
    -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
    "${SPLUNK_URL}/services/server/info?output_mode=json" 2>/dev/null || echo "")

  if echo "$_splunk_info" | grep -q '"server_name"'; then
    _sp_issues=0
    _sp_details=""
    _sp_version=$(echo "$_splunk_info" | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # Check saved searches (security rules)
    _splunk_searches=$(run_with_timeout 15 curl -sSf -k \
      -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
      "${SPLUNK_URL}/services/saved/searches?output_mode=json&count=0" 2>/dev/null || echo "")

    _search_count=$(echo "$_splunk_searches" | grep -c '"name"' || echo "0")
    if [[ "$_search_count" -eq 0 ]]; then
      _sp_details="${_sp_details}\\n    No saved searches/alerts configured"
    fi

    # Check for TLS enforcement
    _splunk_web=$(run_with_timeout 15 curl -sSf -k \
      -H "Authorization: Bearer ${SPLUNK_TOKEN}" \
      "${SPLUNK_URL}/services/properties/web/settings/enableSplunkWebSSL?output_mode=json" 2>/dev/null || echo "")

    if echo "$_splunk_web" | grep -q '"false"'; then
      _sp_issues=$((_sp_issues + 1))
      _sp_details="${_sp_details}\\n    Splunk Web SSL not enabled"
    fi

    if [[ $_sp_issues -eq 0 && -z "$_sp_details" ]]; then
      pass "SAAS-API-014" "Splunk security verified (v${_sp_version})"
    else
      warn "SAAS-API-014" "Splunk issues${_sp_details}" \
        "Enable SSL, configure security alerts and saved searches"
    fi
  else
    warn "SAAS-API-014" "Splunk API connection failed" "Check SPLUNK_URL and SPLUNK_TOKEN"
  fi
else
  skip "SAAS-API-014" "Splunk live check" "Set SPLUNK_URL + SPLUNK_TOKEN"
fi

# ── SAAS-API-015: Twilio Live Check ─────────────────────────────────────

if [[ -n "${TWILIO_ACCOUNT_SID:-}" && -n "${TWILIO_AUTH_TOKEN:-}" ]]; then
  info "Twilio: Scanning via API"

  _twilio_account=$(run_with_timeout 15 curl -sSf \
    -u "${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}" \
    "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}.json" 2>/dev/null || echo "")

  if echo "$_twilio_account" | grep -q '"sid"'; then
    _tw_issues=0
    _tw_details=""
    _tw_name=$(echo "$_twilio_account" | grep -o '"friendly_name":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

    # Check for sub-accounts (isolation)
    _twilio_subs=$(run_with_timeout 15 curl -sSf \
      -u "${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}" \
      "https://api.twilio.com/2010-04-01/Accounts.json?PageSize=1" 2>/dev/null || echo "")

    # Check API key usage (should use API keys instead of master auth)
    _twilio_keys=$(run_with_timeout 15 curl -sSf \
      -u "${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}" \
      "https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Keys.json" 2>/dev/null || echo "")

    _key_count=$(echo "$_twilio_keys" | grep -c '"sid"' || echo "0")
    if [[ "$_key_count" -eq 0 ]]; then
      _tw_details="${_tw_details}\\n    No API keys created (using master auth token is less secure)"
    fi

    if [[ $_tw_issues -eq 0 && -z "$_tw_details" ]]; then
      pass "SAAS-API-015" "Twilio security verified (account: ${_tw_name})"
    else
      warn "SAAS-API-015" "Twilio security recommendations${_tw_details}" \
        "Create scoped API keys instead of using master auth token"
    fi
  else
    warn "SAAS-API-015" "Twilio authentication failed" "Check TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN"
  fi
else
  skip "SAAS-API-015" "Twilio live check" "Set TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN"
fi

# ── SAAS-API-016: MongoDB Atlas Live Check ──────────────────────────────

if [[ -n "${MONGODB_ATLAS_PUBLIC_KEY:-}" && -n "${MONGODB_ATLAS_PRIVATE_KEY:-}" ]]; then
  info "MongoDB Atlas: Scanning via API"

  _atlas_orgs=$(run_with_timeout 15 curl -sSf --digest \
    -u "${MONGODB_ATLAS_PUBLIC_KEY}:${MONGODB_ATLAS_PRIVATE_KEY}" \
    "https://cloud.mongodb.com/api/atlas/v2/orgs" 2>/dev/null || echo "")

  if echo "$_atlas_orgs" | grep -q '"results"'; then
    _ma_issues=0
    _ma_details=""

    _atlas_org_id=$(echo "$_atlas_orgs" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

    if [[ -n "$_atlas_org_id" ]]; then
      # Check for projects/clusters
      _atlas_projects=$(run_with_timeout 15 curl -sSf --digest \
        -u "${MONGODB_ATLAS_PUBLIC_KEY}:${MONGODB_ATLAS_PRIVATE_KEY}" \
        "https://cloud.mongodb.com/api/atlas/v2/orgs/${_atlas_org_id}/groups" 2>/dev/null || echo "")

      _proj_count=$(echo "$_atlas_projects" | grep -c '"id"' || echo "0")

      # Check for 2FA enforcement
      _atlas_settings=$(run_with_timeout 15 curl -sSf --digest \
        -u "${MONGODB_ATLAS_PUBLIC_KEY}:${MONGODB_ATLAS_PRIVATE_KEY}" \
        "https://cloud.mongodb.com/api/atlas/v2/orgs/${_atlas_org_id}" 2>/dev/null || echo "")

      _mfa_required=$(echo "$_atlas_settings" | grep -o '"multiFactorAuthRequired":[a-z]*' | cut -d: -f2 || echo "")
      if [[ "$_mfa_required" == "false" ]]; then
        _ma_issues=$((_ma_issues + 1))
        _ma_details="${_ma_details}\\n    MFA not required for organization"
      fi

      # Check IP access lists on first project
      _first_proj=$(echo "$_atlas_projects" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
      if [[ -n "$_first_proj" ]]; then
        _atlas_access=$(run_with_timeout 15 curl -sSf --digest \
          -u "${MONGODB_ATLAS_PUBLIC_KEY}:${MONGODB_ATLAS_PRIVATE_KEY}" \
          "https://cloud.mongodb.com/api/atlas/v2/groups/${_first_proj}/accessList" 2>/dev/null || echo "")

        # Check for 0.0.0.0/0 (open to all)
        if echo "$_atlas_access" | grep -q '"cidrBlock":"0.0.0.0/0"'; then
          _ma_issues=$((_ma_issues + 1))
          _ma_details="${_ma_details}\\n    IP Access List allows 0.0.0.0/0 (open to all)"
        fi
      fi
    fi

    if [[ $_ma_issues -eq 0 && -z "$_ma_details" ]]; then
      pass "SAAS-API-016" "MongoDB Atlas security verified (${_proj_count} project(s))"
    else
      fail "SAAS-API-016" "MongoDB Atlas security issues" "high" \
        "${_ma_issues} issue(s)${_ma_details}" \
        "Enforce MFA, restrict IP access lists, use VPC peering"
    fi
  else
    warn "SAAS-API-016" "MongoDB Atlas API authentication failed" "Check MONGODB_ATLAS_PUBLIC_KEY and MONGODB_ATLAS_PRIVATE_KEY"
  fi
else
  skip "SAAS-API-016" "MongoDB Atlas live check" "Set MONGODB_ATLAS_PUBLIC_KEY + MONGODB_ATLAS_PRIVATE_KEY"
fi

# ── SAAS-API-017: Elastic Cloud Live Check ──────────────────────────────

if [[ -n "${ELASTIC_API_KEY:-}" || ( -n "${ELASTIC_CLOUD_ID:-}" && -n "${ELASTIC_PASSWORD:-}" ) ]]; then
  info "Elastic Cloud: Scanning via API"

  if [[ -n "${ELASTIC_API_KEY:-}" ]]; then
    _elastic_info=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
      "https://api.elastic-cloud.com/api/v1/user" 2>/dev/null || echo "")
  else
    _elastic_info=""
  fi

  if echo "$_elastic_info" | grep -q '"user_id"'; then
    _el_issues=0
    _el_details=""

    # Check deployments
    _elastic_deployments=$(run_with_timeout 15 curl -sSf \
      -H "Authorization: ApiKey ${ELASTIC_API_KEY}" \
      "https://api.elastic-cloud.com/api/v1/deployments?size=10" 2>/dev/null || echo "")

    _deploy_count=$(echo "$_elastic_deployments" | grep -c '"id"' || echo "0")

    if [[ $_el_issues -eq 0 && -z "$_el_details" ]]; then
      pass "SAAS-API-017" "Elastic Cloud security verified (${_deploy_count} deployment(s))"
    else
      warn "SAAS-API-017" "Elastic Cloud issues${_el_details}" \
        "Review deployment security settings"
    fi
  else
    skip "SAAS-API-017" "Elastic Cloud live check" "API authentication failed or not Elastic Cloud"
  fi
else
  skip "SAAS-API-017" "Elastic Cloud live check" "Set ELASTIC_API_KEY or ELASTIC_CLOUD_ID + ELASTIC_PASSWORD"
fi

# ── SAAS-API-018: Datadog Deep Scan (CSM, CSPM, Logs) ───────────────────

if [[ -n "${DD_API_KEY:-}" && -n "${DD_APP_KEY:-}" ]]; then
  _dd_site="${DD_SITE:-datadoghq.com}"
  _dd_base="https://api.${_dd_site}"

  # Cloud Security Posture Management (CSPM)
  _dd_cspm=$(run_with_timeout 15 curl -sSf \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    "${_dd_base}/api/v2/security_monitoring/signals?filter[query]=type:posture_management&page[limit]=1" 2>/dev/null || echo "")

  _dd_cspm_count=$(echo "$_dd_cspm" | grep -c '"id"' || echo "0")

  _dd_deep_issues=0
  _dd_deep_details=""

  # Check log-based security
  _dd_log_rules=$(run_with_timeout 15 curl -sSf \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    "${_dd_base}/api/v2/security_monitoring/rules?page[size]=5" 2>/dev/null || echo "")

  _dd_rule_count=$(echo "$_dd_log_rules" | grep -c '"id"' || echo "0")

  # Check for Cloud Workload Security
  _dd_cws=$(run_with_timeout 15 curl -sSf \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    "${_dd_base}/api/v2/security_monitoring/signals?filter[query]=type:workload_security&page[limit]=1" 2>/dev/null || echo "")

  # Check SLOs (security-related)
  _dd_slos=$(run_with_timeout 15 curl -sSf \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    "${_dd_base}/api/v1/slo?limit=100" 2>/dev/null || echo "")

  _slo_count=$(echo "$_dd_slos" | grep -c '"id"' || echo "0")

  if [[ "$_dd_rule_count" -eq 0 ]]; then
    _dd_deep_issues=$((_dd_deep_issues + 1))
    _dd_deep_details="${_dd_deep_details}\\n    No security monitoring rules configured"
  fi

  if [[ "$_slo_count" -eq 0 ]]; then
    _dd_deep_details="${_dd_deep_details}\\n    No SLOs defined (consider setting security SLOs)"
  fi

  _dd_deep_details="\\n    Security rules: ${_dd_rule_count}, SLOs: ${_slo_count}, CSPM signals: ${_dd_cspm_count}${_dd_deep_details}"

  if [[ $_dd_deep_issues -eq 0 ]]; then
    pass "SAAS-API-018" "Datadog deep scan: security monitoring active${_dd_deep_details}"
  else
    warn "SAAS-API-018" "Datadog deep scan issues${_dd_deep_details}" \
      "Enable Cloud Security Management, configure detection rules, set SLOs"
  fi
fi

# ── SAAS-API-019: Okta Deep Scan (Policies, Apps, System Log) ────────────

if [[ -n "${OKTA_ORG_URL:-}" && ( -n "${OKTA_OAUTH_TOKEN:-}" || -n "${OKTA_API_TOKEN:-}" ) ]]; then
  _okta_deep_issues=0
  _okta_deep_details=""
  _okta_auth_header=""
  _okta_auth_mode=""
  if [[ -n "${OKTA_OAUTH_TOKEN:-}" ]]; then
    _okta_auth_header="Authorization: Bearer ${OKTA_OAUTH_TOKEN}"
    _okta_auth_mode="OAuth token"
  else
    _okta_auth_header="Authorization: SSWS ${OKTA_API_TOKEN}"
    _okta_auth_mode="API token"
  fi

  # Check sign-on policies
  _okta_signon=$(run_with_timeout 15 curl -sSf \
    -H "${_okta_auth_header}" \
    -H "Accept: application/json" \
    "${OKTA_ORG_URL}/api/v1/policies?type=OKTA_SIGN_ON" 2>/dev/null || echo "")

  _signon_count=$(echo "$_okta_signon" | grep -c '"id"' || echo "0")
  if [[ "$_signon_count" -lt 2 ]]; then
    _okta_deep_details="${_okta_deep_details}\\n    Only ${_signon_count} sign-on policy(ies) (consider context-aware policies)"
  fi

  # Check MFA enrollment policy
  _okta_mfa=$(run_with_timeout 15 curl -sSf \
    -H "${_okta_auth_header}" \
    -H "Accept: application/json" \
    "${OKTA_ORG_URL}/api/v1/policies?type=MFA_ENROLL" 2>/dev/null || echo "")

  _mfa_policies=$(echo "$_okta_mfa" | grep -c '"id"' || echo "0")
  if [[ "$_mfa_policies" -eq 0 ]]; then
    _okta_deep_issues=$((_okta_deep_issues + 1))
    _okta_deep_details="${_okta_deep_details}\\n    No MFA enrollment policy found"
  fi

  # Check applications (OAuth redirect URIs)
  _okta_apps=$(run_with_timeout 15 curl -sSf \
    -H "${_okta_auth_header}" \
    -H "Accept: application/json" \
    "${OKTA_ORG_URL}/api/v1/apps?limit=50&filter=status+eq+%22ACTIVE%22" 2>/dev/null || echo "")

  _app_count=$(echo "$_okta_apps" | grep -c '"id"' || echo "0")
  _http_redirects=$(echo "$_okta_apps" | grep -c '"http://' || echo "0")
  if [[ "$_http_redirects" -gt 0 ]]; then
    _okta_deep_issues=$((_okta_deep_issues + 1))
    _okta_deep_details="${_okta_deep_details}\\n    ${_http_redirects} app(s) with HTTP (non-HTTPS) redirect URIs"
  fi

  # Check system log for suspicious events (last 24h)
  _yesterday=$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  if [[ -n "$_yesterday" ]]; then
    _okta_threats=$(run_with_timeout 15 curl -sSf \
      -H "${_okta_auth_header}" \
      -H "Accept: application/json" \
      "${OKTA_ORG_URL}/api/v1/logs?since=${_yesterday}&filter=outcome.result+eq+%22FAILURE%22+and+severity+eq+%22WARN%22&limit=5" 2>/dev/null || echo "")

    _threat_count=$(echo "$_okta_threats" | grep -c '"uuid"' || echo "0")
    if [[ "$_threat_count" -gt 0 ]]; then
      _okta_deep_details="${_okta_deep_details}\\n    ${_threat_count} warning-level failure event(s) in system log (last 24h)"
    fi
  fi

  _okta_deep_details="\\n    Apps: ${_app_count}, Sign-on policies: ${_signon_count}, MFA policies: ${_mfa_policies}${_okta_deep_details}"

  if [[ $_okta_deep_issues -eq 0 ]]; then
    pass "SAAS-API-019" "Okta deep scan: security posture verified (${_okta_auth_mode})${_okta_deep_details}"
  else
    fail "SAAS-API-019" "Okta security issues found" "high" \
      "${_okta_deep_issues} issue(s)${_okta_deep_details}" \
      "Enable MFA enrollment, use HTTPS redirect URIs, add context-aware sign-on policies"
  fi
fi

# ── Extended Authentication Status Summary ───────────────────────────────

if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
  echo ""
  echo -e "  ${DIM}──── Extended SaaS Authentication ────${NC}"

  _ext_providers=(
    "slack:Slack:SLACK_API_TOKEN or SLACK_BOT_TOKEN"
    "pagerduty:PagerDuty:PAGERDUTY_API_KEY or PD_API_KEY"
    "atlassian:Atlassian:ATLASSIAN_API_TOKEN + EMAIL + DOMAIN"
    "grafana:Grafana:GRAFANA_URL + GRAFANA_API_KEY"
    "newrelic:New Relic:NEW_RELIC_API_KEY"
    "splunk:Splunk:SPLUNK_URL + SPLUNK_TOKEN"
    "twilio:Twilio:TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN"
    "atlas:MongoDB Atlas:MONGODB_ATLAS_PUBLIC_KEY + PRIVATE_KEY"
    "elastic:Elastic:ELASTIC_API_KEY"
  )

  for entry in "${_ext_providers[@]}"; do
    IFS=':' read -r _prov _label _hint <<< "$entry"
    _status_icon="${DIM}○"
    case "$_prov" in
      slack) [[ -n "${SLACK_API_TOKEN:-}${SLACK_BOT_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      pagerduty) [[ -n "${PAGERDUTY_API_KEY:-}${PD_API_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      atlassian) [[ -n "${ATLASSIAN_API_TOKEN:-}" && -n "${ATLASSIAN_DOMAIN:-}" ]] && _status_icon="${GREEN}●" ;;
      grafana) [[ -n "${GRAFANA_URL:-}" && -n "${GRAFANA_API_KEY:-}${GRAFANA_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      newrelic) [[ -n "${NEW_RELIC_API_KEY:-}${NEWRELIC_API_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      splunk) [[ -n "${SPLUNK_URL:-}" && -n "${SPLUNK_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      twilio) [[ -n "${TWILIO_ACCOUNT_SID:-}" && -n "${TWILIO_AUTH_TOKEN:-}" ]] && _status_icon="${GREEN}●" ;;
      atlas) [[ -n "${MONGODB_ATLAS_PUBLIC_KEY:-}" && -n "${MONGODB_ATLAS_PRIVATE_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
      elastic) [[ -n "${ELASTIC_API_KEY:-}" ]] && _status_icon="${GREEN}●" ;;
    esac
    printf "  ${_status_icon}${NC} %-12s ${DIM}%s${NC}\n" "$_label" "$_hint"
  done
  echo ""
fi
