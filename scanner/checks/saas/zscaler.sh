#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Zscaler ZIA Live API Security Checks
# Authenticates to ZIA API and audits security posture.
#
# PRIVACY: Only aggregate counts are used — no PII (emails, names, departments)
# is ever logged, printed, or stored.
#
# Required env vars (from ~/.claudesec.env):
#   ZSCALER_API_KEY, ZSCALER_API_ADMIN, ZSCALER_API_PASSWORD, ZSCALER_BASE_URL
# ============================================================================

# ── SAAS-ZIA-001: Zscaler API Authentication ────────────────────────────────

if [[ -z "${ZSCALER_API_KEY:-}" || -z "${ZSCALER_API_ADMIN:-}" || \
      -z "${ZSCALER_API_PASSWORD:-}" || -z "${ZSCALER_BASE_URL:-}" ]]; then
  skip "SAAS-ZIA-001" "Zscaler ZIA API scan" \
    "Credentials not configured (set ZSCALER_* in ~/.claudesec.env)"
else
  info "Zscaler ZIA: Scanning via API (${ZSCALER_BASE_URL})"

  # Call Python helper — returns sanitized JSON (counts only, no PII)
  _zia_json=$(python3 "$LIB_DIR/zscaler-api.py" 2>/dev/null || echo '{"error":"python_failed"}')
  _zia_error=$(echo "$_zia_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "parse_failed")

  if [[ -n "$_zia_error" && "$_zia_error" != "" ]]; then
    if [[ "$_zia_error" == "auth_failed" ]]; then
      fail "SAAS-ZIA-001" "Zscaler ZIA API authentication failed" "high" \
        "API key or credentials rejected" \
        "Verify ZSCALER_API_KEY, ZSCALER_API_ADMIN, ZSCALER_API_PASSWORD in ~/.claudesec.env"
    elif [[ "$_zia_error" == "missing_credentials" ]]; then
      skip "SAAS-ZIA-001" "Zscaler ZIA API scan" "Incomplete credentials"
    else
      warn "SAAS-ZIA-001" "Zscaler ZIA API connection error: ${_zia_error}" \
        "Check network connectivity and ZSCALER_BASE_URL"
    fi
  else
    # Auth succeeded
    _zia_status=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('service_status','UNKNOWN'))" 2>/dev/null)

    if [[ "$_zia_status" == "ACTIVE" ]]; then
      pass "SAAS-ZIA-001" "Zscaler ZIA API authenticated, service ACTIVE"
    else
      warn "SAAS-ZIA-001" "Zscaler ZIA authenticated but service status: ${_zia_status}" \
        "Verify Zscaler subscription and service health"
    fi

    # ── SAAS-ZIA-002: User Hygiene (aggregate counts only) ──────────────────

    _zia_users_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('users',{}).get('accessible',False))" 2>/dev/null)

    if [[ "$_zia_users_accessible" == "True" ]]; then
      _zia_total=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['users']['total'])" 2>/dev/null)
      _zia_no_group=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['users']['no_group'])" 2>/dev/null)
      _zia_unassigned=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['users']['unassigned'])" 2>/dev/null)

      _zia_user_issues=0
      _zia_user_details=""

      if [[ "$_zia_unassigned" -gt 0 ]]; then
        _zia_user_issues=$((_zia_user_issues + 1))
        _zia_user_details="${_zia_user_details}\n    ${_zia_unassigned}/${_zia_total} users have no group AND no department assigned"
      fi

      if [[ "$_zia_no_group" -gt 5 ]]; then
        _zia_user_issues=$((_zia_user_issues + 1))
        _zia_user_details="${_zia_user_details}\n    ${_zia_no_group}/${_zia_total} users not assigned to any group"
      fi

      if [[ $_zia_user_issues -eq 0 ]]; then
        pass "SAAS-ZIA-002" "Zscaler user hygiene healthy (${_zia_total} users, all assigned)"
      elif [[ $_zia_user_issues -eq 1 && "$_zia_unassigned" -lt 5 ]]; then
        warn "SAAS-ZIA-002" "Zscaler minor user hygiene issues (${_zia_total} users)${_zia_user_details}" \
          "Assign all users to appropriate groups and departments in ZIA Admin Portal"
      else
        fail "SAAS-ZIA-002" "Zscaler user hygiene issues (${_zia_total} users)" "medium" \
          "${_zia_user_issues} issue(s) detected${_zia_user_details}" \
          "Review unassigned users in ZIA Admin Portal > User Management"
      fi
    else
      skip "SAAS-ZIA-002" "Zscaler user hygiene" "Users API not accessible (RBA restricted)"
    fi

    # ── SAAS-ZIA-003: Advanced Settings Audit ───────────────────────────────

    _zia_adv_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('advanced_settings',{}).get('accessible',False))" 2>/dev/null)

    if [[ "$_zia_adv_accessible" == "True" ]]; then
      _zia_bypass_urls=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['advanced_settings']['auth_bypass_urls_count'])" 2>/dev/null)
      _zia_bypass_apps=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['advanced_settings']['auth_bypass_apps_count'])" 2>/dev/null)
      _zia_df_bypass=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['advanced_settings']['domain_fronting_bypass_count'])" 2>/dev/null)

      _zia_adv_issues=0
      _zia_adv_details=""

      if [[ "$_zia_bypass_urls" -gt 10 ]]; then
        _zia_adv_issues=$((_zia_adv_issues + 1))
        _zia_adv_details="${_zia_adv_details}\n    ${_zia_bypass_urls} auth bypass URLs configured (excessive)"
      fi

      if [[ "$_zia_bypass_apps" -gt 5 ]]; then
        _zia_adv_issues=$((_zia_adv_issues + 1))
        _zia_adv_details="${_zia_adv_details}\n    ${_zia_bypass_apps} auth bypass apps configured"
      fi

      if [[ "$_zia_df_bypass" -gt 0 ]]; then
        _zia_adv_issues=$((_zia_adv_issues + 1))
        _zia_adv_details="${_zia_adv_details}\n    ${_zia_df_bypass} domain fronting bypass categories (potential evasion risk)"
      fi

      if [[ $_zia_adv_issues -eq 0 ]]; then
        pass "SAAS-ZIA-003" "Zscaler advanced settings secure (bypass URLs: ${_zia_bypass_urls}, bypass apps: ${_zia_bypass_apps})"
      elif [[ $_zia_adv_issues -eq 1 ]]; then
        warn "SAAS-ZIA-003" "Zscaler advanced settings review recommended${_zia_adv_details}" \
          "Minimize auth bypass entries and review domain fronting bypass in ZIA Policy"
      else
        fail "SAAS-ZIA-003" "Zscaler advanced settings security risks" "medium" \
          "${_zia_adv_issues} concern(s)${_zia_adv_details}" \
          "Audit and reduce bypass rules in ZIA Admin > Advanced Settings"
      fi
    else
      skip "SAAS-ZIA-003" "Zscaler advanced settings" "Advanced settings API not accessible"
    fi

    # ── SAAS-ZIA-004: API Permission Scope Audit ────────────────────────────

    _zia_acc_count=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('policy_access',{}).get('accessible_count',0))" 2>/dev/null)
    _zia_rest_count=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('policy_access',{}).get('restricted_count',0))" 2>/dev/null)

    if [[ "$_zia_acc_count" -gt 5 ]]; then
      warn "SAAS-ZIA-004" "Zscaler API key has broad access (${_zia_acc_count} policy endpoints accessible)" \
        "Apply least-privilege: restrict API key scope to only required endpoints in ZIA Admin > API Key Management"
    elif [[ "$_zia_rest_count" -gt 0 ]]; then
      pass "SAAS-ZIA-004" "Zscaler API key has scoped access (${_zia_acc_count} accessible, ${_zia_rest_count} restricted)"
    else
      pass "SAAS-ZIA-004" "Zscaler API key permissions validated"
    fi

    # ── SAAS-ZIA-005: Group & Department Coverage ───────────────────────────

    _zia_groups_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('groups',{}).get('accessible',False))" 2>/dev/null)
    _zia_depts_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('departments',{}).get('accessible',False))" 2>/dev/null)

    if [[ "$_zia_groups_accessible" == "True" && "$_zia_depts_accessible" == "True" ]]; then
      _zia_group_count=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['groups']['total'])" 2>/dev/null)
      _zia_dept_count=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['departments']['total'])" 2>/dev/null)

      if [[ "$_zia_group_count" -lt 2 ]]; then
        warn "SAAS-ZIA-005" "Zscaler has very few groups (${_zia_group_count}) — granular policy enforcement may be limited" \
          "Create role-based groups for differentiated security policies"
      else
        pass "SAAS-ZIA-005" "Zscaler org structure healthy (${_zia_group_count} groups, ${_zia_dept_count} departments)"
      fi
    else
      skip "SAAS-ZIA-005" "Zscaler org coverage" "Groups/Departments API not accessible"
    fi

    # ── SAAS-ZIA-006: NSS Log Streaming Configuration ─────────────────────

    _zia_nss_count=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('nss_feeds',{}).get('total',0))" 2>/dev/null)
    _zia_nss_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('nss_feeds',{}).get('accessible',False))" 2>/dev/null)

    if [[ "$_zia_nss_accessible" == "True" ]]; then
      if [[ "$_zia_nss_count" -eq 0 ]]; then
        fail "SAAS-ZIA-006" "Zscaler NSS log streaming not configured" "high" \
          "No NSS feeds found — security logs are not being streamed to any SIEM" \
          "Configure NSS feeds in ZIA Admin > Nanolog Streaming Service to stream logs to Datadog/Splunk/etc"
      else
        pass "SAAS-ZIA-006" "Zscaler NSS log streaming configured (${_zia_nss_count} feed(s))"
      fi
    else
      skip "SAAS-ZIA-006" "Zscaler NSS feeds" "NSS API not accessible"
    fi

    # ── SAAS-ZIA-007: SAML/SSO & Provisioning Configuration ─────────────

    _zia_auth_accessible=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('auth_settings',{}).get('accessible',False))" 2>/dev/null)

    if [[ "$_zia_auth_accessible" == "True" ]]; then
      _zia_saml=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_settings']['saml_enabled'])" 2>/dev/null)
      _zia_auto_prov=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_settings']['auto_provision'])" 2>/dev/null)
      _zia_auth_freq=$(echo "$_zia_json" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_settings']['auth_frequency'])" 2>/dev/null)

      _zia_sso_issues=0
      _zia_sso_details=""

      if [[ "$_zia_saml" != "True" ]]; then
        _zia_sso_issues=$((_zia_sso_issues + 1))
        _zia_sso_details="${_zia_sso_details}\n    SAML SSO not enabled — users authenticate with local credentials only"
      fi

      if [[ "$_zia_auto_prov" != "True" ]]; then
        _zia_sso_issues=$((_zia_sso_issues + 1))
        _zia_sso_details="${_zia_sso_details}\n    SCIM auto-provisioning disabled — user/group sync requires manual management"
      fi

      if [[ "$_zia_auth_freq" == "PERMANENT_COOKIE" ]]; then
        _zia_sso_details="${_zia_sso_details}\n    Auth frequency set to PERMANENT_COOKIE — consider periodic re-authentication"
      fi

      if [[ $_zia_sso_issues -eq 0 ]]; then
        pass "SAAS-ZIA-007" "Zscaler SAML SSO enabled with auto-provisioning"
      elif [[ "$_zia_saml" == "True" ]]; then
        warn "SAAS-ZIA-007" "Zscaler SAML SSO enabled but improvements recommended${_zia_sso_details}" \
          "Enable SCIM auto-provisioning in ZIA Admin > Authentication Settings for automated user/group sync"
      else
        fail "SAAS-ZIA-007" "Zscaler SSO/provisioning issues" "high" \
          "${_zia_sso_issues} issue(s)${_zia_sso_details}" \
          "Enable SAML SSO and SCIM in ZIA Admin > Authentication Settings"
      fi
    else
      skip "SAAS-ZIA-007" "Zscaler SSO/auth settings" "Auth settings API not accessible"
    fi
  fi
fi
