#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — SaaS & Solutions Security Checks
# Scans for security best practices across popular SaaS tools and platforms
# ============================================================================

# ── SAAS-001: GitHub Security Configuration ──────────────────────────────────

if is_git_repo; then
  _gh_score=0
  _gh_total=0
  _gh_issues=""

  # Check for security-relevant GitHub configurations
  _gh_total=$((_gh_total + 1))
  if has_file ".github/dependabot.yml" || has_file ".github/dependabot.yaml"; then
    _gh_score=$((_gh_score + 1))
  else
    _gh_issues="${_gh_issues}\n    Missing: Dependabot configuration"
  fi

  _gh_total=$((_gh_total + 1))
  if has_file ".github/workflows/codeql.yml" || has_file ".github/workflows/codeql-analysis.yml" || \
     files_contain ".github/workflows/*.yml" "(codeql|semgrep|snyk|trivy)" 2>/dev/null; then
    _gh_score=$((_gh_score + 1))
  else
    _gh_issues="${_gh_issues}\n    Missing: Security scanning (CodeQL/Semgrep/Snyk)"
  fi

  _gh_total=$((_gh_total + 1))
  if has_file "SECURITY.md"; then
    _gh_score=$((_gh_score + 1))
  else
    _gh_issues="${_gh_issues}\n    Missing: SECURITY.md disclosure policy"
  fi

  _gh_total=$((_gh_total + 1))
  if has_file ".github/CODEOWNERS"; then
    _gh_score=$((_gh_score + 1))
  else
    _gh_issues="${_gh_issues}\n    Missing: CODEOWNERS file"
  fi

  if [[ $_gh_score -eq $_gh_total ]]; then
    pass "SAAS-001" "GitHub security configuration complete (${_gh_score}/${_gh_total})"
  elif [[ $_gh_score -gt 0 ]]; then
    warn "SAAS-001" "GitHub security partially configured (${_gh_score}/${_gh_total})${_gh_issues}" \
      "Complete all GitHub security features for comprehensive protection"
  else
    fail "SAAS-001" "GitHub security not configured (${_gh_score}/${_gh_total})" "high" \
      "No GitHub security features detected${_gh_issues}" \
      "Add Dependabot, CodeQL, SECURITY.md, and CODEOWNERS"
  fi
else
  skip "SAAS-001" "GitHub security" "Not a git repository"
fi

# ── SAAS-002: GitHub Actions Security ────────────────────────────────────────

if has_dir ".github/workflows"; then
  _gha_issues=""
  _gha_problems=0

  # Check for OIDC usage (preferred over long-lived secrets)
  if files_contain ".github/workflows/*.yml" "aws-actions/configure-aws-credentials" 2>/dev/null && \
     ! files_contain ".github/workflows/*.yml" "role-to-assume" 2>/dev/null; then
    _gha_problems=$((_gha_problems + 1))
    _gha_issues="${_gha_issues}\n    AWS credentials using secrets instead of OIDC"
  fi

  # Check for environment protection rules reference
  if files_contain ".github/workflows/*.yml" "environment:" 2>/dev/null; then
    :  # Good — uses environment protection
  elif files_contain ".github/workflows/*.yml" "deploy\|release\|production" 2>/dev/null; then
    _gha_problems=$((_gha_problems + 1))
    _gha_issues="${_gha_issues}\n    Deploy workflows without environment protection rules"
  fi

  # Check for concurrency control
  if ! files_contain ".github/workflows/*.yml" "concurrency:" 2>/dev/null; then
    _gha_problems=$((_gha_problems + 1))
    _gha_issues="${_gha_issues}\n    No concurrency control (parallel runs may conflict)"
  fi

  if [[ $_gha_problems -eq 0 ]]; then
    pass "SAAS-002" "GitHub Actions security best practices followed"
  else
    warn "SAAS-002" "GitHub Actions security issues (${_gha_problems})${_gha_issues}" \
      "Use OIDC for cloud auth, environment rules for deploys, concurrency control"
  fi
else
  skip "SAAS-002" "GitHub Actions security" "No workflows found"
fi

# ── SAAS-003: Vercel Configuration Security ──────────────────────────────────

if has_file "vercel.json" || has_file ".vercel/project.json"; then
  _vercel_issues=0
  _vercel_details=""

  # Check for security headers in vercel.json
  if has_file "vercel.json"; then
    if ! file_contains "vercel.json" "X-Frame-Options\|Content-Security-Policy\|x-frame-options\|content-security-policy" 2>/dev/null; then
      _vercel_issues=$((_vercel_issues + 1))
      _vercel_details="${_vercel_details}\n    Missing security headers (CSP, X-Frame-Options)"
    fi

    # Check for exposed source maps
    if file_contains "vercel.json" "sourceMap.*true\|source-map" 2>/dev/null; then
      _vercel_issues=$((_vercel_issues + 1))
      _vercel_details="${_vercel_details}\n    Source maps may be exposed in production"
    fi
  fi

  # Check for .env in Vercel deployment
  if has_file ".vercel/.env" || has_file ".vercel/.env.production"; then
    _vercel_issues=$((_vercel_issues + 1))
    _vercel_details="${_vercel_details}\n    .env files found in .vercel/ directory"
  fi

  if [[ $_vercel_issues -eq 0 ]]; then
    pass "SAAS-003" "Vercel configuration follows security best practices"
  else
    warn "SAAS-003" "Vercel configuration issues (${_vercel_issues})${_vercel_details}" \
      "Add security headers, disable source maps in prod, use Vercel env vars"
  fi
elif files_contain "package.json" "\"vercel\"" 2>/dev/null || \
     files_contain "*.ts" "from.*@vercel" 2>/dev/null; then
  pass "SAAS-003" "Vercel detected — no configuration issues found"
else
  skip "SAAS-003" "Vercel security" "Vercel not detected"
fi

# ── SAAS-004: ArgoCD GitOps Security ─────────────────────────────────────────

if files_contain "*.yaml" "kind:[[:space:]]*Application" 2>/dev/null && \
   files_contain "*.yaml" "apiVersion.*argoproj" 2>/dev/null; then

  _argo_issues=0
  _argo_details=""

  # Check for auto-sync with self-heal (dangerous without review)
  if files_contain "*.yaml" "automated:" 2>/dev/null && \
     files_contain "*.yaml" "selfHeal:[[:space:]]*true" 2>/dev/null; then
    if ! files_contain "*.yaml" "prune:[[:space:]]*false" 2>/dev/null; then
      _argo_issues=$((_argo_issues + 1))
      _argo_details="${_argo_details}\n    Auto-sync with selfHeal+prune enabled (risky without review)"
    fi
  fi

  # Check for plaintext secrets in ArgoCD manifests
  if files_contain "*.yaml" "kind:[[:space:]]*Secret" 2>/dev/null && \
     ! files_contain "*.yaml" "sealed-secrets\|external-secrets\|vault" 2>/dev/null; then
    _argo_issues=$((_argo_issues + 1))
    _argo_details="${_argo_details}\n    Plaintext Secrets in manifests (use SealedSecrets/ExternalSecrets)"
  fi

  # Check for RBAC restrictions
  if files_contain "*.yaml" "apiVersion.*argoproj.*AppProject" 2>/dev/null; then
    if files_contain "*.yaml" "destinations:.*server:[[:space:]]*['\"]\\*['\"]" 2>/dev/null; then
      _argo_issues=$((_argo_issues + 1))
      _argo_details="${_argo_details}\n    AppProject allows deployment to all clusters (*)"
    fi
  fi

  if [[ $_argo_issues -eq 0 ]]; then
    pass "SAAS-004" "ArgoCD configuration follows security best practices"
  else
    warn "SAAS-004" "ArgoCD security issues (${_argo_issues})${_argo_details}" \
      "Use SealedSecrets, restrict AppProject destinations, review auto-sync policies"
  fi
else
  skip "SAAS-004" "ArgoCD security" "ArgoCD manifests not detected"
fi

# ── SAAS-005: Sentry Configuration Security ──────────────────────────────────

_sentry_detected=false
if files_contain "*.js" "Sentry.init\|@sentry/node\|@sentry/browser\|@sentry/react" 2>/dev/null || \
   files_contain "*.ts" "Sentry.init\|@sentry/node\|@sentry/browser\|@sentry/nextjs" 2>/dev/null || \
   files_contain "*.py" "sentry_sdk\|sentry-sdk" 2>/dev/null; then
  _sentry_detected=true
fi

if [[ "$_sentry_detected" == "true" ]]; then
  _sentry_issues=0
  _sentry_details=""

  # Check for DSN hardcoded in source
  if files_contain "*.js" "dsn:[[:space:]]*['\"]https://[a-f0-9]*@" 2>/dev/null || \
     files_contain "*.ts" "dsn:[[:space:]]*['\"]https://[a-f0-9]*@" 2>/dev/null || \
     files_contain "*.py" "dsn=['\"]https://[a-f0-9]*@" 2>/dev/null; then
    _sentry_issues=$((_sentry_issues + 1))
    _sentry_details="${_sentry_details}\n    Sentry DSN hardcoded in source (use env var SENTRY_DSN)"
  fi

  # Check for PII scrubbing
  if files_contain "*.js" "sendDefaultPii.*true\|send_default_pii.*true" 2>/dev/null || \
     files_contain "*.ts" "sendDefaultPii.*true" 2>/dev/null || \
     files_contain "*.py" "send_default_pii.*True" 2>/dev/null; then
    _sentry_issues=$((_sentry_issues + 1))
    _sentry_details="${_sentry_details}\n    PII sending enabled (sendDefaultPii=true) — review data policy"
  fi

  # Check for source map upload security
  if has_file ".sentryclirc"; then
    if file_contains ".sentryclirc" "token=" 2>/dev/null; then
      _sentry_issues=$((_sentry_issues + 1))
      _sentry_details="${_sentry_details}\n    Sentry auth token in .sentryclirc (use env SENTRY_AUTH_TOKEN)"
    fi
  fi

  if [[ $_sentry_issues -eq 0 ]]; then
    pass "SAAS-005" "Sentry configuration follows security best practices"
  else
    warn "SAAS-005" "Sentry security issues (${_sentry_issues})${_sentry_details}" \
      "Use env vars for DSN/tokens, disable PII sending, review data scrubbing"
  fi
else
  skip "SAAS-005" "Sentry security" "Sentry not detected"
fi

# ── SAAS-006: Datadog Integration Security ───────────────────────────────────

_dd_detected=false
if files_contain "*.yaml" "datadog\|dd-agent" 2>/dev/null || \
   files_contain "*.js" "dd-trace\|datadog" 2>/dev/null || \
   files_contain "*.py" "ddtrace\|datadog" 2>/dev/null || \
   files_contain "*.tf" "datadog" 2>/dev/null; then
  _dd_detected=true
fi

if [[ "$_dd_detected" == "true" ]]; then
  _dd_issues=0
  _dd_details=""

  # Check for hardcoded Datadog API keys
  if files_contain "*.yaml" "[Aa][Pp][Ii]_[Kk][Ee][Yy]:[[:space:]]*[a-f0-9]{32}" 2>/dev/null || \
     files_contain "*.yml" "[Aa][Pp][Ii]_[Kk][Ee][Yy]:[[:space:]]*[a-f0-9]{32}" 2>/dev/null; then
    _dd_issues=$((_dd_issues + 1))
    _dd_details="${_dd_details}\n    Datadog API key hardcoded in YAML config"
  fi

  # Check for DD agent security in K8s
  if files_contain "*.yaml" "dd-agent\|datadog-agent" 2>/dev/null; then
    if ! files_contain "*.yaml" "DD_DOGSTATSD_NON_LOCAL_TRAFFIC\|DD_APM_NON_LOCAL_TRAFFIC" 2>/dev/null; then
      :  # Agent traffic defaults are usually fine
    fi
  fi

  # Check for Datadog secrets in Terraform
  if files_contain "*.tf" "datadog_api_key\|datadog_app_key" 2>/dev/null && \
     ! files_contain "*.tf" "var\\.datadog\|data\\..*vault" 2>/dev/null; then
    _dd_issues=$((_dd_issues + 1))
    _dd_details="${_dd_details}\n    Datadog keys may be hardcoded in Terraform (use variables/vault)"
  fi

  if [[ $_dd_issues -eq 0 ]]; then
    pass "SAAS-006" "Datadog integration follows security best practices"
  else
    warn "SAAS-006" "Datadog security issues (${_dd_issues})${_dd_details}" \
      "Use K8s secrets or Vault for Datadog API keys, never hardcode in config"
  fi
else
  skip "SAAS-006" "Datadog security" "Datadog not detected"
fi

# ── SAAS-007: Cloudflare Security ────────────────────────────────────────────

_cf_detected=false
if files_contain "*.tf" "cloudflare" 2>/dev/null || \
   has_file "wrangler.toml" || has_file "wrangler.jsonc" || \
   files_contain "*.js" "cloudflare\|@cloudflare/workers" 2>/dev/null; then
  _cf_detected=true
fi

if [[ "$_cf_detected" == "true" ]]; then
  _cf_issues=0
  _cf_details=""

  # Check Cloudflare Workers security
  if has_file "wrangler.toml"; then
    # Check for hardcoded secrets in wrangler.toml
    if file_contains "wrangler.toml" "[Aa][Pp][Ii]_[Tt][Oo][Kk][Ee][Nn]\|[Aa][Pp][Ii]_[Kk][Ee][Yy]" 2>/dev/null; then
      _cf_issues=$((_cf_issues + 1))
      _cf_details="${_cf_details}\n    API credentials found in wrangler.toml"
    fi

    # Check for secrets binding (good practice)
    if ! file_contains "wrangler.toml" "\\[vars\\]\|secrets" 2>/dev/null && \
       files_contain "*.js" "env\\." 2>/dev/null; then
      _cf_issues=$((_cf_issues + 1))
      _cf_details="${_cf_details}\n    Worker uses env vars but no [vars] section in wrangler.toml"
    fi
  fi

  # Check Terraform Cloudflare config
  if files_contain "*.tf" "cloudflare_zone_settings_override" 2>/dev/null; then
    if files_contain "*.tf" "ssl.*off\|ssl.*flexible" 2>/dev/null; then
      _cf_issues=$((_cf_issues + 1))
      _cf_details="${_cf_details}\n    Cloudflare SSL set to off or flexible (use full/strict)"
    fi
  fi

  if [[ $_cf_issues -eq 0 ]]; then
    pass "SAAS-007" "Cloudflare configuration follows security best practices"
  else
    warn "SAAS-007" "Cloudflare security issues (${_cf_issues})${_cf_details}" \
      "Use wrangler secrets, enforce full/strict SSL, avoid hardcoded tokens"
  fi
else
  skip "SAAS-007" "Cloudflare security" "Cloudflare not detected"
fi

# ── SAAS-008: Okta / SSO Integration Security ───────────────────────────────

_okta_detected=false
if files_contain "*.js" "@okta\|okta-sdk\|okta-auth" 2>/dev/null || \
   files_contain "*.ts" "@okta\|okta-sdk\|okta-auth" 2>/dev/null || \
   files_contain "*.py" "okta\|pyokta" 2>/dev/null || \
   files_contain "*.yaml" "okta\\.com" 2>/dev/null; then
  _okta_detected=true
fi

if [[ "$_okta_detected" == "true" ]]; then
  _okta_issues=0
  _okta_details=""

  # Check for hardcoded Okta domain/tokens
  if files_contain "*.js" "orgUrl.*https://.*okta\\.com" 2>/dev/null || \
     files_contain "*.ts" "orgUrl.*https://.*okta\\.com" 2>/dev/null; then
    if files_contain "*.js" "token.*['\"][0-9]{2}[a-zA-Z]" 2>/dev/null || \
       files_contain "*.ts" "token.*['\"][0-9]{2}[a-zA-Z]" 2>/dev/null; then
      _okta_issues=$((_okta_issues + 1))
      _okta_details="${_okta_details}\n    Okta API token may be hardcoded in source"
    fi
  fi

  # Check for PKCE usage in OAuth flows
  if files_contain "*.js" "pkce.*false\|responseType.*code.*(?!.*pkce)" 2>/dev/null; then
    _okta_issues=$((_okta_issues + 1))
    _okta_details="${_okta_details}\n    OAuth flow without PKCE (vulnerable to code interception)"
  fi

  if [[ $_okta_issues -eq 0 ]]; then
    pass "SAAS-008" "Okta/SSO integration follows security best practices"
  else
    warn "SAAS-008" "Okta/SSO security issues (${_okta_issues})${_okta_details}" \
      "Use env vars for Okta config, enable PKCE for OAuth flows"
  fi
else
  skip "SAAS-008" "Okta/SSO security" "Okta not detected"
fi

# ── SAAS-009: SendGrid Email Security ────────────────────────────────────────

_sg_detected=false
if files_contain "*.js" "@sendgrid\|sendgrid" 2>/dev/null || \
   files_contain "*.ts" "@sendgrid\|sendgrid" 2>/dev/null || \
   files_contain "*.py" "sendgrid\|SendGridAPIClient" 2>/dev/null; then
  _sg_detected=true
fi

if [[ "$_sg_detected" == "true" ]]; then
  _sg_issues=0
  _sg_details=""

  # Check for hardcoded SendGrid API key
  if files_contain "*.js" "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}" 2>/dev/null || \
     files_contain "*.ts" "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}" 2>/dev/null || \
     files_contain "*.py" "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}" 2>/dev/null; then
    _sg_issues=$((_sg_issues + 1))
    _sg_details="${_sg_details}\n    SendGrid API key hardcoded in source code"
  fi

  # Check for full access API key (should use restricted keys)
  if files_contain "*.js" "SENDGRID_API_KEY\|sendgrid.*api.*key" 2>/dev/null; then
    :  # Using env var is good, but can't verify permissions from code
  fi

  if [[ $_sg_issues -eq 0 ]]; then
    pass "SAAS-009" "SendGrid integration follows security best practices"
  else
    fail "SAAS-009" "SendGrid API key exposed in source code" "critical" \
      "Hardcoded SendGrid key detected${_sg_details}" \
      "Use env SENDGRID_API_KEY and create restricted API keys with minimal permissions"
  fi
else
  skip "SAAS-009" "SendGrid security" "SendGrid not detected"
fi

# ── SAAS-010: Zscaler / Network Security ─────────────────────────────────────

_zs_detected=false
if files_contain "*.yaml" "zscaler" 2>/dev/null || \
   files_contain "*.tf" "zscaler\|zpa_\|zia_" 2>/dev/null || \
   files_contain "*.json" "zscaler" 2>/dev/null; then
  _zs_detected=true
fi

if [[ "$_zs_detected" == "true" ]]; then
  _zs_issues=0
  _zs_details=""

  # Check for Zscaler credentials in config
  if files_contain "*.tf" "zscaler.*api_key\|zia_api_key\|zpa_client_secret" 2>/dev/null && \
     ! files_contain "*.tf" "var\\.\|data\\..*vault" 2>/dev/null; then
    _zs_issues=$((_zs_issues + 1))
    _zs_details="${_zs_details}\n    Zscaler API credentials may be hardcoded in Terraform"
  fi

  if [[ $_zs_issues -eq 0 ]]; then
    pass "SAAS-010" "Zscaler configuration follows security best practices"
  else
    warn "SAAS-010" "Zscaler security issues (${_zs_issues})${_zs_details}" \
      "Use Terraform variables or Vault for Zscaler credentials"
  fi
else
  skip "SAAS-010" "Zscaler security" "Zscaler not detected"
fi

# ── SAAS-011: SentinelOne / Endpoint Security ────────────────────────────────

_s1_detected=false
if files_contain "*.yaml" "sentinelone\|sentinel.one\|s1_agent" 2>/dev/null || \
   files_contain "*.tf" "sentinelone" 2>/dev/null || \
   files_contain "*.py" "sentinelone\|SentinelOneAPI" 2>/dev/null; then
  _s1_detected=true
fi

if [[ "$_s1_detected" == "true" ]]; then
  _s1_issues=0
  _s1_details=""

  # Check for S1 API token exposure
  if files_contain "*.py" "api_token.*['\"][a-zA-Z0-9_-]{80,}" 2>/dev/null || \
     files_contain "*.yaml" "api_token.*[a-zA-Z0-9_-]{80,}" 2>/dev/null; then
    _s1_issues=$((_s1_issues + 1))
    _s1_details="${_s1_details}\n    SentinelOne API token may be hardcoded"
  fi

  if [[ $_s1_issues -eq 0 ]]; then
    pass "SAAS-011" "SentinelOne integration follows security best practices"
  else
    warn "SAAS-011" "SentinelOne security issues (${_s1_issues})${_s1_details}" \
      "Use env vars or vault for SentinelOne API tokens"
  fi
else
  skip "SAAS-011" "SentinelOne security" "SentinelOne not detected"
fi

# ── SAAS-012: Jamf Pro / MDM Security ────────────────────────────────────────

_jamf_detected=false
if files_contain "*.py" "jamf\|JamfPro" 2>/dev/null || \
   files_contain "*.sh" "jamf\|jamfPro" 2>/dev/null || \
   files_contain "*.yaml" "jamf" 2>/dev/null; then
  _jamf_detected=true
fi

if [[ "$_jamf_detected" == "true" ]]; then
  _jamf_issues=0
  _jamf_details=""

  # Check for Jamf credentials in scripts
  if files_contain "*.sh" "jamf.*password\|jamf.*api.*key" 2>/dev/null || \
     files_contain "*.py" "jamf.*password\|jamf.*api.*key" 2>/dev/null; then
    _jamf_issues=$((_jamf_issues + 1))
    _jamf_details="${_jamf_details}\n    Jamf Pro credentials may be exposed in scripts"
  fi

  if [[ $_jamf_issues -eq 0 ]]; then
    pass "SAAS-012" "Jamf Pro integration follows security best practices"
  else
    warn "SAAS-012" "Jamf Pro security issues (${_jamf_issues})${_jamf_details}" \
      "Use Jamf Pro API clients with limited roles, store creds in vault"
  fi
else
  skip "SAAS-012" "Jamf Pro security" "Jamf Pro not detected"
fi

# ── SAAS-013: Redash / Data Query Security ───────────────────────────────────

_redash_detected=false
if files_contain "*.yaml" "redash" 2>/dev/null || \
   files_contain "*.py" "redash\|redash_client" 2>/dev/null || \
   files_contain "docker-compose*" "redash" 2>/dev/null; then
  _redash_detected=true
fi

if [[ "$_redash_detected" == "true" ]]; then
  _redash_issues=0
  _redash_details=""

  # Check for Redash cookie secret
  if files_contain "docker-compose*" "REDASH_COOKIE_SECRET" 2>/dev/null; then
    if files_contain "docker-compose*" "REDASH_COOKIE_SECRET=.*change\|REDASH_COOKIE_SECRET=.*default" 2>/dev/null; then
      _redash_issues=$((_redash_issues + 1))
      _redash_details="${_redash_details}\n    Redash cookie secret is using default/weak value"
    fi
  fi

  # Check for Redash database credentials
  if files_contain "docker-compose*" "REDASH_DATABASE_URL.*password" 2>/dev/null && \
     ! files_contain "docker-compose*" "\\$\\{.*PASSWORD\|\\$PASSWORD" 2>/dev/null; then
    _redash_issues=$((_redash_issues + 1))
    _redash_details="${_redash_details}\n    Redash database password may be hardcoded in docker-compose"
  fi

  if [[ $_redash_issues -eq 0 ]]; then
    pass "SAAS-013" "Redash configuration follows security best practices"
  else
    warn "SAAS-013" "Redash security issues (${_redash_issues})${_redash_details}" \
      "Use strong cookie secrets, externalize database credentials"
  fi
else
  skip "SAAS-013" "Redash security" "Redash not detected"
fi

# ── SAAS-014: QueryPie / Database Access Security ────────────────────────────

_qp_detected=false
if files_contain "*.yaml" "querypie\|query-pie" 2>/dev/null || \
   files_contain "*.json" "querypie" 2>/dev/null || \
   files_contain "*.tf" "querypie" 2>/dev/null; then
  _qp_detected=true
fi

if [[ "$_qp_detected" == "true" ]]; then
  _qp_issues=0
  _qp_details=""

  # Check for QueryPie API token in config
  if files_contain "*.yaml" "querypie.*api.*key\|querypie.*token" 2>/dev/null && \
     ! files_contain "*.yaml" "\\$\\{.*TOKEN\|\\$\\{.*KEY" 2>/dev/null; then
    _qp_issues=$((_qp_issues + 1))
    _qp_details="${_qp_details}\n    QueryPie credentials may be hardcoded"
  fi

  if [[ $_qp_issues -eq 0 ]]; then
    pass "SAAS-014" "QueryPie configuration follows security best practices"
  else
    warn "SAAS-014" "QueryPie security issues (${_qp_issues})${_qp_details}" \
      "Use environment variables or vault for QueryPie API credentials"
  fi
else
  skip "SAAS-014" "QueryPie security" "QueryPie not detected"
fi

# ── SAAS-015: Google Workspace / Drive Security ──────────────────────────────

_gw_detected=false
if files_contain "*.json" "googleapis.com\|client_email.*gserviceaccount" 2>/dev/null || \
   files_contain "*.py" "google.oauth2\|google-auth\|googleapiclient" 2>/dev/null || \
   files_contain "*.js" "googleapis\|google-auth-library" 2>/dev/null || \
   files_contain "*.ts" "googleapis\|google-auth-library" 2>/dev/null; then
  _gw_detected=true
fi

if [[ "$_gw_detected" == "true" ]]; then
  _gw_issues=0
  _gw_details=""

  # Check for service account key files committed
  _sa_keys=$(find "$SCAN_DIR" \
    -name "*service*account*.json" -o -name "*credentials*.json" -o -name "*client_secret*.json" \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/scanner/*" \
    2>/dev/null | head -3 || true)
  if [[ -n "$_sa_keys" ]]; then
    _gw_issues=$((_gw_issues + 1))
    _sa_files=$(echo "$_sa_keys" | tr '\n' ', ' | sed 's/,$//')
    _gw_details="${_gw_details}\n    Service account key file(s): ${_sa_files}"
  fi

  # Check for overly broad OAuth scopes
  if files_contain "*.py" "https://www.googleapis.com/auth/drive['\"]" 2>/dev/null || \
     files_contain "*.js" "https://www.googleapis.com/auth/drive['\"]" 2>/dev/null; then
    if ! files_contain "*.py" "drive\\.readonly\|drive\\.file" 2>/dev/null && \
       ! files_contain "*.js" "drive\\.readonly\|drive\\.file" 2>/dev/null; then
      _gw_issues=$((_gw_issues + 1))
      _gw_details="${_gw_details}\n    Using full Google Drive scope (use drive.readonly or drive.file)"
    fi
  fi

  if [[ $_gw_issues -eq 0 ]]; then
    pass "SAAS-015" "Google Workspace integration follows security best practices"
  else
    warn "SAAS-015" "Google Workspace security issues (${_gw_issues})${_gw_details}" \
      "Use Workload Identity Federation instead of key files, use minimal OAuth scopes"
  fi
else
  skip "SAAS-015" "Google Workspace security" "Google Workspace not detected"
fi

# ── SAAS-016: Cross-Solution Secret Rotation Policy ──────────────────────────

_rotation_issues=0
_rotation_details=""

# Check for any hardcoded token/key expiry or rotation config
if has_file ".github/workflows/rotate-secrets.yml" || \
   has_file ".github/workflows/secret-rotation.yml" || \
   files_contain "*.yaml" "secret.*rotation\|key.*rotation\|token.*expir" 2>/dev/null; then
  pass "SAAS-016" "Secret rotation policy or automation detected"
else
  # Only warn if there are actual integrations that need rotation
  _has_integrations=false
  if files_contain "*.yml" "DATADOG\|SENTRY\|SENDGRID\|OKTA\|CLOUDFLARE\|VERCEL\|ARGOCD" 2>/dev/null || \
     files_contain "*.yaml" "DATADOG\|SENTRY\|SENDGRID\|OKTA\|CLOUDFLARE\|VERCEL\|ARGOCD" 2>/dev/null; then
    _has_integrations=true
  fi

  if [[ "$_has_integrations" == "true" ]]; then
    warn "SAAS-016" "No secret rotation policy detected for SaaS integrations" \
      "Implement automated secret rotation (GitHub Actions scheduled workflow, Vault dynamic secrets)"
  else
    skip "SAAS-016" "Secret rotation" "No SaaS integrations requiring rotation detected"
  fi
fi

# ── SAAS-017: Harbor (Container Registry) Configuration Security ─────────────
#
# Heuristic, repo-local checks. For live Harbor API checks, see saas/api-checks.sh.
# References:
# - Harbor docs (Security): https://goharbor.io/docs/
# - OWASP Cheat Sheet Series (Secrets Management): https://cheatsheetseries.owasp.org/

_harbor_detected=false
if has_file "harbor.yml" || has_file "harbor.yaml" || has_dir ".harbor" || \
   files_contain "*.yaml" "goharbor|harbor\\." 2>/dev/null || \
   files_contain "*.yml" "goharbor|harbor\\." 2>/dev/null; then
  _harbor_detected=true
fi

if [[ "$_harbor_detected" == "true" ]]; then
  _harbor_issues=0
  _harbor_details=""

  # Check for embedded passwords/secrets in Harbor config files
  if files_contain "harbor*.yml" "password:|secret:|harbor_admin_password" 2>/dev/null || \
     files_contain "harbor*.yaml" "password:|secret:|harbor_admin_password" 2>/dev/null; then
    _harbor_issues=$((_harbor_issues + 1))
    _harbor_details="${_harbor_details}\n    Potential secrets found in Harbor config (use env vars / secret manager)"
  fi

  # If Harbor is referenced, ensure TLS is expected (https URLs)
  if files_contain "*.yaml" "http://.*harbor" 2>/dev/null || files_contain "*.yml" "http://.*harbor" 2>/dev/null; then
    _harbor_issues=$((_harbor_issues + 1))
    _harbor_details="${_harbor_details}\n    Harbor referenced over HTTP (use HTTPS/TLS termination)"
  fi

  if [[ $_harbor_issues -eq 0 ]]; then
    pass "SAAS-017" "Harbor detected — no obvious insecure config patterns found"
  else
    warn "SAAS-017" "Harbor security findings (${_harbor_issues})${_harbor_details}" \
      "Avoid committing secrets; enforce HTTPS; prefer secret managers for Harbor credentials"
  fi
else
  skip "SAAS-017" "Harbor security" "Harbor not detected"
fi

# ── SAAS-018: Jenkins (CI) Configuration & Pipeline Security ─────────────────
#
# Repo-local checks only. For live Jenkins endpoint checks, see saas/api-checks.sh.
# References:
# - OWASP CI/CD Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html
# - Jenkins docs (Securing Jenkins): https://www.jenkins.io/doc/book/security/

_jenkins_detected=false
if has_file "Jenkinsfile" || has_dir ".jenkins" || has_file "jenkins.yml" || has_file "jenkins.yaml"; then
  _jenkins_detected=true
fi

if [[ "$_jenkins_detected" == "true" ]]; then
  _j_issues=0
  _j_details=""

  # Check for hardcoded credentials in Jenkinsfile
  if files_contain "Jenkinsfile" "(password|token|secret)[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" 2>/dev/null || \
     files_contain "Jenkinsfile" "withCredentials\\(\\[[^\\]]*(string|usernamePassword|sshUserPrivateKey)" 2>/dev/null; then
    # withCredentials is good; hardcoded is bad. We only fail on obvious literals.
    if files_contain "Jenkinsfile" "(password|token|secret)[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" 2>/dev/null; then
      _j_issues=$((_j_issues + 1))
      _j_details="${_j_details}\n    Possible hardcoded secret in Jenkinsfile (use credentials binding)"
    fi
  fi

  # Check for permissive docker builds without pinning images (supply chain risk)
  if files_contain "Jenkinsfile" "docker\\.image\\(['\"][^'\"]+:latest['\"]\\)" 2>/dev/null; then
    _j_details="${_j_details}\n    Docker images use :latest tag (pin versions or digests)"
  fi

  # Check for downloading scripts and executing without integrity verification
  if files_contain "Jenkinsfile" "(curl|wget).*(\\||;)[[:space:]]*(sh|bash)" 2>/dev/null; then
    _j_details="${_j_details}\n    Downloads piped to shell (consider checksum/signature verification)"
  fi

  if [[ $_j_issues -eq 0 && -z "$_j_details" ]]; then
    pass "SAAS-018" "Jenkins detected — pipeline follows basic security practices"
  elif [[ $_j_issues -eq 0 ]]; then
    warn "SAAS-018" "Jenkins pipeline recommendations${_j_details}" \
      "Pin images, avoid curl|bash, and keep secrets in Jenkins Credentials"
  else
    fail "SAAS-018" "Jenkins pipeline security issues found" "high" \
      "${_j_issues} issue(s)${_j_details}" \
      "Remove hardcoded secrets; use Jenkins Credentials + withCredentials()"
  fi
else
  skip "SAAS-018" "Jenkins security" "Jenkins not detected"
fi

# ── SAAS-019: IDE / Workspace Configuration Security ─────────────────────────
#
# Focus: common insecure workspace settings that weaken trust/verification.
# References:
# - OWASP Cheat Sheet Series (Secure Coding Practices): https://cheatsheetseries.owasp.org/

_ide_detected=false
if has_dir ".vscode" || has_dir ".idea"; then
  _ide_detected=true
fi

if [[ "$_ide_detected" == "true" ]]; then
  _ide_issues=0
  _ide_details=""

  # VS Code: workspace trust disabled is risky in shared repos
  if has_file ".vscode/settings.json"; then
    if file_contains ".vscode/settings.json" "\"security\\.workspace\\.trust\\.enabled\"[[:space:]]*:[[:space:]]*false" 2>/dev/null; then
      _ide_issues=$((_ide_issues + 1))
      _ide_details="${_ide_details}\n    VS Code workspace trust disabled (security.workspace.trust.enabled=false)"
    fi
    if file_contains ".vscode/settings.json" "\"http\\.proxyStrictSSL\"[[:space:]]*:[[:space:]]*false" 2>/dev/null; then
      _ide_issues=$((_ide_issues + 1))
      _ide_details="${_ide_details}\n    VS Code proxy strict SSL disabled (http.proxyStrictSSL=false)"
    fi
    if file_contains ".vscode/settings.json" "(password|token|secret)[^\n]*:" 2>/dev/null; then
      _ide_issues=$((_ide_issues + 1))
      _ide_details="${_ide_details}\n    Possible credentials stored in .vscode/settings.json"
    fi
  fi

  if [[ $_ide_issues -eq 0 ]]; then
    pass "SAAS-019" "IDE workspace files detected — no obvious insecure settings found"
  else
    warn "SAAS-019" "IDE/workspace security findings (${_ide_issues})${_ide_details}" \
      "Avoid storing credentials in workspace files; keep TLS verification enabled; keep workspace trust enabled"
  fi
else
  skip "SAAS-019" "IDE/workspace security" "No IDE workspace files detected"
fi
