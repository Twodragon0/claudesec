#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Secrets & API Key Scanner
# Detects leaked API keys, tokens, and credentials in source code and config
# ============================================================================

# ── API Key Patterns ────────────────────────────────────────────────────────
# Each entry: "NAME|PATTERN|SEVERITY"

SECRET_PATTERNS=(
  # Cloud Providers
  "AWS Access Key|AKIA[0-9A-Z]{16}|critical"
  "AWS Secret Key|[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[A-Za-z0-9/+=]{40}|critical"
  "GCP Service Account|\"type\":[[:space:]]*\"service_account\"|high"
  "GCP API Key|AIza[0-9A-Za-z_-]{35}|critical"
  "Azure Storage Key|DefaultEndpointsProtocol=https;AccountName=|high"

  # AI / LLM
  "OpenAI API Key|sk-[a-zA-Z0-9]{20,}|critical"
  "Anthropic API Key|sk-ant-[a-zA-Z0-9_-]{20,}|critical"
  "HuggingFace Token|hf_[a-zA-Z0-9]{34}|high"

  # Monitoring & Observability
  "Datadog API Key|[Dd][Dd]_[Aa][Pp][Ii]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]{32}|high"
  "Datadog API Key Alt|[Dd][Aa][Tt][Aa][Dd][Oo][Gg]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]|high"
  "Datadog App Key|[Dd][Dd]_[Aa][Pp][Pp]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]{40}|high"
  "Datadog App Key Alt|[Dd][Aa][Tt][Aa][Dd][Oo][Gg]_[Aa][Pp][Pp]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]|high"
  "New Relic Key|NRAK-[a-zA-Z0-9]{27}|high"
  "Sentry DSN|https://[a-f0-9]{32}@[a-z0-9]+\\.ingest\\.sentry\\.io|medium"

  # CI/CD & DevOps
  "GitHub Token|gh[ps]_[a-zA-Z0-9]{36}|critical"
  "GitHub OAuth|gho_[a-zA-Z0-9]{36}|critical"
  "GitHub App Token|(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|critical"
  "GitLab Token|glpat-[a-zA-Z0-9_-]{20,}|critical"
  "CircleCI Token|[Cc][Ii][Rr][Cc][Ll][Ee].*[Tt][Oo][Kk][Ee][Nn].*[a-f0-9]{40}|high"

  # Communication
  "Slack Token|xox[baprs]-[0-9a-zA-Z-]{10,}|critical"
  "Slack Webhook|https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}|high"
  "Discord Webhook|https://discord(app)?\\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+|high"
  "Telegram Bot Token|[0-9]+:AA[a-zA-Z0-9_-]{33}|high"
  "Twilio Account SID|AC[a-f0-9]{32}|high"
  "SendGrid API Key|SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}|critical"
  "Mailgun API Key|key-[a-zA-Z0-9]{32}|high"

  # Payment & Finance
  "Stripe Secret Key|sk_live_[a-zA-Z0-9]{24,}|critical"
  "Stripe Publishable Key|pk_live_[a-zA-Z0-9]{24,}|medium"
  "Square Access Token|sq0atp-[a-zA-Z0-9_-]{22}|critical"

  # Database
  "MongoDB URI|mongodb(\\+srv)?://[^[:space:]\"']+@[^[:space:]\"']+|high"
  "PostgreSQL URI|postgres(ql)?://[^[:space:]\"']+:[^[:space:]\"']+@[^[:space:]\"']+|high"
  "MySQL URI|mysql://[^[:space:]\"']+:[^[:space:]\"']+@[^[:space:]\"']+|high"
  "Redis URI|redis://[^[:space:]\"':]+:[^[:space:]\"'@]+@[^[:space:]\"']+|high"

  # Auth & Identity
  "Firebase API Key|[Ff][Ii][Rr][Ee][Bb][Aa][Ss][Ee].*[Aa][Pp][Ii].*AIza[0-9A-Za-z_-]{35}|critical"

  # Infrastructure
  "Private Key Header|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|critical"
  "Hashicorp Vault Token|(VAULT_TOKEN|vault_token)[[:space:]]*[=:][[:space:]]*hvs\\.[a-zA-Z0-9_-]+|critical"
  "Terraform Cloud Token|credentials.*app\\.terraform\\.io|high"

  # SaaS & APIs
  "Google Maps API Key|AIza[0-9A-Za-z_-]{35}|high"
  "Mapbox Token|pk\\.[a-zA-Z0-9]{60,}|medium"
  "npm Token|npm_[a-zA-Z0-9]{36}|critical"
  "PyPI Token|pypi-[a-zA-Z0-9_-]{100,}|critical"
  "Shopify Token|shpat_[a-f0-9]{32}|high"
  "FRED API Key|[Ff][Rr][Ee][Dd]_[Aa][Pp][Ii]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]{32}|medium"

  # Security & Identity (Okta, Zscaler, SentinelOne, Jamf)
  "Okta API Token|[Oo][Kk][Tt][Aa].*[Aa][Pp][Ii].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*['\"]?00[a-zA-Z0-9_-]{38,}['\"]?|critical"
  "Okta SSWS Token|SSWS [a-zA-Z0-9_-]{30,}|critical"
  "Zscaler API Key|[Zz][Ss][Cc][Aa][Ll][Ee][Rr].*[Aa][Pp][Ii].*[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9_-]{20,}|high"
  "SentinelOne API Token|[Ss][Ee][Nn][Tt][Ii][Nn][Ee][Ll].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9_-]{80,}|critical"
  "Jamf Pro Token|[Jj][Aa][Mm][Ff].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9_-]{20,}|high"

  # CDN & Edge (Cloudflare, Vercel)
  "Cloudflare API Token|[Cc][Ff]_[Aa][Pp][Ii]_[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9_-]{40}|critical"
  "Cloudflare Global Key|[Cc][Ll][Oo][Uu][Dd][Ff][Ll][Aa][Rr][Ee].*[Aa][Pp][Ii].*[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-f0-9]{37}|critical"
  "Vercel Token|[Vv][Ee][Rr][Cc][Ee][Ll].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9]{24,}|high"

  # CI/CD & GitOps (ArgoCD)
  "ArgoCD Token|[Aa][Rr][Gg][Oo][Cc][Dd].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9._-]{20,}|high"
  "ArgoCD Admin Password|[Aa][Rr][Gg][Oo][Cc][Dd].*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][[:space:]]*[=:][[:space:]]*['\"][^'\"]{8,}['\"]|high"

  # Analytics & Data (Redash, QueryPie)
  "Redash API Key|[Rr][Ee][Dd][Aa][Ss][Hh].*[Aa][Pp][Ii].*[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9]{20,}|high"
  "QueryPie Token|[Qq][Uu][Ee][Rr][Yy][Pp][Ii][Ee].*[Tt][Oo][Kk][Ee][Nn][[:space:]]*[=:][[:space:]]*[a-zA-Z0-9_-]{20,}|high"

  # Google Workspace
  "Google OAuth Client Secret|client_secret.*[a-zA-Z0-9_-]{24}|high"
  "Google Service Account Key|\"private_key\":[[:space:]]*\"-----BEGIN|critical"

  # Generic patterns (used only when explicitly enabled)
  "Generic API Key|[Aa][Pp][Ii]_[Kk][Ee][Yy][[:space:]]*[=:][[:space:]]*['\"]?[a-zA-Z0-9_-]{20,}['\"]?|medium"
  "Generic Secret|([Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])[[:space:]]*[=:][[:space:]]*['\"][^'\"]{8,}['\"]|medium"
  "Generic Token|([Aa][Cc][Cc][Ee][Ss][Ss]_[Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh]_[Tt][Oo][Kk][Ee][Nn])[[:space:]]*[=:][[:space:]]*['\"]?[a-zA-Z0-9._-]{20,}['\"]?|medium"
)

# ── SECRETS-001: Source code API key scan ────────────────────────────────────

_found_secrets=0
_secret_details=""

# Scan source code files for secret patterns
for entry in "${SECRET_PATTERNS[@]}"; do
  IFS='|' read -r secret_name secret_pattern secret_severity <<< "$entry"

  # Skip base64/generic patterns for source scan (too noisy)
  [[ "$secret_name" == "Base64"* ]] && continue
  [[ "$secret_name" == "Generic"* ]] && continue

  # Search across common file types (exclude node_modules, .git, vendor, dist, scanner output)
  hit=$(find "$SCAN_DIR" \
    \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" \
       -o -name "*.go" -o -name "*.java" -o -name "*.rb" -o -name "*.rs" \
       -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o -name "*.toml" \
       -o -name "*.cfg" -o -name "*.ini" -o -name "*.conf" -o -name "*.properties" \
       -o -name "*.tf" -o -name "*.tfvars" -o -name "*.sh" -o -name "*.bash" \
       -o -name "Dockerfile*" -o -name "docker-compose*" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/vendor/*" \
    -not -path "*/dist/*" -not -path "*/.env.example" -not -path "*/scanner/*" \
    -not -path "*/.claudesec-prowler/*" -not -path "*/.claudesec-history/*" \
    -exec grep -lE "$secret_pattern" {} \; 2>/dev/null | head -3 || true)

  if [[ -n "$hit" ]]; then
    _found_secrets=$((_found_secrets + 1))
    _hit_files=$(echo "$hit" | tr '\n' ', ' | sed 's/,$//')
    _secret_details="${_secret_details}\n    ${secret_name}: ${_hit_files}"
  fi
done

if [[ $_found_secrets -gt 0 ]]; then
  fail "SECRETS-001" "$_found_secrets secret pattern(s) detected in source code" "critical" \
    "Hardcoded secrets found:${_secret_details}" \
    "Move secrets to env vars or a secrets manager (Vault, AWS Secrets Manager, 1Password)"
else
  pass "SECRETS-001" "No hardcoded secrets detected in source code"
fi

# ── SECRETS-002: .env file API key audit ─────────────────────────────────────

# Collect .env files to scan: project .env files + external --env-file paths
_env_files=""

# Project-level .env files (not tracked in git)
_project_envs=$(find "$SCAN_DIR" -maxdepth 3 -name ".env" -o -name ".env.local" -o -name ".env.production" \
  -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
[[ -n "$_project_envs" ]] && _env_files="$_project_envs"

# External .env files from --env-file option
for ef in "${ENV_SCAN_FILES[@]+"${ENV_SCAN_FILES[@]}"}"; do
  [[ -f "$ef" ]] && _env_files="${_env_files}${_env_files:+$'\n'}$ef"
done

if [[ -n "$_env_files" ]]; then
  _env_secrets=0
  _env_secret_list=""

  while IFS= read -r envfile; do
    [[ -z "$envfile" || ! -f "$envfile" ]] && continue

    # Read each line looking for key=value patterns with actual secret values
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip comments and empty lines
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$line" ]] && continue

      # Extract key name
      _key=$(echo "$line" | cut -d'=' -f1 | tr -d ' ')
      _val=$(echo "$line" | cut -d'=' -f2-)

      # Skip empty values, placeholders, examples
      [[ -z "$_val" || "$_val" == "\"\"" || "$_val" == "''" ]] && continue
      [[ "$_val" =~ (YOUR_|CHANGE_ME|xxx|placeholder|example|TODO) ]] && continue

      # Match known secret key names
      _key_upper=$(echo "$_key" | tr '[:lower:]' '[:upper:]')
      case "$_key_upper" in
        *API_KEY*|*APIKEY*|*SECRET*|*TOKEN*|*PASSWORD*|*PASSWD*|*CREDENTIAL*|\
        *PRIVATE_KEY*|*ACCESS_KEY*|*AUTH_KEY*|*CLIENT_SECRET*|\
        *DD_API*|*DD_APP*|*DATADOG*|*SENTRY_DSN*|*NEW_RELIC*|\
        *OPENAI*|*ANTHROPIC*|*STRIPE*|*TWILIO*|*SENDGRID*|\
        *SLACK*|*GITHUB*|*GITLAB*|*DATABASE_URL*|*REDIS_URL*|\
        *MONGO*|*POSTGRES*|*MYSQL*|*FIREBASE*|*SUPABASE*|\
        *FRED_*|*GRAFANA*|*PAGERDUTY*|*MAPBOX*|*ALGOLIA*|\
        *NPM_TOKEN*|*PYPI_TOKEN*|*VAULT*|*AWS_SECRET*|\
        *OKTA*|*ZSCALER*|*SENTINEL*|*JAMF*|*CLOUDFLARE*|*CF_API*|\
        *VERCEL*|*ARGOCD*|*ARGO_*|*REDASH*|*QUERYPIE*|\
        *GOOGLE_*|*SENTRY*|*SENDGRID*)
          _env_secrets=$((_env_secrets + 1))
          _env_secret_list="${_env_secret_list}\n    $(basename "$envfile"): $_key"
          ;;
      esac
    done < "$envfile"
  done <<< "$_env_files"

  if [[ $_env_secrets -gt 0 ]]; then
    _env_file_count=$(echo "$_env_files" | wc -l | tr -d ' ')
    warn "SECRETS-002" "$_env_secrets secret(s) found in $_env_file_count .env file(s)${_env_secret_list}" \
      "Ensure .env files are in .gitignore. Use a secrets manager for production."
  else
    pass "SECRETS-002" ".env files scanned — no recognized secret patterns"
  fi
else
  skip "SECRETS-002" ".env file audit" "No .env files found"
fi

# ── SECRETS-003: Git history secret leak check ──────────────────────────────

if is_git_repo; then
  # Quick check: search recent commits for known patterns
  _git_secrets=0

  # Check for common secret patterns in recent git diff
  _recent_leak=$(git -C "$SCAN_DIR" log --oneline --diff-filter=A -p -20 -- '*.env' '*.pem' '*.key' '*.p12' '*.pfx' 2>/dev/null | head -1 || true)
  if [[ -n "$_recent_leak" ]]; then
    _git_secrets=$((_git_secrets + 1))
  fi

  # Check for AWS keys in git history
  _aws_in_history=$(git -C "$SCAN_DIR" log -p --all -20 2>/dev/null | grep -cE 'AKIA[0-9A-Z]{16}' 2>/dev/null || true)
  _aws_in_history=$(echo "$_aws_in_history" | tail -1 | tr -dc '0-9')
  : "${_aws_in_history:=0}"
  if [[ "$_aws_in_history" -gt 0 ]]; then
    _git_secrets=$((_git_secrets + _aws_in_history))
  fi

  if [[ $_git_secrets -gt 0 ]]; then
    fail "SECRETS-003" "Potential secrets found in git history" "high" \
      "Secret files or patterns detected in recent commits" \
      "Use git-filter-repo or BFG to remove secrets from history. Rotate exposed credentials."
  else
    pass "SECRETS-003" "No obvious secrets in recent git history"
  fi
else
  skip "SECRETS-003" "Git history scan" "Not a git repository"
fi

# ── SECRETS-004: Cloud credential file exposure ─────────────────────────────

_cred_exposed=0
_cred_details=""

# Check if cloud credential paths are referenced in code
_cred_patterns=(
  ".aws/credentials|AWS credentials file path"
  ".gcloud/|GCP credentials directory"
  "service-account.*\.json|GCP service account key file"
  ".azure/|Azure credentials directory"
  ".kube/config|Kubernetes config file"
  ".docker/config\.json|Docker config with auth"
  ".npmrc|npm credentials"
  ".pypirc|PyPI credentials"
  "id_rsa|SSH private key"
  "id_ed25519|SSH private key"
)

for cp in "${_cred_patterns[@]}"; do
  IFS='|' read -r cred_pattern cred_desc <<< "$cp"

  cred_hit=$(find "$SCAN_DIR" \
    \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.yaml" -o -name "*.yml" \
       -o -name "*.sh" -o -name "*.tf" -o -name "Dockerfile*" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/scanner/*" \
    -exec grep -lE "$cred_pattern" {} \; 2>/dev/null | head -1 || true)

  if [[ -n "$cred_hit" ]]; then
    _cred_exposed=$((_cred_exposed + 1))
    _cred_details="${_cred_details}\n    $cred_desc: $cred_hit"
  fi
done

if [[ $_cred_exposed -gt 0 ]]; then
  warn "SECRETS-004" "$_cred_exposed credential file reference(s) in code${_cred_details}" \
    "Avoid hardcoding credential file paths. Use environment variables or IAM roles."
else
  pass "SECRETS-004" "No credential file path references in code"
fi
