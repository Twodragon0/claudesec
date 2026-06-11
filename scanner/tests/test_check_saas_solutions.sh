#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
# Unit tests for scanner/checks/saas/solutions.sh
#
# solutions.sh (SAAS-001..019) uses only file-system heuristics (has_file,
# has_dir, files_contain, file_contains, find). All checks are hermetic: no
# network calls, no live CLIs. Most checks are fully testable with fixtures.
#
# GREP PORTABILITY NOTE (resolved):
# solutions.sh previously used files_contain with "\|" (backslash-pipe) in many
# detection conditions. Under grep -E (ERE) "\|" is a LITERAL pipe, not alternation,
# so those detectors never matched and always SKIPped. That bug is now fixed — every
# "\|" was converted to proper (a|b) ERE alternation — and the detection paths for
# SAAS-005 (Sentry), SAAS-009 (SendGrid), SAAS-011 (SentinelOne), SAAS-014 (QueryPie)
# and SAAS-015 (Google Workspace) are exercised by the "alternation regression" tests
# near the end of this file (integration-present fixture -> detected, not SKIP).
#
# CHECKS COVERED WITH FIXTURES:
#   SAAS-001  GitHub security config (needs git repo)
#   SAAS-002  GitHub Actions security (has_dir + files_contain)
#   SAAS-003  Vercel config (SKIP + WARN paths only)
#   SAAS-004  ArgoCD (files_contain "*.yaml" without \|)
#   SAAS-006  Datadog via *.tf "datadog" (no \|)
#   SAAS-007  Cloudflare via has_file "wrangler.toml" (no \|)
#   SAAS-008  Okta via *.yaml "okta\\.com" (no \|)
#   SAAS-010  Zscaler via *.yaml "zscaler" (no \|)
#   SAAS-012  Jamf Pro via *.yaml "jamf" (no \|)
#   SAAS-013  Redash via docker-compose* "redash" (no \|)
#   SAAS-016  Secret rotation (has_file based)
#   SAAS-017  Harbor (has_file "harbor.yml")
#   SAAS-018  Jenkins (has_file "Jenkinsfile")
#   SAAS-019  IDE/VS Code (has_dir ".vscode")
#
# Run: CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_check_saas_solutions.sh
set -uo pipefail

export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""
FORMAT="text"
QUIET=1
SEVERITY="low"

RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { true; }

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"
    ((TEST_FAILED++))
  fi
}

assert_no_result() {
  local desc="$1" unexpected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${unexpected_type}:${check_id}"* ]]; then
      found=true
      break
    fi
  done
  if ! $found; then
    echo "  PASS: $desc"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (unexpected $unexpected_type:$check_id found)"
    ((TEST_FAILED++))
  fi
}

run_check() {
  RESULTS=()
  set +u
  source "$CHECKS_DIR/saas/solutions.sh" 2>/dev/null || true
  set -u
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── SAAS-001: GitHub security config ─────────────────────────────────────────

echo "=== SAAS-001: not a git repo -> SKIP ==="

mkdir -p "$tmpdir/not_git"
SCAN_DIR="$tmpdir/not_git"
# Override is_git_repo to return false so the check SKIPs
is_git_repo() { return 1; }
run_check
unset -f is_git_repo 2>/dev/null || true
source "$LIB_DIR/checks.sh"
assert_has_result "Not a git repo -> SKIP SAAS-001" "SKIP" "SAAS-001"

echo "=== SAAS-001: all GitHub security files present -> PASS ==="

mkdir -p "$tmpdir/gh_full/.github/workflows"
touch "$tmpdir/gh_full/.github/dependabot.yml"
touch "$tmpdir/gh_full/.github/CODEOWNERS"
touch "$tmpdir/gh_full/SECURITY.md"
printf 'on: push\njobs:\n  codeql:\n    runs-on: ubuntu-latest\n    steps: []\n' \
  > "$tmpdir/gh_full/.github/workflows/codeql.yml"
# Initialize a git repo so is_git_repo returns true
git -C "$tmpdir/gh_full" init -q 2>/dev/null || true
git -C "$tmpdir/gh_full" config user.email "test@example.com" 2>/dev/null || true
git -C "$tmpdir/gh_full" config user.name "Test" 2>/dev/null || true
SCAN_DIR="$tmpdir/gh_full" run_check
assert_has_result "All GitHub security files -> PASS SAAS-001" "PASS" "SAAS-001"

echo "=== SAAS-001: no GitHub security files in git repo -> FAIL ==="

mkdir -p "$tmpdir/gh_empty"
git -C "$tmpdir/gh_empty" init -q 2>/dev/null || true
git -C "$tmpdir/gh_empty" config user.email "test@example.com" 2>/dev/null || true
git -C "$tmpdir/gh_empty" config user.name "Test" 2>/dev/null || true
SCAN_DIR="$tmpdir/gh_empty" run_check
assert_has_result "No GitHub security files -> FAIL SAAS-001" "FAIL" "SAAS-001"

# ── SAAS-002: GitHub Actions security ────────────────────────────────────────

echo "=== SAAS-002: no workflows dir -> SKIP ==="

mkdir -p "$tmpdir/no_workflows"
SCAN_DIR="$tmpdir/no_workflows" run_check
assert_has_result "No .github/workflows -> SKIP SAAS-002" "SKIP" "SAAS-002"

echo "=== SAAS-002: workflow with concurrency -> PASS ==="

mkdir -p "$tmpdir/wf_good/.github/workflows"
cat > "$tmpdir/wf_good/.github/workflows/ci.yml" <<'YML'
on: push
concurrency:
  group: ${{ github.ref }}
  cancel-in-progress: true
jobs:
  build:
    runs-on: ubuntu-latest
    environment: production
    steps: []
YML
SCAN_DIR="$tmpdir/wf_good" run_check
assert_has_result "Workflow with concurrency + env -> PASS SAAS-002" "PASS" "SAAS-002"

echo "=== SAAS-002: workflow missing concurrency -> WARN ==="

mkdir -p "$tmpdir/wf_noconcur/.github/workflows"
cat > "$tmpdir/wf_noconcur/.github/workflows/ci.yml" <<'YML'
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps: []
YML
SCAN_DIR="$tmpdir/wf_noconcur" run_check
assert_has_result "Workflow missing concurrency -> WARN SAAS-002" "WARN" "SAAS-002"

# ── SAAS-003: Vercel config (SKIP + WARN paths) ──────────────────────────────
# NOTE: only SKIP (no vercel files) and WARN (vercel.json present without security
# headers) are exercised here; the PASS path (headers present) is left untested.

echo "=== SAAS-003: no vercel files -> SKIP ==="

mkdir -p "$tmpdir/no_vercel"
SCAN_DIR="$tmpdir/no_vercel" run_check
assert_has_result "No vercel.json -> SKIP SAAS-003" "SKIP" "SAAS-003"

echo "=== SAAS-003: vercel.json present without security headers -> WARN ==="

mkdir -p "$tmpdir/vercel_present"
cat > "$tmpdir/vercel_present/vercel.json" <<'JSON'
{
  "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
JSON
SCAN_DIR="$tmpdir/vercel_present" run_check
assert_has_result "vercel.json present -> WARN SAAS-003" "WARN" "SAAS-003"

# ── SAAS-004: ArgoCD GitOps security ─────────────────────────────────────────

echo "=== SAAS-004: no ArgoCD manifests -> SKIP ==="

mkdir -p "$tmpdir/no_argo"
SCAN_DIR="$tmpdir/no_argo" run_check
assert_has_result "No ArgoCD manifests -> SKIP SAAS-004" "SKIP" "SAAS-004"

echo "=== SAAS-004: ArgoCD Application manifest, no plaintext secrets -> PASS ==="

mkdir -p "$tmpdir/argo_good"
cat > "$tmpdir/argo_good/app.yaml" <<'YAML'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
spec:
  source:
    repoURL: https://github.com/example/myapp
  destination:
    server: https://kubernetes.default.svc
YAML
SCAN_DIR="$tmpdir/argo_good" run_check
assert_has_result "ArgoCD manifest no plaintext secrets -> PASS SAAS-004" "PASS" "SAAS-004"

# ── SAAS-005: Sentry (SKIP only — all detection patterns use \| on BSD grep) ─

echo "=== SAAS-005: no Sentry files -> SKIP ==="

mkdir -p "$tmpdir/no_sentry"
printf 'print("hello")\n' > "$tmpdir/no_sentry/app.py"
SCAN_DIR="$tmpdir/no_sentry" run_check
assert_has_result "No Sentry detected -> SKIP SAAS-005" "SKIP" "SAAS-005"

# ── SAAS-006: Datadog via Terraform (no \| in pattern) ───────────────────────

echo "=== SAAS-006: no Datadog detected -> SKIP ==="

mkdir -p "$tmpdir/no_dd"
printf 'print("hello")\n' > "$tmpdir/no_dd/app.py"
SCAN_DIR="$tmpdir/no_dd" run_check
assert_has_result "No Datadog detected -> SKIP SAAS-006" "SKIP" "SAAS-006"

echo "=== SAAS-006: Datadog Terraform with variable reference -> PASS ==="

mkdir -p "$tmpdir/dd_tf"
cat > "$tmpdir/dd_tf/main.tf" <<'TF'
resource "datadog_monitor" "memory" {
  name  = "High Memory"
  type  = "metric alert"
  query = var.dd_monitor_query
}
TF
SCAN_DIR="$tmpdir/dd_tf" run_check
assert_has_result "Datadog TF with var reference -> PASS SAAS-006" "PASS" "SAAS-006"

# ── SAAS-007: Cloudflare via wrangler.toml ────────────────────────────────────

echo "=== SAAS-007: no Cloudflare detected -> SKIP ==="

mkdir -p "$tmpdir/no_cf"
SCAN_DIR="$tmpdir/no_cf" run_check
assert_has_result "No Cloudflare detected -> SKIP SAAS-007" "SKIP" "SAAS-007"

echo "=== SAAS-007: wrangler.toml without credentials -> PASS ==="

mkdir -p "$tmpdir/cf_good"
cat > "$tmpdir/cf_good/wrangler.toml" <<'TOML'
name = "my-worker"
main = "src/index.js"
compatibility_date = "2023-01-01"

[vars]
ENVIRONMENT = "production"
TOML
SCAN_DIR="$tmpdir/cf_good" run_check
assert_has_result "wrangler.toml without credentials -> PASS SAAS-007" "PASS" "SAAS-007"

# ── SAAS-008: Okta via *.yaml "okta\\.com" (no \|) ───────────────────────────

echo "=== SAAS-008: no Okta detected -> SKIP ==="

mkdir -p "$tmpdir/no_okta"
printf 'const x = 1;\n' > "$tmpdir/no_okta/app.js"
SCAN_DIR="$tmpdir/no_okta" run_check
assert_has_result "No Okta detected -> SKIP SAAS-008" "SKIP" "SAAS-008"

echo "=== SAAS-008: Okta config in YAML with env vars -> PASS ==="

mkdir -p "$tmpdir/okta_yaml"
cat > "$tmpdir/okta_yaml/auth.yaml" <<'YAML'
issuer: https://example.okta.com/oauth2/default
clientId: "${OKTA_CLIENT_ID}"
clientSecret: "${OKTA_CLIENT_SECRET}"
YAML
SCAN_DIR="$tmpdir/okta_yaml" run_check
assert_has_result "Okta YAML with env vars -> PASS SAAS-008" "PASS" "SAAS-008"

# ── SAAS-009: SendGrid (SKIP only — all detection patterns use \| on BSD grep) ─

echo "=== SAAS-009: no SendGrid detected -> SKIP ==="

mkdir -p "$tmpdir/no_sg"
printf 'print("hello")\n' > "$tmpdir/no_sg/app.py"
SCAN_DIR="$tmpdir/no_sg" run_check
assert_has_result "No SendGrid detected -> SKIP SAAS-009" "SKIP" "SAAS-009"

# ── SAAS-010: Zscaler via *.yaml "zscaler" (no \|) ───────────────────────────

echo "=== SAAS-010: no Zscaler detected -> SKIP ==="

mkdir -p "$tmpdir/no_zs"
SCAN_DIR="$tmpdir/no_zs" run_check
assert_has_result "No Zscaler detected -> SKIP SAAS-010" "SKIP" "SAAS-010"

echo "=== SAAS-010: Zscaler YAML config with env var -> PASS ==="

mkdir -p "$tmpdir/zs_yaml"
cat > "$tmpdir/zs_yaml/config.yaml" <<'YAML'
zscaler:
  api_key: "${ZSCALER_API_KEY}"
  base_url: "https://zsapi.zscaler.net"
YAML
SCAN_DIR="$tmpdir/zs_yaml" run_check
assert_has_result "Zscaler YAML with env var -> PASS SAAS-010" "PASS" "SAAS-010"

# ── SAAS-011: SentinelOne (SKIP only — all detection patterns use \|) ─────────

echo "=== SAAS-011: no SentinelOne detected -> SKIP ==="

mkdir -p "$tmpdir/no_s1"
SCAN_DIR="$tmpdir/no_s1" run_check
assert_has_result "No SentinelOne detected -> SKIP SAAS-011" "SKIP" "SAAS-011"

# ── SAAS-012: Jamf Pro via *.yaml "jamf" (no \|) ─────────────────────────────

echo "=== SAAS-012: no Jamf detected -> SKIP ==="

mkdir -p "$tmpdir/no_jamf"
SCAN_DIR="$tmpdir/no_jamf" run_check
assert_has_result "No Jamf detected -> SKIP SAAS-012" "SKIP" "SAAS-012"

echo "=== SAAS-012: Jamf YAML config without credentials -> PASS ==="

mkdir -p "$tmpdir/jamf_yaml"
cat > "$tmpdir/jamf_yaml/mdm.yaml" <<'YAML'
mdm:
  provider: jamf
  url: https://jamf.example.com
  auth: "${JAMF_AUTH_TOKEN}"
YAML
SCAN_DIR="$tmpdir/jamf_yaml" run_check
assert_has_result "Jamf YAML with env auth -> PASS SAAS-012" "PASS" "SAAS-012"

# ── SAAS-013: Redash ──────────────────────────────────────────────────────────

echo "=== SAAS-013: no Redash detected -> SKIP ==="

mkdir -p "$tmpdir/no_redash"
SCAN_DIR="$tmpdir/no_redash" run_check
assert_has_result "No Redash detected -> SKIP SAAS-013" "SKIP" "SAAS-013"

echo "=== SAAS-013: Redash docker-compose with env-var secrets -> PASS ==="

mkdir -p "$tmpdir/redash_good"
cat > "$tmpdir/redash_good/docker-compose.yml" <<'YML'
version: "3"
services:
  redash:
    image: redash/redash:latest
    environment:
      REDASH_COOKIE_SECRET: "${REDASH_COOKIE_SECRET}"
      REDASH_DATABASE_URL: "${DATABASE_URL}"
YML
SCAN_DIR="$tmpdir/redash_good" run_check
assert_has_result "Redash with env-var secrets -> PASS SAAS-013" "PASS" "SAAS-013"

echo "=== SAAS-013: Redash with default cookie secret -> WARN ==="

mkdir -p "$tmpdir/redash_bad"
cat > "$tmpdir/redash_bad/docker-compose.yml" <<'YML'
version: "3"
services:
  redash:
    image: redash/redash:latest
    environment:
      REDASH_COOKIE_SECRET: changeme_default_value
      REDASH_DATABASE_URL: "postgresql://postgres:password@db/redash"
YML
SCAN_DIR="$tmpdir/redash_bad" run_check
assert_has_result "Redash with default cookie secret -> WARN SAAS-013" "WARN" "SAAS-013"

# ── SAAS-014: QueryPie (SKIP only — all detection patterns use \|) ─────────────

echo "=== SAAS-014: no QueryPie detected -> SKIP ==="

mkdir -p "$tmpdir/no_qp"
SCAN_DIR="$tmpdir/no_qp" run_check
assert_has_result "No QueryPie detected -> SKIP SAAS-014" "SKIP" "SAAS-014"

# ── SAAS-015: Google Workspace (SKIP only — all detection patterns use \|) ────

echo "=== SAAS-015: no Google Workspace detected -> SKIP ==="

mkdir -p "$tmpdir/no_gw"
SCAN_DIR="$tmpdir/no_gw" run_check
assert_has_result "No Google Workspace detected -> SKIP SAAS-015" "SKIP" "SAAS-015"

# ── SAAS-016: Secret rotation ─────────────────────────────────────────────────

echo "=== SAAS-016: no integrations, no rotation policy -> SKIP ==="

mkdir -p "$tmpdir/no_rotation"
SCAN_DIR="$tmpdir/no_rotation" run_check
assert_has_result "No integrations -> SKIP SAAS-016" "SKIP" "SAAS-016"

echo "=== SAAS-016: rotation workflow present -> PASS ==="

mkdir -p "$tmpdir/rotation_good/.github/workflows"
cat > "$tmpdir/rotation_good/.github/workflows/rotate-secrets.yml" <<'YML'
name: Rotate secrets
on:
  schedule:
    - cron: "0 0 1 * *"
jobs:
  rotate:
    runs-on: ubuntu-latest
    steps: []
YML
SCAN_DIR="$tmpdir/rotation_good" run_check
assert_has_result "Rotation workflow present -> PASS SAAS-016" "PASS" "SAAS-016"

# ── SAAS-017: Harbor ──────────────────────────────────────────────────────────

echo "=== SAAS-017: no Harbor detected -> SKIP ==="

mkdir -p "$tmpdir/no_harbor"
SCAN_DIR="$tmpdir/no_harbor" run_check
assert_has_result "No Harbor detected -> SKIP SAAS-017" "SKIP" "SAAS-017"

echo "=== SAAS-017: harbor.yml without secrets -> PASS ==="

mkdir -p "$tmpdir/harbor_good"
cat > "$tmpdir/harbor_good/harbor.yml" <<'YAML'
hostname: harbor.example.com
https:
  port: 443
  certificate: /path/to/cert
  private_key: /path/to/key
YAML
SCAN_DIR="$tmpdir/harbor_good" run_check
assert_has_result "harbor.yml without hardcoded secrets -> PASS SAAS-017" "PASS" "SAAS-017"

echo "=== SAAS-017: harbor.yml with password field -> WARN ==="

mkdir -p "$tmpdir/harbor_bad"
cat > "$tmpdir/harbor_bad/harbor.yml" <<'YAML'
hostname: harbor.example.com
harbor_admin_password: changeit
YAML
SCAN_DIR="$tmpdir/harbor_bad" run_check
assert_has_result "harbor.yml with password field -> WARN SAAS-017" "WARN" "SAAS-017"

# ── SAAS-018: Jenkins ─────────────────────────────────────────────────────────

echo "=== SAAS-018: no Jenkinsfile -> SKIP ==="

mkdir -p "$tmpdir/no_jenkins"
SCAN_DIR="$tmpdir/no_jenkins" run_check
assert_has_result "No Jenkinsfile -> SKIP SAAS-018" "SKIP" "SAAS-018"

echo "=== SAAS-018: clean Jenkinsfile -> PASS ==="

mkdir -p "$tmpdir/jenkins_good"
cat > "$tmpdir/jenkins_good/Jenkinsfile" <<'GV'
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        withCredentials([usernamePassword(credentialsId: 'my-creds', usernameVariable: 'USER', passwordVariable: 'PASS')]) {
          sh 'echo deploying'
        }
      }
    }
  }
}
GV
SCAN_DIR="$tmpdir/jenkins_good" run_check
assert_has_result "Clean Jenkinsfile -> PASS SAAS-018" "PASS" "SAAS-018"

echo "=== SAAS-018: Jenkinsfile with hardcoded secret -> FAIL ==="

mkdir -p "$tmpdir/jenkins_bad"
cat > "$tmpdir/jenkins_bad/Jenkinsfile" <<'GV'
pipeline {
  agent any
  environment {
    token = 'hardcoded-deploy-token'
  }
  stages {
    stage('Deploy') {
      steps {
        sh "echo deploying"
      }
    }
  }
}
GV
SCAN_DIR="$tmpdir/jenkins_bad" run_check
assert_has_result "Jenkinsfile with hardcoded secret -> FAIL SAAS-018" "FAIL" "SAAS-018"

# ── SAAS-019: IDE/VS Code ─────────────────────────────────────────────────────

echo "=== SAAS-019: no IDE files -> SKIP ==="

mkdir -p "$tmpdir/no_ide"
SCAN_DIR="$tmpdir/no_ide" run_check
assert_has_result "No IDE workspace files -> SKIP SAAS-019" "SKIP" "SAAS-019"

echo "=== SAAS-019: .vscode/settings.json without insecure settings -> PASS ==="

mkdir -p "$tmpdir/ide_good/.vscode"
cat > "$tmpdir/ide_good/.vscode/settings.json" <<'JSON'
{
  "editor.formatOnSave": true,
  "editor.tabSize": 2
}
JSON
SCAN_DIR="$tmpdir/ide_good" run_check
assert_has_result ".vscode/settings.json (clean) -> PASS SAAS-019" "PASS" "SAAS-019"

echo "=== SAAS-019: .vscode/settings.json with workspace trust disabled -> WARN ==="

mkdir -p "$tmpdir/ide_bad/.vscode"
cat > "$tmpdir/ide_bad/.vscode/settings.json" <<'JSON'
{
  "security.workspace.trust.enabled": false,
  "editor.formatOnSave": true
}
JSON
SCAN_DIR="$tmpdir/ide_bad" run_check
assert_has_result ".vscode workspace trust disabled -> WARN SAAS-019" "WARN" "SAAS-019"

# ── REGRESSION (grep -E alternation): integration detection used "\|" ──────────
# These detectors keyed on patterns like "Sentry.init\|@sentry/node". Under
# grep -E (ERE) "\|" is a LITERAL pipe, not alternation, so the integration was
# never detected and the check always emitted SKIP. With the alternation fixed
# to (a|b), an integration-present fixture is detected and emits PASS/WARN (never
# SKIP). assert_no_result SKIP is RED on the old code, GREEN on the fix.
mkdir -p "$tmpdir/sentry_app"
cat > "$tmpdir/sentry_app/app.js" <<'JS'
const Sentry = require("@sentry/node");
Sentry.init({ dsn: process.env.SENTRY_DSN });
JS
SCAN_DIR="$tmpdir/sentry_app" run_check
assert_no_result "Sentry detected -> not SKIP SAAS-005 (alternation regression)" "SKIP" "SAAS-005"

mkdir -p "$tmpdir/sendgrid_app"
cat > "$tmpdir/sendgrid_app/mail.js" <<'JS'
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
JS
SCAN_DIR="$tmpdir/sendgrid_app" run_check
assert_no_result "SendGrid detected -> not SKIP SAAS-009 (alternation regression)" "SKIP" "SAAS-009"

mkdir -p "$tmpdir/s1_app"
cat > "$tmpdir/s1_app/agents.yaml" <<'YAML'
sentinelone:
  console: https://example.sentinelone.net
YAML
SCAN_DIR="$tmpdir/s1_app" run_check
assert_no_result "SentinelOne detected -> not SKIP SAAS-011 (alternation regression)" "SKIP" "SAAS-011"

mkdir -p "$tmpdir/qp_app"
cat > "$tmpdir/qp_app/config.yaml" <<'YAML'
querypie:
  url: https://example.querypie.com
YAML
SCAN_DIR="$tmpdir/qp_app" run_check
assert_no_result "QueryPie detected -> not SKIP SAAS-014 (alternation regression)" "SKIP" "SAAS-014"

mkdir -p "$tmpdir/gws_app"
cat > "$tmpdir/gws_app/creds.json" <<'JSON'
{ "endpoint": "https://www.googleapis.com/admin/directory/v1/users" }
JSON
SCAN_DIR="$tmpdir/gws_app" run_check
assert_no_result "Google Workspace detected -> not SKIP SAAS-015 (alternation regression)" "SKIP" "SAAS-015"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
