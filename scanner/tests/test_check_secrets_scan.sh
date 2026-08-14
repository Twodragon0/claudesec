#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/access-control/secrets-scan.sh
# Covers patterns and edge cases not in test_check_access_control.sh, plus
# SECRETS-003 (git history scan) which requires a real git repo fixture.
# Run: bash scanner/tests/test_check_secrets_scan.sh
set -uo pipefail

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

# Capture pass/fail/warn/skip calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }

# Stub JSON output helpers used by the check
append_json() { :; }
_emit_finding_json() { :; }
JSON_RESULTS=""
TOTAL_CHECKS=0
PASSED_COUNT=0
FAILED_COUNT=0
WARNINGS=0
SKIPPED=0

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
  ENV_SCAN_FILES=()
  source "$CHECKS_DIR/access-control/secrets-scan.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── SECRETS-001: Additional source-code secret pattern coverage ──────────────

echo "=== SECRETS-001: Stripe secret key in source ==="

# FAIL: Stripe secret key pattern in Python file.
# Build the dummy key from prefix + suffix at runtime so the committed test
# source holds no contiguous secret literal (GitHub push protection scans source
# files, not the temp fixture). The check still sees the full value on disk.
mkdir -p "$tmpdir/stripe_leak/src"
_sk_prefix='sk_live_'
printf 'STRIPE_KEY = "%s%s"\n' "$_sk_prefix" 'abcdefghijklmnopqrstuvwx' \
  > "$tmpdir/stripe_leak/src/payments.py"
SCAN_DIR="$tmpdir/stripe_leak" run_check
assert_has_result "Stripe secret key in source -> FAIL SECRETS-001" "FAIL" "SECRETS-001"

echo "=== SECRETS-001: Slack token in source ==="

# FAIL: Slack xoxb token in YAML config. Same runtime-assembly trick as above so
# the source contains only the bare "xoxb-" prefix (too short to match GitHub's
# Slack detector), while the fixture on disk holds the full dummy token.
mkdir -p "$tmpdir/slack_leak"
_slack_prefix='xoxb-'
printf 'slack:\n  token: "%s%s"\n' "$_slack_prefix" '000000000-000000000000-FakeSlackTokenForTestOnly' \
  > "$tmpdir/slack_leak/config.yaml"
SCAN_DIR="$tmpdir/slack_leak" run_check
assert_has_result "Slack token in YAML -> FAIL SECRETS-001" "FAIL" "SECRETS-001"

echo "=== SECRETS-001: npm token in source ==="

# FAIL: npm token pattern in a .sh file.
# The npm Token pattern is "npm_[a-zA-Z0-9]{36}" — no | inside the regex,
# so IFS='|' splitting in the check loop produces a valid grep pattern.
# Dummy value: npm_ prefix + 36 obviously-fake alphanumeric chars. Build it from
# prefix + suffix at runtime (same trick as the Stripe/Slack fixtures above) so the
# committed test source holds no contiguous npm-token literal — GitGuardian scans
# every commit in the PR, not just the temp fixture written to disk.
mkdir -p "$tmpdir/npm_leak"
_npm_prefix='npm_'
printf '#!/usr/bin/env bash\nNPM_AUTH_TOKEN="%s%s"\n' "$_npm_prefix" 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij' \
  > "$tmpdir/npm_leak/publish.sh"
SCAN_DIR="$tmpdir/npm_leak" run_check
assert_has_result "npm token in .sh -> FAIL SECRETS-001" "FAIL" "SECRETS-001"

echo "=== SECRETS-001: GitHub App Token (|-alternation pattern) ==="

# REGRESSION (IFS pipe-split bug): the "GitHub App Token" pattern is
# (ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,} — it contains '|' alternation. The old
# `IFS='|' read` truncated it to the unbalanced "(ghp", so grep -E errored and the
# detector silently matched nothing. A ghu_-prefixed token is matched ONLY by this
# pattern (the gh[ps]_/gho_ patterns exclude ghu_), so it isolates the fix.
# Build it from prefix + 36 fake chars at runtime so no contiguous token literal
# sits in the committed source.
mkdir -p "$tmpdir/ghapp_leak"
_gh_prefix='ghu_'
printf 'GH_APP_TOKEN="%s%s"\n' "$_gh_prefix" 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab' \
  > "$tmpdir/ghapp_leak/deploy.sh"
SCAN_DIR="$tmpdir/ghapp_leak" run_check
assert_has_result "GitHub App Token (ghu_) in source -> FAIL SECRETS-001 (IFS pipe-split regression)" "FAIL" "SECRETS-001"

echo "=== SECRETS-001: Allowlisted path (scanner/tests/) not flagged ==="

# PASS: A file under scanner/tests/ is in the allowlisted path, so SECRETS-001
# scans source code via find -exec grep, but the check itself excludes */scanner/*
# Verify that a clean source dir with no patterns passes
mkdir -p "$tmpdir/clean_src"
cat > "$tmpdir/clean_src/app.py" <<'PY'
import os
db_password = os.environ.get("DB_PASSWORD", "")
PY
SCAN_DIR="$tmpdir/clean_src" run_check
assert_has_result "No secrets in source -> PASS SECRETS-001" "PASS" "SECRETS-001"

# ── SECRETS-001: GCP service account pattern ─────────────────────────────────

echo "=== SECRETS-001: GCP service account JSON pattern ==="

# FAIL: GCP service account type field in JSON file
mkdir -p "$tmpdir/gcp_sa_leak"
cat > "$tmpdir/gcp_sa_leak/credentials.json" <<'JSON'
{
  "type": "service_account",
  "project_id": "fake-project-id-example",
  "private_key_id": "fakekeyid00000000000000000000000000000000"
}
JSON
SCAN_DIR="$tmpdir/gcp_sa_leak" run_check
assert_has_result "GCP service_account type field -> FAIL SECRETS-001" "FAIL" "SECRETS-001"

# ── SECRETS-002: Additional .env edge cases ───────────────────────────────────

echo "=== SECRETS-002: VAULT_TOKEN in non-allowlisted .env ==="

# FAIL: Vault token key in a non-allowlisted .env. Assemble from the bare "s."
# prefix + suffix at runtime (as with the source-secret fixtures above) so no
# contiguous Vault-style token literal sits in the committed source.
mkdir -p "$tmpdir/vault_env"
_vault_prefix='s.'
printf 'VAULT_TOKEN=%s%s\n' "$_vault_prefix" 'fake-vault-token-value-for-testing' \
  > "$tmpdir/vault_env/.env"
cat > "$tmpdir/vault_env/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/vault_env" run_check
assert_has_result "VAULT_TOKEN in .env -> FAIL SECRETS-002" "FAIL" "SECRETS-002"

echo "=== SECRETS-002: Empty .env values skipped ==="

# PASS: .env with empty values for sensitive keys — no real secret
mkdir -p "$tmpdir/empty_env"
cat > "$tmpdir/empty_env/.env" <<'ENV'
API_KEY=
SECRET=
TOKEN=""
PASSWORD=''
ENV
cat > "$tmpdir/empty_env/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/empty_env" run_check
assert_has_result "Empty .env values -> PASS SECRETS-002" "PASS" "SECRETS-002"

echo "=== SECRETS-002: .env in examples/ allowlisted path -> WARN ==="

# WARN: .env with a non-placeholder value inside examples/ (allowlisted path).
# The value must NOT contain: YOUR_, CHANGE_ME, xxx, placeholder, example, TODO
# (those are treated as placeholders by the check and skipped).
# Use a value that looks real but is obviously a dummy (all-caps FAKE prefix).
# Assemble from prefix + suffix at runtime (as above) so no contiguous OpenAI-style
# literal sits in the committed source for GitGuardian to flag.
mkdir -p "$tmpdir/examples_env/examples"
_openai_prefix='sk-'
printf 'OPENAI_API_KEY=FAKE-%s%s\n' "$_openai_prefix" 'abcdefghijklmnopqrstuvwxyz0123456789' \
  > "$tmpdir/examples_env/examples/.env"
cat > "$tmpdir/examples_env/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/examples_env" run_check
assert_has_result ".env with non-placeholder value in examples/ -> WARN SECRETS-002" "WARN" "SECRETS-002"

# ── SECRETS-003: Git history scan ────────────────────────────────────────────

echo "=== SECRETS-003: Not a git repo -> skip ==="

# SKIP: SCAN_DIR is not a git repository
mkdir -p "$tmpdir/not_a_repo"
cat > "$tmpdir/not_a_repo/app.py" <<'PY'
pass
PY
SCAN_DIR="$tmpdir/not_a_repo" run_check
assert_has_result "Non-git dir -> skip SECRETS-003" "SKIP" "SECRETS-003"

echo "=== SECRETS-003: Clean git repo -> pass ==="

# PASS: git repo with no secrets in history
gitrepo="$tmpdir/clean_git_repo"
mkdir -p "$gitrepo"
git -C "$gitrepo" init -q
git -C "$gitrepo" config user.email "test@example.com"
git -C "$gitrepo" config user.name "Test"
cat > "$gitrepo/app.py" <<'PY'
import os
api_key = os.environ.get("API_KEY", "")
PY
git -C "$gitrepo" add app.py
git -C "$gitrepo" commit -q -m "initial commit"
SCAN_DIR="$gitrepo" run_check
assert_has_result "Clean git repo -> PASS SECRETS-003" "PASS" "SECRETS-003"

echo "=== SECRETS-003: Git repo with AWS key pattern in history -> fail ==="

# FAIL: git repo where a recent commit added a file containing an AWS key pattern.
# The dummy value is the canonical AWS documentation example access-key id. It is
# assembled from prefix + suffix at runtime (like the source-secret fixtures above)
# so the committed test source holds no contiguous AKIA-literal — the AWS Keys
# detector flags even the documentation example, so we keep it out of the diff. The
# throwaway git repo built below still contains the full value the check detects.
awsrepo="$tmpdir/aws_history_repo"
mkdir -p "$awsrepo"
git -C "$awsrepo" init -q
git -C "$awsrepo" config user.email "test@example.com"
git -C "$awsrepo" config user.name "Test"
# First commit: clean file
cat > "$awsrepo/app.py" <<'PY'
pass
PY
git -C "$awsrepo" add app.py
git -C "$awsrepo" commit -q -m "initial"
# Second commit: accidentally add a file with AWS key pattern (fake/example key)
_aws_prefix='AKIA'
printf '# FAKE test fixture — AWS documentation example key, not a real credential\nAWS_ACCESS_KEY_ID = "%s%s"\n' \
  "$_aws_prefix" 'IOSFODNN7EXAMPLE' > "$awsrepo/oops.py"
git -C "$awsrepo" add oops.py
git -C "$awsrepo" commit -q -m "oops added fake key"
SCAN_DIR="$awsrepo" run_check
assert_has_result "AWS key pattern in git history -> FAIL SECRETS-003" "FAIL" "SECRETS-003"

# ── SECRETS-004: Credential file path references ──────────────────────────────

echo "=== SECRETS-004: SSH key path in Dockerfile ==="

# FAIL: reference to id_rsa in Dockerfile (non-allowlisted)
mkdir -p "$tmpdir/dockerfile_ssh"
cat > "$tmpdir/dockerfile_ssh/Dockerfile" <<'DOCKER'
FROM ubuntu:22.04
COPY id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
DOCKER
SCAN_DIR="$tmpdir/dockerfile_ssh" run_check
assert_has_result "id_rsa path in Dockerfile -> FAIL SECRETS-004" "FAIL" "SECRETS-004"

echo "=== SECRETS-004: kube config path in allowlisted template ==="

# WARN: kubeconfig reference in templates/ (allowlisted path)
mkdir -p "$tmpdir/kube_template/templates"
cat > "$tmpdir/kube_template/templates/setup.sh" <<'SH'
#!/usr/bin/env bash
# Example setup — replace with your actual path
KUBECONFIG=~/.kube/config
SH
SCAN_DIR="$tmpdir/kube_template" run_check
assert_has_result "kubeconfig path in templates/ -> WARN SECRETS-004" "WARN" "SECRETS-004"

echo "=== SECRETS-004: No credential path refs -> pass ==="

# PASS: source files with no credential path references
mkdir -p "$tmpdir/cred_clean"
cat > "$tmpdir/cred_clean/main.py" <<'PY'
print("hello world")
PY
SCAN_DIR="$tmpdir/cred_clean" run_check
assert_has_result "No credential path refs -> PASS SECRETS-004" "PASS" "SECRETS-004"

echo "=== SECRETS-004: multi-hit detail blob (count + newline regression) ==="

# The accumulators used to append the two-character sequence `\n` (bash leaves
# `\n` literal inside double quotes), which collapsed the whole blob onto ONE
# line. Two defects followed: the awk dedup/count saw a single line and always
# reported "1 reference(s)" no matter how many files matched, and
# _json_escape_str escaped the backslash so scan-report.json carried `\\n` —
# rendered as visible `\n` text in the dashboard. Both are asserted here.
#
# The default `warn()` stub above records only the check id, so this block
# installs a title-capturing stub for the duration and restores it after.
_captured_warn_title=""
warn() { RESULTS+=("WARN:$1"); _captured_warn_title="$2"; }

mkdir -p "$tmpdir/cred_multi/templates"
for _n in one two three; do
  cat > "$tmpdir/cred_multi/templates/setup-$_n.sh" <<SH
#!/usr/bin/env bash
KUBECONFIG=~/.kube/config
SH
done
SCAN_DIR="$tmpdir/cred_multi" run_check

# 1. The count must equal the number of distinct matching files, not 1.
if [[ "$_captured_warn_title" == 3\ * ]]; then
  echo "  PASS: 3 matching files -> title reports 3, not 1"
  ((TEST_PASSED++))
else
  echo "  FAIL: expected title to start with '3 ', got: ${_captured_warn_title%%$'\n'*}"
  ((TEST_FAILED++))
fi

# 1b. The summary line must stand alone: `awk NF` drops the leading blank line,
#     which glued the first detail onto it.
if [[ "${_captured_warn_title%%$'\n'*}" != *"Kubernetes config file:"* ]]; then
  echo "  PASS: summary line is not glued to the first detail line"
  ((TEST_PASSED++))
else
  echo "  FAIL: first detail is on the summary line: ${_captured_warn_title%%$'\n'*}"
  ((TEST_FAILED++))
fi

# 2. Details must be separated by REAL newlines...
if [[ "$_captured_warn_title" == *$'\n'* ]]; then
  echo "  PASS: detail lines are separated by real newlines"
  ((TEST_PASSED++))
else
  echo "  FAIL: no real newline in title — the blob collapsed onto one line"
  ((TEST_FAILED++))
fi

# 3. ...and must NOT contain a literal backslash-n, which is what leaks into
#    scan-report.json as `\\n` and reaches the dashboard as visible garbage.
if [[ "$_captured_warn_title" != *'\n'* ]]; then
  echo "  PASS: no literal backslash-n in the detail blob"
  ((TEST_PASSED++))
else
  echo "  FAIL: literal backslash-n present — it will render as \\n in the dashboard"
  ((TEST_FAILED++))
fi

# Mutation self-test: the assertions above must actually be able to fail.
# Rebuild the pre-fix blob and confirm each one rejects it.
_broken=""
for _p in a b c; do _broken="${_broken}\n    Kubernetes config file: $_p"; done
_broken="3 references${_broken}"
if [[ "$_broken" == *$'\n'* ]] || [[ "$_broken" != *'\n'* ]]; then
  echo "  FAIL: mutation self-test — assertions 2/3 accept the pre-fix blob (vacuous)"
  ((TEST_FAILED++))
else
  echo "  PASS: mutation self-test — assertions 2/3 reject the pre-fix blob"
  ((TEST_PASSED++))
fi

# Restore the id-only stub for any later block.
warn() { RESULTS+=("WARN:$1"); }

echo "=== SECRETS-004: nested worktree checkouts are not scanned ==="

# .claude/worktrees/<id>/ holds gitignored checkouts of OTHER branches. Scanning
# them reported the same template file once per worktree — four duplicate
# findings for one real one, on a developer machine only.
mkdir -p "$tmpdir/cred_wt/templates" "$tmpdir/cred_wt/.claude/worktrees/agent-dead/templates"
cat > "$tmpdir/cred_wt/.claude/worktrees/agent-dead/templates/setup.sh" <<'SH'
#!/usr/bin/env bash
KUBECONFIG=~/.kube/config
SH
cat > "$tmpdir/cred_wt/main.py" <<'PY'
print("hello world")
PY
SCAN_DIR="$tmpdir/cred_wt" run_check
assert_has_result "credential ref only inside .claude/worktrees -> PASS SECRETS-004" "PASS" "SECRETS-004"

# Positive control: the identical file OUTSIDE the worktree must still be found,
# so the exclusion cannot pass by disabling the check entirely.
cp "$tmpdir/cred_wt/.claude/worktrees/agent-dead/templates/setup.sh" "$tmpdir/cred_wt/templates/setup.sh"
SCAN_DIR="$tmpdir/cred_wt" run_check
assert_has_result "same file outside the worktree -> WARN SECRETS-004" "WARN" "SECRETS-004"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
