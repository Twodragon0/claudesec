#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# TTY-gated branches of aws_sso_ensure_login() and aws_sso_login_all_profiles()
# in scanner/lib/checks.sh.
#
# Both functions have a [[ ! -t 0 ]] guard that causes early-return when stdin
# is not a terminal.  This test must be invoked via pty_run.py so that stdin is
# a pty slave, making [[ -t 0 ]] return true and letting kcov instrument the
# protected body.
#
# Run standalone: python3 scanner/tests/pty_run.py bash scanner/tests/test_aws_sso_tty.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((TEST_FAILED++))
  fi
}

assert_true() {
  local label="$1" rc="$2"
  if [[ "$rc" == "0" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label (rc=$rc)"
    ((TEST_FAILED++))
  fi
}

assert_false() {
  local label="$1" rc="$2"
  if [[ "$rc" != "0" ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label (expected nonzero, got 0)"
    ((TEST_FAILED++))
  fi
}

# Color codes referenced by sourced lib
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ─── PATH stubs ───────────────────────────────────────────────────────────────
stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

# aws stub: AWS_STS_MODE (ok|fail) controls sts get-caller-identity;
#           AWS_SSO_MODE (ok|fail|timeout) controls sso login.
cat > "$stub_dir/aws" <<'STUB'
#!/usr/bin/env bash
args="$*"
case "$args" in
  *"sts get-caller-identity"*)
    case "${AWS_STS_MODE:-fail}" in
      ok) echo '{"Account":"acctid","Arn":"arn:aws:iam::acctid:user/tester"}'; exit 0 ;;
      *)  exit 1 ;;
    esac
    ;;
  *"sso login"*)
    case "${AWS_SSO_MODE:-ok}" in
      ok)      exit 0   ;;
      timeout) exit 124 ;;
      *)       exit 1   ;;
    esac
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/aws"

# timeout stub: drop first arg (seconds) and exec the rest
cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
shift
"$@"
STUB
chmod +x "$stub_dir/timeout"

export PATH="$stub_dir:$PATH"

# ─── Fake AWS config files ────────────────────────────────────────────────────
fake_config="$tmpdir/aws_config"
# [default] is placed last so grep -A10 on it doesn't bleed into any
# [profile ...] stanza that has sso_start_url — which would wrongly prepend
# "default" to the sso_profiles list in aws_sso_ensure_login.
cat > "$fake_config" <<'CFG'
[profile dev]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
region = us-east-1

[profile staging]
sso_start_url = https://staging.awsapps.com/start
sso_region = us-west-2
region = us-west-2

[default]
region = us-east-1
CFG

no_sso_config="$tmpdir/aws_no_sso"
cat > "$no_sso_config" <<'CFG'
[default]
region = us-east-1

[profile plain]
region = us-east-1
CFG

# Sanity: verify we actually have a tty on stdin
if [[ ! -t 0 ]]; then
  echo "WARNING: stdin is not a tty — run via: python3 scanner/tests/pty_run.py bash $0" >&2
fi

# ─── aws_sso_ensure_login() — TTY-gated body ─────────────────────────────────
echo ""
echo "=== aws_sso_ensure_login() — TTY-gated body ==="

# A. Already authenticated: sts returns 0 → return 0 immediately
export AWS_STS_MODE=ok AWS_SSO_MODE=ok AWS_CONFIG_FILE="$fake_config"
unset AWS_PROFILE AWS_DEFAULT_PROFILE CLAUDESEC_NONINTERACTIVE
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_true "already_auth: sts-ok returns 0" "$rc"

# B. Not auth, AWS_PROFILE=dev, sso login succeeds → return 0, exports AWS_DEFAULT_PROFILE
export AWS_STS_MODE=fail AWS_SSO_MODE=ok AWS_PROFILE=dev
unset AWS_DEFAULT_PROFILE
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_true "profile_set sso_ok: returns 0" "$rc"
assert_eq   "profile_set sso_ok: AWS_DEFAULT_PROFILE=dev" "dev" "${AWS_DEFAULT_PROFILE:-}"

# C. Not auth, AWS_PROFILE=dev, sso login times out (rc=124) → return 1
export AWS_STS_MODE=fail AWS_SSO_MODE=timeout AWS_PROFILE=dev
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_false "profile_set sso_timeout: returns nonzero" "$rc"

# D. Not auth, AWS_PROFILE=dev, sso login fails (rc=1) → return 1
export AWS_STS_MODE=fail AWS_SSO_MODE=fail AWS_PROFILE=dev
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_false "profile_set sso_fail: returns nonzero" "$rc"

# E. Not auth, no AWS_PROFILE, config file missing → return 1 at file guard
export AWS_STS_MODE=fail AWS_SSO_MODE=ok
unset AWS_PROFILE
export AWS_CONFIG_FILE="/nonexistent_sso_config_$$"
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_false "no_profile no_config: returns nonzero" "$rc"

# F. Not auth, no profile, config has no SSO profiles → return 1
export AWS_CONFIG_FILE="$no_sso_config"
unset AWS_PROFILE
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_false "no_profile no_sso_in_config: returns nonzero" "$rc"

# G. Not auth, no profile, config has SSO profiles, login succeeds → return 0, exports AWS_PROFILE
export AWS_STS_MODE=fail AWS_SSO_MODE=ok AWS_CONFIG_FILE="$fake_config"
unset AWS_PROFILE
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_true "no_profile sso_ok: returns 0" "$rc"
assert_eq   "no_profile sso_ok: AWS_PROFILE exported as first sso profile" "dev" "${AWS_PROFILE:-}"

# H. Not auth, no profile, config has SSO profiles, login times out → return 1
export AWS_STS_MODE=fail AWS_SSO_MODE=timeout AWS_CONFIG_FILE="$fake_config"
unset AWS_PROFILE
aws_sso_ensure_login >/dev/null 2>&1
rc=$?
assert_false "no_profile sso_timeout: returns nonzero" "$rc"

# ─── aws_sso_login_all_profiles() — TTY-gated body ───────────────────────────
echo ""
echo "=== aws_sso_login_all_profiles() — TTY-gated body ==="

unset CLAUDESEC_NONINTERACTIVE

# I. Config file missing → return 1 at file guard
export AWS_CONFIG_FILE="/nonexistent_sso_config_$$"
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_false "all_profiles no_config: returns nonzero" "$rc"

# J. Config exists but no SSO profiles → return 1 (empty sso_profiles)
export AWS_CONFIG_FILE="$no_sso_config"
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_false "all_profiles no_sso_profiles: returns nonzero" "$rc"

# K. Config has SSO profiles, profile already auth (sts-ok) → returns 0
export AWS_STS_MODE=ok AWS_CONFIG_FILE="$fake_config"
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_true "all_profiles already_auth: returns 0" "$rc"

# L. Not auth, sso login succeeds → newly_auth, any_success=true → returns 0
export AWS_STS_MODE=fail AWS_SSO_MODE=ok
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_true "all_profiles sso_ok: returns 0" "$rc"

# M. Not auth, sso login times out → timeout_skipped, any_success=false → returns 1
export AWS_STS_MODE=fail AWS_SSO_MODE=timeout
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_false "all_profiles sso_timeout: returns nonzero" "$rc"

# N. Not auth, sso login fails → failed_auth, any_success=false → returns 1
export AWS_STS_MODE=fail AWS_SSO_MODE=fail
aws_sso_login_all_profiles >/dev/null 2>&1
rc=$?
assert_false "all_profiles sso_fail: returns nonzero" "$rc"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
