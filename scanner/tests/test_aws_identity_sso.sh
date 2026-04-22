#!/usr/bin/env bash
# shellcheck disable=SC2034,SC1091
# Unit tests for AWS identity + SSO helpers in checks.sh.
# Covers:
#   - aws_identity_info()             (parses aws sts get-caller-identity JSON)
#   - aws_sso_login_with_timeout()    (early-return branches; no real login)
#   - aws_sso_ensure_login()          (CLAUDESEC_NONINTERACTIVE and non-TTY guards,
#                                      plus missing-aws-CLI guard)
#   - aws_sso_login_all_profiles()    (same guards; never triggers a real login)
#
# All AWS CLI invocations are stubbed via a throwaway PATH-prepended directory
# so no network/browser/login ever happens.
# Run: bash scanner/tests/test_aws_identity_sso.sh
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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: $haystack"
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
    echo "  FAIL: $label (rc=$rc)"
    ((TEST_FAILED++))
  fi
}

# Color codes some helpers reference (silenced for test output)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/checks.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ──────────────────────────────────────────────────────────────────────────────
# Stub `aws` CLI via PATH so no real AWS calls ever happen.
# Default stub: a dispatcher keyed off $AWS_STUB_MODE.
#   sts-ok      → sts get-caller-identity returns valid JSON
#   sts-fail    → sts returns non-zero, empty output
#   sso-ok      → sso login exits 0
#   sso-fail    → sso login exits 1
#   sso-timeout → sso login exits 124 (timeout)
# ──────────────────────────────────────────────────────────────────────────────
stub_dir="$tmpdir/bin"
mkdir -p "$stub_dir"

cat > "$stub_dir/aws" <<'STUB'
#!/usr/bin/env bash
mode="${AWS_STUB_MODE:-sts-fail}"
# Flatten argv so we can pattern-match regardless of argument order
args="$*"
case "$args" in
  *"sts get-caller-identity"*)
    case "$mode" in
      sts-ok)
        cat <<JSON
{
  "UserId": "AIDAEXAMPLE:abc",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/test"
}
JSON
        exit 0
        ;;
      *) exit 1 ;;
    esac
    ;;
  *"sso login"*)
    case "$mode" in
      sso-ok) exit 0 ;;
      sso-timeout) exit 124 ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$stub_dir/aws"

# Stub `timeout` to just exec its command so we can exercise the
# has_command timeout branch of aws_sso_login_with_timeout deterministically.
cat > "$stub_dir/timeout" <<'STUB'
#!/usr/bin/env bash
# timeout <secs> <cmd> [args...] → drop the secs arg and run the rest.
shift
"$@"
STUB
chmod +x "$stub_dir/timeout"

# Put stubs first on PATH so has_command/run_with_timeout pick them up.
export PATH="$stub_dir:$PATH"

# ──────────────────────────────────────────────────────────────────────────────
# aws_identity_info()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== aws_identity_info() ==="

# 1. Happy path: valid JSON parsed into "account|arn"
export AWS_STUB_MODE="sts-ok"
info=$(aws_identity_info)
assert_eq       "aws_identity_info: account field"  "123456789012" "$(echo "$info" | cut -d'|' -f1)"
assert_contains "aws_identity_info: arn field"      "$info"         "arn:aws:iam::123456789012:user/test"
assert_contains "aws_identity_info: pipe delimiter" "$info"         "|"

# 2. Failure path: sts returns non-zero → fallback "unknown|unknown"
export AWS_STUB_MODE="sts-fail"
info_fail=$(aws_identity_info)
assert_eq "aws_identity_info: fallback account" "unknown" "$(echo "$info_fail" | cut -d'|' -f1)"
assert_eq "aws_identity_info: fallback arn"     "unknown" "$(echo "$info_fail" | cut -d'|' -f2)"

# ──────────────────────────────────────────────────────────────────────────────
# aws_sso_login_with_timeout()
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== aws_sso_login_with_timeout() ==="

# 1. Empty profile → returns 1 without invoking aws
aws_sso_login_with_timeout "" >/dev/null 2>&1
assert_false "aws_sso_login_with_timeout: empty profile returns 1" "$?"

# 2. Missing arg (defaults to "") → returns 1
aws_sso_login_with_timeout >/dev/null 2>&1
assert_false "aws_sso_login_with_timeout: missing arg returns 1" "$?"

# 3. Success path with stubbed timeout + aws
export AWS_STUB_MODE="sso-ok"
aws_sso_login_with_timeout "dev" >/dev/null 2>&1
assert_true "aws_sso_login_with_timeout: sso-ok returns 0" "$?"

# 4. Failure path (non-timeout)
export AWS_STUB_MODE="sso-fail"
aws_sso_login_with_timeout "dev" >/dev/null 2>&1
assert_false "aws_sso_login_with_timeout: sso-fail returns nonzero" "$?"

# 5. Timeout path (rc=124 passes through)
export AWS_STUB_MODE="sso-timeout"
aws_sso_login_with_timeout "dev" >/dev/null 2>&1
assert_eq "aws_sso_login_with_timeout: preserves rc=124" "124" "$?"

# ──────────────────────────────────────────────────────────────────────────────
# aws_sso_ensure_login() — guard branches only (never actually logs in)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== aws_sso_ensure_login() ==="

# 1. Non-interactive mode → early return 1, no aws calls attempted
export CLAUDESEC_NONINTERACTIVE=1
aws_sso_ensure_login </dev/null >/dev/null 2>&1
assert_false "aws_sso_ensure_login: CLAUDESEC_NONINTERACTIVE=1 returns 1" "$?"
unset CLAUDESEC_NONINTERACTIVE

# 2. Missing aws CLI branch: simulate by pointing PATH at an empty dir
orig_path="$PATH"
empty_dir="$tmpdir/empty_path"
mkdir -p "$empty_dir"
PATH="$empty_dir"
aws_sso_ensure_login </dev/null >/dev/null 2>&1
assert_false "aws_sso_ensure_login: no aws CLI returns 1" "$?"
PATH="$orig_path"

# 3. Non-TTY branch (stdin is a file, not a tty): CLAUDESEC_NONINTERACTIVE
#    must be unset and aws CLI must be on PATH to reach the non-TTY guard.
export AWS_STUB_MODE="sts-fail"
unset CLAUDESEC_NONINTERACTIVE
out=$(aws_sso_ensure_login </dev/null 2>&1)
rc=$?
assert_false "aws_sso_ensure_login: non-TTY returns nonzero" "$rc"
assert_contains "aws_sso_ensure_login: non-TTY prints hint" "$out" "interactive terminal"

# ──────────────────────────────────────────────────────────────────────────────
# aws_sso_login_all_profiles() — guard branches
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== aws_sso_login_all_profiles() ==="

# 1. CLAUDESEC_NONINTERACTIVE=1 blocks even with aws present
export CLAUDESEC_NONINTERACTIVE=1
aws_sso_login_all_profiles </dev/null >/dev/null 2>&1
assert_false "aws_sso_login_all_profiles: NONINTERACTIVE blocks" "$?"
unset CLAUDESEC_NONINTERACTIVE

# 2. Non-TTY with no sso profiles → returns 1 after printing hint
out2=$(aws_sso_login_all_profiles </dev/null 2>&1)
rc2=$?
assert_false "aws_sso_login_all_profiles: non-TTY returns 1" "$rc2"
assert_contains "aws_sso_login_all_profiles: non-TTY prints hint" "$out2" "interactive terminal"

# 3. No aws CLI on PATH → returns 1 before other guards
PATH="$empty_dir"
aws_sso_login_all_profiles </dev/null >/dev/null 2>&1
assert_false "aws_sso_login_all_profiles: no aws CLI returns 1" "$?"
PATH="$orig_path"

# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
