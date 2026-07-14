#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/lib/output.sh: save_scan_history prowler OCSF
# compliance summary. The OCSF detection loop + embedded python3 parser +
# compliance-map invocation now live in _prowler_compliance_summary_json
# (scanner/lib/output_prowler.sh); save_scan_history calls it and assigns
# comp_field when the returned compliance_json is non-empty. Exercised here
# end-to-end through save_scan_history.
#
# Run: bash scanner/tests/test_save_scan_history_ocsf.sh
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
    echo "    actual: ${haystack:0:200}"
    ((TEST_FAILED++))
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected NOT to contain: $needle"
    ((TEST_FAILED++))
  fi
}

# Stub color codes (output.sh references them)
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/output.sh"

# _reset_state mirrors the helper used in test_output_functions.sh so that
# save_scan_history sees a known per-test starting point.
_reset_state() {
  TOTAL_CHECKS=0; PASSED=0; FAILED=0; WARNINGS=0; SKIPPED=0
  FINDINGS_CRITICAL=(); FINDINGS_HIGH=(); FINDINGS_MEDIUM=()
  FINDINGS_LOW=(); FINDINGS_WARN=()
  JSON_RESULTS="[]"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

OLD_SCAN_DIR="${SCAN_DIR:-}"

# `save_scan_history`'s OCSF python block is gated on `timeout 10 python3 ...`.
# `timeout` is GNU coreutils — present on the Linux runners that execute the
# scanner-shell-coverage job, but absent on macOS by default. Skip the
# compliance-key assertions when `timeout` is missing so the test still
# passes on developer macOS while exercising the surrounding loop/guard
# branches that we care about for kcov coverage. CI still verifies the
# full path.
HAS_TIMEOUT=0
if command -v timeout >/dev/null 2>&1; then
  HAS_TIMEOUT=1
fi

# ============================================================================
# Scenario 1: prowler dir present with a FAIL finding -> compliance section
# emitted into scan-*.json history entry.
# ============================================================================
echo ""
echo "=== Scenario 1: prowler-*.ocsf.json with FAIL findings ==="

SCAN_DIR="$tmpdir/s1"
mkdir -p "$SCAN_DIR/.claudesec-prowler" "$SCAN_DIR/.claudesec-history"

# Minimal valid OCSF fixture: one FAIL, one PASS. The FAIL maps to a
# 'security_policy' check via compliance-map.py's CHECK_TO_FRAMEWORKS, which
# is present in the ISO 27001:2022 A.5.1 entry seen at compliance-map.py:9.
cat > "$SCAN_DIR/.claudesec-prowler/prowler-aws.ocsf.json" <<'EOF'
[
  {
    "status_code": "FAIL",
    "message": "S3 bucket public read access detected",
    "metadata": {"event_code": "s3_bucket_public_access"},
    "finding_info": {"title": "S3 Bucket Public Access"},
    "unmapped": {"compliance": {"iso27001_2022": ["A.5.1"]}}
  },
  {
    "status_code": "PASS",
    "message": "MFA enabled for root account",
    "metadata": {"event_code": "iam_root_mfa_enabled"},
    "finding_info": {"title": "Root Account MFA"},
    "unmapped": {"compliance": {"iso27001_2022": ["A.8.2"]}}
  }
]
EOF

_reset_state
TOTAL_CHECKS=10; PASSED=8; FAILED=2; WARNINGS=0; SKIPPED=0
save_scan_history

# Verify the history file was written
hist_files=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | wc -l | tr -d ' ')
assert_eq "scenario 1: history file created" "1" "$hist_files"

# The python block should have produced a non-empty compliance dict and
# emitted comp_field into the JSON record (CI-only assertion).
hist_path=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | head -1)
hist_content=$(cat "$hist_path")
if [[ "$HAS_TIMEOUT" -eq 1 ]]; then
  assert_contains "scenario 1: compliance key emitted (L443-445)" "$hist_content" '"compliance":'
  # It should reference one of compliance-map.py's frameworks. The exact key
  # depends on what map_compliance returns from a security_policy-tagged
  # finding — ISO 27001:2022 is the most common output.
  assert_contains "scenario 1: ISO framework reference present" "$hist_content" "ISO"
else
  echo "  SKIP: scenario 1: compliance emission (no \`timeout\` binary on this host)"
fi

# ============================================================================
# Scenario 2: prowler dir present, ONLY PASS findings -> python exits early
# (L435 `if not findings: exit(0)`), compliance_json stays empty, comp_field
# is NOT emitted (L444 guard).
# ============================================================================
echo ""
echo "=== Scenario 2: prowler-*.ocsf.json with only PASS findings ==="

SCAN_DIR="$tmpdir/s2"
mkdir -p "$SCAN_DIR/.claudesec-prowler" "$SCAN_DIR/.claudesec-history"

cat > "$SCAN_DIR/.claudesec-prowler/prowler-pass-only.ocsf.json" <<'EOF'
[
  {
    "status_code": "PASS",
    "message": "OK",
    "metadata": {"event_code": "everything_fine"},
    "finding_info": {"title": "All good"},
    "unmapped": {"compliance": {}}
  }
]
EOF

_reset_state
TOTAL_CHECKS=5; PASSED=5; FAILED=0; WARNINGS=0; SKIPPED=0
save_scan_history

hist_path=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | head -1)
hist_content=$(cat "$hist_path")
assert_eq "scenario 2: history file created" "1" \
  "$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | wc -l | tr -d ' ')"
assert_not_contains "scenario 2: no compliance key (early exit path)" "$hist_content" '"compliance":'

# ============================================================================
# Scenario 3: prowler dir present but file is NDJSON (line-delimited JSON
# objects, not a JSON array). Exercises L427 second branch
# `[json.loads(l) for l in raw.splitlines() if l.strip()]`.
# ============================================================================
echo ""
echo "=== Scenario 3: NDJSON ocsf file (line-delimited objects) ==="

SCAN_DIR="$tmpdir/s3"
mkdir -p "$SCAN_DIR/.claudesec-prowler" "$SCAN_DIR/.claudesec-history"

cat > "$SCAN_DIR/.claudesec-prowler/prowler-ndjson.ocsf.json" <<'EOF'
{"status_code":"FAIL","message":"IAM weak policy","metadata":{"event_code":"iam_weak_pwd"},"finding_info":{"title":"Weak IAM policy"},"unmapped":{"compliance":{"iso27001_2022":["A.8.5"]}}}
{"status_code":"FAIL","message":"Encryption disabled","metadata":{"event_code":"rds_encryption_off"},"finding_info":{"title":"RDS Encryption"},"unmapped":{"compliance":{"iso27001_2022":["A.8.5"]}}}
EOF

_reset_state
TOTAL_CHECKS=8; PASSED=6; FAILED=2; WARNINGS=0; SKIPPED=0
save_scan_history

hist_path=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | head -1)
hist_content=$(cat "$hist_path")
if [[ "$HAS_TIMEOUT" -eq 1 ]]; then
  assert_contains "scenario 3: compliance emitted from NDJSON parse path" "$hist_content" '"compliance":'
else
  echo "  SKIP: scenario 3: NDJSON compliance emission (no \`timeout\` binary)"
fi

# ============================================================================
# Scenario 4: prowler dir present, ocsf file is malformed (broken JSON).
# Exercises L434 `except Exception: pass` swallow — python block should not
# fail the whole save_scan_history call. compliance_json stays empty.
# ============================================================================
echo ""
echo "=== Scenario 4: malformed OCSF JSON tolerated ==="

SCAN_DIR="$tmpdir/s4"
mkdir -p "$SCAN_DIR/.claudesec-prowler" "$SCAN_DIR/.claudesec-history"
printf 'not-json{{{\n' > "$SCAN_DIR/.claudesec-prowler/prowler-bad.ocsf.json"

_reset_state
TOTAL_CHECKS=3; PASSED=3; FAILED=0; WARNINGS=0; SKIPPED=0
save_scan_history

hist_path=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | head -1)
assert_eq "scenario 4: history still written despite malformed ocsf" "1" \
  "$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | wc -l | tr -d ' ')"
hist_content=$(cat "$hist_path")
assert_not_contains "scenario 4: no compliance key on parse failure" "$hist_content" '"compliance":'

# ============================================================================
# Scenario 5: prowler dir does NOT exist — _has_ocsf stays 0, python block
# is skipped entirely (L412 guard). Already covered by existing
# test_output_functions.sh Group 13, but re-asserting here ensures the
# L412-417 branch transitions are also covered when this file is run in
# isolation.
# ============================================================================
echo ""
echo "=== Scenario 5: no prowler dir → no compliance key ==="

SCAN_DIR="$tmpdir/s5"
mkdir -p "$SCAN_DIR/.claudesec-history"  # no .claudesec-prowler subdir

_reset_state
TOTAL_CHECKS=2; PASSED=2; FAILED=0; WARNINGS=0; SKIPPED=0
save_scan_history

hist_path=$(find "$SCAN_DIR/.claudesec-history" -name 'scan-*.json' | head -1)
hist_content=$(cat "$hist_path")
assert_not_contains "scenario 5: no compliance key when prowler dir missing" "$hist_content" '"compliance":'

SCAN_DIR="$OLD_SCAN_DIR"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "Results: PASSED=$TEST_PASSED FAILED=$TEST_FAILED"
echo "=========================================="
[[ "$TEST_FAILED" -eq 0 ]] && exit 0 || exit 1
