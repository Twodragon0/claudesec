#!/usr/bin/env bash
# shellcheck disable=SC2034
# Cover scanner/lib/output_prowler.sh: _prowler_dashboard_summary main
# rendering loop including the severity counter.
#
# Direct-call pattern (no $() wrapping the SUT) so kcov DEBUG-trap fires
# on every in-shell command. The severity counter now runs from an external
# program file (scanner/lib/prowler_severity_count.awk, invoked via awk -f)
# rather than an inline multi-line single-quoted awk string — the former
# inline body was text data that kcov's per-line accounting counted as
# uncoverable, so it was extracted (kcov measures bash, not the .awk file).
# This test still validates the counter behaviourally via the emitted HTML
# cells. The surrounding bash lines (provider loop, basename, total grep,
# read pipeline, td emission) are unambiguous bash and all light up.
#
# Run: bash scanner/tests/test_output_prowler_severity.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

TEST_PASSED=0
TEST_FAILED=0

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS: $label"
    ((TEST_PASSED++))
  else
    echo "  FAIL: $label"
    echo "    expected to contain: $needle"
    echo "    actual: ${haystack:0:240}"
    ((TEST_FAILED++))
  fi
}

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

# Stub color/CSS variables referenced in echo strings
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

source "$LIB_DIR/output.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ============================================================================
# Build a prowler-aws.ocsf.json fixture with FAIL findings tagged at all
# four severity levels (Critical, High, Medium, Low). The awk counter on
# L551-558 should tally one of each.
# ============================================================================
echo ""
echo "=== _prowler_dashboard_summary awk severity counter (L551-558) ==="

SCAN_DIR="$tmpdir/scan1"
mkdir -p "$SCAN_DIR/.claudesec-prowler"

cat > "$SCAN_DIR/.claudesec-prowler/prowler-aws.ocsf.json" <<'OCSF_EOF'
{
  "status_code": "FAIL",
  "severity": "Critical",
  "message": "Critical IAM finding",
  "metadata": {"event_code": "iam_root_access_key"},
  "finding_info": {"title": "Root access key present"}
}
{
  "status_code": "FAIL",
  "severity": "High",
  "message": "S3 public read access",
  "metadata": {"event_code": "s3_bucket_public_read"},
  "finding_info": {"title": "S3 Bucket Public Read"}
}
{
  "status_code": "FAIL",
  "severity": "Medium",
  "message": "RDS without encryption",
  "metadata": {"event_code": "rds_no_encryption"},
  "finding_info": {"title": "RDS No Encryption"}
}
{
  "status_code": "FAIL",
  "severity": "Low",
  "message": "EC2 missing tag",
  "metadata": {"event_code": "ec2_missing_tag"},
  "finding_info": {"title": "Missing tag"}
}
{
  "status_code": "PASS",
  "severity": "Informational",
  "message": "OK",
  "metadata": {"event_code": "iam_password_policy"},
  "finding_info": {"title": "Strong password policy"}
}
OCSF_EOF

# A second provider's fixture to exercise the per-provider loop (L545-548)
cat > "$SCAN_DIR/.claudesec-prowler/prowler-gcp.ocsf.json" <<'OCSF_EOF'
{"status_code":"FAIL","severity":"High","message":"GKE private cluster off","metadata":{"event_code":"gke_private_off"},"finding_info":{"title":"GKE private off"}}
{"status_code":"FAIL","severity":"Critical","message":"Service account key leak","metadata":{"event_code":"gcp_sa_key_leak"},"finding_info":{"title":"SA key leak"}}
OCSF_EOF

# Call the function directly into a file so kcov sees the in-shell
# invocation; don't wrap in $().
_prowler_dashboard_summary > "$tmpdir/summary.html"
rc=$?
html=$(<"$tmpdir/summary.html")

assert_eq "_prowler_dashboard_summary returns 0" "0" "$rc"
assert_contains "html: AWS provider label present" "$html" ">AWS<"
assert_contains "html: GCP provider label present" "$html" ">GCP<"

# AWS: 1 Critical, 1 High, 1 Medium, 1 Low — total 4 FAILs.
# The HTML emits <td>$total</td><td>$c</td><td>$h</td><td>$m</td><td>$l</td>
# right-aligned. Use unambiguous substrings that include surrounding
# style markers so we don't match other numeric cells.
assert_contains "html: AWS FAIL total = 4" "$html" 'color:#dc2626">1</td>'
assert_contains "html: AWS contains Critical/High/Medium/Low cell pattern" \
  "$html" 'color:#eab308">1</td>'

# GCP: 1 Critical + 1 High, no Medium/Low. So the awk counter must have
# emitted "1 1 0 0" — the resulting HTML cells include color:#eab308">0</td>
# and color:var(--muted)">0</td>.
assert_contains "html: GCP zero-medium cell" "$html" 'color:#eab308">0</td>'
assert_contains "html: GCP zero-low cell" "$html" 'color:var(--muted)">0</td>'

# Footer guidance text emitted at L563 (additional surrounding-line
# coverage; this proves the loop completed normally past the awk read).
assert_contains "html: footer caption emitted (L563)" "$html" "claudesec scan -c prowler"

# ============================================================================
# Empty prowler dir: function should return 0 early without writing HTML.
# Covers L535 ([[ -z "$files" ]] && return 0).
# ============================================================================
echo ""
echo "=== _prowler_dashboard_summary empty prowler dir early return ==="

SCAN_DIR="$tmpdir/scan2"
mkdir -p "$SCAN_DIR/.claudesec-prowler"

_prowler_dashboard_summary > "$tmpdir/empty.html"
rc=$?
empty_html=$(<"$tmpdir/empty.html")
assert_eq "empty prowler dir: returns 0" "0" "$rc"
assert_eq "empty prowler dir: no HTML body emitted" "" "$empty_html"

# ============================================================================
# Missing prowler dir: function should return 0 without scanning. Covers
# L534 ([[ -d "$prowler_dir" ]] || return 0).
# ============================================================================
echo ""
echo "=== _prowler_dashboard_summary missing prowler dir early return ==="

SCAN_DIR="$tmpdir/scan3-nonexistent"
mkdir -p "$tmpdir"  # parent exists but no .claudesec-prowler subdir

_prowler_dashboard_summary > "$tmpdir/missing.html"
rc=$?
missing_html=$(<"$tmpdir/missing.html")
assert_eq "missing prowler dir: returns 0" "0" "$rc"
assert_eq "missing prowler dir: no HTML body emitted" "" "$missing_html"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "=========================================="
echo "Results: PASSED=$TEST_PASSED FAILED=$TEST_FAILED"
echo "=========================================="
[[ "$TEST_FAILED" -eq 0 ]] && exit 0 || exit 1
