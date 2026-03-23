#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/cicd/pipeline.sh
# Run: bash scanner/tests/test_check_cicd_pipeline.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:${4:-}"); }
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }
info()  { :; }

source "$LIB_DIR/checks.sh"

assert_has_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    if [[ "$r" == "${expected_type}:${check_id}"* ]]; then
      found=true; break
    fi
  done
  if $found; then
    echo "  PASS: $desc"; ((TEST_PASSED++))
  else
    echo "  FAIL: $desc (expected $expected_type:$check_id, got: ${RESULTS[*]:-none})"; ((TEST_FAILED++))
  fi
}

run_check() {
  RESULTS=()
  source "$CHECKS_DIR/cicd/pipeline.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── No .github/workflows -> all skip ──

echo "=== CICD: No workflows ==="

mkdir -p "$tmpdir/empty"
echo "hi" > "$tmpdir/empty/README.md"
SCAN_DIR="$tmpdir/empty" run_check
assert_has_result "No workflows skips CICD-001" "SKIP" "CICD-001"
assert_has_result "No workflows skips CICD-002" "SKIP" "CICD-002"

# ── CICD-001: Permissions ──

echo "=== CICD-001: Permissions ==="

# Test: Workflow with permissions -> PASS
mkdir -p "$tmpdir/perm_ok/.github/workflows"
cat > "$tmpdir/perm_ok/.github/workflows/ci.yml" <<'YML'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
YML
SCAN_DIR="$tmpdir/perm_ok" run_check
assert_has_result "Workflow with permissions passes" "PASS" "CICD-001"

# Test: Workflow without permissions -> FAIL
mkdir -p "$tmpdir/perm_no/.github/workflows"
cat > "$tmpdir/perm_no/.github/workflows/ci.yml" <<'YML'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
YML
SCAN_DIR="$tmpdir/perm_no" run_check
assert_has_result "Workflow without permissions fails" "FAIL" "CICD-001"

# ── CICD-002: Actions pinned to SHA ──

echo "=== CICD-002: Actions SHA pinning ==="

# Test: SHA-pinned actions -> PASS
SCAN_DIR="$tmpdir/perm_ok" run_check
assert_has_result "SHA-pinned actions passes" "PASS" "CICD-002"

# Test: Version-tag-pinned -> WARN
SCAN_DIR="$tmpdir/perm_no" run_check
assert_has_result "Version-tag-pinned warns" "WARN" "CICD-002"

# ── CICD-003: No secrets in logs ──

echo "=== CICD-003: Secret logging ==="

# Test: Workflow echoing secrets -> FAIL
mkdir -p "$tmpdir/leak_secret/.github/workflows"
cat > "$tmpdir/leak_secret/.github/workflows/ci.yml" <<'YML'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - run: echo ${{ secrets.MY_TOKEN }}
YML
SCAN_DIR="$tmpdir/leak_secret" run_check
assert_has_result "Secret in echo detected" "FAIL" "CICD-003"

# Test: Clean workflow -> PASS
SCAN_DIR="$tmpdir/perm_ok" run_check
assert_has_result "No secret logging passes" "PASS" "CICD-003"

# ── CICD-005: Security scanning ──

echo "=== CICD-005: Security scanning ==="

# Test: Workflow with codeql -> PASS
mkdir -p "$tmpdir/with_sast/.github/workflows"
cat > "$tmpdir/with_sast/.github/workflows/security.yml" <<'YML'
name: Security
on: push
permissions:
  contents: read
  security-events: write
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/init@de0fac2e4500dabe0009e67214ff5f5447ce83dd
YML
SCAN_DIR="$tmpdir/with_sast" run_check
assert_has_result "CodeQL in CI passes" "PASS" "CICD-005"

# ── CICD-007: Lockfile ──

echo "=== CICD-007: Lockfile ==="

# Test: Has package-lock.json -> PASS
mkdir -p "$tmpdir/with_lock"
echo '{}' > "$tmpdir/with_lock/package.json"
echo '{}' > "$tmpdir/with_lock/package-lock.json"
SCAN_DIR="$tmpdir/with_lock" run_check
assert_has_result "Lockfile present passes" "PASS" "CICD-007"

# Test: package.json without lockfile -> FAIL
mkdir -p "$tmpdir/no_lock"
echo '{}' > "$tmpdir/no_lock/package.json"
SCAN_DIR="$tmpdir/no_lock" run_check
assert_has_result "Missing lockfile fails" "FAIL" "CICD-007"

# ── Summary ──

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
