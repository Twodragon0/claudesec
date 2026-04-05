#!/usr/bin/env bash
# shellcheck disable=SC2034
# Unit tests for scanner/checks/infra/docker.sh
# Run: bash scanner/tests/test_check_infra_docker.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"
CHECKS_DIR="$SCRIPT_DIR/../checks"

TEST_PASSED=0
TEST_FAILED=0

# Stub color codes
NC="" GREEN="" RED="" YELLOW="" BLUE="" DIM="" BOLD="" MAGENTA="" CYAN=""

# Capture pass/fail/warn/skip calls instead of printing
RESULTS=()
pass()  { RESULTS+=("PASS:$1"); }
fail()  { RESULTS+=("FAIL:$1:$4"); }  # $4 = severity
warn()  { RESULTS+=("WARN:$1"); }
skip()  { RESULTS+=("SKIP:$1"); }

source "$LIB_DIR/checks.sh"

assert_result() {
  local desc="$1" expected_type="$2" check_id="$3"
  local found=false
  for r in "${RESULTS[@]}"; do
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

run_check() {
  RESULTS=()
  source "$CHECKS_DIR/infra/docker.sh"
}

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# ── INFRA-001: Non-root user ──

echo "=== INFRA-001: Dockerfile non-root user ==="

# Test: Dockerfile with USER nonroot -> PASS
mkdir -p "$tmpdir/test1"
cat > "$tmpdir/test1/Dockerfile" <<'DOCKER'
FROM alpine:3.20
RUN apk add --no-cache bash
USER nonroot
DOCKER
SCAN_DIR="$tmpdir/test1" run_check
assert_result "Dockerfile with USER nonroot passes" "PASS" "INFRA-001"

# Test: Dockerfile with USER root -> FAIL
mkdir -p "$tmpdir/test2"
cat > "$tmpdir/test2/Dockerfile" <<'DOCKER'
FROM alpine:3.20
USER root
DOCKER
SCAN_DIR="$tmpdir/test2" run_check
assert_result "Dockerfile with USER root fails" "FAIL" "INFRA-001"

# Test: Dockerfile missing USER directive -> FAIL
mkdir -p "$tmpdir/test3"
cat > "$tmpdir/test3/Dockerfile" <<'DOCKER'
FROM alpine:3.20
RUN echo hello
DOCKER
SCAN_DIR="$tmpdir/test3" run_check
assert_result "Dockerfile missing USER fails" "FAIL" "INFRA-001"

# Test: No Dockerfile -> SKIP
mkdir -p "$tmpdir/test4"
echo "hello" > "$tmpdir/test4/README.md"
SCAN_DIR="$tmpdir/test4" run_check
assert_result "No Dockerfile skips" "SKIP" "INFRA-001"

# ── INFRA-002: No :latest tag ──

echo "=== INFRA-002: Docker image pinning ==="

# Test: Pinned version -> PASS
SCAN_DIR="$tmpdir/test1" run_check
assert_result "Pinned FROM tag passes" "PASS" "INFRA-002"

# Test: :latest tag -> FAIL
mkdir -p "$tmpdir/test5"
cat > "$tmpdir/test5/Dockerfile" <<'DOCKER'
FROM node:latest
USER app
DOCKER
SCAN_DIR="$tmpdir/test5" run_check
assert_result "FROM :latest fails" "FAIL" "INFRA-002"

# ── INFRA-003: No secrets in Dockerfile ──

echo "=== INFRA-003: No secrets in Dockerfile ==="

# Test: Clean Dockerfile -> PASS
SCAN_DIR="$tmpdir/test1" run_check
assert_result "Clean Dockerfile passes secrets check" "PASS" "INFRA-003"

# Test: Dockerfile with hardcoded secret -> FAIL
mkdir -p "$tmpdir/test6"
cat > "$tmpdir/test6/Dockerfile" <<'DOCKER'
FROM alpine:3.20
ENV API_KEY=mysecretkey123
USER app
DOCKER
SCAN_DIR="$tmpdir/test6" run_check
assert_result "Dockerfile with ENV API_KEY fails" "FAIL" "INFRA-003"

# ── INFRA-004: Docker Compose privileged ──

echo "=== INFRA-004: Docker Compose privileged ==="

# Test: Compose without privileged -> PASS
mkdir -p "$tmpdir/test7"
cat > "$tmpdir/test7/Dockerfile" <<'DOCKER'
FROM alpine:3.20
USER app
DOCKER
cat > "$tmpdir/test7/docker-compose.yml" <<'YML'
services:
  app:
    build: .
    ports: ["8080:8080"]
YML
SCAN_DIR="$tmpdir/test7" run_check
assert_result "Compose without privileged passes" "PASS" "INFRA-004"

# Test: Compose with privileged: true -> FAIL
mkdir -p "$tmpdir/test8"
cp "$tmpdir/test7/Dockerfile" "$tmpdir/test8/"
cat > "$tmpdir/test8/docker-compose.yml" <<'YML'
services:
  app:
    build: .
    privileged: true
YML
SCAN_DIR="$tmpdir/test8" run_check
assert_result "Compose with privileged:true fails" "FAIL" "INFRA-004"

# ── INFRA-005: .dockerignore ──

echo "=== INFRA-005: .dockerignore ==="

# Test: Has .dockerignore -> PASS
mkdir -p "$tmpdir/test9"
cp "$tmpdir/test1/Dockerfile" "$tmpdir/test9/"
echo "node_modules" > "$tmpdir/test9/.dockerignore"
SCAN_DIR="$tmpdir/test9" run_check
assert_result ".dockerignore present passes" "PASS" "INFRA-005"

# Test: Missing .dockerignore -> WARN
SCAN_DIR="$tmpdir/test1" run_check
assert_result "Missing .dockerignore warns" "WARN" "INFRA-005"

# ── Summary ──

echo ""
echo "=== Results: $TEST_PASSED passed, $TEST_FAILED failed ==="
[[ "$TEST_FAILED" -eq 0 ]] || exit 1
