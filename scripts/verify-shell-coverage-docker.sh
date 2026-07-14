#!/usr/bin/env bash
# ============================================================================
# verify-shell-coverage-docker.sh — local mirror of the CI scanner-shell-coverage
# job, run inside an ubuntu+kcov container.
# ============================================================================
# kcov is a Linux/ptrace tool and does not work on macOS, so this reproduces the
# CI bash-coverage gate locally via Docker. Use it to pre-verify the 90% floor
# before pushing a scanner/lib/*.sh change (e.g. splitting output.sh / checks.sh).
#
# Usage:
#   ./scripts/verify-shell-coverage-docker.sh            # build image if needed, run
#   ./scripts/verify-shell-coverage-docker.sh --rebuild  # force image rebuild
#
# Mirrors lint.yml: --include-pattern=checks.sh,checks_credentials.sh,output.sh,output_prowler.sh
# --exclude-pattern=api-checks.sh,api_checks.sh,test_run_category_checks.sh, direct-script invocation (never
# `bash script.sh`, which would instrument the bash binary and report 0 lines),
# CLAUDESEC_DASHBOARD_OFFLINE=1, and a 90.0% floor.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="claudesec-kcov"
DOCKERFILE="scripts/docker/shell-coverage.Dockerfile"
FLOOR="90.0"
INCLUDE="checks.sh,checks_credentials.sh,kubectl.sh,output.sh,output_prowler.sh"
EXCLUDE="api-checks.sh,api_checks.sh,test_run_category_checks.sh"

cd "$REPO_ROOT"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

if [[ "${1:-}" == "--rebuild" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "==> Building $IMAGE (kcov v42 compile is cached after the first build)…"
  docker build -f "$DOCKERFILE" -t "$IMAGE" .
fi

echo "==> Running scanner shell tests under kcov in container…"
# Mount the repo read-only; all writes (kcov-out, test tmpdirs) go to container /tmp.
docker run --rm -v "$REPO_ROOT":/repo:ro -w /repo \
  -e CLAUDESEC_DASHBOARD_OFFLINE=1 -e FLOOR="$FLOOR" \
  -e INCLUDE="$INCLUDE" -e EXCLUDE="$EXCLUDE" \
  "$IMAGE" bash -euo pipefail -c '
    out=/tmp/kcov-out; mkdir -p "$out"
    for sh in scanner/tests/test_*.sh; do
      name=$(basename "$sh" .sh); rc=0
      # Direct-script invocation (NOT `bash "$sh"`), matching CI, so kcov measures
      # the script bash lines rather than the bash binary. _tty tests need a pty.
      if [[ "$name" == *_tty ]]; then
        timeout 60 python3 scanner/tests/pty_run.py \
          kcov --include-pattern="$INCLUDE" --exclude-pattern="$EXCLUDE" "$out/$name" "$sh" \
          >/dev/null 2>&1 || rc=$?
      else
        timeout 60 kcov --include-pattern="$INCLUDE" --exclude-pattern="$EXCLUDE" "$out/$name" "$sh" \
          >/dev/null 2>&1 || rc=$?
      fi
      [ "$rc" -ne 0 ] && echo "  (rc=$rc $name)"
    done
    kcov --merge "$out/merged" "$out"/*/ >/dev/null 2>&1
    cov=$(find "$out/merged" -name coverage.json -print -quit 2>/dev/null || true)
    [ -z "$cov" ] && cov=$(find "$out" -name coverage.json -print -quit 2>/dev/null || true)
    if [ -z "$cov" ]; then echo "ERROR: no coverage.json produced" >&2; exit 1; fi
    python3 scripts/docker/kcov_report.py "$cov" "$FLOOR"
  '
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "==> PASS: bash coverage floor ($FLOOR%) satisfied."
else
  echo "==> FAIL: bash coverage below floor ($FLOOR%)." >&2
fi
exit "$rc"
