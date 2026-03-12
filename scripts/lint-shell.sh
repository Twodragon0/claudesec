#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SHELLCHECK_VERSION="v0.10.0"

cd "$ROOT_DIR"

files=(
  run
  scripts/*.sh
)

args=(-x)
for file in "${files[@]}"; do
  [[ -e "$file" ]] || continue
  args+=("$file")
done

echo "[claudesec] Shell lint targets: scripts/*.sh and run"

if [[ "${#args[@]}" -le 1 ]]; then
  echo "No shell files found to lint."
  exit 0
fi

if command -v shellcheck >/dev/null 2>&1; then
  echo "[claudesec] Running local shellcheck binary"
  shellcheck "${args[@]}"
  exit 0
fi

if command -v docker >/dev/null 2>&1; then
  echo "[claudesec] shellcheck not found; using pinned Docker image koalaman/shellcheck-alpine:${SHELLCHECK_VERSION}"
  docker run --rm -v "$ROOT_DIR:/mnt" -w /mnt "koalaman/shellcheck-alpine:${SHELLCHECK_VERSION}" shellcheck "${args[@]}"
  exit 0
fi

echo "shellcheck is not installed and Docker is unavailable." >&2
echo "Install shellcheck locally or install Docker, then rerun scripts/lint-shell.sh" >&2
exit 1
