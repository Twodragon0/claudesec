#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MCP_DIR="${CLAUDESEC_GITHUB_REPO_MCP_DIR:-$ROOT_DIR/.claudesec-sources/github-repo-mcp}"
LOCAL_DIST="$MCP_DIR/dist/index.js"

if command -v node >/dev/null 2>&1 && [[ -f "$LOCAL_DIST" ]]; then
  exec node "$LOCAL_DIST" "$@"
fi

if command -v npx >/dev/null 2>&1; then
  exec npx -y github-repo-mcp "$@"
fi

cat >&2 <<EOF
GitHub Repo MCP is not ready.

Expected local build:
  $LOCAL_DIST

Recovery:
  1. Run ./scripts/setup-legal-intel.sh
  2. Or install Node.js with npx support
EOF
exit 1
