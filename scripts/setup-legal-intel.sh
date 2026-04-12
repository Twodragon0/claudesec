#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$ROOT_DIR"
SOURCES_DIR="${CLAUDESEC_SOURCES_DIR:-$ROOT_DIR/.claudesec-sources}"
LEGALIZE_REPO="${CLAUDESEC_LEGALIZE_REPO:-https://github.com/legalize-kr/legalize-kr.git}"
MCP_REPO="${CLAUDESEC_GITHUB_REPO_MCP_REPO:-https://github.com/Ryan0204/github-repo-mcp.git}"
LEGALIZE_DIR="$SOURCES_DIR/legalize-kr"
MCP_DIR="$SOURCES_DIR/github-repo-mcp"
WRITE_MCP=1
SYNC_REMOTE=1
BUILD_MCP=1

usage() {
  cat <<'EOF'
Usage:
  ./scripts/setup-legal-intel.sh [options]

Options:
  --target <dir>       Target project for .mcp.json generation (default: repo root)
  --sources <dir>      Directory for local mirrors (default: ./.claudesec-sources)
  --write-config-only  Only write .mcp.json using existing local assets
  --skip-build         Skip npm ci / npm run build for github-repo-mcp
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_DIR="$2"
      shift 2
      ;;
    --sources)
      SOURCES_DIR="$2"
      LEGALIZE_DIR="$SOURCES_DIR/legalize-kr"
      MCP_DIR="$SOURCES_DIR/github-repo-mcp"
      shift 2
      ;;
    --write-config-only)
      SYNC_REMOTE=0
      BUILD_MCP=0
      shift
      ;;
    --skip-build)
      BUILD_MCP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

mkdir -p "$SOURCES_DIR"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

sync_repo() {
  local repo_url="$1"
  local repo_dir="$2"

  if [[ -d "$repo_dir/.git" ]]; then
    echo "[claudesec] Updating $(basename "$repo_dir")..."
    git -C "$repo_dir" pull --ff-only
    return
  fi

  echo "[claudesec] Cloning $(basename "$repo_dir")..."
  git clone "$repo_url" "$repo_dir"
}

if [[ "$SYNC_REMOTE" == "1" ]]; then
  sync_repo "$LEGALIZE_REPO" "$LEGALIZE_DIR"
  sync_repo "$MCP_REPO" "$MCP_DIR"
fi

if [[ "$BUILD_MCP" == "1" && -f "$MCP_DIR/package.json" ]]; then
  if command -v npm >/dev/null 2>&1; then
    echo "[claudesec] Building github-repo-mcp..."
    npm ci --prefix "$MCP_DIR"
    npm run build --prefix "$MCP_DIR"
  else
    echo "[claudesec] npm not found; skipping github-repo-mcp build" >&2
  fi
fi

if [[ "$WRITE_MCP" == "1" ]]; then
  python3 - "$TARGET_DIR" "$ROOT_DIR" "$LEGALIZE_DIR" <<'PY'
import json
import sys
from pathlib import Path

target_dir = Path(sys.argv[1])
root_dir = Path(sys.argv[2])
legalize_dir = Path(sys.argv[3])
mcp_path = target_dir / ".mcp.json"
wrapper_path = root_dir / "scripts" / "run-github-repo-mcp.sh"

payload = {
    "mcpServers": {
        "github-repo-mcp": {
            "command": str(wrapper_path),
            "args": [],
            "cwd": str(root_dir),
            "enabled": True,
        }
    },
    "claudesec": {
        "legalizeKrDir": str(legalize_dir),
        "notes": [
            "Set GITHUB_TOKEN in your MCP client environment for higher GitHub API rate limits.",
            "Use scripts/legalize-search.sh for local grep and history lookup over legalize-kr.",
        ],
    },
}

mcp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(mcp_path)
PY
fi

cat <<EOF
[claudesec] Legal intelligence setup complete.
  legalize-kr mirror: $LEGALIZE_DIR
  github-repo-mcp:    $MCP_DIR
  mcp config:         $TARGET_DIR/.mcp.json

Examples:
  ./scripts/legalize-search.sh "개인정보" 개인정보보호법
  ./scripts/legalize-search.sh --history 개인정보보호법 법률.md
EOF
