#!/bin/bash
# ============================================================================
# ClaudeSec Setup — Install hooks, templates, and optional scanner config
# ============================================================================
# Usage:
#   ./scripts/setup.sh                    # setup current dir (repo root)
#   ./scripts/setup.sh /path/to/project   # setup another project
#   ./scripts/setup.sh --scan-only        # only scanner readiness (config + deps)
# ============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CLAUDESEC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${1:-.}"

if [[ "$TARGET_DIR" == "--scan-only" ]]; then
  TARGET_DIR="."
  SCAN_ONLY=1
else
  SCAN_ONLY=0
fi

# ── Scanner readiness (dashboard + scan) ────────────────────────────────────
# Python3 required for HTML dashboard; optional .claudesec.yml from template
scan_readiness() {
  local dir="${1:-.}"
  echo -e "${CYAN}[*]${NC} Scanner readiness (scan + dashboard)..."
  if command -v python3 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} python3 found (dashboard will be generated)"
  else
    echo -e "  ${YELLOW}!${NC} python3 not found — install for HTML dashboard (scan still works)"
  fi
  if [[ ! -f "$dir/.claudesec.yml" ]]; then
    if [[ -f "$CLAUDESEC_DIR/templates/claudesec.example.yml" ]]; then
      cp "$CLAUDESEC_DIR/templates/claudesec.example.yml" "$dir/.claudesec.yml"
      echo -e "  ${GREEN}+${NC} Created .claudesec.yml from template (edit as needed)"
    else
      echo -e "  ${YELLOW}~${NC} No .claudesec.yml (optional; copy from templates/*.example.yml)"
    fi
  else
    echo -e "  ${GREEN}✓${NC} .claudesec.yml exists"
  fi
}

if [[ "$SCAN_ONLY" == "1" ]]; then
  scan_readiness "$(cd "$TARGET_DIR" && pwd)"
  echo ""
  echo "Run full scan + dashboard: ./run   or   ./scripts/run-full-dashboard.sh"
  exit 0
fi

# ── Full setup ─────────────────────────────────────────────────────────────
echo "ClaudeSec Setup"
echo "==============="
echo "Source: $CLAUDESEC_DIR"
echo "Target: $(cd "$TARGET_DIR" 2>/dev/null && pwd || echo "$TARGET_DIR")"
echo ""

# Create directories
mkdir -p "$TARGET_DIR/.github/workflows"
mkdir -p "$TARGET_DIR/.github/actions/datadog-ci-collect"
mkdir -p "$TARGET_DIR/.github/actions/token-expiry-gate"
mkdir -p "$TARGET_DIR/.claude/hooks"
mkdir -p "$TARGET_DIR/scripts"

# Copy hooks
echo -e "${GREEN}[+]${NC} Installing Claude Code hooks..."
cp "$CLAUDESEC_DIR/hooks/security-lint.sh" "$TARGET_DIR/.claude/hooks/"
cp "$CLAUDESEC_DIR/hooks/secret-check.sh" "$TARGET_DIR/.claude/hooks/"
chmod +x "$TARGET_DIR/.claude/hooks/"*.sh

# Copy workflow templates
echo -e "${GREEN}[+]${NC} Installing GitHub Actions workflows..."
cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"
cp "$CLAUDESEC_DIR/templates/dependency-review.yml" "$TARGET_DIR/.github/workflows/"
cp "$CLAUDESEC_DIR/.github/actions/datadog-ci-collect/action.yml" "$TARGET_DIR/.github/actions/datadog-ci-collect/"
cp "$CLAUDESEC_DIR/.github/actions/token-expiry-gate/action.yml" "$TARGET_DIR/.github/actions/token-expiry-gate/"
cp "$CLAUDESEC_DIR/scripts/token-expiry-gate.py" "$TARGET_DIR/scripts/"

# Copy dependabot config
if [ ! -f "$TARGET_DIR/.github/dependabot.yml" ]; then
  cp "$CLAUDESEC_DIR/templates/dependabot.yml" "$TARGET_DIR/.github/"
  echo -e "${GREEN}[+]${NC} Installed dependabot.yml"
else
  echo -e "${YELLOW}[~]${NC} dependabot.yml already exists, skipping"
fi

# Copy SECURITY.md
if [ ! -f "$TARGET_DIR/SECURITY.md" ] && [ ! -f "$TARGET_DIR/.github/SECURITY.md" ]; then
  cp "$CLAUDESEC_DIR/templates/SECURITY.md" "$TARGET_DIR/.github/"
  echo -e "${GREEN}[+]${NC} Installed SECURITY.md"
else
  echo -e "${YELLOW}[~]${NC} SECURITY.md already exists, skipping"
fi

# Scanner readiness (optional config + deps hint)
scan_readiness "$TARGET_DIR"

echo ""
echo "Setup complete! Next steps:"
echo "  1. Run scan + dashboard:  ./run   (or from repo root: ./scripts/run-full-dashboard.sh)"
echo "  2. Review and customize the installed files"
echo "  3. Update SECURITY.md with your contact info"
echo "  4. Commit the changes"
