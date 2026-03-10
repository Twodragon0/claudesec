#!/bin/bash
# ClaudeSec Setup Script
# Installs security hooks and templates into your project

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CLAUDESEC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${1:-.}"

echo "ClaudeSec Setup"
echo "==============="
echo "Source: $CLAUDESEC_DIR"
echo "Target: $(cd "$TARGET_DIR" && pwd)"
echo ""

# Create directories
mkdir -p "$TARGET_DIR/.github/workflows"
mkdir -p "$TARGET_DIR/.claude/hooks"

# Copy hooks
echo -e "${GREEN}[+]${NC} Installing Claude Code hooks..."
cp "$CLAUDESEC_DIR/hooks/security-lint.sh" "$TARGET_DIR/.claude/hooks/"
cp "$CLAUDESEC_DIR/hooks/secret-check.sh" "$TARGET_DIR/.claude/hooks/"
chmod +x "$TARGET_DIR/.claude/hooks/"*.sh

# Copy workflow templates
echo -e "${GREEN}[+]${NC} Installing GitHub Actions workflows..."
cp "$CLAUDESEC_DIR/templates/codeql.yml" "$TARGET_DIR/.github/workflows/"
cp "$CLAUDESEC_DIR/templates/dependency-review.yml" "$TARGET_DIR/.github/workflows/"

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

echo ""
echo "Setup complete! Next steps:"
echo "  1. Review and customize the installed files"
echo "  2. Update SECURITY.md with your contact info"
echo "  3. Update dependabot.yml with your team reviewers"
echo "  4. Commit the changes"
