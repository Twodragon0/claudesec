#!/usr/bin/env bash
# Create recommended GitHub labels for this repository.
# Requires: gh (GitHub CLI) installed and authenticated.
# Run from repo root: ./scripts/github-setup-labels.sh

set -e

REPO="${GITHUB_REPOSITORY:-Twodragon0/claudesec}"

if ! command -v gh &>/dev/null; then
  echo "GitHub CLI (gh) is required. Install: https://cli.github.com/"
  exit 1
fi

echo "Creating labels for $REPO..."
gh label create "good first issue" --color "7057ff" --description "Good for newcomers" --repo "$REPO" 2>/dev/null || true
gh label create "help wanted" --color "008672" --description "Extra help welcome" --repo "$REPO" 2>/dev/null || true
echo "Done. Add these labels to issues via the GitHub UI."
