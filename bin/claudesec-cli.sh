#!/usr/bin/env bash
# ClaudeSec CLI — npx claudesec <command>
set -euo pipefail

# Resolve symlinks (npx creates .bin/claudesec -> ../claudesec/bin/claudesec-cli.sh)
SOURCE="$0"
while [ -L "$SOURCE" ]; do
  DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd "$(dirname "$SOURCE")/.." && pwd)"

case "${1:-help}" in
  scan)
    shift
    exec "$SCRIPT_DIR/scanner/claudesec" scan "$@"
    ;;
  dashboard)
    shift
    exec "$SCRIPT_DIR/scripts/quick-start.sh" "$@"
    ;;
  setup)
    shift
    exec "$SCRIPT_DIR/scripts/setup.sh" "$@"
    ;;
  init)
    exec "$SCRIPT_DIR/scanner/claudesec" init
    ;;
  quickstart)
    echo "ClaudeSec Quick Start — scan + dashboard at localhost:11777"
    docker compose -f "$SCRIPT_DIR/docker-compose.quickstart.yml" up --build
    ;;
  version)
    grep '"version"' "$SCRIPT_DIR/package.json" | head -1 | sed 's/.*"\([0-9][^"]*\)".*/claudesec v\1/'
    ;;
  help|--help|-h|*)
    echo "ClaudeSec — DevSecOps Scanner & ISMS Dashboard"
    echo ""
    echo "Usage:"
    echo "  claudesec scan [options]      Run security scan"
    echo "  claudesec dashboard           Build + serve dashboard (Docker)"
    echo "  claudesec setup [target]      Install hooks/workflows to a project"
    echo "  claudesec init                Initialize .claudesec.yml config"
    echo "  claudesec quickstart          Docker scan + dashboard (one command)"
    echo "  claudesec version             Show version"
    echo ""
    echo "Quick start:"
    echo "  npx claudesec scan            Scan current directory"
    echo "  npx claudesec dashboard       Full scan + dashboard"
    echo "  npx claudesec quickstart      Docker: scan + dashboard at localhost:11777"
    ;;
esac
