#!/usr/bin/env bash
# ClaudeSec CLI — npx claudesec <command>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

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
  version)
    echo "claudesec v0.5.0"
    ;;
  help|--help|-h|*)
    echo "ClaudeSec — DevSecOps Scanner & Dashboard"
    echo ""
    echo "Usage:"
    echo "  claudesec scan [options]      Run security scan"
    echo "  claudesec dashboard           Build + serve dashboard (Docker)"
    echo "  claudesec setup [target]      Install hooks/workflows"
    echo "  claudesec init                Initialize .claudesec.yml"
    echo "  claudesec version             Show version"
    echo ""
    echo "Quick start:"
    echo "  npx claudesec scan            Scan current directory"
    echo "  npx claudesec dashboard       Full scan + dashboard"
    ;;
esac
