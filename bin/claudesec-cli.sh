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
  prowler)
    # Thin alias for the Prowler multi-cloud scan category.
    shift
    exec "$SCRIPT_DIR/scanner/claudesec" scan -c prowler "$@"
    ;;
  compliance)
    # Compliance gap scan: map findings to a framework (default isms-p).
    # `claudesec compliance [framework] [scan-options...]`
    shift
    if [[ $# -gt 0 && "$1" != -* ]]; then
      framework="$1"
      shift
    else
      framework="isms-p"
    fi
    exec "$SCRIPT_DIR/scanner/claudesec" scan --compliance "$framework" "$@"
    ;;
  dashboard)
    shift
    exec "$SCRIPT_DIR/scripts/run-dashboard-safe.sh" "$@"
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
  isms-report)
    shift
    exec python3 "$SCRIPT_DIR/scripts/isms-p-report.py" "$@"
    ;;
  version)
    grep '"version"' "$SCRIPT_DIR/package.json" | head -1 | sed 's/.*"\([0-9][^"]*\)".*/claudesec v\1/'
    ;;
  help|--help|-h|*)
    echo "ClaudeSec — DevSecOps Scanner & ISMS Dashboard"
    echo ""
    echo "Usage:"
    echo "  claudesec scan [options]      Run security scan"
    echo "  claudesec prowler [options]   Prowler multi-cloud scan (alias: scan -c prowler)"
    echo "  claudesec compliance [fw]     Compliance gap scan (scan --compliance, default isms-p)"
    echo "  claudesec dashboard           Build + serve dashboard (Docker-first, local fallback)"
    echo "  claudesec setup [target]      Install hooks/workflows to a project"
    echo "  claudesec init                Initialize .claudesec.yml config"
    echo "  claudesec quickstart          Docker scan + dashboard (one command)"
    echo "  claudesec isms-report [opts]  ISMS-P certification readiness report"
    echo "  claudesec version             Show version"
    echo ""
    echo "Quick start:"
    echo "  npx claudesec scan            Scan current directory"
    echo "  npx claudesec dashboard       Full scan + dashboard (safe runner)"
    echo "  npx claudesec quickstart      Docker: scan + dashboard at localhost:11777"
    ;;
esac
