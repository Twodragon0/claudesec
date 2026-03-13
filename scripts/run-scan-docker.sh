#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${CLAUDESEC_DOCKER_IMAGE:-claudesec:local}"
SCAN_DIR="${CLAUDESEC_SCAN_DIR:-$ROOT_DIR}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
BUILD_IF_MISSING=1

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-scan-docker.sh [options] [scanner args]

Options:
  --image <name>       Docker image tag (default: claudesec:local)
  --scan-dir <path>    Host directory to scan (default: repository root)
  --no-build           Fail if image does not exist locally
  --build              Force image rebuild before run
  -h, --help           Show this help

Examples:
  ./scripts/run-scan-docker.sh
  ./scripts/run-scan-docker.sh -c access-control
  ./scripts/run-scan-docker.sh --scan-dir /path/to/project -c infra
EOF
}

force_build=0
scanner_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      IMAGE="$2"
      shift 2
      ;;
    --scan-dir)
      SCAN_DIR="$2"
      shift 2
      ;;
    --no-build)
      BUILD_IF_MISSING=0
      shift
      ;;
    --build)
      force_build=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      scanner_args+=("$1")
      shift
      ;;
  esac
done

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
  echo "Error: docker command not found ($DOCKER_BIN)" >&2
  exit 1
fi

if [[ ! -d "$SCAN_DIR" ]]; then
  echo "Error: scan directory not found: $SCAN_DIR" >&2
  exit 1
fi

if [[ "$force_build" == "1" ]]; then
  "$DOCKER_BIN" build -t "$IMAGE" "$ROOT_DIR"
elif ! "$DOCKER_BIN" image inspect "$IMAGE" >/dev/null 2>&1; then
  if [[ "$BUILD_IF_MISSING" == "1" ]]; then
    "$DOCKER_BIN" build -t "$IMAGE" "$ROOT_DIR"
  else
    echo "Error: Docker image not found: $IMAGE" >&2
    exit 1
  fi
fi

exec "$DOCKER_BIN" run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$SCAN_DIR:/workspace" \
  -w /workspace \
  -e SCAN_DIR=/workspace \
  -e CLAUDESEC_ENV_FILE=/workspace/.claudesec.env \
  "$IMAGE" scan -d /workspace "${scanner_args[@]}"
