#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${CLAUDESEC_DOCKER_IMAGE:-claudesec:local}"
SCAN_DIR="${CLAUDESEC_SCAN_DIR:-$ROOT_DIR}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
MODE="full"
SERVE=1
HOST="127.0.0.1"
PORT="11777"
BUILD_IF_MISSING=1
force_build=0

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-dashboard-docker.sh [options]

Options:
  --quick              Quick categories only (access-control,cicd,code)
  --no-serve           Generate dashboard only (no local server)
  --host <host>        Host for serving (default: 127.0.0.1)
  --port <port>        Port for serving (default: 11777)
  --image <name>       Docker image tag (default: claudesec:local)
  --scan-dir <path>    Host directory to scan (default: repository root)
  --no-build           Fail if image does not exist locally
  --build              Force image rebuild before run
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      MODE="quick"
      shift
      ;;
    --no-serve)
      SERVE=0
      shift
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
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
      echo "Unknown option: $1" >&2
      exit 1
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

cmd=(dashboard -d /workspace)

if [[ "$MODE" == "quick" ]]; then
  cmd+=("-c" "access-control,cicd,code")
fi

if [[ "$SERVE" == "1" ]]; then
  cmd+=( --serve --host 0.0.0.0 --port "$PORT" )
elif [[ "$MODE" != "quick" ]]; then
  cmd+=( --all )
fi

docker_args=(
  run --rm
  --user "$(id -u):$(id -g)"
  -v "$SCAN_DIR:/workspace"
  -w /workspace
  -e SCAN_DIR=/workspace
  -e CLAUDESEC_ENV_FILE=/workspace/.claudesec.env
)

if [[ "$SERVE" == "1" ]]; then
  docker_args+=( -p "$HOST:$PORT:$PORT" )
fi

exec "$DOCKER_BIN" "${docker_args[@]}" "$IMAGE" "${cmd[@]}"
