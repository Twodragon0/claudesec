#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEGALIZE_DIR="${CLAUDESEC_LEGALIZE_KR_DIR:-$ROOT_DIR/.claudesec-sources/legalize-kr}"
LAW_TREE="$LEGALIZE_DIR/kr"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/legalize-search.sh <pattern> [law-name]
  ./scripts/legalize-search.sh --history <law-name> [file-name]
  ./scripts/legalize-search.sh --list-laws

Examples:
  ./scripts/legalize-search.sh "개인정보" 개인정보보호법
  ./scripts/legalize-search.sh "정보통신망" 정보통신망법
  ./scripts/legalize-search.sh --history 개인정보보호법 법률.md
EOF
}

normalize_law_dir() {
  printf '%s' "$1" | tr -d '[:space:]'
}

if [[ ! -d "$LAW_TREE" ]]; then
  echo "legalize-kr mirror not found at $LAW_TREE" >&2
  echo "Run ./scripts/setup-legal-intel.sh first." >&2
  exit 1
fi

case "${1:-}" in
  --list-laws)
    find "$LAW_TREE" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort
    exit 0
    ;;
  --history)
    law_name="${2:-}"
    file_name="${3:-법률.md}"
    if [[ -z "$law_name" ]]; then
      usage
      exit 1
    fi
    law_dir="$LAW_TREE/$(normalize_law_dir "$law_name")"
    if [[ ! -d "$law_dir" ]]; then
      echo "law not found: $law_name" >&2
      exit 1
    fi
    exec git -C "$LEGALIZE_DIR" log -- "$law_dir/$file_name"
    ;;
  ""|-h|--help)
    usage
    exit 0
    ;;
esac

pattern="$1"
law_name="${2:-}"
search_root="$LAW_TREE"

if [[ -n "$law_name" ]]; then
  search_root="$LAW_TREE/$(normalize_law_dir "$law_name")"
  if [[ ! -d "$search_root" ]]; then
    echo "law not found: $law_name" >&2
    exit 1
  fi
fi

if command -v rg >/dev/null 2>&1; then
  exec rg -n --hidden --glob '*.md' "$pattern" "$search_root"
fi

exec grep -RIn --include='*.md' -- "$pattern" "$search_root"
