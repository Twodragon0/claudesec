#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — dashboard serve helper library
# ============================================================================
#
# Holds the local dashboard HTTP-serve logic (open-in-browser + `python3 -m
# http.server`), extracted from the `scanner/claudesec` entrypoint to keep it
# focused. This module depends on the output helpers in output.sh (`error`,
# `warning`) and the color variables (`DIM`, `BOLD`, `NC`) being sourced into
# the same shell BEFORE serve_dashboard is invoked.
#
# Like datadog.sh, this is network-I/O code (binds a socket / spawns an HTTP
# server) and is therefore intentionally NOT part of the kcov --include-pattern
# SUT set — see the "kcov SUT allowlist" note and test_ci_scanner_lib_reachability.py.
#
# No `set -euo pipefail` here — this is a sourced lib, mirroring the other libs
# which have no `set` line after the shebang.

# ── Dashboard serve ──────────────────────────────────────────────────────────

open_url_best_effort() {
  local url="$1"
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
    return 0
  fi
  return 0
}

serve_dashboard() {
  local html_path="$1"
  local host="${2:-127.0.0.1}"
  local port="${3:-11777}"
  local abs_dir abs_file url direct_url

  # Validate port is numeric (1-65535)
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    error "Invalid port: $port (must be 1-65535)"
    return 1
  fi
  # Validate host is a safe hostname/IP
  if [[ ! "$host" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    error "Invalid host: $host"
    return 1
  fi

  if [[ ! -f "$html_path" ]]; then
    error "Dashboard file not found: $html_path"
    return 1
  fi

  abs_dir="$(cd "$(dirname "$html_path")" && pwd)"
  abs_file="$(basename "$html_path")"
  url="http://${host}:${port}/"
  direct_url="http://${host}:${port}/${abs_file}"

  # Fail fast if the port is already in use to avoid confusing "silent" hangs.
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((host, port))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
    then
      if python3 - "$direct_url" <<'PY' 2>/dev/null
import sys
import urllib.request

u = sys.argv[1]
req = urllib.request.Request(u, headers={"User-Agent": "claudesec/serve-check"})
with urllib.request.urlopen(req, timeout=3) as res:
    body = res.read(8192).decode("utf-8", errors="ignore").lower()
    if res.status >= 400:
        sys.exit(1)
    if "claudesec" not in body and "dashboard" not in body:
        sys.exit(1)
sys.exit(0)
PY
      then
        warning "Port ${host}:${port} is already in use; detected reachable dashboard. Reusing existing server."
        echo -e "  ${DIM}Dashboard URL: ${BOLD}${direct_url}${NC}"
        open_url_best_effort "$direct_url"
        return 0
      fi
      error "Port ${host}:${port} is already in use. Choose another port with: claudesec dashboard --serve --port <port>"
      return 1
    fi
  fi

  # Ensure "/" renders the dashboard by writing an index.html redirect.
  # This keeps the generated dashboard filename stable while making localhost root convenient.
  cat > "${abs_dir}/index.html" <<EOF
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="refresh" content="0; url=./${abs_file}" />
    <meta name="referrer" content="no-referrer" />
    <title>ClaudeSec Dashboard</title>
  </head>
  <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
    <p>Redirecting to <a href="./${abs_file}">${abs_file}</a>…</p>
  </body>
</html>
EOF

  echo -e "  ${DIM}Serving dashboard on: ${BOLD}${url}${NC}"
  echo -e "  ${DIM}Press Ctrl+C to stop.${NC}"
  open_url_best_effort "$url"

  if command -v python3 >/dev/null 2>&1; then
    (cd "$abs_dir" && python3 -m http.server "$port" --bind "$host")
    return $?
  fi
  if command -v python >/dev/null 2>&1; then
    (cd "$abs_dir" && python -m http.server "$port" --bind "$host")
    return $?
  fi

  error "python3 not found — cannot serve dashboard. Open it directly: file://$abs_dir/$abs_file"
  return 1
}
