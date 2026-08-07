#!/usr/bin/env bash
# ClaudeSec — ISMS ASSET dashboard control-liveness smoke (headless-Chrome harness).
#
# claudesec-asset-dashboard.html is a checked-in TEMPLATE (scripts/build-dashboard.py
# reads it and injects data). It ships the SAME strict meta-CSP as the scan dashboard
# — `script-src 'nonce-…' 'strict-dynamic'`, no `'unsafe-inline'` — and the same
# delegated data-action dispatcher, so an inline `on*=` handler or a data-action with
# no dispatcher case is silently DEAD in the browser. It previously had no automated
# coverage at all. This wrapper renders it offline from a synthetic fixture and drives
# every reachable control in real headless Chrome via
# scanner/tests/asset-dashboard-assertions.js.
#
# HERMETIC: no network. The page is materialised in a temp dir with the fixture data
# inlined exactly the way scripts/build-dashboard.py does it, so the browser never
# needs to fetch .claudesec-assets/dashboard-data.json. The page's own
# `fetch('/scan-report.json')` resolves to a file:// URL that simply fails and falls
# through to its `.catch(render)` path — no egress, no CSP violation (verified).
# CLAUDESEC_DASHBOARD_OFFLINE=1 is exported anyway so this can never start depending
# on the network (the un-gated-call class behind the #190 hangs).
#
# Requires: python3, node (>= 21, for built-in WebSocket), and a Chrome/Chromium
# binary (CHROME_BIN / CHROME_PATH, else auto-detected). Skips cleanly (exit 0) when
# node or Chrome is unavailable locally so it never blocks unrelated work; CI
# provisions both explicitly.
#
# Run: bash scanner/tests/test_asset_dashboard_control_liveness.sh
set -euo pipefail

# Offline guard (PR #190): never let anything in this path make live API calls.
export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEMPLATE="$REPO_ROOT/claudesec-asset-dashboard.html"
FIXTURE="$SCRIPT_DIR/fixtures/asset-dashboard-data.json"
HARNESS="$SCRIPT_DIR/dashboard-control-liveness.mjs"
ASSERTIONS="$SCRIPT_DIR/asset-dashboard-assertions.js"

# The CI kcov job globs scanner/tests/test_*.sh and runs each DIRECTLY under kcov's
# ptrace tracer. Driving headless Chrome under ptrace is unreliable (and pointless —
# this harness measures no SUT bash coverage). Skip when traced so the kcov glob runs
# us as an instant no-op; the dedicated dashboard-control smoke workflow runs us
# untraced. macOS/local (no /proc) => treated as untraced.
if [[ -r /proc/self/status ]]; then
  tracer_pid="$(awk '/^TracerPid:/{print $2}' /proc/self/status 2>/dev/null || echo 0)"
  if [[ "${tracer_pid:-0}" != "0" ]]; then
    echo "SKIP: running under a tracer (kcov/ptrace) — browser smoke runs only in the dedicated workflow."
    exit 0
  fi
fi

for f in "$TEMPLATE" "$FIXTURE" "$HARNESS" "$ASSERTIONS"; do
  if [[ ! -s "$f" ]]; then
    echo "FAIL: required file missing or empty: $f"
    exit 1
  fi
done

# ── graceful local skip when tooling is missing ──────────────────────────────
resolve_chrome() {
  local c
  for c in "${CHROME_BIN:-}" "${CHROME_PATH:-}" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/usr/bin/google-chrome" "/usr/bin/google-chrome-stable" \
    "/usr/bin/chromium-browser" "/usr/bin/chromium"; do
    [[ -n "$c" && -x "$c" ]] && { echo "$c"; return 0; }
  done
  return 1
}

if ! command -v node >/dev/null 2>&1; then
  echo "SKIP: node not found — control-liveness smoke needs Node >= 21 (built-in WebSocket)."
  exit 0
fi
if ! CHROME="$(resolve_chrome)"; then
  echo "SKIP: no Chrome/Chromium binary found — set CHROME_BIN or install Chrome."
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
dash="$tmpdir/asset-dashboard.html"

# ── materialise the page: fixture data + a fixed CSP nonce ────────────────────
# The substitutions mirror scripts/build-dashboard.py exactly (same placeholders,
# same `</` / `<!--` escaping). Every replacement is COUNT-CHECKED: if a placeholder
# is renamed the script fails loudly instead of silently shipping a page whose data
# never landed (which would fall back to the fetch path, render a .load-error panel,
# and make every control assertion fail for the wrong reason).
#
# Quoted heredoc + env-var inputs: no shell interpolation into the interpreter body
# (the CWE-94 shape pinned by scanner/tests/test_ci_no_code_injection_regression.py).
CLAUDESEC_ASSET_TEMPLATE="$TEMPLATE" \
CLAUDESEC_ASSET_FIXTURE="$FIXTURE" \
CLAUDESEC_ASSET_OUT="$dash" \
python3 - <<'PY'
import json
import os
import sys

template = open(os.environ["CLAUDESEC_ASSET_TEMPLATE"], encoding="utf-8").read()
data = json.load(open(os.environ["CLAUDESEC_ASSET_FIXTURE"], encoding="utf-8"))

# Same escaping scripts/build-dashboard.py applies before injecting into <script>.
payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/").replace("<!--", "<\\!--")

DATA_PLACEHOLDER = "const D=/*__DATA__*/null;"
JSON_PLACEHOLDER = "__DASHBOARD_DATA__"
NONCE_PLACEHOLDER = "{{CSP_NONCE}}"
NONCE = "claudesec-liveness-test-nonce"

for name, needle, want in (
    ("data", DATA_PLACEHOLDER, 1),
    ("json-island", JSON_PLACEHOLDER, 1),
    ("csp-nonce", NONCE_PLACEHOLDER, 2),
):
    found = template.count(needle)
    if found != want:
        sys.exit(
            "FAIL: %s placeholder %r appears %d time(s), expected %d — "
            "claudesec-asset-dashboard.html drifted from scripts/build-dashboard.py"
            % (name, needle, found, want)
        )

html = template.replace(DATA_PLACEHOLDER, "const D=%s;" % payload)
html = html.replace(JSON_PLACEHOLDER, payload)
html = html.replace(NONCE_PLACEHOLDER, NONCE)

if NONCE_PLACEHOLDER in html or DATA_PLACEHOLDER in html:
    sys.exit("FAIL: placeholder survived substitution")
if "'nonce-%s'" % NONCE not in html:
    sys.exit("FAIL: the meta-CSP no longer carries a script-src nonce")

open(os.environ["CLAUDESEC_ASSET_OUT"], "w", encoding="utf-8").write(html)
PY

if [[ ! -s "$dash" ]]; then
  echo "FAIL: asset dashboard page was not materialised at $dash"
  exit 1
fi

# ── drive the controls in headless Chrome ─────────────────────────────────────
echo "Chrome: $CHROME"
node "$HARNESS" --html "$dash" --chrome "$CHROME" --assert-file "$ASSERTIONS"
