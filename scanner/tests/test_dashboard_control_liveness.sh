#!/usr/bin/env bash
# ClaudeSec — dashboard control-liveness smoke test (headless-Chrome harness).
#
# Generates the dashboard OFFLINE via scanner/lib/dashboard-gen.py, then drives
# every delegated control in real headless Chrome and asserts the DOM effect
# (see dashboard-control-liveness.mjs for the "why"). Catches the one regression
# class the pytest/source-pin guards can't: a data-action value with no matching
# dispatcher case (a silently-dead control), plus reintroduced inline handlers.
#
# Hermetic: CLAUDESEC_DASHBOARD_OFFLINE=1 forces the generator to skip all live
# GitHub API calls (un-gated calls were the root cause of the multi-minute kcov
# hangs fixed in #190). No network is touched.
#
# Requires: python3, node (>= 21, for built-in WebSocket), and a Chrome/Chromium
# binary (CHROME_BIN / CHROME_PATH, else auto-detected). Skips cleanly (exit 0)
# when node or Chrome is unavailable locally so it never blocks unrelated work;
# CI provisions both explicitly.
#
# Run: bash scanner/tests/test_dashboard_control_liveness.sh
set -euo pipefail

# Offline guard (PR #190): never let the generator make live API calls.
export CLAUDESEC_DASHBOARD_OFFLINE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$REPO_ROOT/scanner/lib/dashboard-gen.py"
HARNESS="$SCRIPT_DIR/dashboard-control-liveness.mjs"

# The CI kcov job globs scanner/tests/test_*.sh and runs each one under kcov.
# Driving headless Chrome there is unreliable and pointless — this harness
# measures no SUT bash coverage, since it never sources one of the five files in
# kcov's include-pattern. Skip under kcov so the glob runs us as an instant
# no-op; the dedicated dashboard-control smoke workflow runs us for real.
#
# DETECTED BY ENV VAR, NOT BY TracerPid. The original check read
# `/proc/self/status` for a non-zero `TracerPid` and NEVER ONCE FIRED, because
# kcov 42 instruments bash through XTRACE, not ptrace. Measured under the exact
# CI invocation (`timeout 30 kcov --include-pattern=… <script>`):
#
#     TracerPid                 0        <- for the script itself, too
#     KCOV_BASH_COMMAND         /bin/bash
#     KCOV_BASH_XTRACEFD        262144
#     PS4                       kcov@${BASH_SOURCE}@${LINENO}@
#     SHELLOPTS                 …:xtrace
#
# So both browser smokes ran fully under kcov for as long as the guard existed —
# 7s, 9s, 13s, 21s and 30s across five observed runs, one of them a red build on
# PR #465 that blocked a merge for a change touching none of this. The env var is
# set by kcov itself, needs no /proc, and works on macOS.
if [[ -n "${KCOV_BASH_XTRACEFD:-}" || -n "${KCOV_BASH_COMMAND:-}" ]]; then
  echo "SKIP: running under kcov (xtrace instrumentation) — browser smoke runs only in the dedicated workflow."
  exit 0
fi

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

# ── generate the dashboard offline from a small in-repo fixture ───────────────
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/scan-report.json" <<'JSON'
{
  "passed": 8, "failed": 3, "warnings": 1, "skipped": 0, "total": 12,
  "score": 66, "grade": "D", "duration": 5,
  "findings": [
    {"id": "IAM-001", "check": "IAM-001", "title": "Root key exposed", "message": "Root access key present", "severity": "critical", "category": "access-control", "action": "Rotate now", "location": "/app/.env", "provider": "aws"},
    {"id": "NET-010", "check": "NET-010", "title": "TLS 1.0 enabled", "message": "Legacy TLS protocol", "severity": "high", "category": "network", "action": "Disable TLS 1.0", "location": ""},
    {"id": "CICD-020", "check": "CICD-020", "title": "No branch protection", "message": "Missing branch protection", "severity": "medium", "category": "cicd", "action": "Enable protection", "location": ""}
  ]
}
JSON

# Synthetic policies fixture so the Policies card (and its togglePolDet control)
# renders. The card is emitted ONLY when .claudesec-assets/policies.json exists
# in the scan dir; a normal scan has none. PLACEHOLDER data only — no real
# QueryPie/company/internal content (repo no-sensitive-data rule).
mkdir -p "$tmpdir/.claudesec-assets"
cat > "$tmpdir/.claudesec-assets/policies.json" <<'JSON'
[
  {
    "name": "Sample Access Control Policy",
    "url": "",
    "total_chapters": 2,
    "total_articles": 3,
    "isms_controls": ["2.5.1"],
    "articles": [
      {"chapter": "Chapter 1 General", "num": "Article 1", "title": "Purpose"},
      {"chapter": "Chapter 1 General", "num": "Article 2", "title": "Scope"},
      {"chapter": "Chapter 2 Controls", "num": "Article 3", "title": "Access review"}
    ]
  }
]
JSON

dash="$tmpdir/dashboard.html"
CLAUDESEC_SCAN_DIR="$tmpdir" \
  CLAUDESEC_SCAN_JSON="$tmpdir/scan-report.json" \
  CLAUDESEC_GENERATE_DIAGRAMS=0 \
  python3 "$GEN" "$dash" >/dev/null

if [[ ! -s "$dash" ]]; then
  echo "FAIL: dashboard generation produced no output at $dash"
  exit 1
fi

# ── drive the controls in headless Chrome ─────────────────────────────────────
echo "Chrome: $CHROME"
node "$HARNESS" --html "$dash" --chrome "$CHROME"
