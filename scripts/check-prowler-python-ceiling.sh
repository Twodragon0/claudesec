#!/usr/bin/env bash
# check-prowler-python-ceiling.sh
# Fetch prowler's PyPI metadata and determine whether the Python <3.13 ceiling
# has been lifted (i.e. Python 3.13+ is now allowed).
#
# Exit codes:
#   0 — ceiling still present (frozen) OR network/parse error (fail-safe no-op)
#   2 — ceiling LIFTED (py3.13+ now allowed) — caller should open alert issue
#
# Outputs (to stdout):
#   PROWLER_VERSION=<version>
#   REQUIRES_PYTHON=<specifier>
#   CEILING_LIFTED=true|false
#
# Design notes:
#   - Uses stdlib python3 only (no third-party packages required).
#   - Network errors exit 0 (no-op) rather than 1 to prevent false alerts on
#     transient PyPI outages during scheduled runs.
#   - All expansions quoted; shellcheck-clean.

set -euo pipefail

PYPI_URL="https://pypi.org/pypi/prowler/json"

# ── Step 1: fetch PyPI metadata (fail-safe on curl error) ──────────────────
PYPI_JSON=""
if ! PYPI_JSON="$(curl -fsSL --max-time 30 "${PYPI_URL}" 2>/dev/null)"; then
  echo "WARNING: curl failed to fetch ${PYPI_URL} — transient error, skipping run" >&2
  echo "PROWLER_VERSION=unknown"
  echo "REQUIRES_PYTHON=unknown"
  echo "CEILING_LIFTED=false"
  exit 0
fi

if [ -z "${PYPI_JSON}" ]; then
  echo "WARNING: empty response from ${PYPI_URL} — skipping run" >&2
  echo "PROWLER_VERSION=unknown"
  echo "REQUIRES_PYTHON=unknown"
  echo "CEILING_LIFTED=false"
  exit 0
fi

# ── Step 2: parse version + requires_python via stdlib python3 ──────────────
PARSE_RESULT=""
if ! PARSE_RESULT="$(echo "${PYPI_JSON}" | python3 -c '
import sys, json

try:
    d = json.load(sys.stdin)
    v  = d["info"]["version"]
    rp = d["info"].get("requires_python") or ""
    print(v)
    print(rp)
except Exception as e:
    print("PARSE_ERROR", file=sys.stderr)
    print(str(e), file=sys.stderr)
    sys.exit(1)
' 2>/dev/null)"; then
  echo "WARNING: failed to parse PyPI JSON — skipping run" >&2
  echo "PROWLER_VERSION=unknown"
  echo "REQUIRES_PYTHON=unknown"
  echo "CEILING_LIFTED=false"
  exit 0
fi

PROWLER_VERSION="$(echo "${PARSE_RESULT}" | head -n1)"
REQUIRES_PYTHON="$(echo "${PARSE_RESULT}" | tail -n1)"

# ── Step 3: determine whether ceiling is lifted ─────────────────────────────
# ceiling_lifted returns "true" if Python 3.13+ is now allowed:
#   - no upper bound at all                  => lifted
#   - strict upper bound <3.13               => frozen
#   - inclusive upper bound <=3.13           => lifted (3.13 IS allowed)
#   - upper bound <3.14 or higher            => lifted (3.13 IS allowed)
CEILING_LIFTED="$(REQUIRES_PYTHON="${REQUIRES_PYTHON}" python3 -c "
import re, os

rp = os.environ.get('REQUIRES_PYTHON', '')

def ceiling_lifted(requires_python):
    if not requires_python or not requires_python.strip():
        return True
    upper_bounds = re.findall(r'(<[=]?)\s*(\d+)[.](\d+)', requires_python)
    if not upper_bounds:
        return True
    for op, major_s, minor_s in upper_bounds:
        major, minor = int(major_s), int(minor_s)
        if major != 3:
            continue
        if op == '<' and minor <= 13:
            return False   # strictly <3.13 or lower => frozen
        if op == '<=' and minor < 13:
            return False   # <=3.12 or lower => frozen
    return True

print('true' if ceiling_lifted(rp) else 'false')
" 2>/dev/null || echo "false")"

echo "PROWLER_VERSION=${PROWLER_VERSION}"
echo "REQUIRES_PYTHON=${REQUIRES_PYTHON}"
echo "CEILING_LIFTED=${CEILING_LIFTED}"

if [ "${CEILING_LIFTED}" = "true" ]; then
  exit 2
else
  exit 0
fi
