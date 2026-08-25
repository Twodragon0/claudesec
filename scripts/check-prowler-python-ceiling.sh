#!/usr/bin/env bash
# check-prowler-python-ceiling.sh
# Fetch prowler's PyPI metadata and determine whether the Python ceiling has
# moved far enough to lift the alpine freeze — i.e. whether **py3.14** is now
# allowed, py3.14 being what the next alpine minor (3.24) ships. See the
# TARGET_PY_MINOR note in Step 3 for why the threshold is 3.14 and not 3.13.
#
# Exit codes:
#   0 — still frozen (py3.14 not yet allowed) OR network/parse error (fail-safe no-op)
#   2 — LIFTED (py3.14 now allowed) — caller should open alert issue
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

# ── Step 3: determine whether the ceiling is lifted ─────────────────────────
# THE THRESHOLD IS 3.14, NOT 3.13, and that is the whole point of this check.
#
# The original test asked "is py3.13 allowed?" because prowler required `<3.13`
# at the time. It fired correctly when prowler moved to `<3.14` (issue #295) — and
# then stayed latched true forever, because every later release also satisfies
# "3.13 is allowed". A permanently-firing alert is a dead alert: the workflow
# dedupes onto the already-open issue, so the NEXT real unblock would arrive with
# no signal at all.
#
# It was also asking the wrong question. The alert exists to tell us the alpine
# freeze can be lifted, and that depends on the Python the NEXT alpine minor
# ships — measured 2026-08-24 by installing python3 in each image:
#
#   alpine:3.20 -> py3.12.13   alpine:3.22 -> py3.12.14   alpine:3.24 -> py3.14.7
#   alpine:3.21 -> py3.12.14   alpine:3.23 -> py3.12.14
#
# alpine skips py3.13 entirely. There is no py3.13 alpine to move to, so prowler
# accepting py3.13 unblocks nothing; the freeze lifts when prowler accepts
# **py3.14**, which is what alpine 3.24 ships. Hence TARGET_PY_MINOR below.
#
# Keep TARGET_PY_MINOR equal to the Python minor of the next alpine minor line —
# re-measure rather than assume when alpine 3.25 lands.
CEILING_LIFTED="$(REQUIRES_PYTHON="${REQUIRES_PYTHON}" python3 -c "
import re, os

rp = os.environ.get('REQUIRES_PYTHON', '')

# The Python minor that must become permissible for the alpine freeze to lift.
TARGET_PY_MINOR = 14

def ceiling_lifted(requires_python):
    '''True when Python 3.TARGET_PY_MINOR is allowed by requires_python.

    No upper bound, or no parseable 3.x upper bound, counts as lifted — the
    fail-safe direction here is a false ALERT (a human re-checks and closes it),
    never a missed one.
    '''
    if not requires_python or not requires_python.strip():
        return True
    upper_bounds = re.findall(r'(<[=]?)\s*(\d+)[.](\d+)', requires_python)
    if not upper_bounds:
        return True
    for op, major_s, minor_s in upper_bounds:
        major, minor = int(major_s), int(minor_s)
        if major != 3:
            continue
        # '<3.14' excludes 3.14  -> frozen;  '<3.15' allows it -> lifted
        if op == '<' and minor <= TARGET_PY_MINOR:
            return False
        # '<=3.13' excludes 3.14 -> frozen;  '<=3.14' allows it -> lifted
        if op == '<=' and minor < TARGET_PY_MINOR:
            return False
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
