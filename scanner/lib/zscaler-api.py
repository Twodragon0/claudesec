#!/usr/bin/env python3
"""
ClaudeSec — Zscaler ZIA API helper.

Authenticates to the ZIA API and returns **sanitized** security posture
statistics.  No PII (emails, names, department names) is ever printed —
only aggregate counts and boolean flags.

Usage (called from zscaler.sh):
    python3 zscaler-api.py

Environment variables (loaded by scanner from ~/.claudesec.env):
    ZSCALER_API_KEY
    ZSCALER_API_ADMIN
    ZSCALER_API_PASSWORD
    ZSCALER_BASE_URL
"""

import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print(json.dumps({"error": "requests library not installed"}))
    sys.exit(1)


def _obfuscate_api_key(api_key: str) -> tuple[int, str]:
    """Zscaler timestamp-based API key obfuscation."""
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for ch in n:
        key += api_key[int(ch)]
    for ch in r:
        key += api_key[int(ch) + 2]
    return now, key


def _auth(session: "requests.Session", base: str, api_key: str,
          admin: str, password: str) -> bool:
    """Authenticate and store session cookie. Returns True on success."""
    ts, obf = _obfuscate_api_key(api_key)
    resp = session.post(
        f"{base}/api/v1/authenticatedSession",
        json={"apiKey": obf, "username": admin,
              "password": password, "timestamp": ts},
        timeout=15,
    )
    return resp.status_code == 200


def _safe_get(session: "requests.Session", base: str, path: str):
    """GET and return (status_code, json_or_None).

    A status code of 0 means the request never reached the API (DNS failure,
    timeout, TLS error, connection reset) — see ``_unreachable``.
    """
    try:
        r = session.get(f"{base}{path}", timeout=10)
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, None
    except Exception:
        return 0, None


def _unreachable(code: int) -> dict:
    """Fail-CLOSED descriptor for an endpoint we did not successfully read.

    ``accessible`` is True only when the endpoint actually returned usable data
    (HTTP 200 + expected shape), matching the ``policy_access`` audit below.
    The previous ``code != 403`` form rendered ``accessible: True`` for every
    transport failure, because ``_safe_get`` reports those as code 0 — the
    dashboard then claimed the API key reached the ZIA admin surface when
    nothing had been read.

    ``reason`` keeps the four states distinct, since a 403 is real
    information (the key reached the API and was denied):
      * ``transport_error``     — code 0, never reached the API
      * ``permission_denied``   — HTTP 403, reached the API, RBA restricted
      * ``unexpected_payload``  — HTTP 200 but not the expected JSON shape
      * ``http_error``          — any other non-200 status

    ``detail`` renders that same state as one human sentence, and exists because
    ``reason`` was WRITE-ONLY for as long as it existed: four distinct states
    were recorded here and no consumer read any of them, so
    ``scanner/checks/saas/zscaler.sh`` printed the fixed string
    ``"Users API not accessible (RBA restricted)"`` for all four. That is not a
    vague message — it is a specific, confident diagnosis that is WRONG for three
    of them, and the data to contradict it was already sitting in the same dict.
    An operator chasing an RBA grant for what is actually a DNS failure is worse
    off than one told nothing.

    The mapping lives here rather than in the shell check for the reason
    #346/#348 moved embedded interpreters out of ``.sh`` files: in Python it is
    covered by the ``scanner/lib`` gate and unit-tested; re-implemented in bash
    it would be neither, and a second copy would drift from ``reason``.
    """
    if code == 0:
        reason = "transport_error"
    elif code == 403:
        reason = "permission_denied"
    elif code == 200:
        reason = "unexpected_payload"
    else:
        reason = "http_error"
    return {
        "accessible": False,
        "status_code": code,
        "reason": reason,
        "detail": _unreachable_detail(reason, code),
    }


# One sentence per `_unreachable` reason. Keyed by reason rather than re-deriving
# from the status code, so the two can never disagree about the same response.
_UNREACHABLE_DETAIL = {
    "transport_error": (
        "request never reached the API (DNS failure, timeout, TLS error or "
        "connection reset)"
    ),
    "permission_denied": (
        "HTTP 403 — the API key reached ZIA and was denied (RBA restricted)"
    ),
    "unexpected_payload": "HTTP 200 but the payload was not the expected shape",
}


def _unreachable_detail(reason: str, code: int) -> str:
    """Human-readable rendering of an `_unreachable` reason.

    Falls back to naming the reason verbatim rather than to a generic phrase: an
    unmapped reason is a bug in this pair of functions, and a message that hides
    which state it was in reproduces the defect this whole field exists to fix.
    """
    if reason == "http_error":
        return f"HTTP {code}"
    return _UNREACHABLE_DETAIL.get(reason, f"not read ({reason})")


def collect_posture(base: str, session: "requests.Session") -> dict:
    """Collect sanitized posture data — counts only, no PII."""
    result: dict = {}

    # 1. Service status
    #
    # `if data else` tested TRUTHINESS where it needed to test TYPE. A 200 whose
    # body is a JSON string or list is truthy, so `.get` raised
    # `AttributeError: 'str' object has no attribute 'get'` and took down the
    # whole posture collection — `scanner/checks/saas/zscaler.sh` then produced
    # no SAAS-ZIA-* findings at all, with its `2>/dev/null` hiding why.
    # Reproduced against the real function before the fix:
    #   {"status": "ok"} -> 'ok'      "a string" -> CRASH      [1, 2] -> CRASH
    # An `isinstance` guard is also the idiom the rest of this function already
    # uses (`if code == 200 and isinstance(data, list)` for every list endpoint).
    #
    # UNEXPECTED_PAYLOAD is kept distinct from UNKNOWN so the two are
    # distinguishable downstream: the consumer passes only on `== "ACTIVE"` and
    # echoes the value in its warning otherwise, so a reachable-but-malformed API
    # no longer reads the same as one that reported nothing.
    code, data = _safe_get(session, base, "/api/v1/status")
    if isinstance(data, dict):
        result["service_status"] = str(data.get("status") or "UNKNOWN")
    elif code == 200:
        result["service_status"] = "UNEXPECTED_PAYLOAD"
    else:
        # Non-200 and transport failures both land here and both report UNKNOWN.
        # Left as-is deliberately: it predates this fix, it warns either way
        # rather than passing, and separating them changes a value that is not
        # part of the crash being fixed. `_unreachable()` below already draws
        # that distinction for the endpoints where it decides accessibility.
        result["service_status"] = "UNKNOWN"

    # 2. Users — count only, never expose emails/names
    #
    # `isinstance(data, list)` checked the CONTAINER and not its elements, so a
    # 200 body of `[1, 2]` or `["okta"]` reached `u.get("groups")` and raised
    # `AttributeError: 'int' object has no attribute 'get'`, taking down the whole
    # posture collection. Measured before this guard:
    #   [{"groups": [...], ...}] -> counted      [1, 2] -> CRASH
    #   ["okta"] -> CRASH                        [None] -> CRASH
    # Same shape as the `{"saas": ["okta"]}` case in the dashboard asset loader:
    # a type check one level too shallow.
    #
    # A list with a non-dict element is routed to `_unreachable(code)` rather
    # than filtered down to the dict elements. Filtering would keep `total` and
    # call it a success while silently under-counting, which trades a crash for a
    # quiet wrong number — and `_unreachable(200)` already means exactly this
    # ("reason": "unexpected_payload"), so no new state is invented.
    #
    # This endpoint is the only one that needs the element check: groups,
    # departments and nss_feeds take `len(data)` and never dereference an element.
    code, data = _safe_get(session, base, "/api/v1/users")
    if (
        code == 200
        and isinstance(data, list)
        and all(isinstance(u, dict) for u in data)
    ):
        total = len(data)
        no_group = sum(1 for u in data if not u.get("groups"))
        no_dept = sum(1 for u in data if not u.get("department"))
        # Detect inactive: users with no groups AND no department
        unassigned = sum(1 for u in data
                         if not u.get("groups") and not u.get("department"))
        result["users"] = {
            "total": total,
            "no_group": no_group,
            "no_department": no_dept,
            "unassigned": unassigned,
            "accessible": True,
        }
    else:
        result["users"] = _unreachable(code)

    # 3. Groups — count only
    code, data = _safe_get(session, base, "/api/v1/groups")
    if code == 200 and isinstance(data, list):
        result["groups"] = {"total": len(data), "accessible": True}
    else:
        result["groups"] = _unreachable(code)

    # 4. Departments — count only
    code, data = _safe_get(session, base, "/api/v1/departments")
    if code == 200 and isinstance(data, list):
        result["departments"] = {"total": len(data), "accessible": True}
    else:
        result["departments"] = _unreachable(code)

    # 5. Advanced settings — flag risky configs
    code, data = _safe_get(session, base, "/api/v1/advancedSettings")
    if code == 200 and isinstance(data, dict):
        bypass_urls = data.get("authBypassUrls", [])
        bypass_apps = data.get("authBypassApps", [])
        domain_fronting = data.get("domainFrontingBypassUrlCategories", [])
        result["advanced_settings"] = {
            "auth_bypass_urls_count": len(bypass_urls),
            "auth_bypass_apps_count": len(bypass_apps),
            "domain_fronting_bypass_count": len(domain_fronting),
            "accessible": True,
        }
    else:
        result["advanced_settings"] = _unreachable(code)

    # 6. NSS feeds — log streaming configuration
    code, data = _safe_get(session, base, "/api/v1/nssFeeds")
    if code == 200 and isinstance(data, list):
        result["nss_feeds"] = {"total": len(data), "accessible": True}
    else:
        result["nss_feeds"] = _unreachable(code)

    # 7. Auth settings — SAML/SSO and provisioning config
    code, data = _safe_get(session, base, "/api/v1/authSettings")
    if code == 200 and isinstance(data, dict):
        result["auth_settings"] = {
            "saml_enabled": data.get("samlEnabled", False),
            "kerberos_enabled": data.get("kerberosEnabled", False),
            "auto_provision": data.get("autoProvision", False),
            "auth_frequency": data.get("authFrequency", ""),
            "org_auth_type": data.get("orgAuthType", ""),
            "scim_migration_enabled": data.get(
                "directorySyncMigrateToScimEnabled", False),
            "accessible": True,
        }
    else:
        result["auth_settings"] = _unreachable(code)

    # 8. Policy endpoint access audit (check what API key can reach)
    policy_endpoints = {
        "url_categories": "/api/v1/urlCategories",
        "firewall_rules": "/api/v1/firewallRules",
        "dlp": "/api/v1/dlpDictionaries",
        "ssl_inspection": "/api/v1/sslInspectionRules",
        "sandbox": "/api/v1/sandboxRules",
        "admin_users": "/api/v1/adminUsers",
        "locations": "/api/v1/locations",
    }
    accessible = []
    restricted = []
    for name, ep in policy_endpoints.items():
        code, _ = _safe_get(session, base, ep)
        if code == 200:
            accessible.append(name)
        else:
            restricted.append(name)
    result["policy_access"] = {
        "accessible_count": len(accessible),
        "restricted_count": len(restricted),
        "accessible_endpoints": accessible,
        "restricted_endpoints": restricted,
    }

    return result


def main():
    api_key = os.environ.get("ZSCALER_API_KEY", "")
    admin = os.environ.get("ZSCALER_API_ADMIN", "")
    password = os.environ.get("ZSCALER_API_PASSWORD", "")
    base = os.environ.get("ZSCALER_BASE_URL", "")

    if not all([api_key, admin, password, base]):
        print(json.dumps({"error": "missing_credentials"}))
        sys.exit(0)

    session = requests.Session()
    if not _auth(session, base, api_key, admin, password):
        print(json.dumps({"error": "auth_failed"}))
        sys.exit(0)

    try:
        posture = collect_posture(base, session)
        posture["authenticated"] = True
        print(json.dumps(posture, ensure_ascii=False))
    finally:
        # Always logout
        try:
            session.delete(f"{base}/api/v1/authenticatedSession", timeout=5)
        except Exception:
            pass


if __name__ == "__main__":
    main()
