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
    """GET and return (status_code, json_or_None)."""
    try:
        r = session.get(f"{base}{path}", timeout=10)
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, None
    except Exception:
        return 0, None


def collect_posture(base: str, session: "requests.Session") -> dict:
    """Collect sanitized posture data — counts only, no PII."""
    result: dict = {}

    # 1. Service status
    code, data = _safe_get(session, base, "/api/v1/status")
    result["service_status"] = data.get("status") if data else "UNKNOWN"

    # 2. Users — count only, never expose emails/names
    code, data = _safe_get(session, base, "/api/v1/users")
    if code == 200 and isinstance(data, list):
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
        result["users"] = {"accessible": code != 403}

    # 3. Groups — count only
    code, data = _safe_get(session, base, "/api/v1/groups")
    if code == 200 and isinstance(data, list):
        result["groups"] = {"total": len(data), "accessible": True}
    else:
        result["groups"] = {"accessible": code != 403}

    # 4. Departments — count only
    code, data = _safe_get(session, base, "/api/v1/departments")
    if code == 200 and isinstance(data, list):
        result["departments"] = {"total": len(data), "accessible": True}
    else:
        result["departments"] = {"accessible": code != 403}

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
        result["advanced_settings"] = {"accessible": code != 403}

    # 6. NSS feeds — log streaming configuration
    code, data = _safe_get(session, base, "/api/v1/nssFeeds")
    if code == 200 and isinstance(data, list):
        result["nss_feeds"] = {"total": len(data), "accessible": True}
    else:
        result["nss_feeds"] = {"accessible": code != 403}

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
        result["auth_settings"] = {"accessible": code != 403}

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
