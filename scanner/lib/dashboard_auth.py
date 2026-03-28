import os
import json
import base64
from datetime import datetime, timezone

from dashboard_utils import h


def _parse_expiry_datetime(raw_value):
    if raw_value is None:
        return None
    raw = str(raw_value).strip()
    if not raw:
        return None
    try:
        if raw.isdigit():
            return datetime.fromtimestamp(int(raw), timezone.utc)
    except Exception:
        pass
    try:
        norm = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(norm)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _jwt_expiry_datetime(token_value):
    token = (token_value or "").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    try:
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode(
            "utf-8"
        )
        payload = json.loads(payload_json)
    except Exception:
        return None
    exp = payload.get("exp")
    try:
        if exp is None:
            return None
        return datetime.fromtimestamp(int(exp), timezone.utc)
    except Exception:
        return None


def _collect_token_expiry_items():
    candidates = [
        (
            "Okta OAuth",
            os.environ.get("OKTA_OAUTH_TOKEN_EXPIRES_AT", ""),
            os.environ.get("OKTA_OAUTH_TOKEN", ""),
        ),
        (
            "GitHub",
            os.environ.get("GITHUB_TOKEN_EXPIRES_AT", "")
            or os.environ.get("GH_TOKEN_EXPIRES_AT", ""),
            "",
        ),
    ]
    out = []
    for provider, explicit_raw, token in candidates:
        expiry = _parse_expiry_datetime(explicit_raw)
        source = "env"
        if expiry is None and token:
            expiry = _jwt_expiry_datetime(token)
            source = "jwt"
        if expiry is None:
            continue
        out.append({"provider": provider, "expiry": expiry, "source": source})
    return out


def _parse_duration_seconds(raw_value, default_seconds, default_unit):
    raw = (raw_value or "").strip().lower()
    if not raw:
        return default_seconds, "default"
    unit_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if raw[-1:] in unit_map:
        num = raw[:-1]
        if num.isdigit() and int(num) > 0:
            return int(num) * unit_map[raw[-1]], "env"
        return default_seconds, "default"
    if raw.isdigit() and int(raw) > 0:
        factor = 3600 if default_unit == "h" else 86400
        return int(raw) * factor, "env"
    return default_seconds, "default"


def _duration_label(seconds):
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def _load_saas_sso_stats():
    """Load SaaS SSO stats from .claudesec-assets/dashboard-data.json if available."""
    scan_dir = os.environ.get("SCAN_DIR", ".")
    data_path = os.path.join(scan_dir, ".claudesec-assets", "dashboard-data.json")
    try:
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
        saas = data.get("saas", [])
        if not saas:
            return None
        sso_keywords = ("sso", "okta", "saml")
        sso_count = sum(
            1
            for s in saas
            if any(k in (s.get("auth", "") or "").lower() for k in sso_keywords)
        )
        total = len(saas)
        pct = round(sso_count / total * 100) if total else 0
        non_sso = total - sso_count
        return {
            "sso_count": sso_count,
            "total": total,
            "pct": pct,
            "non_sso": non_sso,
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None


def build_auth_summary_html(envs, findings_list):
    """Build Auth & SSO posture card with dynamic SaaS data."""
    auth_finding_count = 0
    auth_keywords = ("auth", "oauth", "token", "session", "mfa", "login", "sso", "jwt")
    for f in findings_list or []:
        text = (
            str(f.get("id", ""))
            + " "
            + str(f.get("title", ""))
            + " "
            + str(f.get("details", ""))
        ).lower()
        if any(k in text for k in auth_keywords):
            auth_finding_count += 1

    # Dynamic SSO stats from asset data
    stats = _load_saas_sso_stats()
    sso_count = stats["sso_count"] if stats else 0
    sso_total = stats["total"] if stats else 0
    sso_pct = stats["pct"] if stats else 0
    non_sso = stats["non_sso"] if stats else 0
    sso_label = f"{sso_count}/{sso_total}" if stats else "N/A"
    pct_label = f"{sso_pct}%" if stats else "N/A"

    practices = [
        {
            "title": "Use Authorization Code + PKCE for OAuth clients",
            "detail": "Avoid implicit/password grants, and enforce PKCE (S256) for browser-based and public clients.",
            "source_label": "RFC 9700",
            "source_url": "https://datatracker.ietf.org/doc/html/rfc9700",
        },
        {
            "title": "Enforce MFA for privileged identities",
            "detail": "Require phishing-resistant MFA for admin or security-sensitive scan integrations.",
            "source_label": "CIS Controls",
            "source_url": "https://www.cisecurity.org/controls",
        },
    ]

    practices_html = ""
    for item in practices:
        practices_html += (
            '<li style="margin:.45rem 0">'
            + f"<strong>{h(item['title'])}</strong><br>"
            + f'<span style="color:var(--muted)">{h(item["detail"])}</span> '
            + f'<a href="{h(item["source_url"])}" target="_blank" rel="noopener" class="ref-link" style="margin-top:0">{h(item["source_label"])}</a>'
            + "</li>"
        )

    sso_pill_class = "sp-pass" if sso_pct >= 70 else ("sp-warn" if sso_pct >= 50 else "sp-fail")
    policy_text = (
        f"MFA enforced &middot; SSO coverage {pct_label} &middot; Remaining {non_sso} SaaS apps require direct credential review"
        if stats
        else "Run asset collection to populate SSO coverage data"
    )

    return (
        '<div class="card">'
        '<div class="card-title">Authentication &amp; SSO posture</div>'
        '<div style="padding:1rem 1.25rem">'
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem;margin-bottom:1rem">'
        + f'<div class="stat-pill {sso_pill_class}" style="margin:0"><div class="sp-icon">&#x1f512;</div><div><div class="sp-num">{sso_label}</div><div class="sp-label">SaaS via Okta SSO</div></div></div>'
        + f'<div class="stat-pill sp-info" style="margin:0"><div class="sp-icon">&#x1f4c8;</div><div><div class="sp-num">{pct_label}</div><div class="sp-label">SSO coverage</div></div></div>'
        + f'<div class="stat-pill {("sp-warn" if auth_finding_count > 0 else "sp-info")}" style="margin:0"><div class="sp-icon">&#x1f9ea;</div><div><div class="sp-num">{auth_finding_count}</div><div class="sp-label">Auth-related findings</div></div></div>'
        + "</div>"
        + f'<div style="margin-bottom:.75rem"><strong>Connected providers</strong>'
        + '<div style="margin-top:.4rem">'
        + f'<span class="trust-badge trust-ms" style="margin:0 .35rem .35rem 0">Okta SSO ({sso_label} SaaS)</span>'
        + '<span class="trust-badge trust-ms" style="margin:0 .35rem .35rem 0">Google (via SSO)</span>'
        + '<span class="trust-badge trust-ms" style="margin:0 .35rem .35rem 0">Zscaler ZIA/ZPA</span>'
        + "</div></div>"
        + '<div style="margin-bottom:.75rem"><strong>Policy</strong>'
        + f'<div style="margin-top:.4rem;color:var(--muted)">{policy_text}</div>'
        + "</div>"
        + '<div><strong>Best-practice improvements</strong><ul style="margin:.5rem 0 0 1.1rem">'
        + practices_html
        + "</ul></div>"
        + "</div></div>"
    )


__all__ = [
    "_parse_expiry_datetime",
    "_jwt_expiry_datetime",
    "_collect_token_expiry_items",
    "_parse_duration_seconds",
    "_duration_label",
    "_load_saas_sso_stats",
    "build_auth_summary_html",
]
