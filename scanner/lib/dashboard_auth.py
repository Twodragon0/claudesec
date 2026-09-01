import os
import json
import base64
import warnings
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


def _warn_asset_data_unusable(data_path, reason):
    """Make a degraded SaaS SSO card observable instead of a silent omission."""
    warnings.warn(
        f"Ignoring unusable asset data at {data_path}: {reason}. "
        "SaaS SSO coverage will render as 'N/A'.",
        RuntimeWarning,
        stacklevel=3,
    )


def _load_saas_sso_stats():
    """Load SaaS SSO stats from .claudesec-assets/dashboard-data.json if available.

    The asset file is produced by a separate collector, so neither its encoding
    nor its shape is guaranteed. Every read/decode/shape failure degrades to
    ``None`` ("no SaaS SSO data") plus a ``RuntimeWarning`` — a malformed asset
    file must not take down the whole dashboard build via
    ``build_auth_summary_html``.

    ONE UNREADABLE ENTRY REJECTS THE WHOLE LIST, DELIBERATELY. The obvious
    alternative — drop the bad entry, keep the rest — was raised in review and is
    wrong here, because this function's output is a DENOMINATOR. It reports "X of
    Y SaaS apps use SSO", and dropping an entry shrinks Y silently while the
    percentage keeps looking exactly as confident. Measured on a five-app file
    with one unreadable entry, a skip-the-entry implementation returns
    ``{'sso_count': 3, 'total': 4, 'pct': 75}`` — byte-identical to what it
    returns for a CLEAN four-app file. Nothing downstream can tell a fifth app
    existed, and the true coverage is somewhere in 60-80%.

    That is the "corrupt is worse than missing" shape this repo has paid for
    twice: #471, where an unreadable Prowler file became an empty-but-present
    provider and scored as a clean prowler-backed PASS instead of degrading to
    keyword matching; and #489, where a corrupt nmap artifact made
    ``network_evidence`` truthy and suppressed the very warning that said the
    evidence was missing. Returning ``None`` renders the section as "N/A" with a
    named ``RuntimeWarning`` — visibly weaker, and therefore honest.

    Pinned by ``test_dashboard_auth_asset_degradation``'s mixed-list cases. They
    exist because the all-entries-bad fixture CANNOT distinguish the two designs:
    a skip implementation that warns once passes all 54 pre-existing tests while
    silently truncating the denominator (measured 2026-09-01).
    """
    scan_dir = os.environ.get("SCAN_DIR", ".")
    data_path = os.path.join(scan_dir, ".claudesec-assets", "dashboard-data.json")
    try:
        with open(data_path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        # Asset collection was never run — expected, not an anomaly.
        return None
    except (OSError, ValueError) as exc:
        # ValueError covers json.JSONDecodeError (truncated/invalid JSON) AND
        # UnicodeDecodeError (non-UTF-8 byte); they are sibling ValueError
        # subclasses, so catching JSONDecodeError alone missed the latter.
        _warn_asset_data_unusable(data_path, f"{type(exc).__name__}: {exc}")
        return None

    if not isinstance(data, dict):
        _warn_asset_data_unusable(
            data_path, f"top-level JSON is {type(data).__name__}, expected an object"
        )
        return None
    saas = data.get("saas") or []
    if not isinstance(saas, list):
        _warn_asset_data_unusable(
            data_path, f"'saas' is {type(saas).__name__}, expected a list"
        )
        return None
    if not saas:
        return None
    sso_keywords = ("sso", "okta", "saml")
    sso_count = 0
    for entry in saas:
        if not isinstance(entry, dict):
            _warn_asset_data_unusable(
                data_path, f"'saas' entry is {type(entry).__name__}, expected an object"
            )
            return None
        auth = str(entry.get("auth") or "").lower()
        if any(k in auth for k in sso_keywords):
            sso_count += 1
    total = len(saas)
    pct = round(sso_count / total * 100) if total else 0
    non_sso = total - sso_count
    return {
        "sso_count": sso_count,
        "total": total,
        "pct": pct,
        "non_sso": non_sso,
    }


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
    "_warn_asset_data_unusable",
    "_load_saas_sso_stats",
    "build_auth_summary_html",
]
