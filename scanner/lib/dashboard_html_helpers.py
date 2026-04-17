#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Helpers
Extracted helper functions for HTML generation used by dashboard-gen.py.
"""

import hashlib
import os
import shutil
import sys
from collections import defaultdict
from typing import Any

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import h, SEV_ORDER, sev_badge
from dashboard_mapping import CATEGORY_META


# ── Severity sort weight (promoted from generate_dashboard local) ───────────
_SEV_WEIGHT = {"Critical": 100, "High": 10, "Medium": 3, "Low": 1, "Informational": 0}


# ── Category / scanner helpers ──────────────────────────────────────────────

def _infer_category(fid):
    prefix = fid.split("-")[0].upper() if "-" in fid else fid.upper()
    return {
        "IAM": "access-control",
        "INFRA": "infra",
        "NET": "network",
        "TLS": "network",
        "CICD": "cicd",
        "CODE": "code",
        "SAST": "code",
        "AI": "ai",
        "LLM": "ai",
        "CLOUD": "cloud",
        "AWS": "cloud",
        "GCP": "cloud",
        "AZURE": "cloud",
        "MAC": "macos",
        "CIS": "macos",
        "SAAS": "saas",
        "ZIA": "saas",
        "WIN": "windows",
        "KISA": "windows",
        "PROWLER": "prowler",
        "DOCKER": "infra",
        "TRIVY": "network",
        "NMAP": "network",
    }.get(prefix, "other")


def _scanner_default_action(category):
    return {
        "access-control": "Enforce MFA/SSO, tighten session and token handling, and remove weak secrets from code/config.",
        "infra": "Harden infrastructure defaults, reduce exposed services, and apply baseline controls for containers and IaC.",
        "network": "Close unnecessary ports, enforce TLS hardening, and continuously validate security headers/certificate posture.",
        "cicd": "Add security gates (SAST/SCA/secrets), require protected branches, and block unsafe workflow permissions.",
        "code": "Prioritize injection/crypto findings, apply secure coding patterns, and enforce automated static analysis in CI.",
        "ai": "Add prompt/data guardrails, tighten model/tool permissions, and monitor for sensitive output leakage.",
        "cloud": "Apply least privilege IAM, disable public exposure by default, and enable audit logging with alerting.",
        "macos": "Align host settings to CIS controls and remediate high-impact endpoint hardening gaps first.",
        "saas": "Rotate and scope API tokens, enforce provider security baselines, and verify integration auth posture.",
        "windows": "Remediate KISA high-risk findings first and enforce endpoint hardening/monitoring baselines.",
        "prowler": "Fix critical/high cloud findings first, then medium findings with ownership and due dates.",
        "other": "Review finding details and apply control owner-driven remediation with verification evidence.",
    }.get(
        category, "Review findings and apply prioritized remediation with verification."
    )


# ── Redaction / link helpers ────────────────────────────────────────────────

def _redact_target(value: str) -> str:
    show = os.environ.get("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", "0") == "1"
    v = (value or "").strip()
    if show or not v:
        return v
    h10 = hashlib.sha256(v.encode("utf-8")).hexdigest()[:10]
    return f"target-{h10}"


def _rel_link(path: str, label: str | None = None) -> str:
    # Keep links relative so they work under `python -m http.server` and file://.
    p = (path or "").lstrip("/")
    text = label or p
    return f'<a href="{h(p)}" class="mono" style="color:var(--accent);text-decoration:underline">{h(text)}</a>'


# ── Command detection helpers ───────────────────────────────────────────────

def _has_cmd(cmd: str) -> bool:
    try:
        return shutil.which(cmd) is not None
    except Exception:
        return False


def _cmd_pill(name: str, present: bool, note: str = "") -> str:
    cls = "env-on" if present else "env-off"
    dot = (
        '<span class="ep-st on">●</span>'
        if present
        else '<span class="ep-st off">○</span>'
    )
    note_html = (
        f'<div style="margin-top:.2rem;color:var(--muted);font-size:.72rem">{h(note)}</div>'
        if note
        else ""
    )
    return (
        f'<div class="env-pill {cls}" style="display:block">'
        f'<div style="display:flex;align-items:center;gap:.4rem">'
        f'<span class="ep-name">{h(name)}</span>{dot}'
        f"</div>{note_html}</div>"
    )


# ── Severity computation helpers ────────────────────────────────────────────

def _compute_severity_counts(prov_summary, findings_list):
    """Compute severity counts from provider summary and scanner findings."""
    n_crit = sum(v["critical"] for v in prov_summary.values())
    n_high = sum(v["high"] for v in prov_summary.values())
    n_med = sum(v["medium"] for v in prov_summary.values())
    n_low = sum(v["low"] for v in prov_summary.values())
    n_info = sum(v.get("informational", 0) for v in prov_summary.values())
    # Merge scanner findings into severity counts for unified bar
    policy_022_top = 0
    for f in findings_list:
        sev = (f.get("severity") or "").lower()
        fid = str(f.get("id") or "").upper()
        if "SAAS-API-022" in fid:
            policy_022_top += 1
        if sev == "critical":
            n_crit += 1
        elif sev == "high":
            n_high += 1
        elif sev == "medium":
            n_med += 1
        elif sev == "low":
            n_low += 1
    return {
        "n_crit": n_crit,
        "n_high": n_high,
        "n_med": n_med,
        "n_low": n_low,
        "n_info": n_info,
        "policy_022_top": policy_022_top,
    }


def _compute_severity_bars(n_crit, n_high, n_med, n_low, warnings):
    """Compute severity bar percentages."""
    sev_total = max(n_crit + n_high + n_med + n_low + warnings, 1)
    return {
        "bar_crit": round(n_crit / sev_total * 100, 1),
        "bar_high": round(n_high / sev_total * 100, 1),
        "bar_med": round(n_med / sev_total * 100, 1),
        "bar_warn": round(warnings / sev_total * 100, 1),
        "bar_low": round(n_low / sev_total * 100, 1),
    }


# ── Template key mapping ───────────────────────────────────────────────────

_TEMPLATE_KEYS = [
    "VERSION",
    "NOW",
    "DURATION",
    "PASSED",
    "FAILED",
    "WARNINGS",
    "SKIPPED",
    "SCORE",
    "GRADE",
    "GRADE_COLOR",
    "ACTIVE",
    "SCORE_DASH",
    "N_CRIT",
    "N_HIGH",
    "N_MED",
    "N_LOW",
    "N_WARN",
    "POLICY_022_TOP",
    "N_INFO",
    "TOTAL_PASSED",
    "TOTAL_PROWLER_FAIL",
    "TOTAL_PROWLER_PASS",
    "TOTAL_ALL",
    "TOTAL_ISSUES",
    "ENV_HTML",
    "ENV_CONNECTED",
    "ENV_TOTAL",
    "PROV_CARDS",
    "PROV_TABLE",
    "SCANNER_ROWS",
    "SCANNER_CAT_SUMMARY",
    "SCANNER_INSIGHTS_HTML",
    "SCANNER_TOTAL",
    "PASS_PCT",
    "FAIL_PCT",
    "WARN_PCT",
    "GH_TABLE",
    "GH_TOTAL",
    "AWS_TABLE",
    "AWS_TOTAL",
    "GCP_TABLE",
    "GCP_TOTAL",
    "GWS_TABLE",
    "GWS_TOTAL",
    "K8S_TABLE",
    "K8S_TOTAL",
    "AZURE_TABLE",
    "AZURE_TOTAL",
    "M365_TABLE",
    "M365_TOTAL",
    "IAC_TABLE",
    "IAC_TOTAL",
    "OWASP_HTML",
    "ARCH_HTML",
    "ARCH_IMG",
    "COMP_HTML",
    "HISTORY_JSON",
    "TOP_FINDINGS",
    "BAR_CRIT",
    "BAR_HIGH",
    "BAR_MED",
    "BAR_WARN",
    "BAR_LOW",
    "NETWORK_TOOLS_HTML",
    "NETWORK_TOOLS_BADGE",
    "AUDIT_POINTS_HTML",
    "SCANNER_ISSUES",
    "SCAN_SCOPE_HTML",
    "AUTH_SUMMARY_HTML",
    "ARCH_OVERVIEW_HTML",
    "NETWORK_SUMMARY_HTML",
    "POLICIES_HTML",
    "SERVICE_SURFACE_HTML",
    "PRIORITY_QUEUE_HTML",
]


def _build_replacements(*values):
    return dict(zip(_TEMPLATE_KEYS, (str(v) for v in values)))
