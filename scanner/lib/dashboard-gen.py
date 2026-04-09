#!/usr/bin/env python3
"""
ClaudeSec Dashboard Generator v0.7.0
Generates a tabbed HTML security dashboard from scan results and Prowler OCSF data.

Modules:
  - dashboard_utils: Constants, TypedDicts, utility functions
  - dashboard_mapping: OWASP/Compliance/Architecture mapping data
  - dashboard_api_client: GitHub API communication
  - dashboard_data_loader: File-based data loading and parsing
  - dashboard_auth: Authentication/token expiry summary
"""

import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import Any

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from csp_utils import generate_nonce, inject_csp_nonce

# ── Module imports (extracted from monolithic dashboard-gen.py) ──────────────
from dashboard_utils import (  # noqa: F401
    VERSION,
    AUDIT_POINTS_REPO, AUDIT_POINTS_CACHE_TTL_HOURS,
    CLAUDESEC_DASHBOARD_OFFLINE_ENV,
    MS_BEST_PRACTICES_CACHE_TTL_HOURS, MS_INCLUDE_SCUBAGEAR_ENV,
    MS_SOURCE_FILTER_ENV,
    TRUST_LEVEL_ORDER, TRUST_LEVEL_FILTER_MAP, TRUST_FILTER_TOKEN_ORDER,
    _ALLOWED_FETCH_HOSTS, SEV_ORDER,
    AuditPointFile, AuditPointProduct, AuditPointsData,
    TrivySummary, TrivyVuln,
    NmapHost, NmapScan, SSLScanResult, NetworkToolResult,
    DatadogLogEntry, DatadogSummary, DatadogSeveritySummary, DatadogLogsData,
    GitHubContentItem, RepoFocusFile, RepoFocusData,
    MicrosoftBestPracticeSource, MicrosoftBestPracticesData,
    h, _is_env_truthy, _is_best_practice_file,
    _resolve_source_filter, _normalized_source_filter, _trust_token_from_level,
    comp_slug, sev_badge,
)

from dashboard_mapping import (  # noqa: F401
    CHECK_EN_MAP, DEFAULT_SUMMARY, DEFAULT_ACTION, get_check_en,
    OWASP_2025, OWASP_CHECK_MAP, OWASP_LLM_2025, map_findings_to_owasp,
    COMPLIANCE_FRAMEWORKS, COMPLIANCE_CONTROL_MAP,
    map_compliance, _match_prowler_compliance,
    ARCH_DOMAINS, ARCH_DOMAIN_LINKS, OWASP_TO_ARCH, map_architecture,
    CATEGORY_META,
)

from dashboard_api_client import (  # noqa: F401
    MS_BEST_PRACTICES_REPO_SOURCES, SAAS_BEST_PRACTICES_SOURCES,
    SAAS_BEST_PRACTICES_CACHE_TTL_HOURS,
    _github_api_json, _fetch_audit_points_from_github,
    _fetch_repo_focus_files,
    _fetch_microsoft_best_practices_from_github,
    _fetch_saas_best_practices_from_github,
    _fetch_markdown_preview,
)

from dashboard_data_loader import (  # noqa: F401
    load_scan_results, load_prowler_files, load_scan_history,
    load_audit_points_detected, load_audit_points,
    load_microsoft_best_practices, load_saas_best_practices,
    load_network_tool_results, load_datadog_logs,
    analyze_prowler, _parse_ocsf_json, _normalize_provider,
    github_findings, aws_findings, gcp_findings, gws_findings,
    k8s_findings, azure_findings, m365_findings, iac_findings,
    get_env_status,
)

from dashboard_auth import (  # noqa: F401
    build_auth_summary_html,
    _parse_expiry_datetime, _jwt_expiry_datetime,
    _collect_token_expiry_items,
    _parse_duration_seconds, _duration_label,
    _load_saas_sso_stats,
)


# ── HTML Generation ──────────────────────────────────────────────────────────

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


def _build_scanner_section(findings_list):
    SCANNER_TO_ARCH = {
        "network": [0],
        "access-control": [1, 2],
        "code": [2, 5],
        "cicd": [3, 5],
        "cloud": [4],
        "infra": [4, 5],
        "macos": [],
        "ai": [],
        "saas": [],
        "windows": [],
        "prowler": [],
        "other": [],
    }
    cat_order = [
        "access-control",
        "infra",
        "network",
        "cicd",
        "code",
        "ai",
        "cloud",
        "macos",
        "saas",
        "windows",
        "prowler",
        "other",
    ]
    grouped = defaultdict(list)
    for f in findings_list:
        cat = f.get("category") or _infer_category(f.get("id", ""))
        grouped[cat].append(f)
    scanner_rows = ""
    scanner_cat_summary = ""
    scanner_insights_html = ""
    for cat in cat_order:
        items = grouped.get(cat, [])
        if not items:
            continue
        items.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "medium"), 9))
        meta = CATEGORY_META.get(cat, CATEGORY_META["other"])
        arch_links = ""
        for aidx in SCANNER_TO_ARCH.get(cat, []):
            if aidx < len(ARCH_DOMAINS):
                d = ARCH_DOMAINS[aidx]
                arch_links += f'<button class="arch-link-chip arch-sm" onclick="switchTab(\'arch\',\'arch-dom-{aidx}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
        arch_row = (
            f'<div class="scanner-arch-links"><span class="arch-links-label">Related architecture</span>{arch_links}</div>'
            if arch_links
            else ""
        )
        scanner_rows += f'<tr class="cat-header" id="scanner-cat-{cat}"><td colspan="5"><span class="cat-hdr-icon">{meta["icon"]}</span> {h(meta["label"])}<span class="cat-hdr-desc">{h(meta["desc"])}</span>{arch_row}</td></tr>'
        for f in items:
            sev = f.get("severity", "medium")
            sev_cls = f"sev-{sev}"
            badge = sev_badge(sev)
            fid = h(f.get("id", ""))
            title = h(f.get("title", ""))
            details = h(f.get("details", ""))
            status_icon = "✗" if sev in ("critical", "high", "medium") else "⚠"
            status_label = (
                "Fail" if sev in ("critical", "high", "medium") else "Warning"
            )
            location = h(f.get("location", ""))
            loc_html = f' <span class="scan-loc">📍 <code>{location}</code></span>' if location else ""
            has_expandable = location or details
            row_cls = f'{sev_cls} expandable' if has_expandable else sev_cls
            toggle = ' data-action="toggleRow"' if has_expandable else ""
            scanner_rows += f'<tr class="{row_cls}"{toggle}><td>{badge}</td><td><span class="scan-status-{sev}">{status_icon} {status_label}</span></td><td class="mono">{fid}</td><td>{title}</td><td class="fix">{details if details else "<em>-</em>"}</td></tr>'
            if has_expandable:
                detail_parts = []
                if details:
                    detail_parts.append(f'<p style="margin-bottom:.4rem"><strong>Remediation:</strong> {details}</p>')
                if location:
                    detail_parts.append(f'<p style="margin-top:.3rem"><strong>Location:</strong> <code style="font-size:.75rem;word-break:break-all">{location}</code></p>')
                scanner_rows += f'<tr class="row-detail"><td colspan="5"><div class="detail-panel">{"".join(detail_parts)}</div></td></tr>'
        scanner_cat_summary += f'<div class="scat-chip" data-action="scrollToCategory" data-arg="{h(cat)}" title="Jump to {h(meta["label"])} findings"><span class="scat-icon">{meta["icon"]}</span><span class="scat-label">{meta["label"]}</span><span class="scat-cnt">{len(items)}</span></div>'
    if not scanner_rows:
        scanner_rows = '<tr><td colspan="5" class="scan-empty" style="padding:1.5rem;text-align:center;color:var(--muted);font-size:.9rem">No failed or warning findings from the local scanner. All reported checks passed or were skipped.</td></tr>'

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "warning": 0, "low": 0}
    cat_counts = {}
    for f in findings_list:
        sev = str(f.get("severity") or "").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        cat = f.get("category") or _infer_category(f.get("id", ""))
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    top_categories = sorted(cat_counts.items(), key=lambda x: (-x[1], x[0]))[:3]
    top_findings = sorted(
        findings_list,
        key=lambda x: (
            SEV_ORDER.get((x.get("severity") or "").lower(), 9),
            str(x.get("id") or ""),
        ),
    )[:6]

    summary_parts = []
    for k, lbl in (
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("warning", "warning"),
        ("low", "low"),
    ):
        if sev_counts[k] > 0:
            summary_parts.append(f"{sev_counts[k]} {lbl}")
    summary_line = (
        ", ".join(summary_parts)
        if summary_parts
        else "No active failed/warning findings"
    )

    top_cat_line = (
        " · ".join(
            f"{h(CATEGORY_META.get(cat, CATEGORY_META['other'])['label'])} ({cnt})"
            for cat, cnt in top_categories
        )
        if top_categories
        else "No category hotspots detected"
    )

    detail_list = ""
    for f in top_findings:
        sev = (f.get("severity") or "medium").lower()
        title = h(f.get("title") or "Untitled finding")
        fid = h(f.get("id") or "N/A")
        fcat = f.get("category") or _infer_category(f.get("id", ""))
        detail_list += f'<li data-action="scrollToCategory" data-arg="{h(fcat)}" title="Jump to {fid}" style="cursor:pointer"><span class="si-sev si-{sev}">{sev}</span><span class="mono">{fid}</span> {title}</li>'
    if not detail_list:
        detail_list = "<li>No outstanding scanner findings.</li>"

    action_items = []
    seen_actions = set()
    for f in top_findings:
        cat = f.get("category") or _infer_category(f.get("id", ""))
        raw_action = (f.get("details") or "").strip()
        action = raw_action if raw_action else _scanner_default_action(cat)
        action_norm = action.lower()
        if action_norm in seen_actions:
            continue
        seen_actions.add(action_norm)
        action_items.append(action)
        if len(action_items) >= 5:
            break
    if not action_items:
        action_items = [
            "Continue running regular scans and keep remediation SLAs for any new critical/high findings."
        ]

    action_list = "".join(f"<li>{h(item)}</li>" for item in action_items)
    scanner_insights_html = (
        '<div class="scanner-insights-grid">'
        '<div class="scanner-insight-card">'
        '<div class="scanner-insight-title">Summary</div>'
        f'<p class="scanner-insight-text">{h(summary_line)}</p>'
        f'<p class="scanner-insight-sub">Hotspots: {top_cat_line}</p>'
        "</div>"
        '<div class="scanner-insight-card">'
        '<div class="scanner-insight-title">Detail (Top findings)</div>'
        f'<ul class="scanner-insight-list">{detail_list}</ul>'
        "</div>"
        '<div class="scanner-insight-card">'
        '<div class="scanner-insight-title">Action plan</div>'
        f'<ol class="scanner-insight-action-list">{action_list}</ol>'
        "</div>"
        "</div>"
    )

    return scanner_rows, scanner_cat_summary, scanner_insights_html


# ── Helper functions extracted from _build_overview_blocks ─────────────────


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


def _build_provider_cards(prov_summary):
    """Build provider card HTML snippets."""
    prov_cards = ""
    prov_icons = {
        "aws": "☁",
        "github": "🐙",
        "iac": "📋",
        "kubernetes": "☸",
        "azure": "◇",
        "gcp": "◈",
        "googleworkspace": "🏢",
        "m365": "📧",
        "cloudflare": "🌐",
        "nhn": "☁",
    }
    prov_labels = {
        "aws": "AWS",
        "github": "GitHub",
        "iac": "IaC",
        "kubernetes": "K8s",
        "azure": "Azure",
        "gcp": "GCP",
        "googleworkspace": "Google Workspace",
        "m365": "Microsoft 365",
        "cloudflare": "Cloudflare",
        "nhn": "NHN Cloud",
    }
    for pname, pdata in sorted(prov_summary.items()):
        icon = prov_icons.get(pname, "☁")
        label = prov_labels.get(pname, pname)
        ptotal = pdata["total_fail"] + pdata["total_pass"]
        pfail = pdata["total_fail"]
        pcrit = pdata["critical"]
        phigh = pdata["high"]
        prov_cards += '<div class="prov-card" onclick="switchTab(\'prowler\')">'
        prov_cards += f'<div class="prov-card-icon">{icon}</div><div class="prov-card-name">{label}</div>'
        prov_cards += f'<div class="prov-card-num">{pfail}<span class="prov-card-total">/{ptotal}</span></div><div class="prov-card-sev">'
        if pcrit > 0:
            prov_cards += f'<span class="pcs-crit">{pcrit}C</span>'
        if phigh > 0:
            prov_cards += f'<span class="pcs-high">{phigh}H</span>'
        if pdata["medium"] > 0:
            prov_cards += f'<span class="pcs-med">{pdata["medium"]}M</span>'
        prov_cards += "</div></div>"
    return prov_cards


def _build_service_surface_html(
    findings_list,
    total_checks,
    failed,
    warnings,
    prov_summary,
    env_connected,
    env_total,
    net_data,
    datadog_data,
    arch_domains,
    audit_points_data,
    ms_best_practices_data,
):
    """Build high-level product coverage cards for the Overview tab."""
    datadog_data = datadog_data or {}
    net_data = net_data or {}
    audit_points_data = audit_points_data or {}
    ms_best_practices_data = ms_best_practices_data or {}

    scanner_cats_seen = sorted(
        {
            str(f.get("category") or _infer_category(f.get("id", ""))).strip().lower()
            for f in findings_list
            if str(f.get("category") or f.get("id") or "").strip()
        }
    )
    scanner_labels = [
        CATEGORY_META.get(cat, CATEGORY_META["other"])["label"]
        for cat in scanner_cats_seen
    ]
    providers_run = sum(
        1
        for pdata in prov_summary.values()
        if int(pdata.get("total_fail", 0)) + int(pdata.get("total_pass", 0)) > 0
    )
    providers_total = max(len(prov_summary), 1)
    total_prowler_fail = sum(int(v.get("total_fail", 0)) for v in prov_summary.values())
    total_prowler_pass = sum(int(v.get("total_pass", 0)) for v in prov_summary.values())
    trivy_summary = net_data.get("trivy_summary") or {}
    trivy_total = sum(int(trivy_summary.get(k, 0)) for k in ("critical", "high", "medium", "low"))
    nmap_count = len(net_data.get("nmap_scans", []) or [])
    ssl_count = len(net_data.get("sslscan_results", []) or [])
    datadog_total = int((datadog_data.get("summary") or {}).get("total", 0))
    datadog_signal_total = int((datadog_data.get("signal_summary") or {}).get("total", 0))
    datadog_case_total = int((datadog_data.get("case_summary") or {}).get("total", 0))
    arch_attention = sum(1 for dom in arch_domains if int(dom.get("fail_count", 0)) > 0)
    audit_product_count = len(audit_points_data.get("products", []) or [])
    ms_source_count = len(ms_best_practices_data.get("sources", []) or [])

    cards = [
        {
            "label": "Local scanner",
            "value": f"{total_checks} checks",
            "detail": (
                f"{len(scanner_labels)} categories · {failed + warnings} actionable "
                f"({', '.join(scanner_labels[:2]) if scanner_labels else 'pass/skip only'})"
            ),
        },
        {
            "label": "Cloud CSPM",
            "value": f"{providers_run}/{providers_total} providers",
            "detail": f"{total_prowler_fail} failed · {total_prowler_pass} passed",
        },
        {
            "label": "Integrations",
            "value": f"{env_connected}/{env_total or 1} connected",
            "detail": (
                "All configured providers connected"
                if env_total and env_connected == env_total
                else f"{max(env_total - env_connected, 0)} providers still need setup"
            ),
        },
        {
            "label": "Architecture",
            "value": f"{len(arch_domains)} domains",
            "detail": (
                f"{arch_attention} domains need attention"
                if arch_attention
                else "No mapped architecture findings in this run"
            ),
        },
        {
            "label": "Network telemetry",
            "value": f"{trivy_total + datadog_total + datadog_signal_total + datadog_case_total}",
            "detail": f"Trivy {trivy_total} · Nmap {nmap_count} · TLS {ssl_count}",
        },
        {
            "label": "Guidance hub",
            "value": f"{audit_product_count + ms_source_count} sources",
            "detail": f"Audit points {audit_product_count} · Best-practice repos {ms_source_count}",
        },
    ]

    html = '<div class="coverage-grid">'
    for card in cards:
        html += (
            '<div class="coverage-card">'
            f'<div class="coverage-label">{h(card["label"])}</div>'
            f'<div class="coverage-value">{h(card["value"])}</div>'
            f'<div class="coverage-detail">{h(card["detail"])}</div>'
            '</div>'
        )
    html += '</div>'
    return html


def _build_priority_queue_html(
    findings_list,
    prov_summary,
    env_connected,
    env_total,
    net_data,
    datadog_data,
):
    """Build prioritized next-action cards for the Overview tab."""
    datadog_data = datadog_data or {}
    net_data = net_data or {}

    provider_labels = {
        "aws": "AWS",
        "github": "GitHub",
        "iac": "IaC",
        "kubernetes": "Kubernetes",
        "azure": "Azure",
        "gcp": "GCP",
        "googleworkspace": "Google Workspace",
        "m365": "Microsoft 365",
        "cloudflare": "Cloudflare",
        "nhn": "NHN Cloud",
    }

    scanner_urgent = [
        f for f in findings_list if str(f.get("severity") or "").lower() in ("critical", "high")
    ]
    scanner_by_category: dict[str, int] = {}
    for finding in findings_list:
        category = str(
            finding.get("category") or _infer_category(finding.get("id", ""))
        ).strip().lower()
        if not category:
            continue
        scanner_by_category[category] = scanner_by_category.get(category, 0) + 1
    top_scanner_categories = sorted(
        scanner_by_category.items(), key=lambda item: (-item[1], item[0])
    )[:3]

    provider_failures = sorted(
        (
            (
                provider_labels.get(name, str(name).upper()),
                int(data.get("critical", 0)) + int(data.get("high", 0)),
                int(data.get("total_fail", 0)),
            )
            for name, data in prov_summary.items()
        ),
        key=lambda item: (-item[1], -item[2], item[0]),
    )
    top_provider = next((item for item in provider_failures if item[2] > 0), None)
    prowler_urgent = sum(item[1] for item in provider_failures)

    trivy_summary = net_data.get("trivy_summary") or {}
    network_evidence = any(
        [
            sum(int(trivy_summary.get(k, 0)) for k in ("critical", "high", "medium", "low")),
            len(net_data.get("nmap_scans", []) or []),
            len(net_data.get("sslscan_results", []) or []),
            int((datadog_data.get("summary") or {}).get("total", 0)),
            int((datadog_data.get("signal_summary") or {}).get("total", 0)),
            int((datadog_data.get("case_summary") or {}).get("total", 0)),
        ]
    )
    visibility_gaps = []
    if env_total and env_connected < env_total:
        visibility_gaps.append(f"{env_total - env_connected} disconnected integration(s)")
    if not any(int(data.get("total_fail", 0)) + int(data.get("total_pass", 0)) > 0 for data in prov_summary.values()):
        visibility_gaps.append("cloud CSPM evidence missing")
    if not network_evidence:
        visibility_gaps.append("network or Datadog telemetry missing")

    focus_items = []
    if top_scanner_categories:
        focus_items.extend(
            f'{CATEGORY_META.get(cat, CATEGORY_META["other"])["label"]} ({count})'
            for cat, count in top_scanner_categories[:2]
        )
    if top_provider:
        focus_items.append(f"{top_provider[0]} ({top_provider[2]})")

    cards: list[dict[str, Any]] = []
    urgent_total = len(scanner_urgent) + prowler_urgent
    if urgent_total:
        dominant_area = "Cloud CSPM" if prowler_urgent > len(scanner_urgent) else "Local scanner"
        chips = [f"Local {len(scanner_urgent)}", f"Cloud {prowler_urgent}"]
        if top_provider and top_provider[2] > 0:
            chips.append(f"Top provider {top_provider[0]}")
        cards.append(
            {
                "tone": "critical" if urgent_total >= 5 else "warning",
                "kicker": "Immediate",
                "title": f"Burn down {urgent_total} critical/high findings",
                "body": (
                    f"{dominant_area} is contributing the larger share of urgent issues. "
                    "Start with the highest-volume source before widening scope."
                ),
                "chips": chips,
                "footer": "Jump to top findings",
                "onclick": "document.getElementById('top-findings-section').scrollIntoView({behavior:'smooth'});",
            }
        )
    else:
        cards.append(
            {
                "tone": "success",
                "kicker": "Immediate",
                "title": "No critical/high findings in this run",
                "body": "Use the remaining items to tighten coverage, medium findings, and operational hygiene.",
                "chips": ["Urgent backlog clear"],
                "footer": "Review medium and warning findings",
                "onclick": "document.getElementById('scanner-section').scrollIntoView({behavior:'smooth'});",
            }
        )

    if visibility_gaps:
        cards.append(
            {
                "tone": "warning",
                "kicker": "Coverage",
                "title": "Close visibility gaps before trusting the score",
                "body": (
                    "A partial scan can look cleaner than the real environment. "
                    "Connect the missing evidence sources, then rerun the dashboard."
                ),
                "chips": visibility_gaps[:3],
                "footer": "Open environment and network setup",
                "onclick": "switchTab('networktools');",
            }
        )
    else:
        cards.append(
            {
                "tone": "success",
                "kicker": "Coverage",
                "title": "Evidence sources are connected",
                "body": "Environment, cloud, and telemetry inputs are present, so prioritization is based on a broader signal set.",
                "chips": ["Coverage baseline met"],
                "footer": "Inspect coverage details",
                "onclick": "document.getElementById('scanner-section').scrollIntoView({behavior:'smooth'});",
            }
        )

    if focus_items:
        cards.append(
            {
                "tone": "info",
                "kicker": "Focus",
                "title": "Concentrate the next improvement pass",
                "body": (
                    "Findings are clustered in a few areas. Fix those hotspots first, then retest to collapse the backlog faster."
                ),
                "chips": focus_items[:3],
                "footer": "Open the dominant area",
                "onclick": (
                    "switchTab('prowler');"
                    if top_provider and (not top_scanner_categories or top_provider[2] >= top_scanner_categories[0][1])
                    else "document.getElementById('scanner-section').scrollIntoView({behavior:'smooth'});"
                ),
            }
        )
    else:
        cards.append(
            {
                "tone": "info",
                "kicker": "Focus",
                "title": "Use guidance and architecture tabs for hardening",
                "body": "When findings are low, the next wins come from best-practice adoption, design review, and missing telemetry setup.",
                "chips": ["Architecture", "Code security", "Network tooling"],
                "footer": "Review guidance surfaces",
                "onclick": "switchTab('bestpractices');",
            }
        )

    html = '<div class="priority-grid">'
    for card in cards:
        html += (
            f'<button class="priority-card priority-{h(card["tone"])}" onclick="{card["onclick"]}" type="button">'
            f'<div class="priority-kicker">{h(card["kicker"])}</div>'
            f'<div class="priority-title">{h(card["title"])}</div>'
            f'<div class="priority-body">{h(card["body"])}</div>'
            '<div class="priority-meta">'
        )
        for chip in card["chips"]:
            html += f'<span class="priority-chip">{h(chip)}</span>'
        html += (
            '</div>'
            f'<div class="priority-footer">{h(card["footer"])} →</div>'
            '</button>'
        )
    html += '</div>'
    return html


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


def _build_top_findings(findings_list, all_findings):
    """Build top findings HTML from scanner and Prowler findings."""
    # Top findings: merge scanner critical/high with Prowler; group by (severity, check, provider) and sort by severity then count
    top_findings_html = ""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _add_grouped(severity: str, check: str, provider: str, msg: str, resource: str = "") -> None:
        key = (severity, check, provider)
        if key not in grouped:
            grouped[key] = {"count": 0, "message": "", "resource": ""}
        grouped[key]["count"] = int(grouped[key]["count"]) + 1
        if not grouped[key]["message"]:
            grouped[key]["message"] = msg
        if resource and not grouped[key]["resource"]:
            grouped[key]["resource"] = resource

    for f in findings_list:
        sev = (f.get("severity") or "").lower()
        if sev in ("critical", "high"):
            msg = ((f.get("title") or "") + " " + (f.get("details") or ""))[:200]
            _add_grouped(sev.capitalize(), str(f.get("id", "")), "Scanner", msg)
    for ff in all_findings:
        if (ff.get("severity") or "") in ("Critical", "High"):
            prov = ff.get("provider", "Prowler")
            msg = (ff.get("message") or "")[:200]
            _add_grouped(
                str(ff.get("severity", "High")),
                str(ff.get("check", "")),
                str(prov),
                msg,
                str(ff.get("resource") or ""),
            )
    # Sort: Critical first, then High; within same severity by count descending
    combined = [
        {
            "severity": sev,
            "check": ck,
            "provider": prov,
            "count": int(d["count"]),
            "message": str(d["message"]),
            "resource": str(d.get("resource") or ""),
        }
        for (sev, ck, prov), d in grouped.items()
    ]
    combined.sort(
        key=lambda x: (
            0 if str(x["severity"]) == "Critical" else 1,
            -int(x["count"]),
            str(x["check"]),
        )
    )
    for ff in combined[:12]:
        cnt = int(ff["count"])
        cnt_html = (
            f' <span class="tf-cnt" title="{cnt} occurrence(s)">({cnt})</span>'
            if cnt > 1
            else ""
        )
        tab_click = (
            "switchTab('overview','scanner-section')"
            if str(ff["provider"]) == "Scanner"
            else "switchTab('prowler')"
        )
        severity_text = str(ff["severity"])
        provider_text = str(ff["provider"])
        check_text = str(ff["check"])
        message_text = str(ff["message"])
        en = get_check_en(check_text)
        resource_text = str(ff.get("resource") or "")
        res_html = f'<div class="tf-resource"><span class="tf-res-label">Location:</span> <code>{h(resource_text[:80])}</code></div>' if resource_text else ""
        action_html = f'<div class="tf-action"><span class="tf-act-label">Action:</span> {h(en["action"][:120])}</div>'
        top_findings_html += f'<div class="top-finding" onclick="{tab_click}"><div class="tf-badge">{sev_badge(severity_text)}</div><div class="tf-body"><div class="tf-check"><code>{h(check_text)}</code><span class="tf-prov">{h(provider_text.upper())}</span>{cnt_html}</div><div class="tf-msg">{h(message_text[:150])}</div>{res_html}{action_html}</div></div>'
    if not top_findings_html:
        top_findings_html = '<div class="top-finding" style="border-color:var(--border)"><div class="tf-body" style="color:var(--muted);font-size:.9rem">No critical or high findings from the scanner or Prowler in this scan. Check the Scanner and Prowler CSPM tabs for full results.</div></div>'
    return top_findings_html


def _build_network_config_section():
    """Build the network configuration cockpit card."""
    html = ""
    net_enabled = os.environ.get("CLAUDESEC_NETWORK_SCAN_ENABLED", "0")
    net_targets = os.environ.get("CLAUDESEC_NETWORK_SCAN_TARGETS", "")
    trivy_enabled = os.environ.get("CLAUDESEC_TRIVY_ENABLED", "1")
    html += '<div class="card"><div class="card-title">Network &amp; Security — Configuration</div><div style="padding:1rem 1.25rem">'
    html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-bottom:.9rem">'
    html += f'<div class="ssb-item"><strong>network_scan_enabled</strong><div class="mono" style="margin-top:.25rem">{h(net_enabled)}</div></div>'
    html += f'<div class="ssb-item"><strong>network_scan_targets</strong><div class="mono" style="margin-top:.25rem;word-break:break-all">{h(net_targets or "(empty)")}</div></div>'
    html += f'<div class="ssb-item"><strong>trivy_enabled</strong><div class="mono" style="margin-top:.25rem">{h(trivy_enabled)}</div></div>'
    html += "</div>"
    html += (
        '<div style="color:var(--muted);font-size:.82rem;line-height:1.6">'
    )
    html += "<div><strong>Enable network scanning</strong></div>"
    html += '<div class="mono" style="margin-top:.35rem;white-space:pre-wrap;border:1px solid var(--border);border-radius:10px;padding:.75rem;background:rgba(255,255,255,.02)">'
    html += "# Add to .claudesec.yml or export as environment variables\n"
    html += "export CLAUDESEC_NETWORK_SCAN_ENABLED=1\n"
    html += (
        'export CLAUDESEC_NETWORK_SCAN_TARGETS="your-domain.com:443"\n'
    )
    html += "./run --quick    # or ./run-all.sh\n"
    html += "</div>"
    html += '<div style="margin-top:.6rem">Results are saved to <code>.claudesec-network/</code>. Targets are redacted by default.</div>'
    html += "</div>"
    html += "</div></div>"
    return html, net_enabled, net_targets, trivy_enabled


def _build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled):
    """Build tooling detection, guidance, and install commands card."""
    html = ""
    # Tooling detection + guidance (why empty / how to fill).
    has_targets = bool((net_targets or "").strip())
    is_net_enabled = str(net_enabled).strip() in ("1", "true", "yes", "on")
    is_trivy_enabled = str(trivy_enabled).strip() not in ("0", "false", "no", "off")

    has_trivy = _has_cmd("trivy")
    has_nmap = _has_cmd("nmap")
    has_sslscan = _has_cmd("sslscan")
    has_testssl = False  # removed: use sslscan instead
    has_curl = _has_cmd("curl")
    has_python = _has_cmd("python3")

    html += '<div class="card"><div class="card-title">Tooling readiness (auto-detected)</div><div style="padding:1rem 1.25rem">'
    html += '<div class="env-grid" style="padding:0">'
    html += _cmd_pill(
        "python3", has_python, "required for normalization + dashboard"
    )
    html += _cmd_pill("curl", has_curl, "required for HTTP header scan")
    html += _cmd_pill(
        "trivy", has_trivy, "filesystem/config scan (.claudesec-network/trivy-*.json)"
    )
    html += _cmd_pill(
        "nmap", has_nmap, "optional port scan (when enabled + targets set)"
    )
    html += _cmd_pill(
        "sslscan", has_sslscan, "optional TLS scan (when enabled + targets set)"
    )
    html += "</div>"

    # Why sections are empty (explain with concrete next steps).
    missing_notes: list[str] = []
    if not is_net_enabled:
        missing_notes.append(
            "Enable network scanning: `export CLAUDESEC_NETWORK_SCAN_ENABLED=1` and set scan targets."
        )
    if is_net_enabled and not has_targets:
        missing_notes.append(
            "No targets configured: set `CLAUDESEC_NETWORK_SCAN_TARGETS` (comma-separated hosts/URLs)."
        )
    if is_net_enabled and has_targets and not has_curl:
        missing_notes.append("`curl` not found: HTTP header scan can't run.")
    if is_net_enabled and has_targets and not has_sslscan:
        missing_notes.append(
            "`sslscan` not found: TLS grade section will be empty. Install with `brew install sslscan`."
        )
    if is_trivy_enabled and not has_trivy:
        missing_notes.append(
            "`trivy` not found: Trivy section will be empty (install Trivy or disable with `CLAUDESEC_TRIVY_ENABLED=0`)."
        )

    # If artifacts still missing despite tooling, hint where to look.
    report = net_data.get("network_report")
    report_targets = report.get("targets", []) if isinstance(report, dict) else []
    has_http_artifacts = bool(report_targets)
    has_tls_artifacts = any(
        isinstance(t, dict) and isinstance(t.get("tls"), dict)
        for t in (report_targets or [])
        if isinstance(report_targets, list)
    )
    has_header_artifacts = any(
        isinstance(t, dict) and isinstance(t.get("http"), dict)
        for t in (report_targets or [])
        if isinstance(report_targets, list)
    )
    if is_net_enabled and has_targets and has_curl and not has_header_artifacts:
        missing_notes.append(
            "HTTP header artifacts not found yet. Re-run dashboard generation after enabling network scan; expected files: `.claudesec-network/http-headers-*.txt` and `network-report.v1.json`."
        )
    if (
        is_net_enabled
        and has_targets
        and (has_sslscan or has_testssl)
        and not has_tls_artifacts
    ):
        missing_notes.append(
            "TLS artifacts not found yet. Expected files: `.claudesec-network/sslscan-*.json` and `network-report.v1.json`."
        )

    if missing_notes:
        html += '<div style="margin-top:.85rem;border-top:1px solid var(--border);padding-top:.85rem">'
        html += (
            '<div style="font-weight:800;margin-bottom:.35rem">Next steps</div>'
        )
        html += (
            '<ul style="margin-left:1.1rem;color:var(--muted);line-height:1.7">'
        )
        for m in missing_notes[:8]:
            html += f"<li>{h(m)}</li>"
        html += "</ul>"
        html += "</div>"

    html += '<div style="margin-top:.9rem;border-top:1px solid var(--border);padding-top:.85rem">'
    html += '<div style="font-weight:800;margin-bottom:.35rem">Recommended install commands</div>'
    html += '<div class="mono" style="white-space:pre-wrap;border:1px solid var(--border);border-radius:10px;padding:.75rem;background:rgba(255,255,255,.02)">'
    html += "# macOS (Homebrew)\n"
    html += "brew install curl nmap sslscan\n"
    html += "brew install aquasecurity/trivy/trivy\n"
    html += "</div>"
    html += '<div style="margin-top:.5rem;color:var(--muted);font-size:.78rem;line-height:1.6">'
    html += "Tip: in CI, prefer pinned tool versions and run with least privilege. Only scan explicitly configured external targets."
    html += "</div></div>"
    html += "</div></div>"
    return html


def _build_artifact_links_section():
    """Build artifact quick links card."""
    html = ""
    # Artifact links (best-effort)
    artifacts = [
        ".claudesec-network/network-report.v1.json",
        ".claudesec-network/trivy-fs.json",
        ".claudesec-network/trivy-config.json",
        ".claudesec-datadog/datadog-logs-sanitized.json",
        ".claudesec-datadog/datadog-cloud-signals-sanitized.json",
        ".claudesec-datadog/datadog-cases-sanitized.json",
    ]
    existing = []
    for rel in artifacts:
        try:
            if os.path.isfile(rel):
                existing.append(rel)
        except Exception:
            pass
    if existing:
        html += '<div class="card"><div class="card-title">Artifacts (quick links)</div><div style="padding:1rem 1.25rem">'
        html += '<ul style="margin-left:1.2rem;line-height:1.7">'
        for rel in existing:
            html += f"<li>{_rel_link(rel)}</li>"
        html += "</ul></div></div>"
    return html


def _build_target_posture_table(net_data):
    """Build the target posture (HTTP/TLS/DNS summary) table."""
    html = ""
    # Target posture table from normalized network report (preferred)
    report = net_data.get("network_report")
    targets = report.get("targets", []) if isinstance(report, dict) else []
    if isinstance(targets, list) and targets:
        html += '<div class="card"><div class="card-title">Target posture (HTTP/TLS/DNS summary)</div><div style="max-height:60vh;overflow-y:auto">'
        html += '<table><thead><tr><th style="width:170px">Target</th><th style="width:70px">DNS</th><th style="width:70px">TLS</th><th style="width:70px">HTTP</th><th style="width:80px">HSTS</th><th style="width:110px">CSP</th><th class="r" style="width:90px">Header issues</th></tr></thead><tbody>'
        for t in targets[:50]:
            if not isinstance(t, dict):
                continue
            raw_target = str(t.get("target") or t.get("host") or "")
            label = _redact_target(raw_target)
            dns_raw = t.get("dns")
            dns = dns_raw if isinstance(dns_raw, dict) else {}
            ips = dns.get("ips") if isinstance(dns, dict) else []
            dns_cnt = len(ips) if isinstance(ips, list) else 0
            tls_raw = t.get("tls")
            tls = tls_raw if isinstance(tls_raw, dict) else {}
            tls_grade = str(tls.get("grade") or "unknown")
            http_raw = t.get("http")
            http = http_raw if isinstance(http_raw, dict) else {}
            http_status = http.get("status") or 0
            hsts_raw = http.get("hsts")
            hsts = hsts_raw if isinstance(hsts_raw, dict) else None
            hsts_max = hsts.get("max_age") if isinstance(hsts, dict) else None
            hsts_txt = str(hsts_max) if isinstance(hsts_max, int) else "—"
            csp_raw = http.get("csp")
            csp = csp_raw if isinstance(csp_raw, dict) else {}
            csp_q = str(csp.get("quality") or "unknown")
            issues_raw = http.get("issues")
            issues = issues_raw if isinstance(issues_raw, list) else []
            issue_cnt = len(issues)

            detail = ""
            chain_raw = http.get("redirect_chain")
            chain = chain_raw if isinstance(chain_raw, list) else []
            if chain or issues:
                detail += '<div style="color:var(--muted);line-height:1.6">'
                if chain:
                    detail += '<div style="margin-bottom:.35rem"><strong>Redirect chain</strong></div><div class="mono" style="white-space:pre-wrap">'
                    for hop in chain[:10]:
                        if not isinstance(hop, dict):
                            continue
                        detail += f"{h(str(hop.get('status', '')))} → {h(str(hop.get('location') or ''))}\n"
                    detail += "</div>"
                if issues:
                    detail += '<div style="margin-top:.65rem;margin-bottom:.35rem"><strong>Header issues</strong></div>'
                    for it in issues[:20]:
                        if not isinstance(it, dict):
                            continue
                        sev = (it.get("severity") or "low").lower()
                        sev_cls = (
                            "medium"
                            if sev in ("medium", "warning")
                            else ("high" if sev in ("high", "critical") else "low")
                        )
                        detail += f'<div style="margin:.2rem 0">{sev_badge(sev_cls)} <code>{h(str(it.get("id", "")))}</code> {h(str(it.get("title", "")))}</div>'
                    if len(issues) > 20:
                        detail += f'<div style="margin-top:.35rem">… and {len(issues) - 20} more</div>'
                detail += "</div>"

            onclick = ' onclick="toggleRow(this)"' if detail else ""
            row_cls = ' class="expandable"' if detail else ""
            html += f'<tr{row_cls}{onclick}><td class="mono">{h(label)}</td><td>{dns_cnt}</td><td class="mono">{h(tls_grade)}</td><td class="mono">{h(str(http_status))}</td><td class="mono">{h(hsts_txt)}</td><td class="mono">{h(csp_q)}</td><td class="r">{issue_cnt}</td></tr>'
            if detail:
                html += f'<tr class="row-detail"><td colspan="7"><div class="detail-panel">{detail}</div></td></tr>'
        html += "</tbody></table></div></div>"
    return html


def _build_trivy_section(net_data, ts):
    """Build Trivy, Nmap, and SSL/TLS scan cards."""
    html = ""
    if (
        net_data["trivy_fs"] is not None
        or net_data["nmap_scans"]
        or net_data["sslscan_results"]
    ):
        html += '<div class="card"><div class="card-title">Trivy (vulnerabilities &amp; config)</div><div style="padding:1rem 1.25rem">'
        html += f'<table><thead><tr><th>Severity</th><th class="r">Count</th></tr></thead><tbody>'
        html += f'<tr><td><span class="badge critical">Critical</span></td><td class="r">{ts["critical"]}</td></tr><tr><td><span class="badge high">High</span></td><td class="r">{ts["high"]}</td></tr><tr><td><span class="badge medium">Medium</span></td><td class="r">{ts["medium"]}</td></tr><tr><td><span class="badge low">Low</span></td><td class="r">{ts["low"]}</td></tr></tbody></table></div></div>'
        vulns = sorted(
            net_data["trivy_vulns"],
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                x["severity"], 9
            ),
        )[:50]
        if vulns:
            html += '<div class="card"><div class="card-title">Trivy findings (top 50)</div><div style="max-height:50vh;overflow-y:auto">'
            html += '<table><thead><tr><th style="width:80px">Severity</th><th style="width:100px">ID</th><th>Target/Package</th><th>Title</th></tr></thead><tbody>'
            for v in vulns:
                sev = (v.get("severity") or "UNKNOWN").upper()
                sev_cls = (
                    "low"
                    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                    else sev.lower()
                )
                html += f'<tr><td><span class="badge {sev_cls}">{sev}</span></td><td class="mono">{h(v.get("id", ""))}</td><td class="mono">{h((v.get("target") or "") + " " + (v.get("pkg") or v.get("message", ""))[:60])}</td><td>{h((v.get("title") or "")[:80])}</td></tr>'
            html += "</tbody></table></div></div>"
        if net_data["nmap_scans"]:
            html += '<div class="card"><div class="card-title">Nmap scan summary</div><div style="padding:1rem 1.25rem">'
            for scan in net_data["nmap_scans"]:
                html += f'<div style="margin-bottom:1rem"><strong>{h(scan["name"])}</strong><ul style="margin:.5rem 0 0 1rem">'
                for hst in scan["hosts"][:10]:
                    ports = ", ".join(hst["ports"][:15]) if hst["ports"] else "(none)"
                    html += (
                        f"<li>{h(hst['addr']) or 'host'}: {ports}</li>"
                    )
                html += "</ul></div>"
            html += "</div></div>"
        if net_data["sslscan_results"]:
            html += '<div class="card"><div class="card-title">SSL/TLS scan</div><div style="padding:1rem 1.25rem">'
            for s in net_data["sslscan_results"]:
                html += f'<div><strong>{h(s["name"])}</strong> <span style="color:var(--muted)">(JSON data available)</span></div>'
            html += "</div></div>"
    return html


def _build_datadog_logs_section(datadog_data):
    """Build Datadog CI log summary and log table cards."""
    html = ""
    dd_summary = datadog_data.get("summary") or {}
    if dd_summary.get("total", 0) > 0:
        html += '<div class="card"><div class="card-title">Datadog CI log summary</div><div style="padding:1rem 1.25rem">'
        html += '<table><thead><tr><th>Level</th><th class="r">Count</th></tr></thead><tbody>'
        html += f'<tr><td><span class="badge high">Error</span></td><td class="r">{dd_summary.get("error", 0)}</td></tr>'
        html += f'<tr><td><span class="badge warning">Warning</span></td><td class="r">{dd_summary.get("warning", 0)}</td></tr>'
        html += f'<tr><td><span class="badge info">Info</span></td><td class="r">{dd_summary.get("info", 0)}</td></tr>'
        html += f'<tr><td><span class="badge low">Unknown</span></td><td class="r">{dd_summary.get("unknown", 0)}</td></tr>'
        html += "</tbody></table></div></div>"
        html += '<div class="card"><div class="card-title">Datadog CI logs (latest 100)</div><div style="max-height:50vh;overflow-y:auto">'
        html += '<table><thead><tr><th style="width:160px">Timestamp</th><th style="width:100px">Level</th><th style="width:160px">Source</th><th>Message</th></tr></thead><tbody>'
        for row in (datadog_data.get("logs") or [])[:100]:
            sev = row.get("severity", "unknown")
            sev_cls = (
                "low"
                if sev == "unknown"
                else (
                    "warning"
                    if sev == "warning"
                    else ("high" if sev == "error" else "info")
                )
            )
            html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("source", "-"))}</td><td>{h(row.get("message", ""))}</td></tr>'
        html += "</tbody></table></div></div>"
    return html


def _build_datadog_signals_section(datadog_data):
    """Build Datadog Cloud Security signals cards."""
    html = ""
    dd_signal_summary = datadog_data.get("signal_summary") or {}
    if dd_signal_summary.get("total", 0) > 0:
        html += '<div class="card"><div class="card-title">Datadog Cloud Security signals summary</div><div style="padding:1rem 1.25rem">'
        html += '<table><thead><tr><th>Severity</th><th class="r">Count</th></tr></thead><tbody>'
        html += f'<tr><td><span class="badge critical">Critical</span></td><td class="r">{dd_signal_summary.get("critical", 0)}</td></tr>'
        html += f'<tr><td><span class="badge high">High</span></td><td class="r">{dd_signal_summary.get("high", 0)}</td></tr>'
        html += f'<tr><td><span class="badge medium">Medium</span></td><td class="r">{dd_signal_summary.get("medium", 0)}</td></tr>'
        html += f'<tr><td><span class="badge low">Low</span></td><td class="r">{dd_signal_summary.get("low", 0)}</td></tr>'
        html += "</tbody></table></div></div>"
        html += '<div class="card"><div class="card-title">Datadog Cloud Security signals (critical/high first)</div><div style="max-height:50vh;overflow-y:auto">'
        html += '<table><thead><tr><th style="width:150px">Timestamp</th><th style="width:90px">Severity</th><th style="width:110px">Status</th><th style="width:180px">Rule</th><th>Title</th></tr></thead><tbody>'
        for row in (datadog_data.get("signals") or [])[:100]:
            sev = row.get("severity", "unknown")
            sev_cls = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
            }.get(sev, "low")
            html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("status", ""))}</td><td class="mono">{h(row.get("rule", ""))}</td><td>{h(row.get("title", ""))}</td></tr>'
        html += "</tbody></table></div></div>"
    return html


def _build_datadog_cases_section(datadog_data):
    """Build Datadog case management cards."""
    html = ""
    dd_case_summary = datadog_data.get("case_summary") or {}
    if dd_case_summary.get("total", 0) > 0:
        html += '<div class="card"><div class="card-title">Datadog case management summary</div><div style="padding:1rem 1.25rem">'
        html += '<table><thead><tr><th>Priority/Severity</th><th class="r">Count</th></tr></thead><tbody>'
        html += f'<tr><td><span class="badge critical">Critical/P1</span></td><td class="r">{dd_case_summary.get("critical", 0)}</td></tr>'
        html += f'<tr><td><span class="badge high">High/P2</span></td><td class="r">{dd_case_summary.get("high", 0)}</td></tr>'
        html += f'<tr><td><span class="badge medium">Medium/P3</span></td><td class="r">{dd_case_summary.get("medium", 0)}</td></tr>'
        html += f'<tr><td><span class="badge low">Low/P4+</span></td><td class="r">{dd_case_summary.get("low", 0)}</td></tr>'
        html += "</tbody></table></div></div>"
        html += '<div class="card"><div class="card-title">Datadog cases (critical/high first)</div><div style="max-height:50vh;overflow-y:auto">'
        html += '<table><thead><tr><th style="width:150px">Updated</th><th style="width:90px">Severity</th><th style="width:120px">Status</th><th style="width:160px">Type</th><th>Title</th></tr></thead><tbody>'
        for row in datadog_data["cases"][:100]:
            sev = row.get("severity", "unknown")
            sev_cls = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
            }.get(sev, "low")
            html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("status", ""))}</td><td class="mono">{h(row.get("rule", ""))}</td><td>{h(row.get("title", ""))}</td></tr>'
        html += "</tbody></table></div></div>"
    return html


def _build_overview_blocks(
    prov_summary,
    all_findings,
    envs,
    net_data,
    datadog_data,
    passed,
    total_prowler_pass,
    warnings,
    total_checks,
    failed,
    arch_domains,
    audit_points_data,
    ms_best_practices_data,
    findings_list=None,
):
    findings_list = findings_list or []
    datadog_data = datadog_data or {}
    net_data = net_data or {}

    sev = _compute_severity_counts(prov_summary, findings_list)
    n_crit = sev["n_crit"]
    n_high = sev["n_high"]
    n_med = sev["n_med"]
    n_low = sev["n_low"]
    n_info = sev["n_info"]
    policy_022_top = sev["policy_022_top"]

    prov_cards = _build_provider_cards(prov_summary)

    bars = _compute_severity_bars(n_crit, n_high, n_med, n_low, warnings)

    top_findings_html = _build_top_findings(findings_list, all_findings)

    env_connected = sum(1 for e in envs if e["connected"])
    env_total = len(envs)
    service_surface_html = _build_service_surface_html(
        findings_list,
        total_checks,
        failed,
        warnings,
        prov_summary,
        env_connected,
        env_total,
        net_data,
        datadog_data,
        arch_domains,
        audit_points_data,
        ms_best_practices_data,
    )
    priority_queue_html = _build_priority_queue_html(
        findings_list,
        prov_summary,
        env_connected,
        env_total,
        net_data,
        datadog_data,
    )
    ts = net_data["trivy_summary"]
    trivy_total = ts["critical"] + ts["high"] + ts["medium"] + ts["low"]
    dd_total = datadog_data["summary"].get("total", 0)
    dd_signal_total = datadog_data["signal_summary"].get("total", 0)
    dd_case_total = datadog_data["case_summary"].get("total", 0)
    network_total = trivy_total + dd_total
    network_total += dd_signal_total + dd_case_total
    has_network_artifacts = bool(net_data["nmap_scans"] or net_data["sslscan_results"])
    network_tools_badge = (
        str(network_total) if network_total else ("✓" if has_network_artifacts else "—")
    )

    # Always show a "cockpit" card so this tab is useful even without artifacts.
    config_html, net_enabled, net_targets, trivy_enabled = _build_network_config_section()
    network_tools_html = config_html

    network_tools_html += _build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled)

    network_tools_html += _build_artifact_links_section()

    network_tools_html += _build_target_posture_table(net_data)

    network_tools_html += _build_trivy_section(net_data, ts)

    network_tools_html += _build_datadog_logs_section(datadog_data)

    network_tools_html += _build_datadog_signals_section(datadog_data)

    network_tools_html += _build_datadog_cases_section(datadog_data)

    # network_tools_html always contains at least the cockpit card now.
    return {
        "n_crit": n_crit,
        "n_high": n_high,
        "n_med": n_med,
        "n_low": n_low,
        "n_info": n_info,
        "policy_022_top": policy_022_top,
        "prov_cards": prov_cards,
        "bar_crit": bars["bar_crit"],
        "bar_high": bars["bar_high"],
        "bar_med": bars["bar_med"],
        "bar_warn": bars["bar_warn"],
        "bar_low": bars["bar_low"],
        "top_findings_html": top_findings_html,
        "env_connected": env_connected,
        "env_total": env_total,
        "service_surface_html": service_surface_html,
        "priority_queue_html": priority_queue_html,
        "network_tools_html": network_tools_html,
        "network_tools_badge": network_tools_badge,
    }


def _build_owasp_html(owasp_map):
    out = '<h2 style="font-size:.95rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem"><span style="color:var(--accent)">🛡</span> OWASP Top 10:2025 — Web application security</h2>'
    for ow in OWASP_2025:
        oid = ow["id"]
        findings = owasp_map.get(oid, [])
        count = len(findings)
        status_cls = "pass" if count == 0 else "fail"
        out += f'<div class="owasp-item {status_cls}" id="owasp-{oid}">'
        out += f'<div class="owasp-header" onclick="toggleOwasp(this)"><span class="owasp-id">{oid}</span><span class="owasp-name">{h(ow["name"])}</span><span class="owasp-count">{count}</span><span class="owasp-arrow">▸</span></div>'
        arch_idx_list = OWASP_TO_ARCH.get(
            oid, OWASP_TO_ARCH.get(oid.split(":")[0] if ":" in oid else oid, [])
        )
        summary = (ow.get("summary") or ow.get("desc") or "").strip()
        action = (
            ow.get("action")
            or "Review the OWASP documentation and apply recommended controls."
        ).strip()
        out += f'<div class="owasp-body"><p class="owasp-desc">{h(ow["desc"])}</p>'
        out += f'<p class="owasp-summary"><strong>Summary</strong> {h(summary or "See description above.")}</p>'
        out += f'<p class="owasp-action"><strong>Remediation</strong> {h(action)}</p>'
        out += f'<a href="{ow["url"]}" target="_blank" class="ref-link">📖 OWASP documentation</a>'
        if arch_idx_list:
            out += f'<div class="owasp-arch-links"><span class="arch-links-label">Related architecture</span>'
            for i in arch_idx_list:
                d = ARCH_DOMAINS[i] if i < len(ARCH_DOMAINS) else None
                if d:
                    out += f'<button class="arch-link-chip" onclick="switchTab(\'arch\',\'arch-dom-{i}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
            out += "</div>"
        if findings:
            out += '<div class="owasp-findings">'
            for ff in findings[:10]:
                res = (ff.get("resource") or "").strip()
                prov = (ff.get("provider") or "").strip()
                res_html = f' <span class="of-resource" title="Resource: {h(res)}">📍 <code>{h(res[:50])}</code></span>' if res else ""
                prov_html = f' <span class="of-prov">{h(prov.upper())}</span>' if prov else ""
                en = get_check_en(ff.get("check", ""))
                out += f'<div class="of-row">{sev_badge(ff["severity"])} <code>{h(ff["check"])}</code>{prov_html} {h(ff["message"][:120])}{res_html}</div>'
                out += f'<div class="of-detail"><span class="of-action">Action: {h(en["action"][:150])}</span></div>'
            if count > 10:
                out += f'<div class="of-more">... and {count - 10} more</div>'
            out += "</div>"
        out += "</div></div>"
    out += '<div style="margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)">'
    out += '<h2 style="font-size:.95rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem"><span style="color:var(--accent)">🤖</span> OWASP Top 10 for LLM Applications 2025</h2>'
    out += '<p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">AI/LLM application security risks — <a href="https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/" target="_blank" style="color:var(--accent)">Official docs</a></p>'
    for llm in OWASP_LLM_2025:
        out += f'<div class="owasp-item" style="border-left:3px solid var(--accent)">'
        out += f'<div class="owasp-header" onclick="toggleOwasp(this)"><span class="owasp-id" style="color:#f59e0b">{llm["id"]}</span><span class="owasp-name">{h(llm["name"])}</span><span class="owasp-arrow">▸</span></div>'
        summary = (llm.get("summary") or llm.get("desc") or "").strip()
        action = (
            llm.get("action")
            or "Review the OWASP GenAI documentation and apply recommended controls."
        ).strip()
        out += f'<div class="owasp-body"><p class="owasp-desc">{h(llm["desc"])}</p>'
        out += f'<p class="owasp-summary"><strong>Summary</strong> {h(summary or "See description above.")}</p>'
        out += f'<p class="owasp-action"><strong>Remediation</strong> {h(action)}</p>'
        out += f'<a href="{llm["url"]}" target="_blank" class="ref-link">📖 OWASP GenAI documentation</a></div></div>'
    out += "</div>"
    return out


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


def _apply_template_and_write(output_file, template, replacements):
    for k, v in replacements.items():
        template = template.replace(f"{{{{{k}}}}}", v)
    # CSP nonce 주입 (빌드마다 새로운 랜덤 nonce 생성)
    nonce = generate_nonce()
    template = inject_csp_nonce(template, nonce)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(template)


# Inline architecture diagram (fallback when SVG file not found) — dark theme
_INLINE_ARCH_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 260" width="100%" style="max-width:900px;height:auto;display:block" class="arch-diagram-svg">
<defs><marker id="arch-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#94a3b8"/></marker></defs>
<style>.arch-txt{font-family:system-ui,sans-serif;font-size:11px;fill:#e2e8f0}.arch-title{font-weight:bold}</style>
<line x1="180" y1="105" x2="260" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="420" y1="110" x2="520" y2="75" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="75" x2="720" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="100" x2="720" y2="170" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<rect x="40" y="80" width="140" height="50" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="110" y="96" text-anchor="middle" class="arch-txt arch-title">ClaudeSec Scanner</text><text x="110" y="110" text-anchor="middle" class="arch-txt">(CLI)</text>
<rect x="260" y="40" width="160" height="140" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="340" y="56" text-anchor="middle" class="arch-txt arch-title">Scan Categories</text>
<text x="340" y="70" text-anchor="middle" class="arch-txt">infra, ai, network, cloud</text><text x="340" y="84" text-anchor="middle" class="arch-txt">access-control, cicd, code</text><text x="340" y="98" text-anchor="middle" class="arch-txt">... prowler</text>
<rect x="520" y="50" width="180" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="610" y="66" text-anchor="middle" class="arch-txt arch-title">Scan Results</text><text x="610" y="80" text-anchor="middle" class="arch-txt">JSON / score / grade</text>
<rect x="520" y="120" width="140" height="40" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="590" y="136" text-anchor="middle" class="arch-txt arch-title">scan-report.json</text>
<rect x="520" y="180" width="160" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="600" y="196" text-anchor="middle" class="arch-txt arch-title">Prowler OCSF</text>
<rect x="720" y="80" width="120" height="50" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="96" text-anchor="middle" class="arch-txt arch-title">Dashboard</text><text x="780" y="110" text-anchor="middle" class="arch-txt">(HTML)</text>
<rect x="720" y="150" width="120" height="40" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="166" text-anchor="middle" class="arch-txt arch-title">History</text>
</svg>"""


def _get_architecture_diagram_html(output_file, scan_dir: str = ""):
    """Load architecture SVG from docs/architecture or return built-in inline SVG.

    Prefer `scan_dir` when provided, because the HTML output may be generated
    from a different working directory than the scan artifacts.
    """
    candidates = []
    # Prefer the one-screen overview SVG when available.
    preferred_names = [
        "claudesec-overview.svg",
        "claudesec-architecture.svg",
    ]
    if scan_dir:
        try:
            for name in preferred_names:
                candidates.append(
                    os.path.join(
                        os.path.abspath(scan_dir),
                        "docs",
                        "architecture",
                        name,
                    )
                )
        except Exception:
            pass
    if output_file:
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            for name in preferred_names:
                candidates.append(os.path.join(out_dir, "docs", "architecture", name))
    cwd = os.getcwd()
    for name in preferred_names:
        candidates.append(os.path.join(cwd, "docs", "architecture", name))
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(script_dir))
        for name in preferred_names:
            candidates.append(os.path.join(repo_root, "docs", "architecture", name))
    except Exception:
        pass
    for svg_path in candidates:
        if svg_path and os.path.isfile(svg_path):
            try:
                with open(svg_path, "r", encoding="utf-8") as f:
                    svg_content = f.read()
                b64 = base64.b64encode(svg_content.encode("utf-8")).decode("ascii")
                label = (
                    "ClaudeSec Overview Architecture"
                    if svg_path.endswith("claudesec-overview.svg")
                    else "ClaudeSec Architecture"
                )
                return f'<img src="data:image/svg+xml;base64,{b64}" alt="{label}" loading="lazy" style="max-width:100%;height:auto;display:block;border-radius:8px" />'
            except Exception:
                continue
    return f'<div class="arch-diagram-wrap">{_INLINE_ARCH_SVG}</div>'


def generate_dashboard(scan_data, prowler_dir, history_dir, output_file):
    network_dir = os.environ.get("CLAUDESEC_NETWORK_DIR", "")
    scan_dir = os.environ.get("CLAUDESEC_SCAN_DIR", "") or os.environ.get(
        "SCAN_DIR", ""
    )
    if scan_dir:
        scan_dir = os.path.abspath(scan_dir)
    if not scan_dir and prowler_dir and os.path.isdir(prowler_dir):
        scan_dir = os.path.dirname(os.path.abspath(prowler_dir))
    if not scan_dir and output_file:
        scan_dir = os.path.dirname(os.path.abspath(output_file))
    if not scan_dir:
        scan_dir = os.getcwd()

    if not network_dir:
        network_dir = os.path.join(scan_dir, ".claudesec-network")
    datadog_dir = os.environ.get("CLAUDESEC_DATADOG_DIR", "")
    if not datadog_dir:
        datadog_dir = os.path.join(scan_dir, ".claudesec-datadog")
    net_data = load_network_tool_results(network_dir)
    datadog_data = load_datadog_logs(datadog_dir)
    audit_points_data = load_audit_points(scan_dir)
    ms_best_practices_data = load_microsoft_best_practices(scan_dir)

    providers = load_prowler_files(prowler_dir)
    prov_summary, all_findings = analyze_prowler(providers)
    history = load_scan_history(history_dir)
    owasp_map = map_findings_to_owasp(all_findings)
    compliance_map = map_compliance(all_findings)
    arch_domains = map_architecture(all_findings)
    gh_finds = github_findings(all_findings)
    aws_finds = aws_findings(all_findings)
    gcp_finds = gcp_findings(all_findings)
    gws_finds = gws_findings(all_findings)
    k8s_finds = k8s_findings(all_findings)
    azure_finds = azure_findings(all_findings)
    m365_finds = m365_findings(all_findings)
    iac_finds = iac_findings(all_findings)
    envs = get_env_status()

    sd = scan_data
    passed = sd.get("passed", 0)
    failed = sd.get("failed", 0)
    warnings = sd.get("warnings", 0)
    skipped = sd.get("skipped", 0)
    total = sd.get("total", 0)
    score = sd.get("score", 0)
    grade = sd.get("grade", "F")
    duration = sd.get("duration", 0)
    findings_list = sd.get("findings", [])
    active = total - skipped

    grade_color = {"A": "#22c55e", "B": "#22c55e", "C": "#eab308", "D": "#eab308"}.get(
        grade, "#ef4444"
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    total_prowler_fail = sum(v["total_fail"] for v in prov_summary.values())
    total_prowler_pass = sum(v["total_pass"] for v in prov_summary.values())

    # Compliance summary for history tracking
    compliance_summary = {}
    for fw, controls in compliance_map.items():
        fw_pass = sum(1 for c in controls if c["status"] == "PASS")
        fw_fail = sum(1 for c in controls if c["status"] == "FAIL")
        compliance_summary[fw] = {"pass": fw_pass, "fail": fw_fail, "total": fw_pass + fw_fail}

    history_json = json.dumps(
        history
        + [
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "score": score,
                "failed": failed,
                "critical": sum(v["critical"] for v in prov_summary.values()),
                "high": sum(v["high"] for v in prov_summary.values()),
                "compliance": compliance_summary,
            }
        ]
    )
    # Escape sequences that break out of <script> context (XSS prevention)
    history_json = history_json.replace("</", "<\\/").replace("<!--", "<\\!--")

    # ── Build HTML sections ──────────────────────────────────────────────

    # Environment items — compact pill layout with a stable connected/total
    # counter for the Overview header. Both connected and disconnected
    # providers are clickable and open the setup modal for quick fixes.
    env_html = ""
    env_connected = 0
    env_total = len(envs)
    for e in envs:
        if e["connected"]:
            env_connected += 1
            env_html += (
                f'<button class="env-pill env-on" '
                f'onclick="openSetup(\'{h(e["setup_id"])}\')">'
                f'<span class="ep-icon">{e["icon"]}</span>'
                f'<span class="ep-name">{h(e["name"])}</span>'
                f'<span class="ep-st on">●</span>'
                f'</button>'
            )
        else:
            env_html += (
                f'<button class="env-pill env-off" '
                f'onclick="openSetup(\'{h(e["setup_id"])}\')">'
                f'<span class="ep-icon">{e["icon"]}</span>'
                f'<span class="ep-name">{h(e["name"])}</span>'
                f'<span class="ep-st off">○</span>'
                f'</button>'
            )

    # Prowler summary table: show fixed set (K8s, Google Workspace, etc.) even when no OCSF data
    _prov_labels = {
        "aws": "AWS",
        "github": "GitHub",
        "iac": "IaC",
        "kubernetes": "K8s",
        "azure": "Azure",
        "gcp": "GCP",
        "googleworkspace": "Google Workspace",
        "m365": "Microsoft 365",
        "cloudflare": "Cloudflare",
        "nhn": "NHN Cloud",
        "llm": "LLM",
        "image": "Container Image",
        "oraclecloud": "Oracle Cloud",
        "alibabacloud": "Alibaba Cloud",
        "openstack": "OpenStack",
        "mongodbatlas": "MongoDB Atlas",
    }
    _subtab_map = {
        "aws": "aws",
        "gcp": "gcp",
        "googleworkspace": "gws",
        "kubernetes": "k8s",
        "azure": "azure",
        "m365": "m365",
        "iac": "iac",
    }
    _display_order = [
        "aws",
        "gcp",
        "googleworkspace",
        "kubernetes",
        "azure",
        "m365",
        "iac",
        "github",
    ]
    prov_table = ""
    seen = set()
    for pname in _display_order:
        pdata = prov_summary.get(pname)
        if pdata is None:
            pdata = {
                "total_fail": 0,
                "total_pass": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        seen.add(pname)
        label = _prov_labels.get(pname, pname)
        subtab = _subtab_map.get(pname)
        onclick = (
            f' onclick="switchProvTab(\'{h(subtab)}\')" style="cursor:pointer"'
            if subtab
            else ""
        )
        total_cells = pdata["total_fail"] + pdata["total_pass"]
        no_data = total_cells == 0 and pname in ("kubernetes", "googleworkspace")
        if no_data:
            prov_table += f'<tr class="prov-row-no-data"{onclick}><td>{label} <span style="font-size:.7rem;color:var(--muted);font-weight:400" title="Add to prowler_providers in .claudesec.yml and configure credentials (kubeconfig / GOOGLE_WORKSPACE_CUSTOMER_ID)">— not run</span></td><td class="r">0</td><td class="r">0</td><td class="r">0</td><td class="r">0</td><td class="r">0</td><td class="r">0</td></tr>'
        else:
            prov_table += f'<tr{onclick}><td>{label}</td><td class="r">{total_cells}</td><td class="r" style="color:#f87171">{pdata["critical"]}</td><td class="r" style="color:#fca5a5">{pdata["high"]}</td><td class="r" style="color:#fde68a">{pdata["medium"]}</td><td class="r">{pdata["low"]}</td><td class="r" style="color:#22c55e">{pdata["total_pass"]}</td></tr>'
    for pname, pdata in sorted(prov_summary.items()):
        if pname in seen:
            continue
        label = _prov_labels.get(pname, pname)
        subtab = _subtab_map.get(pname)
        onclick = (
            f' onclick="switchProvTab(\'{h(subtab)}\')" style="cursor:pointer"'
            if subtab
            else ""
        )
        prov_table += f'<tr{onclick}><td>{label}</td><td class="r">{pdata["total_fail"] + pdata["total_pass"]}</td><td class="r" style="color:#f87171">{pdata["critical"]}</td><td class="r" style="color:#fca5a5">{pdata["high"]}</td><td class="r" style="color:#fde68a">{pdata["medium"]}</td><td class="r">{pdata["low"]}</td><td class="r" style="color:#22c55e">{pdata["total_pass"]}</td></tr>'

    # Scanner findings — grouped by category with descriptions
    scanner_rows, scanner_cat_summary, scanner_insights_html = _build_scanner_section(
        findings_list
    )

    # GitHub Security findings
    gh_by_check = defaultdict(list)
    for f in gh_finds:
        gh_by_check[f["check"]].append(f)
    gh_table = ""
    for check, items in sorted(gh_by_check.items(), key=lambda x: -len(x[1])):
        sev = items[0]["severity"]
        repos = list(set(f["resource"] for f in items if f["resource"]))
        repos_shown = repos[:5]
        repos_html = ", ".join(f"<code>{h(r)}</code>" for r in repos_shown)
        if len(repos) > 5:
            repos_html += f' <span class="res-toggle" onclick="var s=this.nextElementSibling;s.style.display=s.style.display===\'none\'?\'inline\':\'none\';this.textContent=this.textContent.indexOf(\'+\')>=0?\'hide\':\'... +{len(repos)-5} more\'" style="color:var(--accent);cursor:pointer;font-weight:600">... +{len(repos) - 5} more</span><span style="display:none">, ' + ", ".join(f"<code>{h(r)}</code>" for r in repos[5:]) + "</span>"
        gh_table += f'<tr class="expandable" onclick="toggleRow(this)"><td>{sev_badge(sev)}</td><td class="mono">{h(check)}</td><td>{h(items[0]["title"])} <span class="cnt">({len(items)})</span></td><td>{repos_html}</td></tr>'
        en = get_check_en(check)
        desc = items[0].get("desc") or items[0].get("title") or ""
        native_rem = (items[0].get("native_remediation") or "").strip()
        action_text = en["action"] if en["action"] != DEFAULT_ACTION else (native_rem or en["action"])
        gh_table += f'<tr class="row-detail"><td colspan="4"><div class="detail-panel">'
        if desc:
            gh_table += f"<p>{h(desc)}</p>"
        gh_table += f'<p class="detail-ko-summary"><strong>Summary</strong> {h(en["summary"])}</p>'
        gh_table += f'<p class="detail-ko-action"><strong>Remediation</strong> {h(action_text)}</p>'
        ref_links = []
        if items[0].get("related_url"):
            ref_links.append(items[0]["related_url"])
        for nr in (items[0].get("native_refs") or []):
            if nr and nr not in ref_links:
                ref_links.append(nr)
        for rl in ref_links:
            gh_table += f'<a href="{h(rl)}" target="_blank" rel="noopener" class="ref-link">📖 Reference</a> '
        gh_table += "</div></td></tr>"

    _SEV_WEIGHT = {"Critical": 100, "High": 10, "Medium": 3, "Low": 1, "Informational": 0}

    def _build_provider_table(finds):
        by_check = defaultdict(list)
        for f in finds:
            by_check[f["check"]].append(f)
        parts = []
        # Severity-weighted sort: Critical findings rank above High even with fewer instances
        def _check_sort_key(pair):
            _check, _items = pair
            top_sev = max((_SEV_WEIGHT.get(i.get("severity", ""), 0) for i in _items), default=0)
            return -(top_sev * 1000 + len(_items))
        for check, items in sorted(by_check.items(), key=_check_sort_key):
            sev = items[0]["severity"]
            parts.append(f'<tr class="expandable" onclick="toggleRow(this)"><td>{sev_badge(sev)}</td><td class="mono">{h(check)}</td><td>{h(items[0]["title"])} <span class="cnt">({len(items)})</span></td></tr>')
            en = get_check_en(check)
            desc = items[0].get("desc") or items[0].get("title") or ""
            # Use Prowler native remediation as fallback when CHECK_EN_MAP has no match
            native_rem = (items[0].get("native_remediation") or "").strip()
            action_text = en["action"] if en["action"] != DEFAULT_ACTION else (native_rem or en["action"])
            summary_text = en["summary"]
            detail = [f'<tr class="row-detail"><td colspan="3"><div class="detail-panel">']
            if desc:
                detail.append(f"<p>{h(desc)}</p>")
            detail.append(f'<p class="detail-ko-summary"><strong>Summary</strong> {h(summary_text)}</p>')
            detail.append(f'<p class="detail-ko-action"><strong>Remediation</strong> {h(action_text)}</p>')
            # Affected resources with type, region, namespace — all shown, overflow toggleable
            resources = []
            seen_res = set()
            for it in items:
                res = (it.get("resource") or "").strip()
                if res and res not in seen_res:
                    seen_res.add(res)
                    r_type = (it.get("resource_type") or "").strip()
                    r_region = (it.get("region") or "").strip()
                    r_ns = (it.get("namespace") or "").strip()
                    r_line = (it.get("start_line") or "").strip()
                    resources.append({"name": res, "type": r_type, "region": r_region, "namespace": r_ns, "line": r_line})
            if resources:
                SHOW_LIMIT = 15
                detail.append('<div class="detail-resources"><strong>Affected resources</strong><ul class="resource-list">')
                for idx_r, r in enumerate(resources):
                    extra = []
                    if r["type"]:
                        extra.append(r["type"])
                    if r["region"]:
                        extra.append(r["region"])
                    if r["namespace"]:
                        extra.append(f'ns:{r["namespace"]}')
                    if r["line"]:
                        extra.append(f'L{r["line"]}')
                    extra_html = f' <span class="res-meta">{h(" · ".join(extra))}</span>' if extra else ""
                    hidden = ' style="display:none" class="res-overflow"' if idx_r >= SHOW_LIMIT else ""
                    detail.append(f"<li{hidden}><code>{h(r['name'])}</code>{extra_html}</li>")
                if len(resources) > SHOW_LIMIT:
                    overflow_count = len(resources) - SHOW_LIMIT
                    detail.append(f'<li class="res-toggle" onclick="var p=this.parentNode;p.querySelectorAll(\'.res-overflow\').forEach(function(e){{e.style.display=e.style.display===\'none\'?\'list-item\':\'none\'}});this.textContent=this.textContent.indexOf(\'+\')>=0?\'Hide {overflow_count} resources\':\'+ {overflow_count} more resources\'" style="color:var(--accent);cursor:pointer;font-weight:600">+ {overflow_count} more resources</li>')
                detail.append("</ul></div>")
            # Reference links: primary + native refs
            ref_links = []
            if items[0].get("related_url"):
                ref_links.append(items[0]["related_url"])
            for nr in (items[0].get("native_refs") or []):
                if nr and nr not in ref_links:
                    ref_links.append(nr)
            # Auto-generate Prowler Hub link from check ID
            _check_raw = items[0].get("check", "")
            if _check_raw and "prowler" in _check_raw.lower():
                _hub_name = re.sub(r"^prowler-[a-z]+-", "", _check_raw)
                _hub_name = re.sub(r"-\d{12}.*$", "", _hub_name)
                _hub_name = re.sub(r"-[0-9a-f]{5,}$", "", _hub_name)
                _HUB_FIX = {
                    "core_minimize_containers_added_capabiliti": "core_minimize_containers_added_capabilities",
                    "iam_aws_attached_policy_no_administrative_privil": "iam_aws_attached_policy_no_administrative_privileges",
                }
                _hub_name = _HUB_FIX.get(_hub_name, _hub_name)
                if _hub_name and "iac-branch" not in _hub_name:
                    _hub_url = f"https://hub.prowler.com/check/{_hub_name}"
                    if _hub_url not in ref_links:
                        ref_links.insert(0, _hub_url)
            for rl in ref_links:
                detail.append(f'<a href="{h(rl)}" target="_blank" rel="noopener" class="ref-link">Reference</a> ')
            detail.append("</div></td></tr>")
            parts.append("".join(detail))
        return "".join(parts)

    aws_table = _build_provider_table(aws_finds)
    gcp_table = _build_provider_table(gcp_finds)
    gws_table = _build_provider_table(gws_finds)
    k8s_table = _build_provider_table(k8s_finds)
    azure_table = _build_provider_table(azure_finds)
    m365_table = _build_provider_table(m365_finds)
    iac_table = _build_provider_table(iac_finds)

    owasp_html = _build_owasp_html(owasp_map)

    # Architecture tab — with linked OWASP/Compliance/Scanner
    arch_html = ""
    owasp_names = {o["id"]: o["name"] for o in OWASP_2025}
    scanner_labels = {
        "access-control": "Access control",
        "infra": "Infrastructure",
        "network": "Network",
        "cicd": "CI/CD",
        "code": "Code",
        "ai": "AI",
        "cloud": "Cloud",
        "macos": "macOS",
        "saas": "SaaS",
        "windows": "Windows",
        "prowler": "Prowler",
        "other": "Other",
    }
    for idx, dom in enumerate(arch_domains):
        status_cls = "fail" if dom["fail_count"] > 0 else "pass"
        links = dom.get("links", {})
        arch_html += f'<div class="arch-domain {status_cls}" id="arch-dom-{idx}" data-arch-idx="{idx}">'
        scanner_cats = links.get("scanner", [])
        coverage_dots = ""
        if scanner_cats:
            coverage_dots = '<span class="arch-coverage">'
            for scat in scanner_cats:
                slab = scanner_labels.get(scat, scat)
                has_data = dom["fail_count"] > 0
                dot_cls = "cov-on" if has_data else "cov-off"
                coverage_dots += f'<span class="cov-dot {dot_cls}" title="{h(slab)}">{h(slab[:3])}</span>'
            coverage_dots += '</span>'
        arch_html += f'<div class="arch-header" onclick="toggleArch(this)"><span class="arch-icon">{dom["icon"]}</span><span class="arch-name">{h(dom["name"])}</span>{coverage_dots}<span class="arch-stat"><span class="arch-fail">{dom["fail_count"]} failed</span></span><span class="arch-arrow">▸</span></div>'
        arch_html += '<div class="arch-body">'
        summary = dom.get("summary", "")
        action = dom.get("action", "")
        summary = (dom.get("summary") or dom.get("name") or "").strip()
        action = (
            dom.get("action")
            or "Apply security best practices for this domain; see related OWASP and compliance controls."
        ).strip()
        arch_html += '<div class="arch-summary-block">'
        arch_html += f'<p class="arch-summary-ko"><strong>Summary</strong> {h(summary or "See related findings and controls below.")}</p>'
        arch_html += (
            f'<p class="arch-action-ko"><strong>Remediation</strong> {h(action)}</p>'
        )
        arch_html += "</div>"
        if links.get("owasp") or links.get("compliance") or links.get("scanner"):
            arch_html += '<div class="arch-links"><span class="arch-links-label">Related items</span>'
            for oid in links.get("owasp", []):
                oname = owasp_names.get(oid, oid)
                arch_html += f'<button class="arch-link-chip arch-owasp" onclick="switchTab(\'bestpractices\',\'owasp-{oid}\')" title="OWASP {oid}">{oid}</button>'
            for fw, ctrl in links.get("compliance", []):
                cid = comp_slug(fw)
                arch_html += f'<button class="arch-link-chip arch-comp" onclick="switchTab(\'bestpractices\',\'{cid}\')" title="{h(fw)} {h(ctrl)}">{ctrl}</button>'
            for scat in links.get("scanner", []):
                slab = scanner_labels.get(scat, scat)
                arch_html += f'<button class="arch-link-chip arch-scanner" onclick="switchTab(\'overview\',\'scanner-cat-{scat}\')" title="Scanner {slab}">{slab}</button>'
            arch_html += "</div>"
        if dom["findings"]:
            for ff in dom["findings"][:8]:
                res = (ff.get("resource") or "").strip()
                prov = (ff.get("provider") or "").strip()
                res_html = f' <span class="of-resource" title="Resource: {h(res)}">📍 <code>{h(res[:40])}</code></span>' if res else ""
                prov_html = f' <span class="of-prov">{h(prov.upper())}</span>' if prov else ""
                en = get_check_en(ff.get("check", ""))
                arch_html += f'<div class="af-row">{sev_badge(ff["severity"])} <code>{h(ff["check"])}</code>{prov_html} {h(ff["message"][:100])}{res_html}</div>'
                arch_html += f'<div class="af-detail"><span class="af-action">Action: {h(en["action"][:120])}</span></div>'
            if dom["fail_count"] > 8:
                arch_html += (
                    f'<div class="of-more">... and {dom["fail_count"] - 8} more</div>'
                )
        else:
            arch_html += '<div class="arch-pass">✓ No findings in this domain.</div>'
        arch_html += "</div></div>"

    # Compliance tab
    comp_html = '<div class="comp-frameworks">'
    for fw in COMPLIANCE_FRAMEWORKS:
        comp_html += f'<a href="{fw["url"]}" target="_blank" class="comp-fw-chip" rel="noopener"><strong>{h(fw["name"])}</strong><span>{h(fw["desc"])}</span></a>'
    comp_html += "</div>"

    COMP_FW_TO_ARCH = {
        "ISO 27001:2022": [0, 1, 2, 3, 4, 5],
        "KISA ISMS-P": [1, 2, 3, 4],
        "PCI-DSS v4.0.1": [0, 1, 2, 3, 4, 5],
    }
    for framework, controls in compliance_map.items():
        total_c = len(controls)
        pass_c = sum(1 for c in controls if c["status"] == "PASS")
        fail_c = total_c - pass_c
        comp_id = comp_slug(framework)
        comp_arch_html = ""
        for aidx in COMP_FW_TO_ARCH.get(framework, []):
            if aidx < len(ARCH_DOMAINS):
                d = ARCH_DOMAINS[aidx]
                comp_arch_html += f'<button class="arch-link-chip arch-sm" onclick="switchTab(\'arch\',\'arch-dom-{aidx}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
        comp_arch_row = (
            f'<div class="comp-arch-links"><span class="arch-links-label">Related architecture</span>{comp_arch_html}</div>'
            if comp_arch_html
            else ""
        )
        comp_html += f'<div class="comp-section" id="{comp_id}"><div class="comp-title" onclick="toggleComp(this)">{h(framework)} <span class="comp-stat"><span class="cs-pass">{pass_c} pass</span> / <span class="cs-fail">{fail_c} fail</span></span><span class="comp-arrow">▸</span></div>'
        if comp_arch_row:
            comp_html += comp_arch_row
        comp_html += '<div class="comp-body"><table><thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Related</th><th>Summary · Remediation</th></tr></thead><tbody>'
        for ctrl in controls:
            st_cls = "pass" if ctrl["status"] == "PASS" else "fail"
            st_icon = "✓" if ctrl["status"] == "PASS" else "✗"
            st_text = "Pass" if ctrl["status"] == "PASS" else "Fail"
            desc = (ctrl.get("desc") or ctrl.get("name") or "").strip()
            action = (
                ctrl.get("action")
                or "Apply security best practices for this control; refer to the framework documentation."
            ).strip()
            findings_detail = ""
            if ctrl.get("findings"):
                findings_detail = '<div class="comp-findings">'
                for cf in ctrl["findings"][:5]:
                    cf_res = (cf.get("resource") or "").strip()
                    cf_prov = (cf.get("provider") or "").strip()
                    cf_res_html = f' <span class="of-resource">📍 <code>{h(cf_res[:40])}</code></span>' if cf_res else ""
                    cf_prov_html = f' <span class="of-prov">{h(cf_prov.upper())}</span>' if cf_prov else ""
                    findings_detail += f'<div class="of-row" style="font-size:.78rem">{sev_badge(cf.get("severity","Medium"))} <code>{h(cf.get("check",""))}</code>{cf_prov_html} {h((cf.get("message") or cf.get("title") or "")[:100])}{cf_res_html}</div>'
                if ctrl["count"] > 5:
                    findings_detail += f'<div class="of-more">... +{ctrl["count"] - 5} more</div>'
                findings_detail += "</div>"
            summary_cell = f'<div class="comp-summary-cell"><span class="comp-desc-ko">{h(desc or "—")}</span><br><span class="comp-action-ko"><strong>Remediation</strong> {h(action)}</span>{findings_detail}</div>'
            comp_html += f'<tr class="comp-{st_cls}"><td class="mono">{h(ctrl["control"])}</td><td>{h(ctrl["name"])}</td><td class="comp-st-{st_cls}">{st_icon} {st_text}</td><td>{ctrl["count"]}</td><td class="comp-summary-td">{summary_cell}</td></tr>'
        comp_html += "</tbody></table></div></div>"

    total_passed = passed + total_prowler_pass
    total_all = total_prowler_fail + total_prowler_pass + failed + warnings
    total_issues = total_prowler_fail + failed + warnings
    audit_points_detected = load_audit_points_detected(scan_dir)
    # Scan scope: what data is included in this dashboard (for Overview)
    prov_count = len(prov_summary)
    hist_count = len(history)
    scope_parts = [f"Scanner ({total} checks)"]
    scanner_cat_labels = []
    scanner_cats_seen = sorted(
        {
            str(f.get("category", "")).strip().lower()
            for f in findings_list
            if str(f.get("category", "")).strip()
        }
    )
    for cat in scanner_cats_seen:
        meta = CATEGORY_META.get(cat)
        scanner_cat_labels.append(meta["label"] if meta else cat)
    scanner_cat_count = len(scanner_cat_labels)

    scanner_cat_links_html = ""
    for cat in scanner_cats_seen:
        meta = CATEGORY_META.get(cat)
        label = meta["label"] if meta else cat
        scanner_cat_links_html += f'<a href="#" class="scope-cat-link" onclick="switchTab(\'overview\',\'scanner-cat-{h(cat)}\');return false;">{h(label)}</a>'
    cat_count_html = (
        f'<a href="#" class="scope-cat-count" onclick="switchTab(\'overview\',\'scanner-cat-{h(scanner_cats_seen[0])}\');return false;">{scanner_cat_count} categories</a>'
        if scanner_cats_seen
        else f'<span class="scope-cat-count">{scanner_cat_count} categories</span>'
    )

    def _middle_ellipsis(text, max_len=64):
        raw = str(text or "")
        if len(raw) <= max_len:
            return raw
        keep = max_len - 3
        left = keep // 2
        right = keep - left
        return raw[:left] + "..." + raw[-right:]

    if prov_count:
        scope_parts.append(
            f"Prowler ({prov_count} provider{'s' if prov_count != 1 else ''})"
        )
    scope_parts.append(f"History ({hist_count} run{'s' if hist_count != 1 else ''})")
    if audit_points_detected.get("detected_products"):
        scope_parts.append("Audit Points (project-relevant)")
    elif audit_points_data.get("products"):
        scope_parts.append("Audit Points")
    if (
        net_data.get("trivy_fs")
        or net_data.get("nmap_scans")
        or net_data.get("sslscan_results")
        or (datadog_data.get("summary", {}).get("total", 0) > 0)
    ):
        scope_parts.append("Network / Datadog")
    local_targets = "source code, config files, CI workflows, environment artifacts"
    scanner_cat_text = (
        ", ".join(scanner_cat_labels)
        if scanner_cat_labels
        else "No fail/warn categories in this run (checks may be pass/skip only)."
    )
    scan_root_short = _middle_ellipsis(scan_dir, 68)
    scan_root_badge = (
        '<span class="trust-badge trust-ms" style="margin-left:.35rem">Repo root</span>'
        if os.path.abspath(scan_dir) == os.path.abspath(os.getcwd())
        else ""
    )

    prowler_provider_options = [
        ("aws", "AWS"),
        ("gcp", "GCP"),
        ("googleworkspace", "Google Workspace"),
        ("kubernetes", "Kubernetes"),
        ("azure", "Azure"),
        ("m365", "Microsoft 365"),
        ("iac", "IaC"),
    ]
    prowler_subtab_map = {
        "aws": "aws",
        "gcp": "gcp",
        "googleworkspace": "gws",
        "kubernetes": "k8s",
        "azure": "azure",
        "m365": "m365",
        "iac": "iac",
    }
    prowler_selector_options_html = '<option value="">Prowler summary</option>'
    for key, label in prowler_provider_options:
        pdata = prov_summary.get(key)
        total_checks = (
            int(pdata.get("total_fail", 0)) + int(pdata.get("total_pass", 0))
            if pdata
            else 0
        )
        subtab = prowler_subtab_map.get(key)
        if not subtab:
            continue
        suffix = " (not run)" if total_checks == 0 and pdata is None else ""
        prowler_selector_options_html += (
            f'<option value="{h(subtab)}">{h(label)} ({total_checks}){suffix}</option>'
        )
    scan_scope_html = (
        '<div style="font-size:.8rem;color:var(--muted);margin-top:.5rem;padding:.55rem 0;border-top:1px solid var(--border)">'
        + '<strong style="color:var(--text)">Data in this view:</strong> '
        + " · ".join(scope_parts)
        + f'<div style="margin-top:.35rem"><strong style="color:var(--text)">Scanned locally:</strong> {h(local_targets)}</div>'
        + f'<div style="margin-top:.25rem"><strong style="color:var(--text)">Local scanner categories detected:</strong> {cat_count_html} '
        + (scanner_cat_links_html if scanner_cat_links_html else h(scanner_cat_text))
        + "</div>"
        + f'<div style="margin-top:.25rem"><strong style="color:var(--text)">Scan root:</strong> <code class="scan-root-path" title="{h(scan_dir)}">{h(scan_root_short)}</code>{scan_root_badge}</div>'
        + '<div style="margin-top:.4rem;display:flex;flex-wrap:wrap;gap:.75rem;align-items:center"><a href="#scanner-section" onclick="document.getElementById(\'scanner-section\').scrollIntoView({behavior:\'smooth\'});return false;" style="color:var(--accent);text-decoration:underline;font-weight:600">View scanner results ↓</a><label style="display:flex;align-items:center;gap:.35rem"><span style="color:var(--text);font-weight:600">Prowler summary</span><select class="scope-select" onchange="openProwlerFromOverview(this)">'
        + prowler_selector_options_html
        + "</select></label></div>"
        + "</div>"
    )
    auth_summary_html = build_auth_summary_html(envs, findings_list)
    repo_url = f"https://github.com/{AUDIT_POINTS_REPO}"
    # Product icon mapping for visual differentiation
    _ap_icons = {
        "Jenkins": "🔧", "Harbor": "🐳", "Nexus": "📦", "Okta": "🔐",
        "QueryPie": "🔎", "Scalr": "☁️", "IDEs": "💻",
    }
    # QueryPie Audit Points tab content — structured for Best Practices hub UI/UX
    _bp_intro = (
        '<p class="bp-audit-intro" style="color:var(--muted);font-size:.9rem;margin-bottom:1.25rem;line-height:1.5">'
        "SaaS/DevSecOps audit checklists (QueryPie) and Microsoft platform best-practice sources. Use the sections below to review project-relevant checklists and open official guidance.</p>"
    )
    audit_points_html = ""
    detected_products = audit_points_detected.get("detected_products") or []
    all_products = audit_points_data.get("products", [])
    products_by_name = {
        p.get("name"): p for p in all_products if p.get("name")
    }
    total_items = sum(len(p.get("files", [])) for p in all_products)
    detected_items = sum(
        len(products_by_name.get(pn, {}).get("files", [])) for pn in detected_products
    )

    # Detected products summary strip
    if detected_products or all_products:
        audit_points_html = _bp_intro
        # Detection summary
        det_count = len(detected_products)
        all_count = len(all_products)
        audit_points_html += '<div class="ap-detected-strip">'
        if detected_products:
            for pn in detected_products:
                icon = _ap_icons.get(pn, "📋")
                audit_points_html += f'<span class="ap-detected-chip">{icon} {h(pn)}</span>'
            audit_points_html += f'<span style="font-size:.72rem;color:var(--muted);align-self:center;margin-left:.5rem">{det_count} detected / {all_count} total · {detected_items} checklist items</span>'
        else:
            audit_points_html += f'<span style="font-size:.78rem;color:var(--muted)">No products detected in this repo · {all_count} products available · run <code>claudesec scan -c saas</code></span>'
        audit_points_html += "</div>"
        # Search bar
        audit_points_html += '<input type="text" class="ap-search" placeholder="Search products or checklist items..." onkeyup="apFilterProducts(this.value)">'
        # Progress bar
        audit_points_html += '<div class="ap-progress-label"><span id="ap-progress-label">0 / 0 reviewed</span><span id="ap-progress-pct">0%</span></div>'
        audit_points_html += '<div class="ap-progress-bar"><div id="ap-progress-fill" class="ap-progress-fill" style="width:0%"></div></div>'

    # Detected products section
    if detected_products and products_by_name:
        audit_points_html += '<div class="card bp-audit-section" style="margin-bottom:1rem"><div class="card-title" style="display:flex;align-items:center;gap:.5rem">Relevant to this project <span class="badge" style="font-size:.65rem;background:rgba(34,197,94,.15);color:#22c55e">' + str(det_count) + ' detected</span></div><div style="padding:.75rem 1rem">'
        for pname in detected_products:
            prod = products_by_name.get(pname)
            if not prod:
                continue
            files = prod.get("files", [])
            icon = _ap_icons.get(pname, "📋")
            tree_url = prod.get("tree_url") or f"{repo_url}/tree/main/{urllib.parse.quote(pname)}"
            audit_points_html += f'<div class="ap-product-card open" data-product="{h(pname.lower())}">'
            audit_points_html += f'<div class="ap-product-header" onclick="this.parentElement.classList.toggle(\'open\')">'
            audit_points_html += f'<span class="ap-product-icon">{icon}</span>'
            audit_points_html += f'<span class="ap-product-name">{h(pname)}</span>'
            audit_points_html += f'<span class="ap-product-count">{len(files)} items</span>'
            audit_points_html += '<span class="ap-product-chevron">▶</span>'
            audit_points_html += '</div>'
            audit_points_html += '<div class="ap-product-body">'
            audit_points_html += f'<a href="{h(tree_url)}" target="_blank" rel="noopener" class="ap-product-github-link">Open on GitHub ↗</a>'
            for idx, f in enumerate(files, start=1):
                url = f.get("url") or f.get("raw_url") or "#"
                fname = f.get("name", "")
                ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
                cb_id = f"ap-{pname}-{idx}".lower().replace(" ", "-")
                audit_points_html += f'<div class="bp-audit-item-row" data-ap-id="{h(cb_id)}">'
                audit_points_html += f'<input type="checkbox" class="ap-checkbox" data-ap-id="{h(cb_id)}" onchange="apToggleCheck(this)">'
                audit_points_html += f'<span class="bp-audit-index">{idx}</span>'
                audit_points_html += f'<a href="{h(url)}" target="_blank" rel="noopener" class="bp-audit-link">{h(fname)}</a>'
                if ext:
                    audit_points_html += f'<span class="bp-audit-ext">.{h(ext)}</span>'
                audit_points_html += "</div>"
            audit_points_html += "</div></div>"
        audit_points_html += "</div></div>"

    # All products catalog
    if all_products:
        if not detected_products:
            audit_points_html = audit_points_html or _bp_intro
        title = "All products" if detected_products else "QueryPie Audit Points"
        audit_points_html += f'<div class="card bp-audit-section" style="margin-bottom:1rem"><div class="card-title" style="display:flex;align-items:center;gap:.5rem">{h(title)} <span class="badge" style="font-size:.65rem">{len(all_products)} products · {total_items} items</span></div><div style="padding:.75rem 1rem">'
        audit_points_html += f'<p style="color:var(--muted);font-size:.82rem;margin-bottom:.75rem">SaaS/DevSecOps audit checklists from <a href="{h(repo_url)}" target="_blank" rel="noopener" style="color:var(--accent)">querypie/audit-points</a>. Click a product to expand.</p>'
        for prod in all_products:
            pname = prod.get("name", "")
            is_detected = pname in detected_products
            files = prod.get("files", [])
            icon = _ap_icons.get(pname, "📋")
            tree_url = prod.get("tree_url") or f"{repo_url}/tree/main/{urllib.parse.quote(pname)}"
            open_cls = ""
            audit_points_html += f'<div class="ap-product-card{open_cls}" data-product="{h(pname.lower())}">'
            audit_points_html += f'<div class="ap-product-header" onclick="this.parentElement.classList.toggle(\'open\')">'
            audit_points_html += f'<span class="ap-product-icon">{icon}</span>'
            audit_points_html += f'<span class="ap-product-name">{h(pname)}'
            if is_detected:
                audit_points_html += ' <span style="font-size:.6rem;color:#22c55e;vertical-align:middle">● detected</span>'
            audit_points_html += '</span>'
            audit_points_html += f'<span class="ap-product-count">{len(files)} items</span>'
            audit_points_html += '<span class="ap-product-chevron">▶</span>'
            audit_points_html += '</div>'
            audit_points_html += '<div class="ap-product-body">'
            audit_points_html += f'<a href="{h(tree_url)}" target="_blank" rel="noopener" class="ap-product-github-link">Open on GitHub ↗</a>'
            for idx, f in enumerate(files[:50], start=1):
                url = f.get("url") or f.get("raw_url") or "#"
                fname = f.get("name", "")
                ext = fname.rsplit(".", 1)[-1] if "." in fname else ""
                cb_id = f"ap-{pname}-{idx}".lower().replace(" ", "-")
                audit_points_html += f'<div class="bp-audit-item-row" data-ap-id="{h(cb_id)}">'
                audit_points_html += f'<input type="checkbox" class="ap-checkbox" data-ap-id="{h(cb_id)}" onchange="apToggleCheck(this)">'
                audit_points_html += f'<span class="bp-audit-index">{idx}</span>'
                audit_points_html += f'<a href="{h(url)}" target="_blank" rel="noopener" class="bp-audit-link">{h(fname)}</a>'
                if ext:
                    audit_points_html += f'<span class="bp-audit-ext">.{h(ext)}</span>'
                audit_points_html += "</div>"
            if len(files) > 50:
                audit_points_html += f'<div style="padding:.3rem .5rem;font-size:.78rem;color:var(--muted)">… and {len(files) - 50} more in <a href="{h(tree_url)}" target="_blank" rel="noopener" style="color:var(--accent)">GitHub folder</a></div>'
            audit_points_html += "</div></div>"
        if audit_points_data.get("fetched_at"):
            audit_points_html += f'<p style="font-size:.72rem;color:var(--muted);margin-top:.75rem">Cache updated: {h(audit_points_data["fetched_at"][:19])}</p>'
        audit_points_html += "</div></div>"
    if not audit_points_html:
        audit_points_html = (
            _bp_intro
            + '<div class="card bp-audit-section"><div class="card-title">QueryPie Audit Points</div><div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:.5rem">SaaS/DevSecOps audit checklists from <a href="https://github.com/querypie/audit-points" target="_blank" rel="noopener">querypie/audit-points</a>.</p><p style="color:var(--muted);font-size:.85rem">Run <code>claudesec scan -c saas</code> to detect products (Jenkins, Harbor, Nexus, Okta, etc.) and populate the checklist for this project.</p></div></div>'
        )

    ms_sources = ms_best_practices_data.get("sources", [])
    scubagear_enabled = _is_env_truthy(MS_INCLUDE_SCUBAGEAR_ENV)
    source_filter = (
        ms_best_practices_data.get("source_filter") or _normalized_source_filter()
    )
    audit_points_html += '<div class="card bp-audit-section ms-source-root"><div class="card-title">Windows / Intune / Office 365 best-practice sources</div>'
    # MS sources progress bar (same localStorage as audit points)
    audit_points_html += '<div style="padding:.5rem 1.25rem 0"><div class="ap-progress-label"><span id="ms-progress-label">0 / 0 reviewed</span><span id="ms-progress-pct">0%</span></div>'
    audit_points_html += '<div class="ap-progress-bar"><div id="ms-progress-fill" class="ap-progress-fill" style="width:0%"></div></div></div>'
    if source_filter == "none":
        preset_default = "none"
    elif source_filter == "official,gov":
        preset_default = "official,gov"
    else:
        preset_default = "all"
    audit_points_html += f'<div style="padding:0 1.25rem"><div class="source-filter-chips" data-active-filter="{h(source_filter)}"><button class="source-filter-chip{(" active" if preset_default == "all" else "")}" data-filter="all" onclick="applyMsSourcePresetFilter(this)">all</button><button class="source-filter-chip{(" active" if preset_default == "official,gov" else "")}" data-filter="official,gov" onclick="applyMsSourcePresetFilter(this)">official,gov</button><button class="source-filter-chip{(" active" if preset_default == "none" else "")}" data-filter="none" onclick="applyMsSourcePresetFilter(this)">none</button><span class="ms-source-filter-status" style="font-size:.75rem;color:var(--muted)">Active env filter: {h(source_filter)}</span></div></div>'
    if ms_sources:
        audit_points_html += '<div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:.45rem">Curated GitHub sources for Microsoft platform hardening and security baseline guidance.</p>'
        if source_filter != "all":
            audit_points_html += f'<p style="color:var(--muted);font-size:.8rem;margin-bottom:.55rem">Active source filter: <code>{h(source_filter)}</code> (set <code>{h(MS_SOURCE_FILTER_ENV)}=all</code> to view all trust levels).</p>'
        trust_counts = {"Microsoft Official": 0, "Government": 0, "Community": 0}
        for src in ms_sources:
            level = src.get("trust_level") or "Community"
            if level not in trust_counts:
                trust_counts[level] = 0
            trust_counts[level] += 1
        count_chips = []
        count_chips.append(
            f'<span class="badge info" style="font-size:.66rem">Total sources {len(ms_sources)}</span>'
        )
        for level in ("Microsoft Official", "Government", "Community"):
            cls = {
                "Microsoft Official": "trust-ms",
                "Government": "trust-gov",
                "Community": "trust-community",
            }.get(level, "trust-community")
            count_chips.append(
                f'<span class="trust-badge {h(cls)}">{h(level)} {trust_counts.get(level, 0)}</span>'
            )
        audit_points_html += f'<div style="display:flex;flex-wrap:wrap;gap:.45rem;margin-bottom:1rem">{"".join(count_chips)}</div>'
        if not scubagear_enabled:
            audit_points_html += f'<p style="color:var(--muted);font-size:.8rem;margin-bottom:1rem">Optional source available: <code>cisagov/ScubaGear</code> (enable with <code>{h(MS_INCLUDE_SCUBAGEAR_ENV)}=1</code> before dashboard generation).</p>'
        else:
            audit_points_html += '<p style="color:var(--muted);font-size:.8rem;margin-bottom:1rem"><code>cisagov/ScubaGear</code> is enabled as an additional Office 365 source.</p>'
        grouped_sources = defaultdict(list)
        for src in ms_sources:
            grouped_sources[src.get("product") or "Other"].append(src)
        for product in ("Windows", "Intune", "Office 365", "Other"):
            entries = grouped_sources.get(product, [])
            if not entries:
                continue
            entries.sort(
                key=lambda s: (
                    TRUST_LEVEL_ORDER.get(s.get("trust_level", "Community"), 9),
                    s.get("label", ""),
                )
            )
            audit_points_html += f'<h4 style="margin:.75rem 0 .5rem 0;font-size:.9rem;color:var(--text)">{h(product)}</h4>'
            for src in entries:
                files = src.get("files", [])
                repo_url = src.get("repo_url") or "#"
                label = src.get("label") or src.get("repo") or "Source"
                reason = src.get("reason") or ""
                updated = src.get("updated_at") or ""
                trust_level = src.get("trust_level") or "Community"
                trust_class = {
                    "Microsoft Official": "trust-ms",
                    "Government": "trust-gov",
                    "Community": "trust-community",
                }.get(trust_level, "trust-community")
                trust_token = _trust_token_from_level(trust_level)
                archive_tag = (
                    ' <span style="font-size:.72rem;color:#f59e0b">(archived)</span>'
                    if src.get("archived")
                    else ""
                )
                src_id = f"ms-{product}-{label}".lower().replace(" ", "-").replace("/", "-").replace("(", "").replace(")", "")
                audit_points_html += f'<div class="card ms-source-entry" data-trust-token="{h(trust_token)}" style="margin-bottom:.75rem;padding:0"><div class="card-title" onclick="this.parentElement.querySelector(\'.ms-src-body\').style.display=this.parentElement.querySelector(\'.ms-src-body\').style.display==\'none\'?\'\':\'none\'" style="cursor:pointer;user-select:none;display:flex;align-items:center;gap:.5rem"><input type="checkbox" class="ap-checkbox ms-src-checkbox" data-ap-id="{h(src_id)}" onchange="apToggleCheck(this);msUpdateProgress()" onclick="event.stopPropagation()"> ▸ {h(label)} <span class="trust-badge {h(trust_class)}">{h(trust_level)}</span>{archive_tag} <span style="font-size:.75rem;color:var(--muted);font-weight:400">({len(files)} files)</span></div>'
                audit_points_html += '<div class="ms-src-body" style="padding:.75rem 1rem">'
                audit_points_html += f'<div style="color:var(--muted);font-size:.82rem;margin-bottom:.45rem">{h(reason)}</div>'
                audit_points_html += f'<a href="{h(repo_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.85rem">Open repository</a>'
                if updated:
                    audit_points_html += f'<span style="font-size:.75rem;color:var(--muted);margin-left:.5rem">Updated: {h(updated[:10])}</span>'
                for fidx, f in enumerate(files[:25]):
                    url = f.get("url") or f.get("raw_url") or "#"
                    fname = f.get("path") or f.get("name") or "file"
                    file_id = f"{src_id}-f{fidx}"
                    audit_points_html += f'<div class="bp-audit-item-row" style="margin-top:.35rem"><input type="checkbox" class="ap-checkbox ms-file-checkbox" data-ap-id="{h(file_id)}" onchange="apToggleCheck(this);msUpdateProgress()"><a href="{h(url)}" target="_blank" rel="noopener" class="mono bp-audit-link" style="font-size:.8rem;color:var(--text)">{h(fname)}</a></div>'
                if len(files) > 25:
                    audit_points_html += f'<div style="margin-top:.5rem;color:var(--muted);font-size:.78rem">… and {len(files) - 25} more files</div>'
                audit_points_html += "</div></div>"
        if ms_best_practices_data.get("fetched_at"):
            audit_points_html += f'<p style="font-size:.72rem;color:var(--muted);margin-top:1rem">Microsoft source cache updated: {h(ms_best_practices_data["fetched_at"][:19])}</p>'
        audit_points_html += "</div>"
    else:
        if source_filter == "none":
            audit_points_html += f'<div style="padding:1rem 1.25rem;color:var(--muted)">Microsoft source area is hidden by <code>{h(MS_SOURCE_FILTER_ENV)}=none</code>. Change to <code>all</code> or <code>official,gov</code> and re-run dashboard generation.</div>'
        elif source_filter != "all":
            audit_points_html += f'<div style="padding:1rem 1.25rem;color:var(--muted)">No Microsoft best-practice sources matched filter <code>{h(source_filter)}</code>. Try <code>{h(MS_SOURCE_FILTER_ENV)}=all</code> and re-run dashboard generation.</div>'
        else:
            audit_points_html += '<div style="padding:1rem 1.25rem;color:var(--muted)">No Microsoft best-practice source metadata cached yet. Re-run dashboard generation to refresh GitHub source discovery.</div>'
    audit_points_html += "</div>"
    # ── SaaS / DevOps best-practice sources (Okta, QueryPie, ArgoCD, IDE) ──
    saas_bp_data = load_saas_best_practices(scan_dir)
    saas_sources = saas_bp_data.get("sources") or SAAS_BEST_PRACTICES_SOURCES
    audit_points_html += '<div class="card bp-audit-section ms-source-root"><div class="card-title">Okta / QueryPie / ArgoCD / IDE best-practice sources</div>'
    audit_points_html += '<div style="padding:.5rem 1.25rem 0"><div class="ap-progress-label"><span id="saas-progress-label">0 / 0 reviewed</span><span id="saas-progress-pct">0%</span></div>'
    audit_points_html += '<div class="ap-progress-bar"><div id="saas-progress-fill" class="ap-progress-fill" style="width:0%"></div></div></div>'
    if saas_sources:
        audit_points_html += '<div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:.45rem">Curated sources for identity, database access control, GitOps, and IDE security hardening.</p>'
        saas_trust_counts: dict[str, int] = {}
        for src in saas_sources:
            level = src.get("trust_level") or "Community"
            saas_trust_counts[level] = saas_trust_counts.get(level, 0) + 1
        saas_count_chips = [f'<span class="badge info" style="font-size:.66rem">Total sources {len(saas_sources)}</span>']
        for level in ("Vendor Official", "CNCF Official", "Government", "Community"):
            if saas_trust_counts.get(level, 0) > 0:
                cls = {"Vendor Official": "trust-ms", "CNCF Official": "trust-ms", "Government": "trust-gov", "Community": "trust-community"}.get(level, "trust-community")
                saas_count_chips.append(f'<span class="trust-badge {h(cls)}">{h(level)} {saas_trust_counts[level]}</span>')
        audit_points_html += f'<div style="display:flex;flex-wrap:wrap;gap:.45rem;margin-bottom:1rem">{"".join(saas_count_chips)}</div>'
        saas_grouped: dict[str, list] = {}
        for src in saas_sources:
            p = src.get("product") or "Other"
            saas_grouped.setdefault(p, []).append(src)
        for product in ("Okta", "QueryPie", "ArgoCD", "IDE"):
            entries = saas_grouped.get(product, [])
            if not entries:
                continue
            audit_points_html += f'<h4 style="margin:.75rem 0 .5rem 0;font-size:.9rem;color:var(--text)">{h(product)}</h4>'
            for src in entries:
                files = src.get("files", [])
                repo_url = src.get("repo_url") or f"https://github.com/{src.get('repo', '')}"
                label = src.get("label") or src.get("repo") or "Source"
                reason = src.get("reason") or ""
                trust_level = src.get("trust_level") or "Community"
                trust_class = {"Vendor Official": "trust-ms", "CNCF Official": "trust-ms", "Government": "trust-gov", "Community": "trust-community"}.get(trust_level, "trust-community")
                src_id = f"saas-{product}-{label}".lower().replace(" ", "-").replace("/", "-").replace("(", "").replace(")", "")
                focus = ", ".join(src.get("focus_paths", []))
                audit_points_html += f'<div class="card ms-source-entry" style="margin-bottom:.75rem;padding:0"><div class="card-title" onclick="this.parentElement.querySelector(\'.ms-src-body\').style.display=this.parentElement.querySelector(\'.ms-src-body\').style.display==\'none\'?\'\':\'none\'" style="cursor:pointer;user-select:none;display:flex;align-items:center;gap:.5rem"><input type="checkbox" class="ap-checkbox saas-src-checkbox" data-ap-id="{h(src_id)}" onchange="apToggleCheck(this);saasUpdateProgress()" onclick="event.stopPropagation()"> ▸ {h(label)} <span class="trust-badge {h(trust_class)}">{h(trust_level)}</span> <span style="font-size:.75rem;color:var(--muted);font-weight:400">({len(files)} files)</span></div>'
                audit_points_html += '<div class="ms-src-body" style="padding:.75rem 1rem">'
                audit_points_html += f'<div style="color:var(--muted);font-size:.82rem;margin-bottom:.45rem">{h(reason)}</div>'
                audit_points_html += f'<a href="{h(repo_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.85rem">Open repository ↗</a>'
                if focus:
                    audit_points_html += f'<div style="color:var(--muted);font-size:.78rem;margin-top:.35rem">Focus paths: <code>{h(focus)}</code></div>'
                for fidx, fl in enumerate(files[:25]):
                    url = fl.get("url") or fl.get("raw_url") or "#"
                    fname = fl.get("path") or fl.get("name") or "file"
                    file_id = f"{src_id}-f{fidx}"
                    audit_points_html += f'<div class="bp-audit-item-row" style="margin-top:.35rem"><input type="checkbox" class="ap-checkbox saas-file-checkbox" data-ap-id="{h(file_id)}" onchange="apToggleCheck(this);saasUpdateProgress()"><a href="{h(url)}" target="_blank" rel="noopener" class="mono bp-audit-link" style="font-size:.8rem;color:var(--text)">{h(fname)}</a></div>'
                audit_points_html += "</div></div>"
        audit_points_html += "</div>"
    else:
        audit_points_html += '<div style="padding:1rem 1.25rem;color:var(--muted)">No SaaS/DevOps best-practice sources configured.</div>'
    audit_points_html += "</div>"
    overview = _build_overview_blocks(
        prov_summary,
        all_findings,
        envs,
        net_data,
        datadog_data,
        passed,
        total_prowler_pass,
        warnings,
        total,
        failed,
        arch_domains,
        audit_points_data,
        ms_best_practices_data,
        findings_list,
    )
    n_crit = overview["n_crit"]
    n_high = overview["n_high"]
    n_med = overview["n_med"]
    n_low = overview["n_low"]
    n_info = overview["n_info"]
    policy_022_top = overview["policy_022_top"]
    prov_cards = overview["prov_cards"]
    bar_crit = overview["bar_crit"]
    bar_high = overview["bar_high"]
    bar_med = overview["bar_med"]
    bar_warn = overview["bar_warn"]
    bar_low = overview["bar_low"]
    top_findings_html = overview["top_findings_html"]
    env_connected = overview["env_connected"]
    env_total = overview["env_total"]
    service_surface_html = overview["service_surface_html"]
    priority_queue_html = overview["priority_queue_html"]
    network_tools_html = overview["network_tools_html"]
    network_tools_badge = overview["network_tools_badge"]

    # Architecture domain summary for Overview tab
    arch_overview_html = '<div class="arch-ov-grid">'
    for idx, dom in enumerate(arch_domains):
        fc = dom["fail_count"]
        status_cls = "arch-ov-fail" if fc > 0 else "arch-ov-pass"
        arch_overview_html += (
            f'<div class="arch-ov-card {status_cls}" onclick="switchTab(\'arch\',\'arch-dom-{idx}\')">'
            f'<div class="arch-ov-icon">{dom["icon"]}</div>'
            f'<div class="arch-ov-name">{h(dom["name"])}</div>'
            f'<div class="arch-ov-count">{fc}</div>'
            f'<div class="arch-ov-label">{"findings" if fc != 1 else "finding"}</div>'
            f'</div>'
        )
    arch_overview_html += '</div>'

    # Network tools summary for Overview tab
    ts = net_data.get("trivy_summary", {}) if net_data else {}
    nmap_count = len(net_data.get("nmap_scans", [])) if net_data else 0
    ssl_count = len(net_data.get("sslscan_results", [])) if net_data else 0
    trivy_crit = ts.get("critical", 0)
    trivy_high = ts.get("high", 0)
    trivy_med = ts.get("medium", 0)
    trivy_low = ts.get("low", 0)
    trivy_total = trivy_crit + trivy_high + trivy_med + trivy_low
    net_summary_html = '<div class="net-ov-row">'
    net_summary_html += (
        f'<div class="net-ov-card" onclick="switchTab(\'networktools\')">'
        f'<div class="net-ov-icon">🔍</div>'
        f'<div class="net-ov-body"><div class="net-ov-title">Trivy CVEs</div>'
        f'<div class="net-ov-nums">'
    )
    if trivy_total > 0:
        if trivy_crit: net_summary_html += f'<span class="pcs-crit">{trivy_crit}C</span>'
        if trivy_high: net_summary_html += f'<span class="pcs-high">{trivy_high}H</span>'
        if trivy_med: net_summary_html += f'<span class="pcs-med">{trivy_med}M</span>'
        if trivy_low: net_summary_html += f'<span class="pcs-low">{trivy_low}L</span>'
    else:
        net_summary_html += '<span class="net-ov-none">—</span>'
    net_summary_html += '</div></div></div>'
    net_summary_html += (
        f'<div class="net-ov-card" onclick="switchTab(\'networktools\')">'
        f'<div class="net-ov-icon">🌐</div>'
        f'<div class="net-ov-body"><div class="net-ov-title">Nmap scans</div>'
        f'<div class="net-ov-nums"><span class="net-ov-big">{nmap_count}</span></div></div></div>'
    )
    net_summary_html += (
        f'<div class="net-ov-card" onclick="switchTab(\'networktools\')">'
        f'<div class="net-ov-icon">🔒</div>'
        f'<div class="net-ov-body"><div class="net-ov-title">TLS/SSL scans</div>'
        f'<div class="net-ov-nums"><span class="net-ov-big">{ssl_count}</span></div></div></div>'
    )
    net_summary_html += '</div>'

    # Architecture diagram: embed SVG from docs/architecture, or use built-in inline SVG
    arch_img = _get_architecture_diagram_html(output_file, scan_dir)

    # Policies: load from .claudesec-assets/policies.json (generated by build-dashboard.py)
    policies_html = ""
    try:
        policies_path = os.path.join(scan_dir or os.getcwd(), ".claudesec-assets", "policies.json")
        if os.path.isfile(policies_path):
            with open(policies_path, "r", encoding="utf-8") as _pf:
                _policies = json.load(_pf)
            if _policies:
                policies_html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:.75rem">'
                _isms_colors = ["var(--accent)", "#0984e3", "#00b894", "#f39c12", "#e17055", "#6c5ce7", "#fd79a8", "#00cec9"]
                for _pi, _pol in enumerate(_policies):
                    _color = _isms_colors[_pi % len(_isms_colors)]
                    _url = h(_pol.get("url", ""))
                    _name = h(_pol.get("name", ""))
                    _ch = _pol.get("total_chapters", 0)
                    _ar = _pol.get("total_articles", 0)
                    _isms = " · ".join(h(c) for c in _pol.get("isms_controls", []))
                    policies_html += f'<div style="border:1px solid var(--border);border-left:3px solid {_color};border-radius:10px;overflow:hidden;cursor:pointer" '
                    policies_html += "onclick=\"var d=this.querySelector('.pol-det');if(d.style.display==='none'){d.style.display='block'}else{d.style.display='none'}\">"
                    policies_html += f'<div style="display:flex;align-items:center;gap:8px;padding:12px 14px;background:var(--card2)">'
                    policies_html += f'<span style="font-size:16px">📄</span>'
                    policies_html += f'<div style="flex:1"><div style="font-size:13px;font-weight:700">{_name}</div>'
                    policies_html += f'<div style="font-size:10px;color:var(--muted)">{_ch}장 {_ar}조'
                    if _isms:
                        policies_html += f' · ISMS: {_isms}'
                    policies_html += '</div></div>'
                    if _url:
                        policies_html += f'<a href="{_url}" target="_blank" rel="noopener" onclick="event.stopPropagation()" style="font-size:10px;color:var(--accent);text-decoration:underline">원문↗</a>'
                    policies_html += '</div>'
                    # Article list (collapsed)
                    _articles = _pol.get("articles", [])
                    if _articles:
                        policies_html += '<div class="pol-det" style="display:none;padding:10px 14px;border-top:1px dashed var(--border);max-height:200px;overflow-y:auto">'
                        _cur_ch = ""
                        for _a in _articles:
                            _ach = _a.get("chapter", "")
                            if _ach != _cur_ch:
                                _cur_ch = _ach
                                policies_html += f'<div style="font-size:11px;font-weight:700;color:var(--accent);margin:6px 0 3px">{h(_ach)}</div>'
                            policies_html += f'<div style="font-size:11px;color:var(--muted);padding:1px 0">{_a.get("num", "")}. {h(_a.get("title", ""))}</div>'
                        policies_html += '</div>'
                    policies_html += '</div>'
                policies_html += '</div>'
                _total_a = sum(p.get("total_articles", 0) for p in _policies)
                policies_html = f'<div style="font-size:.82rem;color:var(--muted);margin-bottom:.75rem">{len(_policies)}개 규정 · {_total_a}개 조항 · Google Drive 원본 연동</div>' + policies_html
    except Exception as _pe:
        print(f"  [policies] load error: {_pe}")

    if policies_html:
        print(f"  [policies] loaded successfully")
    else:
        print(f"  [policies] no data (scan_dir={scan_dir})")

    # ── Assemble Full HTML ───────────────────────────────────────────────
    reps = _build_replacements(
        VERSION,
        now,
        duration,
        passed,
        failed,
        warnings,
        skipped,
        score,
        grade,
        grade_color,
        active,
        score * 327 // 100,
        n_crit,
        n_high,
        n_med,
        n_low,
        warnings,
        policy_022_top,
        n_info,
        total_passed,
        total_prowler_fail,
        total_prowler_pass,
        total_all,
        total_issues,
        env_html,
        env_connected,
        env_total,
        prov_cards,
        prov_table,
        scanner_rows,
        scanner_cat_summary,
        scanner_insights_html,
        total,
        round(passed / total * 100) if total else 0,
        round(failed / total * 100) if total else 0,
        round(warnings / total * 100) if total else 0,
        gh_table,
        len(gh_finds),
        aws_table,
        len(aws_finds),
        gcp_table,
        len(gcp_finds),
        gws_table,
        len(gws_finds),
        k8s_table,
        len(k8s_finds),
        azure_table,
        len(azure_finds),
        m365_table,
        len(m365_finds),
        iac_table,
        len(iac_finds),
        owasp_html,
        arch_html,
        arch_img,
        comp_html,
        history_json,
        top_findings_html,
        bar_crit,
        bar_high,
        bar_med,
        bar_warn,
        bar_low,
        network_tools_html,
        network_tools_badge,
        audit_points_html,
        failed + warnings,
        scan_scope_html,
        auth_summary_html,
        arch_overview_html,
        net_summary_html,
        policies_html,
        service_surface_html,
        priority_queue_html,
    )
    _apply_template_and_write(output_file, _load_html_template(), reps)


# ── HTML Template ────────────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent


def _load_html_template() -> str:
    tmpl_path = _TEMPLATE_DIR / "dashboard-template.html"
    return tmpl_path.read_text(encoding="utf-8")


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    scan_json = os.environ.get("CLAUDESEC_SCAN_JSON", "")
    prowler_dir = os.environ.get("CLAUDESEC_PROWLER_DIR", ".claudesec-prowler")
    history_dir = os.environ.get("CLAUDESEC_HISTORY_DIR", ".claudesec-history")
    output_file = sys.argv[1] if len(sys.argv) > 1 else "claudesec-dashboard.html"

    if scan_json and os.path.isfile(scan_json):
        scan_data = load_scan_results(scan_json)
    else:
        scan_data = {
            "passed": int(os.environ.get("CLAUDESEC_PASSED", 0)),
            "failed": int(os.environ.get("CLAUDESEC_FAILED", 0)),
            "warnings": int(os.environ.get("CLAUDESEC_WARNINGS", 0)),
            "skipped": int(os.environ.get("CLAUDESEC_SKIPPED", 0)),
            "total": int(os.environ.get("CLAUDESEC_TOTAL", 0)),
            "score": int(os.environ.get("CLAUDESEC_SCORE", 0)),
            "grade": os.environ.get("CLAUDESEC_GRADE", "F"),
            "duration": int(os.environ.get("CLAUDESEC_DURATION", 0)),
            "findings": json.loads(os.environ.get("CLAUDESEC_FINDINGS_JSON", "[]")),
        }

    generate_dashboard(scan_data, prowler_dir, history_dir, output_file)
    print(f"Dashboard v{VERSION} generated: {output_file}")
