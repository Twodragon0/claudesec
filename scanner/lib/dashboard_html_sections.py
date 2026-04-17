#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Sections
Analytical section builder functions extracted from dashboard-gen.py.
"""

import os
import sys
from typing import Any

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import h, sev_badge
from dashboard_mapping import CATEGORY_META, get_check_en

# Re-export builders extracted into dedicated modules in the Option B split
# (see .omc/plans/dashboard-standards-split.md). Keeping the names here means
# `from dashboard_html_sections import _build_owasp_html` etc. continues to work.
from dashboard_html_owasp import _build_owasp_html  # noqa: F401
from dashboard_html_arch import _build_arch_html  # noqa: F401
from dashboard_html_compliance import _build_compliance_html  # noqa: F401
from dashboard_html_helpers import (
    _infer_category, _has_cmd, _cmd_pill,
    _compute_severity_counts, _compute_severity_bars,
    _build_replacements,
)
from dashboard_html_builders import (
    _build_provider_cards,
    _build_artifact_links_section,
    _build_target_posture_table,
    _build_trivy_section,
    _build_datadog_logs_section,
    _build_datadog_signals_section,
    _build_datadog_cases_section,
)
from dashboard_html_audit_sources import (
    build_ms_sources_html,
    build_saas_sources_html,
)
from dashboard_html_audit_points import (
    build_audit_points_querypie_html,
)
from dashboard_html_network import (
    build_network_config_section,
    build_tooling_readiness_section,
)


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
    """Delegates to dashboard_html_network.build_network_config_section (kept for back-compat)."""
    return build_network_config_section()


def _build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled):
    """Delegates to dashboard_html_network.build_tooling_readiness_section (kept for back-compat)."""
    return build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled)


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


def _build_prov_table(prov_summary) -> str:
    """Build the Prowler provider summary table rows (fixed display order + extras)."""
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
    return prov_table


def _build_audit_points_html(
    audit_points_data,
    audit_points_detected,
    ms_best_practices_data,
    saas_bp_data,
) -> str:
    """Build the QueryPie Audit Points tab HTML (audit points + MS sources + SaaS sources)."""
    audit_points_html = build_audit_points_querypie_html(
        audit_points_data, audit_points_detected
    )
    audit_points_html += build_ms_sources_html(ms_best_practices_data)
    audit_points_html += build_saas_sources_html(saas_bp_data)
    return audit_points_html
