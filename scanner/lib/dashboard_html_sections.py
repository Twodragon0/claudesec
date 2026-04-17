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

from dashboard_utils import (
    h, sev_badge, comp_slug,
)
from dashboard_mapping import (
    CATEGORY_META, OWASP_2025, OWASP_LLM_2025, OWASP_TO_ARCH, ARCH_DOMAINS,
    COMPLIANCE_FRAMEWORKS,
    get_check_en,
)
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
from dashboard_html_arch import (
    build_arch_html,
    build_owasp_html,
)
from dashboard_html_compliance import (
    build_compliance_html,
    build_prov_table,
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
    """Delegates to dashboard_html_arch.build_owasp_html (kept for back-compat)."""
    return build_owasp_html(owasp_map)


def _build_prov_table(prov_summary) -> str:
    """Delegates to dashboard_html_compliance.build_prov_table (kept for back-compat)."""
    return build_prov_table(prov_summary)


def _build_arch_html(arch_domains) -> str:
    """Delegates to dashboard_html_arch.build_arch_html (kept for back-compat)."""
    return build_arch_html(arch_domains)


def _build_compliance_html(compliance_map) -> str:
    """Delegates to dashboard_html_compliance.build_compliance_html (kept for back-compat)."""
    return build_compliance_html(compliance_map)


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
