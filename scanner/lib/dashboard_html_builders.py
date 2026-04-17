#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Builders
Extracted data-source builder functions for HTML generation used by dashboard-gen.py.
"""

import os
import sys
from collections import defaultdict

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import (
    SEV_ORDER,
    h, sev_badge,
)

from dashboard_mapping import (
    ARCH_DOMAINS,
    CATEGORY_META,
)

from dashboard_html_helpers import (
    _infer_category, _scanner_default_action, _redact_target, _rel_link,
    _has_cmd, _cmd_pill,
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
