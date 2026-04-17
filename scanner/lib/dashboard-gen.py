#!/usr/bin/env python3
"""
ClaudeSec Dashboard Generator v0.7.1
Generates a tabbed HTML security dashboard from scan results and Prowler OCSF data.

Modules:
  - dashboard_utils: Constants, TypedDicts, utility functions
  - dashboard_mapping: OWASP/Compliance/Architecture mapping data
  - dashboard_api_client: GitHub API communication
  - dashboard_data_loader: File-based data loading and parsing
  - dashboard_auth: Authentication/token expiry summary
"""

import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict

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

from dashboard_html_helpers import (  # noqa: F401
    _infer_category, _scanner_default_action, _redact_target, _rel_link,
    _has_cmd, _cmd_pill, _compute_severity_counts, _compute_severity_bars,
    _build_replacements, _SEV_WEIGHT,
)

from dashboard_html_builders import (  # noqa: F401
    _build_scanner_section, _build_provider_cards,
    _build_artifact_links_section, _build_target_posture_table,
    _build_trivy_section, _build_datadog_logs_section,
    _build_datadog_signals_section, _build_datadog_cases_section,
)

from dashboard_html_sections import (  # noqa: F401
    _build_service_surface_html, _build_priority_queue_html,
    _build_top_findings, _build_network_config_section,
    _build_tooling_readiness_section, _build_overview_blocks,
    _build_owasp_html, _build_arch_html, _build_compliance_html,
    _build_audit_points_html, _build_prov_table,
)


# _TEMPLATE_KEYS and _build_replacements imported from dashboard_html_helpers


from dashboard_template import (
    _apply_template_and_write, _get_architecture_diagram_html,
    _load_html_template,
)


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

    prov_table = _build_prov_table(prov_summary)

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
    arch_html = _build_arch_html(arch_domains)
    comp_html = _build_compliance_html(compliance_map)

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
    saas_bp_data = load_saas_best_practices(scan_dir)
    audit_points_html = _build_audit_points_html(
        audit_points_data,
        audit_points_detected,
        ms_best_practices_data,
        saas_bp_data,
    )
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
