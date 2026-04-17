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
    _build_owasp_html,
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
