#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Compliance
Builders for the Compliance tab HTML (ISO 27001, ISMS-P, PCI-DSS...) and the
Prowler provider summary table, extracted from dashboard_html_sections.py.
"""

import os
import sys

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import (
    h,
    sev_badge,
    comp_slug,
)
from dashboard_mapping import (
    ARCH_DOMAINS,
    COMPLIANCE_FRAMEWORKS,
)


def build_compliance_html(compliance_map) -> str:
    """Build the Compliance tab HTML from the compliance_map."""
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
    return comp_html


def build_prov_table(prov_summary) -> str:
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


__all__ = [
    "build_compliance_html",
    "build_prov_table",
]
