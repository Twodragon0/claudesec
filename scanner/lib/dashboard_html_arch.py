#!/usr/bin/env python3
"""
ClaudeSec Dashboard — Architecture HTML builder.

Extracted from dashboard_html_sections.py via the Option B split documented in
.omc/plans/dashboard-standards-split.md.  Owns rendering of the architecture
domain cards with OWASP/compliance/scanner cross-links.
"""

import os
import sys

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import h, sev_badge, comp_slug
from dashboard_mapping import OWASP_2025, get_check_en


def _build_arch_html(arch_domains) -> str:
    """Build the Architecture tab HTML with OWASP/Compliance/Scanner cross-links."""
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
    return arch_html
