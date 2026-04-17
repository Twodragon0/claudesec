#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Architecture / OWASP
Builders for the Architecture tab HTML and the OWASP Top 10 (Web + LLM 2025)
best-practice tab, extracted from dashboard_html_sections.py.
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
    OWASP_2025,
    OWASP_LLM_2025,
    OWASP_TO_ARCH,
    ARCH_DOMAINS,
    get_check_en,
)


def build_owasp_html(owasp_map):
    """Build the OWASP Top 10:2025 (Web + LLM) best-practice tab HTML."""
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


def build_arch_html(arch_domains) -> str:
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


__all__ = [
    "build_arch_html",
    "build_owasp_html",
]
