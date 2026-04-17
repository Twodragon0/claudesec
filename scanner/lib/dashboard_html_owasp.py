#!/usr/bin/env python3
"""
ClaudeSec Dashboard — OWASP HTML builder.

Extracted from dashboard_html_sections.py via the Option B split documented in
.omc/plans/dashboard-standards-split.md.  Owns rendering of the OWASP Top
10:2025 (web) and OWASP Top 10 for LLM Applications 2025 sections together
with cross-links to the architecture domains.
"""

import os
import sys

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import h, sev_badge
from dashboard_mapping import (
    OWASP_2025, OWASP_LLM_2025, OWASP_TO_ARCH, ARCH_DOMAINS,
    get_check_en,
)


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
