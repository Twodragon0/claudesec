#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Audit Points
QueryPie audit-points HTML builders (detected-products summary, per-product cards,
and All-products catalog), extracted from dashboard_html_sections.py.
"""

import os
import sys
import urllib.parse

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import (
    h,
    AUDIT_POINTS_REPO,
)


def build_audit_points_querypie_html(audit_points_data, audit_points_detected) -> str:
    """Build the QueryPie detected-products summary, per-product cards, and All-products catalog HTML.

    Returns the HTML for the audit-points portion only (no MS/SaaS sources).
    """
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
    return audit_points_html


__all__ = [
    "build_audit_points_querypie_html",
]
