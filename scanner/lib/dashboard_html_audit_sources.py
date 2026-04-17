#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Audit Sources
Builders for Microsoft (Windows/Intune/Office 365) and SaaS (Okta/QueryPie/ArgoCD/IDE)
best-practice source sections, extracted from dashboard_html_sections.py.
"""

import os
import sys
from collections import defaultdict

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import (
    h,
    TRUST_LEVEL_ORDER,
    MS_INCLUDE_SCUBAGEAR_ENV,
    MS_SOURCE_FILTER_ENV,
    _is_env_truthy,
    _normalized_source_filter,
    _trust_token_from_level,
)
from dashboard_api_client import SAAS_BEST_PRACTICES_SOURCES


def build_ms_sources_html(ms_best_practices_data) -> str:
    """Build the Microsoft Windows/Intune/Office 365 best-practice sources HTML section."""
    ms_best_practices_data = ms_best_practices_data or {}
    ms_sources = ms_best_practices_data.get("sources", [])
    scubagear_enabled = _is_env_truthy(MS_INCLUDE_SCUBAGEAR_ENV)
    source_filter = (
        ms_best_practices_data.get("source_filter") or _normalized_source_filter()
    )
    audit_points_html = '<div class="card bp-audit-section ms-source-root"><div class="card-title">Windows / Intune / Office 365 best-practice sources</div>'
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
    return audit_points_html


def build_saas_sources_html(saas_bp_data) -> str:
    """Build the Okta/QueryPie/ArgoCD/IDE SaaS best-practice sources HTML section."""
    saas_bp_data = saas_bp_data or {}
    saas_sources = saas_bp_data.get("sources") or SAAS_BEST_PRACTICES_SOURCES
    audit_points_html = '<div class="card bp-audit-section ms-source-root"><div class="card-title">Okta / QueryPie / ArgoCD / IDE best-practice sources</div>'
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
    return audit_points_html


__all__ = [
    "build_ms_sources_html",
    "build_saas_sources_html",
]
