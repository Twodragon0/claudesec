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

from dashboard_utils import h, sev_badge
from dashboard_mapping import CATEGORY_META, get_check_en

# Re-export builders extracted into dedicated modules in the Option B split
# (see .omc/plans/dashboard-standards-split.md). Keeping the names here means
# `from dashboard_html_sections import _build_owasp_html` etc. continues to work.
from dashboard_html_owasp import _build_owasp_html  # noqa: F401
from dashboard_html_arch import _build_arch_html  # noqa: F401
from dashboard_html_compliance import _build_compliance_html  # noqa: F401
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
from dashboard_html_network import (
    build_network_config_section,
    build_tooling_readiness_section,
)
from dashboard_html_overview import (
    build_service_surface_html,
    build_priority_queue_html,
    build_overview_blocks,
    _build_top_findings,  # noqa: F401  (re-exported for dashboard-gen.py back-compat)
)


def _build_service_surface_html(*args, **kwargs):
    """Delegates to dashboard_html_overview.build_service_surface_html (kept for back-compat)."""
    return build_service_surface_html(*args, **kwargs)


def _build_priority_queue_html(*args, **kwargs):
    """Delegates to dashboard_html_overview.build_priority_queue_html (kept for back-compat)."""
    return build_priority_queue_html(*args, **kwargs)


def _build_network_config_section():
    """Delegates to dashboard_html_network.build_network_config_section (kept for back-compat)."""
    return build_network_config_section()


def _build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled):
    """Delegates to dashboard_html_network.build_tooling_readiness_section (kept for back-compat)."""
    return build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled)


def _build_overview_blocks(*args, **kwargs):
    """Delegates to dashboard_html_overview.build_overview_blocks (kept for back-compat)."""
    return build_overview_blocks(*args, **kwargs)


def _build_prov_table(prov_summary) -> str:
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
