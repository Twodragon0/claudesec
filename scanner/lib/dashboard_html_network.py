#!/usr/bin/env python3
"""
ClaudeSec Dashboard HTML Network
Builders for the Network tab configuration cockpit card and the tooling
readiness / install-guidance card, extracted from dashboard_html_sections.py.
"""

import os
import sys

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from dashboard_utils import h
from dashboard_html_helpers import _has_cmd, _cmd_pill


def build_network_config_section():
    """Build the network configuration cockpit card."""
    html = ""
    net_enabled = os.environ.get("CLAUDESEC_NETWORK_SCAN_ENABLED", "0")
    net_targets = os.environ.get("CLAUDESEC_NETWORK_SCAN_TARGETS", "")
    trivy_enabled = os.environ.get("CLAUDESEC_TRIVY_ENABLED", "1")
    html += '<div class="card"><div class="card-title">Network &amp; Security — Configuration</div><div style="padding:1rem 1.25rem">'
    html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-bottom:.9rem">'
    html += f'<div class="ssb-item"><strong>network_scan_enabled</strong><div class="mono" style="margin-top:.25rem">{h(net_enabled)}</div></div>'
    html += f'<div class="ssb-item"><strong>network_scan_targets</strong><div class="mono" style="margin-top:.25rem;word-break:break-all">{h(net_targets or "(empty)")}</div></div>'
    html += f'<div class="ssb-item"><strong>trivy_enabled</strong><div class="mono" style="margin-top:.25rem">{h(trivy_enabled)}</div></div>'
    html += "</div>"
    html += (
        '<div style="color:var(--muted);font-size:.82rem;line-height:1.6">'
    )
    html += "<div><strong>Enable network scanning</strong></div>"
    html += '<div class="mono" style="margin-top:.35rem;white-space:pre-wrap;border:1px solid var(--border);border-radius:10px;padding:.75rem;background:rgba(255,255,255,.02)">'
    html += "# Add to .claudesec.yml or export as environment variables\n"
    html += "export CLAUDESEC_NETWORK_SCAN_ENABLED=1\n"
    html += (
        'export CLAUDESEC_NETWORK_SCAN_TARGETS="your-domain.com:443"\n'
    )
    html += "./run --quick    # or ./run-all.sh\n"
    html += "</div>"
    html += '<div style="margin-top:.6rem">Results are saved to <code>.claudesec-network/</code>. Targets are redacted by default.</div>'
    html += "</div>"
    html += "</div></div>"
    return html, net_enabled, net_targets, trivy_enabled


def build_tooling_readiness_section(net_data, net_enabled, net_targets, trivy_enabled):
    """Build tooling detection, guidance, and install commands card."""
    html = ""
    # Tooling detection + guidance (why empty / how to fill).
    has_targets = bool((net_targets or "").strip())
    is_net_enabled = str(net_enabled).strip() in ("1", "true", "yes", "on")
    is_trivy_enabled = str(trivy_enabled).strip() not in ("0", "false", "no", "off")

    has_trivy = _has_cmd("trivy")
    has_nmap = _has_cmd("nmap")
    has_sslscan = _has_cmd("sslscan")
    has_testssl = False  # removed: use sslscan instead
    has_curl = _has_cmd("curl")
    has_python = _has_cmd("python3")

    html += '<div class="card"><div class="card-title">Tooling readiness (auto-detected)</div><div style="padding:1rem 1.25rem">'
    html += '<div class="env-grid" style="padding:0">'
    html += _cmd_pill(
        "python3", has_python, "required for normalization + dashboard"
    )
    html += _cmd_pill("curl", has_curl, "required for HTTP header scan")
    html += _cmd_pill(
        "trivy", has_trivy, "filesystem/config scan (.claudesec-network/trivy-*.json)"
    )
    html += _cmd_pill(
        "nmap", has_nmap, "optional port scan (when enabled + targets set)"
    )
    html += _cmd_pill(
        "sslscan", has_sslscan, "optional TLS scan (when enabled + targets set)"
    )
    html += "</div>"

    # Why sections are empty (explain with concrete next steps).
    missing_notes: list[str] = []
    if not is_net_enabled:
        missing_notes.append(
            "Enable network scanning: `export CLAUDESEC_NETWORK_SCAN_ENABLED=1` and set scan targets."
        )
    if is_net_enabled and not has_targets:
        missing_notes.append(
            "No targets configured: set `CLAUDESEC_NETWORK_SCAN_TARGETS` (comma-separated hosts/URLs)."
        )
    if is_net_enabled and has_targets and not has_curl:
        missing_notes.append("`curl` not found: HTTP header scan can't run.")
    if is_net_enabled and has_targets and not has_sslscan:
        missing_notes.append(
            "`sslscan` not found: TLS grade section will be empty. Install with `brew install sslscan`."
        )
    if is_trivy_enabled and not has_trivy:
        missing_notes.append(
            "`trivy` not found: Trivy section will be empty (install Trivy or disable with `CLAUDESEC_TRIVY_ENABLED=0`)."
        )

    # If artifacts still missing despite tooling, hint where to look.
    report = net_data.get("network_report")
    report_targets = report.get("targets", []) if isinstance(report, dict) else []
    has_http_artifacts = bool(report_targets)
    has_tls_artifacts = any(
        isinstance(t, dict) and isinstance(t.get("tls"), dict)
        for t in (report_targets or [])
        if isinstance(report_targets, list)
    )
    has_header_artifacts = any(
        isinstance(t, dict) and isinstance(t.get("http"), dict)
        for t in (report_targets or [])
        if isinstance(report_targets, list)
    )
    if is_net_enabled and has_targets and has_curl and not has_header_artifacts:
        missing_notes.append(
            "HTTP header artifacts not found yet. Re-run dashboard generation after enabling network scan; expected files: `.claudesec-network/http-headers-*.txt` and `network-report.v1.json`."
        )
    if (
        is_net_enabled
        and has_targets
        and (has_sslscan or has_testssl)
        and not has_tls_artifacts
    ):
        missing_notes.append(
            "TLS artifacts not found yet. Expected files: `.claudesec-network/sslscan-*.json` and `network-report.v1.json`."
        )

    if missing_notes:
        html += '<div style="margin-top:.85rem;border-top:1px solid var(--border);padding-top:.85rem">'
        html += (
            '<div style="font-weight:800;margin-bottom:.35rem">Next steps</div>'
        )
        html += (
            '<ul style="margin-left:1.1rem;color:var(--muted);line-height:1.7">'
        )
        for m in missing_notes[:8]:
            html += f"<li>{h(m)}</li>"
        html += "</ul>"
        html += "</div>"

    html += '<div style="margin-top:.9rem;border-top:1px solid var(--border);padding-top:.85rem">'
    html += '<div style="font-weight:800;margin-bottom:.35rem">Recommended install commands</div>'
    html += '<div class="mono" style="white-space:pre-wrap;border:1px solid var(--border);border-radius:10px;padding:.75rem;background:rgba(255,255,255,.02)">'
    html += "# macOS (Homebrew)\n"
    html += "brew install curl nmap sslscan\n"
    html += "brew install aquasecurity/trivy/trivy\n"
    html += "</div>"
    html += '<div style="margin-top:.5rem;color:var(--muted);font-size:.78rem;line-height:1.6">'
    html += "Tip: in CI, prefer pinned tool versions and run with least privilege. Only scan explicitly configured external targets."
    html += "</div></div>"
    html += "</div></div>"
    return html


__all__ = [
    "build_network_config_section",
    "build_tooling_readiness_section",
]
