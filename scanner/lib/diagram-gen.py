#!/usr/bin/env python3
"""
ClaudeSec Diagram Generator — draw.io architecture, scan flow, and security domains.
Combines scan results, Prowler OCSF, and history to produce .drawio diagrams.
"""
import json
import os
import sys
import xml.etree.ElementTree as ET  # builders only (Element, SubElement, tostring) — no untrusted XML parsed here
from pathlib import Path
import hashlib

# Sibling-module imports: ensure this file's dir (scanner/lib) is importable
# whether run directly (python3 scanner/lib/diagram-gen.py) or loaded via
# importlib.spec_from_file_location (the test harness, since the filename has a
# hyphen). Mirrors the _LIB_DIR pattern used by the dashboard_* modules.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard_arch import ARCH_DOMAINS  # noqa: E402  (canonical security domains)
from dashboard_compliance import COMPLIANCE_FRAMEWORKS  # noqa: E402
# load_scan_results is single-sourced in dashboard_data_loader (with try/except
# hardening) so the two implementations can't drift.
from dashboard_data_loader import load_scan_results  # noqa: E402,F401
# Low-level draw.io (mxGraph) XML primitives live in diagram_drawio (leaf module,
# no back-dependency on this file) — imported so the page/diagram builders below
# and the tests (MOD.mx_escape / MOD.drawio_cell …) resolve them as before.
from diagram_drawio import (  # noqa: E402,F401
    mx_escape,
    drawio_cell,
    emit_mx_geometry,
    create_drawio_root,
    create_multipage_drawio_root,
    add_drawio_page,
    _draw_edge,
)
# Scan data loading/aggregation lives in the diagram_data leaf module; the draw.io
# builders below and the tests (MOD.aggregate_scan_data / MOD.load_prowler_files /
# MOD.CATEGORIES …) resolve them via these re-exports.
from diagram_data import (  # noqa: E402,F401
    CATEGORIES,
    _parse_ocsf_json,
    load_prowler_files,
    load_scan_history,
    aggregate_scan_data,
)
# SVG builders live in the diagram_svg leaf module (re-exported so
# MOD.generate_architecture_svg / MOD.generate_overview_svg / MOD._svg_escape
# resolve as before).
from diagram_svg import (  # noqa: E402,F401
    _svg_escape,
    generate_architecture_svg,
    generate_overview_svg,
)

VERSION = "0.1.0"

# Security architecture domains and compliance frameworks are single-sourced
# from dashboard_arch.ARCH_DOMAINS and dashboard_compliance.COMPLIANCE_FRAMEWORKS
# (imported above) — no inline copies here, so the diagram never drifts from the
# dashboard. Kept honest by scanner/tests/test_ci_diagram_gen_canonical_sync.py.


def _overview_architecture_page(gr, agg):
    """Page 1: Architecture overview (same as existing claudesec-architecture.drawio)."""
    sid = 2
    style_box = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    style_data = "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    style_out = "rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;"

    c_scanner = ET.SubElement(gr, "mxCell", id=str(sid), value="ClaudeSec Scanner\n(CLI)", style=style_box, vertex="1", parent="1")
    emit_mx_geometry(c_scanner, 40, 80, 160, 60)
    id_scanner = sid
    sid += 1

    cat_label = "Scan Categories\n" + "\n".join(CATEGORIES[:8]) + "\n..."
    c_cat = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(cat_label), style=style_box, vertex="1", parent="1")
    emit_mx_geometry(c_cat, 260, 40, 190, 150)
    id_cat = sid
    sid += 1

    scan = agg.get("scan", {}) or {}
    score = scan.get("score", 0)
    grade = scan.get("grade", "F")
    total = scan.get("total", 0)
    failed = scan.get("failed", 0)
    warnings = scan.get("warnings", 0)
    summary = f"Scan Results\nTotal: {total} | Failed: {failed} | Warn: {warnings}\nScore: {score}% (Grade {grade})"
    c_results = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(summary), style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_results, 520, 40, 240, 70)
    id_results = sid
    sid += 1

    c_json = ET.SubElement(gr, "mxCell", id=str(sid), value="scan-report.json\n(results)", style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_json, 520, 125, 160, 45)
    sid += 1

    prowler_list = agg.get("prowler_providers", []) or []
    prov_summary = agg.get("prowler_summary", {}) or {}
    total_prowler_fail = sum(int(v.get("fail", 0) or 0) for v in prov_summary.values()) if isinstance(prov_summary, dict) else 0
    if prowler_list:
        sub = ", ".join(prowler_list[:5]) + (", ..." if len(prowler_list) > 5 else "")
        prowler_label = f"Prowler OCSF\nFail: {total_prowler_fail}\n({sub})"
    else:
        prowler_label = "Prowler OCSF\n(no data)"
    c_prowler = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(prowler_label), style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_prowler, 520, 185, 200, 65)
    sid += 1

    c_dash = ET.SubElement(gr, "mxCell", id=str(sid), value="Dashboard\n(HTML)", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(c_dash, 790, 70, 160, 60)
    id_dash = sid
    sid += 1

    hist = agg.get("history_count", 0)
    c_hist = ET.SubElement(gr, "mxCell", id=str(sid), value=f"History\n({hist} entries)", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(c_hist, 790, 150, 160, 45)
    id_hist = sid
    sid += 1

    sid = _draw_edge(gr, sid, id_scanner, id_cat)
    sid = _draw_edge(gr, sid, id_cat, id_results)
    sid = _draw_edge(gr, sid, id_results, id_dash)
    sid = _draw_edge(gr, sid, id_results, id_hist)


def _overview_service_flow_page(gr, agg):
    """Page 2: Service flow (who calls what, and what artifacts appear)."""
    sid = 2
    style_actor = "rounded=1;whiteSpace=wrap;html=1;fillColor=#0b1220;strokeColor=#334155;fontColor=#e2e8f0;"
    style_proc = "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    style_store = "shape=database;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    style_out = "rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;"

    # Actors
    user = ET.SubElement(gr, "mxCell", id=str(sid), value="Engineer / CI Runner", style=style_actor, vertex="1", parent="1")
    emit_mx_geometry(user, 40, 70, 180, 55)
    id_user = sid
    sid += 1

    repo = ET.SubElement(gr, "mxCell", id=str(sid), value="Repo / Workspace\n(scan target)", style=style_actor, vertex="1", parent="1")
    emit_mx_geometry(repo, 40, 150, 180, 55)
    id_repo = sid
    sid += 1

    # Core processes
    cli = ET.SubElement(gr, "mxCell", id=str(sid), value="claudesec (CLI)\nscan / dashboard / diagrams", style=style_proc, vertex="1", parent="1")
    emit_mx_geometry(cli, 280, 70, 230, 70)
    id_cli = sid
    sid += 1

    checks = ET.SubElement(gr, "mxCell", id=str(sid), value="Checks execution\n(categories: infra/ai/network/…)", style=style_proc, vertex="1", parent="1")
    emit_mx_geometry(checks, 560, 60, 240, 60)
    id_checks = sid
    sid += 1

    agg_box = ET.SubElement(gr, "mxCell", id=str(sid), value="Aggregate & normalize\n(severity/category)", style=style_proc, vertex="1", parent="1")
    emit_mx_geometry(agg_box, 560, 140, 240, 55)
    id_agg = sid
    sid += 1

    # Data stores / artifacts
    scan = agg.get("scan", {}) or {}
    score = scan.get("score", 0)
    grade = scan.get("grade", "F")
    total = scan.get("total", 0)
    store_scan = ET.SubElement(
        gr,
        "mxCell",
        id=str(sid),
        value=mx_escape(f"scan-report.json\nTotal:{total} Score:{score}% Grade:{grade}"),
        style=style_store,
        vertex="1",
        parent="1",
    )
    emit_mx_geometry(store_scan, 840, 55, 260, 65)
    id_store_scan = sid
    sid += 1

    store_prowler = ET.SubElement(gr, "mxCell", id=str(sid), value=".claudesec-prowler/\nprowler-*.ocsf.json", style=style_store, vertex="1", parent="1")
    emit_mx_geometry(store_prowler, 840, 135, 260, 55)
    id_store_prowler = sid
    sid += 1

    store_history = ET.SubElement(gr, "mxCell", id=str(sid), value=".claudesec-history/\nscan-*.json", style=style_store, vertex="1", parent="1")
    emit_mx_geometry(store_history, 840, 205, 260, 55)
    id_store_hist = sid
    sid += 1

    out_dash = ET.SubElement(gr, "mxCell", id=str(sid), value="claudesec-dashboard.html\n(embeds architecture SVG)", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(out_dash, 280, 200, 230, 60)
    id_out_dash = sid
    sid += 1

    out_diagrams = ET.SubElement(gr, "mxCell", id=str(sid), value="docs/architecture/\n*.drawio + claudesec-architecture.svg", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(out_diagrams, 560, 215, 240, 60)
    id_out_diagrams = sid
    sid += 1

    # Edges
    sid = _draw_edge(gr, sid, id_user, id_cli)
    sid = _draw_edge(gr, sid, id_repo, id_cli)
    sid = _draw_edge(gr, sid, id_cli, id_checks)
    sid = _draw_edge(gr, sid, id_checks, id_agg)
    sid = _draw_edge(gr, sid, id_agg, id_store_scan)
    sid = _draw_edge(gr, sid, id_checks, id_store_prowler, style="endArrow=classic;html=1;rounded=0;dashed=1;")
    sid = _draw_edge(gr, sid, id_agg, id_store_hist, style="endArrow=classic;html=1;rounded=0;dashed=1;")
    sid = _draw_edge(gr, sid, id_cli, id_out_dash)
    sid = _draw_edge(gr, sid, id_cli, id_out_diagrams)


def _overview_network_topology_page(gr, scan_dir):
    """Page 3: Network topology / inspection view.

    If `.claudesec-network/` has outputs, show a summary box; otherwise show a clear placeholder.
    """
    sid = 2
    style_zone = "rounded=1;whiteSpace=wrap;html=1;fillColor=#0f172a;strokeColor=#334155;fontColor=#e2e8f0;"
    style_comp = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    style_data = "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"

    # Zones / layers
    z_local = ET.SubElement(gr, "mxCell", id=str(sid), value="Local / CI Environment", style=style_zone, vertex="1", parent="1")
    emit_mx_geometry(z_local, 30, 30, 320, 240)
    sid += 1

    z_inet = ET.SubElement(gr, "mxCell", id=str(sid), value="Internet / SaaS / Cloud", style=style_zone, vertex="1", parent="1")
    emit_mx_geometry(z_inet, 400, 30, 740, 240)
    sid += 1

    # Components (left)
    c_cli = ET.SubElement(gr, "mxCell", id=str(sid), value="ClaudeSec\n(network checks)", style=style_comp, vertex="1", parent="1")
    emit_mx_geometry(c_cli, 70, 80, 240, 60)
    id_cli = sid
    sid += 1

    c_tools = ET.SubElement(gr, "mxCell", id=str(sid), value="Tools\n(dns/http/tls/port)", style=style_comp, vertex="1", parent="1")
    emit_mx_geometry(c_tools, 70, 160, 240, 60)
    id_tools = sid
    sid += 1

    # Targets (right)
    c_dns = ET.SubElement(gr, "mxCell", id=str(sid), value="DNS", style=style_comp, vertex="1", parent="1")
    emit_mx_geometry(c_dns, 470, 70, 160, 50)
    id_dns = sid
    sid += 1

    c_tls = ET.SubElement(gr, "mxCell", id=str(sid), value="TLS endpoints\n(certs, ciphers)", style=style_comp, vertex="1", parent="1")
    emit_mx_geometry(c_tls, 660, 70, 220, 50)
    id_tls = sid
    sid += 1

    c_http = ET.SubElement(gr, "mxCell", id=str(sid), value="HTTP(S) services\n(headers, auth, leaks)", style=style_comp, vertex="1", parent="1")
    emit_mx_geometry(c_http, 910, 70, 200, 50)
    id_http = sid
    sid += 1

    def _maybe_redact(value: str) -> str:
        show = os.environ.get("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", "0") == "1"
        if show:
            return value
        # Deterministic pseudonym (stable across regenerations)
        h = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
        return f"target-{h}"

    net_dir = Path(scan_dir or ".") / ".claudesec-network"
    report_path = net_dir / "network-report.v1.json"
    report = None
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            report = None

    targets = []
    if isinstance(report, dict):
        targets = report.get("targets") or []
        if not isinstance(targets, list):
            targets = []

    # Summary box
    file_count = 0
    if net_dir.is_dir():
        try:
            file_count = len([p for p in net_dir.glob("**/*") if p.is_file()])
        except Exception:
            file_count = 0
    summary = f".claudesec-network/\nfiles: {file_count}\nreport: {'network-report.v1.json' if report else 'missing'}\nTargets: {len(targets)}"
    c_store = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(summary), style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_store, 470, 150, 640, 60)
    id_store = sid
    sid += 1

    # Dynamic target nodes (right side) with service flow per target: DNS → TLS → HTTP.
    max_show = 6
    shown = targets[:max_show]
    y0 = 235
    for i, t in enumerate(shown):
        if not isinstance(t, dict):
            continue
        raw = str(t.get("target") or t.get("host") or f"unknown-{i}")
        host = str(t.get("host") or raw)
        port = t.get("port")
        host_label = _maybe_redact(host)
        label = f"{host_label}:{port}" if isinstance(port, int) else host_label

        dns = t.get("dns") if isinstance(t.get("dns"), dict) else {}
        ips = dns.get("ips") if isinstance(dns, dict) else []
        ips_str = ", ".join(ips[:3]) + ("..." if isinstance(ips, list) and len(ips) > 3 else "")

        tls = t.get("tls") if isinstance(t.get("tls"), dict) else {}
        tls_grade = tls.get("grade") if isinstance(tls, dict) else None
        tls_grade = tls_grade if isinstance(tls_grade, str) else "unknown"

        http = t.get("http") if isinstance(t.get("http"), dict) else {}
        http_status = http.get("status") if isinstance(http, dict) else 0
        issues = http.get("issues") if isinstance(http, dict) else []
        issue_cnt = len(issues) if isinstance(issues, list) else 0
        hsts = http.get("hsts") if isinstance(http, dict) else None
        hsts_max = hsts.get("max_age") if isinstance(hsts, dict) else None
        csp = http.get("csp") if isinstance(http, dict) else {}
        csp_quality = csp.get("quality") if isinstance(csp, dict) else "unknown"
        redirects = http.get("redirects") if isinstance(http, dict) else None

        # DNS node
        v_dns = f"{label}\nDNS: {ips_str or 'n/a'}"
        cell_dns = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(v_dns), style=style_comp, vertex="1", parent="1")
        emit_mx_geometry(cell_dns, 470, y0 + i * 90, 200, 60)
        id_t_dns = sid
        sid += 1

        # TLS node
        v_tls = f"TLS grade: {tls_grade}\nPort: {port if isinstance(port, int) else 'n/a'}"
        cell_tls = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(v_tls), style=style_comp, vertex="1", parent="1")
        emit_mx_geometry(cell_tls, 690, y0 + i * 90, 200, 60)
        id_t_tls = sid
        sid += 1

        # HTTP node
        v_http = f"HTTP: {http_status}\nHeader issues: {issue_cnt}\nHSTS max-age: {hsts_max if isinstance(hsts_max, int) else 'n/a'} | CSP: {csp_quality}"
        cell_http = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(v_http), style=style_comp, vertex="1", parent="1")
        emit_mx_geometry(cell_http, 910, y0 + i * 90, 200, 60)
        id_t_http = sid
        sid += 1

        # Edges: tools -> DNS -> TLS -> HTTP
        sid = _draw_edge(gr, sid, id_tools, id_t_dns)
        sid = _draw_edge(gr, sid, id_t_dns, id_t_tls, style=f"endArrow=classic;html=1;rounded=0;labelBackgroundColor=#ffffff;")
        # Add redirect count on TLS->HTTP edge when available (often indicates http->https)
        edge_style = "endArrow=classic;html=1;rounded=0;labelBackgroundColor=#ffffff;"
        # draw.io edge label is value; keep style.
        e = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(f"redirects: {redirects}" if isinstance(redirects, int) else ""), style=edge_style, edge="1", parent="1")
        e.set("source", str(id_t_tls))
        e.set("target", str(id_t_http))
        g = ET.SubElement(e, "mxGeometry", relative="1")
        g.set("as", "geometry")
        sid += 1

        # Traceability: store -> DNS (dashed)
        sid = _draw_edge(gr, sid, id_store, id_t_dns, style="endArrow=classic;html=1;rounded=0;dashed=1;")

    # Edges
    sid = _draw_edge(gr, sid, id_cli, id_tools)
    for tgt in (id_dns, id_tls, id_http):
        sid = _draw_edge(gr, sid, id_tools, tgt)
    sid = _draw_edge(gr, sid, id_tools, id_store, style="endArrow=classic;html=1;rounded=0;dashed=1;")


def generate_overview_drawio(agg, scan_dir, out_path):
    """Generate a single draw.io with multiple pages:
    - Architecture overview
    - Service flow
    - Network topology
    """
    root = create_multipage_drawio_root()
    gr1 = add_drawio_page(root, "Architecture Overview", "overview-arch")
    _overview_architecture_page(gr1, agg)
    gr2 = add_drawio_page(root, "Service Flow", "overview-flow")
    _overview_service_flow_page(gr2, agg)
    gr3 = add_drawio_page(root, "Network Topology", "overview-net")
    _overview_network_topology_page(gr3, scan_dir)
    write_drawio_file(root, out_path)


def write_drawio_file(root, filepath):
    # Keep output deterministic but fast.
    # minidom pretty-print becomes very slow on larger mxfiles; emit compact XML instead.
    xml = ET.tostring(root, encoding="unicode", default_namespace="")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"  {filepath}")


def generate_architecture_diagram(agg, out_path):
    """Architecture: Scanner → Categories → Outputs (JSON, HTML, Prowler, History)."""
    root, gr = create_drawio_root()
    sid = 2
    style_box = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    style_data = "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    style_out = "rounded=1;whiteSpace=wrap;html=1;fillColor=#e1d5e7;strokeColor=#9673a6;"

    # Scanner CLI
    c_scanner = ET.SubElement(gr, "mxCell", id=str(sid), value="ClaudeSec Scanner\n(CLI)", style=style_box, vertex="1", parent="1")
    emit_mx_geometry(c_scanner, 40, 80, 140, 50)
    sid += 1

    # Categories box (one shape with multiline)
    cat_label = "Scan Categories\n" + "\n".join(CATEGORIES[:8]) + "\n..."
    c_cat = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(cat_label), style=style_box, vertex="1", parent="1")
    emit_mx_geometry(c_cat, 260, 40, 160, 140)
    sid += 1

    # Data stores / outputs
    scan = agg.get("scan", {})
    score = scan.get("score", 0)
    grade = scan.get("grade", "F")
    total = scan.get("total", 0)
    summary = f"Scan Results\nTotal: {total} | Score: {score}% (Grade {grade})"
    c_results = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(summary), style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_results, 520, 50, 180, 50)
    sid += 1

    c_json = ET.SubElement(gr, "mxCell", id=str(sid), value="scan-report.json\n(results)", style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_json, 520, 120, 140, 40)
    sid += 1

    prowler_list = agg.get("prowler_providers", [])
    if prowler_list:
        sub = ", ".join(prowler_list[:5]) + (", ..." if len(prowler_list) > 5 else "")
        prowler_label = f"Prowler OCSF\n({sub})"
    else:
        prowler_label = "Prowler OCSF\n(no data)"
    c_prowler = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(prowler_label), style=style_data, vertex="1", parent="1")
    emit_mx_geometry(c_prowler, 520, 180, 160, 50)
    sid += 1

    c_dash = ET.SubElement(gr, "mxCell", id=str(sid), value="Dashboard\n(HTML)", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(c_dash, 720, 80, 120, 50)
    sid += 1

    hist = agg.get("history_count", 0)
    c_hist = ET.SubElement(gr, "mxCell", id=str(sid), value=f"History\n({hist} entries)", style=style_out, vertex="1", parent="1")
    emit_mx_geometry(c_hist, 720, 150, 120, 40)
    sid += 1

    # Edges: scanner -> categories -> results -> dashboard/history
    for src, tgt in [(2, 3), (3, 4), (4, 7), (4, 8)]:
        e = ET.SubElement(gr, "mxCell", id=str(sid), value="", style="endArrow=classic;html=1;rounded=0;", edge="1", parent="1")
        e.set("source", str(src))
        e.set("target", str(tgt))
        g = ET.SubElement(e, "mxGeometry", relative="1")
        g.set("as", "geometry")
        sid += 1

    write_drawio_file(root, out_path)


def generate_scan_flow_diagram(agg, out_path):
    """Flow: Start → Config → Run categories → Aggregate → Report/Dashboard."""
    root, gr = create_drawio_root()
    sid = 2
    style_step = "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    style_decision = "rhombus;whiteSpace=wrap;html=1;fillColor=#ffe6cc;strokeColor=#d79b00;"

    y = 30
    step_h = 50
    step_w = 200

    steps = [
        ("Start", "claudesec scan"),
        ("Load config", ".claudesec.yml\nkubeconfig, aws_profile, prowler_providers"),
        ("Run categories", "infra → ai → network → cloud → access-control → cicd → code → … → prowler"),
        ("Aggregate", "passed/failed/warnings\nfindings by severity"),
        ("Output", "text / JSON / HTML dashboard\nhistory saved"),
    ]
    ids = []
    for i, (title, detail) in enumerate(steps):
        val = f"{title}\n{detail}" if detail else title
        c = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(val), style=style_step, vertex="1", parent="1")
        emit_mx_geometry(c, 80, y + i * (step_h + 20), step_w, step_h if "\n" in val else 36)
        ids.append(sid)
        sid += 1

    for i in range(len(ids) - 1):
        e = ET.SubElement(gr, "mxCell", id=str(sid), value="", style="endArrow=classic;html=1;rounded=0;", edge="1", parent="1")
        e.set("source", str(ids[i]))
        e.set("target", str(ids[i + 1]))
        g = ET.SubElement(e, "mxGeometry", relative="1")
        g.set("as", "geometry")
        sid += 1

    write_drawio_file(root, out_path)


def generate_security_domains_diagram(agg, out_path):
    """Security domains (architecture view) with OWASP/compliance context."""
    root, gr = create_drawio_root()
    sid = 2
    style_domain = "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;"
    style_ref = "rounded=0;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;fontStyle=2"

    # Two columns: domains (left), frameworks (right)
    for i, dom in enumerate(ARCH_DOMAINS):
        val = f"{dom['icon']} {dom['name']}"
        c = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(val), style=style_domain, vertex="1", parent="1")
        emit_mx_geometry(c, 40, 40 + i * 70, 200, 50)
        sid += 1

    frameworks = [f["name"] for f in COMPLIANCE_FRAMEWORKS]
    for i, fw in enumerate(frameworks):
        c = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(fw), style=style_ref, vertex="1", parent="1")
        emit_mx_geometry(c, 320, 40 + i * 50, 160, 36)
        sid += 1

    # Central "Findings" box from scan
    scan = agg.get("scan", {})
    fail = scan.get("failed", 0)
    fval = f"Scan findings\nFailed: {fail} | Prowler providers: {len(agg.get('prowler_providers', []))}"
    c_find = ET.SubElement(gr, "mxCell", id=str(sid), value=mx_escape(fval), style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;", vertex="1", parent="1")
    emit_mx_geometry(c_find, 520, 120, 180, 60)
    sid += 1

    write_drawio_file(root, out_path)


def main():
    scan_dir = os.environ.get("CLAUDESEC_SCAN_DIR", os.environ.get("SCAN_DIR", "."))
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(scan_dir, "docs", "architecture")
    os.makedirs(out_dir, exist_ok=True)

    agg = aggregate_scan_data(scan_dir)
    base = Path(out_dir)

    print("Generating diagrams (combined scan data)...")
    generate_overview_drawio(agg, scan_dir, str(base / "claudesec-overview.drawio"))
    generate_overview_svg(agg, scan_dir, str(base / "claudesec-overview.svg"))
    generate_architecture_svg(agg, str(base / "claudesec-architecture.svg"))
    generate_architecture_diagram(agg, str(base / "claudesec-architecture.drawio"))
    generate_scan_flow_diagram(agg, str(base / "claudesec-scan-flow.drawio"))
    generate_security_domains_diagram(agg, str(base / "claudesec-security-domains.drawio"))

    print(f"Done. View claudesec-architecture.svg in browser/docs; open .drawio in draw.io to edit or export PNG.")


if __name__ == "__main__":
    main()
