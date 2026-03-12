#!/usr/bin/env python3
"""
ClaudeSec Diagram Generator — draw.io architecture, scan flow, and security domains.
Combines scan results, Prowler OCSF, and history to produce .drawio diagrams.
"""
import json
import os
import sys
import glob
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pathlib import Path
from collections import defaultdict
import hashlib

VERSION = "0.1.0"

# Scanner categories (from claudesec)
CATEGORIES = [
    "infra", "ai", "network", "cloud", "access-control",
    "cicd", "code", "macos", "saas", "windows", "prowler",
]

# Security architecture domains (aligned with dashboard-gen)
ARCH_DOMAINS = [
    {"name": "Network & TLS", "icon": "🌐"},
    {"name": "Identity & Access", "icon": "🔑"},
    {"name": "Data protection", "icon": "🔒"},
    {"name": "CI/CD pipeline", "icon": "⚡"},
    {"name": "Monitoring & logging", "icon": "📊"},
    {"name": "Supply chain", "icon": "📦"},
]


def load_scan_results(path):
    if not path or not os.path.isfile(path):
        return {"passed": 0, "failed": 0, "warnings": 0, "skipped": 0, "total": 0, "score": 0, "grade": "F", "duration": 0, "findings": []}
    with open(path) as f:
        return json.load(f)


def _parse_ocsf_json(content):
    items = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(content):
        while idx < len(content) and content[idx] in " \t\n\r":
            idx += 1
        if idx >= len(content):
            break
        try:
            obj, end = decoder.raw_decode(content, idx)
            if isinstance(obj, list):
                items.extend(o for o in obj if isinstance(o, dict))
            elif isinstance(obj, dict):
                items.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx += 1
    return items


def load_prowler_files(prowler_dir):
    providers = {}
    if not os.path.isdir(prowler_dir):
        return providers
    for fpath in sorted(glob.glob(os.path.join(prowler_dir, "prowler-*.ocsf.json"))):
        name = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
        try:
            with open(fpath) as f:
                content = f.read().strip()
            items = _parse_ocsf_json(content)
            providers[name] = items
        except Exception:
            providers[name] = []
    return providers


def load_scan_history(history_dir):
    entries = []
    if not os.path.isdir(history_dir):
        return entries
    for fpath in sorted(glob.glob(os.path.join(history_dir, "scan-*.json"))):
        try:
            with open(fpath) as f:
                entries.append(json.load(f))
        except Exception:
            pass
    return entries


def aggregate_scan_data(scan_dir):
    """Load and aggregate all scan-related data for diagram labels."""
    base = Path(scan_dir or ".")
    scan_json = base / "scan-report.json"
    prowler_dir = base / ".claudesec-prowler"
    history_dir = base / ".claudesec-history"

    scan_data = load_scan_results(str(scan_json))
    # Fallback: allow overriding scan JSON file.
    if (not scan_data.get("total")) and os.environ.get("CLAUDESEC_SCAN_JSON"):
        p = os.environ.get("CLAUDESEC_SCAN_JSON")
        if os.path.isfile(p):
            scan_data = load_scan_results(p)

    # Fallback: build minimal scan_data from env vars (dashboard generation path).
    # This keeps diagram generation functional even when scan-report.json is missing.
    if not scan_data.get("total"):
        try:
            passed = int(os.environ.get("CLAUDESEC_PASSED", "0") or "0")
            failed = int(os.environ.get("CLAUDESEC_FAILED", "0") or "0")
            warnings = int(os.environ.get("CLAUDESEC_WARNINGS", "0") or "0")
            skipped = int(os.environ.get("CLAUDESEC_SKIPPED", "0") or "0")
            total = int(os.environ.get("CLAUDESEC_TOTAL", "0") or "0")
            score = int(os.environ.get("CLAUDESEC_SCORE", "0") or "0")
            grade = os.environ.get("CLAUDESEC_GRADE", "F") or "F"
            duration = int(os.environ.get("CLAUDESEC_DURATION", "0") or "0")
            findings = []
            env_findings = os.environ.get("CLAUDESEC_FINDINGS_JSON", "") or ""
            if env_findings.strip().startswith("["):
                findings = json.loads(env_findings)
            scan_data = {
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "skipped": skipped,
                "total": total,
                "score": score,
                "grade": grade,
                "duration": duration,
                "findings": findings if isinstance(findings, list) else [],
            }
        except Exception:
            pass

    providers = load_prowler_files(str(prowler_dir))
    prov_summary = {}
    for prov, items in providers.items():
        fails = [i for i in items if i.get("status_code") == "FAIL"]
        prov_summary[prov] = {"fail": len(fails), "total": len(items)}

    history = load_scan_history(str(history_dir))
    return {
        "scan": scan_data,
        "prowler_providers": list(providers.keys()),
        "prowler_summary": prov_summary,
        "history_count": len(history),
    }


def mx_escape(s):
    if s is None:
        return ""
    s = str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def drawio_cell(parent, cell_id, value=None, style=None, vertex=True, parent_id="1", x=0, y=0, width=120, height=40, source=None, target=None):
    """Append one mxCell to parent (root). Returns cell id."""
    cell = ET.SubElement(parent, "mxCell")
    cell.set("id", str(cell_id))
    if value is not None:
        cell.set("value", mx_escape(value))
    if style:
        cell.set("style", style)
    cell.set("vertex" if vertex else "edge", "1")
    cell.set("parent", str(parent_id))
    if vertex:
        geom = ET.SubElement(cell, "mxGeometry")
        geom.set("x", str(x))
        geom.set("y", str(y))
        geom.set("width", str(width))
        geom.set("height", str(height))
        geom.set("as", "geometry")
    else:
        geom = ET.SubElement(cell, "mxGeometry")
        geom.set("relative", "1")
        geom.set("as", "geometry")
        if source is not None:
            geom.set("sourcePoint", source)
        if target is not None:
            geom.set("targetPoint", target)
    return cell_id


def emit_mx_geometry(parent_cell, x, y, width, height):
    geom = ET.SubElement(parent_cell, "mxGeometry")
    geom.set("x", str(x))
    geom.set("y", str(y))
    geom.set("width", str(width))
    geom.set("height", str(height))
    geom.set("as", "geometry")


def create_drawio_root():
    root = ET.Element("mxfile", host="app.diagrams.net", modified="", agent="", version="24.0", etag="", type="device")
    diagram = ET.SubElement(root, "diagram", id="diagram-1", name="Page-1")
    model = ET.SubElement(diagram, "mxGraphModel", dx="1422", dy="794", grid="1", gridSize="10", guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1", pageScale="1", pageWidth="1169", pageHeight="827", math="0", shadow="0")
    graph_root = ET.SubElement(model, "root")
    ET.SubElement(graph_root, "mxCell", id="0")
    ET.SubElement(graph_root, "mxCell", id="1", parent="0")
    return root, graph_root


def create_multipage_drawio_root():
    """Create an mxfile that can hold multiple <diagram> pages."""
    return ET.Element(
        "mxfile",
        host="app.diagrams.net",
        modified="",
        agent="",
        version="24.0",
        etag="",
        type="device",
    )


def add_drawio_page(mxfile_root, page_name, page_id):
    """Add a new page to an mxfile and return its graph_root."""
    diagram = ET.SubElement(mxfile_root, "diagram", id=str(page_id), name=str(page_name))
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        dx="1422",
        dy="794",
        grid="1",
        gridSize="10",
        guides="1",
        tooltips="1",
        connect="1",
        arrows="1",
        fold="1",
        page="1",
        pageScale="1",
        pageWidth="1169",
        pageHeight="827",
        math="0",
        shadow="0",
    )
    graph_root = ET.SubElement(model, "root")
    ET.SubElement(graph_root, "mxCell", id="0")
    ET.SubElement(graph_root, "mxCell", id="1", parent="0")
    return graph_root


def _draw_edge(gr, sid, src, tgt, style="endArrow=classic;html=1;rounded=0;"):
    e = ET.SubElement(gr, "mxCell", id=str(sid), value="", style=style, edge="1", parent="1")
    e.set("source", str(src))
    e.set("target", str(tgt))
    g = ET.SubElement(e, "mxGeometry", relative="1")
    g.set("as", "geometry")
    return sid + 1


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


def _svg_escape(s):
    if s is None:
        return ""
    s = str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    return s


def generate_architecture_svg(agg, out_path):
    """Same layout as architecture drawio, as SVG for viewing in browser/docs."""
    scan = agg.get("scan", {})
    score = scan.get("score", 0)
    grade = scan.get("grade", "F")
    total = scan.get("total", 0)
    failed = scan.get("failed", 0)
    warnings = scan.get("warnings", 0)
    findings = scan.get("findings", []) or []

    # Summaries from scan findings JSON (best-effort).
    sev_counts = defaultdict(int)
    cat_counts = defaultdict(int)
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = (f.get("severity") or "").lower().strip()
        cat = (f.get("category") or "").lower().strip()
        if sev:
            sev_counts[sev] += 1
        if cat:
            cat_counts[cat] += 1

    prowler_list = agg.get("prowler_providers", [])
    prowler_str = ", ".join(prowler_list[:5]) + ("..." if len(prowler_list) > 5 else "") if prowler_list else "no data"
    hist = agg.get("history_count", 0)
    prov_summary = agg.get("prowler_summary", {}) or {}
    total_prowler_fail = sum(int(v.get("fail", 0) or 0) for v in prov_summary.values()) if isinstance(prov_summary, dict) else 0

    # Top categories by count (for quick "what's noisy" signal).
    top_cats = sorted(cat_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
    top_cats_str = ", ".join(f"{k}:{v}" for k, v in top_cats) if top_cats else "none"

    # Coordinates (match drawio layout)
    boxes = [
        (40, 80, 140, 50, "#dae8fc", "#6c8ebf", ["ClaudeSec Scanner", "(CLI)"]),
        (260, 40, 160, 140, "#dae8fc", "#6c8ebf", ["Scan Categories"] + CATEGORIES[:7] + ["..."]),
        (520, 50, 220, 64, "#fff2cc", "#d6b656", [
            "Scan Results",
            f"Total:{total} Failed:{failed} Warn:{warnings}",
            f"Score:{score}% Grade:{grade}  Crit:{sev_counts.get('critical', 0)} High:{sev_counts.get('high', 0)}",
        ]),
        (520, 120, 140, 40, "#fff2cc", "#d6b656", ["scan-report.json", "(results)"]),
        (520, 190, 200, 56, "#fff2cc", "#d6b656", ["Prowler OCSF", f"Fail:{total_prowler_fail} ({prowler_str})"]),
        (720, 80, 120, 50, "#e1d5e7", "#9673a6", ["Dashboard", "(HTML)"]),
        (720, 150, 160, 40, "#e1d5e7", "#9673a6", [f"History", f"({hist} entries)"]),
        (40, 10, 840, 26, "#111827", "#111827", [f"Top categories: {top_cats_str}"]),
    ]
    w, h = 900, 270
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">',
        '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#374151"/></marker></defs>',
        '<style>text { font-family: system-ui, sans-serif; font-size: 11px; fill: #333; } .title { font-weight: bold; } .banner { font-size: 11px; fill: #f9fafb; }</style>',
    ]
    # Arrows (under boxes): Scanner→Categories, Categories→Results, Results→Dashboard, Results→History
    arrow_list = [(180, 105, 260, 105), (420, 110, 520, 75), (700, 75, 720, 105), (700, 100, 720, 170)]
    for sx, sy, ex, ey in arrow_list:
        lines.append(f'<line x1="{sx}" y1="{sy}" x2="{ex}" y2="{ey}" stroke="#374151" stroke-width="1.5" marker-end="url(#arrow)"/>')
    # Boxes
    for x, y, bw, bh, fill, stroke, labels in boxes:
        lines.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        for i, label in enumerate(labels):
            ly = y + 16 + i * 14
            if ly < y + bh - 4:
                cls = "banner" if (fill == "#111827") else ("title" if i == 0 else "")
                lines.append(f'<text x="{x + bw/2}" y="{ly}" text-anchor="middle" class="{cls}">{_svg_escape(label)}</text>')
    lines.append("</svg>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {out_path}")


def generate_overview_svg(agg, scan_dir, out_path):
    """One-screen overview SVG: Architecture + Service flow + Network flow.

    This is optimized for embedding into claudesec-dashboard.html.
    """
    scan = agg.get("scan", {}) or {}
    total = scan.get("total", 0)
    failed = scan.get("failed", 0)
    warnings = scan.get("warnings", 0)
    score = scan.get("score", 0)
    grade = scan.get("grade", "F")

    prov_summary = agg.get("prowler_summary", {}) or {}
    total_prowler_fail = (
        sum(int(v.get("fail", 0) or 0) for v in prov_summary.values())
        if isinstance(prov_summary, dict)
        else 0
    )

    # Network report (best-effort)
    net_dir = Path(scan_dir or ".") / ".claudesec-network"
    net_report = net_dir / "network-report.v1.json"
    net_targets = 0
    net_header_issues = 0
    if net_report.is_file():
        try:
            d = json.loads(net_report.read_text(encoding="utf-8"))
            targets = d.get("targets") or []
            if isinstance(targets, list):
                net_targets = len(targets)
                for t in targets[:20]:
                    http = t.get("http") if isinstance(t, dict) else None
                    issues = http.get("issues") if isinstance(http, dict) else []
                    if isinstance(issues, list):
                        net_header_issues += len(issues)
        except Exception:
            pass

    w, h = 1100, 720
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">',
        "<defs>",
        '<marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#334155"/></marker>',
        "</defs>",
        "<style>",
        "  .bg{fill:#0b1220}",
        "  .card{fill:#0f172a;stroke:#334155;stroke-width:1.5}",
        "  .boxA{fill:#0b2a4a;stroke:#38bdf8;stroke-width:1.5}",
        "  .boxB{fill:#3a2503;stroke:#eab308;stroke-width:1.5}",
        "  .boxC{fill:#2b1b57;stroke:#a78bfa;stroke-width:1.5}",
        "  .txt{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:12px;fill:#e5e7eb}",
        "  .muted{fill:#94a3b8}",
        "  .title{font-size:16px;font-weight:700}",
        "  .h2{font-size:13px;font-weight:700;fill:#e2e8f0}",
        "  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:11px}",
        "</style>",
        f'<rect class="bg" x="0" y="0" width="{w}" height="{h}"/>',
        # Header
        '<text class="txt title" x="30" y="38">ClaudeSec Overview Architecture</text>',
        f'<text class="txt muted" x="30" y="60">Scan: total {total}, failed {failed}, warnings {warnings} · Score {score}% (Grade {mx_escape(grade)}) · Prowler fail {total_prowler_fail} · Network targets {net_targets} (header issues {net_header_issues})</text>',
        # Panels
        '<rect class="card" x="20" y="90" width="520" height="290" rx="12"/>',
        '<rect class="card" x="560" y="90" width="520" height="290" rx="12"/>',
        '<rect class="card" x="20" y="400" width="1060" height="290" rx="12"/>',
        f'<text class="txt h2" x="40" y="120">{_svg_escape("Architecture (artifacts & data)")}</text>',
        f'<text class="txt h2" x="580" y="120">{_svg_escape("Service flow (who calls what)")}</text>',
        f'<text class="txt h2" x="40" y="430">{_svg_escape("Network flow (DNS → TLS → HTTP)")}</text>',
    ]

    # Panel 1: Architecture
    def box(x, y, bw, bh, cls, title, subtitle=""):
        lines.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="10" class="{cls}"/>')
        lines.append(f'<text class="txt" x="{x + bw/2}" y="{y + 22}" text-anchor="middle">{_svg_escape(title)}</text>')
        if subtitle:
            lines.append(f'<text class="txt muted mono" x="{x + bw/2}" y="{y + 42}" text-anchor="middle">{_svg_escape(subtitle)}</text>')

    box(50, 150, 150, 60, "boxA", "Scanner", "claudesec (CLI)")
    box(240, 150, 150, 60, "boxA", "Categories", "infra/ai/network/…")
    box(430, 150, 90, 60, "boxB", "JSON", "scan-report.json")
    box(50, 240, 180, 60, "boxB", "Prowler", f"fail:{total_prowler_fail}")
    box(260, 240, 150, 60, "boxC", "Dashboard", "claudesec-dashboard.html")
    box(430, 240, 90, 60, "boxC", "History", f"{agg.get('history_count', 0)} entries")
    # arrows
    lines.append('<line x1="200" y1="180" x2="240" y2="180" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append('<line x1="390" y1="180" x2="430" y2="180" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append('<line x1="295" y1="210" x2="295" y2="240" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')

    # Panel 2: Service flow
    box(590, 150, 160, 60, "boxA", "Engineer / CI", "runs scan/dashboard")
    box(780, 150, 160, 60, "boxA", "claudesec", "scan → aggregate")
    box(970, 150, 90, 60, "boxB", "Outputs", "HTML/SVG")
    lines.append('<line x1="750" y1="180" x2="780" y2="180" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append('<line x1="940" y1="180" x2="970" y2="180" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append('<text class="txt muted mono" x="590" y="245">Artifacts: docs/architecture/*.drawio + *.svg</text>')
    lines.append('<text class="txt muted mono" x="590" y="265">Logs/findings: scan-report.json (+ .claudesec-history)</text>')

    # Panel 3: Network flow (summary)
    box(60, 470, 260, 70, "boxA", "DNS", "resolve host → IPs")
    box(370, 470, 260, 70, "boxA", "TLS", "grade A/B/D/unknown")
    box(680, 470, 380, 70, "boxA", "HTTP(S)", "headers, redirects, HSTS, CSP")
    lines.append('<line x1="320" y1="505" x2="370" y2="505" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append('<line x1="630" y1="505" x2="680" y2="505" stroke="#334155" stroke-width="2" marker-end="url(#arrow)"/>')
    lines.append(f'<text class="txt muted mono" x="60" y="565">Source: .claudesec-network/network-report.v1.json (targets: {net_targets})</text>')
    lines.append(f'<text class="txt muted mono" x="60" y="585">HTTP header issues (sum, top20 targets): {net_header_issues}</text>')

    lines.append("</svg>")
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  {out_path}")


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

    frameworks = ["OWASP Top 10:2025", "OWASP LLM Top 10", "NIST CSF 2.0", "ISO 27001", "KISA ISMS-P", "PCI-DSS"]
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
