#!/usr/bin/env python3
"""
ClaudeSec diagram SVG builders — architecture and overview SVGs.

Renders the same layouts as the draw.io diagrams as standalone SVG for viewing
in a browser or embedding into claudesec-dashboard.html. Pure string builders:
no draw.io/mxGraph XML, no untrusted parsing.
"""
import os
import sys
import json
from pathlib import Path
from collections import defaultdict

# Sibling-module imports: ensure this file's dir (scanner/lib) is importable
# whether imported by diagram-gen.py or loaded standalone (pytest coverage).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from diagram_drawio import mx_escape  # noqa: E402
from diagram_data import CATEGORIES  # noqa: E402


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
