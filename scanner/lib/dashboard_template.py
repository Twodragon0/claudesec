"""
ClaudeSec Dashboard Template I/O helpers.

Extracted from dashboard-gen.py: template application, architecture diagram HTML,
and HTML template loading.
"""

import base64
import os
import sys
from pathlib import Path

# Ensure sibling modules are importable when loaded via importlib
_LIB_DIR = os.path.dirname(os.path.abspath(__file__))
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

from csp_utils import generate_nonce, inject_csp_nonce


def _apply_template_and_write(output_file, template, replacements):
    for k, v in replacements.items():
        template = template.replace(f"{{{{{k}}}}}", v)
    # CSP nonce 주입 (빌드마다 새로운 랜덤 nonce 생성)
    nonce = generate_nonce()
    template = inject_csp_nonce(template, nonce)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(template)


# Inline architecture diagram (fallback when SVG file not found) — dark theme
_INLINE_ARCH_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 260" width="100%" style="max-width:900px;height:auto;display:block" class="arch-diagram-svg">
<defs><marker id="arch-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#94a3b8"/></marker></defs>
<style>.arch-txt{font-family:system-ui,sans-serif;font-size:11px;fill:#e2e8f0}.arch-title{font-weight:bold}</style>
<line x1="180" y1="105" x2="260" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="420" y1="110" x2="520" y2="75" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="75" x2="720" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="100" x2="720" y2="170" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<rect x="40" y="80" width="140" height="50" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="110" y="96" text-anchor="middle" class="arch-txt arch-title">ClaudeSec Scanner</text><text x="110" y="110" text-anchor="middle" class="arch-txt">(CLI)</text>
<rect x="260" y="40" width="160" height="140" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="340" y="56" text-anchor="middle" class="arch-txt arch-title">Scan Categories</text>
<text x="340" y="70" text-anchor="middle" class="arch-txt">infra, ai, network, cloud</text><text x="340" y="84" text-anchor="middle" class="arch-txt">access-control, cicd, code</text><text x="340" y="98" text-anchor="middle" class="arch-txt">... prowler</text>
<rect x="520" y="50" width="180" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="610" y="66" text-anchor="middle" class="arch-txt arch-title">Scan Results</text><text x="610" y="80" text-anchor="middle" class="arch-txt">JSON / score / grade</text>
<rect x="520" y="120" width="140" height="40" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="590" y="136" text-anchor="middle" class="arch-txt arch-title">scan-report.json</text>
<rect x="520" y="180" width="160" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="600" y="196" text-anchor="middle" class="arch-txt arch-title">Prowler OCSF</text>
<rect x="720" y="80" width="120" height="50" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="96" text-anchor="middle" class="arch-txt arch-title">Dashboard</text><text x="780" y="110" text-anchor="middle" class="arch-txt">(HTML)</text>
<rect x="720" y="150" width="120" height="40" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="166" text-anchor="middle" class="arch-txt arch-title">History</text>
</svg>"""


def _get_architecture_diagram_html(output_file, scan_dir: str = ""):
    """Load architecture SVG from docs/architecture or return built-in inline SVG.

    Prefer `scan_dir` when provided, because the HTML output may be generated
    from a different working directory than the scan artifacts.
    """
    candidates = []
    # Prefer the one-screen overview SVG when available.
    preferred_names = [
        "claudesec-overview.svg",
        "claudesec-architecture.svg",
    ]
    if scan_dir:
        try:
            for name in preferred_names:
                candidates.append(
                    os.path.join(
                        os.path.abspath(scan_dir),
                        "docs",
                        "architecture",
                        name,
                    )
                )
        except Exception:
            pass
    if output_file:
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            for name in preferred_names:
                candidates.append(os.path.join(out_dir, "docs", "architecture", name))
    cwd = os.getcwd()
    for name in preferred_names:
        candidates.append(os.path.join(cwd, "docs", "architecture", name))
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(script_dir))
        for name in preferred_names:
            candidates.append(os.path.join(repo_root, "docs", "architecture", name))
    except Exception:
        pass
    for svg_path in candidates:
        if svg_path and os.path.isfile(svg_path):
            try:
                with open(svg_path, "r", encoding="utf-8") as f:
                    svg_content = f.read()
                b64 = base64.b64encode(svg_content.encode("utf-8")).decode("ascii")
                label = (
                    "ClaudeSec Overview Architecture"
                    if svg_path.endswith("claudesec-overview.svg")
                    else "ClaudeSec Architecture"
                )
                return f'<img src="data:image/svg+xml;base64,{b64}" alt="{label}" loading="lazy" style="max-width:100%;height:auto;display:block;border-radius:8px" />'
            except Exception:
                continue
    return f'<div class="arch-diagram-wrap">{_INLINE_ARCH_SVG}</div>'


# ── HTML Template ────────────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).resolve().parent


def _load_html_template() -> str:
    tmpl_path = _TEMPLATE_DIR / "dashboard-template.html"
    return tmpl_path.read_text(encoding="utf-8")
