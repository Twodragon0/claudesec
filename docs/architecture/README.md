---
title: Architecture Diagrams
description: Draw.io diagrams for ClaudeSec scanner architecture, scan flow, and security domains
tags: [architecture, drawio, diagrams]
---

# Architecture Diagrams

This directory contains **draw.io** (diagrams.net) source files generated from ClaudeSec scan data. The diagrams combine scanner results, Prowler OCSF outputs, and scan history into architecture, flow, and security-domain views.

## Generated Files

These files are auto-generated and excluded from git (may contain scan-specific data).

| File | Description |
|------|-------------|
| `claudesec-overview.drawio` | Multi-page overview: Architecture + Service flow + Network topology |
| `claudesec-architecture.drawio` | System architecture (draw.io source) |
| `claudesec-architecture.svg` | Architecture as image |
| `claudesec-scan-flow.drawio` | Scan flow diagram |
| `claudesec-security-domains.drawio` | Security domains and framework references |

## Regenerating Diagrams

From the repository root:

```bash
./scanner/claudesec diagrams
# or with custom output directory:
./scanner/claudesec diagrams /path/to/output
```

Or run the generator directly (uses `SCAN_DIR` or current directory for scan data):

```bash
python3 scanner/lib/diagram-gen.py docs/architecture
```

Data used when present:

- `scan-report.json` (or env `CLAUDESEC_SCAN_JSON`) — scan summary and score
- `.claudesec-prowler/*.ocsf.json` — Prowler provider results
- `.claudesec-history/scan-*.json` — scan history count

## Exporting to Images (PNG/SVG)

1. Open any `.drawio` file in [app.diagrams.net](https://app.diagrams.net/) or Draw.io desktop.
2. **File → Export as → PNG** or **SVG**.
3. Or use [draw.io CLI](https://github.com/jgraph/drawio-desktop/releases) if installed:  
   `drawio -x -o out.png claudesec-architecture.drawio`

Diagrams are editable; adjust layout and styles as needed for your documentation.
