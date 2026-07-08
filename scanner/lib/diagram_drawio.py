#!/usr/bin/env python3
"""
diagram_drawio.py — low-level draw.io (mxGraph) XML primitives.

Extracted from diagram-gen.py: these are the leaf builders (no dependency on the
scanner's aggregate data, categories, or the higher-level page/diagram
generators) that assemble mxfile / mxGraphModel / mxCell / mxGeometry elements.
Single-sourcing them here keeps diagram-gen.py focused on composition.

Stdlib-only (xml.etree.ElementTree). Builders only — no untrusted XML is parsed.
"""
import xml.etree.ElementTree as ET  # noqa: S405 (builders only; no untrusted parse)


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
