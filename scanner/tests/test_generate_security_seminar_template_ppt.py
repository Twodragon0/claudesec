from __future__ import annotations

import importlib.util
from pathlib import Path


def load_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "generate_security_seminar_template_ppt.py"
    spec = importlib.util.spec_from_file_location("generate_security_seminar_template_ppt", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_prune_unreachable_parts_removes_unused_package_parts(tmp_path: Path) -> None:
    module = load_module()

    write_text(
        tmp_path / "[Content_Types].xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
  <Override PartName="/ppt/slides/slide2.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>
</Types>
""",
    )
    write_text(
        tmp_path / "_rels" / ".rels",
        """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>
""",
    )
    write_text(tmp_path / "ppt" / "presentation.xml", "<presentation/>")
    write_text(
        tmp_path / "ppt" / "_rels" / "presentation.xml.rels",
        """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide1.xml"/>
</Relationships>
""",
    )
    write_text(tmp_path / "ppt" / "slides" / "slide1.xml", "<slide/>")
    write_text(
        tmp_path / "ppt" / "slides" / "_rels" / "slide1.xml.rels",
        """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image1.png"/>
</Relationships>
""",
    )
    write_text(tmp_path / "ppt" / "media" / "image1.png", "keep")
    write_text(tmp_path / "ppt" / "slides" / "slide2.xml", "<slide/>")
    write_text(tmp_path / "ppt" / "media" / "image2.png", "drop")

    module.prune_unreachable_parts(tmp_path)

    assert (tmp_path / "ppt" / "presentation.xml").exists()
    assert (tmp_path / "ppt" / "slides" / "slide1.xml").exists()
    assert (tmp_path / "ppt" / "media" / "image1.png").exists()
    assert not (tmp_path / "ppt" / "slides" / "slide2.xml").exists()
    assert not (tmp_path / "ppt" / "media" / "image2.png").exists()

    content_types = (tmp_path / "[Content_Types].xml").read_text(encoding="utf-8")
    assert "/ppt/slides/slide1.xml" in content_types
    assert "/ppt/slides/slide2.xml" not in content_types
