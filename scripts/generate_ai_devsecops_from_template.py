#!/usr/bin/env python3
from __future__ import annotations

import copy
import os
import shutil
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE_NAME = "버디 방향성 2026.pptx"
TEMPLATE_HINT = "$CLAUDESEC_PPT_TEMPLATE or ~/Downloads/버디 방향성 2026.pptx"


def resolve_template() -> Path:
    override = os.getenv("CLAUDESEC_PPT_TEMPLATE")
    if override:
        return Path(override).expanduser()
    return Path.home() / "Downloads" / DEFAULT_TEMPLATE_NAME


TEMPLATE = resolve_template()
OUTPUT = ROOT / "docs" / "reports" / "ai-devsecops-work-improvement-template.pptx"
OUTLINE = ROOT / "docs" / "reports" / "ai-devsecops-work-improvement-template.md"

NS = {
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
}

for prefix, uri in NS.items():
    ET.register_namespace(prefix if prefix != "ep" else "", uri)


SLIDE_ORDER = [
    "slide18.xml",
    "slide1.xml",
    "slide14.xml",
    "slide15.xml",
    "slide10.xml",
    "slide12.xml",
    "slide6.xml",
    "slide19.xml",
    "slide11.xml",
    "slide21.xml",
    "slide16.xml",
    "slide20.xml",
    "slide27.xml",
]


SLIDE_TEXT = {
    "slide18.xml": {
        1: ["AI를 통한 업무 개선", "Small DevSecOps Team, 60+ SaaS, ISMS 대응을 위한 ClaudeSec 전략"],
    },
    "slide1.xml": {
        1: ["Yong"],
        2: ["DevSecOps"],
        3: ["+"],
        4: ["AI Workflow\nSecurity Operations"],
        5: ["Contact withheld"],
        6: ["LEVVELS"],
        7: ["ClaudeSec"],
        8: ["+"],
        9: ["Internal System"],
        10: ["[ Presenter ]"],
        11: ["[ Role ]"],
        12: ["AI / DevSecOps 방향성"],
    },
    "slide14.xml": {
        1: ["LEVVELS 소개"],
        2: ["빠른 실행과 높은 신뢰가 동시에 필요한 조직에서 AI와 DevSecOps를 함께 설계해야 합니다."],
        3: ["Playground for Culture Lovers"],
        4: ["Speed with Trust"],
    },
    "slide15.xml": {
        1: ["발표 개요", "2026"],
        2: ["배경"],
        3: ["해결"],
        4: ["실행"],
        5: ["소규모 DevSecOps 팀\nISMS 및 CISO 요구\n60개+ SaaS 관리 복잡성"],
        6: ["ClaudeSec 내부 시스템\n표준화된 운영 기준\n비용 최적화와 가시성"],
        7: ["우선순위 정의\nKPI 관리\n다음 단계 실행안"],
        8: ["주니어부터 시니어까지 이해할 수 있도록 문제, 통제, 실행의 순서로 정리"],
    },
    "slide10.xml": {
        1: ["왜 지금 필요한가"],
    },
    "slide12.xml": {
        1: ["+"],
        2: ["AS IS"],
        3: ["Small DevSecOps team"],
        4: ["DevOps 1명 + Security 1명이 운영, 보안, 감사 대응을 동시에 수행"],
        5: ["60+ SaaS admin scope"],
        6: ["60개 이상의 SaaS를 관리자 관점에서 이해하고 설정, 권한, 증적을 관리해야 함"],
        7: ["System-first execution"],
        8: ["인력 확장보다 체계, 자동화, 가시성이 먼저 필요한 단계"],
    },
    "slide6.xml": {
        1: ["+"],
        2: ["Current reality"],
        3: ["DevSecOps team"],
        4: ["DevOps 1 + Security 1"],
        5: ["SaaS admin coverage"],
        6: ["60+ systems"],
        7: ["Compliance requirement"],
        8: ["ISMS · 정보보호 · CISO"],
    },
    "slide19.xml": {
        1: ["핵심 방향성"],
        2: ["ClaudeSec 필요성"],
        3: ["ISMS, 정보보호 요구사항, CISO 역할을 개인 역량이 아니라 시스템과 운영 절차로 설명할 수 있어야 함"],
        4: ["운영, 점검, 문서화, 증적, 보안체크를 한 흐름으로 연결해 작은 팀도 반복 가능한 체계를 만들어야 함"],
        5: ["[Compliance]"],
        6: ["[Operations]"],
    },
    "slide11.xml": {
        1: ["어떻게 해결할 것인가"],
    },
    "slide21.xml": {
        1: ["1:N", "소수 인력과 다수 시스템 구조"],
        2: ["ClaudeSec x DevSecOps"],
        3: ["DevSecOps team"],
        4: ["Governance\nSecurity baseline"],
        5: ["60+ SaaS"],
        6: ["Access\nConfig\nEvidence"],
        7: ["Visibility"],
        8: ["Cost / Risk"],
    },
    "slide16.xml": {
        1: ["ClaudeSec으로 연결할 수 있는 실무 항목"],
        2: ["SaaS 인벤토리"],
        3: ["권한 점검"],
        4: ["설정 기준"],
        5: ["증적 수집"],
        6: ["보안 리뷰"],
        7: ["비용 시야"],
        8: ["대시보드"],
        9: ["로그/신호"],
        10: ["AI 가이드"],
        11: ["감사 대응"],
        12: ["운영 문서"],
        13: ["Internal system", "2026"],
    },
    "slide20.xml": {
        1: ["경영진 관점에서의 기대효과"],
        2: ["CFO / CEO View"],
        3: ["비용 최적화: 반복 점검, 수작업 보고, 중복 SaaS 파악에 쓰이는 시간을 줄이고 운영 효율을 높임"],
        4: ["가시성 고도화: 현재 상태, 리스크, 우선순위를 한 화면에서 설명 가능한 구조를 만들어 CEO 의사결정을 돕음"],
        5: ["[CFO]"],
        6: ["[CEO]"],
        7: ["+"],
    },
    "slide27.xml": {
        1: ["2026 목표"],
        2: ["소수 인력으로도 ISMS, 정보보호, CISO 요구를 설명하고\n60개 이상 SaaS 환경을 더 안전하고 더 보이게 운영하는\nDevSecOps 체계 구축"],
    },
}


def qn(prefix: str, tag: str) -> str:
    return f"{{{NS[prefix]}}}{tag}"


def text_shapes(root: ET.Element) -> list[ET.Element]:
    shapes: list[ET.Element] = []
    for sp in root.findall(".//p:sp", NS):
        tx_body = sp.find("p:txBody", NS)
        if tx_body is not None:
            shapes.append(sp)
    return shapes


def clear_children(elem: ET.Element) -> None:
    for child in list(elem):
        elem.remove(child)


def clone_first(src: ET.Element | None) -> ET.Element | None:
    return copy.deepcopy(src) if src is not None else None


def set_shape_paragraphs(shape: ET.Element, paragraphs: list[str]) -> None:
    tx_body = shape.find("p:txBody", NS)
    if tx_body is None:
        return
    existing_paras = tx_body.findall("a:p", NS)
    template_para = existing_paras[0] if existing_paras else ET.Element(qn("a", "p"))
    template_ppr = clone_first(template_para.find("a:pPr", NS))
    template_end = clone_first(template_para.find("a:endParaRPr", NS))
    template_rpr = None
    first_run = template_para.find("a:r", NS)
    if first_run is not None:
        template_rpr = clone_first(first_run.find("a:rPr", NS))
    clear_children(tx_body)
    body_pr = ET.SubElement(tx_body, qn("a", "bodyPr")) if tx_body.find("a:bodyPr", NS) is None else None
    lst_style = ET.SubElement(tx_body, qn("a", "lstStyle")) if tx_body.find("a:lstStyle", NS) is None else None
    if body_pr is not None or lst_style is not None:
        # bodyPr/lstStyle were missing because children were cleared from a malformed txBody.
        pass
    if tx_body.find("a:bodyPr", NS) is None:
        tx_body.insert(0, ET.Element(qn("a", "bodyPr")))
    if tx_body.find("a:lstStyle", NS) is None:
        tx_body.insert(1, ET.Element(qn("a", "lstStyle")))
    for idx, paragraph in enumerate(paragraphs):
        p = ET.Element(qn("a", "p"))
        if template_ppr is not None:
            p.append(copy.deepcopy(template_ppr))
        run = ET.SubElement(p, qn("a", "r"))
        if template_rpr is not None:
            run.append(copy.deepcopy(template_rpr))
        else:
            ET.SubElement(run, qn("a", "rPr"), {"lang": "ko-KR", "dirty": "0"})
        text = ET.SubElement(run, qn("a", "t"))
        text.text = paragraph
        if template_end is not None:
            p.append(copy.deepcopy(template_end))
        else:
            ET.SubElement(p, qn("a", "endParaRPr"), {"lang": "ko-KR", "dirty": "0"})
        tx_body.append(p)


def update_slide(slide_path: Path, replacements: dict[int, list[str]]) -> None:
    tree = ET.parse(slide_path)
    root = tree.getroot()
    shapes = text_shapes(root)
    for idx, paragraphs in replacements.items():
        if idx < 1 or idx > len(shapes):
            raise IndexError(f"{slide_path.name}: text shape index {idx} out of range (max {len(shapes)})")
        set_shape_paragraphs(shapes[idx - 1], paragraphs)
    tree.write(slide_path, encoding="UTF-8", xml_declaration=True)


def reorder_presentation(presentation_path: Path, rels_path: Path) -> None:
    pres_tree = ET.parse(presentation_path)
    pres_root = pres_tree.getroot()
    rels_tree = ET.parse(rels_path)
    rels_root = rels_tree.getroot()
    rel_by_target = {Path(rel.attrib["Target"]).name: rel.attrib["Id"] for rel in rels_root if rel.attrib["Target"].startswith("slides/")}
    sld_id_lst = pres_root.find("p:sldIdLst", NS)
    if sld_id_lst is None:
        raise RuntimeError("presentation.xml missing slide list")
    existing = {
        elem.attrib[qn("r", "id")]: elem
        for elem in list(sld_id_lst)
    }
    clear_children(sld_id_lst)
    for slide_name in SLIDE_ORDER:
        rel_id = rel_by_target[slide_name]
        sld_id_lst.append(copy.deepcopy(existing[rel_id]))
    pres_tree.write(presentation_path, encoding="UTF-8", xml_declaration=True)


def update_app_xml(app_path: Path) -> None:
    tree = ET.parse(app_path)
    root = tree.getroot()
    slides = root.find("ep:Slides", NS)
    if slides is not None:
        slides.text = str(len(SLIDE_ORDER))
    titles = root.find("ep:TitlesOfParts/vt:vector", NS)
    if titles is not None:
        titles.attrib["size"] = str(len(SLIDE_ORDER))
        clear_children(titles)
        slide_titles = [
            "Cover",
            "Presenter",
            "LEVVELS",
            "Agenda",
            "Why now",
            "As-is",
            "Current reality",
            "Need for ClaudeSec",
            "How",
            "1:N framework",
            "Use cases",
            "Executive value",
            "Closing",
        ]
        for title in slide_titles:
            elem = ET.SubElement(titles, qn("vt", "lpstr"))
            elem.text = title
    heading_pairs = root.find("ep:HeadingPairs/vt:vector", NS)
    if heading_pairs is not None and len(list(heading_pairs)) >= 2:
        second_variant = list(heading_pairs)[1]
        i4 = second_variant.find("vt:i4", NS)
        if i4 is not None:
            i4.text = str(len(SLIDE_ORDER))
    tree.write(app_path, encoding="UTF-8", xml_declaration=True)


def rezip(source_dir: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir).as_posix())


def write_outline() -> None:
    OUTLINE.write_text(
        f"""---
title: 템플릿 기반 AI 업무개선 발표자료 원고
description: '버디 방향성 2026' 템플릿을 재활용한 LEVVELS DevSecOps x ClaudeSec 발표자료
tags: [ppt, template, ai, devsecops, claudesec]
---

# 템플릿 기반 발표자료 구성

사용 템플릿: `{TEMPLATE_HINT}`

재활용한 템플릿 슬라이드:

- `slide18`: 커버
- `slide1`: 발표자 소개
- `slide14`: LEVVELS 소개
- `slide15`: 목차
- `slide10`: 섹션 구분
- `slide12`: 현재 문제
- `slide6`: 조직 현실
- `slide19`: 내부 시스템 필요성
- `slide11`: 섹션 구분
- `slide21`: 1:N 운영 구조
- `slide16`: ClaudeSec 실무 항목
- `slide20`: CFO / CEO 관점 효과
- `slide27`: 마무리

핵심 메시지:

- DevSecOps 팀은 `DevOps 1명 + 보안 1명` 규모
- 60개 이상 SaaS를 관리자 관점에서 이해하고 운영해야 함
- ISMS, 정보보호 요구사항, CISO 조건을 체계로 설명할 내부 시스템이 필요
- ClaudeSec은 보안, 문서화, 가시성, 비용 최적화를 함께 설명할 수 있는 내부 시스템 사례
""",
        encoding="utf-8",
    )


def main() -> None:
    if not TEMPLATE.exists():
        raise FileNotFoundError(f"Template not found: {TEMPLATE}")
    with TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with zipfile.ZipFile(TEMPLATE) as zf:
            zf.extractall(tmpdir)
        for slide_name, replacements in SLIDE_TEXT.items():
            update_slide(tmpdir / "ppt" / "slides" / slide_name, replacements)
        reorder_presentation(tmpdir / "ppt" / "presentation.xml", tmpdir / "ppt" / "_rels" / "presentation.xml.rels")
        update_app_xml(tmpdir / "docProps" / "app.xml")
        rezip(tmpdir, OUTPUT)
    write_outline()
    print(f"Generated {OUTPUT}")


if __name__ == "__main__":
    main()
