#!/usr/bin/env python3
from __future__ import annotations

import copy
import os
import posixpath
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree as ET

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE_NAME = "버디 방향성 2026.pptx"
TEMPLATE_HINT = "$CLAUDESEC_PPT_TEMPLATE or ~/Downloads/버디 방향성 2026.pptx"


def resolve_template() -> Path:
    override = os.getenv("CLAUDESEC_PPT_TEMPLATE")
    if override:
        return Path(override).expanduser()
    return Path.home() / "Downloads" / DEFAULT_TEMPLATE_NAME


TEMPLATE = resolve_template()
OUTPUT = ROOT / "docs" / "reports" / "claudesec-security-seminar-30min-template.pptx"
OUTLINE = ROOT / "docs" / "reports" / "claudesec-security-seminar-30min-template.md"
LINKEDIN = ROOT / "docs" / "reports" / "linkedin_assets"

NS = {
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "p": "http://schemas.openxmlformats.org/presentationml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}
REL_NS = {"pr": "http://schemas.openxmlformats.org/package/2006/relationships"}

for prefix, uri in NS.items():
    ET.register_namespace(prefix if prefix not in ("ep", "vt") else prefix, uri)


SLIDE_ORDER = [
    "slide18.xml",
    "slide1.xml",
    "slide14.xml",
    "slide15.xml",
    "slide10.xml",
    "slide12.xml",
    "slide6.xml",
    "slide19.xml",
    "slide9.xml",
    "slide11.xml",
    "slide8.xml",
    "slide34.xml",
    "slide21.xml",
    "slide16.xml",
    "slide20.xml",
    "slide27.xml",
]


SLIDE_TEXT = {
    "slide18.xml": {
        1: [
            "ClaudeSec로 보는 AI 기반 DevSecOps 자산관리와 ISMS 대응",
            "30분 보안 세미나 | Small team, 60+ SaaS, visibility, compliance",
        ],
        2: [""],
    },
    "slide1.xml": {
        1: ["Security Seminar"],
        2: ["DevSecOps"],
        3: ["+"],
        4: ["AI-assisted Security Operations"],
        5: ["Sanitized version"],
        6: ["LEVVELS"],
        7: ["ClaudeSec"],
        8: ["+"],
        9: ["AI Workflow"],
        10: ["[ Session ]"],
        11: ["[ Context ]"],
        12: ["Security Seminar 2026"],
    },
    "slide14.xml": {
        1: ["왜 지금 이 이야기가 필요한가"],
        2: ["스타트업과 중소기업 규모에서는 보안팀을 키우기보다, 보안이 작동하는 시스템을 먼저 만들어야 합니다."],
        3: ["Small Team\nHigh Responsibility"],
        4: ["60+ SaaS\nISMS · CISO · Visibility"],
        5: [""],
    },
    "slide15.xml": {
        1: ["세미나 개요", "30 min"],
        2: ["문제"],
        3: ["해결"],
        4: ["실행"],
        5: ["소수 DevSecOps 인력\nSaaS/엔드포인트/AWS\nISMS·CISO 요구"],
        6: ["ClaudeSec 아키텍처\nAI 자동화·대시보드\n컴플라이언스 매핑"],
        7: ["비용 최적화\n가시성 고도화\nAI 활용 보안 운영 개선"],
        8: ["공개 글·공개 이미지·템플릿·저장소 문서를 바탕으로 재구성하고 개인정보/민감정보는 제거"],
    },
    "slide10.xml": {
        1: ["문제 배경"],
    },
    "slide12.xml": {
        1: ["+"],
        2: ["AS IS"],
        3: ["Small DevSecOps team"],
        4: ["DevOps 1명 + Security 1명이 운영, 점검, 문서화, 감사 대응까지 함께 수행"],
        5: ["60+ SaaS admin scope"],
        6: ["60개 이상 SaaS를 관리자 관점에서 이해하고 접근권한, 설정, 증적, 비용을 함께 관리"],
        7: ["Manual work does not scale"],
        8: ["사람의 기억과 스프레드시트만으로는 속도, 일관성, 가시성을 유지하기 어려움"],
    },
    "slide6.xml": {
        1: ["+"],
        2: ["운영 규모"],
        3: ["SaaS / License"],
        4: ["60+ managed tools"],
        5: ["Endpoints / AI"],
        6: ["100+ devices · 5+ AI subscriptions"],
        7: ["Infra / Compliance"],
        8: ["Multi-account AWS · ISMS-P · CISO"],
    },
    "slide19.xml": {
        1: ["왜 내부 시스템이 필요했는가"],
        2: ["ClaudeSec 방향성"],
        3: ["ISMS-P, 정보보호 요구사항, CISO 책임을 개인 역량이 아니라 시스템과 운영 절차로 설명할 수 있어야 했습니다."],
        4: ["비용, 자산, 보안 점검, 증적, 정기점검 이력, 내부 문서를 한 흐름으로 연결해 작은 팀도 반복 가능한 체계를 만들어야 했습니다."],
        5: ["[Compliance]"],
        6: ["[Operations]"],
    },
    "slide9.xml": {
        1: ["+"],
        2: ["Architecture"],
        3: ["ClaudeSec overview"],
        4: ["데이터 수집 + AI 요약/분류 + 교차검증 + 대시보드 생성"],
        5: ["Sheets, Datadog, AWS, Notion, Scanner 결과를 한 흐름으로 연결하고 사람이 최종 승인"],
        6: [""],
        8: [""],
    },
    "slide11.xml": {
        1: ["ClaudeSec으로 어떻게 해결하는가"],
    },
    "slide8.xml": {
        1: ["+"],
        2: ["핵심 자동화 영역"],
        3: ["ClaudeSec"],
        4: ["SaaS / 라이선스 비용 가시성"],
        5: ["엔드포인트 / 점검 이력 통합"],
        6: ["클라우드 보안 + 컴플라이언스 + AI 요약"],
        7: [""],
    },
    "slide34.xml": {
        1: ["실제 화면 예시"],
        2: ["ISMS PDCA 대시보드와 보안 파인딩 뷰"],
    },
    "slide21.xml": {
        1: ["1:N", "소수 인력과 다수 시스템 구조"],
        2: ["ClaudeSec x DevSecOps"],
        3: ["DevSecOps team"],
        4: ["Governance\nPolicy\nControls"],
        5: ["60+ SaaS"],
        6: ["Access\nConfig\nEvidence"],
        7: ["Visibility"],
        8: ["Cost / Risk"],
        9: [""],
    },
    "slide16.xml": {
        1: ["무엇을 먼저 자동화할 것인가"],
        2: ["SaaS 인벤토리 정규화"],
        3: ["권한 점검 준비"],
        4: ["설정 기준 요약"],
        5: ["증적 수집 초안"],
        6: ["AI 보안 코드리뷰"],
        7: ["비용 시야"],
        8: ["대시보드"],
        9: ["로그/신호 트리아지"],
        10: ["LLM 보안 가이드"],
        11: ["감사 대응 문안"],
        12: ["내부 문서 요약"],
        13: ["Priority actions", "2026"],
    },
    "slide20.xml": {
        1: ["보안팀만의 도구가 아닌 경영 시스템"],
        2: ["Security / Management"],
        3: ["보안·컴플라이언스: ISMS-P 102 기준, 8개 규정/지침 186개 조항, 40+ 자동 점검, 정기점검 이력 연계, AI 기반 증적 정리"],
        4: ["운영 가치: CFO에게는 비용 최적화, CEO에게는 운영 가시성, CISO에게는 책임 설명 가능성, 실무자에게는 반복 업무 절감"],
        5: ["[Security]"],
        6: ["[Management]"],
        7: ["+"],
    },
    "slide27.xml": {
        1: ["핵심 메시지"],
        2: ["소수 인력 환경에서 중요한 것은 도구 하나가 아니라\n보안, 자산, 비용, 운영, 컴플라이언스, 내부 지식을 한 흐름으로 설명하는 체계입니다.\nClaudeSec은 AI를 활용해 그 체계를 내부 시스템으로 구현하려는 시도입니다."],
    },
}


IMAGE_TARGETS = {
    ("slide9.xml", "rId7"): ("claudesec-arch.jpg", LINKEDIN / "claudesec-1.jpg", (1600, 804), "ClaudeSec Architecture"),
    ("slide34.xml", "rId6"): ("claudesec-overview.jpg", LINKEDIN / "claudesec-2.jpg", (1200, 888), "ISMS PDCA Dashboard"),
    ("slide34.xml", "rId7"): ("claudesec-findings.jpg", LINKEDIN / "claudesec-3.jpg", (1600, 850), "Security Findings"),
}


def qn(prefix: str, tag: str) -> str:
    return f"{{{NS[prefix]}}}{tag}"


def load_font(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/AppleSDGothicNeo.ttc",
        "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size=size)
    return ImageFont.load_default()


FONT = load_font(42)
FONT_SMALL = load_font(28)


def prepare_image(src: Path, out_path: Path, canvas_size: tuple[int, int], label: str) -> None:
    img = Image.open(src).convert("RGB")
    canvas = Image.new("RGB", canvas_size, (14, 16, 31))
    margin = 34
    max_w = canvas_size[0] - margin * 2
    max_h = canvas_size[1] - margin * 2 - 70
    ratio = min(max_w / img.width, max_h / img.height)
    resized = img.resize((max(1, int(img.width * ratio)), max(1, int(img.height * ratio))), Image.LANCZOS)
    x = (canvas_size[0] - resized.width) // 2
    y = 60 + (max_h - resized.height) // 2
    canvas.paste(resized, (x, y))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((20, 18, 20 + min(520, int(len(label) * 22 + 60)), 68), radius=18, fill=(39, 35, 78))
    draw.text((40, 28), label, font=FONT_SMALL, fill=(242, 243, 247))
    draw.rounded_rectangle((x - 2, y - 2, x + resized.width + 2, y + resized.height + 2), radius=10, outline=(80, 90, 130), width=2)
    canvas.save(out_path, format="JPEG", quality=92)


def text_shapes(root: ET.Element) -> list[ET.Element]:
    return [sp for sp in root.findall(".//p:sp", NS) if sp.find("p:txBody", NS) is not None]


def clear_children(elem: ET.Element) -> None:
    for child in list(elem):
        elem.remove(child)


def set_shape_paragraphs(shape: ET.Element, paragraphs: list[str]) -> None:
    tx_body = shape.find("p:txBody", NS)
    if tx_body is None:
        return
    existing_paras = tx_body.findall("a:p", NS)
    template_para = existing_paras[0] if existing_paras else ET.Element(qn("a", "p"))
    existing_body_pr = tx_body.find("a:bodyPr", NS)
    existing_lst_style = tx_body.find("a:lstStyle", NS)
    body_pr = copy.deepcopy(existing_body_pr) if existing_body_pr is not None else ET.Element(qn("a", "bodyPr"))
    lst_style = copy.deepcopy(existing_lst_style) if existing_lst_style is not None else ET.Element(qn("a", "lstStyle"))
    template_ppr = copy.deepcopy(template_para.find("a:pPr", NS))
    template_end = copy.deepcopy(template_para.find("a:endParaRPr", NS))
    template_rpr = None
    first_run = template_para.find("a:r", NS)
    if first_run is not None:
        template_rpr = copy.deepcopy(first_run.find("a:rPr", NS))
    clear_children(tx_body)
    tx_body.append(body_pr)
    tx_body.append(lst_style)
    for text_value in paragraphs:
        p = ET.Element(qn("a", "p"))
        if template_ppr is not None:
            p.append(copy.deepcopy(template_ppr))
        r = ET.SubElement(p, qn("a", "r"))
        if template_rpr is not None:
            r.append(copy.deepcopy(template_rpr))
        else:
            ET.SubElement(r, qn("a", "rPr"), {"lang": "ko-KR"})
        t = ET.SubElement(r, qn("a", "t"))
        t.text = text_value
        if template_end is not None:
            p.append(copy.deepcopy(template_end))
        else:
            ET.SubElement(p, qn("a", "endParaRPr"), {"lang": "ko-KR"})
        tx_body.append(p)


def update_slide_text(slide_path: Path, replacements: dict[int, list[str]]) -> None:
    tree = ET.parse(slide_path)
    root = tree.getroot()
    shapes = text_shapes(root)
    for idx, paragraphs in replacements.items():
        if idx < 1 or idx > len(shapes):
            raise IndexError(f"{slide_path.name}: text shape index {idx} out of range ({len(shapes)})")
        set_shape_paragraphs(shapes[idx - 1], paragraphs)
    tree.write(slide_path, encoding="UTF-8", xml_declaration=True)


def update_slide_rel_target(rel_path: Path, rel_id: str, target: str) -> None:
    tree = ET.parse(rel_path)
    root = tree.getroot()
    found = False
    for rel in root:
        if rel.attrib.get("Id") == rel_id:
            rel.attrib["Target"] = target
            found = True
            break
    if not found:
        raise KeyError(f"{rel_path.name}: relationship {rel_id} not found")
    tree.write(rel_path, encoding="UTF-8", xml_declaration=True)


def reorder_presentation(presentation_path: Path, rels_path: Path) -> None:
    pres_tree = ET.parse(presentation_path)
    pres_root = pres_tree.getroot()
    rels_tree = ET.parse(rels_path)
    rels_root = rels_tree.getroot()
    rel_by_target = {Path(rel.attrib["Target"]).name: rel.attrib["Id"] for rel in rels_root if rel.attrib["Target"].startswith("slides/")}
    sld_id_lst = pres_root.find("p:sldIdLst", NS)
    existing = {elem.attrib[qn("r", "id")]: elem for elem in list(sld_id_lst)}
    clear_children(sld_id_lst)
    for slide_name in SLIDE_ORDER:
        rel_id = rel_by_target[slide_name]
        sld_id_lst.append(copy.deepcopy(existing[rel_id]))
    pres_tree.write(presentation_path, encoding="UTF-8", xml_declaration=True)
    keep_rel_ids = {rel_by_target[slide_name] for slide_name in SLIDE_ORDER}
    for rel in list(rels_root):
        target = rel.attrib.get("Target", "")
        if target.startswith("slides/") and rel.attrib.get("Id") not in keep_rel_ids:
            rels_root.remove(rel)
    rels_tree.write(rels_path, encoding="UTF-8", xml_declaration=True)


def update_app_xml(app_path: Path) -> None:
    if not app_path.exists():
        return
    tree = ET.parse(app_path)
    root = tree.getroot()
    slides = root.find("ep:Slides", NS)
    if slides is not None:
        slides.text = str(len(SLIDE_ORDER))
    titles_vec = root.find("ep:TitlesOfParts/vt:vector", NS)
    if titles_vec is not None:
        titles = [
            "Cover",
            "Speaker",
            "Why now",
            "Agenda",
            "Problem section",
            "As-is pain",
            "Operating scale",
            "Need for system",
            "Architecture",
            "Solution section",
            "Automation pillars",
            "Screenshots",
            "1:N model",
            "Priorities",
            "Security & management value",
            "Closing",
        ]
        titles_vec.attrib["size"] = str(len(titles))
        clear_children(titles_vec)
        for title in titles:
            elem = ET.SubElement(titles_vec, qn("vt", "lpstr"))
            elem.text = title
    heading_pairs = root.find("ep:HeadingPairs/vt:vector", NS)
    if heading_pairs is not None and len(list(heading_pairs)) >= 2:
        variant = list(heading_pairs)[1]
        i4 = variant.find("vt:i4", NS)
        if i4 is not None:
            i4.text = str(len(SLIDE_ORDER))
    tree.write(app_path, encoding="UTF-8", xml_declaration=True)


def rezip(source_dir: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source_dir).as_posix())


def rels_path_for(part_name: str) -> str:
    if not part_name:
        return "_rels/.rels"
    parent, name = posixpath.split(part_name)
    if parent:
        return f"{parent}/_rels/{name}.rels"
    return f"_rels/{name}.rels"


def resolve_target(part_name: str, target: str) -> str | None:
    if "://" in target or target.startswith("mailto:"):
        return None
    if target.startswith("/"):
        return posixpath.normpath(target.lstrip("/"))
    base_dir = posixpath.dirname(part_name)
    return posixpath.normpath(posixpath.join(base_dir, target))


def collect_reachable_parts(package_dir: Path) -> set[str]:
    reachable = {"[Content_Types].xml"}
    queue = [""]
    seen = set()
    while queue:
        part_name = queue.pop()
        if part_name in seen:
            continue
        seen.add(part_name)
        rels_name = rels_path_for(part_name)
        rels_path = package_dir / rels_name
        if not rels_path.exists():
            continue
        reachable.add(rels_name)
        tree = ET.parse(rels_path)
        root = tree.getroot()
        for rel in root.findall("pr:Relationship", REL_NS):
            if rel.attrib.get("TargetMode") == "External":
                continue
            target_name = resolve_target(part_name, rel.attrib["Target"])
            if target_name is None:
                continue
            target_path = package_dir / target_name
            if not target_path.exists():
                continue
            reachable.add(target_name)
            queue.append(target_name)
    return reachable


def prune_content_types(package_dir: Path, reachable: set[str]) -> None:
    content_types_path = package_dir / "[Content_Types].xml"
    tree = ET.parse(content_types_path)
    root = tree.getroot()
    for override in list(root.findall("{*}Override")):
        part_name = override.attrib["PartName"].lstrip("/")
        if part_name not in reachable:
            root.remove(override)
    tree.write(content_types_path, encoding="UTF-8", xml_declaration=True)


def prune_unreachable_parts(package_dir: Path) -> None:
    reachable = collect_reachable_parts(package_dir)
    prune_content_types(package_dir, reachable)
    for path in sorted(package_dir.rglob("*"), reverse=True):
        if not path.is_file():
            continue
        relative = path.relative_to(package_dir).as_posix()
        if relative not in reachable:
            path.unlink()
    for path in sorted(package_dir.rglob("*"), reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def write_outline() -> None:
    OUTLINE.write_text(
        f"""---
title: ClaudeSec 30분 보안 세미나 발표자료 원고
description: 버디 방향성 2026 템플릿과 LinkedIn 공개 글/이미지를 재활용한 ClaudeSec 세미나 자료
tags: [ppt, seminar, claudesec, devsecops, isms]
---

# ClaudeSec 30분 보안 세미나

## 사용 자료

- 템플릿: `{TEMPLATE_HINT}`
- LinkedIn 공개 글: `https://kr.linkedin.com/posts/twodragon_devsecops-isms-%EB%B3%B4%EC%95%88-activity-7439616126894104577-6ADD`
- LinkedIn 공개 이미지 3장
- 로컬 문서:
  - `docs/compliance/isms-p.md`
  - `docs/guides/compliance-mapping.md`
  - `README.md`

## 세미나 핵심 메시지

- 소수 DevSecOps 인력 구조에서는 보안 운영을 사람 중심이 아니라 시스템 중심으로 설명해야 한다.
- 60개 이상 SaaS, 100대 이상 엔드포인트, 멀티 계정 AWS, ISMS-P 대응이 동시에 요구되면 자동화와 가시성이 필수다.
- ClaudeSec은 비용, 자산, 보안 점검, 증적, 컴플라이언스, 내부 문서 지식을 하나의 흐름으로 묶는 내부 시스템 사례다.

## AI 활용 관점 보강

- AI는 보안 코드를 대신 결정하는 도구가 아니라, 보안 코드리뷰 초안, 로그/알림 트리아지, 증적 정리, 정책/문서 요약을 가속하는 도구로 배치했다.
- 내부 문서와 점검 이력을 AI가 요약하더라도, 민감정보와 개인정보는 제거하거나 마스킹하고 사람 승인 후만 사용한다.
- 발표자료에도 직접 식별 가능한 발표자 정보와 세부 개인 식별 정보는 넣지 않았다.

## 한계

- 사용자가 준 Notion 링크들은 공개 HTML 셸까지만 확인되었고 본문 내용은 직접 추출하지 못했다.
- 따라서 Notion 관련 내용은 공개 글에 나온 `Notion 정기점검 이력 연동`, 저장소 내 관련 문서, 그리고 내부 문서 연계라는 안전한 수준의 메시지로만 반영했다.
""",
        encoding="utf-8",
    )


def main() -> None:
    if not TEMPLATE.exists():
        raise FileNotFoundError(f"Template not found: {TEMPLATE}")
    for _, src, _, _ in IMAGE_TARGETS.values():
        if not src.exists():
            raise FileNotFoundError(f"Missing LinkedIn image: {src}")
    with TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with zipfile.ZipFile(TEMPLATE) as zf:
            zf.extractall(tmpdir)

        for (slide_name, rel_id), (media_name, src, size, label) in IMAGE_TARGETS.items():
            media_out = tmpdir / "ppt" / "media" / media_name
            prepare_image(src, media_out, size, label)
            update_slide_rel_target(tmpdir / "ppt" / "slides" / "_rels" / f"{slide_name}.rels", rel_id, f"../media/{media_name}")

        for slide_name, replacements in SLIDE_TEXT.items():
            update_slide_text(tmpdir / "ppt" / "slides" / slide_name, replacements)

        reorder_presentation(tmpdir / "ppt" / "presentation.xml", tmpdir / "ppt" / "_rels" / "presentation.xml.rels")
        update_app_xml(tmpdir / "docProps" / "app.xml")
        prune_unreachable_parts(tmpdir)
        rezip(tmpdir, OUTPUT)

    write_outline()
    print(f"Generated {OUTPUT}")


if __name__ == "__main__":
    main()
