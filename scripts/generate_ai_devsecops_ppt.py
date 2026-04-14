#!/usr/bin/env python3
from __future__ import annotations

import io
import math
import subprocess
import textwrap
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
REPORTS = ROOT / "docs" / "reports"
OUTPUT_PPTX = REPORTS / "ai-devsecops-work-improvement.pptx"
LINKEDIN_ASSETS = REPORTS / "linkedin_assets"
BLOG_ASSETS = REPORTS / "blog_assets"
NOTION_ASSETS = REPORTS / "notion_assets"
GENERATED_ASSETS = REPORTS / "generated_assets"

WIDTH = 1920
HEIGHT = 1080
SLIDE_W_EMU = 12192000
SLIDE_H_EMU = 6858000

BG = "#F6F1E8"
BG_ALT = "#FFFDFC"
TEXT = "#161514"
MUTED = "#5B5650"
ACCENT = "#E26D2F"
ACCENT_DARK = "#B24B17"
CARD = "#FFF9F3"
LINE = "#E8D9CA"
GREEN = "#117864"
NAVY = "#19324D"
GOLD = "#C99724"


def rgb(hex_color: str) -> tuple[int, int, int]:
    hex_color = hex_color.lstrip("#")
    return tuple(int(hex_color[i : i + 2], 16) for i in (0, 2, 4))


FONT_CANDIDATES = [
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
]


def font_path() -> str:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    raise FileNotFoundError("No usable Korean font found.")


FONT_FILE = font_path()


def load_font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_FILE, size=size)


TITLE_FONT = load_font(56)
SUBTITLE_FONT = load_font(26)
BODY_FONT = load_font(30)
BODY_SMALL_FONT = load_font(26)
BODY_TINY_FONT = load_font(22)
SECTION_FONT = load_font(20)
BIG_NUMBER_FONT = load_font(74)


def line_height(font: ImageFont.FreeTypeFont, extra: int = 8) -> int:
    box = font.getbbox("가나다ABC123")
    return box[3] - box[1] + extra


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont, max_width: int) -> list[str]:
    if not text:
        return []
    if "\n" in text:
        lines: list[str] = []
        for chunk in text.splitlines():
            if not chunk:
                lines.append("")
                continue
            lines.extend(wrap_text(draw, chunk, font, max_width))
        return lines
    words = text.split(" ")
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        test = f"{current} {word}"
        if draw.textlength(test, font=font) <= max_width:
            current = test
            continue
        lines.append(current)
        current = word
    lines.append(current)
    return lines


def draw_text_block(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    width: int,
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str = TEXT,
    spacing: int = 8,
) -> int:
    cursor = y
    for line in wrap_text(draw, text, font, width):
        draw.text((x, cursor), line, font=font, fill=fill)
        cursor += line_height(font, extra=spacing)
    return cursor


def bullet_block(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    width: int,
    bullets: list[str],
    font: ImageFont.FreeTypeFont = BODY_FONT,
    fill: str = TEXT,
) -> int:
    cursor = y
    bullet_r = 6
    for bullet in bullets:
        bx = x + 8
        by = cursor + 13
        draw.ellipse((bx - bullet_r, by - bullet_r, bx + bullet_r, by + bullet_r), fill=ACCENT)
        cursor = draw_text_block(draw, x + 28, cursor, width - 28, bullet, font=font, fill=fill, spacing=10) + 12
    return cursor


def rounded_rect(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str, outline: str | None = None, width: int = 1, radius: int = 26) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def add_logo(base: Image.Image, path: Path, box: tuple[int, int, int, int]) -> None:
    logo = Image.open(path).convert("RGBA")
    max_w = box[2] - box[0]
    max_h = box[3] - box[1]
    ratio = min(max_w / logo.width, max_h / logo.height)
    new_size = (max(1, int(logo.width * ratio)), max(1, int(logo.height * ratio)))
    logo = logo.resize(new_size, Image.LANCZOS)
    x = box[0] + (max_w - logo.width) // 2
    y = box[1] + (max_h - logo.height) // 2
    base.alpha_composite(logo, (x, y))


def ensure_claudesec_hero() -> Path:
    GENERATED_ASSETS.mkdir(parents=True, exist_ok=True)
    out = GENERATED_ASSETS / "claudesec-hero.png"
    if out.exists():
        return out
    image = Image.new("RGBA", (1600, 900), (250, 247, 243, 255))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((40, 40, 1560, 860), radius=36, fill=(255, 252, 248, 255), outline=rgb(LINE), width=3)
    draw.ellipse((980, -120, 1640, 520), fill=(226, 109, 47, 24))
    draw.ellipse((1120, 420, 1700, 980), fill=(17, 120, 100, 18))
    add_logo(image, ASSETS / "claudesec-logo-512.png", (90, 90, 620, 300))
    draw.text((110, 320), "AI-driven Security Operations", font=load_font(46), fill=rgb(TEXT))
    draw.text((112, 382), "Scan, Explain, Visualize, Improve", font=BODY_SMALL_FONT, fill=rgb(MUTED))
    blocks = [
        ((120, 500, 470, 710), "Security Scan", "Code / Infra / CI/CD / AI", ACCENT),
        ((510, 500, 860, 710), "Asset Visibility", "SaaS / License / Endpoint", GREEN),
        ((900, 500, 1250, 710), "Compliance", "ISMS-P / Audit / Evidence", NAVY),
        ((1290, 500, 1480, 710), "Signals", "Logs / Alerts", GOLD),
    ]
    for box, title, desc, color in blocks:
        draw.rounded_rectangle(box, radius=26, fill=(255, 249, 243, 255), outline=rgb(LINE), width=2)
        draw.rectangle((box[0], box[1], box[0] + 12, box[3]), fill=rgb(color))
        draw.text((box[0] + 28, box[1] + 34), title, font=BODY_SMALL_FONT, fill=rgb(TEXT))
        draw.text((box[0] + 28, box[1] + 92), desc, font=BODY_TINY_FONT, fill=rgb(MUTED))
    draw.line((470, 605, 510, 605), fill=rgb(LINE), width=6)
    draw.line((860, 605, 900, 605), fill=rgb(LINE), width=6)
    draw.line((1250, 605, 1290, 605), fill=rgb(LINE), width=6)
    draw.rounded_rectangle((1060, 170, 1460, 380), radius=28, fill=(24, 23, 22, 255))
    draw.text((1100, 230), "Small Team\nBig Surface Area", font=load_font(42), fill=(255, 247, 239, 255), spacing=10)
    draw.text((1120, 700), "ClaudeSec as an operating system for a small DevSecOps team", font=BODY_TINY_FONT, fill=rgb(MUTED))
    image.save(out)
    return out


def ensure_qr(name: str, url: str) -> Path:
    out = GENERATED_ASSETS / f"{name}-qr.png"
    if not out.exists():
        raise FileNotFoundError(f"QR asset missing: {out}")
    return out


def add_framed_image(base: Image.Image, draw: ImageDraw.ImageDraw, path: Path, box: tuple[int, int, int, int], label: str | None = None) -> None:
    rounded_rect(draw, box, fill="#FFFDFC", outline="#D9DDE6", width=2, radius=26)
    src = Image.open(path)
    if src.mode in ("RGBA", "LA") or (src.mode == "P" and "transparency" in src.info):
        rgba = src.convert("RGBA")
        white = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        white.alpha_composite(rgba)
        img = white
    else:
        img = src.convert("RGBA")
    inner_x1, inner_y1, inner_x2, inner_y2 = box[0] + 22, box[1] + 22, box[2] - 22, box[3] - 22
    if label:
        rounded_rect(draw, (box[0] + 20, box[1] + 18, min(box[0] + 360, box[2] - 20), box[1] + 68), fill="#F4E4D7", radius=16)
        draw.text((box[0] + 40, box[1] + 31), label, font=BODY_TINY_FONT, fill=ACCENT_DARK)
        inner_y1 += 42
    max_w = inner_x2 - inner_x1
    max_h = inner_y2 - inner_y1
    ratio = min(max_w / img.width, max_h / img.height)
    new_size = (max(1, int(img.width * ratio)), max(1, int(img.height * ratio)))
    img = img.resize(new_size, Image.LANCZOS)
    x = inner_x1 + (max_w - img.width) // 2
    y = inner_y1 + (max_h - img.height) // 2
    base.alpha_composite(img, (x, y))
    draw.rounded_rectangle((x - 4, y - 4, x + img.width + 4, y + img.height + 4), radius=14, outline="#E4E8F0", width=2)


def new_slide(bg: str = BG) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGBA", (WIDTH, HEIGHT), rgb(bg) + (255,))
    draw = ImageDraw.Draw(image)
    return image, draw


def decorate(draw: ImageDraw.ImageDraw, title: str, subtitle: str, slide_no: int) -> None:
    draw.rectangle((88, 70, 102, 1010), fill=ACCENT)
    draw.text((138, 82), title, font=TITLE_FONT, fill=TEXT)
    draw_text_block(draw, 140, 150, 1250, subtitle, SUBTITLE_FONT, fill=MUTED, spacing=6)
    rounded_rect(draw, (1550, 72, 1820, 130), fill="#FCE6D9", radius=20)
    draw.text((1586, 88), f"Slide {slide_no:02d}", font=SECTION_FONT, fill=ACCENT_DARK)
    draw.line((140, 212, 1780, 212), fill=LINE, width=3)
    draw.text((140, 1020), "OWASP Seoul | ClaudeSec | AI를 활용한 보안 업무 개선", font=BODY_TINY_FONT, fill=MUTED)


def card_title(draw: ImageDraw.ImageDraw, x: int, y: int, title: str, color: str = NAVY) -> None:
    draw.text((x, y), title, font=BODY_SMALL_FONT, fill=color)


def card(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], title: str, bullets: list[str], accent_color: str) -> None:
    rounded_rect(draw, box, fill=CARD, outline=LINE, width=2, radius=30)
    draw.rectangle((box[0], box[1], box[0] + 16, box[3]), fill=accent_color)
    card_title(draw, box[0] + 34, box[1] + 22, title)
    bullet_block(draw, box[0] + 36, box[1] + 70, box[2] - box[0] - 64, bullets, font=BODY_SMALL_FONT)


def stat_card(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], label: str, value: str, detail: str, color: str) -> None:
    rounded_rect(draw, box, fill=CARD, outline=LINE, width=2, radius=26)
    draw.text((box[0] + 28, box[1] + 22), label, font=BODY_TINY_FONT, fill=MUTED)
    draw.text((box[0] + 28, box[1] + 54), value, font=load_font(42), fill=color)
    draw_text_block(draw, box[0] + 28, box[1] + 112, box[2] - box[0] - 56, detail, BODY_TINY_FONT, fill=TEXT, spacing=6)


def image_title_card(base: Image.Image, draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], image_path: Path, title: str, subtitle: str, color: str = ACCENT) -> None:
    rounded_rect(draw, box, fill=CARD, outline=LINE, width=2, radius=24)
    img_box = (box[0] + 18, box[1] + 18, box[2] - 18, box[1] + int((box[3] - box[1]) * 0.62))
    add_framed_image(base, draw, image_path, img_box, None)
    draw.rectangle((box[0], box[1], box[0] + 12, box[3]), fill=color)
    draw.text((box[0] + 24, img_box[3] + 28), title, font=BODY_SMALL_FONT, fill=TEXT)
    draw_text_block(draw, box[0] + 24, img_box[3] + 68, box[2] - box[0] - 48, subtitle, BODY_TINY_FONT, fill=MUTED, spacing=5)


def render_case_slide(slide_no: int, title: str, subtitle: str, image_path: Path, bullets: list[str], ai_usage: list[str], link: str, color: str) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, title, subtitle, slide_no)
    add_framed_image(image, draw, image_path, (120, 250, 980, 770), "Case")
    card(draw, (1030, 250, 1780, 530), "사례 핵심", bullets, color)
    card(draw, (1030, 560, 1780, 840), "AI 활용 포인트", ai_usage, NAVY)
    rounded_rect(draw, (120, 800, 980, 960), fill="#FFF1E6", radius=22)
    draw.text((154, 838), "참고 링크", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    qr = ensure_qr(Path(link).name or "link", link)
    add_framed_image(image, draw, qr, (150, 836, 350, 952), None)
    draw_text_block(draw, 382, 856, 520, "QR 스캔으로 원문 보기", BODY_SMALL_FONT, fill=TEXT, spacing=6)
    draw_text_block(draw, 382, 904, 520, link.replace("https://", ""), BODY_TINY_FONT, fill=MUTED, spacing=4)
    rounded_rect(draw, (1030, 870, 1780, 940), fill=CARD, outline=LINE, width=2, radius=20)
    draw.text((1064, 892), "메시지: 사례를 설명하는 데서 끝내지 않고, 다음에는 어떤 반복 작업을 AI가 줄일 수 있는지까지 연결해야 실무 발표가 됩니다.", font=BODY_TINY_FONT, fill=MUTED)
    return image


def section_slide(title: str, subtitle: str, slide_no: int, accent: str = ACCENT) -> Image.Image:
    image, draw = new_slide("#171614")
    draw.ellipse((1050, -140, 2100, 760), fill=rgb(accent) + (44,))
    draw.ellipse((1200, 420, 2200, 1450), fill=(17, 120, 100, 34))
    draw.rectangle((120, 160, 136, 860), fill=accent)
    draw.text((180, 210), title, font=load_font(72), fill="#FFF7EF")
    draw_text_block(draw, 184, 380, 960, subtitle, SUBTITLE_FONT, fill="#E8DDD2", spacing=8)
    rounded_rect(draw, (184, 600, 720, 710), fill="#24211F", outline="#3A3531", width=2, radius=22)
    draw.text((220, 636), "OWASP Seoul Session Flow", font=BODY_SMALL_FONT, fill="#F5E7DA")
    draw.text((1600, 910), f"{slide_no:02d}", font=BIG_NUMBER_FONT, fill="#413B36")
    draw.text((184, 1008), "OWASP Seoul | ClaudeSec | AI를 활용한 보안 업무 개선", font=BODY_TINY_FONT, fill="#B9AAA0")
    return image


@dataclass
class SlideSpec:
    title: str
    subtitle: str
    render: callable


def render_intro(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    for i in range(10):
        alpha = 18 - i
        draw.ellipse((1140 - i * 24, -180 - i * 18, 2120 + i * 20, 820 + i * 14), fill=(226, 109, 47, max(alpha, 2)))
    rounded_rect(draw, (110, 120, 1810, 960), fill="#FFF9F2", outline=LINE, width=2, radius=34)
    draw.text((170, 180), "소규모 DevSecOps 팀에서\nAI를 활용한 보안 개선", font=load_font(62), fill=TEXT, spacing=8)
    draw_text_block(
        draw,
        172,
        300,
        860,
        "OWASP Seoul 세미나\n실전 사례와 ClaudeSec으로 보는 DevSecOps 운영 개선",
        SUBTITLE_FONT,
        fill=MUTED,
        spacing=8,
    )
    rounded_rect(draw, (170, 500, 860, 780), fill="#FFF1E6", radius=30)
    draw.text((214, 548), "핵심 키워드", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    bullet_block(
        draw,
        214,
        606,
        600,
        [
            "실전 사례 중심",
            "작은 DevSecOps 팀 현실",
            "AI 보안 운영 개선",
            "ClaudeSec",
        ],
        font=BODY_SMALL_FONT,
        fill=TEXT,
    )
    hero = ensure_claudesec_hero()
    add_framed_image(image, draw, hero, (1060, 220, 1770, 860), None)
    draw_text_block(
        draw,
        170,
        840,
        820,
        "반복적인 보안 업무를 어떻게 더 적게, 더 빠르게, 더 설명 가능하게 만들 수 있는지에 집중합니다.",
        BODY_SMALL_FONT,
        fill=TEXT,
        spacing=8,
    )
    draw.text((170, 900), "2026.04", font=BODY_SMALL_FONT, fill=MUTED)
    draw.text((1640, 900), f"{slide_no:02d}", font=BIG_NUMBER_FONT, fill="#EBD7C8")
    return image


def render_speaker(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    for i in range(10):
        alpha = 18 - i
        draw.ellipse((1140 - i * 24, -180 - i * 18, 2120 + i * 20, 820 + i * 14), fill=(226, 109, 47, max(alpha, 2)))
    rounded_rect(draw, (110, 120, 1810, 960), fill="#FFF9F2", outline=LINE, width=2, radius=34)
    draw.text((170, 180), "발표자 소개", font=load_font(64), fill=TEXT)
    draw_text_block(
        draw,
        172,
        300,
        850,
        "실전 사례를 직접 다루고, 운영 구조를 함께 정리하는 DevSecOps 팀원 관점의 발표입니다.",
        SUBTITLE_FONT,
        fill=MUTED,
        spacing=8,
    )
    rounded_rect(draw, (170, 410, 760, 552), fill="#FFF1E6", radius=28)
    draw.text((200, 442), "발표자", font=SECTION_FONT, fill=ACCENT_DARK)
    draw.text((198, 476), "Yong", font=load_font(42), fill=TEXT)
    draw.text((198, 526), "DevSecOps Team Member | AI-Assisted Security Ops", font=BODY_SMALL_FONT, fill=MUTED)
    rounded_rect(draw, (170, 590, 760, 824), fill=CARD, outline=LINE, width=2, radius=28)
    draw.text((198, 620), "소개", font=BODY_SMALL_FONT, fill=NAVY)
    bullet_block(
        draw,
        198,
        670,
        520,
        [
            "DevSecOps 실무 관점에서 본 보안 운영 개선",
            "세미나 버전은 개인정보와 민감정보를 제거해 재구성",
            "목표: 반복적인 보안 업무를 AI와 시스템으로 줄이는 방법 설명",
        ],
        font=BODY_SMALL_FONT,
    )
    add_logo(image, ASSETS / "claudesec-logo-512.png", (1080, 220, 1730, 500))
    draw_text_block(
        draw,
        1020,
        640,
        640,
        "역할: 실전 사례를 운영 관점에서 풀어내고, AI와 ClaudeSec이 어디에 실질적으로 도움 되는지 정리합니다.",
        BODY_SMALL_FONT,
        fill=TEXT,
        spacing=8,
    )
    draw.text((170, 900), "2026.04", font=BODY_SMALL_FONT, fill=MUTED)
    draw.text((1640, 900), f"{slide_no:02d}", font=BIG_NUMBER_FONT, fill="#EBD7C8")
    return image


def render_levvels(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "LEVVELS 소개", "작은 DevSecOps 팀이 많은 운영 대상을 관리해야 하는 환경이 왜 중요한지 먼저 공유합니다.", slide_no)
    rounded_rect(draw, (140, 260, 980, 900), fill=CARD, outline=LINE, width=2, radius=30)
    add_logo(image, ASSETS / "levvels-logo.png", (190, 300, 920, 410))
    bullet_block(
        draw,
        190,
        470,
        720,
        [
            "빠른 실행과 높은 신뢰를 동시에 요구하는 제품/운영 환경",
            "보안은 개발, 운영, SaaS, 사용자 환경, 컴플라이언스를 함께 다뤄야 함",
            "작은 팀이 많은 대상을 관리하는 구조에서 표준화와 자동화 필요성이 높음",
            "따라서 보안은 특정 솔루션보다 운영 방식의 문제로 다뤄야 함",
        ],
        font=BODY_SMALL_FONT,
    )
    rounded_rect(draw, (1030, 260, 1780, 900), fill="#1A1918", radius=34)
    draw.text((1088, 320), "이번 발표의 초점", font=BODY_SMALL_FONT, fill="#F7EEE5")
    bullet_block(
        draw,
        1088,
        386,
        620,
        [
            "실전 사고와 운영 문제를 통해 무엇을 자동화해야 하는지 설명",
            "AI가 실제로 도움 되는 보안 업무를 구체적으로 분리",
            "ClaudeSec을 DevSecOps 운영 체계의 한 예시로 소개",
        ],
        font=BODY_SMALL_FONT,
        fill="#FFF9F3",
    )
    rounded_rect(draw, (1088, 708, 1718, 848), fill="#2A2927", radius=26)
    draw.text((1128, 744), "시사점: 작은 팀일수록 보안 운영은 도구보다 체계, 체계보다 증거가 중요합니다.", font=BODY_TINY_FONT, fill="#F3E4D7")
    return image


def render_overview(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "발표 방향", "이번 발표는 프레임워크 일반론보다 실전 사례와 ClaudeSec 중심으로 구성합니다.", slide_no)
    card(
        draw,
        (150, 280, 850, 760),
        "중심 질문",
        [
            "실전 사건과 운영 문제에서 반복적으로 드러나는 병목은 무엇인가",
            "그 병목 중 무엇을 AI와 내부 시스템으로 줄일 수 있는가",
            "ClaudeSec은 그 문제를 어디까지 흡수할 수 있는가",
        ],
        ACCENT,
    )
    card(
        draw,
        (920, 280, 1770, 760),
        "오늘 다룰 축",
        [
            "실전 사례 5개",
            "작은 DevSecOps 팀의 운영 현실",
            "AI를 활용한 보안 업무 개선",
            "ClaudeSec 소개와 적용 포인트",
        ],
        NAVY,
    )
    rounded_rect(draw, (150, 820, 1770, 950), fill="#FFF1E6", radius=24)
    draw.text((184, 850), "핵심", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    draw_text_block(draw, 270, 846, 1440, "핵심은 설명 비용과 반복 작업을 줄이는 것입니다. 사례를 보고, 그 위에 AI와 ClaudeSec을 얹는 순서로 설명합니다.", BODY_SMALL_FONT, fill=TEXT, spacing=8)
    return image


def render_agenda(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "오늘의 목차", "30분 안에 문제, 대응, AI 활용, 운영 체계를 한 번에 이해할 수 있도록 구성했습니다.", slide_no)
    agenda_items = [
        "1. 실전 사례 5개",
        "2. 작은 DevSecOps 팀의 운영 현실",
        "3. 실전 사례에서 운영 개선으로 이어지는 흐름",
        "4. AI를 활용한 보안 업무 개선",
        "5. ClaudeSec 소개와 사례 매핑",
        "6. 도입 우선순위와 로드맵",
    ]
    y = 290
    for idx, item in enumerate(agenda_items, start=1):
        box = (180, y, 1730, y + 100)
        fill = "#FFF1E6" if idx in (1, 3, 5, 6) else CARD
        rounded_rect(draw, box, fill=fill, outline=LINE, width=2, radius=26)
        draw.ellipse((214, y + 24, 270, y + 80), fill=ACCENT)
        draw.text((232, y + 31), str(idx), font=BODY_SMALL_FONT, fill="white")
        draw.text((300, y + 32), item, font=BODY_FONT, fill=TEXT)
        y += 104
    return image


def render_framework_overview(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "실전 사례 5개", "대표 이미지 중심으로 먼저 보고, 하단에서 공통 패턴을 한 번에 읽을 수 있게 구성했습니다.", slide_no)
    cards = [
        ("npm 공급망 공격", "대규모 패키지 생태계 침해와 대응", BLOG_ASSETS / "692.png", ACCENT),
        ("AI와 보안의 공존", "AWSKRUG, OWASP, Datadog 인사이트", BLOG_ASSETS / "704.png", GREEN),
        ("Slack AIOps 챗봇", "Bedrock 기반 장애 분석·로그 요약", BLOG_ASSETS / "673.png", NAVY),
        ("DB 접근 게이트웨이", "NLB + Security Group, Zero Trust", BLOG_ASSETS / "696.png", GOLD),
        ("Karpenter 장애 분석", "운영 안정성과 가드레일의 중요성", BLOG_ASSETS / "695.png", ACCENT_DARK),
    ]
    positions = [
        (120, 250, 700, 610),
        (730, 250, 1310, 610),
        (1340, 250, 1820, 610),
        (220, 635, 900, 905),
        (1020, 635, 1700, 905),
    ]
    for (title, desc, img, color), box in zip(cards, positions):
        image_title_card(image, draw, box, img, title, desc, color)
    rounded_rect(draw, (120, 920, 1800, 980), fill="#1A1918", radius=22)
    draw.text((156, 942), "공통점", font=BODY_SMALL_FONT, fill="#FFF6EE")
    draw.text((300, 942), "반복 업무가 많다  |  설명 비용이 크다  |  표준화가 부족하다  |  AI가 보조할 여지가 있다", font=BODY_TINY_FONT, fill="#FFF6EE")
    return image


def render_case_692(slide_no: int) -> Image.Image:
    return render_case_slide(
        slide_no,
        "사례 1. npm / Axios 공급망 공격과 조직 단위 대응",
        "패키지 생태계 침해와 Axios 악성 버전 이슈는 사건 대응, 전수 점검, 운영 부채 정리를 한 번에 요구하는 사례였습니다.",
        BLOG_ASSETS / "692.png",
        [
            "영향 버전, 실제 설치 버전, IOC를 함께 확인",
            "조직 단위 전수 점검과 빠른 안전 판정이 중요",
        ],
        [
            "점검 순서와 대응 문안 초안 정리",
            "직접 감염과 운영 부채를 분리한 설명 자료 작성",
        ],
        "https://twodragon.tistory.com/692",
        ACCENT,
    )


def render_case_704(slide_no: int) -> Image.Image:
    return render_case_slide(
        slide_no,
        "사례 2. AI와 보안의 공존",
        "컨퍼런스 인사이트를 통해 AI와 보안은 대립보다 공존 방식 설계가 중요하다는 점을 확인했습니다.",
        BLOG_ASSETS / "704.png",
        [
            "AI 도입보다 안전한 운영 방식 설계가 더 중요",
            "guardrail이 없으면 생산성 도구가 리스크가 될 수 있음",
        ],
        [
            "팀 인사이트 문서 초안으로 요약",
            "액션 아이템 빠르게 정리",
        ],
        "https://twodragon.tistory.com/704",
        GREEN,
    )


def render_case_673(slide_no: int) -> Image.Image:
    return render_case_slide(
        slide_no,
        "사례 3. Slack 기반 AIOps 챗봇",
        "Bedrock과 Slack을 활용한 AIOps 챗봇은 로그 요약과 아키텍처 질의에서 실제 운영 효율을 보여줍니다.",
        BLOG_ASSETS / "673.png",
        [
            "로그 요약과 장애 분석을 채팅 인터페이스로 수렴 가능",
            "초기에는 권한과 운영 범위 설정이 가장 큰 난제",
        ],
        [
            "로그와 원인 후보를 자연어로 요약",
            "첫 판단 속도를 높임",
        ],
        "https://twodragon.tistory.com/673",
        NAVY,
    )


def render_case_696(slide_no: int) -> Image.Image:
    return render_case_slide(
        slide_no,
        "사례 4. Zero Trust DB 접근 게이트웨이",
        "데이터베이스 접근은 보안 철학보다 네트워크·권한·감사 추적의 표준화 문제로 귀결됩니다.",
        BLOG_ASSETS / "696.png",
        [
            "중앙 통제와 감사 가능성을 높이는 현실적 방법",
            "접근 통제는 철학보다 운영 표준화 문제",
        ],
        [
            "구조를 문서화하고 설명 자료로 요약",
            "구성 변경 체크리스트 작성",
        ],
        "https://twodragon.tistory.com/696",
        GOLD,
    )


def render_case_695(slide_no: int) -> Image.Image:
    return render_case_slide(
        slide_no,
        "사례 5. Karpenter 장애와 프로덕션 진단",
        "운영 가드레일 부재와 프로덕션 보안 진단 결과는 결국 같은 질문, 즉 무엇부터 막고 무엇부터 표준화할 것인가로 이어졌습니다.",
        BLOG_ASSETS / "695.png",
        [
            "작은 설정 부재가 대규모 재시작과 장애로 이어짐",
            "프로덕션 진단 결과는 인터넷 악용 가능성과 조치 비용으로 번역해야 함",
        ],
        [
            "장애 타임라인과 진단 우선순위 요약",
            "사후 보고서와 액션 아이템 초안 작성",
        ],
        "https://twodragon.tistory.com/695",
        ACCENT_DARK,
    )


def render_case_patterns(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "실전 사례에서 운영 개선으로", "다섯 사례는 서로 달라 보이지만, 결국 같은 종류의 보안 운영 병목을 드러냈고 모두 운영 개선으로 이어졌습니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 820),
        "사례별 핵심 교훈",
        [
            "공급망 공격: 의존성, SBOM, lockfile, endpoint를 한 번에 봐야 함",
            "Karpenter 장애: 운영 가드레일과 사전 검증 없이는 작은 설정도 대형 장애로 이어짐",
            "DB 접근 게이트웨이: Zero Trust는 철학이 아니라 네트워크/접근 표준화 문제",
            "AIOps 챗봇: Slack 안에서 로그 요약과 아키텍처 질의가 실제로 도움 됨",
            "컨퍼런스 인사이트: AI와 보안은 대립보다 공존 방식이 중요",
        ],
        ACCENT,
    )
    card(
        draw,
        (920, 280, 1770, 820),
        "사건 대응에서 운영 개선으로",
        [
            "탐지 이후 분류와 설명에 가장 많은 시간이 듦",
            "같은 내용을 사건 보고, 경영 보고, 점검 문안으로 반복 작성하게 됨",
            "운영 표준이 문서와 사람 기억에 흩어져 있어 일관성이 떨어짐",
            "결국 사건 대응은 운영 개선과 자동화로 이어져야 의미가 남음",
        ],
        NAVY,
    )
    rounded_rect(draw, (150, 860, 1770, 950), fill="#FFF1E6", radius=20)
    draw.text((186, 888), "핵심: Supply chain to security ops라는 흐름은 별도 섹션이 아니라, 각 사례를 공통 운영 개선 문제로 묶어낼 때 자연스럽게 전달됩니다.", font=BODY_TINY_FONT, fill=ACCENT_DARK)
    return image


def render_business_risk(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "DevSecOps 팀의 현실", "실무자는 프레임워크보다 먼저 '오늘 처리해야 할 일'의 압력과 마주합니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 820),
        "작은 팀이 안고 있는 일",
        [
            "SaaS, 엔드포인트, CI/CD, 클라우드, GitHub, 모니터링을 동시에 본다",
            "사고 대응, 취약점 정리, 증적 작성, 보고 문안을 같은 주에 처리한다",
            "팀은 작지만 설명해야 하는 범위는 넓다",
        ],
        ACCENT,
    )
    card(
        draw,
        (920, 280, 1770, 820),
        "그래서 생기는 병목",
        [
            "같은 정보를 여러 번 요약하고 설명하게 됨",
            "코드 리뷰와 로그 분석의 품질이 사람마다 달라짐",
            "정기점검과 감사 대응 문안이 매번 처음부터 다시 시작됨",
        ],
        NAVY,
    )
    return image


def render_management_arch(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "보안 업무 개선 프레임", "사례가 달라도 개선 포인트는 비슷합니다. Detect, Triage, Explain, Improve 네 축으로 정리할 수 있습니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 840),
        "Detect",
        [
            "사건, 취약점, 로그, 패키지, 의존성, 접근 이슈를 빠르게 찾는다",
            "중요한 것은 알림 수가 아니라 놓치지 않는 것",
        ],
        GREEN,
    )
    card(
        draw,
        (920, 280, 1770, 840),
        "Triage / Explain / Improve",
        [
            "무엇이 직접 위험인지 먼저 분리하고",
            "리더십과 팀이 이해할 언어로 설명하고",
            "다음에는 더 적은 수작업으로 같은 일을 하도록 개선한다",
        ],
        GOLD,
    )
    return image


def render_operations_arch(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "AI를 어디에 붙일 것인가", "AI는 모든 걸 대신하는 도구가 아니라, 반복적이고 구조화 가능한 단계에 붙일 때 가장 효과적입니다.", slide_no)
    card(
        draw,
        (150, 280, 900, 820),
        "붙이기 좋은 영역",
        [
            "코드 리뷰 초안",
            "로그/알림 트리아지",
            "증적·감사 문안 정리",
            "운영 문서와 정책 요약",
            "SaaS 인벤토리와 설정 기준 정리",
        ],
        ACCENT_DARK,
    )
    card(
        draw,
        (980, 280, 1770, 820),
        "붙이면 안 되는 영역",
        [
            "최종 승인과 계정/권한 변경",
            "법적 판단, 예외 승인, 대외 커뮤니케이션",
            "민감정보 원문 처리와 고위험 자동 조치",
        ],
        NAVY,
    )
    return image


def render_why_now(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "사례 1. Axios 공급망 공격", "외부 의존성 하나의 침해가 전체 개발 조직의 운영 리듬을 어떻게 흔드는지 보여주는 전형적인 사례입니다.", slide_no)
    card(
        draw,
        (150, 270, 610, 790),
        "공격 개요",
        [
            "유지관리자 계정 탈취 후 악성 의존성을 삽입한 공급망 공격",
            "postinstall 실행을 통해 RAT 설치를 노린 구조",
            "공격 대상은 Windows, macOS, Linux 전부",
        ],
        ACCENT,
    )
    card(
        draw,
        (730, 270, 1190, 790),
        "보안팀이 바로 봐야 할 것",
        [
            "영향 버전, 악성 패키지, IOC, 설치 방식",
            "lockfile과 실제 설치 버전이 안전한지",
            "CI/CD, 서버, 개발자 단말에 감염 흔적이 있는지",
        ],
        GREEN,
    )
    card(
        draw,
        (1310, 270, 1770, 790),
        "운영 교훈",
        [
            "semver 선언만 보지 말고 실제 설치 버전까지 검증",
            "새로 게시된 패키지를 바로 설치하지 않는 최소 대기 전략 필요",
            "SBOM, Dependabot, endpoint, network를 같이 봐야 함",
        ],
        NAVY,
    )
    draw.text((150, 860), "정리", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    draw_text_block(
        draw,
        210,
        858,
        1420,
        "공급망 공격 대응에서 중요한 것은 탐지 도구 하나가 아니라, 어떤 데이터를 어떤 순서로 결합해 신속하게 안전 판정을 내릴 수 있는가입니다.",
        BODY_SMALL_FONT,
        fill=TEXT,
        spacing=6,
    )
    return image


def render_pain_points(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "공급망 공격 전수 점검 결과", "조직 단위 전수 점검은 '감염 여부'와 '이미 알고 있던 취약점 잔존 여부'를 분리해서 봐야 합니다.", slide_no)
    left_bullets = [
        "점검 범위: GitHub Organization 전체 211개 리포지토리",
        "악성 패키지, C2 IoC, Dependency Graph, Dependabot, lockfile을 함께 확인",
        "악성 패키지와 알려진 C2 흔적은 미검출",
        "즉, '직접 감염'과 '기존 취약성 잔존'은 다른 문제로 정리해야 함",
    ]
    right_bullets = [
        "다수 리포지토리는 공격 버전 범위 밖이었지만, 기존 Dependabot 알림은 계속 열려 있었음",
        "일부 서비스는 기존 업데이트 PR 머지 대기 상태",
        "endpoint와 network 차단, 개발환경 재설치 금지, lockfile 재확인 같은 후속 대응이 필요",
        "공격 대응 보고서는 기술 검증과 경영 보고를 동시에 만족해야 함",
    ]
    card(draw, (150, 280, 900, 820), "무엇을 확인했는가", left_bullets, ACCENT)
    card(draw, (1020, 280, 1770, 820), "무엇이 남았는가", right_bullets, NAVY)
    rounded_rect(draw, (150, 860, 1770, 960), fill="#FFF1E6", radius=24)
    draw.text((190, 892), "결론: 공급망 공격의 직접 감염이 없어도, 기존 취약점과 운영 부채는 별도 우선순위로 계속 관리해야 합니다.", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    return image


def render_attack_timeline(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "공급망 공격 대응 Best Practices", "공격 자체보다 대응 순서가 더 중요합니다. 실제로는 패키지, 조직, 엔드포인트, 네트워크를 함께 봐야 합니다.", slide_no)
    stat_card(draw, (150, 280, 510, 470), "악성 패키지", "plain-crypto-js", "postinstall 기반 RAT 설치 시도", ACCENT_DARK)
    stat_card(draw, (550, 280, 910, 470), "영향 버전", "axios 1.14.1 / 0.30.4", "semver 선언보다 실제 설치 버전 확인이 우선", NAVY)
    stat_card(draw, (950, 280, 1310, 470), "점검 범위", "211 repos", "Dependency Graph, lockfile, Dependabot 동시 점검", GREEN)
    stat_card(draw, (1350, 280, 1710, 470), "판정", "IOC 미검출", "직접 감염은 없었지만 기존 취약점은 별도 관리", GOLD)
    card(
        draw,
        (150, 540, 880, 860),
        "권장 대응 순서",
        [
            "1. 영향 버전과 악성 의존성 확인",
            "2. lockfile / SBOM 기준 실제 설치 버전 검증",
            "3. endpoint와 CI/CD에서 설치 흔적 제거",
            "4. network 차단과 관리자 공지 병행",
        ],
        ACCENT,
    )
    card(
        draw,
        (940, 540, 1770, 860),
        "운영 Best Practices",
        [
            "신규 게시 패키지의 최소 대기 시간 설정",
            "ignore-scripts, lockfile 보호, action pinning 적용",
            "SBOM과 Dependabot을 사건 대응 체계 안에 포함",
            "사건 종료 후에도 기존 취약점 PR 머지 상태를 추적",
        ],
        NAVY,
    )
    return image


def render_org_reality(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "사례 2. 프로덕션 보안 진단 요약", "프로덕션 보안 진단은 개별 취약점 나열보다, 공격 가능성과 영향 범위를 기준으로 계층화해야 합니다.", slide_no)
    card(
        draw,
        (150, 290, 700, 800),
        "요약 판정",
        [
            "총 23건 수준으로 분류: Critical 3, High 8, Medium 7, Low 5",
            "인터넷에서 즉시 악용 가능한 취약점이 실제 확인됨",
            "관리자 API, 외부 콜백, 인증 우회, 시크릿 노출, 인프라 설정 문제가 혼재",
        ],
        ACCENT,
    )
    card(
        draw,
        (760, 290, 1310, 800),
        "대표 위험 유형",
        [
            "과도한 permitAll, 인증 우회용 더미 필터, 검증 없는 외부 콜백",
            "하드코딩된 시크릿과 로테이션 미흡",
            "Redis/TLS, NetworkPolicy, 관리도구 노출, CI/CD action pinning 부재",
        ],
        GREEN,
    )
    card(
        draw,
        (1370, 290, 1770, 800),
        "발표용 익명화 기준",
        [
            "도메인, 레포명, 파일 경로, 시크릿 값, 사용자 데이터는 직접 공개하지 않음",
            "취약점 유형, 우선순위, 조치 방향만 구조적으로 설명",
            "사례의 학습 가치와 조직 보호를 동시에 만족",
        ],
        NAVY,
    )
    rounded_rect(draw, (150, 850, 1770, 960), fill="#FFF1E6", radius=24)
    draw.text((188, 885), "정리: 프로덕션 보안 진단 결과는 '무엇이 위험한가'보다 '무엇부터 막아야 하는가' 중심으로 번역되어야 경영과 실무 모두에 전달됩니다.", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    return image


def render_findings_breakdown(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "프로덕션 보안 진단 Best Practices", "취약점 목록을 그대로 전달하는 대신, 인터넷 악용 가능성·범위·조치 비용으로 번역해야 합니다.", slide_no)
    stat_card(draw, (150, 270, 450, 455), "Critical", "3", "인터넷에서 즉시 악용 가능한 취약점", "#D94841")
    stat_card(draw, (490, 270, 790, 455), "High", "8", "1주 내 조치 권고", "#E28A2F")
    stat_card(draw, (830, 270, 1130, 455), "Medium", "7", "설계/구성 보완 필요", "#C99724")
    stat_card(draw, (1170, 270, 1470, 455), "Low", "5", "업그레이드와 정책 보완", "#6C757D")
    stat_card(draw, (1510, 270, 1770, 455), "총계", "23", "기술 부채와 즉시 위험이 혼재", GREEN)
    card(
        draw,
        (150, 520, 880, 860),
        "발표용으로 남기고 제거할 것",
        [
            "남길 것: 취약점 유형, 심각도, 조치 방향, 학습 포인트",
            "제거할 것: 도메인, 레포명, 파일 경로, 시크릿 값, 사용자 정보",
            "사례 공유의 목표는 조직 보호와 학습 확산의 균형",
        ],
        ACCENT,
    )
    card(
        draw,
        (940, 520, 1770, 860),
        "실무 Best Practices",
        [
            "permitAll / callback validation / dummy auth 같은 구조적 결함부터 우선",
            "시크릿 로테이션, TLS, NetworkPolicy, 관리도구 노출은 즉시 운영 항목으로 묶기",
            "수정 난이도와 영향 범위를 함께 써야 리더십 의사결정이 빨라짐",
        ],
        NAVY,
    )
    return image


def render_persona(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "작은 DevSecOps 팀이 왜 내부 시스템을 필요로 하는가", "운영 대상은 많고 팀은 작을수록, 사람의 기억보다 시스템의 구조가 더 중요해집니다.", slide_no)
    columns = [
        ("운영 복잡성", "대상은 많고 팀은 작다", [
            "60개 이상 SaaS, 100대 이상 엔드포인트, 멀티 계정 클라우드",
            "정기점검, 감사, 취약점, 비용, 권한 이슈가 동시에 발생",
            "사람 중심 운영은 누락과 설명 비용을 키움",
        ], ACCENT),
        ("설명 책임", "CISO / ISMS / 경영 보고", [
            "무엇을 점검했고 무엇이 남았는지 설명 가능해야 함",
            "증적과 이행 상태를 다시 만들지 않고 보여줄 수 있어야 함",
            "보안 활동이 개인 역량이 아니라 체계로 보여야 함",
        ], GREEN),
        ("경영 가치", "비용과 가시성", [
            "CFO는 비용 최적화, CEO는 운영 가시성, 실무자는 반복업무 절감을 원함",
            "그래서 내부 시스템은 보안 도구이면서 운영 체계가 되어야 함",
            "ClaudeSec은 이 접점을 설명하기 좋은 사례",
        ], NAVY),
    ]
    x = 150
    for title, subtitle, bullets, color in columns:
        rounded_rect(draw, (x, 290, x + 500, 850), fill=CARD, outline=LINE, width=2, radius=30)
        draw.rectangle((x, 290, x + 500, 370), fill=color)
        draw.text((x + 34, 316), title, font=load_font(36), fill="white")
        draw.text((x + 34, 392), subtitle, font=BODY_SMALL_FONT, fill=MUTED)
        bullet_block(draw, x + 34, 448, 430, bullets, font=BODY_SMALL_FONT)
        x += 560
    return image


def render_ai_security(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "AI를 활용한 보안 업무 개선", "AI는 보안 의사결정을 대체하기보다, 반복적이고 구조화 가능한 보안 업무를 먼저 줄이는 데 효과적입니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 520),
        "1. AI 보안 코드리뷰",
        [
            "변경된 코드에서 인증·권한·비밀정보·취약 패턴 우선 점검",
            "주니어는 체크리스트 학습, 시니어는 리뷰 누락 감소",
            "최종 승인과 예외 판단은 사람 리뷰어가 수행",
        ],
        ACCENT,
    )
    card(
        draw,
        (900, 280, 1770, 520),
        "2. 로그/알림 트리아지",
        [
            "Datadog·EDR·운영 로그를 요약해 이상징후 후보를 빠르게 정리",
            "사람이 먼저 볼 알림을 줄여 분석 우선순위 선명화",
            "오탐 가능성이 있으므로 자동 차단보다 분석 보조에 우선 사용",
        ],
        NAVY,
    )
    card(
        draw,
        (150, 570, 840, 860),
        "3. 증적·감사 문안 초안",
        [
            "ISMS 점검 결과, 조치 현황, 정기점검 요약을 초안으로 정리",
            "규정/지침과 실제 점검 결과 연결 시 시간 절감 효과 큼",
            "개인정보·민감정보는 제거 또는 마스킹 후만 사용",
        ],
        GREEN,
    )
    card(
        draw,
        (900, 570, 1770, 860),
        "4. 정책/운영 문서 요약",
        [
            "내부 규정, 운영 절차, SaaS 설정 기준을 검색·요약 가능하게 정리",
            "신규 담당자 온보딩과 부서 간 설명 비용 감소",
            "문서 최신성 검증과 승인 이력은 별도로 유지해야 함",
        ],
        GOLD,
    )
    return image


def render_devsecops(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "사건 대응에서 운영 개선으로", "실전 사례를 겪고 나면, 논점은 사고 자체보다 다음부터 같은 일을 어떻게 덜 반복할지로 이동합니다.", slide_no)
    steps = [
        ("Detect", "공급망 공격, IOC, SBOM, Dependabot 확인", ACCENT),
        ("Triage", "무엇이 직접 위험이고 무엇이 운영 부채인지 구분", GREEN),
        ("Contain", "endpoint / network / CI 대응과 차단 조치", GOLD),
        ("Explain", "증적, 정기점검, 리더십 보고 문안 정리", NAVY),
        ("Improve", "정책, 자동화, KPI, 재발방지 업데이트", ACCENT_DARK),
    ]
    x = 148
    for title, desc, color in steps:
        rounded_rect(draw, (x, 380, x + 290, 720), fill=CARD, outline=LINE, width=2, radius=28)
        draw.ellipse((x + 86, 280, x + 206, 400), fill=color)
        draw.text((x + 118, 320), title[0], font=load_font(58), fill="white")
        draw.text((x + 36, 436), title, font=BODY_FONT, fill=TEXT)
        draw_text_block(draw, x + 36, 496, 220, desc, BODY_SMALL_FONT, fill=MUTED, spacing=8)
        if x < 148 + 4 * 322:
            draw.line((x + 290, 550, x + 322, 550), fill=LINE, width=6)
        x += 322
    rounded_rect(draw, (180, 810, 1740, 930), fill="#1A1918", radius=28)
    draw.text((224, 844), "메시지: 사건 대응이 끝나도 운영 개선은 남습니다. AI는 그 반복 구간을 줄이는 데 가장 효과적입니다.", font=BODY_SMALL_FONT, fill="#FAF1E8")
    return image


def render_claudesec(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "ClaudeSec 소개", "ClaudeSec은 AI 기반 DevSecOps 자산관리와 보안 운영을 연결하는 오픈소스 프로젝트로 설명할 수 있습니다.", slide_no)
    rounded_rect(draw, (150, 280, 760, 850), fill="#1A1918", radius=32)
    add_logo(image, ASSETS / "claudesec-logo-512.png", (220, 320, 690, 520))
    bullet_block(
        draw,
        214,
        560,
        500,
        [
            "코드, 인프라, SaaS, 컴플라이언스, 점검 이력을 한 화면에 연결",
            "보안 점검과 운영 데이터를 대시보드와 문서화 흐름으로 연결",
            "작은 팀에서도 체계가 작동하도록 운영 기준을 고정",
            "SaaS 관리자 관점의 현황 파악과 통제 기준 정리에 도움",
        ],
        font=BODY_SMALL_FONT,
        fill="#FFF9F3",
    )
    qr = ensure_qr("claudesec-github", "https://github.com/Twodragon0/claudesec")
    add_framed_image(image, draw, qr, (270, 700, 430, 840), None)
    draw.text((458, 742), "GitHub", font=BODY_SMALL_FONT, fill="#FFF8F2")
    draw.text((458, 782), "QR 스캔으로 저장소 보기", font=BODY_TINY_FONT, fill="#D9CEC4")
    card(
        draw,
        (840, 280, 1770, 520),
        "실무 활용 예시",
        [
            "보안 스캐너와 대시보드",
            "ISMS-P / 컴플라이언스 매핑",
            "SaaS / 자산 / 라이선스 가시성",
            "정기점검 이력 연계",
            "보안 운영 문서화",
        ],
        ACCENT,
    )
    card(
        draw,
        (840, 570, 1770, 850),
        "발표 포인트",
        [
            "보안 조직뿐 아니라 개발·운영·관리자 모두가 같은 데이터를 보게 함",
            "CFO 관점의 비용 최적화와 CEO 관점의 운영 가시성을 같이 설명 가능",
            "특히 다수 SaaS를 관리하는 작은 조직에서 효과가 큼",
            "AI 활용 보안 운영을 구체적 시스템으로 보여주는 사례가 됨",
        ],
        NAVY,
    )
    return image


def render_claudesec_mapping(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "ClaudeSec이 사례 문제를 어떻게 흡수하는가", "ClaudeSec은 각 사례에서 반복된 수집·정리·가시화 문제를 일부 흡수하는 운영 허브로 설명할 수 있습니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 820),
        "사례와 연결되는 기능",
        [
            "공급망 공격: 스캐너, 의존성 점검, 보고서 초안",
            "운영 장애: 로그/시그널/정기점검 이력 요약",
            "Zero Trust 운영: SaaS·자산·접근 현황 가시화",
            "AIOps: Slack/문서/대시보드 기반 설명 비용 절감",
        ],
        ACCENT,
    )
    card(
        draw,
        (920, 280, 1770, 820),
        "대체가 아니라 연결",
        [
            "물리보안, 계약, 법률 판단, 최종 승인까지 대체하지는 않음",
            "대신 수집·요약·가시화·설명 비용을 줄이는 역할에 강함",
            "작은 팀에게 중요한 것은 기능 수보다 연결된 흐름",
            "그래서 ClaudeSec은 도구보다 운영 체계에 가깝게 설명하는 편이 맞음",
        ],
        NAVY,
    )
    return image


def render_ai_guardrails(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "AI 활용 Guardrails", "AI 활용 범위를 넓히기 전에, 무엇을 맡기고 무엇을 맡기지 않을지 먼저 고정해야 합니다.", slide_no)
    card(
        draw,
        (150, 280, 840, 520),
        "AI에 맡겨도 되는 일",
        [
            "코드리뷰 초안, 로그 요약, 증적 문안 정리",
            "정책/운영 문서 검색·요약, SaaS 인벤토리 정규화",
            "반복적이고 설명 가능한 업무",
        ],
        GREEN,
    )
    card(
        draw,
        (900, 280, 1770, 520),
        "사람이 유지해야 하는 일",
        [
            "최종 승인, 예외 판단, 계정·권한 변경",
            "법적/사업적 리스크 평가",
            "외부 커뮤니케이션과 공식 판정",
        ],
        ACCENT,
    )
    card(
        draw,
        (150, 570, 840, 860),
        "데이터 Best Practices",
        [
            "민감정보, 개인정보, 시크릿은 제거·마스킹 후만 사용",
            "내부 문서는 최신본 기준과 승인 이력 유지",
            "프롬프트와 출력 모두 로그/보관 정책 안에서 관리",
        ],
        NAVY,
    )
    card(
        draw,
        (900, 570, 1770, 860),
        "운영 Best Practices",
        [
            "human-in-the-loop, least privilege, audit trail을 기본값으로 설정",
            "자동 차단보다 요약·분류·추천부터 시작",
            "정확도보다 재현 가능성과 설명 가능성을 KPI에 포함",
        ],
        GOLD,
    )
    return image


def render_dashboard_examples(slide_no: int) -> Image.Image:
    image, draw = new_slide("#F5F7FA")
    decorate(draw, "ClaudeSec 화면 예시", "공개된 ClaudeSec 대시보드 이미지 기준으로, 어떤 가시성을 제공하는지 예시 수준에서만 보여줍니다.", slide_no)
    add_framed_image(image, draw, LINKEDIN_ASSETS / "claudesec-1.jpg", (120, 260, 1030, 770), "Architecture")
    add_framed_image(image, draw, LINKEDIN_ASSETS / "claudesec-2.jpg", (1080, 260, 1800, 530), "ISMS PDCA")
    add_framed_image(image, draw, LINKEDIN_ASSETS / "claudesec-3.jpg", (1080, 560, 1800, 830), "Findings")
    rounded_rect(draw, (120, 800, 1030, 950), fill=CARD, outline=LINE, width=2, radius=24)
    draw.text((156, 832), "이 화면이 주는 의미", font=BODY_SMALL_FONT, fill=NAVY)
    bullet_block(
        draw,
        156,
        874,
        820,
        [
            "데이터 수집, 교차검증, 점검 결과를 한 흐름으로 설명 가능",
            "경영진은 현황과 리스크를 보고, 실무자는 다음 액션을 결정 가능",
        ],
        font=BODY_TINY_FONT,
    )
    return image


def render_governance(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "무엇부터 자동화하고 무엇으로 통제할 것인가", "AI를 쓴다고 통제가 줄어드는 것이 아니라, 오히려 입력·승인·로그 통제가 더 중요해집니다.", slide_no)
    sections = [
        ("입력 통제", ["민감정보·개인정보 업로드 기준 정의", "내부 문서는 제거·마스킹 후만 요약"], ACCENT),
        ("권한 통제", ["최소권한, 1인 1계정, MFA 유지", "고위험 작업은 사람 승인 필수"], GREEN),
        ("운영 통제", ["로그 보관, 변경 이력, 승인 이력 관리", "AI 출력 결과는 실행 전 검토"], NAVY),
        ("리스크 통제", ["프롬프트 인젝션과 정보유출 대응", "잘못된 자동화와 과도한 권한 방지"], GOLD),
    ]
    x = 150
    y = 290
    for idx, (title, bullets, color) in enumerate(sections):
        card(draw, (x, y, x + 770, y + 220), title, bullets, color)
        if idx % 2 == 1:
            x = 150
            y += 260
        else:
            x = 1000
    rounded_rect(draw, (150, 860, 1770, 960), fill="#FFF1E6", radius=24)
    draw.text((190, 892), "정리: AI 도입은 생산성 프로젝트이면서 동시에 보안 통제 프로젝트입니다. 입력, 승인, 로그 세 가지를 먼저 고정해야 합니다.", font=BODY_SMALL_FONT, fill=ACCENT_DARK)
    return image


def render_roadmap(slide_no: int) -> Image.Image:
    image, draw = new_slide()
    decorate(draw, "단계별 도입 로드맵", "사건 대응에서 바로 연결되는 반복 구간부터 자동화하는 편이 가장 설득력이 있습니다.", slide_no)
    phases = [
        ("1단계\n1개월", "반복 문서화", ["사건 요약 초안", "증적/정기점검 문안", "보고서 템플릿"], ACCENT),
        ("2단계\n2~3개월", "보안 점검", ["코드 리뷰 보조", "체크리스트 자동화", "취약점 요약"], GREEN),
        ("3단계\n3~6개월", "운영 연계", ["로그/알림 트리아지", "SaaS 인벤토리", "운영 문서화"], NAVY),
        ("4단계\n6개월+", "관리 체계", ["승인 프로세스", "권한/로그 통제", "KPI 측정과 표준화"], ACCENT_DARK),
    ]
    x = 150
    for phase, subtitle, bullets, color in phases:
        rounded_rect(draw, (x, 330, x + 380, 860), fill=CARD, outline=LINE, width=2, radius=30)
        draw.rectangle((x, 330, x + 380, 460), fill=color)
        draw.multiline_text((x + 34, 360), phase, font=load_font(34), fill="white", spacing=8)
        draw.text((x + 34, 500), subtitle, font=BODY_FONT, fill=TEXT)
        bullet_block(draw, x + 34, 560, 300, bullets, font=BODY_SMALL_FONT)
        if x < 1310:
            draw.line((x + 380, 594, x + 438, 594), fill=LINE, width=8)
        x += 420
    return image


def render_priority(slide_no: int) -> Image.Image:
    image, draw = new_slide(BG_ALT)
    decorate(draw, "우선순위와 KPI", "바로 시작할 수 있는 과제와 나중에 확장할 과제를 구분해야 세미나가 실행안으로 보입니다.", slide_no)
    card(
        draw,
        (150, 290, 840, 780),
        "우선순위 P0",
        [
            "사건 요약·보고서 초안 작성",
            "보안 코드리뷰 보조",
            "점검 체크리스트 자동화",
            "로그/알림 트리아지 초안",
            "60개+ SaaS 관리 현황 정리와 보안 설정 점검 보조",
        ],
        ACCENT,
    )
    card(
        draw,
        (900, 290, 1770, 780),
        "KPI 예시",
        [
            "문서 초안 작성 시간 50% 절감",
            "리뷰 누락 항목 30% 감소",
            "감사 대응 자료 준비 시간 40% 절감",
            "알림 1차 분석 시간 50% 절감",
            "SaaS 현황 파악 및 점검 준비 리드타임 단축",
        ],
        NAVY,
    )
    rounded_rect(draw, (150, 830, 1770, 960), fill=CARD, outline=LINE, width=2, radius=26)
    draw.text((184, 862), "판단 기준", font=BODY_SMALL_FONT, fill=TEXT)
    draw_text_block(
        draw,
        330,
        860,
        1360,
        "반복 빈도, 품질 편차, 보안 리스크 통제 가능성, 성과 측정 가능성. 이 네 가지를 기준으로 파일럿 대상을 정하면 무리한 확대를 피할 수 있습니다.",
        BODY_SMALL_FONT,
        fill=MUTED,
        spacing=8,
    )
    return image


def render_closing(slide_no: int) -> Image.Image:
    image, draw = new_slide("#171614")
    draw.ellipse((1120, -200, 2100, 780), fill=(226, 109, 47, 34))
    draw.ellipse((1260, 420, 2140, 1300), fill=(17, 120, 100, 34))
    draw.text((150, 170), "마무리", font=SECTION_FONT, fill="#E9D7C8")
    draw.text((150, 238), "공급망 공격 대응과 보안 진단이 남긴 질문은\n'무엇을 더 살까'가 아니라,\n'무엇을 어떻게 더 체계적으로 운영할까'입니다.", font=load_font(58), fill="#FFF8F2", spacing=10)
    rounded_rect(draw, (150, 590, 860, 860), fill="#24211F", outline="#3A3531", width=2, radius=28)
    bullet_block(
        draw,
        194,
        640,
        600,
        [
            "작은 DevSecOps 팀일수록 반복 업무와 설명 비용을 줄이는 시스템이 필요",
            "AI는 코드리뷰, 트리아지, 증적 정리, 문서 요약부터 적용하는 것이 현실적",
            "ClaudeSec은 그 메시지를 보여주는 실무형 사례가 될 수 있음",
            "단, 개인정보와 민감정보는 제거·마스킹 후만 AI와 발표 자료에 반영",
            "특히 60개 이상 SaaS를 관리하는 소수 인력 구조에서 체계화 효과가 큼",
        ],
        font=BODY_SMALL_FONT,
        fill="#FFF7EF",
    )
    add_logo(image, ASSETS / "claudesec-logo-512.png", (1110, 720, 1720, 930))
    draw.text((1490, 970), f"{slide_no:02d}", font=BIG_NUMBER_FONT, fill="#4A433F")
    return image


SLIDES: list[SlideSpec] = [
    SlideSpec("표지", "", render_intro),
    SlideSpec("발표자 소개", "", render_speaker),
    SlideSpec("LEVVELS 소개", "", render_levvels),
    SlideSpec("개요 및 목적", "", render_overview),
    SlideSpec("목차", "", render_agenda),
    SlideSpec("DevSecOps 팀 현실", "", render_business_risk),
    SlideSpec("보안 개선 프레임", "", render_management_arch),
    SlideSpec("AI 적용 범위", "", render_operations_arch),
    SlideSpec("내부 시스템 필요성", "", render_persona),
    SlideSpec("프레임워크 개요", "", render_framework_overview),
    SlideSpec("사례 1", "", render_case_692),
    SlideSpec("사례 2", "", render_case_704),
    SlideSpec("사례 3", "", render_case_673),
    SlideSpec("사례 4", "", render_case_696),
    SlideSpec("사례 5", "", render_case_695),
    SlideSpec("사례 패턴", "", render_case_patterns),
    SlideSpec("AI 운영 섹션", "", lambda n: section_slide("AI for Security Workflows", "AI는 보안 판단의 대체물이 아니라, 반복적이고 구조화 가능한 업무를 줄이는 보조 레이어입니다.", n, GREEN)),
    SlideSpec("AI 보안 운영 개선", "", render_ai_security),
    SlideSpec("AI Guardrails", "", render_ai_guardrails),
    SlideSpec("DevSecOps 프레임", "", render_devsecops),
    SlideSpec("ClaudeSec 소개", "", render_claudesec),
    SlideSpec("ClaudeSec 매핑", "", render_claudesec_mapping),
    SlideSpec("ClaudeSec 화면 예시", "", render_dashboard_examples),
    SlideSpec("보안·규정 준수", "", render_governance),
    SlideSpec("도입 로드맵", "", render_roadmap),
    SlideSpec("우선순위와 KPI", "", render_priority),
    SlideSpec("마무리", "", render_closing),
]


def content_types_xml(slide_count: int) -> str:
    slide_overrides = "\n".join(
        f'    <Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        for i in range(1, slide_count + 1)
    )
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="png" ContentType="image/png"/>
    <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
    <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
    <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
    <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
    <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
    <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
{slide_overrides}
</Types>
"""


def root_rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""


def app_xml(slide_count: int) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>ClaudeSec PPT Generator</Application>
  <PresentationFormat>On-screen Show (16:9)</PresentationFormat>
  <Slides>{slide_count}</Slides>
  <Notes>0</Notes>
  <HiddenSlides>0</HiddenSlides>
  <MMClips>0</MMClips>
  <ScaleCrop>false</ScaleCrop>
  <HeadingPairs>
    <vt:vector size="2" baseType="variant">
      <vt:variant><vt:lpstr>Slides</vt:lpstr></vt:variant>
      <vt:variant><vt:i4>{slide_count}</vt:i4></vt:variant>
    </vt:vector>
  </HeadingPairs>
  <TitlesOfParts>
    <vt:vector size="{slide_count}" baseType="lpstr">
      {''.join(f'<vt:lpstr>Slide {i}</vt:lpstr>' for i in range(1, slide_count + 1))}
    </vt:vector>
  </TitlesOfParts>
  <Company>LEVVELS</Company>
  <LinksUpToDate>false</LinksUpToDate>
  <SharedDoc>false</SharedDoc>
  <HyperlinksChanged>false</HyperlinksChanged>
  <AppVersion>1.0</AppVersion>
</Properties>
"""


def core_xml() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>AI를 통한 업무 개선</dc:title>
  <dc:subject>LEVVELS x ClaudeSec DevSecOps presentation</dc:subject>
  <dc:creator>Codex</dc:creator>
  <cp:keywords>AI, DevSecOps, ClaudeSec, LEVVELS</cp:keywords>
  <dc:description>LEVVELS와 ClaudeSec을 포함한 AI 업무개선 발표자료</dc:description>
  <cp:lastModifiedBy>Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{ts}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{ts}</dcterms:modified>
</cp:coreProperties>
"""


def presentation_xml(slide_count: int) -> str:
    slide_ids = "\n".join(
        f'    <p:sldId id="{256 + i}" r:id="rId{i + 1}"/>'
        for i in range(1, slide_count + 1)
    )
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>
{slide_ids}
  </p:sldIdLst>
  <p:sldSz cx="{SLIDE_W_EMU}" cy="{SLIDE_H_EMU}"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>
"""


def presentation_rels_xml(slide_count: int) -> str:
    rels = ['  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>']
    for i in range(1, slide_count + 1):
        rels.append(
            f'  <Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>'
        )
    rels_joined = "\n".join(rels)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
{rels_joined}
</Relationships>
"""


def slide_master_xml() -> str:
    tx_styles = """
  <p:txStyles>
    <p:titleStyle>
      <a:lvl1pPr algn="l">
        <a:defRPr sz="3200" b="1"/>
      </a:lvl1pPr>
    </p:titleStyle>
    <p:bodyStyle>
      <a:lvl1pPr marL="0" indent="0">
        <a:defRPr sz="1800"/>
      </a:lvl1pPr>
    </p:bodyStyle>
    <p:otherStyle>
      <a:lvl1pPr marL="0" indent="0">
        <a:defRPr sz="1800"/>
      </a:lvl1pPr>
    </p:otherStyle>
  </p:txStyles>
"""
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld name="Master">
    <p:bg>
      <p:bgRef idx="1001">
        <a:schemeClr val="bg1"/>
      </p:bgRef>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm>
          <a:off x="0" y="0"/>
          <a:ext cx="0" cy="0"/>
          <a:chOff x="0" y="0"/>
          <a:chExt cx="0" cy="0"/>
        </a:xfrm>
      </p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="1" r:id="rId1"/>
  </p:sldLayoutIdLst>
{tx_styles}
</p:sldMaster>
"""


def slide_master_rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>
"""


def slide_layout_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm>
          <a:off x="0" y="0"/>
          <a:ext cx="0" cy="0"/>
          <a:chOff x="0" y="0"/>
          <a:chExt cx="0" cy="0"/>
        </a:xfrm>
      </p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>
"""


def slide_layout_rels_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>
"""


def theme_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="ClaudeSec Theme">
  <a:themeElements>
    <a:clrScheme name="ClaudeSec">
      <a:dk1><a:srgbClr val="161514"/></a:dk1>
      <a:lt1><a:srgbClr val="FFFDFC"/></a:lt1>
      <a:dk2><a:srgbClr val="19324D"/></a:dk2>
      <a:lt2><a:srgbClr val="F6F1E8"/></a:lt2>
      <a:accent1><a:srgbClr val="E26D2F"/></a:accent1>
      <a:accent2><a:srgbClr val="117864"/></a:accent2>
      <a:accent3><a:srgbClr val="19324D"/></a:accent3>
      <a:accent4><a:srgbClr val="C99724"/></a:accent4>
      <a:accent5><a:srgbClr val="B24B17"/></a:accent5>
      <a:accent6><a:srgbClr val="5B5650"/></a:accent6>
      <a:hlink><a:srgbClr val="0563C1"/></a:hlink>
      <a:folHlink><a:srgbClr val="954F72"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="ClaudeSec Fonts">
      <a:majorFont>
        <a:latin typeface="Arial"/>
        <a:ea typeface="Apple SD Gothic Neo"/>
        <a:cs typeface="Arial"/>
      </a:majorFont>
      <a:minorFont>
        <a:latin typeface="Arial"/>
        <a:ea typeface="Apple SD Gothic Neo"/>
        <a:cs typeface="Arial"/>
      </a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="ClaudeSec Format">
      <a:fillStyleLst>
        <a:solidFill><a:schemeClr val="accent1"/></a:solidFill>
        <a:solidFill><a:schemeClr val="accent2"/></a:solidFill>
        <a:solidFill><a:schemeClr val="accent3"/></a:solidFill>
      </a:fillStyleLst>
      <a:lnStyleLst>
        <a:ln w="9525"><a:solidFill><a:schemeClr val="accent1"/></a:solidFill></a:ln>
        <a:ln w="25400"><a:solidFill><a:schemeClr val="accent2"/></a:solidFill></a:ln>
        <a:ln w="38100"><a:solidFill><a:schemeClr val="accent3"/></a:solidFill></a:ln>
      </a:lnStyleLst>
      <a:effectStyleLst>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
      </a:effectStyleLst>
      <a:bgFillStyleLst>
        <a:solidFill><a:schemeClr val="lt1"/></a:solidFill>
        <a:solidFill><a:schemeClr val="lt2"/></a:solidFill>
        <a:solidFill><a:schemeClr val="dk1"/></a:solidFill>
      </a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
  <a:objectDefaults/>
  <a:extraClrSchemeLst/>
</a:theme>
"""


def slide_xml(image_rel_id: str = "rId2") -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm>
          <a:off x="0" y="0"/>
          <a:ext cx="0" cy="0"/>
          <a:chOff x="0" y="0"/>
          <a:chExt cx="0" cy="0"/>
        </a:xfrm>
      </p:grpSpPr>
      <p:pic>
        <p:nvPicPr>
          <p:cNvPr id="2" name="Background"/>
          <p:cNvPicPr>
            <a:picLocks noChangeAspect="1"/>
          </p:cNvPicPr>
          <p:nvPr/>
        </p:nvPicPr>
        <p:blipFill>
          <a:blip r:embed="{image_rel_id}"/>
          <a:stretch><a:fillRect/></a:stretch>
        </p:blipFill>
        <p:spPr>
          <a:xfrm>
            <a:off x="0" y="0"/>
            <a:ext cx="{SLIDE_W_EMU}" cy="{SLIDE_H_EMU}"/>
          </a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
        </p:spPr>
      </p:pic>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>
"""


def slide_rels_xml(slide_no: int) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/slide{slide_no}.png"/>
</Relationships>
"""


def write_pptx(slide_paths: list[Path]) -> None:
    OUTPUT_PPTX.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUTPUT_PPTX, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        slide_count = len(slide_paths)
        zf.writestr("[Content_Types].xml", content_types_xml(slide_count))
        zf.writestr("_rels/.rels", root_rels_xml())
        zf.writestr("docProps/app.xml", app_xml(slide_count))
        zf.writestr("docProps/core.xml", core_xml())
        zf.writestr("ppt/presentation.xml", presentation_xml(slide_count))
        zf.writestr("ppt/_rels/presentation.xml.rels", presentation_rels_xml(slide_count))
        zf.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml())
        zf.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", slide_master_rels_xml())
        zf.writestr("ppt/slideLayouts/slideLayout1.xml", slide_layout_xml())
        zf.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", slide_layout_rels_xml())
        zf.writestr("ppt/theme/theme1.xml", theme_xml())
        for idx, slide_path in enumerate(slide_paths, start=1):
            zf.writestr(f"ppt/slides/slide{idx}.xml", slide_xml())
            zf.writestr(f"ppt/slides/_rels/slide{idx}.xml.rels", slide_rels_xml(idx))
            zf.write(slide_path, f"ppt/media/slide{idx}.png")


def render_slides() -> list[Path]:
    slide_paths: list[Path] = []
    with TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for idx, spec in enumerate(SLIDES, start=1):
            image = spec.render(idx).convert("RGB")
            path = tmpdir / f"slide{idx}.png"
            image.save(path, format="PNG", optimize=True)
            slide_paths.append(path)
        write_pptx(slide_paths)
    return slide_paths


def main() -> None:
    render_slides()
    print(f"Generated {OUTPUT_PPTX}")


if __name__ == "__main__":
    main()
