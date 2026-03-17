#!/usr/bin/env python3
"""
5.PC 워크시트 업데이트 스크립트

Jamf Pro 인벤토리 JSON에서 computer 타입만 필터링하여
Google Sheets 5.PC 워크시트의 데이터 행(row 9~)을 완전 교체합니다.

사용법:
  source .venv-asset/bin/activate
  python3 scripts/update-pc-sheet.py
"""

import json
from pathlib import Path

import gspread

# ── 설정 ─────────────────────────────────────────────────────────────────────

SHEET_ID   = "REDACTED_SHEET_ID"
WORKSHEET  = "5.PC"
HEADER_ROW = 8   # row 8 = 헤더 (1-indexed)
DATA_START  = 9  # row 9 = 데이터 시작

ROOT          = Path(__file__).resolve().parent.parent
INVENTORY_JSON = ROOT / ".claudesec-assets" / "jamf-full-inventory.json"

# ── 인벤토리 로드 ──────────────────────────────────────────────────────────────

print(f"[1/4] Jamf 인벤토리 로드: {INVENTORY_JSON}")
with open(INVENTORY_JSON, encoding="utf-8") as f:
    all_devices = json.load(f)

computers = [d for d in all_devices if d.get("type") == "computer"]
print(f"      전체 장치: {len(all_devices)}개  →  computer: {len(computers)}개")

# ── 사용자 이름 기준 정렬 ──────────────────────────────────────────────────────

computers.sort(key=lambda d: (d.get("user") or "").lower())

# ── 행 데이터 생성 ─────────────────────────────────────────────────────────────

def edr_status(device: dict) -> str:
    return "설치됨" if device.get("status") == "active" else "퇴사"

rows = []
for idx, device in enumerate(computers, start=1):
    row = [
        idx,                                # A: No
        "자산",                              # B: (empty header → 자산)
        "",                                 # C: 고정자산관리번호 (재무팀)
        "",                                 # D: 자산코드
        "",                                 # E: 관리번호
        "",                                 # F: 자산번호
        "전산장비",                           # G: 자산분류
        "노트북",                             # H: 자산명
        "Apple",                            # I: 브랜드
        device.get("model", ""),            # J: 형식(모델명)
        "",                                 # K: 모델번호
        device.get("name", ""),             # L: SentinelOne 기기명
        device.get("serial", ""),           # M: 시리얼번호
        edr_status(device),                 # N: EDR 상태
    ]
    rows.append(row)

departed_count = sum(1 for d in computers if d.get("status") != "active")
print(f"      작성 행: {len(rows)}개  (퇴사: {departed_count}개)")

# ── Google Sheets 인증 ────────────────────────────────────────────────────────

print("[2/4] Google Sheets 인증 중...")
gc = gspread.oauth(
    scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
)

# ── 워크시트 접근 ──────────────────────────────────────────────────────────────

print(f"[3/4] 워크시트 '{WORKSHEET}' 접근 중...")
sh = gc.open_by_key(SHEET_ID)
ws = sh.worksheet(WORKSHEET)

# 현재 시트의 총 행 수 확인
existing_row_count = len(ws.get_all_values())
print(f"      현재 데이터 행 수: {existing_row_count}행")

# ── 기존 데이터 행 초기화 후 새 데이터 기록 ──────────────────────────────────────

print("[4/4] 데이터 업데이트 중...")

# 지울 행 범위: DATA_START ~ 현재 마지막 행
if existing_row_count >= DATA_START:
    rows_to_clear = existing_row_count - DATA_START + 1
    clear_range = f"A{DATA_START}:Z{existing_row_count}"
    ws.batch_clear([clear_range])
    print(f"      기존 데이터 행 {rows_to_clear}개 삭제 완료 ({clear_range})")

# 새 데이터 쓰기 (batch_update)
if rows:
    end_row   = DATA_START + len(rows) - 1
    end_col   = chr(ord("A") + len(rows[0]) - 1)   # N = 14번째 열
    write_range = f"A{DATA_START}:{end_col}{end_row}"

    ws.update(
        range_name=write_range,
        values=rows,
        value_input_option="USER_ENTERED",
    )
    print(f"      새 데이터 {len(rows)}행 기록 완료 ({write_range})")

# ── 결과 요약 ──────────────────────────────────────────────────────────────────

print()
print("=" * 50)
print(f"[완료] 5.PC 워크시트 업데이트 성공")
print(f"  - 총 PC 수      : {len(rows)}대")
print(f"  - 재직 (설치됨) : {len(rows) - departed_count}대")
print(f"  - 퇴사          : {departed_count}대")
print("=" * 50)
