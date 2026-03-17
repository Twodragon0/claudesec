#!/usr/bin/env python3
"""
Google Sheets OAuth2 인증 + 자산관리대장 상세 읽기
"""
import os

import gspread
import json
from pathlib import Path

SHEET_ID = os.environ.get("ASSET_SHEET_ID", "YOUR_GOOGLE_SHEET_ID")
OUTPUT_DIR = Path(__file__).resolve().parent.parent / ".claudesec-assets"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

gc = gspread.oauth(
    scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
)

spreadsheet = gc.open_by_key(SHEET_ID)
print(f"시트: '{spreadsheet.title}'\n")

# 모든 시트 상세 읽기
all_data = {}
for ws in spreadsheet.worksheets():
    title = ws.title
    all_values = ws.get_all_values()
    all_data[title] = all_values
    data_rows = len(all_values)
    print(f"[{title}] {data_rows} 행 읽기 완료")

# JSON 저장
output_file = OUTPUT_DIR / "gsheet-asset-raw.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(all_data, f, ensure_ascii=False, indent=2)
print(f"\n전체 데이터 저장: {output_file}")

# 주요 시트별 상세 출력
KEY_SHEETS = ["1.서버", "2.정보보호시스템", "4. DBMS", "8.SaaS", "라이선스_현황"]
for sheet_name in KEY_SHEETS:
    if sheet_name in all_data:
        rows = all_data[sheet_name]
        print(f"\n{'='*60}")
        print(f"[{sheet_name}] 상세 ({len(rows)} 행)")
        print(f"{'='*60}")
        for i, row in enumerate(rows[:8]):
            non_empty = [c for c in row if c.strip()]
            if non_empty:
                print(f"  {i}: {' | '.join(non_empty[:8])}")
