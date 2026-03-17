#!/usr/bin/env python3
"""
라이선스_현황 시트의 활성계정수(active_accounts) 컬럼을 실제 사용 현황으로 업데이트합니다.

사용법:
  source .venv-asset/bin/activate
  python3 scripts/update-license-active-accounts.py
"""

import gspread

# ── 설정 ──────────────────────────────────────────────────────────────────

SHEET_ID = "1jHuyKEkoAe1jui_mO38nqK2urQqxlNUsEoqnTq1ZsgU"
WORKSHEET_NAME = "라이선스_현황"

# 실제 활성 계정 수 (관리자 콘솔 기준)
KNOWN_ACTIVE_COUNTS = {
    "Okta": 80,
    "Notion": 73,
    "시프티": 75,
    "carta": 75,
    "Cursor": 2,
    "Cursor2": 1,
    "Vercel": 2,
    "Lokalise": 4,
    "Figma-3": 1,
    "quickbook": 1,
    "X(Twitter) 2": 1,
}

# 업데이트하지 않을 항목 (실제로 0이 맞는 경우)
SKIP_NAMES = {
    "Peregrinstudio 1",
    "Peregrinstudio 2",
    "Megista Display Font",
    "systemax",
}


def find_column_index(headers: list[str], target: str) -> int:
    """헤더 행에서 컬럼 인덱스를 찾습니다 (0-based)."""
    for i, h in enumerate(headers):
        if h.strip() == target:
            return i
    raise ValueError(f"컬럼 '{target}'을 헤더에서 찾을 수 없습니다. 헤더: {headers}")


def col_letter(index: int) -> str:
    """0-based 컬럼 인덱스를 A1 표기 문자로 변환합니다."""
    result = ""
    n = index + 1
    while n > 0:
        n, remainder = divmod(n - 1, 26)
        result = chr(65 + remainder) + result
    return result


def main():
    print("Google Sheets 연결 중...")
    gc = gspread.oauth(scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ])

    sp = gc.open_by_key(SHEET_ID)
    print(f"  스프레드시트: '{sp.title}'")

    ws = sp.worksheet(WORKSHEET_NAME)
    print(f"  워크시트: '{ws.title}'")

    all_values = ws.get_all_values()
    if not all_values:
        print("시트가 비어 있습니다.")
        return

    headers = all_values[0]
    print(f"\n헤더: {headers}")

    # 라이선스명 컬럼과 활성계정수 컬럼 인덱스 탐색
    license_col_idx = None
    for candidate in ["프로그램명", "라이선스명", "서비스명", "서비스", "이름", "Name", "name"]:
        try:
            license_col_idx = find_column_index(headers, candidate)
            print(f"  라이선스명 컬럼: '{candidate}' (인덱스 {license_col_idx})")
            break
        except ValueError:
            continue

    if license_col_idx is None:
        # 첫 번째 컬럼을 라이선스명으로 가정
        license_col_idx = 0
        print(f"  라이선스명 컬럼: 첫 번째 컬럼(인덱스 0) '{headers[0]}'로 가정")

    # 실제 헤더에 맞춰 "사용 계정 수" 또는 "활성계정수" 탐색
    active_col_idx = None
    for candidate in ["활성계정수", "사용 계정 수", "활성 계정 수", "active_accounts"]:
        try:
            active_col_idx = find_column_index(headers, candidate)
            print(f"  활성계정수 컬럼: '{candidate}' (인덱스 {active_col_idx})")
            break
        except ValueError:
            continue

    if active_col_idx is None:
        raise ValueError(f"활성계정수 컬럼을 찾을 수 없습니다. 헤더: {headers}")
    active_col_letter = col_letter(active_col_idx)
    print(f"  활성계정수 컬럼 주소: '{active_col_letter}'")

    # 업데이트할 셀 수집
    updates = []
    skipped_not_found = []
    skipped_skip_list = []
    already_correct = []

    data_rows = all_values[1:]  # 헤더 제외

    for row_offset, row in enumerate(data_rows):
        sheet_row = row_offset + 2  # 1-based, 헤더가 1행이므로 데이터는 2행부터

        if license_col_idx >= len(row):
            continue

        license_name = row[license_col_idx].strip()
        if not license_name:
            continue

        if license_name in SKIP_NAMES:
            skipped_skip_list.append(license_name)
            continue

        if license_name not in KNOWN_ACTIVE_COUNTS:
            continue

        target_count = KNOWN_ACTIVE_COUNTS[license_name]
        current_value = row[active_col_idx].strip() if active_col_idx < len(row) else ""

        # 현재값 파싱
        try:
            current_count = int(current_value) if current_value else 0
        except ValueError:
            current_count = None

        if current_count == target_count:
            already_correct.append((license_name, target_count))
            continue

        cell_addr = f"{active_col_letter}{sheet_row}"
        updates.append({
            "range": cell_addr,
            "values": [[target_count]],
            "license": license_name,
            "old": current_value or "(빈칸)",
            "new": target_count,
        })

    # 업데이트되지 않은 KNOWN_ACTIVE_COUNTS 항목 추적
    updated_licenses = {u["license"] for u in updates}
    already_correct_licenses = {a[0] for a in already_correct}
    for name in KNOWN_ACTIVE_COUNTS:
        if name not in updated_licenses and name not in already_correct_licenses:
            skipped_not_found.append(name)

    # 배치 업데이트 실행
    print(f"\n업데이트 대상: {len(updates)}개 셀")

    if updates:
        batch_data = [{"range": u["range"], "values": u["values"]} for u in updates]
        ws.batch_update(batch_data, value_input_option="USER_ENTERED")
        print("\n[업데이트 완료]")
        for u in updates:
            print(f"  {u['license']:25s}  {u['old']:>6}  →  {u['new']}")
    else:
        print("  업데이트할 셀이 없습니다.")

    # 요약
    print("\n── 요약 ──────────────────────────────────────")
    print(f"  업데이트됨      : {len(updates)}개")
    if already_correct:
        print(f"  이미 정확함     : {len(already_correct)}개")
        for name, val in already_correct:
            print(f"    - {name} = {val}")
    if skipped_skip_list:
        print(f"  스킵 (정확한 0) : {len(skipped_skip_list)}개 — {', '.join(skipped_skip_list)}")
    if skipped_not_found:
        print(f"  시트에서 미발견  : {len(skipped_not_found)}개 — {', '.join(skipped_not_found)}")
    print("──────────────────────────────────────────────")


if __name__ == "__main__":
    main()
