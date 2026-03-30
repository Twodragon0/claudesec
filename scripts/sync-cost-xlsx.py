#!/usr/bin/env python3
"""
ClaudeSec — 대시보드 데이터 동기화 (로컬 Google Drive + Sheets API)

3가지 소스에서 데이터를 수집하여 dashboard-data.json을 생성합니다:
  1. 자산관리대장 (Google Sheets) → SaaS, 라이선스, 인프라, 자산 분류
  2. AI 구독 현황 (Google Sheets) → AI 구독 목록
  3. 소프트웨어_라이선스_현황.xlsx (로컬 파일) → SaaS 비용 분석

사용법:
  python3 scripts/sync-cost-xlsx.py                    # 전체 동기화
  python3 scripts/sync-cost-xlsx.py --cost-only        # 비용 데이터만
  python3 scripts/sync-cost-xlsx.py --sheets-only      # Sheets 데이터만
  python3 scripts/sync-cost-xlsx.py --inject-html      # HTML 대시보드에 데이터 주입

환경변수:
  COST_XLSX_PATH  — xlsx 파일 경로 (기본: Google Drive 동기화 경로)
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

try:
    import openpyxl
except ImportError:
    openpyxl = None

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner" / "lib"))
from csp_utils import generate_nonce, inject_csp_nonce

ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT / ".claudesec-assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

KST = timezone(timedelta(hours=9))
NOW = datetime.now(KST).strftime("%Y-%m-%d %H:%M KST")

# Google Sheets IDs
SHEET_IDS = {
    "자산관리대장": "REDACTED_SHEET_ID",
    "AI구독현황": "REDACTED_SHEET_ID",
}

# 기본 Google Drive 동기화 경로
DEFAULT_XLSX = Path.home() / (
    "Library/CloudStorage/GoogleDrive-REDACTED_EMAIL/"
    "Shared drives/REDACTED_COMPANY/Tech Div/DevSecOps Team/"
    "003. IT ADMIN/소프트웨어_라이선스_현황.xlsx"
)

# 유사 소프트웨어명 통합 매핑
SW_MERGE = {
    "GWS(GoogleWorkSpace)": "Google Workspace",
    "GitHub (Copilot/Actions)": "GitHub",
    "Microsoft Office 365": "Microsoft 365 / Intune",
}


# ═══════════════════════════════════════════════════════════════════════════
# Google Sheets 수집
# ═══════════════════════════════════════════════════════════════════════════

def collect_sheets() -> dict[str, Any]:
    """Google Sheets API로 자산관리대장 + AI구독현황 수집"""
    import gspread

    print("\n[Sheets] Google Sheets 연결...")
    gc = gspread.oauth(
        scopes=[
            "https://www.googleapis.com/auth/spreadsheets.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
        ]
    )

    result: dict[str, Any] = {
        "saas": [],
        "license": [],
        "ai": [],
        "asset_counts": {},
        "infra": {
            "servers": [],
            "databases": [],
            "sec_systems": [],
            "networks": [],
        },
    }

    # ── 자산관리대장 ──
    sp1 = gc.open_by_key(SHEET_IDS["자산관리대장"])
    print(f"  '{sp1.title}' 연결 OK")

    # SaaS 파싱
    ws_saas = sp1.worksheet("8.SaaS")
    raw = ws_saas.get_all_values()
    saas = []
    for row in raw[4:]:
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        auth_val = cells[7] if len(cells) > 7 else ""
        auth_lower = auth_val.lower()
        sso_linked = auth_lower in ("okta", "okta sso", "google")
        saas.append({
            "no": cells[1] if len(cells) > 1 else "",
            "category": cells[2] if len(cells) > 2 else "",
            "name": cells[3] if len(cells) > 3 else "",
            "description": cells[4] if len(cells) > 4 else "",
            "provider": cells[5] if len(cells) > 5 else "",
            "owner": cells[6] if len(cells) > 6 else "",
            "auth": auth_val,
            "sso": sso_linked,
            "contract_period": cells[9] if len(cells) > 9 else "",
            "note": cells[8] if len(cells) > 8 else "",
        })
    result["saas"] = saas
    print(f"    SaaS: {len(saas)}개")

    # 라이선스 현황
    ws_lic = sp1.worksheet("라이선스_현황")
    raw = ws_lic.get_all_values()
    license_list = []
    for row in raw[1:]:
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        license_list.append({
            "name": cells[0] if len(cells) > 0 else "",
            "description": cells[1] if len(cells) > 1 else "",
            "status": cells[2] if len(cells) > 2 else "",
            "admin": cells[3] if len(cells) > 3 else "",
            "department": cells[4] if len(cells) > 4 else "",
            "accounts": cells[5] if len(cells) > 5 else "",
            "active_accounts": cells[6] if len(cells) > 6 else "",
            "users": cells[7] if len(cells) > 7 else "",
            "cycle": cells[8] if len(cells) > 8 else "",
            "cost": cells[9] if len(cells) > 9 else "",
            "contract_period": cells[10] if len(cells) > 10 else "",
        })
    result["license"] = license_list
    print(f"    라이선스: {len(license_list)}개")

    # 자산 분류별 수량
    sheet_map = {
        "1.서버": "서버",
        "2.정보보호시스템": "정보보호시스템",
        "3.네트워크 장비": "네트워크 장비",
        "4. DBMS": "DBMS",
        "5.PC": "PC",
        "6.홈페이지": "홈페이지",
        "7. 개인정보": "개인정보",
        "8.SaaS": "SaaS",
    }
    asset_counts = {}
    for ws_item in sp1.worksheets():
        if ws_item.title in sheet_map:
            vals = ws_item.get_all_values()
            data_rows = len([r for r in vals[8:] if any(c.strip() for c in r)]) if len(vals) > 8 else 0
            asset_counts[sheet_map[ws_item.title]] = data_rows
    asset_counts["라이선스"] = len(license_list)
    result["asset_counts"] = asset_counts
    print(f"    자산 분류: {asset_counts}")

    # 서버 (EC2)
    raw_srv = sp1.worksheet("1.서버").get_all_values()
    servers = []
    for row in raw_srv[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        servers.append({
            "os_type": c[1], "instance_id": c[2], "name": c[3],
            "account": c[4], "os": c[5], "instance_type": c[6],
            "count": c[7], "region": c[8],
        })
    result["infra"]["servers"] = servers
    print(f"    서버 (EC2): {len(servers)}개")

    # DBMS
    raw_db = sp1.worksheet("4. DBMS").get_all_values()
    databases = []
    for row in raw_db[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        databases.append({
            "type": c[1], "name": c[2], "version": c[3],
            "engine": c[4], "count": c[6], "platform": c[7],
            "region": c[8], "account": c[10] if len(c) > 10 else "",
        })
    result["infra"]["databases"] = databases
    print(f"    DBMS: {len(databases)}개")

    # 정보보호시스템
    raw_sec = sp1.worksheet("2.정보보호시스템").get_all_values()
    sec_systems = []
    for row in raw_sec[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        sec_systems.append({
            "category": c[1], "name": c[2], "description": c[3],
            "type": c[4], "provider": c[5], "domain": c[6],
            "owner": c[7], "auth": c[8],
        })
    result["infra"]["sec_systems"] = sec_systems
    print(f"    정보보호시스템: {len(sec_systems)}개")

    # 네트워크 장비
    raw_net = sp1.worksheet("3.네트워크 장비").get_all_values()
    networks = []
    for row in raw_net[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        networks.append({
            "type": c[1], "resource_id": c[2], "name": c[3],
            "description": c[4], "region": c[5],
            "status": c[7], "account": c[9] if len(c) > 9 else "",
        })
    result["infra"]["networks"] = networks
    print(f"    네트워크 장비: {len(networks)}개")

    # ── AI 구독 현황 ──
    sp2 = gc.open_by_key(SHEET_IDS["AI구독현황"])
    print(f"  '{sp2.title}' 연결 OK")
    ws_ai = sp2.worksheets()[0]
    raw_ai = ws_ai.get_all_values()
    ai_list = []
    for row in raw_ai[3:]:
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        ai_list.append({
            "name": cells[0] if len(cells) > 0 else "",
            "description": cells[1] if len(cells) > 1 else "",
            "quantity": cells[2] if len(cells) > 2 else "",
            "department": cells[3] if len(cells) > 3 else "",
        })
    result["ai"] = ai_list
    print(f"    AI 구독: {len(ai_list)}개")

    return result


# ═══════════════════════════════════════════════════════════════════════════
# 비용 xlsx 파싱
# ═══════════════════════════════════════════════════════════════════════════

def parse_cost_xlsx(xlsx_path: Path) -> dict:
    """xlsx 파일에서 saas_cost 데이터 구조를 추출합니다."""
    if not openpyxl:
        print("  openpyxl 미설치, SaaS 비용 스킵")
        return {"summary": [], "details": {}, "by_user": [], "by_department": []}

    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    cost_data: dict[str, Any] = {"summary": [], "details": {}, "by_user": [], "by_department": []}

    # ── 요약 시트 ──
    ws_sum = wb["요약"]
    section = "software"
    month_names = ["", "jan", "feb", "mar", "apr", "may", "jun",
                    "jul", "aug", "sep", "oct", "nov", "dec"]
    for row in ws_sum.iter_rows(min_row=3, values_only=True):
        cells = list(row)
        label = str(cells[0] or "").strip()
        if not label:
            continue
        if label in ("사용자별 요약", "사용자"):
            section = "user"
            continue
        if label in ("부서별 요약", "부서"):
            section = "department"
            continue
        if label in ("합계", "소프트웨어"):
            continue

        vals = {}
        for i in range(1, len(cells) - 1):
            v = cells[i] if isinstance(cells[i], (int, float)) else 0
            if i < len(month_names):
                vals[month_names[i]] = v
        total = cells[len(cells) - 2] if isinstance(cells[len(cells) - 2], (int, float)) else 0
        vals["total"] = total

        if section == "software":
            cost_data["summary"].append({"software": label, **vals})
        elif section == "user":
            cost_data["by_user"].append({"user": label, **vals})
        elif section == "department":
            cost_data["by_department"].append({"department": label, **vals})

    # ── 월별 상세 ──
    for sn in wb.sheetnames:
        if not sn.startswith("20"):
            continue
        ws_m = wb[sn]
        rows_m = []
        for row in ws_m.iter_rows(min_row=5, values_only=True):
            cells = list(row)
            if not cells[0]:
                continue
            sw = str(cells[0]).strip()
            if sw in ("합계",):
                continue
            date_val = cells[5] if len(cells) > 5 else ""
            if hasattr(date_val, "strftime"):
                date_val = date_val.strftime("%Y-%m-%d")
            rows_m.append({
                "software": sw,
                "user": str(cells[1] or ""),
                "shared": str(cells[2] or ""),
                "department": str(cells[3] or ""),
                "amount": cells[4] if isinstance(cells[4], (int, float)) else 0,
                "date": str(date_val or ""),
                "vendor": str(cells[6] or "") if len(cells) > 6 else "",
                "memo": str(cells[7] or "") if len(cells) > 7 else "",
                "status": str(cells[8] or "") if len(cells) > 8 else "",
            })
        cost_data["details"][sn] = rows_m

    # ── 중복/유사 항목 통합 ──
    merged: dict[str, dict] = {}
    for s in cost_data["summary"]:
        name = SW_MERGE.get(s["software"], s["software"])
        if name in merged:
            for k in list(s.keys()):
                if k != "software" and isinstance(s[k], (int, float)):
                    merged[name][k] = merged[name].get(k, 0) + s[k]
        else:
            merged[name] = {**s, "software": name}
    cost_data["summary"] = list(merged.values())

    for month_key in list(cost_data["details"].keys()):
        rows = cost_data["details"][month_key]
        seen: set[tuple] = set()
        deduped = []
        for r in rows:
            r["software"] = SW_MERGE.get(r["software"], r["software"])
            key = (r["software"], r.get("user", ""), r.get("amount", 0))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(r)
        cost_data["details"][month_key] = deduped

    return cost_data


# ═══════════════════════════════════════════════════════════════════════════
# 대시보드 데이터 조합
# ═══════════════════════════════════════════════════════════════════════════

def build_dashboard_data(
    sheets_data: dict[str, Any] | None,
    cost_data: dict[str, Any] | None,
    scan_report: dict | None = None,
) -> dict:
    """dashboard-data.json 구조를 조합합니다."""
    # 기존 데이터 로드
    existing_path = ASSETS_DIR / "dashboard-data.json"
    data: dict[str, Any] = {}
    if existing_path.exists():
        try:
            data = json.loads(existing_path.read_text())
        except (json.JSONDecodeError, KeyError):
            pass

    # 기본 구조 보장
    data.setdefault("generated_at", NOW)
    data.setdefault("timestamps", {})
    data.setdefault("datadog", {"hosts": [], "signals": []})
    data.setdefault("prowler", {})
    data.setdefault("claudesec", {})
    data.setdefault("saas", [])
    data.setdefault("license", [])
    data.setdefault("ai", [])
    data.setdefault("asset_counts", {})
    data.setdefault("saas_cost", {})
    data.setdefault("infra", {})
    data["generated_at"] = NOW

    # Sheets 데이터 머지
    if sheets_data:
        data["saas"] = sheets_data["saas"]
        data["license"] = sheets_data["license"]
        data["ai"] = sheets_data["ai"]
        data["asset_counts"] = sheets_data["asset_counts"]
        data["infra"] = sheets_data["infra"]
        data["timestamps"]["google_sheets"] = NOW

    # 비용 데이터 머지
    if cost_data:
        data["saas_cost"] = cost_data
        data["timestamps"]["saas_cost_xlsx"] = NOW

    # 스캔 리포트 머지
    if scan_report:
        data["claudesec"] = scan_report

    return data


# ═══════════════════════════════════════════════════════════════════════════
# HTML 주입
# ═══════════════════════════════════════════════════════════════════════════

def inject_html(dashboard_data: dict):
    """대시보드 HTML에 데이터를 주입하여 live 파일 생성"""
    tmpl_path = ROOT / "claudesec-asset-dashboard.html"
    html = tmpl_path.read_text()
    json_str = json.dumps(dashboard_data, ensure_ascii=False, default=str)
    html = html.replace("__DASHBOARD_DATA__", json_str)
    nonce = generate_nonce()
    html = inject_csp_nonce(html, nonce)
    out_path = ROOT / "claudesec-asset-dashboard-live.html"
    out_path.write_text(html)
    print(f"▶ HTML 생성: {out_path}")


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="ClaudeSec 대시보드 데이터 동기화")
    parser.add_argument("--xlsx", type=str, default=None, help="xlsx 파일 경로")
    parser.add_argument("--cost-only", action="store_true", help="비용 데이터만 동기화")
    parser.add_argument("--sheets-only", action="store_true", help="Sheets 데이터만 동기화")
    parser.add_argument("--inject-html", action="store_true", help="HTML 대시보드에 데이터 주입")
    args = parser.parse_args()

    print("━━━ ClaudeSec 대시보드 데이터 동기화 ━━━")
    print(f"시각: {NOW}")

    sheets_data = None
    cost_data = None

    # ── Sheets 수집 ──
    if not args.cost_only:
        try:
            sheets_data = collect_sheets()
        except Exception as e:
            print(f"\n[Sheets] 수집 실패: {e}")
            print("  gspread 인증이 필요합니다. 아래 명령어로 인증하세요:")
            print("  python3 -c \"import gspread; gspread.oauth()\"")

    # ── 비용 xlsx 수집 ──
    if not args.sheets_only:
        xlsx_path = Path(args.xlsx) if args.xlsx else Path(os.environ.get("COST_XLSX_PATH", str(DEFAULT_XLSX)))
        if xlsx_path.exists():
            print(f"\n[Cost] 소스: {xlsx_path.name}")
            print(f"  수정일: {datetime.fromtimestamp(xlsx_path.stat().st_mtime, tz=KST).strftime('%Y-%m-%d %H:%M KST')}")
            cost_data = parse_cost_xlsx(xlsx_path)
            total_cost = sum(s.get("total", 0) for s in cost_data.get("summary", []))
            print(f"    소프트웨어: {len(cost_data['summary'])}종")
            print(f"    월별 상세:  {sum(len(v) for v in cost_data['details'].values())}건")
            print(f"    총 비용:    ₩{total_cost:,.0f}")
        else:
            print(f"\n[Cost] 파일 없음: {xlsx_path}")

    # 데이터가 하나도 없으면 종료
    if not sheets_data and not cost_data:
        print("\n수집된 데이터 없음. 종료.")
        sys.exit(1)

    # scan-report.json 로드
    scan_report = None
    scan_path = ROOT / "scan-report.json"
    if scan_path.exists():
        scan_report = json.loads(scan_path.read_text())

    # 대시보드 데이터 조합
    dashboard_data = build_dashboard_data(sheets_data, cost_data, scan_report)

    # JSON 저장
    json_path = ASSETS_DIR / "dashboard-data.json"
    json_path.write_text(json.dumps(dashboard_data, ensure_ascii=False, indent=2, default=str))
    print(f"\n▶ 저장: {json_path}")

    # HTML 주입
    if args.inject_html:
        inject_html(dashboard_data)

    # 요약
    print("\n━━━ 동기화 결과 ━━━")
    if sheets_data:
        print(f"  SaaS:        {len(sheets_data['saas'])}개")
        print(f"  라이선스:     {len(sheets_data['license'])}개")
        print(f"  AI 구독:      {len(sheets_data['ai'])}개")
        print(f"  자산 분류:    {sheets_data['asset_counts']}")
        infra = sheets_data["infra"]
        print(f"  인프라:       서버 {len(infra['servers'])}, DB {len(infra['databases'])}, 보안 {len(infra['sec_systems'])}, 네트워크 {len(infra['networks'])}")
    if cost_data:
        print(f"  SaaS 비용:    {len(cost_data['summary'])}종, ₩{sum(s.get('total', 0) for s in cost_data['summary']):,.0f}")
    print()


if __name__ == "__main__":
    main()
