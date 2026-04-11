#!/usr/bin/env python3
"""
ClaudeSec — Google Sheets 자산관리 양방향 연동 스크립트

기능:
  1. Google Sheets에서 자산 목록 읽기 (IT 자산, SaaS 라이선스, 보안 자산)
  2. ClaudeSec 스캔 결과를 시트에 동기화 (보안 점수, 취약점, 컴플라이언스)
  3. Prowler/Datadog 결과를 시트에 추가
  4. 자산 현황 요약 JSON 생성 (대시보드 연동용)

사전 요구 사항:
  pip install gspread google-auth google-auth-oauthlib

인증 방법 (택 1):
  A) 서비스 계정 JSON 파일 경로 (CI/CD, Docker용):
     export GOOGLE_SERVICE_ACCOUNT_JSON=/path/to/<sa-key>.json
  B) 서비스 계정 JSON 문자열 (Docker/K8s 시크릿용):
     export GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT='{"type":"<redacted>",...}'
  C) OAuth2 (로컬 개발용):
     export GOOGLE_OAUTH_CREDENTIALS=/path/to/credentials.json

사용법:
  python3 scripts/asset-gsheet-sync.py --sheet-id <SHEET_ID> --action read
  python3 scripts/asset-gsheet-sync.py --sheet-id <SHEET_ID> --action sync
  python3 scripts/asset-gsheet-sync.py --sheet-id <SHEET_ID> --action report
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import gspread
    from google.oauth2.service_account import Credentials as ServiceCredentials
    from gspread.utils import ValueInputOption
except ImportError:
    print(
        "ERROR: gspread 및 google-auth 패키지가 필요합니다.\n"
        "  pip install gspread google-auth google-auth-oauthlib",
        file=sys.stderr,
    )
    sys.exit(1)


# Google Sheets API 스코프
SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive",
]

# ClaudeSec 결과 파일 경로
SCAN_REPORT = "scan-report.json"
PROWLER_DIR = ".claudesec-prowler"
ASSET_SUMMARY_OUTPUT = ".claudesec-assets/asset-summary.json"

# 시트에 동기화할 ClaudeSec 카테고리 매핑
CATEGORY_MAP = {
    "access-control": "접근 제어",
    "ai": "AI/LLM 보안",
    "cicd": "CI/CD 보안",
    "cloud": "클라우드 보안",
    "code": "코드 보안",
    "infra": "인프라 보안",
    "network": "네트워크 보안",
    "saas": "SaaS 보안",
    "prowler": "Prowler 스캔",
}

HEADER_SCAN_ROWS = 10


def get_google_client() -> gspread.Client:
    """Google Sheets 클라이언트 인증 및 반환"""

    # 방법 1: 서비스 계정 JSON 파일
    sa_path = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
    if sa_path and Path(sa_path).exists():
        creds = ServiceCredentials.from_service_account_file(sa_path, scopes=SCOPES)
        return gspread.authorize(creds)

    # 방법 2: 서비스 계정 JSON 문자열 (Docker 환경용)
    sa_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", "")
    if sa_json:
        import json as _json

        info = _json.loads(sa_json)
        creds = ServiceCredentials.from_service_account_info(info, scopes=SCOPES)
        return gspread.authorize(creds)

    # 방법 3: OAuth2 (로컬 개발용) — 환경변수 필수
    oauth_path = os.environ.get("GOOGLE_OAUTH_CREDENTIALS", "")
    if oauth_path and Path(oauth_path).exists():
        gc = gspread.oauth(credentials_filename=oauth_path, scopes=SCOPES)
        return gc

    print(
        "ERROR: Google 인증 정보를 찾을 수 없습니다.\n"
        "  다음 환경변수 중 하나를 설정하세요:\n"
        "    GOOGLE_SERVICE_ACCOUNT_JSON       — 서비스 계정 JSON 파일 경로\n"
        "    GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT — 서비스 계정 JSON 문자열\n"
        "    GOOGLE_OAUTH_CREDENTIALS           — OAuth2 credentials.json 경로",
        file=sys.stderr,
    )
    sys.exit(1)


def detect_header_row(rows: list[list[str]], scan_rows: int = HEADER_SCAN_ROWS) -> int:
    candidates = []
    for idx, row in enumerate(rows[:scan_rows]):
        normalized = [cell.strip() for cell in row]
        non_empty = [cell for cell in normalized if cell]
        if not non_empty:
            continue

        unique_non_empty = len(set(non_empty))
        duplicate_penalty = len(non_empty) - unique_non_empty
        score = (len(non_empty) * 3) - (duplicate_penalty * 2) - idx
        candidates.append((score, len(non_empty), -idx, idx))

    if not candidates:
        return 0

    return max(candidates)[-1]


def sanitize_headers(headers: list[str]) -> tuple[list[str], list[str], list[str]]:
    safe_headers = []
    warnings = []
    counts: dict[str, int] = {}
    blank_columns = []
    duplicate_names = set()

    for idx, raw_header in enumerate(headers, start=1):
        cleaned = re.sub(r"\s+", " ", raw_header.strip())
        if not cleaned:
            cleaned = f"blank_col_{idx}"
            blank_columns.append(idx)

        counts[cleaned] = counts.get(cleaned, 0) + 1
        if counts[cleaned] > 1:
            duplicate_names.add(cleaned)
            safe_headers.append(f"{cleaned}__dup{counts[cleaned]}")
        else:
            safe_headers.append(cleaned)

    if blank_columns:
        warnings.append(f"blank headers at columns {blank_columns}")
    if duplicate_names:
        names = ", ".join(sorted(duplicate_names))
        warnings.append(f"duplicate headers normalized: {names}")

    return headers, safe_headers, warnings


def parse_worksheet_records(ws: gspread.Worksheet) -> dict[str, Any]:
    all_values = ws.get_all_values()
    if not all_values:
        return {
            "row_count": 0,
            "headers": [],
            "safe_headers": [],
            "data": [],
            "header_row": None,
            "header_warnings": [],
        }

    header_row_index = detect_header_row(all_values)
    raw_headers, safe_headers, warnings = sanitize_headers(all_values[header_row_index])
    width = len(safe_headers)
    records = []

    for row_number, row in enumerate(
        all_values[header_row_index + 1 :], start=header_row_index + 2
    ):
        padded = row + [""] * max(0, width - len(row))
        padded = padded[:width]
        if not any(cell.strip() for cell in padded):
            continue

        record = {safe_headers[idx]: padded[idx] for idx in range(width)}
        record["_row"] = row_number
        records.append(record)

    return {
        "row_count": len(records),
        "headers": raw_headers,
        "safe_headers": safe_headers,
        "data": records,
        "header_row": header_row_index + 1,
        "header_warnings": warnings,
    }


def read_assets(spreadsheet: gspread.Spreadsheet) -> dict[str, Any]:
    """Google Sheets에서 자산 목록 읽기"""

    result: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sheets": {},
        "summary": {},
    }

    for ws in spreadsheet.worksheets():
        title = ws.title
        parsed = parse_worksheet_records(ws)
        result["sheets"][title] = parsed
        if parsed["header_warnings"]:
            joined = "; ".join(parsed["header_warnings"])
            print(f"  읽기 완료: '{title}' ({parsed['row_count']} 행, 경고: {joined})")
        else:
            print(f"  읽기 완료: '{title}' ({parsed['row_count']} 행)")

    # 요약 통계 생성
    total_assets = 0
    for sheet_name, sheet_data in result["sheets"].items():
        count = sheet_data["row_count"]
        total_assets += count
        result["summary"][sheet_name] = count

    result["summary"]["total"] = total_assets
    print(f"\n  총 자산 수: {total_assets}")

    return result


def load_scan_report(scan_dir: str) -> dict[str, Any] | None:
    """ClaudeSec 스캔 리포트 로드"""
    report_path = Path(scan_dir) / SCAN_REPORT
    if not report_path.exists():
        print(f"  경고: 스캔 리포트 없음 ({report_path})", file=sys.stderr)
        return None
    with open(report_path) as f:
        return json.load(f)


def load_prowler_results(scan_dir: str) -> list[dict[str, Any]]:
    """Prowler OCSF 결과 파일 로드"""
    prowler_dir = Path(scan_dir) / PROWLER_DIR
    results: list[dict[str, Any]] = []
    if not prowler_dir.exists():
        return results

    for f in prowler_dir.glob("*.ocsf.json"):
        try:
            with open(f) as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    results.extend(data)
                else:
                    results.append(data)
            print(
                f"  Prowler 결과 로드: {f.name} ({len(data) if isinstance(data, list) else 1} 항목)"
            )
        except (json.JSONDecodeError, IOError) as e:
            print(f"  경고: {f.name} 파싱 실패: {e}", file=sys.stderr)

    return results


def ensure_worksheet(
    spreadsheet: gspread.Spreadsheet, title: str, headers: list[str]
) -> gspread.Worksheet:
    """워크시트 확인 또는 생성"""
    try:
        ws = spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=100, cols=len(headers))
        ws.update(range_name="A1", values=[headers])
        ws.format(
            "A1:Z1",
            {
                "textFormat": {"bold": True},
                "backgroundColor": {"red": 0.2, "green": 0.3, "blue": 0.5},
            },
        )
        print(f"  새 시트 생성: '{title}'")
    return ws


def sync_scan_results(spreadsheet: gspread.Spreadsheet, scan_dir: str) -> None:
    """ClaudeSec 스캔 결과를 Google Sheets에 동기화"""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 1. 보안 스캔 결과 시트
    report = load_scan_report(scan_dir)
    if report:
        headers = ["스캔일시", "등급", "점수", "통과", "실패", "경고", "스킵", "총검사"]
        ws = ensure_worksheet(spreadsheet, "ClaudeSec 스캔결과", headers)

        row = [
            now,
            report.get("grade", "N/A"),
            report.get("score", 0),
            report.get("passed", 0),
            report.get("failed", 0),
            report.get("warnings", 0),
            report.get("skipped", 0),
            report.get("total", 0),
        ]
        ws.append_row(row, value_input_option=ValueInputOption.user_entered)
        print(
            f"  스캔 결과 동기화 완료: 등급 {report.get('grade')}, 점수 {report.get('score')}"
        )

    # 2. 취약점 상세 시트
    if report and report.get("findings"):
        headers = ["스캔일시", "ID", "제목", "심각도", "카테고리", "상세"]
        ws = ensure_worksheet(spreadsheet, "ClaudeSec 취약점", headers)

        rows = []
        for f in report["findings"]:
            rows.append(
                [
                    now,
                    f.get("id", ""),
                    f.get("title", "")[:200],  # 시트 셀 길이 제한
                    f.get("severity", ""),
                    CATEGORY_MAP.get(f.get("category", ""), f.get("category", "")),
                    f.get("details", "")[:300],
                ]
            )

        if rows:
            ws.append_rows(rows, value_input_option=ValueInputOption.user_entered)
            print(f"  취약점 {len(rows)}건 동기화 완료")

    # 3. Prowler 결과 시트
    prowler_results = load_prowler_results(scan_dir)
    if prowler_results:
        headers = [
            "스캔일시",
            "Provider",
            "심각도",
            "상태",
            "리소스",
            "메시지",
            "컴플라이언스",
        ]
        ws = ensure_worksheet(spreadsheet, "Prowler 스캔결과", headers)

        rows = []
        for item in prowler_results:
            # OCSF 형식 파싱
            severity = item.get("severity", "")
            status = item.get("status_code", item.get("status", ""))
            message = item.get("message", item.get("status_detail", ""))[:300]

            # Provider 정보
            provider = ""
            unmapped = item.get("unmapped", {})
            if isinstance(unmapped, dict):
                provider = unmapped.get("provider", "")

            # 컴플라이언스 매핑
            compliance_info = ""
            if isinstance(unmapped, dict) and "compliance" in unmapped:
                comp = unmapped["compliance"]
                compliance_info = ", ".join(
                    f"{k}: {','.join(v)}" for k, v in comp.items()
                )

            # 리소스 정보
            resource = ""
            resources = item.get("resources", [])
            if resources and isinstance(resources, list):
                res = resources[0]
                if isinstance(res, dict):
                    resource = res.get("uid", res.get("name", ""))

            rows.append(
                [
                    now,
                    provider,
                    severity,
                    status,
                    resource[:200],
                    message,
                    compliance_info[:300],
                ]
            )

        if rows:
            # 최대 500행 제한 (시트 과부하 방지)
            ws.append_rows(rows[:500], value_input_option=ValueInputOption.user_entered)
            print(f"  Prowler 결과 {min(len(rows), 500)}건 동기화 완료")


def generate_asset_report(
    spreadsheet: gspread.Spreadsheet, scan_dir: str
) -> dict[str, Any]:
    """자산 현황 요약 JSON 생성 (ClaudeSec 대시보드 연동용)"""

    assets = read_assets(spreadsheet)
    report = load_scan_report(scan_dir)
    prowler_results = load_prowler_results(scan_dir)

    # 통합 리포트
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "google_sheet_id": spreadsheet.id,
        "google_sheet_title": spreadsheet.title,
        "asset_summary": assets.get("summary", {}),
        "sheets": list(assets.get("sheets", {}).keys()),
        "security": {},
        "prowler": {},
    }

    # 보안 스캔 요약
    if report:
        summary["security"] = {
            "grade": report.get("grade", "N/A"),
            "score": report.get("score", 0),
            "passed": report.get("passed", 0),
            "failed": report.get("failed", 0),
            "warnings": report.get("warnings", 0),
            "findings_count": len(report.get("findings", [])),
        }

    # Prowler 요약
    if prowler_results:
        severity_counts = {}
        status_counts = {}
        for item in prowler_results:
            sev = item.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            st = item.get("status_code", "unknown")
            status_counts[st] = status_counts.get(st, 0) + 1

        summary["prowler"] = {
            "total_findings": len(prowler_results),
            "by_severity": severity_counts,
            "by_status": status_counts,
        }

    # JSON 파일 출력
    output_path = Path(scan_dir) / ASSET_SUMMARY_OUTPUT
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n  자산 요약 리포트 생성: {output_path}")
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="ClaudeSec — Google Sheets 자산관리 연동",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 자산 목록 읽기
  python3 scripts/asset-gsheet-sync.py --sheet-id YOUR_SHEET_ID --action read

  # ClaudeSec 스캔 결과 동기화
  python3 scripts/asset-gsheet-sync.py --sheet-id YOUR_SHEET_ID --action sync

  # 통합 리포트 생성
  python3 scripts/asset-gsheet-sync.py --sheet-id YOUR_SHEET_ID --action report

  # Docker 환경에서 실행 (파일 마운트)
  docker run --rm -v $PWD:/workspace \\
    -e GOOGLE_SERVICE_ACCOUNT_JSON=/workspace/sa.json \\
    claudesec:local python3 /opt/claudesec/scripts/asset-gsheet-sync.py --sheet-id ... --action sync

  # Docker 환경에서 실행 (JSON 문자열 — 파일 마운트 불필요)
  docker run --rm \\
    -e GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT="$(cat sa.json)" \\
    claudesec:local python3 /opt/claudesec/scripts/asset-gsheet-sync.py --sheet-id ... --action sync
        """,
    )
    parser.add_argument(
        "--sheet-id",
        required=True,
        help="Google Sheets ID (URL의 /d/ 뒤 부분)",
    )
    parser.add_argument(
        "--action",
        choices=["read", "sync", "report"],
        default="report",
        help="실행할 작업: read(읽기), sync(동기화), report(통합 리포트)",
    )
    parser.add_argument(
        "--scan-dir",
        default=".",
        help="ClaudeSec 스캔 결과 디렉토리 (기본: 현재 디렉토리)",
    )

    args = parser.parse_args()

    print(f"ClaudeSec 자산관리 연동 v1.0")
    print(f"  시트 ID: {args.sheet_id}")
    print(f"  작업: {args.action}")
    print(f"  스캔 디렉토리: {args.scan_dir}")
    print()

    # Google Sheets 연결
    gc = get_google_client()
    spreadsheet = gc.open_by_key(args.sheet_id)
    print(f"  시트 연결 완료: '{spreadsheet.title}'")
    print()

    if args.action == "read":
        result = read_assets(spreadsheet)
        # 시트별 구조 출력
        print("\n--- 시트 구조 ---")
        for name, data in result["sheets"].items():
            print(f"\n[{name}] ({data['row_count']} 행)")
            if data["headers"]:
                print(f"  컬럼: {', '.join(data['headers'])}")

    elif args.action == "sync":
        sync_scan_results(spreadsheet, args.scan_dir)

    elif args.action == "report":
        summary = generate_asset_report(spreadsheet, args.scan_dir)
        print("\n--- 통합 요약 ---")
        print(json.dumps(summary, indent=2, ensure_ascii=False))

    print("\n완료.")


if __name__ == "__main__":
    main()
