#!/usr/bin/env python3
"""
ClaudeSec — 자산관리대장 통합 동기화

Datadog API + Prowler + ClaudeSec 스캔 결과를 수집하고
Google Sheets 자산관리대장에 보안 현황 시트를 추가/업데이트합니다.

사용법:
  source .venv-asset/bin/activate
  python3 scripts/full-asset-sync.py
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

try:
    import gspread
except ImportError:
    print("ERROR: pip install gspread google-auth google-auth-oauthlib")
    sys.exit(1)

# ── 설정 ──────────────────────────────────────────────────────────────────

SHEET_ID = os.environ.get("ASSET_SHEET_ID", "YOUR_GOOGLE_SHEET_ID")
ROOT_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT_DIR / ".claudesec-assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

# .env 파일에서 Datadog 키 로드
def load_env(env_path: str = os.path.expanduser("~/Desktop/.env")) -> dict:
    """key=value 형식 .env 파일 파싱"""
    env = {}
    if not Path(env_path).exists():
        return env
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env

env = load_env()
DD_API_KEY = env.get("datadog_key_credential", "")
DD_APP_KEY = env.get("datadog_app_key_credential", "")
DD_SITE = "datadoghq.com"
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ── Datadog API 호출 ──────────────────────────────────────────────────────

def dd_api_get(path: str, params: str = "") -> dict:
    """Datadog API GET 요청"""
    url = f"https://api.{DD_SITE}{path}"
    if params:
        url += f"?{params}"
    req = urllib.request.Request(url, headers={
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  Datadog API 오류 ({path}): {e}")
        return {}


def dd_api_post(path: str, body: dict) -> dict:
    """Datadog API POST 요청"""
    url = f"https://api.{DD_SITE}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  Datadog API 오류 ({path}): {e}")
        return {}


# ── 데이터 수집 ──────────────────────────────────────────────────────────

def collect_datadog_hosts() -> list:
    """Datadog에서 호스트 목록 수집"""
    print("  Datadog 호스트 수집 중...")
    data = dd_api_get("/api/v1/hosts", "count=200")
    hosts = []
    for h in data.get("host_list", []):
        tags = {}
        for source, tag_list in h.get("tags_by_source", {}).items():
            for t in tag_list:
                if ":" in t:
                    k, v = t.split(":", 1)
                    tags[k] = v

        hosts.append({
            "name": h.get("name", ""),
            "id": h.get("id"),
            "platform": tags.get("cloud_provider", "unknown"),
            "instance_type": tags.get("instance-type", ""),
            "region": tags.get("region", ""),
            "cluster": tags.get("aws_eks_cluster-name", tags.get("eks_eks-cluster-name", "")),
            "nodepool": tags.get("karpenter.sh/nodepool", ""),
            "env": tags.get("env", ""),
            "aws_account": tags.get("aws_account", ""),
            "aws_alias": tags.get("aws_alias", ""),
            "up": h.get("up", False),
            "apps": h.get("apps", []),
            "agent_version": h.get("meta", {}).get("agent_version", ""),
        })
    print(f"    {len(hosts)}개 호스트 수집 완료")
    return hosts


def collect_datadog_security_signals() -> list:
    """Datadog SIEM에서 최근 보안 시그널 수집"""
    print("  Datadog 보안 시그널 수집 중...")
    data = dd_api_post("/api/v2/security_monitoring/signals/search", {
        "filter": {
            "from": "now-7d",
            "to": "now",
            "query": "status:(high OR critical OR medium)",
        },
        "sort": "timestamp",
        "page": {"limit": 50},
    })
    signals = []
    for s in data.get("data", []):
        attrs = s.get("attributes", {})
        signals.append({
            "id": s.get("id", ""),
            "title": attrs.get("message", "")[:200],
            "severity": attrs.get("severity", ""),
            "status": attrs.get("status", ""),
            "timestamp": attrs.get("timestamp", ""),
            "tags": attrs.get("tags", [])[:10],
        })
    print(f"    {len(signals)}건 보안 시그널 수집 완료")
    return signals


def collect_prowler_summary() -> dict:
    """Prowler 결과 요약"""
    print("  Prowler 결과 요약 중...")
    prowler_dir = ROOT_DIR / ".claudesec-prowler"
    if not prowler_dir.exists():
        print("    Prowler 결과 없음")
        return {}

    all_findings = []
    for f in prowler_dir.glob("*.ocsf.json"):
        try:
            with open(f) as fh:
                data = json.load(fh)
                all_findings.extend(data if isinstance(data, list) else [data])
        except (json.JSONDecodeError, IOError):
            pass

    # FAIL만 필터
    failures = [f for f in all_findings if f.get("status_code") == "FAIL"]
    fail_by_sev = {}
    for f in failures:
        sev = f.get("severity", "unknown")
        fail_by_sev[sev] = fail_by_sev.get(sev, 0) + 1

    # 주요 FAIL 항목 (High/Critical)
    critical_fails = []
    for f in failures:
        if f.get("severity") in ("High", "Critical"):
            msg = f.get("message", f.get("status_detail", ""))[:150]
            provider = ""
            unmapped = f.get("unmapped", {})
            if isinstance(unmapped, dict):
                provider = unmapped.get("provider", "")
            critical_fails.append({
                "message": msg,
                "severity": f.get("severity"),
                "provider": provider,
            })

    summary = {
        "total": len(all_findings),
        "pass": len(all_findings) - len(failures),
        "fail": len(failures),
        "fail_by_severity": fail_by_sev,
        "critical_fails_sample": critical_fails[:20],
    }
    print(f"    총 {len(all_findings)}건 (FAIL: {len(failures)}건)")
    return summary


def load_claudesec_scan() -> dict:
    """ClaudeSec 스캔 리포트 로드"""
    report_path = ROOT_DIR / "scan-report.json"
    if not report_path.exists():
        return {}
    with open(report_path) as f:
        return json.load(f)


# ── Google Sheets 동기화 ──────────────────────────────────────────────────

def ensure_sheet(spreadsheet, title: str, headers: list):
    """워크시트가 없으면 생성, 있으면 헤더 검증"""
    try:
        ws = spreadsheet.worksheet(title)
    except gspread.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=title, rows=200, cols=len(headers))
        ws.update([headers], "A1")
        # 헤더 서식
        ws.format(f"A1:{chr(64+len(headers))}1", {
            "textFormat": {"bold": True, "foregroundColorStyle": {"rgbColor": {"red": 1, "green": 1, "blue": 1}}},
            "backgroundColor": {"red": 0.15, "green": 0.25, "blue": 0.45},
        })
        print(f"  새 시트 생성: [{title}]")
    return ws


def sync_to_sheets(spreadsheet, dd_hosts, dd_signals, prowler, scan_report):
    """수집된 데이터를 Google Sheets에 동기화"""

    # ── 1. 보안 대시보드 시트 ──
    headers = ["스캔일시", "ClaudeSec 등급", "ClaudeSec 점수", "Prowler FAIL", "Prowler High",
               "DD 보안시그널(7일)", "DD 호스트 수", "통과", "실패", "경고"]
    ws = ensure_sheet(spreadsheet, "보안 대시보드", headers)

    prowler_high = prowler.get("fail_by_severity", {}).get("High", 0)
    row = [
        NOW,
        scan_report.get("grade", "N/A"),
        scan_report.get("score", 0),
        prowler.get("fail", 0),
        prowler_high,
        len(dd_signals),
        len(dd_hosts),
        scan_report.get("passed", 0),
        scan_report.get("failed", 0),
        scan_report.get("warnings", 0),
    ]
    ws.append_row(row, value_input_option="USER_ENTERED")
    print(f"  [보안 대시보드] 동기화 완료")

    # ── 2. Datadog 인프라 현황 시트 ──
    headers = ["수집일시", "호스트명", "인스턴스 유형", "리전", "EKS 클러스터",
               "노드풀", "환경", "AWS 계정", "Agent 버전", "상태"]
    ws = ensure_sheet(spreadsheet, "DD 인프라 현황", headers)

    # 기존 데이터 삭제 후 다시 쓰기 (최신 스냅샷)
    existing = ws.get_all_values()
    if len(existing) > 1:
        ws.delete_rows(2, len(existing))

    rows = []
    for h in sorted(dd_hosts, key=lambda x: (x["aws_alias"], x["name"])):
        rows.append([
            NOW,
            h["name"][:60],
            h["instance_type"],
            h["region"],
            h["cluster"],
            h["nodepool"],
            h["env"],
            f"{h['aws_alias']} ({h['aws_account']})",
            h["agent_version"],
            "Running" if h["up"] else "Down",
        ])
    if rows:
        ws.append_rows(rows, value_input_option="USER_ENTERED")
    print(f"  [DD 인프라 현황] {len(rows)}개 호스트 동기화 완료")

    # ── 3. 보안 시그널 시트 ──
    if dd_signals:
        headers = ["수집일시", "시그널 ID", "제목", "심각도", "상태", "발생시각", "태그"]
        ws = ensure_sheet(spreadsheet, "DD 보안시그널", headers)

        rows = []
        for s in dd_signals:
            rows.append([
                NOW,
                s["id"][:30],
                s["title"],
                s["severity"],
                s["status"],
                s["timestamp"],
                ", ".join(s["tags"][:5]),
            ])
        ws.append_rows(rows, value_input_option="USER_ENTERED")
        print(f"  [DD 보안시그널] {len(rows)}건 동기화 완료")

    # ── 4. Prowler 주요 취약점 시트 ──
    if prowler.get("critical_fails_sample"):
        headers = ["수집일시", "심각도", "Provider", "메시지"]
        ws = ensure_sheet(spreadsheet, "Prowler 취약점", headers)

        # 기존 데이터 삭제 후 다시 쓰기
        existing = ws.get_all_values()
        if len(existing) > 1:
            ws.delete_rows(2, len(existing))

        rows = []
        for f in prowler["critical_fails_sample"]:
            rows.append([NOW, f["severity"], f["provider"], f["message"]])
        ws.append_rows(rows, value_input_option="USER_ENTERED")
        print(f"  [Prowler 취약점] {len(rows)}건 동기화 완료")

    # ── 5. ClaudeSec 취약점 상세 시트 ──
    findings = scan_report.get("findings", [])
    if findings:
        headers = ["스캔일시", "ID", "제목", "심각도", "카테고리", "상세"]
        ws = ensure_sheet(spreadsheet, "ClaudeSec 취약점", headers)

        # 기존 데이터 삭제 후 다시 쓰기
        existing = ws.get_all_values()
        if len(existing) > 1:
            ws.delete_rows(2, len(existing))

        rows = []
        for f in findings:
            rows.append([
                NOW,
                f.get("id", ""),
                f.get("title", "")[:200],
                f.get("severity", ""),
                f.get("category", ""),
                f.get("details", "")[:300],
            ])
        ws.append_rows(rows, value_input_option="USER_ENTERED")
        print(f"  [ClaudeSec 취약점] {len(rows)}건 동기화 완료")


# ── 메인 ──────────────────────────────────────────────────────────────────

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  ClaudeSec 자산관리대장 통합 동기화")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  시각: {NOW}")
    print()

    # 1. 데이터 수집
    print("▶ 데이터 수집")
    dd_hosts = collect_datadog_hosts() if DD_API_KEY else []
    dd_signals = collect_datadog_security_signals() if DD_API_KEY else []
    prowler = collect_prowler_summary()
    scan_report = load_claudesec_scan()

    if not DD_API_KEY:
        print("  ⚠ Datadog API Key 미설정 (~/Desktop/.env)")

    # 2. 로컬 JSON 저장
    print("\n▶ 로컬 저장")
    summary = {
        "generated_at": NOW,
        "datadog": {
            "hosts_count": len(dd_hosts),
            "security_signals_count": len(dd_signals),
            "hosts": dd_hosts,
            "signals": dd_signals,
        },
        "prowler": prowler,
        "claudesec": scan_report,
    }
    with open(ASSETS_DIR / "full-asset-report.json", "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"  저장: {ASSETS_DIR / 'full-asset-report.json'}")

    # 3. Google Sheets 동기화
    print("\n▶ Google Sheets 동기화")
    gc = gspread.oauth(scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ])
    spreadsheet = gc.open_by_key(SHEET_ID)
    print(f"  시트 연결: '{spreadsheet.title}'")

    sync_to_sheets(spreadsheet, dd_hosts, dd_signals, prowler, scan_report)

    # 4. 결과 요약
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  동기화 완료")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  ClaudeSec: 등급 {scan_report.get('grade', 'N/A')}, 점수 {scan_report.get('score', 'N/A')}")
    print(f"  Datadog: 호스트 {len(dd_hosts)}개, 보안시그널 {len(dd_signals)}건")
    print(f"  Prowler: 총 {prowler.get('total', 0)}건, FAIL {prowler.get('fail', 0)}건")
    print(f"  시트 URL: https://docs.google.com/spreadsheets/d/{SHEET_ID}")
    print()


if __name__ == "__main__":
    main()
