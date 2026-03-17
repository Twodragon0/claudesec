#!/usr/bin/env python3
"""
ClaudeSec — 통합 대시보드 빌드

Google Sheets 3개 + Datadog + Prowler + ClaudeSec 스캔 결과를
수집하여 대시보드 HTML에 데이터를 주입합니다.

사용법:
  source .venv-asset/bin/activate
  python3 scripts/build-dashboard.py
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import gspread

try:
    import openpyxl
except ImportError:
    openpyxl = None

# ── 설정 ──────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = ROOT / ".claudesec-assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

SHEETS = {
    "자산관리대장": "REDACTED_SHEET_ID",
    "AI구독현황": "REDACTED_SHEET_ID",
}

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

# .env 로드
def load_env():
    env = {}
    p = Path(os.path.expanduser("~/Desktop/.env"))
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env

env_vars = load_env()
DD_API_KEY = env_vars.get("datadog_key_credential", "")
DD_APP_KEY = env_vars.get("datadog_app_key_credential", "")


# ── Datadog API ───────────────────────────────────────────────────────────

def dd_get(path, params=""):
    url = f"https://api.datadoghq.com{path}"
    if params:
        url += f"?{params}"
    req = urllib.request.Request(url, headers={
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  DD API 오류 ({path}): {e}")
        return {}

def dd_post(path, body):
    url = f"https://api.datadoghq.com{path}"
    req = urllib.request.Request(url, json.dumps(body).encode(), method="POST", headers={
        "DD-API-KEY": DD_API_KEY,
        "DD-APPLICATION-KEY": DD_APP_KEY,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        print(f"  DD API 오류 ({path}): {e}")
        return {}


# ── 수집 함수들 ──────────────────────────────────────────────────────────

def collect_datadog():
    """Datadog 호스트 + 보안 시그널 수집"""
    if not DD_API_KEY:
        print("  Datadog API Key 없음, 스킵")
        return [], []

    print("  Datadog 호스트...")
    raw = dd_get("/api/v1/hosts", "count=200")
    hosts = []
    for h in raw.get("host_list", []):
        tags = {}
        for src, tlist in h.get("tags_by_source", {}).items():
            for t in tlist:
                if ":" in t:
                    k, v = t.split(":", 1)
                    tags[k] = v
        hosts.append({
            "name": h.get("name", ""),
            "instance_type": tags.get("instance-type", ""),
            "region": tags.get("region", ""),
            "cluster": tags.get("aws_eks_cluster-name", tags.get("eks_eks-cluster-name", "")),
            "nodepool": tags.get("karpenter.sh/nodepool", ""),
            "env": tags.get("env", ""),
            "aws_alias": tags.get("aws_alias", ""),
            "aws_account": tags.get("aws_account", ""),
            "up": h.get("up", False),
            "agent_version": h.get("meta", {}).get("agent_version", ""),
        })
    print(f"    {len(hosts)}개")

    print("  Datadog 보안 시그널 (14일)...")
    raw = dd_post("/api/v2/security_monitoring/signals/search", {
        "filter": {"from": "now-14d", "to": "now", "query": "status:(high OR critical OR medium)"},
        "sort": "timestamp", "page": {"limit": 100},
    })
    signals = []
    for s in raw.get("data", []):
        a = s.get("attributes", {})
        signals.append({
            "id": s.get("id", "")[:30],
            "title": a.get("message", "")[:200],
            "severity": a.get("severity", ""),
            "status": a.get("status", ""),
            "timestamp": a.get("timestamp", ""),
            "tags": a.get("tags", [])[:5],
        })
    print(f"    {len(signals)}건")
    return hosts, signals


def collect_prowler():
    """Prowler 결과 요약"""
    print("  Prowler...")
    pdir = ROOT / ".claudesec-prowler"
    if not pdir.exists():
        return {}
    findings = []
    for f in pdir.glob("*.ocsf.json"):
        try:
            data = json.loads(f.read_text())
            findings.extend(data if isinstance(data, list) else [data])
        except Exception:
            pass

    failures = [f for f in findings if f.get("status_code") == "FAIL"]
    fail_sev = {}
    for f in failures:
        s = f.get("severity", "unknown")
        fail_sev[s] = fail_sev.get(s, 0) + 1

    samples = []
    for f in failures:
        if f.get("severity") in ("High", "Critical"):
            um = f.get("unmapped", {})
            samples.append({
                "message": f.get("message", f.get("status_detail", ""))[:150],
                "severity": f.get("severity"),
                "provider": um.get("provider", "") if isinstance(um, dict) else "",
            })

    # Group by provider
    by_provider = {}
    for f in failures:
        um = f.get("unmapped", {})
        prov = (um.get("provider", "") if isinstance(um, dict) else "").lower() or "unknown"
        if prov not in by_provider:
            by_provider[prov] = {"total": 0, "fail": 0, "pass": 0, "critical_fails": []}
        by_provider[prov]["fail"] += 1

    # Also count passes per provider
    for f in findings:
        um = f.get("unmapped", {})
        prov = (um.get("provider", "") if isinstance(um, dict) else "").lower() or "unknown"
        if prov not in by_provider:
            by_provider[prov] = {"total": 0, "fail": 0, "pass": 0, "critical_fails": []}
        by_provider[prov]["total"] += 1
        if f.get("status_code") != "FAIL":
            by_provider[prov]["pass"] += 1

    # Add critical fails samples per provider
    for f in failures:
        if f.get("severity") in ("High", "Critical"):
            um = f.get("unmapped", {})
            prov = (um.get("provider", "") if isinstance(um, dict) else "").lower() or "unknown"
            if prov in by_provider and len(by_provider[prov]["critical_fails"]) < 10:
                by_provider[prov]["critical_fails"].append({
                    "message": f.get("message", f.get("status_detail", ""))[:150],
                    "severity": f.get("severity"),
                    "check": f.get("finding_info", {}).get("uid", "")[:60] if isinstance(f.get("finding_info"), dict) else "",
                })

    # Medium severity samples
    medium_samples = []
    for f in failures:
        if f.get("severity") == "Medium" and len(medium_samples) < 20:
            um = f.get("unmapped", {})
            medium_samples.append({
                "message": f.get("message", f.get("status_detail", ""))[:150],
                "severity": "Medium",
                "provider": um.get("provider", "") if isinstance(um, dict) else "",
            })

    result = {
        "total": len(findings),
        "pass": len(findings) - len(failures),
        "fail": len(failures),
        "fail_by_severity": fail_sev,
        "critical_fails_sample": samples[:30],
        "medium_fails_sample": medium_samples,
        "by_provider": by_provider,
    }
    print(f"    총 {len(findings)}건 (FAIL: {len(failures)})")
    return result


def collect_notion_audits():
    """Collect security audit records from Notion API, fallback to cache."""
    cache_path = ASSETS_DIR / "notion-security-audits.json"

    notion_key = env_vars.get("NOTION_API_KEY", "") or os.environ.get("NOTION_API_KEY", "")
    if notion_key:
        print("  Notion API로 정기점검 이력 수집...")
        try:
            # Search for 정기점검 pages
            req = urllib.request.Request(
                "https://api.notion.com/v1/search",
                json.dumps({
                    "query": "보안로그 정기점검",
                    "filter": {"property": "object", "value": "page"},
                    "sort": {"direction": "descending", "timestamp": "last_edited_time"},
                    "page_size": 20,
                }).encode(),
                method="POST",
                headers={
                    "Authorization": f"Bearer {notion_key}",
                    "Content-Type": "application/json",
                    "Notion-Version": "2022-06-28",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())

            audits = []
            for page in data.get("results", []):
                props = page.get("properties", {})
                title_parts = props.get("title", props.get("작업 이름", {}))
                title = ""
                if isinstance(title_parts, dict):
                    for t in title_parts.get("title", []):
                        title += t.get("plain_text", "")

                if "정기점검" not in title:
                    continue

                page_id = page.get("id", "")
                created = page.get("created_time", "")[:10]
                last_edited = page.get("last_edited_time", "")[:10]
                url = page.get("url", f"https://www.notion.so/{page_id.replace('-', '')}")

                audits.append({
                    "date": last_edited or created,
                    "title": title,
                    "status": "완료",
                    "priority": "",
                    "impact": "",
                    "tags": [],
                    "summary": "",
                    "url": url,
                    "task_id": page_id[:8],
                })

            if audits:
                # Merge with cache to preserve impact/summary/tags
                cached = []
                if cache_path.exists():
                    try:
                        cached = json.loads(cache_path.read_text())
                    except Exception:
                        pass

                cache_map = {c.get("url", ""): c for c in cached}
                for a in audits:
                    cached_entry = cache_map.get(a["url"], {})
                    if not a["impact"] and cached_entry.get("impact"):
                        a["impact"] = cached_entry["impact"]
                    if not a["summary"] and cached_entry.get("summary"):
                        a["summary"] = cached_entry["summary"]
                    if not a["tags"] and cached_entry.get("tags"):
                        a["tags"] = cached_entry["tags"]
                    if not a["priority"] and cached_entry.get("priority"):
                        a["priority"] = cached_entry["priority"]

                # Update cache
                cache_path.write_text(json.dumps(audits, ensure_ascii=False, indent=2))
                print(f"    Notion API: {len(audits)}건 (캐시 업데이트)")
                return audits
        except Exception as e:
            print(f"    Notion API 실패: {e}, 캐시 사용")

    # Fallback to cache
    if cache_path.exists():
        try:
            audits = json.loads(cache_path.read_text())
            print(f"    Notion 정기점검: {len(audits)}건 (캐시)")
            return audits
        except Exception:
            pass
    return []


def collect_jamf_pcs():
    """Collect Jamf Pro managed PC data from Datadog logs API."""
    if not DD_API_KEY:
        print("  Jamf PC: Datadog API Key 없음, 스킵")
        return []

    print("  Jamf Pro PC 데이터...")
    # Search Datadog logs for Jamf ComputerPolicyFinished events (webhook)
    raw = dd_post("/api/v2/logs/events/search", {
        "filter": {
            "from": "now-7d",
            "to": "now",
            "query": "source:jamf*",
        },
        "sort": "-timestamp",
        "page": {"limit": 200},
    })

    pcs = []
    seen = set()
    for log in raw.get("data", []):
        attrs = log.get("attributes", {}).get("attributes", {})
        # Jamf webhook structure: event.computer contains device info
        computer = attrs.get("event", {}).get("computer", {})
        if not isinstance(computer, dict):
            computer = attrs  # fallback to flat structure
        if not isinstance(computer, dict):
            continue
        hostname = computer.get("deviceName", computer.get("computer_name", attrs.get("hostname", "")))
        serial = computer.get("serialNumber", computer.get("serial_number", ""))
        key = serial or hostname
        if not key or key in seen:
            continue
        seen.add(key)
        ts = log.get("attributes", {}).get("timestamp", "")
        # Parse user from deviceName pattern "Lv-i <username> <serial>"
        raw_user = computer.get("realName", "") or attrs.get("usr", {}).get("name", "")
        if not raw_user and hostname:
            parts = hostname.split()
            if len(parts) >= 2 and parts[0].lower().startswith("lv"):
                raw_user = parts[1]
        pcs.append({
            "name": hostname,
            "serial": serial,
            "os": computer.get("osVersion", computer.get("os_version", "")),
            "model": computer.get("model", ""),
            "user": raw_user,
            "department": computer.get("department", ""),
            "managed": True,
            "last_checkin": (ts[:19] if ts else ""),
            "source": "jamf",
        })

    # Try full inventory file (from Jamf Pro CSV export)
    inventory_path = ASSETS_DIR / "jamf-full-inventory.json"
    if not pcs and inventory_path.exists():
        try:
            inv = json.loads(inventory_path.read_text())
            pcs = [item for item in inv if item.get("type") == "computer"]
            print(f"    Jamf PC: {len(pcs)}대 (CSV 인벤토리)")
            return pcs
        except Exception:
            pass

    # If no Datadog logs, try loading from cache
    cache_path = ASSETS_DIR / "jamf-computers.json"
    if not pcs and cache_path.exists():
        try:
            pcs = json.loads(cache_path.read_text())
            print(f"    Jamf PC: {len(pcs)}대 (캐시)")
            return pcs
        except Exception:
            pass

    if pcs:
        cache_path.write_text(json.dumps(pcs, ensure_ascii=False, indent=2))

    print(f"    Jamf PC: {len(pcs)}대")
    return pcs


def collect_intune_pcs():
    """Collect Intune managed PC data from cache/CSV."""
    cache_path = ASSETS_DIR / "intune-computers.json"
    if cache_path.exists():
        try:
            pcs = json.loads(cache_path.read_text())
            print(f"  Intune PC: {len(pcs)}대")
            return pcs
        except Exception:
            pass
    print("  Intune PC: 데이터 없음")
    return []


def collect_sheets():
    """Google Sheets 데이터 수집"""
    print("  Google Sheets 연결...")
    gc = gspread.oauth(scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ])

    # 자산관리대장
    sp1 = gc.open_by_key(SHEETS["자산관리대장"])
    print(f"    '{sp1.title}' 연결")

    # SaaS 파싱 — col[1]=No, col[2]=구분, col[3]=자산명, col[4]=설명,
    #   col[5]=제공사, col[6]=관리주체, col[7]=접근관리방식, col[8]=비고
    ws_saas = sp1.worksheet("8.SaaS")
    raw = ws_saas.get_all_values()
    saas = []
    for row in raw[4:]:  # 데이터는 4번째 행부터 (index 4)
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
    print(f"    SaaS: {len(saas)}개")

    # 라이선스 현황 파싱 (row 0 = 헤더, row 1+ = 데이터)
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
    print(f"    라이선스: {len(license_list)}개")

    # 자산 분류별 수량
    asset_counts = {}
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
    for ws_item in sp1.worksheets():
        if ws_item.title in sheet_map:
            vals = ws_item.get_all_values()
            data_rows = len([r for r in vals[8:] if any(c.strip() for c in r)]) if len(vals) > 8 else 0
            asset_counts[sheet_map[ws_item.title]] = data_rows
    asset_counts["라이선스"] = len(license_list)
    print(f"    자산 분류: {asset_counts}")

    # ── 인프라 상세 파싱 ──
    # 서버 (EC2) — row 7=헤더(col1:구분,col2:자산코드,...), row 8+=데이터
    raw_srv = sp1.worksheet("1.서버").get_all_values()
    servers = []
    for row in raw_srv[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        servers.append({"os_type": c[1], "instance_id": c[2], "name": c[3],
                        "account": c[4], "os": c[5], "instance_type": c[6],
                        "count": c[7], "region": c[8]})
    print(f"    서버 (EC2): {len(servers)}개")

    # DBMS — row 7=헤더, row 8+=데이터
    raw_db = sp1.worksheet("4. DBMS").get_all_values()
    databases = []
    for row in raw_db[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        databases.append({"type": c[1], "name": c[2], "version": c[3],
                          "engine": c[4], "count": c[6], "platform": c[7],
                          "region": c[8], "account": c[10] if len(c) > 10 else ""})
    print(f"    DBMS: {len(databases)}개")

    # 정보보호시스템 — row 7=헤더, row 8+=데이터
    raw_sec = sp1.worksheet("2.정보보호시스템").get_all_values()
    sec_systems = []
    for row in raw_sec[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        sec_systems.append({"category": c[1], "name": c[2], "description": c[3],
                            "type": c[4], "provider": c[5], "domain": c[6],
                            "owner": c[7], "auth": c[8]})
    print(f"    정보보호시스템: {len(sec_systems)}개")

    # 네트워크 장비 — row 7=헤더, row 8+=데이터
    raw_net = sp1.worksheet("3.네트워크 장비").get_all_values()
    networks = []
    for row in raw_net[8:]:
        c = [x.strip() for x in row]
        if not c[1] and not c[2]:
            continue
        networks.append({"type": c[1], "resource_id": c[2], "name": c[3],
                         "description": c[4], "region": c[5], "status": c[7],
                         "account": c[9] if len(c) > 9 else ""})
    print(f"    네트워크 장비: {len(networks)}개")

    # AI 구독 현황
    sp2 = gc.open_by_key(SHEETS["AI구독현황"])
    print(f"    '{sp2.title}' 연결")
    ws_ai = sp2.worksheets()[0]
    raw_ai = ws_ai.get_all_values()
    ai_list = []
    for row in raw_ai[3:]:  # 데이터는 3번째 행부터
        cells = [c.strip() for c in row]
        if not any(cells):
            continue
        ai_list.append({
            "name": cells[0] if len(cells) > 0 else "",
            "description": cells[1] if len(cells) > 1 else "",
            "quantity": cells[2] if len(cells) > 2 else "",
            "department": cells[3] if len(cells) > 3 else "",
        })
    print(f"    AI 구독: {len(ai_list)}개")

    # SaaS 비용 (.xlsx via Drive API download)
    cost_data = {"summary": [], "details": {}}
    xlsx_id = "REDACTED_SHEET_ID"
    if openpyxl:
        try:
            print("  SaaS 비용 시트 다운로드 중...")
            resp = gc.http_client.request(
                "get",
                f"https://www.googleapis.com/drive/v3/files/{xlsx_id}?alt=media&supportsAllDrives=true",
            )
            tmp_path = Path("/tmp/claudesec-cost.xlsx")
            tmp_path.write_bytes(resp.content)

            wb = openpyxl.load_workbook(tmp_path, data_only=True)

            # 요약 시트 — 3개 섹션 분리 (소프트웨어별/사용자별/부서별)
            ws_sum = wb["요약"]
            section = "software"
            cost_data["by_user"] = []
            cost_data["by_department"] = []
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
                vals = {
                    "jan": cells[1] if isinstance(cells[1], (int, float)) else 0,
                    "feb": cells[2] if isinstance(cells[2], (int, float)) else 0,
                    "mar": cells[3] if isinstance(cells[3], (int, float)) else 0,
                    "total": cells[4] if isinstance(cells[4], (int, float)) else 0,
                }
                if section == "software":
                    cost_data["summary"].append({"software": label, **vals})
                elif section == "user":
                    cost_data["by_user"].append({"user": label, **vals})
                elif section == "department":
                    cost_data["by_department"].append({"department": label, **vals})

            # 월별 상세
            for month_name in ["2026-01", "2026-02", "2026-03"]:
                if month_name not in wb.sheetnames:
                    continue
                ws_m = wb[month_name]
                rows_m = []
                for row in ws_m.iter_rows(min_row=5, values_only=True):
                    cells = list(row)
                    if not cells[0]:
                        continue
                    # 합계 행 스킵
                    sw = str(cells[0]).strip()
                    if sw in ("합계",):
                        continue
                    rows_m.append({
                        "software": sw,
                        "user": str(cells[1] or ""),
                        "shared": str(cells[2] or ""),
                        "department": str(cells[3] or ""),
                        "amount": cells[4] if isinstance(cells[4], (int, float)) else 0,
                        "date": str(cells[5] or ""),
                        "vendor": str(cells[6] or ""),
                        "memo": str(cells[7] or ""),
                    })
                cost_data["details"][month_name] = rows_m

            # ── 중복/유사 항목 통합 정리 ──
            # 1) summary: 유사 소프트웨어명 통합
            SW_MERGE = {
                "GWS(GoogleWorkSpace)": "Google Workspace",
                "GitHub (Copilot/Actions)": "GitHub",
                "Microsoft Office 365": "Microsoft 365 / Intune",
            }
            merged_summary = {}
            for s in cost_data["summary"]:
                name = SW_MERGE.get(s["software"], s["software"])
                if name in merged_summary:
                    for k in ("jan", "feb", "mar", "total"):
                        merged_summary[name][k] = merged_summary[name].get(k, 0) + s.get(k, 0)
                else:
                    merged_summary[name] = {**s, "software": name}
            cost_data["summary"] = list(merged_summary.values())

            # 2) details: 동일 월+소프트웨어+사용자+금액 완전 중복 제거
            for month_key in list(cost_data["details"].keys()):
                rows = cost_data["details"][month_key]
                seen = set()
                deduped = []
                for r in rows:
                    # 소프트웨어명 통합
                    r["software"] = SW_MERGE.get(r["software"], r["software"])
                    key = (r["software"], r.get("user", ""), r.get("amount", 0))
                    if key in seen:
                        continue
                    seen.add(key)
                    deduped.append(r)
                cost_data["details"][month_key] = deduped

            # 3) Warudo는 대리 결제 — 메모에 명시
            for month_key, rows in cost_data["details"].items():
                for r in rows:
                    if r["software"] == "Warudo (싸이코드)" and r.get("user") == "mauve":
                        r["memo"] = (r.get("memo", "") + " (대리결제 — 싸이코드 프로젝트 비용)").strip()
                        r["department"] = "프로젝트 | 싸이코드 (대리결제)"

            print(f"    SaaS 비용: {len(cost_data['summary'])}종, 월별 상세 {sum(len(v) for v in cost_data['details'].values())}건 (중복 정리 완료)")
        except Exception as e:
            print(f"    SaaS 비용 수집 실패: {e}")
    else:
        print("  openpyxl 미설치, SaaS 비용 스킵")

    infra = {"servers": servers, "databases": databases,
             "sec_systems": sec_systems, "networks": networks}

    # SentinelOne 에이전트 + 위협 + 교차 검증 (캐시)
    s1_path = ASSETS_DIR / "sentinelone-agents.json"
    s1_agents = []
    if s1_path.exists():
        s1_agents = json.loads(s1_path.read_text())
        print(f"    SentinelOne: {len(s1_agents)}대")

    s1_threats_path = ASSETS_DIR / "sentinelone-threats.json"
    s1_threats = json.loads(s1_threats_path.read_text()) if s1_threats_path.exists() else []

    ep_xv_path = ASSETS_DIR / "endpoint-crossverify.json"
    ep_crossverify = json.loads(ep_xv_path.read_text()) if ep_xv_path.exists() else {}

    return saas, license_list, ai_list, asset_counts, cost_data, infra, s1_agents, s1_threats, ep_crossverify


def _is_karpenter_node(name: str) -> bool:
    """Karpenter 동적 노드 여부 판별 (ip-10-* 패턴)"""
    import re
    if not name:
        return False
    return bool(re.match(r"ip-10-\d+-\d+-\d+\.", name))


def _cross_verify_ec2(aws_ec2: list, sheet_servers: list) -> dict:
    """AWS EC2 실시간 vs 자산관리대장 서버 교차 검증 (Karpenter 노드 분리)"""
    # Karpenter 노드와 고정 서버 분리
    aws_static = {}  # 고정 서버 (querypie, zpa-connector 등)
    aws_karpenter = []  # Karpenter 동적 노드
    for e in aws_ec2:
        iid = e.get("InstanceId", "")
        name = e.get("Name", "")
        if not iid:
            continue
        if _is_karpenter_node(name):
            aws_karpenter.append({
                "id": iid, "name": name,
                "type": e.get("Type", ""), "profile": e.get("_profile", ""),
            })
        else:
            aws_static[iid] = e

    # 시트에서도 Karpenter/고정 분리
    sheet_static = {}
    sheet_karpenter = []
    for s in sheet_servers:
        iid = s.get("instance_id", "")
        name = s.get("name", "")
        if not iid:
            continue
        if _is_karpenter_node(name):
            sheet_karpenter.append({
                "id": iid, "name": name,
                "type": s.get("instance_type", ""), "account": s.get("account", ""),
            })
        else:
            sheet_static[iid] = s

    # 고정 서버 교차 검증
    aws_only = []
    for iid, e in aws_static.items():
        if iid not in sheet_static:
            aws_only.append({
                "id": iid, "name": e.get("Name", ""),
                "type": e.get("Type", ""), "profile": e.get("_profile", ""),
                "status": "미등록",
            })

    sheet_only = []
    for iid, s in sheet_static.items():
        if iid not in aws_static:
            sheet_only.append({
                "id": iid, "name": s.get("name", ""),
                "type": s.get("instance_type", ""), "account": s.get("account", ""),
                "status": "종료/교체",
            })

    matched = len(set(aws_static) & set(sheet_static))

    result = {
        "aws_total": len(aws_ec2),
        "aws_static": len(aws_static),
        "aws_karpenter": len(aws_karpenter),
        "sheet_total": len(sheet_servers),
        "sheet_static": len(sheet_static),
        "sheet_karpenter": len(sheet_karpenter),
        "matched": matched,
        "aws_only": aws_only,
        "sheet_only": sheet_only,
        "aws_only_count": len(aws_only),
        "sheet_only_count": len(sheet_only),
        "karpenter_nodes": aws_karpenter,
        "karpenter_count": len(aws_karpenter),
    }
    print(f"  교차검증: 고정 서버 AWS {len(aws_static)} vs 시트 {len(sheet_static)}, "
          f"일치 {matched}, 미등록 {len(aws_only)}, 종료 {len(sheet_only)}")
    print(f"  Karpenter: AWS {len(aws_karpenter)}개 동적 노드 (교차검증 제외)")
    return result


def load_aws_live_data():
    """Load AWS describe results from .claudesec-assets/aws-*.json files"""
    result = {"ec2": [], "rds": [], "elasticache": [], "s3": [], "eks": []}
    for profile in ["dive-dev", "dive-prod", "web3-prod", "playground"]:
        for rtype in ["ec2", "rds", "rds-clusters", "elasticache", "s3", "eks"]:
            fpath = ASSETS_DIR / f"aws-{rtype}-{profile}.json"
            if not fpath.exists():
                continue
            try:
                data = json.loads(fpath.read_text())
                if isinstance(data, list):
                    for item in data:
                        item["_profile"] = profile
                    key = rtype.replace("-clusters", "")
                    if key not in result:
                        result[key] = []
                    result[key].extend(data)
                elif isinstance(data, dict) and "clusters" in data:
                    for c in data["clusters"]:
                        result["eks"].append({"name": c, "_profile": profile})
            except Exception:
                pass
    for k, v in result.items():
        if v:
            print(f"    AWS {k}: {len(v)}개")
    return result


def collect_scan_history():
    """Collect scan history from .claudesec-history/"""
    hist_dir = ROOT / ".claudesec-history"
    if not hist_dir.exists():
        return []
    history = []
    for f in sorted(hist_dir.glob("scan-*.json")):
        try:
            data = json.loads(f.read_text())
            history.append(data)
        except Exception:
            pass
    # Sort by timestamp, keep last 30
    history.sort(key=lambda x: x.get("timestamp", ""))
    return history[-30:]


# ── 메인 ──────────────────────────────────────────────────────────────────

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  ClaudeSec 통합 대시보드 빌드")
    print(f"  {NOW}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("▶ 데이터 수집")

    # 수집
    dd_hosts, dd_signals = collect_datadog()
    prowler = collect_prowler()
    notion_audits = collect_notion_audits()
    jamf_pcs = collect_jamf_pcs()
    intune_pcs = collect_intune_pcs()
    # Load mobile devices if available
    jamf_mobiles = []
    mobile_inv = ASSETS_DIR / "jamf-full-inventory.json"
    if mobile_inv.exists():
        try:
            all_inv = json.loads(mobile_inv.read_text())
            jamf_mobiles = [item for item in all_inv if item.get("type") == "mobile"]
        except Exception:
            pass
    saas, licenses, ai_subs, asset_counts, saas_cost, infra, s1_agents, s1_threats, ep_crossverify = collect_sheets()

    # ClaudeSec 스캔
    scan = {}
    scan_path = ROOT / "scan-report.json"
    if scan_path.exists():
        scan = json.loads(scan_path.read_text())
        print(f"  ClaudeSec: {scan.get('grade')}/{scan.get('score')}")

    scan_history = collect_scan_history()

    # AWS live 데이터 + 파일 수정 시각
    aws_live = load_aws_live_data()

    # 소스별 수집 타임스탬프
    def file_mtime_str(p):
        """파일 수정 시각을 ISO 문자열로 반환"""
        fp = Path(p)
        if fp.exists():
            return datetime.fromtimestamp(fp.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return None

    timestamps = {
        "datadog": NOW,  # API 실시간
        "prowler": file_mtime_str(ROOT / ".claudesec-prowler"),
        "claudesec_scan": file_mtime_str(ROOT / "scan-report.json"),
        "google_sheets": NOW,  # API 실시간
        "saas_cost_xlsx": file_mtime_str("/tmp/claudesec-cost.xlsx"),
        "notion": file_mtime_str(ASSETS_DIR / "notion-security-audits.json"),
        "aws_ec2": file_mtime_str(ASSETS_DIR / "aws-ec2-dive-prod.json"),
        "aws_rds": file_mtime_str(ASSETS_DIR / "aws-rds-dive-prod.json"),
    }

    # EC2 교차 검증: AWS live vs 자산관리대장
    cross_verify = _cross_verify_ec2(aws_live.get("ec2", []), infra.get("servers", []))

    # 대시보드 데이터 조합
    dashboard_data = {
        "generated_at": NOW,
        "timestamps": timestamps,
        "datadog": {"hosts": dd_hosts, "signals": dd_signals},
        "prowler": prowler,
        "claudesec": scan,
        "scan_history": scan_history,
        "saas": saas,
        "license": licenses,
        "ai": ai_subs,
        "asset_counts": asset_counts,
        "saas_cost": saas_cost,
        "infra": infra,
        "aws_live": aws_live,
        "cross_verify": cross_verify,
        "sentinelone": s1_agents,
        "s1_threats": s1_threats,
        "endpoint_crossverify": ep_crossverify,
        "notion_audits": notion_audits,
        "jamf_pcs": jamf_pcs,
        "intune_pcs": intune_pcs,
        "jamf_mobiles": jamf_mobiles,
    }

    # JSON 저장
    json_path = ASSETS_DIR / "dashboard-data.json"
    json_path.write_text(json.dumps(dashboard_data, ensure_ascii=False, indent=2))
    print(f"\n▶ 데이터 저장: {json_path}")

    # HTML에 데이터 주입
    tmpl_path = ROOT / "claudesec-asset-dashboard.html"
    html = tmpl_path.read_text()

    json_str = json.dumps(dashboard_data, ensure_ascii=False, default=str)

    # 템플릿 내 placeholder 교체
    html = html.replace("__DASHBOARD_DATA__", json_str)
    html = html.replace(
        "const D=/*__DATA__*/null;",
        f"const D={json_str};"
    )

    out_path = ROOT / "claudesec-asset-dashboard-live.html"
    out_path.write_text(html)
    print(f"▶ 대시보드 생성: {out_path}")

    # 요약
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  빌드 완료!")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Datadog:  {len(dd_hosts)} 호스트, {len(dd_signals)} 시그널")
    print(f"  Prowler:  {prowler.get('total',0)} 총, {prowler.get('fail',0)} FAIL")
    print(f"  ClaudeSec: {scan.get('grade','N/A')} ({scan.get('score','N/A')}점)")
    print(f"  SaaS:     {len(saas)}개")
    print(f"  라이선스: {len(licenses)}개")
    print(f"  AI 구독:  {len(ai_subs)}개")
    print(f"  SaaS비용: {len(saas_cost.get('summary',[]))}종")
    print(f"  스캔이력: {len(scan_history)}건")
    print(f"\n  open {out_path}")


if __name__ == "__main__":
    main()
