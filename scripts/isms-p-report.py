#!/usr/bin/env python3
"""
ClaudeSec — ISMS-P 인증 준비 현황 리포트 자동 생성

Usage:
  python3 scripts/isms-p-report.py                    # 터미널 출력
  python3 scripts/isms-p-report.py --format json      # JSON 출력
  python3 scripts/isms-p-report.py --format md         # Markdown 파일 생성
  python3 scripts/isms-p-report.py --format html       # HTML 파일 생성

Data sources:
  - scanner/lib/compliance-map.py — ISMS-P 42개 통제항목 매핑
  - .claudesec-prowler/ — Prowler 스캔 결과
  - .claudesec-assets/policies.json — 내부 규정 이행 현황
  - .claudesec-history/ — 스캔 이력
"""

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

KST = timezone(timedelta(hours=9))
BASE_DIR = Path(__file__).resolve().parents[1]


def load_compliance_map():
    spec = importlib.util.spec_from_file_location(
        "compliance_map", BASE_DIR / "scanner" / "lib" / "compliance-map.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.COMPLIANCE_CONTROL_MAP, mod.map_compliance


def load_prowler_findings():
    spec = importlib.util.spec_from_file_location(
        "dashboard_gen", BASE_DIR / "scanner" / "lib" / "dashboard-gen.py"
    )
    mod = importlib.util.module_from_spec(spec)
    os.environ["CLAUDESEC_DASHBOARD_OFFLINE"] = "1"
    spec.loader.exec_module(mod)
    prowler_dir = str(BASE_DIR / ".claudesec-prowler")
    providers = mod.load_prowler_files(prowler_dir)
    _, findings = mod.analyze_prowler(providers)
    return findings


def load_policies():
    path = BASE_DIR / ".claudesec-assets" / "policies.json"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_scan_history():
    hist_dir = BASE_DIR / ".claudesec-history"
    entries = []
    if hist_dir.is_dir():
        for fp in sorted(hist_dir.glob("scan-*.json")):
            try:
                with open(fp, encoding="utf-8") as f:
                    entries.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                continue
    return entries


def generate_report():
    now = datetime.now(KST).strftime("%Y-%m-%d %H:%M KST")

    # 1. Prowler findings + compliance mapping
    findings = load_prowler_findings()
    control_map, map_fn = load_compliance_map()
    compliance = map_fn(findings)
    isms_p = compliance.get("KISA ISMS-P", [])
    isms_simple = compliance.get("KISA ISMS Simple", [])

    pass_count = sum(1 for c in isms_p if c["status"] == "PASS")
    fail_count = sum(1 for c in isms_p if c["status"] == "FAIL")
    total = len(isms_p)
    score = round(pass_count / total * 100) if total else 0

    # 2. Policies
    policies = load_policies()
    policy_summary = []
    for p in policies:
        arts = p.get("articles", [])
        done = sum(1 for a in arts if a.get("status") == "done")
        partial = sum(1 for a in arts if a.get("status") == "partial")
        todo = sum(1 for a in arts if a.get("status") == "todo")
        pct = round(done / len(arts) * 100) if arts else 0
        policy_summary.append({
            "name": p["name"],
            "total": len(arts),
            "done": done,
            "partial": partial,
            "todo": todo,
            "percent": pct,
        })

    total_arts = sum(ps["total"] for ps in policy_summary)
    total_done = sum(ps["done"] for ps in policy_summary)
    total_partial = sum(ps["partial"] for ps in policy_summary)
    total_todo = sum(ps["todo"] for ps in policy_summary)
    policy_score = round(total_done / total_arts * 100) if total_arts else 0

    # 3. Scan history trend
    history = load_scan_history()
    latest_scan = history[-1] if history else {}

    # 4. Top risk areas
    risk_areas = sorted(
        [c for c in isms_p if c["status"] == "FAIL"],
        key=lambda c: c["count"],
        reverse=True,
    )[:10]

    # 5. Domain breakdown
    domains = {
        "1. 관리체계 수립·운영": {"controls": [], "prefix": "1."},
        "2. 보호대책 요구사항": {"controls": [], "prefix": "2."},
        "3. 개인정보 처리단계별": {"controls": [], "prefix": "3."},
    }
    for c in isms_p:
        for dname, dinfo in domains.items():
            if c["control"].startswith(dinfo["prefix"]):
                dinfo["controls"].append(c)
                break

    domain_summary = {}
    for dname, dinfo in domains.items():
        ctrls = dinfo["controls"]
        dp = sum(1 for c in ctrls if c["status"] == "PASS")
        df = sum(1 for c in ctrls if c["status"] == "FAIL")
        domain_summary[dname] = {
            "total": len(ctrls),
            "pass": dp,
            "fail": df,
            "score": round(dp / len(ctrls) * 100) if ctrls else 0,
        }

    # Simple certification readiness
    simple_pass = sum(1 for c in isms_simple if c["status"] == "PASS")
    simple_total = len(isms_simple)
    simple_score = round(simple_pass / simple_total * 100) if simple_total else 0

    return {
        "generated_at": now,
        "prowler_findings": len(findings),
        "isms_p": {
            "total_controls": total,
            "pass": pass_count,
            "fail": fail_count,
            "score": score,
            "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F",
        },
        "isms_simple": {
            "total_controls": simple_total,
            "pass": simple_pass,
            "fail": simple_total - simple_pass,
            "score": simple_score,
        },
        "domains": domain_summary,
        "policies": {
            "total_documents": len(policy_summary),
            "total_articles": total_arts,
            "done": total_done,
            "partial": total_partial,
            "todo": total_todo,
            "score": policy_score,
            "details": policy_summary,
        },
        "risk_areas": [
            {"control": r["control"], "name": r["name"], "findings": r["count"], "action": r["action"]}
            for r in risk_areas
        ],
        "scan_history_count": len(history),
        "latest_scan": {
            "score": latest_scan.get("score", 0),
            "failed": latest_scan.get("failed", 0),
            "timestamp": latest_scan.get("timestamp", ""),
        },
        "controls": [
            {"control": c["control"], "name": c["name"], "status": c["status"], "findings": c["count"]}
            for c in isms_p
        ],
    }


def format_terminal(report):
    r = report
    ip = r["isms_p"]
    pol = r["policies"]

    lines = []
    lines.append("")
    lines.append("━" * 60)
    lines.append("  ISMS-P 인증 준비 현황 리포트")
    lines.append(f"  생성: {r['generated_at']}")
    lines.append("━" * 60)

    lines.append("")
    lines.append(f"  ■ ISMS-P 통제항목 준수율: {ip['score']}% ({ip['grade']})")
    lines.append(f"    PASS {ip['pass']} / FAIL {ip['fail']} / 총 {ip['total_controls']}개")
    lines.append(f"    Prowler 스캔 findings: {r['prowler_findings']}건")

    lines.append("")
    lines.append("  ■ 영역별 현황")
    for dname, ds in r["domains"].items():
        bar = "█" * (ds["score"] // 5) + "░" * (20 - ds["score"] // 5)
        lines.append(f"    {dname}")
        lines.append(f"      {bar} {ds['score']}% ({ds['pass']}/{ds['total']})")

    lines.append("")
    iss = r["isms_simple"]
    lines.append(f"  ■ ISMS 간편인증 준수율: {iss['score']}% (PASS {iss['pass']}/{iss['total_controls']})")

    lines.append("")
    lines.append(f"  ■ 내부 규정 이행률: {pol['score']}%")
    lines.append(f"    완료 {pol['done']} / 부분 {pol['partial']} / 미이행 {pol['todo']} (총 {pol['total_articles']}개 조항)")
    for ps in pol["details"]:
        status = "✅" if ps["percent"] >= 80 else "⚠️" if ps["percent"] >= 60 else "❌"
        lines.append(f"    {status} {ps['name']}: {ps['percent']}% ({ps['done']}/{ps['total']})")

    if r["risk_areas"]:
        lines.append("")
        lines.append("  ■ 상위 위험 영역 (Top 10)")
        for ra in r["risk_areas"]:
            lines.append(f"    ❌ {ra['control']} {ra['name']}: {ra['findings']}건")
            lines.append(f"       → {ra['action']}")

    lines.append("")
    lines.append("━" * 60)
    ls = r["latest_scan"]
    lines.append(f"  최근 스캔: {ls.get('timestamp', 'N/A')} (점수: {ls.get('score', 0)})")
    lines.append(f"  스캔 이력: {r['scan_history_count']}건")
    lines.append("━" * 60)
    lines.append("")

    return "\n".join(lines)


def format_markdown(report):
    r = report
    ip = r["isms_p"]
    pol = r["policies"]

    lines = [
        f"# ISMS-P 인증 준비 현황 리포트",
        f"",
        f"**생성일시**: {r['generated_at']}",
        f"",
        f"## 종합 현황",
        f"",
        f"| 항목 | 값 |",
        f"|------|-----|",
        f"| ISMS-P 준수율 | **{ip['score']}% ({ip['grade']})** |",
        f"| 통제항목 PASS/FAIL | {ip['pass']}/{ip['fail']} (총 {ip['total_controls']}) |",
        f"| Prowler findings | {r['prowler_findings']}건 |",
        f"| 내부 규정 이행률 | **{pol['score']}%** ({pol['done']}/{pol['total_articles']}) |",
        f"| 간편인증 준수율 | {r['isms_simple']['score']}% |",
        f"",
        f"## 영역별 준수율",
        f"",
        f"| 영역 | 점수 | PASS | FAIL | 총 |",
        f"|------|------|------|------|-----|",
    ]
    for dname, ds in r["domains"].items():
        lines.append(f"| {dname} | {ds['score']}% | {ds['pass']} | {ds['fail']} | {ds['total']} |")

    lines.extend([
        f"",
        f"## 내부 규정 이행 현황",
        f"",
        f"| 규정 | 이행률 | 완료 | 부분 | 미이행 |",
        f"|------|--------|------|------|--------|",
    ])
    for ps in pol["details"]:
        lines.append(f"| {ps['name']} | {ps['percent']}% | {ps['done']} | {ps['partial']} | {ps['todo']} |")

    if r["risk_areas"]:
        lines.extend([f"", f"## 상위 위험 영역", f"", f"| 통제항목 | 이름 | Findings | 조치 |", f"|---------|------|----------|------|"])
        for ra in r["risk_areas"]:
            lines.append(f"| {ra['control']} | {ra['name']} | {ra['findings']} | {ra['action'][:60]}... |")

    lines.extend([
        f"",
        f"## 통제항목 상세",
        f"",
        f"| 코드 | 이름 | 상태 | Findings |",
        f"|------|------|------|----------|",
    ])
    for c in r["controls"]:
        status = "PASS" if c["status"] == "PASS" else "**FAIL**"
        lines.append(f"| {c['control']} | {c['name'][:40]} | {status} | {c['findings']} |")

    lines.append(f"\n---\n*Generated by ClaudeSec ISMS-P Report*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="ISMS-P 인증 준비 현황 리포트")
    parser.add_argument("--format", choices=["text", "json", "md", "html"], default="text")
    parser.add_argument("--output", "-o", help="출력 파일 경로")
    args = parser.parse_args()

    report = generate_report()

    if args.format == "json":
        output = json.dumps(report, ensure_ascii=False, indent=2)
    elif args.format == "md":
        output = format_markdown(report)
    elif args.format == "html":
        md = format_markdown(report)
        output = f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>ISMS-P Report</title><style>body{{font-family:sans-serif;max-width:900px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f5f5f5}}</style></head><body><pre>{md}</pre></body></html>"
    else:
        output = format_terminal(report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"리포트 저장: {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
