#!/usr/bin/env python3
"""
ClaudeSec diagram data layer — scan/Prowler/history loading and aggregation.

Leaf module for the diagram generator: it loads scan-report.json, Prowler OCSF
provider files, and scan history, then aggregates them into the label dict the
draw.io / SVG builders consume. No draw.io/SVG concerns live here.

`load_scan_results` is single-sourced from `dashboard_data_loader` (with
try/except hardening) so the two implementations can't drift.
"""
import json
import os
import sys
import glob
from pathlib import Path

# Sibling-module imports: ensure this file's dir (scanner/lib) is importable
# whether imported by diagram-gen.py (which already inserts scanner/lib) or
# loaded standalone (e.g. by pytest for coverage). Mirrors the pattern used by
# diagram-gen.py and the dashboard_* modules.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard_data_loader import load_scan_results  # noqa: E402,F401

# Scanner categories — order must mirror the `CLAUDESEC_ALL_CATEGORIES` array in
# scanner/claudesec (the authoritative scan order). CATEGORIES[:8]/[:7] slices
# feed diagram labels, so order matters. Kept honest by
# scanner/tests/test_ci_diagram_gen_canonical_sync.py.
CATEGORIES = [
    "infra", "ai", "network", "cloud", "access-control",
    "cicd", "code", "macos", "windows", "saas", "prowler",
]


def _parse_ocsf_json(content):
    items = []
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(content):
        while idx < len(content) and content[idx] in " \t\n\r":
            idx += 1
        if idx >= len(content):
            break
        try:
            obj, end = decoder.raw_decode(content, idx)
            if isinstance(obj, list):
                items.extend(o for o in obj if isinstance(o, dict))
            elif isinstance(obj, dict):
                items.append(obj)
            idx = end
        except json.JSONDecodeError:
            idx += 1
    return items


def load_prowler_files(prowler_dir):
    providers = {}
    if not os.path.isdir(prowler_dir):
        return providers
    for fpath in sorted(glob.glob(os.path.join(prowler_dir, "prowler-*.ocsf.json"))):
        name = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
        try:
            with open(fpath) as f:
                content = f.read().strip()
            items = _parse_ocsf_json(content)
            providers[name] = items
        except Exception:
            providers[name] = []
    return providers


def load_scan_history(history_dir):
    entries = []
    if not os.path.isdir(history_dir):
        return entries
    for fpath in sorted(glob.glob(os.path.join(history_dir, "scan-*.json"))):
        try:
            with open(fpath) as f:
                entries.append(json.load(f))
        except Exception:
            pass
    return entries


def aggregate_scan_data(scan_dir):
    """Load and aggregate all scan-related data for diagram labels."""
    base = Path(scan_dir or ".")
    scan_json = base / "scan-report.json"
    prowler_dir = base / ".claudesec-prowler"
    history_dir = base / ".claudesec-history"

    scan_data = load_scan_results(str(scan_json))
    # Fallback: allow overriding scan JSON file.
    if (not scan_data.get("total")) and os.environ.get("CLAUDESEC_SCAN_JSON"):
        p = os.environ.get("CLAUDESEC_SCAN_JSON")
        if os.path.isfile(p):
            scan_data = load_scan_results(p)

    # Fallback: build minimal scan_data from env vars (dashboard generation path).
    # This keeps diagram generation functional even when scan-report.json is missing.
    if not scan_data.get("total"):
        try:
            passed = int(os.environ.get("CLAUDESEC_PASSED", "0") or "0")
            failed = int(os.environ.get("CLAUDESEC_FAILED", "0") or "0")
            warnings = int(os.environ.get("CLAUDESEC_WARNINGS", "0") or "0")
            skipped = int(os.environ.get("CLAUDESEC_SKIPPED", "0") or "0")
            total = int(os.environ.get("CLAUDESEC_TOTAL", "0") or "0")
            score = int(os.environ.get("CLAUDESEC_SCORE", "0") or "0")
            grade = os.environ.get("CLAUDESEC_GRADE", "F") or "F"
            duration = int(os.environ.get("CLAUDESEC_DURATION", "0") or "0")
            findings = []
            env_findings = os.environ.get("CLAUDESEC_FINDINGS_JSON", "") or ""
            if env_findings.strip().startswith("["):
                findings = json.loads(env_findings)
            scan_data = {
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "skipped": skipped,
                "total": total,
                "score": score,
                "grade": grade,
                "duration": duration,
                "findings": findings if isinstance(findings, list) else [],
            }
        except Exception:
            pass

    providers = load_prowler_files(str(prowler_dir))
    prov_summary = {}
    for prov, items in providers.items():
        fails = [i for i in items if i.get("status_code") == "FAIL"]
        prov_summary[prov] = {"fail": len(fails), "total": len(items)}

    history = load_scan_history(str(history_dir))
    return {
        "scan": scan_data,
        "prowler_providers": list(providers.keys()),
        "prowler_summary": prov_summary,
        "history_count": len(history),
    }
