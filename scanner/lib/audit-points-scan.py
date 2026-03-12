#!/usr/bin/env python3
"""
ClaudeSec — Audit Points scan: detect products relevant to the project and
output checklist items from querypie/audit-points for dashboard/scanner integration.
"""

import json
import os
import sys
from pathlib import Path

# Reuse cache path and load logic; avoid fetching here (dashboard or first run does it)
CACHE_DIR_NAME = ".claudesec-audit-points"
CACHE_FILE = "cache.json"
DETECTED_FILE = "detected.json"


def _has_nexus_indicator(scan_dir):
    """True if pom.xml or build files reference nexus repository."""
    import glob
    for pattern in ["pom.xml", "**/pom.xml", "build.gradle", "build.gradle.kts"]:
        for p in glob.glob(os.path.join(scan_dir, pattern)):
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        if "nexus" in f.read().lower():
                            return True
                except OSError:
                    pass
    return False


def _file_contains_any(scan_dir, keywords, suffixes):
    """True if any file with given suffixes contains any keyword."""
    import glob
    for root, _dirs, files in os.walk(scan_dir):
        for name in files:
            if any(name.endswith(s) for s in suffixes):
                path = os.path.join(root, name)
                if ".git" in path or "node_modules" in path:
                    continue
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read().lower()
                        if any(k in text for k in keywords):
                            return True
                except OSError:
                    pass
    return False


def _has_scalr_in_terraform(scan_dir):
    """True if .terraform or *.tf reference scalr."""
    import glob
    for pattern in [".terraform", "**/*.tf", "**/*.tfvars"]:
        for p in glob.glob(os.path.join(scan_dir, pattern)):
            if os.path.isfile(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        if "scalr" in f.read().lower():
                            return True
                except OSError:
                    pass
    return False


# Product detection heuristics: (product_name, list of path globs or file names [, optional callable(scan_dir)])
PRODUCT_DETECTORS = [
    ("Jenkins", ["Jenkinsfile", ".jenkins", "jenkins.yaml", "jenkins.yml", ".jenkinsfile"]),
    ("Harbor", ["harbor.yml", ".harbor", "harbor.yaml"]),
    ("Nexus", ["pom.xml", ".nexus", "nexus.json"], _has_nexus_indicator),
    ("Okta", [".okta", "okta.yaml", "okta.yml", "auth.config.json"], lambda d: _file_contains_any(d, ["okta"], [".env", ".yml", ".yaml", "config.json"])),
    ("QueryPie", ["querypie.yml", ".querypie"], lambda d: _file_contains_any(d, ["querypie"], [".yml", ".yaml"])),
    ("Scalr", [".scalr", "scalr.hcl"], _has_scalr_in_terraform),
    ("IDEs", [".vscode", ".idea"]),
]


def detect_products(scan_dir):
    """
    Return list of Audit Point product names that are relevant to this project.
    """
    scan_dir = os.path.abspath(scan_dir)
    if not os.path.isdir(scan_dir):
        return []
    detected = []
    for row in PRODUCT_DETECTORS:
        product = row[0]
        indicators = row[1]
        extra = row[2] if len(row) > 2 else None
        found = False
        for ind in indicators:
            if "*" in ind:
                import glob
                if glob.glob(os.path.join(scan_dir, ind)):
                    found = True
                    break
            else:
                path = os.path.join(scan_dir, ind)
                if os.path.exists(path):
                    found = True
                    break
        if not found and extra and extra(scan_dir):
            found = True
        if found:
            detected.append(product)
    return detected


def _fetch_and_cache(scan_dir):
    """Fetch audit-points from GitHub and write cache. Uses dashboard-gen if available."""
    try:
        # Prefer dashboard-gen so we don't duplicate fetch logic
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dash = os.path.join(script_dir, "dashboard-gen.py")
        if os.path.isfile(dash):
            import importlib.util
            spec = importlib.util.spec_from_file_location("dashboard_gen", dash)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod.load_audit_points(scan_dir)
    except Exception:
        pass
    return {"products": [], "fetched_at": ""}


def load_cache(scan_dir):
    """Load audit-points cache.json; fetch and cache if missing."""
    cache_path = os.path.join(scan_dir, CACHE_DIR_NAME, CACHE_FILE)
    if os.path.isfile(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
    data = _fetch_and_cache(scan_dir)
    if data.get("products"):
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
    return data


def run_audit_points_scan(scan_dir):
    """
    Detect products, load cache, build list of checklist items for detected products.
    Writes .claudesec-audit-points/detected.json and returns (detected_products, items).
    """
    scan_dir = os.path.abspath(scan_dir)
    detected_names = detect_products(scan_dir)
    data = load_cache(scan_dir)
    products_by_name = {p["name"]: p for p in data.get("products", [])}
    items = []
    for name in detected_names:
        prod = products_by_name.get(name)
        if not prod:
            continue
        for f in prod.get("files", []):
            items.append({
                "product": name,
                "file_name": f.get("name", ""),
                "url": f.get("url") or f.get("raw_url", ""),
            })
    out = {
        "detected_products": detected_names,
        "items": items,
        "scan_dir": scan_dir,
    }
    out_dir = os.path.join(scan_dir, CACHE_DIR_NAME)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, DETECTED_FILE)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return detected_names, items


def main():
    scan_dir = os.environ.get("SCAN_DIR", "")
    if not scan_dir and len(sys.argv) > 1:
        scan_dir = sys.argv[1]
    if not scan_dir:
        scan_dir = os.getcwd()
    detected, items = run_audit_points_scan(scan_dir)
    # Print machine-readable summary for shell
    print(json.dumps({"detected": detected, "item_count": len(items)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
