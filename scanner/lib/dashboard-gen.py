#!/usr/bin/env python3
"""
ClaudeSec Dashboard Generator v0.5.0
Generates a tabbed HTML security dashboard from scan results and Prowler OCSF data.
"""

import base64
import json
import os
import sys
import glob
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import Any, TypedDict

# QueryPie Audit Points repo (SaaS/DevSecOps audit checklists)
AUDIT_POINTS_REPO = "querypie/audit-points"
AUDIT_POINTS_CACHE_TTL_HOURS = 24

MS_BEST_PRACTICES_CACHE_TTL_HOURS = 24
MS_INCLUDE_SCUBAGEAR_ENV = "CLAUDESEC_MS_INCLUDE_SCUBAGEAR"
MS_SOURCE_FILTER_ENV = "CLAUDESEC_MS_SOURCE_FILTER"
TRUST_LEVEL_ORDER = {"Microsoft Official": 0, "Government": 1, "Community": 2}
TRUST_LEVEL_FILTER_MAP = {
    "official": {"Microsoft Official"},
    "gov": {"Government"},
    "community": {"Community"},
    "none": set(),
    "all": set(TRUST_LEVEL_ORDER.keys()),
}
TRUST_FILTER_TOKEN_ORDER = ("official", "gov", "community")
MS_BEST_PRACTICES_REPO_SOURCES = [
    {
        "product": "Windows",
        "repo": "microsoft/SecCon-Framework",
        "label": "Microsoft SecCon Framework",
        "trust_level": "Microsoft Official",
        "reason": "Microsoft guidance for Windows security configuration baselines.",
        "focus_paths": ["README.md"],
    },
    {
        "product": "Windows",
        "repo": "nsacyber/Windows-Secure-Host-Baseline",
        "label": "NSA Windows Secure Host Baseline",
        "trust_level": "Government",
        "reason": "Widely referenced hardening baseline for Windows hosts.",
        "focus_paths": ["README.md", "Documentation"],
    },
    {
        "product": "Windows",
        "repo": "microsoft/PowerStig",
        "label": "PowerStig (Windows STIG automation)",
        "trust_level": "Microsoft Official",
        "reason": "Microsoft-maintained STIG automation for Windows and related platforms; widely used for compliance automation.",
        "focus_paths": ["README.md", "docs"],
    },
    {
        "product": "Windows",
        "repo": "microsoft/SCAR",
        "label": "SCAR (STIG Compliance Automation)",
        "trust_level": "Microsoft Official",
        "reason": "Microsoft-maintained repository for automating STIG compliance workflows and artifacts.",
        "focus_paths": ["README.md", "docs"],
    },
    {
        "product": "Intune",
        "repo": "MicrosoftDocs/memdocs",
        "label": "Microsoft Endpoint Manager Docs",
        "trust_level": "Microsoft Official",
        "reason": "Official Microsoft Intune documentation source repository.",
        "focus_paths": ["intune/protect", "intune/fundamentals", "README.md"],
    },
    {
        "product": "Intune",
        "repo": "microsoftgraph/powershell-intune-samples",
        "label": "Microsoft Graph Intune Samples",
        "trust_level": "Microsoft Official",
        "reason": "Official Intune automation samples for policy and endpoint security.",
        "focus_paths": [
            "EndpointSecurity",
            "CompliancePolicy",
            "DeviceConfiguration",
            "Readme.md",
        ],
    },
    {
        "product": "Office 365",
        "repo": "MicrosoftDocs/microsoft-365-docs",
        "label": "Microsoft 365 Docs",
        "trust_level": "Microsoft Official",
        "reason": "Official Microsoft 365 security and compliance guidance.",
        "focus_paths": [
            "microsoft-365/security",
            "microsoft-365/compliance",
            "README.md",
        ],
    },
    {
        "product": "Office 365",
        "repo": "microsoft/Microsoft365DSC",
        "label": "Microsoft365DSC",
        "trust_level": "Microsoft Official",
        "reason": "Microsoft-backed configuration-as-code baselines for M365 workloads.",
        "focus_paths": ["docs", "Modules", "README.md"],
    },
    {
        "product": "Office 365",
        "repo": "cisagov/ScubaGear",
        "label": "CISA ScubaGear",
        "trust_level": "Government",
        "reason": "CISA baseline and policy artifacts for Microsoft 365 security posture assessment.",
        "focus_paths": ["baselines", "PowerShell", "README.md"],
        "optional_env": MS_INCLUDE_SCUBAGEAR_ENV,
    },
]

VERSION = "0.5.0"


class AuditPointFile(TypedDict):
    name: str
    url: str
    raw_url: str


class AuditPointProduct(TypedDict):
    name: str
    tree_url: str
    files: list[AuditPointFile]


class AuditPointsData(TypedDict):
    products: list[AuditPointProduct]
    fetched_at: str


class TrivySummary(TypedDict):
    critical: int
    high: int
    medium: int
    low: int


class TrivyVuln(TypedDict, total=False):
    target: str
    severity: str
    id: str
    title: str
    pkg: str
    message: str


class NmapHost(TypedDict):
    addr: str
    ports: list[str]


class NmapScan(TypedDict):
    name: str
    hosts: list[NmapHost]


class SSLScanResult(TypedDict):
    name: str
    data: dict[str, Any]


class NetworkToolResult(TypedDict):
    trivy_fs: dict[str, Any] | None
    trivy_config: dict[str, Any] | None
    trivy_summary: TrivySummary
    trivy_vulns: list[TrivyVuln]
    nmap_scans: list[NmapScan]
    sslscan_results: list[SSLScanResult]


class DatadogLogEntry(TypedDict):
    severity: str
    message: str
    source: str
    timestamp: str


class DatadogSummary(TypedDict):
    error: int
    warning: int
    info: int
    unknown: int
    total: int


class DatadogSeveritySummary(TypedDict):
    critical: int
    high: int
    medium: int
    low: int
    info: int
    unknown: int
    total: int


class DatadogLogsData(TypedDict):
    logs: list[DatadogLogEntry]
    summary: DatadogSummary
    signals: list[dict[str, str]]
    signal_summary: DatadogSeveritySummary
    cases: list[dict[str, str]]
    case_summary: DatadogSeveritySummary


class GitHubContentItem(TypedDict, total=False):
    type: str
    name: str
    path: str
    html_url: str
    download_url: str


class RepoFocusFile(TypedDict):
    name: str
    path: str
    url: str
    raw_url: str


class RepoFocusData(TypedDict):
    repo: str
    repo_url: str
    default_branch: str
    updated_at: str
    archived: bool
    files: list[RepoFocusFile]


class MicrosoftBestPracticeSource(TypedDict):
    product: str
    label: str
    trust_level: str
    reason: str
    repo: str
    repo_url: str
    default_branch: str
    updated_at: str
    archived: bool
    files: list[RepoFocusFile]


class MicrosoftBestPracticesData(TypedDict):
    fetched_at: str
    source_filter: str
    scubagear_enabled: bool
    sources: list[MicrosoftBestPracticeSource]


# ── Data Loading ─────────────────────────────────────────────────────────────


def load_scan_results(path: str) -> dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "skipped": 0,
            "total": 0,
            "score": 0,
            "grade": "F",
            "findings": [],
        }
    with open(path) as f:
        return json.load(f)


def _parse_ocsf_json(content: str) -> list[dict[str, Any]]:
    """Parse OCSF JSON that may be a single array, multiple concatenated arrays, or NDJSON."""
    items: list[dict[str, Any]] = []
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


def load_prowler_files(prowler_dir: str) -> dict[str, list[dict[str, Any]]]:
    providers: dict[str, list[dict[str, Any]]] = {}
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


def load_scan_history(history_dir: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not os.path.isdir(history_dir):
        return entries
    for fpath in sorted(glob.glob(os.path.join(history_dir, "scan-*.json"))):
        try:
            with open(fpath, encoding="utf-8") as f:
                entries.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            continue
    return entries


def _fetch_audit_points_from_github() -> AuditPointsData | None:
    """Fetch product list and file list from querypie/audit-points via GitHub API. Returns dict or None on error."""
    base = f"https://api.github.com/repos/{AUDIT_POINTS_REPO}/contents"
    result: AuditPointsData = {
        "products": [],
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        req = urllib.request.Request(
            base, headers={"Accept": "application/vnd.github.v3+json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            root = json.loads(resp.read().decode("utf-8"))
        if not isinstance(root, list):
            return None
        for item in root:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "dir" or not item.get("name"):
                continue
            name = item["name"]
            if name in ("README.md",):
                continue
            product: AuditPointProduct = {
                "name": name,
                "tree_url": item.get("html_url", ""),
                "files": [],
            }
            try:
                sub_req = urllib.request.Request(
                    f"{base}/{urllib.parse.quote(name, safe='')}",
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                with urllib.request.urlopen(sub_req, timeout=15) as sub_resp:
                    children = json.loads(sub_resp.read().decode("utf-8"))
                if not isinstance(children, list):
                    children = []
                for c in children:
                    if not isinstance(c, dict):
                        continue
                    if c.get("type") == "file" and (c.get("name") or "").endswith(
                        ".md"
                    ):
                        product["files"].append(
                            {
                                "name": c["name"],
                                "url": c.get("html_url", ""),
                                "raw_url": c.get("download_url", ""),
                            }
                        )
                product["files"].sort(key=lambda x: x["name"])
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                json.JSONDecodeError,
                OSError,
            ):
                pass
            result["products"].append(product)
        result["products"].sort(key=lambda p: p["name"])
        return result
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ):
        return None


def load_audit_points_detected(scan_dir: str) -> dict[str, Any]:
    """
    Load scan result from audit-points scan: .claudesec-audit-points/detected.json.
    Returns dict with detected_products, items (list of {product, file_name, url}); or empty dict.
    """
    detected_path = os.path.join(scan_dir, ".claudesec-audit-points", "detected.json")
    if not os.path.isfile(detected_path):
        return {}
    try:
        with open(detected_path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def load_audit_points(scan_dir: str) -> AuditPointsData:
    """
    Load QueryPie audit-points data: from cache if fresh, else fetch from GitHub and cache.
    Returns dict with keys: products (list of {name, tree_url, files}), fetched_at; or empty dict on error.
    """
    cache_dir = os.path.join(scan_dir, ".claudesec-audit-points")
    cache_file = os.path.join(cache_dir, "cache.json")
    now = datetime.now(timezone.utc)
    try:
        if os.path.isfile(cache_file):
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            fetched = data.get("fetched_at", "")
            if fetched:
                try:
                    dt = datetime.fromisoformat(fetched.replace("Z", "+00:00"))
                    if (now - dt).total_seconds() < AUDIT_POINTS_CACHE_TTL_HOURS * 3600:
                        return data
                except (ValueError, TypeError):
                    pass
        fresh = _fetch_audit_points_from_github()
        if fresh:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(fresh, f, ensure_ascii=False, indent=2)
            return fresh
    except (OSError, json.JSONDecodeError):
        pass
    return {"products": [], "fetched_at": ""}


def _github_api_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github.v3+json"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _is_best_practice_file(name: str) -> bool:
    lower = (name or "").lower()
    if not lower:
        return False
    exts = (".md", ".markdown", ".txt", ".yml", ".yaml", ".json", ".ps1")
    if lower.endswith(exts):
        return True
    return lower in ("readme", "readme.md", "security.md")


def _is_env_truthy(var_name: str) -> bool:
    return os.environ.get(var_name, "").strip().lower() in ("1", "true", "yes", "on")


def _resolve_source_filter(raw_value: str) -> tuple[str, set[str]]:
    raw = (raw_value or "").strip().lower()
    if not raw:
        return "all", set(TRUST_LEVEL_FILTER_MAP["all"])
    tokens = []
    for token in raw.split(","):
        t = token.strip().lower()
        if not t:
            continue
        if t == "all":
            return "all", set(TRUST_LEVEL_FILTER_MAP["all"])
        if t == "none":
            return "none", set()
        if t in ("official", "gov", "community") and t not in tokens:
            tokens.append(t)
    if not tokens:
        return "all", set(TRUST_LEVEL_FILTER_MAP["all"])
    ordered_tokens = [t for t in TRUST_FILTER_TOKEN_ORDER if t in tokens]
    allowed_levels = set()
    for token in ordered_tokens:
        allowed_levels.update(TRUST_LEVEL_FILTER_MAP[token])
    return ",".join(ordered_tokens), allowed_levels


def _normalized_source_filter() -> str:
    raw = os.environ.get(MS_SOURCE_FILTER_ENV, "all")
    normalized, _ = _resolve_source_filter(raw)
    return normalized


def _trust_token_from_level(level: str) -> str:
    return {
        "Microsoft Official": "official",
        "Government": "gov",
        "Community": "community",
    }.get(level, "community")


def _fetch_repo_focus_files(repo: str, focus_paths: list[str]) -> RepoFocusData:
    result: RepoFocusData = {
        "repo": repo,
        "repo_url": f"https://github.com/{repo}",
        "default_branch": "",
        "updated_at": "",
        "archived": False,
        "files": [],
    }
    try:
        repo_meta = _github_api_json(f"https://api.github.com/repos/{repo}")
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ):
        return result

    if not isinstance(repo_meta, dict):
        return result
    result["default_branch"] = str(repo_meta.get("default_branch", ""))
    result["updated_at"] = (
        repo_meta.get("pushed_at") or repo_meta.get("updated_at") or ""
    )
    result["archived"] = bool(repo_meta.get("archived"))

    seen: set[str] = set()
    collected: list[RepoFocusFile] = []

    def add_file_item(item: dict[str, Any]) -> None:
        path = item.get("path") or item.get("name") or ""
        if not path or path in seen:
            return
        seen.add(path)
        collected.append(
            {
                "name": str(item.get("name") or path),
                "path": path,
                "url": str(item.get("html_url", "")),
                "raw_url": str(item.get("download_url", "")),
            }
        )

    for focus_path in focus_paths:
        qpath = urllib.parse.quote(focus_path, safe="/")
        try:
            payload = _github_api_json(
                f"https://api.github.com/repos/{repo}/contents/{qpath}"
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            json.JSONDecodeError,
            OSError,
        ):
            continue

        entries: list[dict[str, Any]]
        if isinstance(payload, list):
            entries = [e for e in payload if isinstance(e, dict)]
        elif isinstance(payload, dict):
            entries = [payload]
        else:
            entries = []
        for entry in entries:
            etype = entry.get("type")
            name = entry.get("name", "")
            if etype == "file" and _is_best_practice_file(name):
                add_file_item(entry)
            elif etype == "dir":
                sub_path = entry.get("path") or ""
                if not sub_path:
                    continue
                sub_qpath = urllib.parse.quote(sub_path, safe="/")
                try:
                    children = _github_api_json(
                        f"https://api.github.com/repos/{repo}/contents/{sub_qpath}"
                    )
                except (
                    urllib.error.URLError,
                    urllib.error.HTTPError,
                    json.JSONDecodeError,
                    OSError,
                ):
                    continue
                if not isinstance(children, list):
                    continue
                for child in children[:120]:
                    if not isinstance(child, dict):
                        continue
                    if child.get("type") != "file":
                        continue
                    if not _is_best_practice_file(child.get("name", "")):
                        continue
                    add_file_item(child)

    result["files"] = sorted(collected, key=lambda x: x["path"])[:80]
    return result


def _fetch_microsoft_best_practices_from_github() -> MicrosoftBestPracticesData:
    sources: list[MicrosoftBestPracticeSource] = []
    source_filter, allowed_levels = _resolve_source_filter(
        os.environ.get(MS_SOURCE_FILTER_ENV, "all")
    )
    scubagear_enabled = _is_env_truthy(MS_INCLUDE_SCUBAGEAR_ENV)
    for src in MS_BEST_PRACTICES_REPO_SOURCES:
        trust_level = src.get("trust_level", "Community")
        if trust_level not in allowed_levels:
            continue
        optional_env_raw = src.get("optional_env", "")
        optional_env = optional_env_raw if isinstance(optional_env_raw, str) else ""
        if optional_env and not _is_env_truthy(optional_env):
            continue
        repo_raw = src.get("repo", "")
        if not isinstance(repo_raw, str) or not repo_raw:
            continue
        focus_paths_raw = src.get("focus_paths", [])
        focus_paths = (
            [p for p in focus_paths_raw if isinstance(p, str)]
            if isinstance(focus_paths_raw, list)
            else []
        )
        repo_data = _fetch_repo_focus_files(repo_raw, focus_paths)
        # Best Practices list should be high-signal; drop archived repos entirely.
        # (Archived repos often contain outdated guidance and confuse UI/UX.)
        if repo_data.get("archived"):
            continue
        sources.append(
            {
                "product": str(src["product"]),
                "label": str(src["label"]),
                "trust_level": trust_level,
                "reason": str(src["reason"]),
                "repo": repo_data["repo"],
                "repo_url": repo_data["repo_url"],
                "default_branch": repo_data["default_branch"],
                "updated_at": repo_data["updated_at"],
                "archived": repo_data["archived"],
                "files": repo_data["files"],
            }
        )
    sources.sort(
        key=lambda s: (
            TRUST_LEVEL_ORDER.get(s.get("trust_level", "Community"), 9),
            s.get("product", ""),
            s.get("label", ""),
        )
    )
    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source_filter": source_filter,
        "scubagear_enabled": scubagear_enabled,
        "sources": sources,
    }


def load_microsoft_best_practices(scan_dir: str) -> MicrosoftBestPracticesData:
    cache_dir = os.path.join(scan_dir, ".claudesec-ms-best-practices")
    cache_file = os.path.join(cache_dir, "cache.json")
    now = datetime.now(timezone.utc)
    expected_filter = _normalized_source_filter()
    expected_scubagear = _is_env_truthy(MS_INCLUDE_SCUBAGEAR_ENV)
    try:
        if os.path.isfile(cache_file):
            with open(cache_file, encoding="utf-8") as f:
                data = json.load(f)
            fetched = data.get("fetched_at", "")
            if fetched:
                try:
                    dt = datetime.fromisoformat(fetched.replace("Z", "+00:00"))
                    cache_filter = data.get("source_filter", "all")
                    cache_scubagear = bool(data.get("scubagear_enabled", False))
                    if (
                        now - dt
                    ).total_seconds() < MS_BEST_PRACTICES_CACHE_TTL_HOURS * 3600 and (
                        cache_filter == expected_filter
                        and cache_scubagear == expected_scubagear
                    ):
                        return data
                except (ValueError, TypeError):
                    pass
        fresh = _fetch_microsoft_best_practices_from_github()
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(fresh, f, ensure_ascii=False, indent=2)
        return fresh
    except (OSError, json.JSONDecodeError):
        return {
            "fetched_at": "",
            "source_filter": expected_filter,
            "scubagear_enabled": expected_scubagear,
            "sources": [],
        }


def load_network_tool_results(network_dir: str) -> NetworkToolResult:
    """Load Trivy, nmap, sslscan results from .claudesec-network/ for dashboard."""
    out: NetworkToolResult = {
        "trivy_fs": None,
        "trivy_config": None,
        "trivy_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "trivy_vulns": [],
        "nmap_scans": [],
        "sslscan_results": [],
    }
    if not network_dir or not os.path.isdir(network_dir):
        return out
    trivy_fs_path = os.path.join(network_dir, "trivy-fs.json")
    if os.path.isfile(trivy_fs_path):
        try:
            with open(trivy_fs_path) as f:
                data = json.load(f)
            for r in data.get("Results", []):
                for v in r.get("Vulnerabilities", []) or []:
                    s = (v.get("Severity") or "").upper()
                    if s == "CRITICAL":
                        out["trivy_summary"]["critical"] += 1
                    elif s == "HIGH":
                        out["trivy_summary"]["high"] += 1
                    elif s == "MEDIUM":
                        out["trivy_summary"]["medium"] += 1
                    elif s == "LOW":
                        out["trivy_summary"]["low"] += 1
                    out["trivy_vulns"].append(
                        {
                            "target": r.get("Target", ""),
                            "severity": s or "UNKNOWN",
                            "id": v.get("VulnerabilityID", ""),
                            "title": v.get("Title", ""),
                            "pkg": v.get("PkgName", ""),
                            "message": v.get("Message", ""),
                        }
                    )
                for v in r.get("Misconfigurations", []) or []:
                    s = (v.get("Severity") or "").upper()
                    if s == "CRITICAL":
                        out["trivy_summary"]["critical"] += 1
                    elif s == "HIGH":
                        out["trivy_summary"]["high"] += 1
                    elif s == "MEDIUM":
                        out["trivy_summary"]["medium"] += 1
                    elif s == "LOW":
                        out["trivy_summary"]["low"] += 1
                    out["trivy_vulns"].append(
                        {
                            "target": r.get("Target", ""),
                            "severity": s or "UNKNOWN",
                            "id": v.get("ID", ""),
                            "title": v.get("Title", ""),
                            "message": v.get("Message", ""),
                        }
                    )
            out["trivy_fs"] = data
        except (OSError, json.JSONDecodeError):
            pass  # skip missing or invalid trivy-fs.json
    trivy_cfg_path = os.path.join(network_dir, "trivy-config.json")
    if os.path.isfile(trivy_cfg_path):
        try:
            with open(trivy_cfg_path, encoding="utf-8") as f:
                out["trivy_config"] = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass  # skip missing or invalid trivy-config.json
    import xml.etree.ElementTree as ET

    for fpath in glob.glob(os.path.join(network_dir, "nmap-*.xml")):
        try:
            tree = ET.parse(fpath)
            root = tree.getroot()
            name = os.path.basename(fpath).replace("nmap-", "").replace(".xml", "")
            hosts = []
            for host in root.findall(".//host"):
                addr = host.find("address")
                h = addr.get("addr", "") if addr is not None else ""
                ports = []
                for port in host.findall(".//port[@protocol='tcp']"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        ports.append(port.get("port", ""))
                if h or ports:
                    hosts.append({"addr": h, "ports": ports[:20]})
            out["nmap_scans"].append({"name": name, "hosts": hosts})
        except Exception:
            out["nmap_scans"].append({"name": os.path.basename(fpath), "hosts": []})
    for fpath in glob.glob(os.path.join(network_dir, "sslscan-*.json")):
        try:
            with open(fpath) as f:
                out["sslscan_results"].append(
                    {"name": os.path.basename(fpath), "data": json.load(f)}
                )
        except Exception:
            out["sslscan_results"].append({"name": os.path.basename(fpath), "data": {}})
    return out


def load_datadog_logs(datadog_dir: str) -> DatadogLogsData:
    logs: list[DatadogLogEntry] = []
    summary: DatadogSummary = {
        "error": 0,
        "warning": 0,
        "info": 0,
        "unknown": 0,
        "total": 0,
    }
    signal_summary: DatadogSeveritySummary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "total": 0,
    }
    case_summary: DatadogSeveritySummary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "total": 0,
    }
    out: DatadogLogsData = {
        "logs": logs,
        "summary": summary,
        "signals": [],
        "signal_summary": signal_summary,
        "cases": [],
        "case_summary": case_summary,
    }
    if not datadog_dir or not os.path.isdir(datadog_dir):
        return out

    def _normalize_severity(raw):
        val = (raw or "").strip().lower()
        if val in ("critical", "crit", "error", "err", "fatal"):
            return "error"
        if val in ("warn", "warning"):
            return "warning"
        if val in ("info", "notice", "ok", "pass"):
            return "info"
        return "unknown"

    def _normalize_log(item: dict[str, Any]) -> DatadogLogEntry:
        attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
        nested = attrs.get("attributes", {}) if isinstance(attrs, dict) else {}
        status = (
            attrs.get("status")
            or nested.get("status")
            or attrs.get("level")
            or nested.get("level")
        )
        severity = _normalize_severity(status)
        message = (
            attrs.get("message")
            or nested.get("message")
            or item.get("message", "")
            or ""
        )
        source = (
            attrs.get("service")
            or nested.get("service")
            or attrs.get("source")
            or nested.get("source")
            or "-"
        )
        timestamp = (
            attrs.get("timestamp")
            or nested.get("timestamp")
            or item.get("timestamp", "")
        )
        return {
            "severity": severity,
            "message": str(message),
            "source": str(source),
            "timestamp": str(timestamp),
        }

    def _normalize_dd_severity(raw: Any) -> str:
        val = str(raw or "").strip().lower()
        if val in ("critical", "sev-1", "p1"):
            return "critical"
        if val in ("high", "sev-2", "p2"):
            return "high"
        if val in ("medium", "med", "sev-3", "p3"):
            return "medium"
        if val in ("low", "sev-4", "p4"):
            return "low"
        if val in ("info", "informational"):
            return "info"
        return "unknown"

    def _inc_sev(counter: DatadogSeveritySummary, sev: str) -> None:
        if sev == "critical":
            counter["critical"] += 1
        elif sev == "high":
            counter["high"] += 1
        elif sev == "medium":
            counter["medium"] += 1
        elif sev == "low":
            counter["low"] += 1
        elif sev == "info":
            counter["info"] += 1
        else:
            counter["unknown"] += 1

    def _extract_items(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return [x for x in data["data"] if isinstance(x, dict)]
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []

    candidates = [
        "datadog-logs.json",
        "logs.json",
        "datadog-logs.jsonl",
        "logs.jsonl",
    ]
    for name in candidates:
        fpath = os.path.join(datadog_dir, name)
        if not os.path.isfile(fpath):
            continue
        try:
            if name.endswith(".jsonl"):
                with open(fpath, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        normalized = _normalize_log(obj)
                        logs.append(normalized)
            else:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("data"), list):
                    for item in data["data"]:
                        if isinstance(item, dict):
                            logs.append(_normalize_log(item))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            logs.append(_normalize_log(item))
        except (OSError, json.JSONDecodeError):
            continue

    if logs:
        logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:200]
        for log in logs:
            sev = log.get("severity", "unknown")
            if sev == "error":
                summary["error"] += 1
            elif sev == "warning":
                summary["warning"] += 1
            elif sev == "info":
                summary["info"] += 1
            else:
                summary["unknown"] += 1
        summary["total"] = len(logs)
        out["logs"] = logs

    signal_candidates = [
        "datadog-cloud-signals-sanitized.json",
        "datadog-cloud-signals.json",
        "datadog-signals.json",
        "cloud-signals.json",
    ]
    for name in signal_candidates:
        fpath = os.path.join(datadog_dir, name)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        parsed_signals: list[dict[str, str]] = []
        for item in _extract_items(data):
            attrs = (
                item.get("attributes", {})
                if isinstance(item.get("attributes"), dict)
                else {}
            )
            sev = _normalize_dd_severity(attrs.get("severity"))
            _inc_sev(signal_summary, sev)
            parsed_signals.append(
                {
                    "severity": sev,
                    "status": str(
                        attrs.get("signal_status") or attrs.get("status") or ""
                    ),
                    "title": str(
                        attrs.get("title")
                        or attrs.get("message")
                        or item.get("id")
                        or ""
                    ),
                    "rule": str(
                        attrs.get("security_rule_name") or attrs.get("detection", "")
                    ),
                    "source": str(attrs.get("source") or attrs.get("type") or "signal"),
                    "timestamp": str(
                        attrs.get("timestamp") or attrs.get("last_seen") or ""
                    ),
                }
            )
        if parsed_signals:
            parsed_signals = sorted(
                parsed_signals,
                key=lambda x: (
                    {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                        "low": 3,
                        "info": 4,
                        "unknown": 5,
                    }.get(
                        x.get("severity", "unknown"),
                        9,
                    ),
                    x.get("timestamp", ""),
                ),
            )[:150]
            signal_summary["total"] = len(parsed_signals)
            out["signals"] = parsed_signals
        break

    case_candidates = [
        "datadog-cases-sanitized.json",
        "datadog-cases.json",
        "cases.json",
    ]
    for name in case_candidates:
        fpath = os.path.join(datadog_dir, name)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        parsed_cases: list[dict[str, str]] = []
        for item in _extract_items(data):
            attrs = (
                item.get("attributes", {})
                if isinstance(item.get("attributes"), dict)
                else {}
            )
            sev = _normalize_dd_severity(
                attrs.get("severity")
                or attrs.get("priority")
                or attrs.get("case_priority")
            )
            _inc_sev(case_summary, sev)
            parsed_cases.append(
                {
                    "severity": sev,
                    "status": str(
                        attrs.get("status_name")
                        or attrs.get("status")
                        or attrs.get("case_status")
                        or ""
                    ),
                    "title": str(
                        attrs.get("title") or attrs.get("name") or item.get("id") or ""
                    ),
                    "rule": str(attrs.get("type") or "case"),
                    "source": str(attrs.get("owner") or attrs.get("service") or "case"),
                    "timestamp": str(
                        attrs.get("created_at")
                        or attrs.get("updated_at")
                        or attrs.get("last_modified")
                        or ""
                    ),
                }
            )
        if parsed_cases:
            parsed_cases = sorted(
                parsed_cases,
                key=lambda x: (
                    {
                        "critical": 0,
                        "high": 1,
                        "medium": 2,
                        "low": 3,
                        "info": 4,
                        "unknown": 5,
                    }.get(
                        x.get("severity", "unknown"),
                        9,
                    ),
                    x.get("timestamp", ""),
                ),
            )[:150]
            case_summary["total"] = len(parsed_cases)
            out["cases"] = parsed_cases
        break

    return out


# ── Prowler Analysis ─────────────────────────────────────────────────────────


def analyze_prowler(providers):
    summary = {}
    all_findings = []
    for prov, items in providers.items():
        fails = [i for i in items if i.get("status_code") == "FAIL"]
        passes = [i for i in items if i.get("status_code") == "PASS"]
        by_sev = defaultdict(int)
        for f in fails:
            by_sev[f.get("severity", "Unknown")] += 1
        summary[prov] = {
            "total_fail": len(fails),
            "total_pass": len(passes),
            "critical": by_sev.get("Critical", 0),
            "high": by_sev.get("High", 0),
            "medium": by_sev.get("Medium", 0),
            "low": by_sev.get("Low", 0),
            "informational": by_sev.get("Informational", 0),
        }
        for f in fails:
            fi = f.get("finding_info", {})
            res = f.get("resources", [{}])
            res0 = res[0] if res else {}
            comp = f.get("unmapped", {}).get("compliance", {})
            all_findings.append(
                {
                    "provider": prov,
                    "severity": f.get("severity", "Unknown"),
                    "check": f.get("metadata", {}).get("event_code", ""),
                    "title": fi.get("title", ""),
                    "message": f.get("message", ""),
                    "desc": fi.get("desc", ""),
                    "resource": res0.get("data", {})
                    .get("metadata", {})
                    .get("name", res0.get("region", "")),
                    "related_url": f.get("unmapped", {}).get("related_url", ""),
                    "compliance": comp,
                }
            )
    return summary, all_findings


def github_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "github"]


def aws_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "aws"]


def gcp_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "gcp"]


def gws_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "googleworkspace"]


def k8s_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "kubernetes"]


def azure_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "azure"]


def m365_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "m365"]


# Prowler/GitHub check code → English summary & remediation
CHECK_EN_MAP = {
    "guardduty_is_enabled": {
        "summary": "GuardDuty is disabled or not configured per region; threat detection may be missing.",
        "action": "Enable GuardDuty in each region; configure Finding event alerts (SNS/EventBridge).",
    },
    "iam_role_administratoraccess_policy": {
        "summary": "IAM role has AdministratorAccess policy granting excessive privileges.",
        "action": "Apply least privilege; replace with custom policy containing only required permissions.",
    },
    "awslambda_function_no_secrets_in_variables": {
        "summary": "Lambda environment variables contain secrets (API keys, tokens, etc.).",
        "action": "Use Secrets Manager or Parameter Store; remove secrets from environment variables.",
    },
    "cloudformation_stack_outputs_find_secrets": {
        "summary": "CloudFormation stack outputs contain secret strings and may be exposed.",
        "action": "Remove secrets from outputs; reference sensitive values via SSM/Secrets Manager.",
    },
    "s3_bucket_public_access": {
        "summary": "S3 bucket allows public access or Block Public Access is disabled.",
        "action": "Enable Block Public Access at account/bucket level; review bucket policies.",
    },
    "s3_bucket_no_mfa_delete": {
        "summary": "S3 bucket versioning allows delete without MFA; accidental or malicious deletion risk.",
        "action": "Enable MFA delete for versioned buckets; restrict delete permissions.",
    },
    "rds_instance_public_access": {
        "summary": "RDS instance is publicly accessible; increases exposure to network attacks.",
        "action": "Set RDS to private; use VPC and security groups; access via bastion or VPN.",
    },
    "ec2_instance_public_ip": {
        "summary": "EC2 instance has a public IP; may be exposed to the internet.",
        "action": "Use private subnets and NAT; restrict security groups; avoid unnecessary public IPs.",
    },
    "lambda_function_url_public": {
        "summary": "Lambda function URL is publicly accessible without auth.",
        "action": "Add IAM auth or custom auth; restrict via resource policy and VPC.",
    },
    "cloudtrail_log_file_validation": {
        "summary": "CloudTrail log file validation is disabled; integrity of logs cannot be verified.",
        "action": "Enable log file validation for all trails; monitor and alert on changes.",
    },
    "kms_key_rotation": {
        "summary": "KMS key rotation is disabled; key compromise impact is higher.",
        "action": "Enable automatic key rotation for customer-managed KMS keys.",
    },
    "branch_protection": {
        "summary": "Default branch has no branch protection; force push and delete are possible.",
        "action": "Configure branch protection rules; require PR approval, status checks, linear history.",
    },
    "require_approval": {
        "summary": "PR approval and code review are not required before merge.",
        "action": "Set required number of approvals; apply CODEOWNERS and review policy.",
    },
    "secret_scanning": {
        "summary": "Secret scanning is disabled; committed secrets may not be detected.",
        "action": "Enable secret scanning and push protection; configure alerts.",
    },
    "dependabot": {
        "summary": "Dependency vulnerability alerts and auto-PRs are not configured.",
        "action": "Enable Dependabot alerts and security updates; define patch policy.",
    },
    "code_scanning": {
        "summary": "Code scanning (e.g. CodeQL) is not configured; static analysis may be missing.",
        "action": "Enable CodeQL or equivalent SAST; include scan results in PR checks.",
    },
    "vulnerability_alerts": {
        "summary": "Repository vulnerability alerts are disabled; known CVEs may not be surfaced.",
        "action": "Enable Dependabot or security alerts; fix or dismiss findings per policy.",
    },
    "security_policy": {
        "summary": "Security policy (SECURITY.md) is missing; contributors lack a clear reporting path.",
        "action": "Add SECURITY.md with contact and disclosure policy; consider GitHub Advisory.",
    },
    "default_branch_deletion": {
        "summary": "Default branch can be deleted or force-pushed; repository integrity at risk.",
        "action": "Enable branch protection; disallow force push and branch deletion.",
    },
    "repository_private": {
        "summary": "Repository is public; code and metadata are visible to everyone.",
        "action": "Make repository private or reduce exposed secrets and metadata.",
    },
    "mfa": {
        "summary": "Multi-factor authentication is not enforced for organization or high-privilege access.",
        "action": "Enforce MFA for all members; use conditional access and phishing-resistant methods.",
    },
    "two_factor": {
        "summary": "Two-factor authentication is not required; account takeover risk is higher.",
        "action": "Require 2FA for all users; prefer TOTP or hardware keys.",
    },
    "encrypt": {
        "summary": "Encryption at rest or in transit is missing or weak for sensitive data.",
        "action": "Enable TLS 1.2+ and strong ciphers; use KMS or managed encryption for data at rest.",
    },
    "logging": {
        "summary": "Logging or audit trail is disabled or insufficient for detection and forensics.",
        "action": "Enable relevant logging (CloudTrail, VPC flow, app logs); retain and protect logs.",
    },
    "backup": {
        "summary": "Backups are not configured or not tested; recovery may not be possible.",
        "action": "Enable automated backups; test restore; define RPO/RTO and retention.",
    },
    # GCP-specific checks
    "compute_instance_public_ip": {
        "summary": "Compute Engine instance has a public IP; direct exposure to internet increases attack surface.",
        "action": "Use Cloud NAT or IAP for internet access; remove public IPs where not strictly necessary.",
    },
    "compute_instance_ip_forwarding": {
        "summary": "IP forwarding is enabled on instance; may allow packet routing bypass.",
        "action": "Disable IP forwarding unless the instance is a NAT gateway or load balancer.",
    },
    "compute_firewall": {
        "summary": "Firewall rule allows overly permissive ingress (e.g. 0.0.0.0/0 on sensitive ports).",
        "action": "Restrict source ranges to known IPs/CIDRs; deny by default; limit ports.",
    },
    "iam_sa_key": {
        "summary": "Service account key is user-managed; higher key leakage risk than workload identity.",
        "action": "Use Workload Identity Federation instead of long-lived keys; rotate if keys are required.",
    },
    "iam_user_mfa": {
        "summary": "User account lacks MFA; increases risk of credential-based account takeover.",
        "action": "Enforce 2-Step Verification for all users in Google Admin Console.",
    },
    "storage_bucket_public": {
        "summary": "Cloud Storage bucket is publicly accessible; data exposure risk.",
        "action": "Remove allUsers/allAuthenticatedUsers; apply uniform bucket-level access.",
    },
    "storage_bucket_uniform_access": {
        "summary": "Bucket does not enforce uniform access; mixed ACL and IAM policies can be confusing.",
        "action": "Enable uniform bucket-level access and manage permissions via IAM only.",
    },
    "sql_instance_public": {
        "summary": "Cloud SQL instance has a public IP or allows 0.0.0.0/0 access.",
        "action": "Use private IP and Cloud SQL Proxy; restrict authorized networks.",
    },
    "gke_legacy_abac": {
        "summary": "GKE cluster uses legacy ABAC authorization; less granular than RBAC.",
        "action": "Disable legacy ABAC; use Kubernetes RBAC (Role-Based Access Control).",
    },
    "gke_network_policy": {
        "summary": "GKE cluster does not enforce network policies; pod-to-pod traffic is unrestricted.",
        "action": "Enable network policy enforcement; define ingress/egress rules per namespace.",
    },
    "gke_private_cluster": {
        "summary": "GKE cluster nodes have public IPs; increases lateral movement risk.",
        "action": "Enable private cluster mode; use authorized networks for API server access.",
    },
    "dns_dnssec": {
        "summary": "DNS zone does not have DNSSEC enabled; DNS spoofing risk.",
        "action": "Enable DNSSEC in Cloud DNS managed zones.",
    },
    # Google Workspace-specific checks
    "gws_admin_mfa": {
        "summary": "Admin accounts lack 2-Step Verification; high-privilege account takeover risk.",
        "action": "Enforce 2SV for all admin accounts; prefer security keys.",
    },
    "gws_user_mfa": {
        "summary": "User accounts lack 2-Step Verification; credential-based attack risk.",
        "action": "Enforce 2SV for all users; set enrollment deadline.",
    },
    "gws_oauth_app": {
        "summary": "Unreviewed third-party OAuth app has access to organizational data.",
        "action": "Review and restrict third-party app access in Admin Console > Security > API Controls.",
    },
    "gws_dlp": {
        "summary": "Data Loss Prevention rules are not configured; sensitive data may leave the organization.",
        "action": "Configure DLP rules for Gmail and Drive to detect and protect sensitive data.",
    },
    "gws_password_policy": {
        "summary": "Password policy does not meet minimum complexity or length requirements.",
        "action": "Set minimum password length (14+); enforce complexity; enable password reuse restrictions.",
    },
}

# Fallback when no CHECK_EN_MAP match — so every finding has Summary and Remediation
DEFAULT_SUMMARY = "Security finding from scan. Review the finding details and reference link below for context."
DEFAULT_ACTION = "Review the finding, apply security best practices per your risk appetite, and refer to the official documentation for detailed remediation steps."


def get_check_en(check_name):
    """Return English summary and remediation for a check name (or keyword). Always returns at least fallback text."""
    c = (check_name or "").lower()
    for key, val in CHECK_EN_MAP.items():
        if key in c:
            return {
                "summary": val.get("summary") or DEFAULT_SUMMARY,
                "action": val.get("action") or DEFAULT_ACTION,
            }
    return {"summary": DEFAULT_SUMMARY, "action": DEFAULT_ACTION}


# ── OWASP Top 10:2025 Mapping (Official — released 2025) ─────────────────────

OWASP_2025 = [
    {
        "id": "A01:2025",
        "name": "Broken Access Control",
        "desc": "CORS misconfiguration, privilege escalation, IDOR, SSRF (CWE-200, CWE-918, CWE-352)",
        "summary": "Access control failures allow unauthorized resource access; CORS, privilege escalation, IDOR, or SSRF can expose or manipulate data.",
        "action": "Apply branch protection, PR approval, least privilege; validate and whitelist CORS and SSRF inputs.",
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    },
    {
        "id": "A02:2025",
        "name": "Security Misconfiguration",
        "desc": "Missing security headers, default values unchanged, unnecessary features enabled (CWE-16, CWE-611 XXE)",
        "summary": "Default config, unused features, or weak security headers widen attack surface or expose information.",
        "action": "Apply security headers (CSP, X-Frame-Options); remove default passwords and debug mode; enable minimal features.",
        "url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    },
    {
        "id": "A03:2025",
        "name": "Software Supply Chain Failures",
        "desc": "Third-party dependencies, CI/CD pipelines, unmanaged components (CWE-1104, CWE-1395)",
        "summary": "External libs, build pipelines, or unpatched components can introduce malware or leave known CVEs exploitable.",
        "action": "Enable Dependabot/CodeQL; SBOM and dependency checks; immutable releases and CODEOWNERS for changes.",
        "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    },
    {
        "id": "A04:2025",
        "name": "Cryptographic Failures",
        "desc": "Insufficient encryption for sensitive data; weak algorithms",
        "summary": "Missing encryption in transit or at rest, weak algorithms or fixed keys can leak secrets or PII.",
        "action": "TLS 1.2+, strong ciphers; KMS and key rotation for stored data; never store secrets in plaintext.",
        "url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
    },
    {
        "id": "A05:2025",
        "name": "Injection",
        "desc": "SQL, XSS, Command Injection — 37 CWE mappings",
        "summary": "User input reflected in queries, commands, or output can lead to SQL/OS/code injection or XSS.",
        "action": "Use parameterized queries and prepared statements; input validation and escaping; output encoding; SAST/CodeQL.",
        "url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
    },
    {
        "id": "A06:2025",
        "name": "Insecure Design",
        "desc": "Design-phase security flaws — missing threat modeling and secure design patterns",
        "summary": "Missing threat modeling or security requirements at design can enable logic flaws and business logic bypass.",
        "action": "Perform threat modeling (e.g. STRIDE); security design review; safe defaults and fail-secure design.",
        "url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
    },
    {
        "id": "A07:2025",
        "name": "Authentication Failures",
        "desc": "MFA not enforced, weak passwords, session management flaws",
        "summary": "No MFA, weak password policy, or poor session invalidation can enable account takeover and privilege escalation.",
        "action": "Enforce MFA and SSO; strengthen password policy; session timeout, re-auth, and token invalidation.",
        "url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
    },
    {
        "id": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "desc": "Integrity verification failures — CI/CD, auto-updates, deserialization",
        "summary": "Code applied without signature verification in CI/CD or auto-updates, or deserialization can lead to RCE.",
        "action": "Verify signatures and checksums; least-privilege deployment; webhook secret/signature verification; block untrusted deserialization.",
        "url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    },
    {
        "id": "A09:2025",
        "name": "Security Logging & Alerting Failures",
        "desc": "Insufficient logging and alerting — hinders detection and response",
        "summary": "Lack of logs, audit trail, or alerts makes detection, response, and forensics difficult.",
        "action": "Collect auth, access, and change logs; integrate GuardDuty/Security Hub; define alerting and response procedures.",
        "url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    },
    {
        "id": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "desc": "Error handling and logic errors — 24 CWEs (new)",
        "summary": "Poor exception handling or boundary/logic errors can cause DoS, information disclosure, or unexpected behavior.",
        "action": "Consistent exception handling and user-friendly messages; logic and boundary checks; log detailed errors only.",
        "url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
    },
]

OWASP_CHECK_MAP = {
    "A01:2025": [
        "branch_protection",
        "require_pull_request",
        "require_approval",
        "default_branch_deletion",
        "admin_permission",
        "repository_private",
        "dismiss_stale_review",
        "iam",
        "access",
        "permission",
        "restrict",
        "cors",
        "force_push",
        "ssrf",
        "request_forgery",
    ],
    "A02:2025": [
        "configuration",
        "default",
        "misconfigur",
        "hardening",
        "baseline",
        "cis",
        "benchmark",
        "logging_enabled",
        "security_policy",
        "security_header",
        "xxe",
        "unnecessary",
        "enabled_feature",
    ],
    "A03:2025": [
        "dependency",
        "dependabot",
        "sbom",
        "slsa",
        "provenance",
        "supply_chain",
        "vulnerability_alert",
        "cve",
        "outdated",
        "vulnerable",
        "patch",
        "version",
        "eol",
        "deprecat",
        "immutable_release",
        "codeowners",
    ],
    "A04:2025": [
        "encrypt",
        "tls",
        "ssl",
        "certificate",
        "secret",
        "kms",
        "key_rotation",
        "plaintext",
        "https",
        "cryptograph",
        "weak_cipher",
        "rotation",
    ],
    "A05:2025": [
        "injection",
        "input",
        "sanitiz",
        "escap",
        "parameteriz",
        "codeql",
        "sast",
        "xss",
        "command_injection",
        "sql",
    ],
    "A06:2025": [
        "design",
        "architecture",
        "threat_model",
        "security_review",
        "insecure_design",
    ],
    "A07:2025": [
        "authentication",
        "mfa",
        "password",
        "credential",
        "session",
        "totp",
        "sso",
        "two_factor",
        "2fa",
        "login",
        "brute_force",
    ],
    "A08:2025": [
        "integrity",
        "signing",
        "webhook",
        "deploy_key",
        "signature",
        "cicd",
        "pipeline",
        "auto_update",
        "deserialization",
    ],
    "A09:2025": [
        "logging",
        "monitoring",
        "audit",
        "alert",
        "trace",
        "observ",
        "siem",
        "detection",
        "guardduty",
        "securityhub",
        "cloudtrail",
    ],
    "A10:2025": [
        "error",
        "exception",
        "handler",
        "unhandled",
        "crash",
        "panic",
        "overflow",
        "boundary",
        "validation_error",
        "logic_error",
    ],
}

# ── OWASP Top 10 for LLM Applications 2025 ──────────────────────────────────

OWASP_LLM_2025 = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "desc": "Malicious input causes LLM to perform unintended actions or leak data",
        "summary": "Adversarial instructions or delimiters can override system prompts and cause the LLM to leak secrets or misbehave.",
        "action": "Input validation and sanitization; privilege separation and output filtering; protect system prompt and audit logging.",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "desc": "Secrets, PII, or confidential data in responses or logs",
        "summary": "LLM responses or logs may contain passwords, API keys, or PII and leak via third parties or log pipelines.",
        "action": "Mask responses and logs; minimize PII collection; use env vars or secret managers for secrets.",
        "url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    },
    {
        "id": "LLM03",
        "name": "Supply Chain",
        "desc": "Risks from model providers, datasets, dependencies, and infrastructure",
        "summary": "Unverified provenance of models, datasets, SDKs, or infra can introduce backdoors, malware, or licensing risk.",
        "action": "Use official or verified sources; checksum and signature verification; SBOM and license checks.",
        "url": "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
    },
    {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "desc": "Poisoned training or fine-tuning data to manipulate behavior",
        "summary": "Tampered training or fine-tuning data can make the model learn bias, backdoors, or wrong answers.",
        "action": "Verify data provenance and quality; inspect data before fine-tuning; version and provenance tracking.",
        "url": "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    },
    {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "desc": "Trusting or executing model output without verification",
        "summary": "Executing LLM output as code, commands, or queries can lead to injection or privilege escalation.",
        "action": "Validate and whitelist output; human-in-the-loop and confirmation steps; sandbox and least-privilege execution.",
        "url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    {
        "id": "LLM06",
        "name": "Excessive Agency",
        "desc": "AI agents with excessive autonomy or permissions",
        "summary": "Agents with too much permission or autonomy can cause data loss, cost waste, or policy bypass.",
        "action": "Least privilege and scope limits; require user confirmation; set cost and call limits.",
        "url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    },
    {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "desc": "Extraction of hidden prompts, policy, or tool schemas",
        "summary": "Attackers can use special inputs to expose system prompt, policy, or tool schema in responses.",
        "action": "Isolate and protect prompts; filter output to remove internal instructions; regular red-team testing.",
        "url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
    {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "desc": "RAG store or embeddings as attack surface",
        "summary": "Malicious or poisoned data in RAG or embedding DB can manipulate search results or leak information.",
        "action": "Validate RAG input and access control; verify embedding source trust; filter queries and results.",
        "url": "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    },
    {
        "id": "LLM09",
        "name": "Misinformation",
        "desc": "Confidently generated false information causes harm",
        "summary": "Hallucination or manipulated training can lead to wrong decisions or reputation damage.",
        "action": "Show sources and confidence in output; fact-check and verification steps; inform users of uncertainty.",
        "url": "https://genai.owasp.org/llmrisk/llm09-misinformation/",
    },
    {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "desc": "Abuse leads to cost spike, latency, or capacity exhaustion",
        "summary": "Unlimited use of API, tokens, or resources can cause cost explosion, DoS, or service outage.",
        "action": "Rate limits and quotas; per-user and daily caps; detect and block anomalous traffic.",
        "url": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    },
]


def map_findings_to_owasp(all_findings):
    mapping = {o["id"]: [] for o in OWASP_2025}
    for f in all_findings:
        check = f["check"].lower()
        title = f["title"].lower()
        msg = f["message"].lower()
        text = f"{check} {title} {msg}"
        for oid, keywords in OWASP_CHECK_MAP.items():
            if any(kw in text for kw in keywords):
                mapping[oid].append(f)
                break
    return mapping


# ── Compliance Frameworks ────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = [
    {
        "name": "OWASP Top 10:2025",
        "url": "https://owasp.org/Top10/2025/",
        "desc": "Web application security risks Top 10 (2025)",
    },
    {
        "name": "OWASP LLM Top 10",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
        "desc": "LLM application security risks Top 10 (2025)",
    },
    {
        "name": "NIST 800-53 Rev5",
        "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "desc": "US federal information system security controls",
    },
    {
        "name": "NIST CSF 2.0",
        "url": "https://www.nist.gov/cyberframework",
        "desc": "Cybersecurity Framework 2.0",
    },
    {
        "name": "ISO 27001:2022",
        "url": "https://www.iso.org/isoiec-27001-information-security.html",
        "desc": "Information security management system (ISMS) international standard",
    },
    {
        "name": "ISO 27701:2025",
        "url": "https://www.iso.org/standard/85819.html",
        "desc": "Privacy information management (PIMS) — certifiable",
    },
    {
        "name": "PCI-DSS v4.0.1",
        "url": "https://www.pcisecuritystandards.org/document_library/?category=pcidss",
        "desc": "Payment Card Industry Data Security Standard",
    },
    {
        "name": "KISA ISMS-P",
        "url": "https://isms.kisa.or.kr/main/ispims/intro/",
        "desc": "Korea information security and privacy management certification",
    },
    {
        "name": "CIS Benchmarks",
        "url": "https://www.cisecurity.org/cis-benchmarks",
        "desc": "Center for Internet Security benchmarks",
    },
    {
        "name": "SLSA v1.0",
        "url": "https://slsa.dev/spec/v1.0/",
        "desc": "Supply chain Levels for Software Artifacts",
    },
    {
        "name": "MITRE ATT&CK",
        "url": "https://attack.mitre.org/",
        "desc": "Cyber attack tactics, techniques, and procedures (TTP) knowledge base",
    },
]

COMPLIANCE_CONTROL_MAP = {
    "ISO 27001:2022": [
        {
            "control": "A.5.1",
            "name": "Information security policy",
            "desc": "Policies documented, shared, and reviewed",
            "action": "Document policy, periodic review, staff training and approval.",
            "checks": ["security_policy"],
            "status": "",
        },
        {
            "control": "A.8.2",
            "name": "Access control",
            "desc": "Access to resources and systems restricted by role and need",
            "action": "Apply RBAC, branch protection, PR approval; minimize admin rights.",
            "checks": ["branch_protection", "require_approval", "admin"],
            "status": "",
        },
        {
            "control": "A.8.5",
            "name": "Secure authentication",
            "desc": "Strong authentication (MFA, SSO) in use",
            "action": "Adopt MFA and SSO; strengthen password policy and session management.",
            "checks": ["mfa", "two_factor", "sso", "authentication"],
            "status": "",
        },
        {
            "control": "A.8.9",
            "name": "Configuration management",
            "desc": "Config and defaults managed per security baseline",
            "action": "Apply hardening guides; change defaults; disable unnecessary services.",
            "checks": ["configuration", "misconfigur", "default"],
            "status": "",
        },
        {
            "control": "A.8.24",
            "name": "Cryptography",
            "desc": "Encryption and key management for data in transit and at rest",
            "action": "Use TLS and KMS; store secrets in secret manager; key rotation.",
            "checks": ["encrypt", "tls", "ssl", "secret"],
            "status": "",
        },
        {
            "control": "A.8.28",
            "name": "Secure coding",
            "desc": "Secure coding and SAST for vulnerability management",
            "action": "Adopt CodeQL/SAST, code review; prevent injection and XSS.",
            "checks": ["code_scanning", "sast", "injection", "codeql"],
            "status": "",
        },
        {
            "control": "A.8.8",
            "name": "Technical vulnerability management",
            "desc": "Dependency, CVE detection, and patching in place",
            "action": "Dependabot and CVE scanning; patch policy and SBOM.",
            "checks": ["dependabot", "cve", "vulnerability", "outdated"],
            "status": "",
        },
    ],
    "KISA ISMS-P": [
        {
            "control": "2.6.1",
            "name": "Access control policy",
            "desc": "Access control policy and access rights management",
            "action": "Document access policy; least privilege; periodic permission review.",
            "checks": ["branch_protection", "access", "permission", "restrict"],
            "status": "",
        },
        {
            "control": "2.6.2",
            "name": "Authentication and authorization",
            "desc": "Strong authentication and separation of duties",
            "action": "MFA and SSO; separate admin accounts; track permission changes.",
            "checks": ["mfa", "authentication", "sso", "two_factor", "admin"],
            "status": "",
        },
        {
            "control": "2.7.1",
            "name": "Cryptographic policy",
            "desc": "Encryption and key management policy",
            "action": "TLS and encryption at rest; key protection and rotation; no plaintext secrets.",
            "checks": ["encrypt", "tls", "ssl", "secret", "kms"],
            "status": "",
        },
        {
            "control": "2.9.1",
            "name": "Change management",
            "desc": "Change request, review, and approval process",
            "action": "PR and approval workflow; change log and rollback procedure.",
            "checks": ["require_approval", "review", "pull_request"],
            "status": "",
        },
        {
            "control": "2.11.1",
            "name": "Incident response",
            "desc": "Detection, response, and recovery",
            "action": "Logging, monitoring, alerting; response playbook; post-incident analysis.",
            "checks": ["monitoring", "logging", "alert", "audit"],
            "status": "",
        },
        {
            "control": "2.12.1",
            "name": "Privacy protection",
            "desc": "Prevent exposure of PII and sensitive data",
            "action": "Secret scanning; no plaintext storage; access log and masking.",
            "checks": ["secret_scanning", "credential", "plaintext"],
            "status": "",
        },
    ],
    "PCI-DSS v4.0.1": [
        {
            "control": "Req 1",
            "name": "Network security controls",
            "desc": "Firewall, network segmentation, TLS",
            "action": "Firewall policy; DMZ and segmentation; enforce TLS.",
            "checks": ["firewall", "network", "tls"],
            "status": "",
        },
        {
            "control": "Req 2",
            "name": "Secure configuration",
            "desc": "Hardened system and service settings",
            "action": "Hardening; change default passwords; remove unnecessary services.",
            "checks": ["configuration", "default", "hardening", "benchmark"],
            "status": "",
        },
        {
            "control": "Req 3",
            "name": "Protect stored data",
            "desc": "Encryption and key management for cardholder data",
            "action": "Encrypt at rest; KMS and key rotation; consider tokenization.",
            "checks": ["encrypt", "kms", "key_rotation"],
            "status": "",
        },
        {
            "control": "Req 6",
            "name": "Secure software development",
            "desc": "Secure SDLC and vulnerability management",
            "action": "SAST and dependency checks; patching and code review.",
            "checks": ["code_scanning", "sast", "injection", "vulnerability"],
            "status": "",
        },
        {
            "control": "Req 7",
            "name": "Access restriction",
            "desc": "Access only for those who need it",
            "action": "RBAC and least privilege; branch protection and approval policy.",
            "checks": ["branch_protection", "permission", "restrict", "admin"],
            "status": "",
        },
        {
            "control": "Req 8",
            "name": "User identification and authentication",
            "desc": "Strong authentication and account management",
            "action": "MFA; password policy; account lockout and session management.",
            "checks": ["mfa", "authentication", "two_factor", "sso"],
            "status": "",
        },
        {
            "control": "Req 10",
            "name": "Logging and monitoring",
            "desc": "Logs and monitoring for access, change, and incidents",
            "action": "Collect and retain audit logs; detection and alerting; periodic review.",
            "checks": ["logging", "monitoring", "audit", "alert"],
            "status": "",
        },
    ],
}


def map_compliance(all_findings):
    result = {}
    for framework, controls in COMPLIANCE_CONTROL_MAP.items():
        mapped = []
        for ctrl in controls:
            matching = []
            for f in all_findings:
                text = f"{f['check']} {f['title']} {f['message']}".lower()
                if any(kw in text for kw in ctrl["checks"]):
                    matching.append(f)
            status = "PASS" if len(matching) == 0 else "FAIL"
            mapped.append(
                {
                    **ctrl,
                    "status": status,
                    "count": len(matching),
                    "findings": matching[:5],
                }
            )
        result[framework] = mapped
    return result


# ── Architecture Security Domains ────────────────────────────────────────────

ARCH_DOMAINS = [
    {
        "name": "Network & TLS",
        "icon": "🌐",
        "checks": ["tls", "ssl", "https", "certificate", "network", "firewall", "dns"],
        "summary": "TLS/SSL, certificates, firewall and DNS for secure communication.",
        "action": "TLS 1.2+ and strong ciphers; monitor cert expiry; block unnecessary ports.",
    },
    {
        "name": "Identity & Access",
        "icon": "🔑",
        "checks": [
            "mfa",
            "sso",
            "iam",
            "access",
            "permission",
            "admin",
            "authentication",
            "two_factor",
            "branch_protection",
            "require_approval",
        ],
        "summary": "IAM, MFA, branch protection, PR approval for access control and authentication.",
        "action": "Apply MFA and SSO; least privilege and RBAC; branch protection and mandatory code review.",
    },
    {
        "name": "Data protection",
        "icon": "🔒",
        "checks": [
            "encrypt",
            "secret",
            "kms",
            "key_rotation",
            "plaintext",
            "credential",
            "secret_scanning",
        ],
        "summary": "Encryption, secret and key management, secret scanning to prevent data exposure.",
        "action": "Encrypt in transit and at rest; KMS and rotation; use secret manager; scan code for secrets.",
    },
    {
        "name": "CI/CD pipeline",
        "icon": "⚡",
        "checks": [
            "pipeline",
            "workflow",
            "deploy",
            "action",
            "cicd",
            "webhook",
            "deploy_key",
            "signing",
        ],
        "summary": "Build and deploy pipelines; webhooks and signing for integrity and safe deployment.",
        "action": "Least privilege for workflows; webhook signature verification; manage deploy keys and signing; audit logs.",
    },
    {
        "name": "Monitoring & logging",
        "icon": "📊",
        "checks": ["logging", "monitoring", "audit", "alert", "detection", "siem"],
        "summary": "Logs, audit, and alerts for detection and incident response.",
        "action": "Integrate GuardDuty, Security Hub; collect and retain logs; alerting and response procedures.",
    },
    {
        "name": "Supply chain",
        "icon": "📦",
        "checks": [
            "dependency",
            "dependabot",
            "sbom",
            "slsa",
            "provenance",
            "vulnerability_alert",
            "cve",
            "outdated",
        ],
        "summary": "Dependencies, CVE, and SBOM for supply chain vulnerability management.",
        "action": "Dependabot and CVE scanning; generate and verify SBOM; immutable releases and patch policy.",
    },
]

# Mapping: architecture domains ↔ OWASP / compliance / scanner categories
ARCH_DOMAIN_LINKS = [
    {
        "owasp": ["A02", "A05", "A09"],
        "compliance": [
            ("ISO 27001:2022", "A.8.9"),
            ("PCI-DSS v4.0.1", "Req 1"),
            ("PCI-DSS v4.0.1", "Req 2"),
        ],
        "scanner": ["network"],
    },
    {
        "owasp": ["A01", "A07"],
        "compliance": [
            ("ISO 27001:2022", "A.8.2"),
            ("ISO 27001:2022", "A.8.5"),
            ("KISA ISMS-P", "2.6.1"),
            ("KISA ISMS-P", "2.6.2"),
            ("PCI-DSS v4.0.1", "Req 7"),
            ("PCI-DSS v4.0.1", "Req 8"),
        ],
        "scanner": ["access-control"],
    },
    {
        "owasp": ["A04", "A02"],
        "compliance": [
            ("ISO 27001:2022", "A.8.24"),
            ("KISA ISMS-P", "2.7.1"),
            ("PCI-DSS v4.0.1", "Req 3"),
        ],
        "scanner": ["access-control", "code"],
    },
    {
        "owasp": ["A03", "A08"],
        "compliance": [
            ("ISO 27001:2022", "A.8.28"),
            ("KISA ISMS-P", "2.9.1"),
            ("PCI-DSS v4.0.1", "Req 6"),
        ],
        "scanner": ["cicd"],
    },
    {
        "owasp": ["A09"],
        "compliance": [
            ("ISO 27001:2022", "A.8.2"),
            ("KISA ISMS-P", "2.11.1"),
            ("PCI-DSS v4.0.1", "Req 10"),
        ],
        "scanner": ["cloud", "infra"],
    },
    {
        "owasp": ["A03", "A08"],
        "compliance": [("ISO 27001:2022", "A.8.8"), ("PCI-DSS v4.0.1", "Req 6")],
        "scanner": ["cicd", "code", "infra"],
    },
]

# OWASP → related architecture domains (reverse mapping)
OWASP_TO_ARCH = {
    "A01": [1],
    "A02": [0, 2],
    "A03": [3, 5],
    "A04": [2],
    "A05": [0],
    "A06": [],
    "A07": [1],
    "A08": [3, 5],
    "A09": [0, 4],
    "A10": [],
}


def map_architecture(all_findings):
    result = []
    for i, domain in enumerate(ARCH_DOMAINS):
        matching = []
        for f in all_findings:
            text = f"{f['check']} {f['title']} {f['message']}".lower()
            if any(kw in text for kw in domain["checks"]):
                matching.append(f)
        links = (
            ARCH_DOMAIN_LINKS[i]
            if i < len(ARCH_DOMAIN_LINKS)
            else {"owasp": [], "compliance": [], "scanner": []}
        )
        result.append(
            {
                **domain,
                "fail_count": len(matching),
                "findings": matching[:10],
                "links": links,
            }
        )
    return result


# ── Environment Status ───────────────────────────────────────────────────────


def get_env_status():
    envs = []
    items = [
        (
            "🐙",
            "GitHub",
            "CLAUDESEC_ENV_GITHUB_CONNECTED",
            "github",
            "GH_TOKEN/GITHUB_TOKEN or gh auth login",
        ),
        (
            "☸",
            "Kubernetes",
            "CLAUDESEC_ENV_K8S_CONNECTED",
            "k8s",
            "kubeconfig/kubecontext",
        ),
        ("☁", "AWS", "CLAUDESEC_ENV_AWS_CONNECTED", "aws", "--aws-profile"),
        ("◈", "GCP", "CLAUDESEC_ENV_GCP_CONNECTED", "gcp", "gcloud auth login"),
        ("◇", "Azure", "CLAUDESEC_ENV_AZ_CONNECTED", "azure", "az login"),
        (
            "📧",
            "Microsoft 365",
            "CLAUDESEC_ENV_M365_CONNECTED",
            "m365",
            "AZURE_CLIENT_ID/TENANT_ID/CLIENT_SECRET",
        ),
        (
            "🔐",
            "Okta",
            "CLAUDESEC_ENV_OKTA_CONNECTED",
            "okta",
            "OKTA_OAUTH_TOKEN or OKTA_API_TOKEN",
        ),
        (
            "🏢",
            "Google Workspace",
            "CLAUDESEC_ENV_GWS_CONNECTED",
            "gws",
            "GOOGLE_WORKSPACE_CUSTOMER_ID",
        ),
        (
            "🌐",
            "Cloudflare",
            "CLAUDESEC_ENV_CF_CONNECTED",
            "cloudflare",
            "CLOUDFLARE_API_TOKEN",
        ),
        (
            "☁",
            "NHN Cloud",
            "CLAUDESEC_ENV_NHN_CONNECTED",
            "nhn",
            "NHN_API_URL/OS_AUTH_URL",
        ),
        (
            "🤖",
            "LLM",
            "CLAUDESEC_ENV_LLM_CONNECTED",
            "llm",
            "OPENAI_API_KEY/ANTHROPIC_API_KEY",
        ),
        (
            "📊",
            "Datadog",
            "CLAUDESEC_ENV_DATADOG_CONNECTED",
            "datadog",
            "DD_API_KEY/DD_APP_KEY",
        ),
    ]
    for icon, name, env_var, setup_id, hint in items:
        connected = os.environ.get(env_var, "false") == "true"
        envs.append(
            {
                "icon": icon,
                "name": name,
                "connected": connected,
                "setup_id": setup_id,
                "hint": hint,
            }
        )
    return envs


def _parse_expiry_datetime(raw_value):
    if raw_value is None:
        return None
    raw = str(raw_value).strip()
    if not raw:
        return None
    try:
        if raw.isdigit():
            return datetime.fromtimestamp(int(raw), timezone.utc)
    except Exception:
        pass
    try:
        norm = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(norm)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _jwt_expiry_datetime(token_value):
    token = (token_value or "").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    try:
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode(
            "utf-8"
        )
        payload = json.loads(payload_json)
    except Exception:
        return None
    exp = payload.get("exp")
    try:
        if exp is None:
            return None
        return datetime.fromtimestamp(int(exp), timezone.utc)
    except Exception:
        return None


def _collect_token_expiry_items():
    candidates = [
        (
            "Okta OAuth",
            os.environ.get("OKTA_OAUTH_TOKEN_EXPIRES_AT", ""),
            os.environ.get("OKTA_OAUTH_TOKEN", ""),
        ),
        (
            "GitHub",
            os.environ.get("GITHUB_TOKEN_EXPIRES_AT", "")
            or os.environ.get("GH_TOKEN_EXPIRES_AT", ""),
            "",
        ),
    ]
    out = []
    for provider, explicit_raw, token in candidates:
        expiry = _parse_expiry_datetime(explicit_raw)
        source = "env"
        if expiry is None and token:
            expiry = _jwt_expiry_datetime(token)
            source = "jwt"
        if expiry is None:
            continue
        out.append({"provider": provider, "expiry": expiry, "source": source})
    return out


def _parse_duration_seconds(raw_value, default_seconds, default_unit):
    raw = (raw_value or "").strip().lower()
    if not raw:
        return default_seconds, "default"
    unit_map = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if raw[-1:] in unit_map:
        num = raw[:-1]
        if num.isdigit() and int(num) > 0:
            return int(num) * unit_map[raw[-1]], "env"
        return default_seconds, "default"
    if raw.isdigit() and int(raw) > 0:
        factor = 3600 if default_unit == "h" else 86400
        return int(raw) * factor, "env"
    return default_seconds, "default"


def _duration_label(seconds):
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def build_auth_summary_html(envs, findings_list):
    oauth_provider_names = [
        "GitHub",
        "Google Workspace",
        "Microsoft 365",
        "Okta",
    ]
    connected_map = {
        e.get("name", ""): bool(e.get("connected", False)) for e in (envs or [])
    }
    connected = [p for p in oauth_provider_names if connected_map.get(p, False)]
    missing = [p for p in oauth_provider_names if not connected_map.get(p, False)]
    total = len(oauth_provider_names)
    connected_count = len(connected)
    readiness = int(round((connected_count / total) * 100)) if total else 0

    auth_keywords = (
        "auth",
        "oauth",
        "token",
        "session",
        "mfa",
        "login",
        "sso",
        "jwt",
    )
    auth_finding_count = 0
    for f in findings_list or []:
        text = (
            str(f.get("id", ""))
            + " "
            + str(f.get("title", ""))
            + " "
            + str(f.get("details", ""))
        ).lower()
        if any(k in text for k in auth_keywords):
            auth_finding_count += 1

    now_utc = datetime.now(timezone.utc)
    warning_24h_seconds, warning_24h_source = _parse_duration_seconds(
        os.environ.get("CLAUDESEC_TOKEN_EXPIRY_WARNING_24H", ""), 86400, "h"
    )
    warning_7d_seconds, warning_7d_source = _parse_duration_seconds(
        os.environ.get("CLAUDESEC_TOKEN_EXPIRY_WARNING_7D", ""), 7 * 86400, "d"
    )
    if warning_7d_seconds < warning_24h_seconds:
        warning_7d_seconds = warning_24h_seconds
    horizon_24h = now_utc.timestamp() + warning_24h_seconds
    horizon_7d = now_utc.timestamp() + warning_7d_seconds
    window_24_label = _duration_label(warning_24h_seconds)
    window_7_label = _duration_label(warning_7d_seconds)
    token_expiry_items = _collect_token_expiry_items()
    expiring_24h = []
    expiring_7d = []
    expired = []
    for item in token_expiry_items:
        expiry_ts = item["expiry"].timestamp()
        if expiry_ts < now_utc.timestamp():
            expired.append(item)
        elif expiry_ts <= horizon_24h:
            expiring_24h.append(item)
        elif expiry_ts <= horizon_7d:
            expiring_7d.append(item)

    def _remaining_label(expiry_dt):
        delta = int(expiry_dt.timestamp() - now_utc.timestamp())
        if delta < 0:
            minutes = abs(delta) // 60
            return f"expired {minutes}m ago"
        hours = delta // 3600
        minutes = (delta % 3600) // 60
        if hours > 0:
            return f"{hours}h {minutes}m left"
        return f"{minutes}m left"

    token_lines = ""
    for item in sorted(token_expiry_items, key=lambda x: x["expiry"]):
        badge_cls = "low"
        if item in expired:
            badge_cls = "critical"
        elif item in expiring_24h:
            badge_cls = "critical"
        elif item in expiring_7d:
            badge_cls = "warning"
        token_lines += (
            '<div style="display:flex;justify-content:space-between;gap:.75rem;padding:.35rem 0;border-bottom:1px dashed var(--border)">'
            + f'<span><strong>{h(item["provider"])}</strong> <span class="badge {badge_cls}">{h(_remaining_label(item["expiry"]))}</span></span>'
            + f'<span class="mono" style="color:var(--muted)">{h(item["expiry"].strftime("%Y-%m-%d %H:%M UTC"))}</span>'
            + "</div>"
        )

    connected_html = (
        "".join(
            f'<span class="trust-badge trust-ms" style="margin:0 .35rem .35rem 0">{h(name)}</span>'
            for name in connected
        )
        if connected
        else '<span style="color:var(--muted)">No OAuth provider is currently connected.</span>'
    )
    missing_html = (
        "".join(
            f'<span class="trust-badge trust-gov" style="margin:0 .35rem .35rem 0">{h(name)}</span>'
            for name in missing
        )
        if missing
        else '<span class="trust-badge trust-ms" style="margin:0 .35rem .35rem 0">All target providers connected</span>'
    )

    practices = [
        {
            "title": "Use Authorization Code + PKCE for OAuth clients",
            "detail": "Avoid implicit/password grants, and enforce PKCE (S256) for browser-based and public clients.",
            "source_label": "RFC 9700",
            "source_url": "https://datatracker.ietf.org/doc/html/rfc9700",
        },
        {
            "title": "Store tokens in server-side sessions when possible",
            "detail": "Prefer HttpOnly + Secure + SameSite cookies and avoid long-lived access tokens in browser storage.",
            "source_label": "OWASP OAuth 2.0 Cheat Sheet",
            "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Security_Cheat_Sheet.html",
        },
        {
            "title": "Apply least privilege and scope minimization",
            "detail": "Limit requested scopes and rotate high-impact credentials on a defined cadence.",
            "source_label": "NIST SP 800-53 AC-6",
            "source_url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        },
        {
            "title": "Enforce MFA for privileged identities",
            "detail": "Require phishing-resistant MFA for admin or security-sensitive scan integrations.",
            "source_label": "CIS Controls",
            "source_url": "https://www.cisecurity.org/controls",
        },
    ]

    practices_html = ""
    for item in practices:
        practices_html += (
            '<li style="margin:.45rem 0">'
            + f"<strong>{h(item['title'])}</strong><br>"
            + f'<span style="color:var(--muted)">{h(item["detail"])}</span> '
            + f'<a href="{h(item["source_url"])}" target="_blank" rel="noopener" class="ref-link" style="margin-top:0">{h(item["source_label"])}</a>'
            + "</li>"
        )

    threshold_badges_html = (
        '<span class="trust-badge trust-ms" style="margin-left:.5rem">'
        + f"Active windows: &lt;{h(window_24_label)} and {h(window_24_label)}-{h(window_7_label)}"
        + "</span>"
        + '<span class="trust-badge trust-gov" style="margin-left:.35rem">'
        + f"Threshold source: &lt;{h(window_24_label)}={h(warning_24h_source)}, {h(window_7_label)}={h(warning_7d_source)}"
        + "</span>"
    )

    return (
        '<div class="card">'
        '<div class="card-title">OAuth &amp; authentication scan readiness'
        + threshold_badges_html
        + "</div>"
        '<div style="padding:1rem 1.25rem">'
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem;margin-bottom:1rem">'
        + f'<div class="stat-pill sp-info" style="margin:0"><div class="sp-icon">🔐</div><div><div class="sp-num">{connected_count}/{total}</div><div class="sp-label">OAuth providers connected</div></div></div>'
        + f'<div class="stat-pill sp-warn" style="margin:0"><div class="sp-icon">🧪</div><div><div class="sp-num">{auth_finding_count}</div><div class="sp-label">Auth-related findings</div></div></div>'
        + f'<div class="stat-pill sp-pass" style="margin:0"><div class="sp-icon">📈</div><div><div class="sp-num">{readiness}%</div><div class="sp-label">Readiness</div></div></div>'
        + f'<div class="stat-pill {("sp-warn" if len(expiring_24h) > 0 or len(expired) > 0 else "sp-info")}" style="margin:0"><div class="sp-icon">⏳</div><div><div class="sp-num">{len(expiring_24h)}</div><div class="sp-label">Tokens expiring &lt;{h(window_24_label)}</div></div></div>'
        + f'<div class="stat-pill {("sp-warn" if len(expiring_7d) > 0 else "sp-info")}" style="margin:0"><div class="sp-icon">🗓️</div><div><div class="sp-num">{len(expiring_7d)}</div><div class="sp-label">Tokens expiring {h(window_24_label)}-{h(window_7_label)}</div></div></div>'
        + "</div>"
        + '<div style="margin-bottom:.75rem"><strong>Connected</strong><div style="margin-top:.4rem">'
        + connected_html
        + "</div></div>"
        + '<div style="margin-bottom:.9rem"><strong>Missing (recommended to onboard)</strong><div style="margin-top:.4rem">'
        + missing_html
        + "</div></div>"
        + '<div style="margin-bottom:.9rem"><strong>Known token expiries</strong><div style="margin-top:.35rem">'
        + (
            token_lines
            if token_lines
            else '<span style="color:var(--muted)">No token expiry metadata detected. Optional env vars: GITHUB_TOKEN_EXPIRES_AT, GH_TOKEN_EXPIRES_AT, OKTA_OAUTH_TOKEN_EXPIRES_AT.</span>'
        )
        + "</div>"
        + (
            f'<div style="margin-top:.45rem;color:{("#ef4444" if len(expired) > 0 else "#f59e0b")};font-size:.8rem">Expired tokens: {len(expired)} · Expiring &lt;{h(window_24_label)}: {len(expiring_24h)} · Expiring {h(window_24_label)}-{h(window_7_label)}: {len(expiring_7d)}</div>'
            if (len(expired) > 0 or len(expiring_24h) > 0 or len(expiring_7d) > 0)
            else f'<div style="margin-top:.45rem;color:var(--muted);font-size:.8rem">No known tokens are expiring within {h(window_7_label)}.</div>'
        )
        + "</div>"
        + '<div><strong>Best-practice improvements</strong><ul style="margin:.5rem 0 0 1.1rem">'
        + practices_html
        + "</ul></div>"
        + "</div></div>"
    )


# ── HTML Generation ──────────────────────────────────────────────────────────


def h(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def comp_slug(fw):
    return (
        "comp-"
        + "".join(
            c for c in fw.replace(" ", "-").replace(":", "") if c.isalnum() or c == "-"
        ).lower()[:25]
    )


def sev_badge(sev):
    s = sev.lower()
    cls = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "warning": "warning",
        "low": "low",
        "informational": "info",
    }.get(s, "info")
    label = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "warning": "Warning",
        "low": "Low",
        "informational": "Info",
    }.get(s, s)
    return f'<span class="badge {cls}">{label}</span>'


# Scanner category metadata (used by _build_scanner_section)
CATEGORY_META = {
    "access-control": {
        "icon": "🔑",
        "label": "Access control & IAM",
        "desc": "Checks for secret exposure, .env handling, auth tokens, cookie security.",
    },
    "infra": {
        "icon": "🏗️",
        "label": "Infrastructure",
        "desc": "Docker, Kubernetes, IaC security configuration.",
    },
    "network": {
        "icon": "🌐",
        "label": "Network security",
        "desc": "TLS/SSL, certificates, cipher suites.",
    },
    "cicd": {
        "icon": "⚙️",
        "label": "CI/CD pipeline",
        "desc": "GitHub Actions workflow permissions, secret exposure, dependency review.",
    },
    "code": {
        "icon": "💻",
        "label": "Code (SAST)",
        "desc": "Injection, XSS, hardcoded secrets and other code flaws.",
    },
    "ai": {
        "icon": "🤖",
        "label": "AI / LLM security",
        "desc": "Prompt injection, model config, API key protection.",
    },
    "cloud": {
        "icon": "☁️",
        "label": "Cloud (AWS/GCP/Azure)",
        "desc": "Cloud infra config, IAM policies, storage access.",
    },
    "macos": {
        "icon": "🍎",
        "label": "macOS / CIS benchmark",
        "desc": "FileVault, firewall, SIP, Gatekeeper per CIS.",
    },
    "saas": {
        "icon": "🔌",
        "label": "SaaS & solutions",
        "desc": "GitHub, Vercel, ArgoCD, Sentry and other SaaS security.",
    },
    "windows": {
        "icon": "🪟",
        "label": "Windows (KISA)",
        "desc": "Windows security policy and settings per KISA.",
    },
    "prowler": {
        "icon": "🔍",
        "label": "Prowler deep scan",
        "desc": "Prowler multi-cloud security scan results.",
    },
    "other": {"icon": "📋", "label": "Other", "desc": "Uncategorized security checks."},
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4}


def _infer_category(fid):
    prefix = fid.split("-")[0].upper() if "-" in fid else fid.upper()
    return {
        "IAM": "access-control",
        "INFRA": "infra",
        "NET": "network",
        "TLS": "network",
        "CICD": "cicd",
        "CODE": "code",
        "SAST": "code",
        "AI": "ai",
        "LLM": "ai",
        "CLOUD": "cloud",
        "AWS": "cloud",
        "GCP": "cloud",
        "AZURE": "cloud",
        "MAC": "macos",
        "CIS": "macos",
        "SAAS": "saas",
        "WIN": "windows",
        "KISA": "windows",
        "PROWLER": "prowler",
        "DOCKER": "infra",
        "TRIVY": "network",
        "NMAP": "network",
    }.get(prefix, "other")


def _build_scanner_section(findings_list):
    SCANNER_TO_ARCH = {
        "network": [0],
        "access-control": [1, 2],
        "code": [2, 5],
        "cicd": [3, 5],
        "cloud": [4],
        "infra": [4, 5],
        "macos": [],
        "ai": [],
        "saas": [],
        "windows": [],
        "prowler": [],
        "other": [],
    }
    cat_order = [
        "access-control",
        "infra",
        "network",
        "cicd",
        "code",
        "ai",
        "cloud",
        "macos",
        "saas",
        "windows",
        "prowler",
        "other",
    ]
    grouped = defaultdict(list)
    for f in findings_list:
        cat = f.get("category") or _infer_category(f.get("id", ""))
        grouped[cat].append(f)
    scanner_rows = ""
    scanner_cat_summary = ""
    for cat in cat_order:
        items = grouped.get(cat, [])
        if not items:
            continue
        items.sort(key=lambda x: SEV_ORDER.get(x.get("severity", "medium"), 9))
        meta = CATEGORY_META.get(cat, CATEGORY_META["other"])
        arch_links = ""
        for aidx in SCANNER_TO_ARCH.get(cat, []):
            if aidx < len(ARCH_DOMAINS):
                d = ARCH_DOMAINS[aidx]
                arch_links += f'<button class="arch-link-chip arch-sm" onclick="switchTab(\'arch\',\'arch-dom-{aidx}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
        arch_row = (
            f'<div class="scanner-arch-links"><span class="arch-links-label">Related architecture</span>{arch_links}</div>'
            if arch_links
            else ""
        )
        scanner_rows += f'<tr class="cat-header" id="scanner-cat-{cat}"><td colspan="5"><span class="cat-hdr-icon">{meta["icon"]}</span> {h(meta["label"])}<span class="cat-hdr-desc">{h(meta["desc"])}</span>{arch_row}</td></tr>'
        for f in items:
            sev = f.get("severity", "medium")
            sev_cls = f"sev-{sev}"
            badge = sev_badge(sev)
            fid = h(f.get("id", ""))
            title = h(f.get("title", ""))
            details = h(f.get("details", ""))
            status_icon = "✗" if sev in ("critical", "high", "medium") else "⚠"
            status_label = (
                "Fail" if sev in ("critical", "high", "medium") else "Warning"
            )
            scanner_rows += f'<tr class="{sev_cls}"><td>{badge}</td><td><span class="scan-status-{sev}">{status_icon} {status_label}</span></td><td class="mono">{fid}</td><td>{title}</td><td class="fix">{details if details else "<em>-</em>"}</td></tr>'
        scanner_cat_summary += f'<div class="scat-chip"><span class="scat-icon">{meta["icon"]}</span><span class="scat-label">{meta["label"]}</span><span class="scat-cnt">{len(items)}</span></div>'
    if not scanner_rows:
        scanner_rows = '<tr><td colspan="5" class="scan-empty" style="padding:1.5rem;text-align:center;color:var(--muted);font-size:.9rem">No failed or warning findings from the local scanner. All reported checks passed or were skipped.</td></tr>'
    return scanner_rows, scanner_cat_summary


def _build_overview_blocks(
    prov_summary,
    all_findings,
    envs,
    net_data,
    datadog_data,
    passed,
    total_prowler_pass,
    warnings,
    findings_list=None,
):
    findings_list = findings_list or []
    n_crit = sum(v["critical"] for v in prov_summary.values())
    n_high = sum(v["high"] for v in prov_summary.values())
    n_med = sum(v["medium"] for v in prov_summary.values())
    n_low = sum(v["low"] for v in prov_summary.values())
    n_info = sum(v.get("informational", 0) for v in prov_summary.values())
    # Merge scanner findings into severity counts for unified bar
    for f in findings_list:
        sev = (f.get("severity") or "").lower()
        if sev == "critical":
            n_crit += 1
        elif sev == "high":
            n_high += 1
        elif sev == "medium":
            n_med += 1
        elif sev == "low":
            n_low += 1
    prov_cards = ""
    prov_icons = {
        "aws": "☁",
        "github": "🐙",
        "iac": "📋",
        "kubernetes": "☸",
        "azure": "◇",
        "gcp": "◈",
        "googleworkspace": "🏢",
        "m365": "📧",
        "cloudflare": "🌐",
        "nhn": "☁",
    }
    prov_labels = {
        "aws": "AWS",
        "github": "GitHub",
        "iac": "IaC",
        "kubernetes": "K8s",
        "azure": "Azure",
        "gcp": "GCP",
        "googleworkspace": "Google Workspace",
        "m365": "Microsoft 365",
        "cloudflare": "Cloudflare",
        "nhn": "NHN Cloud",
    }
    for pname, pdata in sorted(prov_summary.items()):
        icon = prov_icons.get(pname, "☁")
        label = prov_labels.get(pname, pname)
        ptotal = pdata["total_fail"] + pdata["total_pass"]
        pfail = pdata["total_fail"]
        pcrit = pdata["critical"]
        phigh = pdata["high"]
        prov_cards += '<div class="prov-card" onclick="switchTab(\'prowler\')">'
        prov_cards += f'<div class="prov-card-icon">{icon}</div><div class="prov-card-name">{label}</div>'
        prov_cards += f'<div class="prov-card-num">{pfail}<span class="prov-card-total">/{ptotal}</span></div><div class="prov-card-sev">'
        if pcrit > 0:
            prov_cards += f'<span class="pcs-crit">{pcrit}C</span>'
        if phigh > 0:
            prov_cards += f'<span class="pcs-high">{phigh}H</span>'
        if pdata["medium"] > 0:
            prov_cards += f'<span class="pcs-med">{pdata["medium"]}M</span>'
        prov_cards += "</div></div>"
    sev_total = max(n_crit + n_high + n_med + n_low + warnings, 1)
    bar_crit = round(n_crit / sev_total * 100, 1)
    bar_high = round(n_high / sev_total * 100, 1)
    bar_med = round(n_med / sev_total * 100, 1)
    bar_warn = round(warnings / sev_total * 100, 1)
    bar_low = round(n_low / sev_total * 100, 1)
    # Top findings: merge scanner critical/high with Prowler; group by (severity, check, provider) and sort by severity then count
    top_findings_html = ""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _add_grouped(severity: str, check: str, provider: str, msg: str) -> None:
        key = (severity, check, provider)
        if key not in grouped:
            grouped[key] = {"count": 0, "message": ""}
        grouped[key]["count"] = int(grouped[key]["count"]) + 1
        if not grouped[key]["message"]:
            grouped[key]["message"] = msg

    for f in findings_list:
        sev = (f.get("severity") or "").lower()
        if sev in ("critical", "high"):
            msg = ((f.get("title") or "") + " " + (f.get("details") or ""))[:200]
            _add_grouped(sev.capitalize(), str(f.get("id", "")), "Scanner", msg)
    for ff in all_findings:
        if (ff.get("severity") or "") in ("Critical", "High"):
            prov = ff.get("provider", "Prowler")
            msg = (ff.get("message") or "")[:200]
            _add_grouped(
                str(ff.get("severity", "High")),
                str(ff.get("check", "")),
                str(prov),
                msg,
            )
    # Sort: Critical first, then High; within same severity by count descending
    combined = [
        {
            "severity": sev,
            "check": ck,
            "provider": prov,
            "count": int(d["count"]),
            "message": str(d["message"]),
        }
        for (sev, ck, prov), d in grouped.items()
    ]
    combined.sort(
        key=lambda x: (
            0 if str(x["severity"]) == "Critical" else 1,
            -int(x["count"]),
            str(x["check"]),
        )
    )
    for ff in combined[:12]:
        cnt = int(ff["count"])
        cnt_html = (
            f' <span class="tf-cnt" title="{cnt} occurrence(s)">({cnt})</span>'
            if cnt > 1
            else ""
        )
        tab_click = (
            "switchTab('overview','scanner-section')"
            if str(ff["provider"]) == "Scanner"
            else "switchTab('prowler')"
        )
        severity_text = str(ff["severity"])
        provider_text = str(ff["provider"])
        check_text = str(ff["check"])
        message_text = str(ff["message"])
        top_findings_html += f'<div class="top-finding" onclick="{tab_click}"><div class="tf-badge">{sev_badge(severity_text)}</div><div class="tf-body"><div class="tf-check"><code>{h(check_text)}</code><span class="tf-prov">{h(provider_text.upper())}</span>{cnt_html}</div><div class="tf-msg">{h(message_text[:150])}</div></div></div>'
    if not top_findings_html:
        top_findings_html = '<div class="top-finding" style="border-color:var(--border)"><div class="tf-body" style="color:var(--muted);font-size:.9rem">No critical or high findings from the scanner or Prowler in this scan. Check the Scanner and Prowler CSPM tabs for full results.</div></div>'
    env_connected = sum(1 for e in envs if e["connected"])
    env_total = len(envs)
    ts = net_data["trivy_summary"]
    trivy_total = ts["critical"] + ts["high"] + ts["medium"] + ts["low"]
    dd_total = datadog_data["summary"].get("total", 0)
    dd_signal_total = datadog_data["signal_summary"].get("total", 0)
    dd_case_total = datadog_data["case_summary"].get("total", 0)
    network_total = trivy_total + dd_total
    network_total += dd_signal_total + dd_case_total
    has_network_artifacts = bool(net_data["nmap_scans"] or net_data["sslscan_results"])
    network_tools_badge = (
        str(network_total) if network_total else ("✓" if has_network_artifacts else "—")
    )
    network_tools_html = ""
    if (
        net_data["trivy_fs"] is not None
        or net_data["nmap_scans"]
        or net_data["sslscan_results"]
    ):
        network_tools_html += '<div class="card"><div class="card-title">Trivy (vulnerabilities &amp; config)</div><div style="padding:1rem 1.25rem">'
        network_tools_html += f'<table><thead><tr><th>Severity</th><th class="r">Count</th></tr></thead><tbody>'
        network_tools_html += f'<tr><td><span class="badge critical">Critical</span></td><td class="r">{ts["critical"]}</td></tr><tr><td><span class="badge high">High</span></td><td class="r">{ts["high"]}</td></tr><tr><td><span class="badge medium">Medium</span></td><td class="r">{ts["medium"]}</td></tr><tr><td><span class="badge low">Low</span></td><td class="r">{ts["low"]}</td></tr></tbody></table></div></div>'
        vulns = sorted(
            net_data["trivy_vulns"],
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                x["severity"], 9
            ),
        )[:50]
        if vulns:
            network_tools_html += '<div class="card"><div class="card-title">Trivy findings (top 50)</div><div style="max-height:50vh;overflow-y:auto">'
            network_tools_html += '<table><thead><tr><th style="width:80px">Severity</th><th style="width:100px">ID</th><th>Target/Package</th><th>Title</th></tr></thead><tbody>'
            for v in vulns:
                sev = (v.get("severity") or "UNKNOWN").upper()
                sev_cls = (
                    "low"
                    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                    else sev.lower()
                )
                network_tools_html += f'<tr><td><span class="badge {sev_cls}">{sev}</span></td><td class="mono">{h(v.get("id", ""))}</td><td class="mono">{h((v.get("target") or "") + " " + (v.get("pkg") or v.get("message", ""))[:60])}</td><td>{h((v.get("title") or "")[:80])}</td></tr>'
            network_tools_html += "</tbody></table></div></div>"
        if net_data["nmap_scans"]:
            network_tools_html += '<div class="card"><div class="card-title">Nmap scan summary</div><div style="padding:1rem 1.25rem">'
            for scan in net_data["nmap_scans"]:
                network_tools_html += f'<div style="margin-bottom:1rem"><strong>{h(scan["name"])}</strong><ul style="margin:.5rem 0 0 1rem">'
                for hst in scan["hosts"][:10]:
                    ports = ", ".join(hst["ports"][:15]) if hst["ports"] else "(none)"
                    network_tools_html += (
                        f"<li>{h(hst['addr']) or 'host'}: {ports}</li>"
                    )
                network_tools_html += "</ul></div>"
            network_tools_html += "</div></div>"
        if net_data["sslscan_results"]:
            network_tools_html += '<div class="card"><div class="card-title">SSL/TLS scan</div><div style="padding:1rem 1.25rem">'
            for s in net_data["sslscan_results"]:
                network_tools_html += f'<div><strong>{h(s["name"])}</strong> <span style="color:var(--muted)">(JSON data available)</span></div>'
            network_tools_html += "</div></div>"

    dd_summary = datadog_data["summary"]
    if dd_summary.get("total", 0) > 0:
        network_tools_html += '<div class="card"><div class="card-title">Datadog CI log summary</div><div style="padding:1rem 1.25rem">'
        network_tools_html += '<table><thead><tr><th>Level</th><th class="r">Count</th></tr></thead><tbody>'
        network_tools_html += f'<tr><td><span class="badge high">Error</span></td><td class="r">{dd_summary.get("error", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge warning">Warning</span></td><td class="r">{dd_summary.get("warning", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge info">Info</span></td><td class="r">{dd_summary.get("info", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge low">Unknown</span></td><td class="r">{dd_summary.get("unknown", 0)}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"
        network_tools_html += '<div class="card"><div class="card-title">Datadog CI logs (latest 100)</div><div style="max-height:50vh;overflow-y:auto">'
        network_tools_html += '<table><thead><tr><th style="width:160px">Timestamp</th><th style="width:100px">Level</th><th style="width:160px">Source</th><th>Message</th></tr></thead><tbody>'
        for row in datadog_data["logs"][:100]:
            sev = row.get("severity", "unknown")
            sev_cls = (
                "low"
                if sev == "unknown"
                else (
                    "warning"
                    if sev == "warning"
                    else ("high" if sev == "error" else "info")
                )
            )
            network_tools_html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("source", "-"))}</td><td>{h(row.get("message", ""))}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"

    dd_signal_summary = datadog_data["signal_summary"]
    if dd_signal_summary.get("total", 0) > 0:
        network_tools_html += '<div class="card"><div class="card-title">Datadog Cloud Security signals summary</div><div style="padding:1rem 1.25rem">'
        network_tools_html += '<table><thead><tr><th>Severity</th><th class="r">Count</th></tr></thead><tbody>'
        network_tools_html += f'<tr><td><span class="badge critical">Critical</span></td><td class="r">{dd_signal_summary.get("critical", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge high">High</span></td><td class="r">{dd_signal_summary.get("high", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge medium">Medium</span></td><td class="r">{dd_signal_summary.get("medium", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge low">Low</span></td><td class="r">{dd_signal_summary.get("low", 0)}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"
        network_tools_html += '<div class="card"><div class="card-title">Datadog Cloud Security signals (critical/high first)</div><div style="max-height:50vh;overflow-y:auto">'
        network_tools_html += '<table><thead><tr><th style="width:150px">Timestamp</th><th style="width:90px">Severity</th><th style="width:110px">Status</th><th style="width:180px">Rule</th><th>Title</th></tr></thead><tbody>'
        for row in datadog_data["signals"][:100]:
            sev = row.get("severity", "unknown")
            sev_cls = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
            }.get(sev, "low")
            network_tools_html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("status", ""))}</td><td class="mono">{h(row.get("rule", ""))}</td><td>{h(row.get("title", ""))}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"

    dd_case_summary = datadog_data["case_summary"]
    if dd_case_summary.get("total", 0) > 0:
        network_tools_html += '<div class="card"><div class="card-title">Datadog case management summary</div><div style="padding:1rem 1.25rem">'
        network_tools_html += '<table><thead><tr><th>Priority/Severity</th><th class="r">Count</th></tr></thead><tbody>'
        network_tools_html += f'<tr><td><span class="badge critical">Critical/P1</span></td><td class="r">{dd_case_summary.get("critical", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge high">High/P2</span></td><td class="r">{dd_case_summary.get("high", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge medium">Medium/P3</span></td><td class="r">{dd_case_summary.get("medium", 0)}</td></tr>'
        network_tools_html += f'<tr><td><span class="badge low">Low/P4+</span></td><td class="r">{dd_case_summary.get("low", 0)}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"
        network_tools_html += '<div class="card"><div class="card-title">Datadog cases (critical/high first)</div><div style="max-height:50vh;overflow-y:auto">'
        network_tools_html += '<table><thead><tr><th style="width:150px">Updated</th><th style="width:90px">Severity</th><th style="width:120px">Status</th><th style="width:160px">Type</th><th>Title</th></tr></thead><tbody>'
        for row in datadog_data["cases"][:100]:
            sev = row.get("severity", "unknown")
            sev_cls = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info",
            }.get(sev, "low")
            network_tools_html += f'<tr><td class="mono">{h(row.get("timestamp", ""))}</td><td><span class="badge {sev_cls}">{h(sev.title())}</span></td><td class="mono">{h(row.get("status", ""))}</td><td class="mono">{h(row.get("rule", ""))}</td><td>{h(row.get("title", ""))}</td></tr>'
        network_tools_html += "</tbody></table></div></div>"

    if not network_tools_html:
        network_tools_html = '<div class="card"><div class="card-title">Network &amp; security tools</div><div style="padding:1rem 1.25rem;color:var(--muted)">Trivy, Nmap, SSLScan, Datadog CI logs/signals/cases appear here after scan artifacts are generated. Expected paths: <code>.claudesec-network/</code> and <code>.claudesec-datadog/</code>.</div></div>'
    return {
        "n_crit": n_crit,
        "n_high": n_high,
        "n_med": n_med,
        "n_low": n_low,
        "n_info": n_info,
        "prov_cards": prov_cards,
        "bar_crit": bar_crit,
        "bar_high": bar_high,
        "bar_med": bar_med,
        "bar_warn": bar_warn,
        "bar_low": bar_low,
        "top_findings_html": top_findings_html,
        "env_connected": env_connected,
        "env_total": env_total,
        "network_tools_html": network_tools_html,
        "network_tools_badge": network_tools_badge,
    }


def _build_owasp_html(owasp_map):
    out = '<h3 style="font-size:.95rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem"><span style="color:var(--accent)">🛡</span> OWASP Top 10:2025 — Web application security</h3>'
    for ow in OWASP_2025:
        oid = ow["id"]
        findings = owasp_map.get(oid, [])
        count = len(findings)
        status_cls = "pass" if count == 0 else "fail"
        out += f'<div class="owasp-item {status_cls}" id="owasp-{oid}">'
        out += f'<div class="owasp-header" onclick="toggleOwasp(this)"><span class="owasp-id">{oid}</span><span class="owasp-name">{h(ow["name"])}</span><span class="owasp-count">{count}</span><span class="owasp-arrow">▸</span></div>'
        arch_idx_list = OWASP_TO_ARCH.get(
            oid, OWASP_TO_ARCH.get(oid.split(":")[0] if ":" in oid else oid, [])
        )
        summary = (ow.get("summary") or ow.get("desc") or "").strip()
        action = (
            ow.get("action")
            or "Review the OWASP documentation and apply recommended controls."
        ).strip()
        out += f'<div class="owasp-body"><p class="owasp-desc">{h(ow["desc"])}</p>'
        out += f'<p class="owasp-summary"><strong>Summary</strong> {h(summary or "See description above.")}</p>'
        out += f'<p class="owasp-action"><strong>Remediation</strong> {h(action)}</p>'
        out += f'<a href="{ow["url"]}" target="_blank" class="ref-link">📖 OWASP documentation</a>'
        if arch_idx_list:
            out += f'<div class="owasp-arch-links"><span class="arch-links-label">Related architecture</span>'
            for i in arch_idx_list:
                d = ARCH_DOMAINS[i] if i < len(ARCH_DOMAINS) else None
                if d:
                    out += f'<button class="arch-link-chip" onclick="switchTab(\'arch\',\'arch-dom-{i}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
            out += "</div>"
        if findings:
            out += '<div class="owasp-findings">'
            for ff in findings[:10]:
                out += f'<div class="of-row">{sev_badge(ff["severity"])} <code>{h(ff["check"])}</code> {h(ff["message"][:120])}</div>'
            if count > 10:
                out += f'<div class="of-more">... and {count - 10} more</div>'
            out += "</div>"
        out += "</div></div>"
    out += '<div style="margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)">'
    out += '<h3 style="font-size:.95rem;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem"><span style="color:var(--accent)">🤖</span> OWASP Top 10 for LLM Applications 2025</h3>'
    out += '<p style="font-size:.82rem;color:var(--muted);margin-bottom:1rem">AI/LLM application security risks — <a href="https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/" target="_blank" style="color:var(--accent)">Official docs</a></p>'
    for llm in OWASP_LLM_2025:
        out += f'<div class="owasp-item" style="border-left:3px solid var(--accent)">'
        out += f'<div class="owasp-header" onclick="toggleOwasp(this)"><span class="owasp-id" style="color:#f59e0b">{llm["id"]}</span><span class="owasp-name">{h(llm["name"])}</span><span class="owasp-arrow">▸</span></div>'
        summary = (llm.get("summary") or llm.get("desc") or "").strip()
        action = (
            llm.get("action")
            or "Review the OWASP GenAI documentation and apply recommended controls."
        ).strip()
        out += f'<div class="owasp-body"><p class="owasp-desc">{h(llm["desc"])}</p>'
        out += f'<p class="owasp-summary"><strong>Summary</strong> {h(summary or "See description above.")}</p>'
        out += f'<p class="owasp-action"><strong>Remediation</strong> {h(action)}</p>'
        out += f'<a href="{llm["url"]}" target="_blank" class="ref-link">📖 OWASP GenAI documentation</a></div></div>'
    out += "</div>"
    return out


_TEMPLATE_KEYS = [
    "VERSION",
    "NOW",
    "DURATION",
    "PASSED",
    "FAILED",
    "WARNINGS",
    "SKIPPED",
    "SCORE",
    "GRADE",
    "GRADE_COLOR",
    "ACTIVE",
    "SCORE_DASH",
    "N_CRIT",
    "N_HIGH",
    "N_MED",
    "N_LOW",
    "N_WARN",
    "N_INFO",
    "TOTAL_PASSED",
    "TOTAL_PROWLER_FAIL",
    "TOTAL_PROWLER_PASS",
    "TOTAL_ALL",
    "TOTAL_ISSUES",
    "ENV_HTML",
    "ENV_CONNECTED",
    "ENV_TOTAL",
    "PROV_CARDS",
    "PROV_TABLE",
    "SCANNER_ROWS",
    "SCANNER_CAT_SUMMARY",
    "SCANNER_TOTAL",
    "GH_TABLE",
    "GH_TOTAL",
    "AWS_TABLE",
    "AWS_TOTAL",
    "GCP_TABLE",
    "GCP_TOTAL",
    "GWS_TABLE",
    "GWS_TOTAL",
    "K8S_TABLE",
    "K8S_TOTAL",
    "AZURE_TABLE",
    "AZURE_TOTAL",
    "M365_TABLE",
    "M365_TOTAL",
    "OWASP_HTML",
    "ARCH_HTML",
    "ARCH_IMG",
    "COMP_HTML",
    "HISTORY_JSON",
    "TOP_FINDINGS",
    "BAR_CRIT",
    "BAR_HIGH",
    "BAR_MED",
    "BAR_WARN",
    "BAR_LOW",
    "NETWORK_TOOLS_HTML",
    "NETWORK_TOOLS_BADGE",
    "AUDIT_POINTS_HTML",
    "SCANNER_ISSUES",
    "SCAN_SCOPE_HTML",
    "AUTH_SUMMARY_HTML",
]


def _build_replacements(*values):
    return dict(zip(_TEMPLATE_KEYS, (str(v) for v in values)))


def _apply_template_and_write(output_file, template, replacements):
    for k, v in replacements.items():
        template = template.replace(f"{{{{{k}}}}}", v)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(template)


# Inline architecture diagram (fallback when SVG file not found) — dark theme
_INLINE_ARCH_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 260" width="100%" style="max-width:900px;height:auto;display:block" class="arch-diagram-svg">
<defs><marker id="arch-arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto"><path d="M0,0 L0,6 L9,3 z" fill="#94a3b8"/></marker></defs>
<style>.arch-txt{font-family:system-ui,sans-serif;font-size:11px;fill:#e2e8f0}.arch-title{font-weight:bold}</style>
<line x1="180" y1="105" x2="260" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="420" y1="110" x2="520" y2="75" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="75" x2="720" y2="105" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<line x1="700" y1="100" x2="720" y2="170" stroke="#64748b" stroke-width="1.5" marker-end="url(#arch-arrow)"/>
<rect x="40" y="80" width="140" height="50" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="110" y="96" text-anchor="middle" class="arch-txt arch-title">ClaudeSec Scanner</text><text x="110" y="110" text-anchor="middle" class="arch-txt">(CLI)</text>
<rect x="260" y="40" width="160" height="140" rx="6" fill="#1e3a5f" stroke="#38bdf8" stroke-width="1.5"/>
<text x="340" y="56" text-anchor="middle" class="arch-txt arch-title">Scan Categories</text>
<text x="340" y="70" text-anchor="middle" class="arch-txt">infra, ai, network, cloud</text><text x="340" y="84" text-anchor="middle" class="arch-txt">access-control, cicd, code</text><text x="340" y="98" text-anchor="middle" class="arch-txt">... prowler</text>
<rect x="520" y="50" width="180" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="610" y="66" text-anchor="middle" class="arch-txt arch-title">Scan Results</text><text x="610" y="80" text-anchor="middle" class="arch-txt">JSON / score / grade</text>
<rect x="520" y="120" width="140" height="40" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="590" y="136" text-anchor="middle" class="arch-txt arch-title">scan-report.json</text>
<rect x="520" y="180" width="160" height="50" rx="6" fill="#422006" stroke="#eab308" stroke-width="1.5"/>
<text x="600" y="196" text-anchor="middle" class="arch-txt arch-title">Prowler OCSF</text>
<rect x="720" y="80" width="120" height="50" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="96" text-anchor="middle" class="arch-txt arch-title">Dashboard</text><text x="780" y="110" text-anchor="middle" class="arch-txt">(HTML)</text>
<rect x="720" y="150" width="120" height="40" rx="6" fill="#312e81" stroke="#a78bfa" stroke-width="1.5"/>
<text x="780" y="166" text-anchor="middle" class="arch-txt arch-title">History</text>
</svg>"""


def _get_architecture_diagram_html(output_file, scan_dir: str = ""):
    """Load architecture SVG from docs/architecture or return built-in inline SVG.

    Prefer `scan_dir` when provided, because the HTML output may be generated
    from a different working directory than the scan artifacts.
    """
    candidates = []
    if scan_dir:
        try:
            candidates.append(
                os.path.join(
                    os.path.abspath(scan_dir),
                    "docs",
                    "architecture",
                    "claudesec-architecture.svg",
                )
            )
        except Exception:
            pass
    if output_file:
        out_dir = os.path.dirname(os.path.abspath(output_file))
        if out_dir:
            candidates.append(
                os.path.join(
                    out_dir, "docs", "architecture", "claudesec-architecture.svg"
                )
            )
    cwd = os.getcwd()
    candidates.append(
        os.path.join(cwd, "docs", "architecture", "claudesec-architecture.svg")
    )
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(script_dir))
        candidates.append(
            os.path.join(
                repo_root, "docs", "architecture", "claudesec-architecture.svg"
            )
        )
    except Exception:
        pass
    for svg_path in candidates:
        if svg_path and os.path.isfile(svg_path):
            try:
                with open(svg_path, "r", encoding="utf-8") as f:
                    svg_content = f.read()
                b64 = base64.b64encode(svg_content.encode("utf-8")).decode("ascii")
                return f'<img src="data:image/svg+xml;base64,{b64}" alt="ClaudeSec Architecture" style="max-width:100%;height:auto;display:block;border-radius:8px" />'
            except Exception:
                continue
    return f'<div class="arch-diagram-wrap">{_INLINE_ARCH_SVG}</div>'


def generate_dashboard(scan_data, prowler_dir, history_dir, output_file):
    network_dir = os.environ.get("CLAUDESEC_NETWORK_DIR", "")
    scan_dir = os.environ.get("CLAUDESEC_SCAN_DIR", "") or os.environ.get("SCAN_DIR", "")
    if scan_dir:
        scan_dir = os.path.abspath(scan_dir)
    if not scan_dir and prowler_dir and os.path.isdir(prowler_dir):
        scan_dir = os.path.dirname(os.path.abspath(prowler_dir))
    if not scan_dir and output_file:
        scan_dir = os.path.dirname(os.path.abspath(output_file))
    if not scan_dir:
        scan_dir = os.getcwd()

    if not network_dir:
        network_dir = os.path.join(scan_dir, ".claudesec-network")
    datadog_dir = os.environ.get("CLAUDESEC_DATADOG_DIR", "")
    if not datadog_dir:
        datadog_dir = os.path.join(scan_dir, ".claudesec-datadog")
    net_data = load_network_tool_results(network_dir)
    datadog_data = load_datadog_logs(datadog_dir)
    audit_points_data = load_audit_points(scan_dir)
    ms_best_practices_data = load_microsoft_best_practices(scan_dir)

    providers = load_prowler_files(prowler_dir)
    prov_summary, all_findings = analyze_prowler(providers)
    history = load_scan_history(history_dir)
    owasp_map = map_findings_to_owasp(all_findings)
    compliance_map = map_compliance(all_findings)
    arch_domains = map_architecture(all_findings)
    gh_finds = github_findings(all_findings)
    aws_finds = aws_findings(all_findings)
    gcp_finds = gcp_findings(all_findings)
    gws_finds = gws_findings(all_findings)
    k8s_finds = k8s_findings(all_findings)
    azure_finds = azure_findings(all_findings)
    m365_finds = m365_findings(all_findings)
    envs = get_env_status()

    sd = scan_data
    passed = sd.get("passed", 0)
    failed = sd.get("failed", 0)
    warnings = sd.get("warnings", 0)
    skipped = sd.get("skipped", 0)
    total = sd.get("total", 0)
    score = sd.get("score", 0)
    grade = sd.get("grade", "F")
    duration = sd.get("duration", 0)
    findings_list = sd.get("findings", [])
    active = total - skipped

    grade_color = {"A": "#22c55e", "B": "#22c55e", "C": "#eab308", "D": "#eab308"}.get(
        grade, "#ef4444"
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    total_prowler_fail = sum(v["total_fail"] for v in prov_summary.values())
    total_prowler_pass = sum(v["total_pass"] for v in prov_summary.values())

    history_json = json.dumps(
        history
        + [
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "score": score,
                "failed": failed,
                "critical": sum(v["critical"] for v in prov_summary.values()),
                "high": sum(v["high"] for v in prov_summary.values()),
            }
        ]
    )

    # ── Build HTML sections ──────────────────────────────────────────────

    # Environment items — compact pill layout
    env_html = ""
    for e in envs:
        if e["connected"]:
            env_html += f'<div class="env-pill env-on"><span class="ep-icon">{e["icon"]}</span><span class="ep-name">{h(e["name"])}</span><span class="ep-st on">●</span></div>'
        else:
            env_html += f'<button class="env-pill env-off" onclick="openSetup(\'{e["setup_id"]}\')"><span class="ep-icon">{e["icon"]}</span><span class="ep-name">{h(e["name"])}</span><span class="ep-st off">○</span></button>'

    # Prowler summary table
    prov_table = ""
    for pname, pdata in sorted(prov_summary.items()):
        label = {
            "aws": "AWS",
            "github": "GitHub",
            "iac": "IaC",
            "kubernetes": "K8s",
            "azure": "Azure",
            "gcp": "GCP",
            "googleworkspace": "Google Workspace",
            "m365": "Microsoft 365",
            "cloudflare": "Cloudflare",
            "nhn": "NHN Cloud",
            "llm": "LLM",
            "image": "Container Image",
            "oraclecloud": "Oracle Cloud",
            "alibabacloud": "Alibaba Cloud",
            "openstack": "OpenStack",
            "mongodbatlas": "MongoDB Atlas",
        }.get(pname, pname)
        subtab_map = {
            "aws": "aws",
            "gcp": "gcp",
            "googleworkspace": "gws",
            "kubernetes": "k8s",
            "azure": "azure",
            "m365": "m365",
        }
        onclick = (
            f' onclick="switchProvTab(\'{subtab_map[pname]}\')" style="cursor:pointer"'
            if pname in subtab_map
            else ""
        )
        prov_table += f'<tr{onclick}><td>{label}</td><td class="r">{pdata["total_fail"] + pdata["total_pass"]}</td><td class="r" style="color:#dc2626">{pdata["critical"]}</td><td class="r" style="color:#ef4444">{pdata["high"]}</td><td class="r" style="color:#eab308">{pdata["medium"]}</td><td class="r">{pdata["low"]}</td><td class="r" style="color:#22c55e">{pdata["total_pass"]}</td></tr>'

    # Scanner findings — grouped by category with descriptions
    scanner_rows, scanner_cat_summary = _build_scanner_section(findings_list)

    # GitHub Security findings
    gh_by_check = defaultdict(list)
    for f in gh_finds:
        gh_by_check[f["check"]].append(f)
    gh_table = ""
    for check, items in sorted(gh_by_check.items(), key=lambda x: -len(x[1])):
        sev = items[0]["severity"]
        repos = list(set(f["resource"] for f in items if f["resource"]))[:5]
        repos_html = ", ".join(f"<code>{h(r)}</code>" for r in repos)
        if len(items) > 5:
            repos_html += f" ... +{len(items) - 5}"
        gh_table += f'<tr class="expandable" onclick="toggleRow(this)"><td>{sev_badge(sev)}</td><td class="mono">{h(check)}</td><td>{h(items[0]["title"])} <span class="cnt">({len(items)})</span></td><td>{repos_html}</td></tr>'
        en = get_check_en(check)
        desc = items[0].get("desc") or items[0].get("title") or ""
        gh_table += f'<tr class="row-detail"><td colspan="4"><div class="detail-panel">'
        if desc:
            gh_table += f"<p>{h(desc)}</p>"
        gh_table += f'<p class="detail-ko-summary"><strong>Summary</strong> {h(en["summary"])}</p>'
        gh_table += f'<p class="detail-ko-action"><strong>Remediation</strong> {h(en["action"])}</p>'
        if items[0].get("related_url"):
            gh_table += f'<a href="{h(items[0]["related_url"])}" target="_blank" rel="noopener" class="ref-link">📖 Reference</a>'
        gh_table += "</div></td></tr>"

    def _build_provider_table(finds):
        by_check = defaultdict(list)
        for f in finds:
            by_check[f["check"]].append(f)
        table = ""
        for check, items in sorted(by_check.items(), key=lambda x: -len(x[1])):
            sev = items[0]["severity"]
            table += f'<tr class="expandable" onclick="toggleRow(this)"><td>{sev_badge(sev)}</td><td class="mono">{h(check)}</td><td>{h(items[0]["title"])} <span class="cnt">({len(items)})</span></td></tr>'
            en = get_check_en(check)
            desc = items[0].get("desc") or items[0].get("title") or ""
            table += (
                f'<tr class="row-detail"><td colspan="3"><div class="detail-panel">'
            )
            if desc:
                table += f"<p>{h(desc)}</p>"
            table += f'<p class="detail-ko-summary"><strong>Summary</strong> {h(en["summary"])}</p>'
            table += f'<p class="detail-ko-action"><strong>Remediation</strong> {h(en["action"])}</p>'
            if items[0].get("related_url"):
                table += f'<a href="{h(items[0]["related_url"])}" target="_blank" rel="noopener" class="ref-link">📖 Reference</a>'
            table += "</div></td></tr>"
        return table

    aws_table = _build_provider_table(aws_finds)
    gcp_table = _build_provider_table(gcp_finds)
    gws_table = _build_provider_table(gws_finds)
    k8s_table = _build_provider_table(k8s_finds)
    azure_table = _build_provider_table(azure_finds)
    m365_table = _build_provider_table(m365_finds)

    owasp_html = _build_owasp_html(owasp_map)

    # Architecture tab — with linked OWASP/Compliance/Scanner
    arch_html = ""
    owasp_names = {o["id"]: o["name"] for o in OWASP_2025}
    scanner_labels = {
        "access-control": "Access control",
        "infra": "Infrastructure",
        "network": "Network",
        "cicd": "CI/CD",
        "code": "Code",
        "ai": "AI",
        "cloud": "Cloud",
        "macos": "macOS",
        "saas": "SaaS",
        "windows": "Windows",
        "prowler": "Prowler",
        "other": "Other",
    }
    for idx, dom in enumerate(arch_domains):
        status_cls = "fail" if dom["fail_count"] > 0 else "pass"
        links = dom.get("links", {})
        arch_html += f'<div class="arch-domain {status_cls}" id="arch-dom-{idx}" data-arch-idx="{idx}">'
        arch_html += f'<div class="arch-header" onclick="toggleArch(this)"><span class="arch-icon">{dom["icon"]}</span><span class="arch-name">{h(dom["name"])}</span><span class="arch-stat"><span class="arch-fail">{dom["fail_count"]} failed</span></span><span class="arch-arrow">▸</span></div>'
        arch_html += '<div class="arch-body">'
        summary = dom.get("summary", "")
        action = dom.get("action", "")
        summary = (dom.get("summary") or dom.get("name") or "").strip()
        action = (
            dom.get("action")
            or "Apply security best practices for this domain; see related OWASP and compliance controls."
        ).strip()
        arch_html += '<div class="arch-summary-block">'
        arch_html += f'<p class="arch-summary-ko"><strong>Summary</strong> {h(summary or "See related findings and controls below.")}</p>'
        arch_html += (
            f'<p class="arch-action-ko"><strong>Remediation</strong> {h(action)}</p>'
        )
        arch_html += "</div>"
        if links.get("owasp") or links.get("compliance") or links.get("scanner"):
            arch_html += '<div class="arch-links"><span class="arch-links-label">Related items</span>'
            for oid in links.get("owasp", []):
                oname = owasp_names.get(oid, oid)
                arch_html += f'<button class="arch-link-chip arch-owasp" onclick="switchTab(\'bestpractices\',\'owasp-{oid}\')" title="OWASP {oid}">{oid}</button>'
            for fw, ctrl in links.get("compliance", []):
                cid = comp_slug(fw)
                arch_html += f'<button class="arch-link-chip arch-comp" onclick="switchTab(\'bestpractices\',\'{cid}\')" title="{h(fw)} {h(ctrl)}">{ctrl}</button>'
            for scat in links.get("scanner", []):
                slab = scanner_labels.get(scat, scat)
                arch_html += f'<button class="arch-link-chip arch-scanner" onclick="switchTab(\'overview\',\'scanner-cat-{scat}\')" title="Scanner {slab}">{slab}</button>'
            arch_html += "</div>"
        if dom["findings"]:
            for ff in dom["findings"][:8]:
                arch_html += f'<div class="af-row">{sev_badge(ff["severity"])} <code>{h(ff["check"])}</code> {h(ff["message"][:100])}</div>'
            if dom["fail_count"] > 8:
                arch_html += (
                    f'<div class="of-more">... and {dom["fail_count"] - 8} more</div>'
                )
        else:
            arch_html += '<div class="arch-pass">✓ No findings in this domain.</div>'
        arch_html += "</div></div>"

    # Compliance tab
    comp_html = '<div class="comp-frameworks">'
    for fw in COMPLIANCE_FRAMEWORKS:
        comp_html += f'<a href="{fw["url"]}" target="_blank" class="comp-fw-chip" rel="noopener"><strong>{h(fw["name"])}</strong><span>{h(fw["desc"])}</span></a>'
    comp_html += "</div>"

    COMP_FW_TO_ARCH = {
        "ISO 27001:2022": [0, 1, 2, 3, 4, 5],
        "KISA ISMS-P": [1, 2, 3, 4],
        "PCI-DSS v4.0.1": [0, 1, 2, 3, 4, 5],
    }
    for framework, controls in compliance_map.items():
        total_c = len(controls)
        pass_c = sum(1 for c in controls if c["status"] == "PASS")
        fail_c = total_c - pass_c
        comp_id = comp_slug(framework)
        comp_arch_html = ""
        for aidx in COMP_FW_TO_ARCH.get(framework, []):
            if aidx < len(ARCH_DOMAINS):
                d = ARCH_DOMAINS[aidx]
                comp_arch_html += f'<button class="arch-link-chip arch-sm" onclick="switchTab(\'arch\',\'arch-dom-{aidx}\')" title="{h(d["name"])}">{d["icon"]} {h(d["name"])}</button>'
        comp_arch_row = (
            f'<div class="comp-arch-links"><span class="arch-links-label">Related architecture</span>{comp_arch_html}</div>'
            if comp_arch_html
            else ""
        )
        comp_html += f'<div class="comp-section" id="{comp_id}"><div class="comp-title" onclick="toggleComp(this)">{h(framework)} <span class="comp-stat"><span class="cs-pass">{pass_c} pass</span> / <span class="cs-fail">{fail_c} fail</span></span><span class="comp-arrow">▸</span></div>'
        if comp_arch_row:
            comp_html += comp_arch_row
        comp_html += '<div class="comp-body"><table><thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Related</th><th>Summary · Remediation</th></tr></thead><tbody>'
        for ctrl in controls:
            st_cls = "pass" if ctrl["status"] == "PASS" else "fail"
            st_icon = "✓" if ctrl["status"] == "PASS" else "✗"
            st_text = "Pass" if ctrl["status"] == "PASS" else "Fail"
            desc = (ctrl.get("desc") or ctrl.get("name") or "").strip()
            action = (
                ctrl.get("action")
                or "Apply security best practices for this control; refer to the framework documentation."
            ).strip()
            summary_cell = f'<div class="comp-summary-cell"><span class="comp-desc-ko">{h(desc or "—")}</span><br><span class="comp-action-ko"><strong>Remediation</strong> {h(action)}</span></div>'
            comp_html += f'<tr class="comp-{st_cls}"><td class="mono">{h(ctrl["control"])}</td><td>{h(ctrl["name"])}</td><td class="comp-st-{st_cls}">{st_icon} {st_text}</td><td>{ctrl["count"]}</td><td class="comp-summary-td">{summary_cell}</td></tr>'
        comp_html += "</tbody></table></div></div>"

    total_passed = passed + total_prowler_pass
    total_all = total_prowler_fail + total_prowler_pass + failed + warnings
    total_issues = total_prowler_fail + failed + warnings
    audit_points_detected = load_audit_points_detected(scan_dir)
    # Scan scope: what data is included in this dashboard (for Overview)
    prov_count = len(prov_summary)
    hist_count = len(history)
    scope_parts = [f"Scanner ({total} checks)"]
    if prov_count:
        scope_parts.append(
            f"Prowler ({prov_count} provider{'s' if prov_count != 1 else ''})"
        )
    scope_parts.append(f"History ({hist_count} run{'s' if hist_count != 1 else ''})")
    if audit_points_detected.get("detected_products"):
        scope_parts.append("Audit Points (project-relevant)")
    elif audit_points_data.get("products"):
        scope_parts.append("Audit Points")
    if (
        net_data.get("trivy_fs")
        or net_data.get("nmap_scans")
        or net_data.get("sslscan_results")
        or (datadog_data.get("summary", {}).get("total", 0) > 0)
    ):
        scope_parts.append("Network / Datadog")
    scan_scope_html = (
        '<p style="font-size:.8rem;color:var(--muted);margin-top:.5rem;padding:.5rem 0;border-top:1px solid var(--border)"><strong style="color:var(--text)">Data in this view:</strong> '
        + " · ".join(scope_parts)
        + "</p>"
    )
    auth_summary_html = build_auth_summary_html(envs, findings_list)
    repo_url = f"https://github.com/{AUDIT_POINTS_REPO}"
    # QueryPie Audit Points tab content
    audit_points_html = ""
    if audit_points_detected.get("detected_products") and audit_points_detected.get(
        "items"
    ):
        audit_points_html = '<div class="card"><div class="card-title">Relevant to this project</div><div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:.75rem">Products detected in this repo; review the checklist items below (from <code>claudesec scan -c saas</code>).</p>'
        by_product = defaultdict(list)
        for it in audit_points_detected.get("items", []):
            by_product[it.get("product", "")].append(it)
        for pname in audit_points_detected.get("detected_products", []):
            items = by_product.get(pname, [])
            audit_points_html += f'<div style="margin-bottom:1rem"><strong style="color:var(--accent)">{h(pname)}</strong> <span style="font-size:.8rem;color:var(--muted)">({len(items)} items)</span><div style="margin-top:.35rem">'
            for it in items[:30]:
                url = it.get("url") or "#"
                audit_points_html += f'<div style="margin-left:.5rem"><a href="{h(url)}" target="_blank" rel="noopener" style="font-size:.82rem;color:var(--text)">{h(it.get("file_name", ""))}</a></div>'
            if len(items) > 30:
                audit_points_html += f'<div style="font-size:.8rem;color:var(--muted);margin-left:.5rem">… +{len(items) - 30} more</div>'
            audit_points_html += "</div></div>"
        audit_points_html += "</div></div>"
    if audit_points_data.get("products"):
        title = (
            "All products (querypie/audit-points)"
            if audit_points_html
            else "QueryPie Audit Points"
        )
        audit_points_html += f'<div class="card"><div class="card-title">{h(title)}</div><div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:1rem">SaaS/DevSecOps audit checklists from <a href="{h(repo_url)}" target="_blank" rel="noopener">querypie/audit-points</a>. Click a product to open the folder; click a file to open the checklist.</p>'
        for prod in audit_points_data["products"]:
            tree_url = (
                prod.get("tree_url")
                or f"{repo_url}/tree/main/{urllib.parse.quote(prod['name'])}"
            )
            audit_points_html += f'<div class="card" style="margin-bottom:1rem;padding:0"><div class="card-title" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==\'none\'?\'\':\'none\'" style="cursor:pointer;user-select:none">▸ {h(prod["name"])} <span style="font-size:.75rem;color:var(--muted);font-weight:400">({len(prod.get("files", []))} items)</span></div>'
            audit_points_html += '<div style="padding:.75rem 1rem">'
            audit_points_html += f'<a href="{h(tree_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.85rem">Open folder on GitHub</a>'
            for f in prod.get("files", [])[:50]:
                url = f.get("url") or f.get("raw_url") or "#"
                audit_points_html += f'<div style="margin-top:.5rem"><a href="{h(url)}" target="_blank" rel="noopener" class="mono" style="font-size:.82rem;color:var(--text)">{h(f.get("name", ""))}</a></div>'
            if len(prod.get("files", [])) > 50:
                audit_points_html += f'<div style="margin-top:.5rem;color:var(--muted);font-size:.8rem">… and {len(prod["files"]) - 50} more in <a href="{h(tree_url)}" target="_blank" rel="noopener">folder</a></div>'
            audit_points_html += "</div></div>"
        if audit_points_data.get("fetched_at"):
            audit_points_html += f'<p style="font-size:.72rem;color:var(--muted);margin-top:1rem">Cache updated: {h(audit_points_data["fetched_at"][:19])}</p>'
        audit_points_html += "</div></div>"
    if not audit_points_html:
        audit_points_html = '<div class="card"><div class="card-title">QueryPie Audit Points</div><div style="padding:1rem 1.25rem;color:var(--muted)">SaaS/DevSecOps audit checklists from <a href="https://github.com/querypie/audit-points" target="_blank" rel="noopener">querypie/audit-points</a>. Run <code>claudesec scan -c saas</code> to detect products and populate the checklist for this project.</div></div>'

    ms_sources = ms_best_practices_data.get("sources", [])
    scubagear_enabled = _is_env_truthy(MS_INCLUDE_SCUBAGEAR_ENV)
    source_filter = (
        ms_best_practices_data.get("source_filter") or _normalized_source_filter()
    )
    audit_points_html += '<div class="card ms-source-root"><div class="card-title">Windows / Intune / Office 365 best-practice sources</div>'
    if source_filter == "none":
        preset_default = "none"
    elif source_filter == "official,gov":
        preset_default = "official,gov"
    else:
        preset_default = "all"
    audit_points_html += f'<div style="padding:0 1.25rem"><div class="source-filter-chips" data-active-filter="{h(source_filter)}"><button class="source-filter-chip{(" active" if preset_default == "all" else "")}" data-filter="all" onclick="applyMsSourcePresetFilter(this)">all</button><button class="source-filter-chip{(" active" if preset_default == "official,gov" else "")}" data-filter="official,gov" onclick="applyMsSourcePresetFilter(this)">official,gov</button><button class="source-filter-chip{(" active" if preset_default == "none" else "")}" data-filter="none" onclick="applyMsSourcePresetFilter(this)">none</button><span class="ms-source-filter-status" style="font-size:.75rem;color:var(--muted)">Active env filter: {h(source_filter)}</span></div></div>'
    if ms_sources:
        audit_points_html += '<div style="padding:1rem 1.25rem"><p style="color:var(--muted);margin-bottom:.45rem">Curated GitHub sources for Microsoft platform hardening and security baseline guidance.</p>'
        if source_filter != "all":
            audit_points_html += f'<p style="color:var(--muted);font-size:.8rem;margin-bottom:.55rem">Active source filter: <code>{h(source_filter)}</code> (set <code>{h(MS_SOURCE_FILTER_ENV)}=all</code> to view all trust levels).</p>'
        trust_counts = {"Microsoft Official": 0, "Government": 0, "Community": 0}
        for src in ms_sources:
            level = src.get("trust_level") or "Community"
            if level not in trust_counts:
                trust_counts[level] = 0
            trust_counts[level] += 1
        count_chips = []
        count_chips.append(
            f'<span class="badge info" style="font-size:.66rem">Total sources {len(ms_sources)}</span>'
        )
        for level in ("Microsoft Official", "Government", "Community"):
            cls = {
                "Microsoft Official": "trust-ms",
                "Government": "trust-gov",
                "Community": "trust-community",
            }.get(level, "trust-community")
            count_chips.append(
                f'<span class="trust-badge {h(cls)}">{h(level)} {trust_counts.get(level, 0)}</span>'
            )
        audit_points_html += f'<div style="display:flex;flex-wrap:wrap;gap:.45rem;margin-bottom:1rem">{"".join(count_chips)}</div>'
        if not scubagear_enabled:
            audit_points_html += f'<p style="color:var(--muted);font-size:.8rem;margin-bottom:1rem">Optional source available: <code>cisagov/ScubaGear</code> (enable with <code>{h(MS_INCLUDE_SCUBAGEAR_ENV)}=1</code> before dashboard generation).</p>'
        else:
            audit_points_html += '<p style="color:var(--muted);font-size:.8rem;margin-bottom:1rem"><code>cisagov/ScubaGear</code> is enabled as an additional Office 365 source.</p>'
        grouped_sources = defaultdict(list)
        for src in ms_sources:
            grouped_sources[src.get("product") or "Other"].append(src)
        for product in ("Windows", "Intune", "Office 365", "Other"):
            entries = grouped_sources.get(product, [])
            if not entries:
                continue
            entries.sort(
                key=lambda s: (
                    TRUST_LEVEL_ORDER.get(s.get("trust_level", "Community"), 9),
                    s.get("label", ""),
                )
            )
            audit_points_html += f'<h4 style="margin:.75rem 0 .5rem 0;font-size:.9rem;color:var(--text)">{h(product)}</h4>'
            for src in entries:
                files = src.get("files", [])
                repo_url = src.get("repo_url") or "#"
                label = src.get("label") or src.get("repo") or "Source"
                reason = src.get("reason") or ""
                updated = src.get("updated_at") or ""
                trust_level = src.get("trust_level") or "Community"
                trust_class = {
                    "Microsoft Official": "trust-ms",
                    "Government": "trust-gov",
                    "Community": "trust-community",
                }.get(trust_level, "trust-community")
                trust_token = _trust_token_from_level(trust_level)
                archive_tag = (
                    ' <span style="font-size:.72rem;color:#f59e0b">(archived)</span>'
                    if src.get("archived")
                    else ""
                )
                audit_points_html += f'<div class="card ms-source-entry" data-trust-token="{h(trust_token)}" style="margin-bottom:.75rem;padding:0"><div class="card-title" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==\'none\'?\'\':\'none\'" style="cursor:pointer;user-select:none">▸ {h(label)} <span class="trust-badge {h(trust_class)}">{h(trust_level)}</span>{archive_tag} <span style="font-size:.75rem;color:var(--muted);font-weight:400">({len(files)} files)</span></div>'
                audit_points_html += '<div style="padding:.75rem 1rem">'
                audit_points_html += f'<div style="color:var(--muted);font-size:.82rem;margin-bottom:.45rem">{h(reason)}</div>'
                audit_points_html += f'<a href="{h(repo_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:.85rem">Open repository</a>'
                if updated:
                    audit_points_html += f'<span style="font-size:.75rem;color:var(--muted);margin-left:.5rem">Updated: {h(updated[:10])}</span>'
                for f in files[:25]:
                    url = f.get("url") or f.get("raw_url") or "#"
                    fname = f.get("path") or f.get("name") or "file"
                    audit_points_html += f'<div style="margin-top:.45rem"><a href="{h(url)}" target="_blank" rel="noopener" class="mono" style="font-size:.8rem;color:var(--text)">{h(fname)}</a></div>'
                if len(files) > 25:
                    audit_points_html += f'<div style="margin-top:.5rem;color:var(--muted);font-size:.78rem">… and {len(files) - 25} more files</div>'
                audit_points_html += "</div></div>"
        if ms_best_practices_data.get("fetched_at"):
            audit_points_html += f'<p style="font-size:.72rem;color:var(--muted);margin-top:1rem">Microsoft source cache updated: {h(ms_best_practices_data["fetched_at"][:19])}</p>'
        audit_points_html += "</div>"
    else:
        if source_filter == "none":
            audit_points_html += f'<div style="padding:1rem 1.25rem;color:var(--muted)">Microsoft source area is hidden by <code>{h(MS_SOURCE_FILTER_ENV)}=none</code>. Change to <code>all</code> or <code>official,gov</code> and re-run dashboard generation.</div>'
        elif source_filter != "all":
            audit_points_html += f'<div style="padding:1rem 1.25rem;color:var(--muted)">No Microsoft best-practice sources matched filter <code>{h(source_filter)}</code>. Try <code>{h(MS_SOURCE_FILTER_ENV)}=all</code> and re-run dashboard generation.</div>'
        else:
            audit_points_html += '<div style="padding:1rem 1.25rem;color:var(--muted)">No Microsoft best-practice source metadata cached yet. Re-run dashboard generation to refresh GitHub source discovery.</div>'
    audit_points_html += "</div>"
    overview = _build_overview_blocks(
        prov_summary,
        all_findings,
        envs,
        net_data,
        datadog_data,
        passed,
        total_prowler_pass,
        warnings,
        findings_list,
    )
    n_crit = overview["n_crit"]
    n_high = overview["n_high"]
    n_med = overview["n_med"]
    n_low = overview["n_low"]
    n_info = overview["n_info"]
    prov_cards = overview["prov_cards"]
    bar_crit = overview["bar_crit"]
    bar_high = overview["bar_high"]
    bar_med = overview["bar_med"]
    bar_warn = overview["bar_warn"]
    bar_low = overview["bar_low"]
    top_findings_html = overview["top_findings_html"]
    env_connected = overview["env_connected"]
    env_total = overview["env_total"]
    network_tools_html = overview["network_tools_html"]
    network_tools_badge = overview["network_tools_badge"]

    # Architecture diagram: embed SVG from docs/architecture, or use built-in inline SVG
    arch_img = _get_architecture_diagram_html(output_file, scan_dir)

    # ── Assemble Full HTML ───────────────────────────────────────────────
    reps = _build_replacements(
        VERSION,
        now,
        duration,
        passed,
        failed,
        warnings,
        skipped,
        score,
        grade,
        grade_color,
        active,
        score * 327 // 100,
        n_crit,
        n_high,
        n_med,
        n_low,
        warnings,
        n_info,
        total_passed,
        total_prowler_fail,
        total_prowler_pass,
        total_all,
        total_issues,
        env_html,
        env_connected,
        env_total,
        prov_cards,
        prov_table,
        scanner_rows,
        scanner_cat_summary,
        total,
        gh_table,
        len(gh_finds),
        aws_table,
        len(aws_finds),
        gcp_table,
        len(gcp_finds),
        gws_table,
        len(gws_finds),
        k8s_table,
        len(k8s_finds),
        azure_table,
        len(azure_finds),
        m365_table,
        len(m365_finds),
        owasp_html,
        arch_html,
        arch_img,
        comp_html,
        history_json,
        top_findings_html,
        bar_crit,
        bar_high,
        bar_med,
        bar_warn,
        bar_low,
        network_tools_html,
        network_tools_badge,
        audit_points_html,
        failed + warnings,
        scan_scope_html,
        auth_summary_html,
    )
    _apply_template_and_write(output_file, HTML_TEMPLATE, reps)


# ── HTML Template ────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="ClaudeSec v{{VERSION}}">
<title>ClaudeSec Security Dashboard</title>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--radius:12px}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:1.5rem}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;flex-wrap:wrap;gap:.5rem}
header h1{font-size:1.4rem;font-weight:800}
header h1 span{color:var(--accent)}
.ver{color:var(--accent);font-size:.75rem;font-weight:700;background:rgba(56,189,248,.12);padding:.15rem .5rem;border-radius:4px;margin-left:.5rem}
.meta{color:var(--muted);font-size:.82rem}
/* Language toggle - visible in header */
.lang-toggle{display:flex;align-items:center;gap:0;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--surface);margin-left:auto}
.lang-toggle a,.lang-toggle span{display:inline-block;padding:.4rem .75rem;font-size:.8rem;font-weight:600;text-decoration:none;color:var(--muted);transition:background .15s,color .15s;border:none;background:none;cursor:pointer;font-family:inherit}
.lang-toggle a:hover{color:var(--accent);background:rgba(56,189,248,.08)}
.lang-toggle .lang-active,.lang-toggle span.lang-active{color:var(--text);background:rgba(56,189,248,.15);color:var(--accent)}
.lang-toggle .lang-sep{width:1px;height:1.2em;background:var(--border);padding:0;pointer-events:none}
.lang-toggle a.en-active{color:var(--accent);background:rgba(56,189,248,.15)}
header .header-right{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap}
/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:1.5rem;overflow-x:auto}
.tab{padding:.65rem 1.1rem;font-size:.82rem;font-weight:700;cursor:pointer;color:var(--muted);border:none;border-bottom:2px solid transparent;margin-bottom:-2px;white-space:nowrap;transition:all .15s;background:none}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.prov-panel{display:none}
.prov-panel.active{display:block}
.prov-subtab.active{background:var(--accent)!important;color:#0f172a!important;border-color:var(--accent)!important;font-weight:600}
.prov-subtab:hover{border-color:var(--accent);color:var(--accent)}
/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin-bottom:1.5rem}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;text-align:center}
.stat .num{font-size:1.8rem;font-weight:800;line-height:1}
.stat .label{font-size:.75rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.04em}
.stat.pass .num{color:#22c55e}.stat.fail .num{color:#ef4444}.stat.warn .num{color:#eab308}.stat.skip .num{color:var(--muted)}
/* Score */
.score-section{display:flex;gap:1.5rem;margin-bottom:1.5rem}
.score-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;flex:1;text-align:center}
.score-ring{width:110px;height:110px;margin:0 auto .5rem;position:relative}
.score-ring svg{transform:rotate(-90deg)}
.score-ring .value{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.8rem;font-weight:800}
.score-ring .grade{position:absolute;bottom:14px;left:50%;transform:translateX(-50%);font-size:.7rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
/* Card */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:1.5rem}
.card-title{padding:.85rem 1.25rem;font-size:.95rem;font-weight:700;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
/* Table */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.5rem .75rem;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);border-bottom:1px solid var(--border)}
td{padding:.55rem .75rem;border-bottom:1px solid var(--border);font-size:.82rem;vertical-align:top}
tr:last-child td{border-bottom:none}
.r{text-align:right}
.mono{font-family:'SF Mono','Fira Code',monospace;font-size:.78rem;white-space:nowrap}
.fix{color:var(--accent);font-size:.78rem;max-width:320px}
.cnt{color:var(--muted);font-size:.75rem}
.ref-link{color:var(--accent);font-size:.8rem;text-decoration:underline;display:inline-block;margin-top:.5rem}
/* Badges */
.badge{display:inline-block;padding:.12rem .45rem;border-radius:4px;font-size:.68rem;font-weight:700;letter-spacing:.04em}
.badge.critical{background:#dc2626;color:#fff}.badge.high{background:#991b1b;color:#fca5a5}
.badge.medium{background:#854d0e;color:#fde68a}.badge.warning{background:#92400e;color:#fcd34d}.badge.low{background:#374151;color:#9ca3af}
.badge.info{background:#1e3a5f;color:#93c5fd}
.trust-badge{display:inline-flex;align-items:center;margin-left:.45rem;padding:.08rem .42rem;border-radius:999px;font-size:.62rem;font-weight:700;letter-spacing:.03em;border:1px solid transparent;vertical-align:middle}
.trust-badge.trust-ms{background:rgba(56,189,248,.15);border-color:rgba(56,189,248,.35);color:#7dd3fc}
.trust-badge.trust-gov{background:rgba(245,158,11,.13);border-color:rgba(245,158,11,.35);color:#fbbf24}
.trust-badge.trust-community{background:rgba(148,163,184,.14);border-color:rgba(148,163,184,.35);color:#cbd5e1}
.source-filter-chips{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;padding-top:.75rem}
.source-filter-chip{border:1px solid var(--border);background:var(--surface);color:var(--muted);padding:.2rem .55rem;border-radius:999px;font-size:.72rem;font-weight:700;cursor:pointer;transition:all .15s;font-family:inherit}
.source-filter-chip:hover{border-color:var(--accent);color:var(--accent)}
.source-filter-chip.active{background:rgba(56,189,248,.15);border-color:var(--accent);color:var(--accent)}
.sev-critical{border-left:3px solid #dc2626}.sev-high{border-left:3px solid #ef4444}
.sev-medium{border-left:3px solid #eab308}.sev-low{border-left:3px solid #6b7280}
.sev-warning{border-left:3px solid #f59e0b}
/* Scanner card enhancements */
.scanner-card-title{flex-direction:column;align-items:flex-start!important;gap:.25rem}
.scanner-card-title>span:first-child{font-size:1.05rem}
.scanner-subtitle{font-size:.76rem;color:var(--muted);font-weight:400;line-height:1.4}
.scanner-summary-bar{display:flex;flex-wrap:wrap;gap:.5rem;padding:.6rem 1.25rem;border-bottom:1px solid var(--border);background:rgba(255,255,255,.015)}
.ssb-item{font-size:.78rem;padding:.3rem .65rem;border-radius:6px;border:1px solid var(--border)}
.ssb-total{font-weight:700;color:var(--accent);border-color:var(--accent)}
.ssb-pass{color:#22c55e;border-color:rgba(34,197,94,.25)}.ssb-fail{color:#ef4444;border-color:rgba(239,68,68,.25)}
.ssb-warn{color:#f59e0b;border-color:rgba(245,158,11,.25)}.ssb-skip{color:var(--muted);border-color:var(--border)}
.scanner-cats{display:flex;flex-wrap:wrap;gap:.4rem;padding:.6rem 1.25rem}
.scat-chip{display:inline-flex;align-items:center;gap:.3rem;padding:.25rem .55rem;border-radius:6px;font-size:.72rem;background:rgba(255,255,255,.04);border:1px solid var(--border);cursor:default}
.scat-icon{font-size:.85rem}.scat-label{font-weight:600;color:var(--text)}.scat-cnt{font-weight:700;color:var(--accent);min-width:1.2rem;text-align:center;background:rgba(59,130,246,.12);border-radius:4px;padding:0 .3rem}
.scanner-table .cat-header td{background:rgba(59,130,246,.06);font-weight:700;font-size:.85rem;padding:.55rem 1rem;border-bottom:2px solid var(--accent);letter-spacing:.01em}
.cat-hdr-icon{margin-right:.35rem;font-size:.95rem}
.cat-hdr-desc{display:block;font-size:.72rem;font-weight:400;color:var(--muted);margin-top:.2rem;line-height:1.4}
.scan-status-critical,.scan-status-high,.scan-status-medium{color:#ef4444;font-weight:700;font-size:.72rem}
.scan-status-warning,.scan-status-low{color:#f59e0b;font-weight:600;font-size:.72rem}
td.fix{font-size:.78rem;color:var(--muted);line-height:1.5}
td.fix em{color:rgba(255,255,255,.2)}
/* Expandable rows */
.expandable{cursor:pointer;transition:background .15s}.expandable:hover{background:rgba(255,255,255,.03)}
.row-detail{display:none}.row-detail.open{display:table-row}
.detail-panel{padding:.75rem 1rem;background:var(--bg);border-top:1px dashed var(--border);font-size:.82rem;color:var(--muted);line-height:1.6}
/* Env compact pills */
.env-grid{display:flex;flex-wrap:wrap;gap:.4rem;padding:.75rem 1rem}
.env-pill{display:inline-flex;align-items:center;gap:.35rem;padding:.35rem .65rem;border:1px solid var(--border);border-radius:8px;font-size:.78rem;cursor:default;transition:border-color .15s;background:none;color:var(--text);font-family:inherit}
button.env-pill{cursor:pointer}button.env-pill:hover{border-color:var(--accent)}
.ep-icon{font-size:.9rem}.ep-name{font-weight:600}
.ep-st{font-size:.7rem;font-weight:800;margin-left:.15rem}
.ep-st.on{color:#22c55e}.ep-st.off{color:var(--muted)}
.env-on{border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.05)}
.env-off .ep-name{color:var(--muted)}.env-off .ep-icon{opacity:.4}
/* OWASP */
.owasp-item{border:1px solid var(--border);border-radius:var(--radius);margin-bottom:.65rem;overflow:hidden}
.owasp-item.fail{border-left:3px solid #ef4444}.owasp-item.pass{border-left:3px solid #22c55e}
.owasp-header{display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;cursor:pointer;transition:background .15s}
.owasp-header:hover{background:rgba(255,255,255,.03)}
.owasp-id{font-weight:800;font-size:.85rem;color:var(--accent);min-width:2.5rem}
.owasp-name{flex:1;font-weight:600;font-size:.88rem}
.owasp-count{font-weight:800;font-size:.88rem;min-width:2rem;text-align:right}
.owasp-item.fail .owasp-count{color:#ef4444}.owasp-item.pass .owasp-count{color:#22c55e}
.owasp-arrow{color:var(--muted);font-size:.7rem;transition:transform .2s}
.owasp-item.expanded .owasp-arrow{transform:rotate(90deg)}
.owasp-body{display:none;padding:.75rem 1rem;border-top:1px dashed var(--border);background:var(--bg)}
.owasp-item.expanded .owasp-body{display:block}
.owasp-summary,.owasp-action{font-size:.82rem;color:var(--muted);line-height:1.5;margin:.5rem 0}
.owasp-action{border-left:3px solid var(--accent);padding-left:.5rem;margin-top:.4rem}
.detail-ko-summary,.detail-ko-action{font-size:.8rem;color:var(--muted);line-height:1.5;margin:.4rem 0}
.detail-ko-action{border-left:3px solid var(--accent);padding-left:.5rem}
.comp-summary-td{max-width:280px;font-size:.78rem;color:var(--muted);line-height:1.45}
.comp-summary-cell .comp-desc-ko{display:block;margin-bottom:.25rem}
.comp-summary-cell .comp-action-ko{display:block;font-size:.75rem;border-left:2px solid var(--accent);padding-left:.4rem;margin-top:.3rem}
.arch-summary-block{margin-bottom:.6rem;padding-bottom:.5rem;border-bottom:1px dashed var(--border)}
.arch-summary-ko,.arch-action-ko{font-size:.8rem;color:var(--muted);line-height:1.5;margin:.3rem 0}
.arch-action-ko{border-left:3px solid var(--accent);padding-left:.5rem}
.owasp-desc{font-size:.82rem;color:var(--muted);margin-bottom:.5rem}
.owasp-findings{display:flex;flex-direction:column;gap:.3rem;margin-top:.75rem}
.of-row{font-size:.8rem;padding:.3rem 0;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.of-row code{color:var(--accent);font-size:.75rem}
.of-more{font-size:.78rem;color:var(--muted);padding:.3rem 0}
/* Architecture */
.arch-domain{border:1px solid var(--border);border-radius:var(--radius);margin-bottom:.65rem;overflow:hidden}
.arch-domain.fail{border-left:3px solid #ef4444}.arch-domain.pass{border-left:3px solid #22c55e}
.arch-header{display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;cursor:pointer;transition:background .15s}
.arch-header:hover{background:rgba(255,255,255,.03)}
.arch-icon{font-size:1.1rem}.arch-name{flex:1;font-weight:600;font-size:.88rem}
.arch-stat{font-weight:700;font-size:.82rem}
.arch-fail{color:#ef4444}.arch-pass-text{color:#22c55e}
.arch-arrow{color:var(--muted);font-size:.7rem;transition:transform .2s}
.arch-domain.expanded .arch-arrow{transform:rotate(90deg)}
.arch-body{display:none;padding:.75rem 1rem;border-top:1px dashed var(--border);background:var(--bg)}
.arch-domain.expanded .arch-body{display:block}
.arch-domain.arch-highlight,.owasp-item.arch-highlight,.comp-section.arch-highlight{animation:archPulse 1.2s ease 2}
tr.arch-highlight td{animation:archPulseTd 1.2s ease 2}
@keyframes archPulse{0%,100%{box-shadow:none}50%{box-shadow:0 0 0 2px var(--accent)}}
@keyframes archPulseTd{0%,100%{background:transparent}50%{background:rgba(59,130,246,.12)}}
.arch-links,.owasp-arch-links,.scanner-arch-links,.comp-arch-links{display:flex;flex-wrap:wrap;align-items:center;gap:.35rem;margin-top:.5rem;padding-top:.5rem;border-top:1px dashed var(--border)}
.arch-links-label{font-size:.7rem;color:var(--muted);margin-right:.35rem;font-weight:600}
.arch-link-chip{display:inline-flex;align-items:center;gap:.2rem;padding:.2rem .45rem;border-radius:5px;font-size:.72rem;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.3);color:var(--accent);cursor:pointer;transition:all .15s;font-family:inherit}
.arch-link-chip:hover{background:rgba(59,130,246,.2);border-color:var(--accent)}
.arch-link-chip.arch-sm{font-size:.68rem;padding:.15rem .35rem}
.arch-pass{color:#22c55e;font-size:.85rem;padding:.5rem 0}
.af-row{font-size:.8rem;padding:.3rem 0;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.af-row code{color:var(--accent);font-size:.75rem}
/* Compliance */
.comp-frameworks{display:flex;flex-wrap:wrap;gap:.5rem;padding:1rem 1.25rem;border-bottom:1px solid var(--border)}
.comp-fw-chip{display:flex;flex-direction:column;padding:.6rem .85rem;border:1px solid var(--border);border-radius:8px;text-decoration:none;color:var(--text);transition:border-color .15s;min-width:140px}
.comp-fw-chip:hover{border-color:var(--accent)}
.comp-fw-chip strong{font-size:.82rem;margin-bottom:.15rem}.comp-fw-chip span{font-size:.7rem;color:var(--muted)}
.comp-section{border-bottom:1px solid var(--border)}
.comp-title{padding:.75rem 1.25rem;font-weight:700;font-size:.9rem;cursor:pointer;display:flex;align-items:center;gap:.75rem;transition:background .15s}
.comp-title:hover{background:rgba(255,255,255,.03)}
.comp-stat{font-size:.78rem;font-weight:600;margin-left:auto}
.cs-pass{color:#22c55e}.cs-fail{color:#ef4444}
.comp-arrow{color:var(--muted);font-size:.7rem;transition:transform .2s}
.comp-section.expanded .comp-arrow{transform:rotate(90deg)}
.comp-body{display:none;padding:0}
.comp-section.expanded .comp-body{display:block}
.comp-arch-links{padding:.5rem 1rem;background:rgba(255,255,255,.02);border-bottom:1px solid var(--border)}
.comp-pass td{opacity:.7}.comp-fail td{}.comp-st-pass{color:#22c55e;font-weight:700}.comp-st-fail{color:#ef4444;font-weight:700}
/* Trend */
.trend-section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;margin-bottom:1.5rem}
.trend-section h3{font-size:.95rem;margin-bottom:.75rem}
.trend-chart{width:100%;height:220px;position:relative}
.trend-chart canvas{width:100%!important;height:220px!important;cursor:crosshair}
/* Severity bar */
.sev-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;margin-bottom:1.5rem;background:var(--border)}
.sev-bar div{height:100%}
/* Setup Modal */
.setup-modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;justify-content:center;align-items:center;backdrop-filter:blur(3px)}
.setup-modal-overlay.open{display:flex}
.setup-modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;max-width:600px;width:95%;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.setup-modal-header{display:flex;justify-content:space-between;align-items:center;padding:1.25rem 1.5rem;border-bottom:1px solid var(--border)}
.setup-modal-header h3{font-size:1rem;font-weight:700;display:flex;align-items:center;gap:.5rem}
.setup-modal-close{background:none;border:none;color:var(--muted);font-size:1.2rem;cursor:pointer;padding:.25rem;line-height:1}
.setup-modal-close:hover{color:var(--text)}
.setup-modal-body{padding:1.5rem}
.setup-method{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:1rem;margin-bottom:.75rem}
.setup-method-label{font-size:.82rem;font-weight:700;margin-bottom:.35rem;display:flex;align-items:center;gap:.4rem}
.method-badge{font-size:.62rem;padding:.1rem .4rem;border-radius:3px;font-weight:800;letter-spacing:.04em}
.method-badge.oauth{background:#166534;color:#86efac}.method-badge.apikey{background:#854d0e;color:#fde68a}.method-badge.cli{background:#1e3a5f;color:#93c5fd}
.setup-method p{font-size:.82rem;color:var(--muted);line-height:1.6;margin-bottom:.5rem}
.setup-cmd{display:flex;align-items:stretch;border-radius:8px;overflow:hidden;border:1px solid var(--border);margin-top:.5rem}
.setup-cmd code{flex:1;padding:.6rem .8rem;background:#0f172a;font-family:'SF Mono','Fira Code',monospace;font-size:.78rem;color:var(--accent);white-space:pre-wrap;word-break:break-all}
.setup-cmd-copy{padding:.6rem .8rem;background:var(--border);color:var(--text);border:none;cursor:pointer;font-size:.75rem;font-weight:700;transition:background .15s;min-width:50px}
.setup-cmd-copy:hover{background:var(--accent);color:var(--bg)}
.setup-cmd-copy.copied{background:#22c55e;color:#fff}
.setup-warning{display:flex;gap:.5rem;padding:.75rem;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;font-size:.78rem;color:#fca5a5;margin-top:.75rem}
.setup-section-title{font-size:.78rem;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
/* Provider mini cards */
.prov-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.65rem;margin-bottom:1.5rem}
.prov-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:.85rem;cursor:pointer;transition:border-color .15s,transform .1s;text-align:center}
.prov-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.prov-card-icon{font-size:1.4rem;margin-bottom:.3rem}
.prov-card-name{font-size:.75rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.3rem}
.prov-card-num{font-size:1.4rem;font-weight:800;color:#ef4444;line-height:1}
.prov-card-num .prov-card-total{font-size:.8rem;color:var(--muted);font-weight:600}
.prov-card-sev{display:flex;justify-content:center;gap:.3rem;margin-top:.35rem;font-size:.65rem;font-weight:700}
.pcs-crit{color:#dc2626}.pcs-high{color:#ef4444}.pcs-med{color:#eab308}
/* Severity bar */
.sev-bar-wrap{margin-bottom:1.5rem}
.sev-bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--border)}
.sev-bar div{height:100%;transition:width .3s}
.sev-legend{display:flex;justify-content:center;gap:1rem;margin-top:.5rem;font-size:.72rem;color:var(--muted)}
.sev-legend span{display:flex;align-items:center;gap:.25rem}
.sev-legend .dot{width:8px;height:8px;border-radius:2px;display:inline-block}
/* Overview grid layout */
.ov-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}
.ov-grid .card{margin-bottom:0}
@media(max-width:768px){.ov-grid{grid-template-columns:1fr}}
/* Stat pill */
.stats-row{display:flex;gap:.5rem;margin-bottom:1rem;flex-wrap:wrap}
.stat-pill{flex:1;min-width:100px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem;display:flex;align-items:center;gap:.65rem}
.stat-pill .sp-icon{font-size:1.2rem;opacity:.7;min-width:1.4rem;text-align:center}
.stat-pill .sp-num{font-size:1.6rem;font-weight:800;line-height:1}
.stat-pill .sp-label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.stat-pill.sp-crit .sp-num{color:#dc2626}.stat-pill.sp-high .sp-num{color:#ef4444}.stat-pill.sp-med .sp-num{color:#eab308}.stat-pill.sp-total .sp-num{color:var(--accent)}
.stat-pill.sp-pass .sp-num{color:#22c55e}.stat-pill.sp-warn .sp-num{color:#f59e0b}.stat-pill.sp-info .sp-num{color:#64748b}.stat-pill.sp-skip .sp-num{color:var(--muted)}
.stats-etc .stat-pill{min-width:70px}.stats-etc .sp-num{font-size:1.2rem}.stats-etc .sp-label{font-size:.65rem}
/* Top findings */
.top-finding{display:flex;gap:.65rem;padding:.6rem .85rem;border-bottom:1px solid var(--border);transition:background .15s;cursor:pointer}
.top-finding:last-child{border-bottom:none}
.top-finding:hover{background:rgba(255,255,255,.02)}
.tf-badge{min-width:50px;padding-top:.1rem}
.tf-body{flex:1;min-width:0}
.tf-check{font-size:.8rem;margin-bottom:.15rem;display:flex;align-items:center;gap:.5rem}
.tf-check code{color:var(--accent);font-size:.75rem}
.tf-prov{font-size:.6rem;font-weight:700;color:var(--muted);background:var(--border);padding:.1rem .35rem;border-radius:3px;text-transform:uppercase;letter-spacing:.04em}
.tf-cnt{font-size:.7rem;color:var(--muted);margin-left:.25rem}
.tf-msg{font-size:.78rem;color:var(--muted);line-height:1.45;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
/* Quick nav */
.quick-nav{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.5rem;margin-bottom:1.5rem}
.qn-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:.7rem .85rem;cursor:pointer;transition:border-color .15s;display:flex;align-items:center;gap:.6rem}
.qn-card:hover{border-color:var(--accent)}
.qn-icon{font-size:1.1rem}.qn-text{font-size:.8rem;font-weight:600}
.qn-badge{margin-left:auto;font-size:.7rem;font-weight:700;color:var(--accent);background:rgba(56,189,248,.1);padding:.15rem .4rem;border-radius:4px}
/* Best Practices hub */
.bp-subtabs{display:flex;flex-wrap:wrap;gap:.4rem;margin-bottom:1rem}
.bp-subtab{padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s}
.bp-subtab:hover{border-color:var(--accent);transform:translateY(-1px)}
.bp-subtab.active{border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.12) inset}
.bp-panel{display:none}
.bp-panel.active{display:block}
/* Footer */
footer{text-align:center;padding:2rem 0 1rem;color:var(--muted);font-size:.78rem}
@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}.score-section{flex-direction:column}.tabs{gap:0}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1><span>◆</span> ClaudeSec Security Dashboard <span class="ver">v{{VERSION}}</span></h1>
  <div class="header-right">
    <div class="meta">Scan: {{NOW}} · {{DURATION}}s</div>
  </div>
</header>

<div class="tabs" id="mainTabs">
  <button class="tab active" onclick="switchTab('overview')">Overview</button>
  <button class="tab" onclick="switchTab('prowler')">Prowler CSPM</button>
  <button class="tab" onclick="switchTab('github')">GitHub Security</button>
  <button class="tab" onclick="switchTab('bestpractices')">Best Practices</button>
  <button class="tab" onclick="switchTab('arch')">Architecture</button>
  <button class="tab" onclick="switchTab('networktools')">Network &amp; security tools</button>
</div>

<!-- ── Tab: Overview ───────────────────────────────────────────────── -->
<div class="tab-panel active" id="tab-overview">
  <!-- Stat pills -->
  <div class="stats-row">
    <div class="stat-pill sp-total"><div class="sp-icon">📊</div><div><div class="sp-num">{{TOTAL_ISSUES}}</div><div class="sp-label">Total findings</div></div></div>
    <div class="stat-pill sp-crit"><div class="sp-icon">🔴</div><div><div class="sp-num">{{N_CRIT}}</div><div class="sp-label">Critical</div></div></div>
    <div class="stat-pill sp-high"><div class="sp-icon">🟠</div><div><div class="sp-num">{{N_HIGH}}</div><div class="sp-label">High</div></div></div>
    <div class="stat-pill sp-med"><div class="sp-icon">🟡</div><div><div class="sp-num">{{N_MED}}</div><div class="sp-label">Medium</div></div></div>
  </div>
  <div class="stats-row stats-etc">
    <div class="stat-pill sp-pass"><div class="sp-icon">✓</div><div><div class="sp-num">{{TOTAL_PASSED}}</div><div class="sp-label">Passed</div></div></div>
    <div class="stat-pill sp-warn"><div class="sp-icon">⚠</div><div><div class="sp-num">{{N_WARN}}</div><div class="sp-label">Warnings</div></div></div>
    <div class="stat-pill sp-info"><div class="sp-icon">ℹ</div><div><div class="sp-num">{{N_INFO}}</div><div class="sp-label">Info</div></div></div>
    <div class="stat-pill sp-skip"><div class="sp-icon">—</div><div><div class="sp-num">{{SKIPPED}}</div><div class="sp-label">Skipped</div></div></div>
  </div>

  <!-- Severity distribution bar -->
  <div class="sev-bar-wrap">
    <div class="sev-bar">
      <div style="width:{{BAR_CRIT}}%;background:#dc2626" title="Critical {{N_CRIT}}"></div>
      <div style="width:{{BAR_HIGH}}%;background:#ef4444" title="High {{N_HIGH}}"></div>
      <div style="width:{{BAR_MED}}%;background:#eab308" title="Medium {{N_MED}}"></div>
      <div style="width:{{BAR_WARN}}%;background:#f59e0b" title="Warning {{N_WARN}}"></div>
      <div style="width:{{BAR_LOW}}%;background:#6b7280" title="Low {{N_LOW}}"></div>
    </div>
    <div class="sev-legend">
      <span><span class="dot" style="background:#dc2626"></span>Critical {{N_CRIT}}</span>
      <span><span class="dot" style="background:#ef4444"></span>High {{N_HIGH}}</span>
      <span><span class="dot" style="background:#eab308"></span>Medium {{N_MED}}</span>
      <span><span class="dot" style="background:#f59e0b"></span>Warning {{N_WARN}}</span>
      <span><span class="dot" style="background:#6b7280"></span>Low {{N_LOW}}</span>
    </div>
  </div>

  <!-- Score + Provider cards row -->
  <div class="ov-grid">
    <div class="card" style="margin-bottom:0">
      <div class="card-title">Security Score</div>
      <div style="padding:1rem;display:flex;align-items:center;gap:1.5rem">
        <div class="score-ring">
          <svg width="110" height="110" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="52" fill="none" stroke="{{GRADE_COLOR}}22" stroke-width="10"/>
            <circle cx="60" cy="60" r="52" fill="none" stroke="{{GRADE_COLOR}}" stroke-width="10"
              stroke-dasharray="{{SCORE_DASH}} 327" stroke-linecap="round"/>
          </svg>
          <div class="value" style="color:{{GRADE_COLOR}}">{{SCORE}}</div>
          <div class="grade">Grade {{GRADE}}</div>
        </div>
        <div style="flex:1;font-size:.82rem;color:var(--muted);line-height:1.8">
          <div>Scanner: <strong style="color:var(--text)">{{PASSED}}</strong> passed / <strong style="color:#ef4444">{{FAILED}}</strong> failed / <strong style="color:#eab308">{{WARNINGS}}</strong> warnings</div>
          <div>Prowler: <strong style="color:#ef4444">{{TOTAL_PROWLER_FAIL}}</strong> failed / <strong style="color:#22c55e">{{TOTAL_PROWLER_PASS}}</strong> passed</div>
          <div>Environment: <strong style="color:var(--text)">{{ENV_CONNECTED}}/{{ENV_TOTAL}}</strong> connected</div>
          {{SCAN_SCOPE_HTML}}
        </div>
      </div>
    </div>
    <div class="card" style="margin-bottom:0">
      <div class="card-title">Provider Summary</div>
      <div style="padding:.75rem">
        <div class="prov-cards">{{PROV_CARDS}}</div>
      </div>
    </div>
  </div>

  <!-- Quick nav -->
  <div class="quick-nav">
    <div class="qn-card" onclick="switchTab('overview','scanner-section')"><span class="qn-icon">🛡</span><span class="qn-text">Scanner</span><span class="qn-badge">{{SCANNER_ISSUES}}</span></div>
    <div class="qn-card" onclick="switchTab('prowler')"><span class="qn-icon">☁</span><span class="qn-text">Prowler CSPM</span><span class="qn-badge">{{TOTAL_PROWLER_FAIL}}</span></div>
    <div class="qn-card" onclick="switchTab('github')"><span class="qn-icon">🐙</span><span class="qn-text">GitHub Security</span><span class="qn-badge">{{GH_TOTAL}}</span></div>
    <div class="qn-card" onclick="switchTab('bestpractices')"><span class="qn-icon">📚</span><span class="qn-text">Best Practices</span></div>
    <div class="qn-card" onclick="switchTab('arch')"><span class="qn-icon">🏗</span><span class="qn-text">Architecture</span></div>
    <div class="qn-card" onclick="switchTab('networktools')"><span class="qn-icon">🔬</span><span class="qn-text">Network &amp; security tools</span><span class="qn-badge">{{NETWORK_TOOLS_BADGE}}</span></div>
  </div>

  <!-- Top Critical/High findings -->
  <div class="card">
    <div class="card-title">🔥 Top Critical / High findings</div>
    <div class="card-subtitle" style="font-size:.75rem;color:var(--muted);margin-top:-.35rem;margin-bottom:.5rem">By unique check (click row to open Scanner or Prowler tab)</div>
    <div style="max-height:360px;overflow-y:auto">
      {{TOP_FINDINGS}}
    </div>
  </div>

  <!-- Environment (compact) -->
  <div class="card">
    <div class="card-title">Environment ({{ENV_CONNECTED}}/{{ENV_TOTAL}} connected) <span style="font-size:.72rem;color:var(--muted);font-weight:400;margin-left:.5rem">Click to configure</span></div>
    <div class="env-grid">{{ENV_HTML}}</div>
  </div>

  {{AUTH_SUMMARY_HTML}}

  <!-- Trend -->
  <div class="trend-section">
    <h3>📊 Scan trend <span style="font-size:.72rem;color:var(--muted);font-weight:400;margin-left:.5rem">Security score and fail/warn over time (hover for details)</span></h3>
    <div class="trend-chart"><canvas id="trendChart"></canvas></div>
  </div>

  <!-- Scanner findings (categorized) -->
  <div class="card scanner-card" id="scanner-section">
    <div class="card-title scanner-card-title">
      <span>🛡️ ClaudeSec local security scanner results</span>
      <span class="scanner-subtitle">Security issues from static analysis of project source, config, and environment</span>
    </div>
    <div class="scanner-summary-bar">
      <div class="ssb-item ssb-total"><strong>{{SCANNER_TOTAL}}</strong> checks</div>
      <div class="ssb-item ssb-pass">✓ {{PASSED}} passed</div>
      <div class="ssb-item ssb-fail">✗ {{FAILED}} failed</div>
      <div class="ssb-item ssb-warn">⚠ {{WARNINGS}} warnings</div>
      <div class="ssb-item ssb-skip">— {{SKIPPED}} skipped</div>
    </div>
    <div class="scanner-cats">{{SCANNER_CAT_SUMMARY}}</div>
    <div style="max-height:55vh;overflow-y:auto">
      <table class="scanner-table"><thead><tr><th style="width:68px">Severity</th><th style="width:62px">Status</th><th style="width:100px">Check ID</th><th>Finding</th><th style="width:280px">Details / Remediation</th></tr></thead>
      <tbody>{{SCANNER_ROWS}}</tbody></table>
    </div>
  </div>
</div>

<!-- ── Tab: Prowler CSPM ──────────────────────────────────────────── -->
<div class="tab-panel" id="tab-prowler">
  <div class="card">
    <div class="card-title">Prowler cloud scan summary</div>
    <div style="padding:1rem 1.25rem">
      <table><thead><tr><th>Provider</th><th class="r">Total</th><th class="r">Critical</th><th class="r">High</th><th class="r">Medium</th><th class="r">Low</th><th class="r">Passed</th></tr></thead>
      <tbody>{{PROV_TABLE}}</tbody></table>
    </div>
  </div>

  <!-- Provider sub-tabs -->
  <div class="prov-subtabs" style="display:flex;flex-wrap:wrap;gap:.4rem;margin:1rem 0;padding:0 .25rem">
    <button class="prov-subtab active" onclick="switchProvTab('aws')" id="provtab-aws" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">☁ AWS ({{AWS_TOTAL}})</button>
    <button class="prov-subtab" onclick="switchProvTab('gcp')" id="provtab-gcp" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">◈ GCP ({{GCP_TOTAL}})</button>
    <button class="prov-subtab" onclick="switchProvTab('gws')" id="provtab-gws" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">🏢 Google Workspace ({{GWS_TOTAL}})</button>
    <button class="prov-subtab" onclick="switchProvTab('k8s')" id="provtab-k8s" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">⎈ Kubernetes ({{K8S_TOTAL}})</button>
    <button class="prov-subtab" onclick="switchProvTab('azure')" id="provtab-azure" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">◇ Azure ({{AZURE_TOTAL}})</button>
    <button class="prov-subtab" onclick="switchProvTab('m365')" id="provtab-m365" style="padding:.35rem .8rem;font-size:.78rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s">📧 M365 ({{M365_TOTAL}})</button>
  </div>

  <div class="prov-panel active" id="provpanel-aws">
    <div class="card">
      <div class="card-title">☁ AWS findings ({{AWS_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{AWS_TABLE}}</tbody></table>
      </div>
    </div>
  </div>

  <div class="prov-panel" id="provpanel-gcp">
    <div class="card">
      <div class="card-title">◈ GCP findings ({{GCP_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{GCP_TABLE}}</tbody></table>
      </div>
    </div>
  </div>

  <div class="prov-panel" id="provpanel-gws">
    <div class="card">
      <div class="card-title">🏢 Google Workspace findings ({{GWS_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{GWS_TABLE}}</tbody></table>
      </div>
    </div>
  </div>

  <div class="prov-panel" id="provpanel-k8s">
    <div class="card">
      <div class="card-title">⎈ Kubernetes findings ({{K8S_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{K8S_TABLE}}</tbody></table>
      </div>
    </div>
  </div>

  <div class="prov-panel" id="provpanel-azure">
    <div class="card">
      <div class="card-title">◇ Azure findings ({{AZURE_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{AZURE_TABLE}}</tbody></table>
      </div>
    </div>
  </div>

  <div class="prov-panel" id="provpanel-m365">
    <div class="card">
      <div class="card-title">📧 Microsoft 365 findings ({{M365_TOTAL}})</div>
      <div style="max-height:60vh;overflow-y:auto">
        <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th></tr></thead>
        <tbody>{{M365_TABLE}}</tbody></table>
      </div>
    </div>
  </div>
</div>

<!-- ── Tab: GitHub Security ───────────────────────────────────────── -->
<div class="tab-panel" id="tab-github">
  <div class="card">
    <div class="card-title">GitHub security check results ({{GH_TOTAL}} findings)</div>
    <div style="max-height:70vh;overflow-y:auto">
      <table><thead><tr><th style="width:80px">Severity</th><th style="width:250px">Check ID</th><th>Description</th><th>Affected repos</th></tr></thead>
      <tbody>{{GH_TABLE}}</tbody></table>
    </div>
  </div>
</div>

<!-- ── Tab: Best Practices (Unified) ───────────────────────────────── -->
<div class="tab-panel" id="tab-bestpractices">
  <div class="card">
    <div class="card-title">📚 Best Practices hub <span class="card-subtitle" style="font-size:.75rem;color:var(--muted);font-weight:400;margin-left:.5rem">OWASP + Compliance + Audit Points in one place</span></div>
    <div style="padding:1rem 1.25rem">
      <div class="bp-subtabs">
        <button class="bp-subtab active" onclick="switchBpTab('owasp')" id="bptab-owasp">🛡 OWASP</button>
        <button class="bp-subtab" onclick="switchBpTab('compliance')" id="bptab-compliance">📋 Compliance</button>
        <button class="bp-subtab" onclick="switchBpTab('auditpoints')" id="bptab-auditpoints">✅ Audit Points</button>
      </div>

      <div class="bp-panel active" id="bppanel-owasp">
        <div class="card" style="margin:0 0 1rem 0">
          <div class="card-title">OWASP Top 10:2025 + LLM Top 10:2025 mapping</div>
          <div style="padding:1rem 1.25rem">
            {{OWASP_HTML}}
          </div>
        </div>
      </div>

      <div class="bp-panel" id="bppanel-compliance">
        <div class="card" style="margin:0 0 1rem 0">
          <div class="card-title">Compliance framework mapping</div>
          {{COMP_HTML}}
        </div>
      </div>

      <div class="bp-panel" id="bppanel-auditpoints">
        {{AUDIT_POINTS_HTML}}
      </div>
    </div>
  </div>
</div>

<!-- ── Tab: Architecture ─────────────────────────────────────────── -->
<div class="tab-panel" id="tab-arch">
  <div class="card">
    <div class="card-title">Architecture diagram</div>
    <div style="padding:1rem 1.25rem">
      {{ARCH_IMG}}
    </div>
  </div>
  <div class="card">
    <div class="card-title">Architecture security domains</div>
    <div style="padding:1rem 1.25rem">
      {{ARCH_HTML}}
    </div>
  </div>
</div>

<!-- ── Tab: Network & security tools ─────────────────────────────── -->
<div class="tab-panel" id="tab-networktools">
  {{NETWORK_TOOLS_HTML}}
</div>

<footer>Generated by ClaudeSec v{{VERSION}} · {{NOW}}</footer>
</div>

<!-- Setup Modal -->
<div id="setupModal" class="setup-modal-overlay" onclick="if(event.target===this)closeSetup()">
  <div class="setup-modal">
    <div class="setup-modal-header">
      <h3 id="setupModalTitle">Provider setup</h3>
      <button class="setup-modal-close" onclick="closeSetup()">&times;</button>
    </div>
    <div class="setup-modal-body" id="setupModalBody"></div>
  </div>
</div>

<script>var HIST_DATA={{HISTORY_JSON}};
/* Provider sub-tab switching within Prowler CSPM */
function switchProvTab(id){
  document.querySelectorAll('.prov-panel').forEach(function(p){p.classList.remove('active')});
  document.querySelectorAll('.prov-subtab').forEach(function(t){t.classList.remove('active')});
  var panel=document.getElementById('provpanel-'+id);
  if(panel)panel.classList.add('active');
  var tab=document.getElementById('provtab-'+id);
  if(tab)tab.classList.add('active');
}
/* Best Practices internal sub-tab switching */
function switchBpTab(id){
  document.querySelectorAll('.bp-panel').forEach(function(p){p.classList.remove('active')});
  document.querySelectorAll('.bp-subtab').forEach(function(t){t.classList.remove('active')});
  var panel=document.getElementById('bppanel-'+id);
  if(panel)panel.classList.add('active');
  var tab=document.getElementById('bptab-'+id);
  if(tab)tab.classList.add('active');
}
/* Tab switching — id: tab name, targetId: optional element id to scroll into view */
function switchTab(id,targetId){
  document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active')});
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
  var panel=document.getElementById('tab-'+id);
  if(panel)panel.classList.add('active');
  var tabs=document.querySelectorAll('.tab');
  var names=['overview','prowler','github','bestpractices','arch','networktools'];
  var idx=names.indexOf(id);
  if(idx>=0&&tabs[idx])tabs[idx].classList.add('active');
  if(targetId){
    setTimeout(function(){
      var el=document.getElementById(targetId);
      if(el){el.scrollIntoView({behavior:'smooth',block:'nearest'});el.classList.add('arch-highlight');setTimeout(function(){el.classList.remove('arch-highlight')},2000)}
    },80);
  }
}
function parseMsPresetFilter(preset){
  var raw=(preset||'all').toLowerCase();
  if(raw==='all')return {all:true,tokens:{}};
  if(raw==='none')return {all:false,tokens:{}};
  var tokens={};
  raw.split(',').forEach(function(t){
    var s=t.trim();
    if(!s)return;
    if(s==='all'){tokens={};tokens.all=true;return}
    if(s==='none'){tokens={};tokens.none=true;return}
    if(s==='official'||s==='gov'||s==='community')tokens[s]=true;
  });
  if(tokens.all)return {all:true,tokens:{}};
  if(tokens.none)return {all:false,tokens:{}};
  if(Object.keys(tokens).length===0)return {all:true,tokens:{}};
  return {all:false,tokens:tokens};
}
var MS_SOURCE_PRESET_STORAGE_KEY='claudesec:dashboard:msSourcePreset';
var MS_SOURCE_PRESET_LEGACY_KEY='claudesec.msSourcePreset';
function getStoredMsSourcePreset(){
  try{
    var v=localStorage.getItem(MS_SOURCE_PRESET_STORAGE_KEY);
    if(!v){
      var legacy=localStorage.getItem(MS_SOURCE_PRESET_LEGACY_KEY);
      if(legacy){
        v=legacy;
        localStorage.setItem(MS_SOURCE_PRESET_STORAGE_KEY,legacy);
      }
    }
    if(!v)return '';
    var parsed=parseMsPresetFilter(v);
    if(parsed.all&&v!=='all')return '';
    if(v==='none'||v==='all'||v==='official,gov')return v;
    return '';
  }catch(_){
    return '';
  }
}
function setStoredMsSourcePreset(preset){
  try{localStorage.setItem(MS_SOURCE_PRESET_STORAGE_KEY,preset)}catch(_){/* ignore */}
}
function applyMsSourcePresetFilter(btn){
  var root=btn.closest('.ms-source-root');
  if(!root)return;
  root.querySelectorAll('.source-filter-chip').forEach(function(ch){ch.classList.remove('active')});
  btn.classList.add('active');
  var preset=btn.getAttribute('data-filter')||'all';
  setStoredMsSourcePreset(preset);
  var parsed=parseMsPresetFilter(preset);
  var entries=root.querySelectorAll('.ms-source-entry');
  var visible=0;
  entries.forEach(function(el){
    var token=(el.getAttribute('data-trust-token')||'').toLowerCase();
    var show=parsed.all||!!parsed.tokens[token];
    el.style.display=show?'':'none';
    if(show)visible+=1;
  });
  var status=root.querySelector('.ms-source-filter-status');
  if(status){status.textContent='View preset: '+preset+' · visible '+visible+' / '+entries.length+' sources'}
}
(function(){
  var root=document.querySelector('.ms-source-root');
  if(!root)return;
  var preset=getStoredMsSourcePreset();
  if(!preset)return;
  var btn=root.querySelector('.source-filter-chip[data-filter="'+preset+'"]');
  if(btn)applyMsSourcePresetFilter(btn);
})();
/* Expandable rows */
function toggleRow(tr){var d=tr.nextElementSibling;if(!d||!d.classList.contains('row-detail'))return;d.classList.toggle('open');tr.classList.toggle('expanded')}
function toggleOwasp(el){el.closest('.owasp-item').classList.toggle('expanded')}
function toggleArch(el){el.closest('.arch-domain').classList.toggle('expanded')}
function toggleComp(el){el.closest('.comp-section').classList.toggle('expanded')}
/* Trend chart — rich multi-line with interactive tooltip */
(function(){
  var canvas=document.getElementById('trendChart');
  if(!canvas)return;
  var history=(typeof HIST_DATA!=='undefined')?HIST_DATA:[];
  if(history.length<2){canvas.parentElement.innerHTML='<div style="color:var(--muted);font-size:.85rem;text-align:center;padding:2rem">Scan trend chart appears after 2+ scans.</div>';return}
  var ctx=canvas.getContext('2d');
  var W=canvas.parentElement.offsetWidth,H=220;
  canvas.width=W*2;canvas.height=H*2;canvas.style.width=W+'px';canvas.style.height=H+'px';ctx.scale(2,2);
  var pad={t:28,r:15,b:32,l:42},cw=W-pad.l-pad.r,ch=H-pad.t-pad.b,n=history.length;
  var maxFail=0;for(var k=0;k<n;k++){var tf=(history[k].failed||0)+(history[k].warnings||0);if(tf>maxFail)maxFail=tf}
  if(maxFail<5)maxFail=5;
  /* Grid */
  ctx.save();ctx.strokeStyle='#1e293b';ctx.lineWidth=0.5;
  for(var g=0;g<=100;g+=20){var gy=pad.t+ch-(g/100)*ch;ctx.beginPath();ctx.moveTo(pad.l,gy);ctx.lineTo(W-pad.r,gy);ctx.stroke();ctx.fillStyle='#64748b';ctx.font='9px system-ui';ctx.textAlign='right';ctx.fillText(g,pad.l-6,gy+3)}
  ctx.restore();
  /* X-axis labels */
  ctx.save();ctx.fillStyle='#64748b';ctx.font='8.5px system-ui';ctx.textAlign='center';
  var xstep=Math.max(1,Math.floor(n/8));
  for(var xi=0;xi<n;xi+=xstep){var xp=pad.l+(xi/(n-1))*cw;var dt=history[xi].timestamp||'';var lbl=dt.substring(5,16).replace('T',' ');ctx.fillText(lbl,xp,H-8)}
  ctx.restore();
  /* Bar: failed (stacked) */
  var barW=Math.max(3,Math.min(12,cw/n*0.6));
  for(var i=0;i<n;i++){
    var x=pad.l+(i/(n-1))*cw-barW/2;
    var f=history[i].failed||0;var w=history[i].warnings||0;
    var fh=(f/maxFail)*ch*0.7;var wh=(w/maxFail)*ch*0.7;
    ctx.fillStyle='rgba(239,68,68,0.35)';ctx.fillRect(x,pad.t+ch-fh-wh,barW,fh);
    ctx.fillStyle='rgba(245,158,11,0.25)';ctx.fillRect(x,pad.t+ch-wh,barW,wh);
  }
  /* Line: Score */
  function drawLine(key,color,lw){ctx.save();ctx.strokeStyle=color;ctx.lineWidth=lw;ctx.lineJoin='round';ctx.beginPath();for(var i=0;i<n;i++){var x=pad.l+(i/(n-1))*cw;var v=history[i][key]||0;var y=pad.t+ch-(v/100)*ch;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y)}ctx.stroke();ctx.restore();}
  /* Score glow */
  ctx.save();ctx.shadowColor='#38bdf8';ctx.shadowBlur=6;drawLine('score','#38bdf8',2.5);ctx.restore();
  drawLine('score','#38bdf8',2);
  /* Dots on score line */
  for(var i=0;i<n;i++){var x=pad.l+(i/(n-1))*cw;var y=pad.t+ch-((history[i].score||0)/100)*ch;ctx.fillStyle=(i===n-1)?'#38bdf8':'rgba(56,189,248,0.5)';ctx.beginPath();ctx.arc(x,y,(i===n-1)?4:2.5,0,Math.PI*2);ctx.fill();}
  /* Latest score label */
  var lastS=history[n-1].score||0;
  ctx.save();ctx.fillStyle='#38bdf8';ctx.font='bold 11px system-ui';ctx.textAlign='left';  ctx.fillText(lastS,pad.l+cw+4,pad.t+ch-(lastS/100)*ch+4);ctx.restore();
  /* Legend */
  ctx.save();ctx.font='9.5px system-ui';
  var lx=pad.l+5,ly=12;
  ctx.fillStyle='#38bdf8';ctx.fillRect(lx,ly-5,14,3);ctx.fillText('Score',lx+18,ly);
  ctx.fillStyle='rgba(239,68,68,0.5)';ctx.fillRect(lx+80,ly-6,10,8);ctx.fillStyle='#94a3b8';ctx.fillText('Failed',lx+94,ly);
  ctx.fillStyle='rgba(245,158,11,0.4)';ctx.fillRect(lx+125,ly-6,10,8);ctx.fillStyle='#94a3b8';ctx.fillText('Warnings',lx+139,ly);
  ctx.restore();
  /* Tooltip on hover */
  var tooltip=document.createElement('div');
  tooltip.style.cssText='position:absolute;display:none;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:6px 10px;font-size:12px;color:#e2e8f0;pointer-events:none;white-space:nowrap;z-index:50;box-shadow:0 4px 12px rgba(0,0,0,.4)';
  canvas.parentElement.style.position='relative';canvas.parentElement.appendChild(tooltip);
  canvas.addEventListener('mousemove',function(e){
    var rect=canvas.getBoundingClientRect();var mx=e.clientX-rect.left;
    var idx=Math.round(((mx-pad.l)/cw)*(n-1));
    if(idx<0||idx>=n){tooltip.style.display='none';return}
    var d=history[idx];var ts=(d.timestamp||'').replace('T',' ').substring(0,16);
    tooltip.innerHTML='<div style="font-weight:700;margin-bottom:3px">'+ts+'</div>'
      +'<div style="color:#38bdf8">Score: <b>'+d.score+'</b></div>'
      +'<div style="color:#ef4444">Failed: <b>'+(d.failed||0)+'</b> | Critical: <b>'+(d.critical||0)+'</b> | High: <b>'+(d.high||0)+'</b></div>'
      +'<div style="color:#f59e0b">Warnings: <b>'+(d.warnings||d.warn||0)+'</b></div>'
      +'<div style="color:#64748b">Passed: '+(d.passed||0)+' / Total: '+(d.total||0)+'</div>';
    tooltip.style.display='block';
    var tx=mx+12;if(tx+tooltip.offsetWidth>rect.width)tx=mx-tooltip.offsetWidth-12;
    var iy=pad.t+ch-((d.score||0)/100)*ch;
    tooltip.style.left=tx+'px';tooltip.style.top=Math.max(0,iy/2-20)+'px';
  });
  canvas.addEventListener('mouseleave',function(){tooltip.style.display='none'});
})();
/* Setup modal configs */
var SETUP_CONFIGS={
  github:{title:'🐙 GitHub setup',methods:[{type:'oauth',label:'GitHub CLI OAuth (recommended)',desc:'Authenticate GitHub CLI for repository and security API scan.',cmds:['gh auth login','gh auth status']},{type:'apikey',label:'Token via environment',desc:'Use classic/pat token when CLI login is not available.',cmds:['export GH_TOKEN=<token>','# or export GITHUB_TOKEN=<token>']}],docs:'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github',warn:'Use fine-grained token scopes and rotate tokens regularly (NIST AC-6).'},
  k8s:{title:'\u2638 Kubernetes setup',methods:[{type:'cli',label:'kubeconfig',desc:'Set default kubeconfig file.',cmds:['export KUBECONFIG=~/.kube/config']},{type:'cli',label:'EKS (AWS)',desc:'Connect to AWS EKS cluster.',cmds:['aws eks update-kubeconfig --name &lt;CLUSTER&gt; --region &lt;REGION&gt;']}],docs:'https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/'},
  aws:{title:'\u2601 AWS setup',methods:[{type:'cli',label:'AWS SSO login (recommended)',desc:'Authenticate via AWS IAM Identity Center (SSO).',cmds:['aws configure sso','aws sso login --profile &lt;PROFILE&gt;']},{type:'apikey',label:'Environment variables',desc:'Access Key based. Prefer ReadOnlyAccess only.',cmds:['export AWS_ACCESS_KEY_ID=AKIA...','export AWS_SECRET_ACCESS_KEY=...','export AWS_DEFAULT_REGION=ap-northeast-2']}],docs:'https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html',warn:'Store AWS keys in .env and add to .gitignore (NIST AC-6).'},
  gcp:{title:'\u25C8 GCP setup',methods:[{type:'oauth',label:'gcloud OAuth (recommended)',desc:'Browser OAuth authentication.',cmds:['gcloud auth login','gcloud config set project &lt;PROJECT_ID&gt;']}],docs:'https://cloud.google.com/sdk/docs/authorizing'},
  azure:{title:'\u25C7 Azure setup',methods:[{type:'oauth',label:'Azure CLI (recommended)',desc:'Browser authentication.',cmds:['az login','az account set --subscription &lt;SUB_ID&gt;']},{type:'apikey',label:'Service Principal',desc:'For CI/CD environments.',cmds:['export AZURE_CLIENT_ID=&lt;APP_ID&gt;','export AZURE_TENANT_ID=&lt;TENANT_ID&gt;','export AZURE_CLIENT_SECRET=&lt;SECRET&gt;']}],docs:'https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli',warn:'Store Client Secret in Key Vault (CIS Azure 1.24).'},
  m365:{title:'\uD83D\uDCE7 Microsoft 365 setup',methods:[{type:'oauth',label:'Azure AD app registration',desc:'Register an app in Azure AD for M365 scan.',cmds:['# Azure Portal &gt; App registrations &gt; New','# API Permissions: Graph SecurityEvents.Read.All']},{type:'apikey',label:'Environment variables',desc:'Credentials for the registered app.',cmds:['export AZURE_CLIENT_ID=&lt;APP_ID&gt;','export AZURE_TENANT_ID=&lt;TENANT_ID&gt;','export AZURE_CLIENT_SECRET=&lt;SECRET&gt;']}],docs:'https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/microsoft365/',warn:'Use least-privilege API permissions only (OWASP A07).'},
  okta:{title:'🔐 Okta setup',methods:[{type:'oauth',label:'OAuth service app (recommended)',desc:'Create OAuth 2.0 service app and issue scoped access token.',cmds:['# Okta Admin > Applications > Create app integration','export OKTA_OAUTH_TOKEN=<token>']},{type:'apikey',label:'Okta API token',desc:'Fallback for API checks when OAuth app is not ready.',cmds:['export OKTA_API_TOKEN=<token>']}],docs:'https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/',warn:'Prefer scoped OAuth tokens over broad API tokens (OWASP A07).'},
  gws:{title:'\uD83C\uDFE2 Google Workspace setup',methods:[{type:'oauth',label:'Domain-wide delegation',desc:'Set up domain-wide delegation for the service account.',cmds:['# GCP Console &gt; Service Accounts &gt; Create','# Admin Console &gt; Security &gt; API Controls']},{type:'apikey',label:'Environment variables',desc:'Service account key and Customer ID.',cmds:['export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json','export GOOGLE_WORKSPACE_CUSTOMER_ID=C01234567']}],docs:'https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/googleworkspace/'},
  cloudflare:{title:'\uD83C\uDF10 Cloudflare setup',methods:[{type:'apikey',label:'API Token (recommended)',desc:'Use least-privilege API Token.',cmds:['# dash.cloudflare.com &gt; My Profile &gt; API Tokens','export CF_API_TOKEN=&lt;TOKEN&gt;']},{type:'apikey',label:'Global API Key (not recommended)',desc:'Legacy.',cmds:['export CF_API_KEY=&lt;KEY&gt;','export CF_API_EMAIL=&lt;EMAIL&gt;']}],docs:'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/',warn:'Global API Key has full permissions; use API Token instead (OWASP A01).'},
  nhn:{title:'\u2601 NHN Cloud setup',methods:[{type:'apikey',label:'OpenStack auth',desc:'Keystone authentication.',cmds:['export OS_AUTH_URL=https://api-identity-infrastructure.nhncloudservice.com/v2.0','export OS_TENANT_ID=&lt;PROJECT_ID&gt;','export OS_USERNAME=&lt;EMAIL&gt;']}],docs:'https://docs.nhncloud.com/ko/Compute/Instance/ko/api-guide/'},
  llm:{title:'\uD83E\uDD16 LLM setup',methods:[{type:'cli',label:'promptfoo install',desc:'For LLM security scanning.',cmds:['npm install -g promptfoo','promptfoo init']},{type:'apikey',label:'OpenAI',desc:'For OpenAI model testing.',cmds:['export OPENAI_API_KEY=sk-...']},{type:'apikey',label:'Anthropic',desc:'For Claude model testing.',cmds:['export ANTHROPIC_API_KEY=sk-ant-...']}],docs:'https://www.promptfoo.dev/docs/red-team/',warn:'Set rate limit and spending limit for LLM API keys.'},
  datadog:{title:'\uD83D\uDCCA Datadog setup (recommended)',methods:[{type:'apikey',label:'API Key (recommended)',desc:'Use scoped API keys with least privilege.',cmds:['export DD_API_KEY=<your-api-key>','# Optional: use DD_APP_KEY instead']},{type:'apikey',label:'Application Key',desc:'For management operations and dashboard keys.',cmds:['export DD_APP_KEY=<your-app-key>']}],docs:'https://docs.datadoghq.com/account_management/api-app-keys/',warn:'Recommended: set API/App Key via env only; add .env to .gitignore. Least privilege (NIST AC-6).'}
};
function openSetup(provider){
  var c=SETUP_CONFIGS[provider];if(!c)return;
  document.getElementById('setupModalTitle').innerHTML=c.title;
  var body=document.getElementById('setupModalBody'),html='';
  c.methods.forEach(function(m){
    var bc=m.type==='oauth'?'oauth':m.type==='cli'?'cli':'apikey';
    var bl=m.type==='oauth'?'OAuth':m.type==='cli'?'CLI':'API Key';
    html+='<div class="setup-method"><div class="setup-method-label"><span class="method-badge '+bc+'">'+bl+'</span> '+m.label+'</div><p>'+m.desc+'</p>';
    if(m.cmds&&m.cmds.length>0){html+='<div class="setup-cmd"><code>'+m.cmds.join('\n')+'</code><button class="setup-cmd-copy" onclick="copyCmd(this)">Copy</button></div>'}
    html+='</div>';
  });
  if(c.warn)html+='<div class="setup-warning"><span>\uD83D\uDD12</span><span>'+c.warn+'</span></div>';
  if(c.docs)html+='<div style="margin-top:1rem;text-align:center"><a href="'+c.docs+'" target="_blank" rel="noopener" style="color:var(--accent);font-size:.85rem;text-decoration:underline">View documentation</a></div>';
  body.innerHTML=html;
  document.getElementById('setupModal').classList.add('open');document.body.style.overflow='hidden';
}
function closeSetup(){document.getElementById('setupModal').classList.remove('open');document.body.style.overflow=''}
function copyCmd(btn){var code=btn.previousElementSibling;navigator.clipboard.writeText(code.textContent).then(function(){btn.textContent='Copied';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied')},2000)})}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeSetup()});
</script>
</body>
</html>"""

# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    scan_json = os.environ.get("CLAUDESEC_SCAN_JSON", "")
    prowler_dir = os.environ.get("CLAUDESEC_PROWLER_DIR", ".claudesec-prowler")
    history_dir = os.environ.get("CLAUDESEC_HISTORY_DIR", ".claudesec-history")
    output_file = sys.argv[1] if len(sys.argv) > 1 else "claudesec-dashboard.html"

    if scan_json and os.path.isfile(scan_json):
        scan_data = load_scan_results(scan_json)
    else:
        scan_data = {
            "passed": int(os.environ.get("CLAUDESEC_PASSED", 0)),
            "failed": int(os.environ.get("CLAUDESEC_FAILED", 0)),
            "warnings": int(os.environ.get("CLAUDESEC_WARNINGS", 0)),
            "skipped": int(os.environ.get("CLAUDESEC_SKIPPED", 0)),
            "total": int(os.environ.get("CLAUDESEC_TOTAL", 0)),
            "score": int(os.environ.get("CLAUDESEC_SCORE", 0)),
            "grade": os.environ.get("CLAUDESEC_GRADE", "F"),
            "duration": int(os.environ.get("CLAUDESEC_DURATION", 0)),
            "findings": json.loads(os.environ.get("CLAUDESEC_FINDINGS_JSON", "[]")),
        }

    generate_dashboard(scan_data, prowler_dir, history_dir, output_file)
    print(f"Dashboard v{VERSION} generated: {output_file}")
