"""
ClaudeSec Dashboard Data Loader
Data loading functions extracted from dashboard-gen.py for reuse across scanner modules.
"""

import json
import os
import glob
import warnings
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path
from typing import Any

from dashboard_utils import (
    _is_env_truthy,
    CLAUDESEC_DASHBOARD_OFFLINE_ENV,
    AUDIT_POINTS_REPO,
    AUDIT_POINTS_CACHE_TTL_HOURS,
    MS_BEST_PRACTICES_CACHE_TTL_HOURS,
    MS_SOURCE_FILTER_ENV,
    MS_INCLUDE_SCUBAGEAR_ENV,
    AuditPointsData,
    TrivySummary,
    TrivyVuln,
    NmapHost,
    NmapScan,
    SSLScanResult,
    NetworkToolResult,
    DatadogLogEntry,
    DatadogSummary,
    DatadogSeveritySummary,
    DatadogLogsData,
    MicrosoftBestPracticesData,
    _normalized_source_filter,
)
from dashboard_api_client import (
    _fetch_audit_points_from_github,
    _fetch_microsoft_best_practices_from_github,
    _fetch_saas_best_practices_from_github,
    SAAS_BEST_PRACTICES_CACHE_TTL_HOURS,
)


# ── Data Loading ─────────────────────────────────────────────────────────────


def load_scan_results(path: str) -> dict[str, Any]:
    default: dict[str, Any] = {
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "skipped": 0,
        "total": 0,
        "score": 0,
        "grade": "F",
        "duration": 0,
        "findings": [],
    }
    if not path or not os.path.isfile(path):
        return default
    # Degrade gracefully on a truncated/corrupt scan-report.json (e.g. from a
    # killed scan) instead of crashing dashboard/diagram generation — matches
    # load_scan_history / load_audit_points_detected below.
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


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


def _normalize_provider(name: str) -> str:
    """Normalize provider names so k8s/kubernetes/eks variants merge into 'kubernetes'."""
    if name.startswith("k8s") or name.startswith("kubernetes") or "eks" in name:
        return "kubernetes"
    return name


def _load_single_prowler_file(fpath: str) -> tuple[str, list[dict[str, Any]]]:
    """Load and parse a single Prowler OCSF file. Used by ThreadPoolExecutor."""
    raw_name = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
    name = _normalize_provider(raw_name)
    try:
        with open(fpath, encoding="utf-8") as f:
            content = f.read().strip()
        return name, _parse_ocsf_json(content)
    except Exception:
        return name, []


def load_prowler_files(prowler_dir: str) -> dict[str, list[dict[str, Any]]]:
    providers: dict[str, list[dict[str, Any]]] = {}
    if not os.path.isdir(prowler_dir):
        return providers
    files = sorted(glob.glob(os.path.join(prowler_dir, "*.ocsf.json")))
    if not files:
        return providers
    # Parallel file I/O for multiple provider files
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(len(files), 4)) as pool:
        results = pool.map(_load_single_prowler_file, files)
    for name, items in results:
        if name in providers:
            providers[name].extend(items)
        else:
            providers[name] = items
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
        if _is_env_truthy(CLAUDESEC_DASHBOARD_OFFLINE_ENV):
            return {"products": [], "fetched_at": ""}
        fresh = _fetch_audit_points_from_github()
        if fresh:
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(fresh, f, ensure_ascii=False, indent=2)
            return fresh
    except (OSError, json.JSONDecodeError):
        pass
    return {"products": [], "fetched_at": ""}


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
        if _is_env_truthy(CLAUDESEC_DASHBOARD_OFFLINE_ENV) or expected_filter == "none":
            return {
                "fetched_at": "",
                "source_filter": expected_filter,
                "scubagear_enabled": expected_scubagear,
                "sources": [],
            }
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


def load_saas_best_practices(scan_dir):
    """Load SaaS best practices with 24h cache (same pattern as MS best practices)."""
    cache_dir = os.path.join(scan_dir, ".claudesec-saas-best-practices")
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
                    if (now - dt).total_seconds() < SAAS_BEST_PRACTICES_CACHE_TTL_HOURS * 3600:
                        return data
                except (ValueError, TypeError):
                    pass
        if _is_env_truthy(CLAUDESEC_DASHBOARD_OFFLINE_ENV):
            return {"fetched_at": "", "sources": []}
        fresh = _fetch_saas_best_practices_from_github()
        os.makedirs(cache_dir, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(fresh, f, ensure_ascii=False, indent=2)
        return fresh
    except (OSError, json.JSONDecodeError):
        return {"fetched_at": "", "sources": []}


def load_network_tool_results(network_dir: str) -> NetworkToolResult:
    """Load Trivy, nmap, sslscan results from .claudesec-network/ for dashboard."""
    out: NetworkToolResult = {
        "trivy_fs": None,
        "trivy_config": None,
        "trivy_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "trivy_vulns": [],
        "nmap_scans": [],
        "sslscan_results": [],
        "network_report": None,
    }
    if not network_dir or not os.path.isdir(network_dir):
        return out

    report_path = os.path.join(network_dir, "network-report.v1.json")
    if os.path.isfile(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                out["network_report"] = obj
        except (OSError, json.JSONDecodeError):
            pass  # invalid network-report.v1.json

    trivy_fs_path = os.path.join(network_dir, "trivy-fs.json")
    if os.path.isfile(trivy_fs_path):
        try:
            with open(trivy_fs_path, encoding="utf-8") as f:
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
    try:
        import defusedxml.ElementTree as SafeET

        _parse_xml = SafeET.parse
    except ImportError:
        warnings.warn(
            "defusedxml is not installed; falling back to stdlib xml.etree.ElementTree. "
            "Install defusedxml for safer XML parsing: pip install defusedxml",
            ImportWarning,
            stacklevel=2,
        )
        import xml.etree.ElementTree as ET

        def _parse_xml(fpath):
            """Fallback XML parser with DTD/entity resolution disabled."""
            parser = ET.XMLParser()
            parser.entity = {}  # type: ignore[attr-defined]
            return ET.parse(fpath, parser=parser)  # nosemgrep: use-defused-xml-parse

    for fpath in glob.glob(os.path.join(network_dir, "nmap-*.xml")):
        try:
            tree = _parse_xml(fpath)
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


def _dd_normalize_log_severity(raw: Any) -> str:
    """Map a raw log status/level to the log-summary bucket (error/warning/info)."""
    val = (raw or "").strip().lower()
    if val in ("critical", "crit", "error", "err", "fatal"):
        return "error"
    if val in ("warn", "warning"):
        return "warning"
    if val in ("info", "notice", "ok", "pass"):
        return "info"
    return "unknown"


def _dd_normalize_log(item: dict[str, Any]) -> DatadogLogEntry:
    """Normalize one raw Datadog log record into a DatadogLogEntry."""
    attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
    nested = attrs.get("attributes", {}) if isinstance(attrs, dict) else {}
    status = (
        attrs.get("status")
        or nested.get("status")
        or attrs.get("level")
        or nested.get("level")
    )
    severity = _dd_normalize_log_severity(status)
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


def _dd_normalize_signal_severity(raw: Any) -> str:
    """Map a raw signal/case severity/priority to the standard severity bucket."""
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


def _dd_inc_severity(counter: DatadogSeveritySummary, sev: str) -> None:
    """Increment the matching severity bucket in a DatadogSeveritySummary counter."""
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


def _dd_extract_items(data: Any) -> list[dict[str, Any]]:
    """Pull the list of dict records from a Datadog `{data: [...]}` or bare-list payload."""
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return [x for x in data["data"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []


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
                        normalized = _dd_normalize_log(obj)
                        logs.append(normalized)
            else:
                with open(fpath, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("data"), list):
                    for item in data["data"]:
                        if isinstance(item, dict):
                            logs.append(_dd_normalize_log(item))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            logs.append(_dd_normalize_log(item))
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
        for item in _dd_extract_items(data):
            attrs = (
                item.get("attributes", {})
                if isinstance(item.get("attributes"), dict)
                else {}
            )
            sev = _dd_normalize_signal_severity(attrs.get("severity"))
            _dd_inc_severity(signal_summary, sev)
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
        for item in _dd_extract_items(data):
            attrs = (
                item.get("attributes", {})
                if isinstance(item.get("attributes"), dict)
                else {}
            )
            sev = _dd_normalize_signal_severity(
                attrs.get("severity")
                or attrs.get("priority")
                or attrs.get("case_priority")
            )
            _dd_inc_severity(case_summary, sev)
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


# ── Prowler analysis / provider filters / env status (extracted to dashboard_data_analysis.py) ──
from dashboard_data_analysis import (  # noqa: F401  (re-exported for back-compat)
    analyze_prowler,
    _normalize_severity,
    github_findings,
    aws_findings,
    gcp_findings,
    gws_findings,
    k8s_findings,
    azure_findings,
    m365_findings,
    iac_findings,
    get_env_status,
)


__all__ = [
    "load_scan_results",
    "_parse_ocsf_json",
    "_normalize_provider",
    "load_prowler_files",
    "load_scan_history",
    "load_audit_points_detected",
    "load_audit_points",
    "load_microsoft_best_practices",
    "load_saas_best_practices",
    "load_network_tool_results",
    "load_datadog_logs",
    "analyze_prowler",
    "github_findings",
    "aws_findings",
    "gcp_findings",
    "gws_findings",
    "k8s_findings",
    "azure_findings",
    "m365_findings",
    "iac_findings",
    "get_env_status",
]
