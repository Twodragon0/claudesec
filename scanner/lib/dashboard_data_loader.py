"""
ClaudeSec Dashboard Data Loader
Data loading functions extracted from dashboard-gen.py for reuse across scanner modules.
"""

import json
import os
import glob
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dashboard_utils import (
    _is_env_truthy,
    CLAUDESEC_DASHBOARD_OFFLINE_ENV,
    AUDIT_POINTS_CACHE_TTL_HOURS,
    MS_BEST_PRACTICES_CACHE_TTL_HOURS,
    MS_INCLUDE_SCUBAGEAR_ENV,
    AuditPointsData,
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
    except (OSError, ValueError):
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


def _load_single_prowler_file(fpath: str) -> tuple[str, list[dict[str, Any]] | None]:
    """Load and parse a single Prowler OCSF file. Used by ThreadPoolExecutor.

    Returns `(provider, findings)`, or `(provider, None)` when the file could NOT
    be read as evidence at all.

    `None` and `[]` MUST stay distinguishable, because `load_prowler_files`' keys
    are the repository's "this provider was scanned" claim: `dashboard-gen.py`
    passes them straight to `map_compliance(..., scanned_providers=...)`, where
    the #455 gate uses them to decide whether a control had evidence it could
    have read. A provider that is present with an empty list therefore asserts
    "assessed, nothing found" — the strongest thing the dashboard can say — so
    returning `[]` for a file that never decoded turned an unread file into a
    clean bill of health. Measured before this change, with one 0x80 byte spliced
    into a 3-finding aws OCSF file:

        clean utf-8    providers=['aws'] findings=3 -> AC-2 FAIL  source='prowler'
        one 0x80 byte  providers=['aws'] findings=0 -> AC-2 PASS  source='prowler'
        no file at all providers=[]      findings=0 -> AC-2 PASS  source='keyword'

    Note the third row: a MISSING file already degraded provenance to `keyword`,
    so the corrupt file was the worse of the two — it kept `match_source
    ="prowler"` while resting on nothing. `prowler_compliance_summary.py` has had
    this right all along by adding the provider only after the parse succeeds.

    `errors="replace"` is the other half and does the real work: a single
    non-UTF-8 byte anywhere in a cloud resource tag, owner or description used to
    cost the whole file. Verified recovery is exact, not approximate — 50 of 50
    findings with 0x80 spliced at three different offsets (start, middle, end),
    delta +0 each time. The replacement character can only corrupt the one string
    literal it lands in, and `_parse_ocsf_json`'s `raw_decode` resync already
    tolerates that.

    A file that is READ but holds no record is a third case, resolved below: an
    empty document counts as a real, clean scan, while garbage does not.
    """
    raw_name = Path(fpath).stem.replace(".ocsf", "").replace("prowler-", "")
    name = _normalize_provider(raw_name)
    try:
        with open(fpath, encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
    except Exception:
        return name, None
    findings = _parse_ocsf_json(content)
    if not findings and content:
        # Content that yields no record is either a legitimately empty document
        # or garbage, and only the second may drop the provider — otherwise a
        # truncated or non-JSON file re-opens the same false-PASS through a
        # different door. Decided by asking whether the text is valid JSON at
        # all, NOT by comparing it against a list of empty spellings: the first
        # draft of this used `content not in ("", "[]", "{}")`, where `"{}"` was
        # dead (it parses to `[{}]`, which is truthy) and `"[ ]"` — legal, empty
        # JSON — was misread as garbage. Enumerating the empty forms is the wrong
        # rule; the grammar is the rule (ADR-001 §5).
        try:
            json.loads(content)
        except ValueError:
            return name, None
    return name, findings


def load_prowler_files(prowler_dir: str) -> dict[str, list[dict[str, Any]]]:
    """`{provider: findings}` for every provider whose OCSF file was READ.

    A provider whose file could not be read is omitted rather than mapped empty
    — see `_load_single_prowler_file`. Callers may therefore treat the key set as
    "these providers were actually assessed", which is exactly what
    `dashboard-gen.py` does when it builds `scanned_providers` from it.

    Findings from a provider's readable files are still kept when a SIBLING file
    for the same provider fails, since a real FAIL is evidence regardless of what
    else was unreadable; the provider stays claimed in that case because at least
    one of its files was read. Dropping it instead would hide genuine findings,
    which is the opposite failure and the worse one.
    """
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
        if items is None:
            warnings.warn(
                f"prowler OCSF evidence for provider '{name}' could not be read; "
                "it is excluded from the scanned-provider set so compliance "
                "controls are not scored as assessed against it",
                stacklevel=2,
            )
            continue
        if name in providers:
            providers[name].extend(items)
        else:
            providers[name] = items
    return providers


def load_scan_history(history_dir: str) -> list[dict[str, Any]]:
    """Every readable `scan-*.json` in `history_dir`; unreadable ones are skipped.

    `ValueError`, not `json.JSONDecodeError`. `UnicodeDecodeError` is a SIBLING
    `ValueError` subclass, not a `JSONDecodeError`, so the narrower form let one
    non-UTF-8 byte in a history file abort the whole dashboard build instead of
    dropping that entry — the same defect `_load_saas_sso_stats` carried:

        >>> issubclass(UnicodeDecodeError, ValueError)
        True
        >>> issubclass(UnicodeDecodeError, json.JSONDecodeError)
        False
    """
    entries: list[dict[str, Any]] = []
    if not os.path.isdir(history_dir):
        return entries
    for fpath in sorted(glob.glob(os.path.join(history_dir, "scan-*.json"))):
        try:
            with open(fpath, encoding="utf-8") as f:
                entries.append(json.load(f))
        except (OSError, ValueError):
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
    except (OSError, ValueError):
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
    except (OSError, ValueError):
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
    except (OSError, ValueError):
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
    except (OSError, ValueError):
        return {"fetched_at": "", "sources": []}


def _warn_unreadable_network_artifact(fpath: str, exc: BaseException) -> None:
    """Announce a dropped nmap/sslscan artifact instead of dropping it silently.

    The counterpart to omitting it. An unread file that simply vanishes trades a
    false claim for an invisible gap, which is the #445/#446/#448 failure — so
    the omission has to be audible, exactly as `load_prowler_files` does it.
    """
    warnings.warn(
        f"network artifact {os.path.basename(fpath)} could not be read "
        f"({type(exc).__name__}: {exc}); it is excluded from the dashboard so it "
        "is not counted as network evidence",
        stacklevel=3,
    )


def load_network_tool_results(network_dir: str) -> NetworkToolResult:
    """Load Trivy, nmap, sslscan results from .claudesec-network/ for dashboard.

    An nmap or sslscan file that could NOT be read is OMITTED, not appended with
    an empty payload. The old form appended `{"hosts": []}` / `{"data": {}}`,
    which three consumers read as real evidence:

      * `dashboard_html_builders` drew an "Nmap scan summary" card with the
        filename and an empty host list — indistinguishable from a scan that ran
        and found no open ports — and an "SSL/TLS scan" card labelled
        "(JSON data available)", which is the opposite of true for a file whose
        JSON did not parse;
      * `dashboard_html_overview`'s `nmap_count` / `ssl_count` summary counted it;
      * worst, `network_evidence` in `build_priority_queue_html` went truthy on
        the strength of it, which SUPPRESSED the "network or Datadog telemetry
        missing" entry in `visibility_gaps`. A corrupt artifact actively hid the
        warning that there was no network evidence.

    Measured before this change, with one truncated `nmap-*.xml` and one
    truncated `sslscan-*.json`:

        nmap_scans      [{'name': 'nmap-prod.xml', 'hosts': []}]
        sslscan_results [{'name': 'sslscan-prod.json', 'data': {}}]
        warnings raised 0
        nmap_count=1 ssl_count=1 -> network_evidence=True
        visibility_gaps []          <- the warning the user should have seen

    Same false-clean shape as #484/#485 on the Prowler path, reached through
    `except Exception` rather than through a narrow handler. A scan that READ but
    found nothing keeps its entry: host-less nmap output is a real result.
    """
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
        except (OSError, ValueError):
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
        except (OSError, ValueError):
            pass  # skip missing or invalid trivy-fs.json
    trivy_cfg_path = os.path.join(network_dir, "trivy-config.json")
    if os.path.isfile(trivy_cfg_path):
        try:
            with open(trivy_cfg_path, encoding="utf-8") as f:
                out["trivy_config"] = json.load(f)
        except (OSError, ValueError):
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
            """Fallback XML parser that REFUSES a document carrying a DTD.

            The previous form set `parser.entity = {}`, which is a readonly
            attribute on ElementTree's C accelerator and raises
            `AttributeError: readonly attribute` (verified on CPython 3.13.12).
            So this fallback ALWAYS raised, and every nmap artifact silently
            became an empty scan whenever `defusedxml` was absent — invisible
            until the caller stopped laundering failures into empty results.

            Refusing DOCTYPE is what `defusedxml`'s `forbid_dtd` does and what
            the OWASP XXE Prevention Cheat Sheet asks for: both entity-expansion
            ("billion laughs") and external-entity attacks require a DTD, so
            rejecting one removes the class rather than pretending to neuter it.
            """
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if re.search(r"<!DOCTYPE", text, re.IGNORECASE):
                raise ValueError(
                    f"refusing to parse {os.path.basename(fpath)}: it declares a "
                    "DTD and defusedxml is not installed"
                )
            return ET.ElementTree(ET.fromstring(text))  # nosemgrep: use-defused-xml-parse

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
        except Exception as exc:
            _warn_unreadable_network_artifact(fpath, exc)
    for fpath in glob.glob(os.path.join(network_dir, "sslscan-*.json")):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            _warn_unreadable_network_artifact(fpath, exc)
            continue
        out["sslscan_results"].append(
            {"name": os.path.basename(fpath), "data": data}
        )
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
        except (OSError, ValueError):
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
        except (OSError, ValueError):
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
        except (OSError, ValueError):
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
