"""
ClaudeSec Dashboard Utilities
Shared constants, TypedDicts, and utility functions extracted from dashboard-gen.py.
"""

import os
import re
import urllib.parse
from typing import Any, TypedDict

# ── Constants ─────────────────────────────────────────────────────────────────

# QueryPie Audit Points repo (SaaS/DevSecOps audit checklists)
AUDIT_POINTS_REPO = "querypie/audit-points"
AUDIT_POINTS_CACHE_TTL_HOURS = 24
CLAUDESEC_DASHBOARD_OFFLINE_ENV = "CLAUDESEC_DASHBOARD_OFFLINE"

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

VERSION = "0.7.0"

# ── TypedDict Classes ─────────────────────────────────────────────────────────


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
    network_report: dict[str, Any] | None


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


# ── Utility Functions ─────────────────────────────────────────────────────────


def h(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


_ALLOWED_FETCH_HOSTS = {"raw.githubusercontent.com", "github.com", "api.github.com"}


def _is_env_truthy(var_name: str) -> bool:
    return os.environ.get(var_name, "").strip().lower() in ("1", "true", "yes", "on")


def _is_best_practice_file(name: str) -> bool:
    lower = (name or "").lower()
    if not lower:
        return False
    exts = (".md", ".markdown", ".txt", ".yml", ".yaml", ".json", ".ps1")
    if lower.endswith(exts):
        return True
    return lower in ("readme", "readme.md", "security.md")


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


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4}

# ── Exports ───────────────────────────────────────────────────────────────────

__all__ = [
    # Constants
    "AUDIT_POINTS_REPO",
    "AUDIT_POINTS_CACHE_TTL_HOURS",
    "CLAUDESEC_DASHBOARD_OFFLINE_ENV",
    "MS_BEST_PRACTICES_CACHE_TTL_HOURS",
    "MS_INCLUDE_SCUBAGEAR_ENV",
    "MS_SOURCE_FILTER_ENV",
    "TRUST_LEVEL_ORDER",
    "TRUST_LEVEL_FILTER_MAP",
    "TRUST_FILTER_TOKEN_ORDER",
    "VERSION",
    # TypedDict classes
    "AuditPointFile",
    "AuditPointProduct",
    "AuditPointsData",
    "TrivySummary",
    "TrivyVuln",
    "NmapHost",
    "NmapScan",
    "SSLScanResult",
    "NetworkToolResult",
    "DatadogLogEntry",
    "DatadogSummary",
    "DatadogSeveritySummary",
    "DatadogLogsData",
    "GitHubContentItem",
    "RepoFocusFile",
    "RepoFocusData",
    "MicrosoftBestPracticeSource",
    "MicrosoftBestPracticesData",
    # Utility functions
    "h",
    "_ALLOWED_FETCH_HOSTS",
    "_is_env_truthy",
    "_is_best_practice_file",
    "_resolve_source_filter",
    "_normalized_source_filter",
    "_trust_token_from_level",
    "comp_slug",
    "sev_badge",
    "SEV_ORDER",
]
