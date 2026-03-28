"""
ClaudeSec Dashboard API Client
Provides GitHub API fetching utilities and best-practice source definitions
extracted from dashboard-gen.py for reuse across scanner modules.
"""

import json
import os
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from dashboard_utils import (
    _is_env_truthy,
    _is_best_practice_file,
    _resolve_source_filter,
    _normalized_source_filter,
    _trust_token_from_level,
    h,
    _ALLOWED_FETCH_HOSTS,
    AUDIT_POINTS_REPO,
    AUDIT_POINTS_CACHE_TTL_HOURS,
    CLAUDESEC_DASHBOARD_OFFLINE_ENV,
    MS_BEST_PRACTICES_CACHE_TTL_HOURS,
    TRUST_LEVEL_ORDER,
    TRUST_LEVEL_FILTER_MAP,
    TRUST_FILTER_TOKEN_ORDER,
    MS_INCLUDE_SCUBAGEAR_ENV,
    MS_SOURCE_FILTER_ENV,
    GitHubContentItem,
    RepoFocusFile,
    RepoFocusData,
    MicrosoftBestPracticeSource,
    MicrosoftBestPracticesData,
    AuditPointFile,
    AuditPointProduct,
    AuditPointsData,
)

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

SAAS_BEST_PRACTICES_SOURCES = [
    {
        "product": "Okta",
        "repo": "okta/okta-developer-docs",
        "label": "Okta Developer Docs (Security best practices)",
        "trust_level": "Vendor Official",
        "reason": "Official Okta documentation covering MFA, SSO, lifecycle management, and API token security.",
        "focus_paths": ["packages/@okta/vuepress-site/docs/guides", "README.md"],
    },
    {
        "product": "Okta",
        "repo": "OktaSecurityLabs/sgt",
        "label": "Okta Security Guard Toolkit",
        "trust_level": "Vendor Official",
        "reason": "Okta Security Labs toolkit for identity threat detection and event monitoring.",
        "focus_paths": ["README.md", "docs"],
    },
    {
        "product": "Okta",
        "repo": "cisagov/ScubaGoggles",
        "label": "CISA ScubaGoggles (GWS + Identity)",
        "trust_level": "Government",
        "reason": "CISA baseline assessment for Google Workspace and identity provider security, applicable to Okta SSO.",
        "focus_paths": ["baselines", "README.md"],
    },
    {
        "product": "QueryPie",
        "repo": "querypie/audit-points",
        "label": "QueryPie Audit Points (SaaS security checklists)",
        "trust_level": "Vendor Official",
        "reason": "Official QueryPie repository for SaaS and DevSecOps audit checklists, covering database access, privilege management, and audit logging.",
        "focus_paths": ["README.md"],
    },
    {
        "product": "QueryPie",
        "repo": "querypie/querypie-docs",
        "label": "QueryPie Documentation",
        "trust_level": "Vendor Official",
        "reason": "Official QueryPie documentation covering DAC (Database Access Control), SAC (System Access Control), and audit policies.",
        "focus_paths": ["docs", "README.md"],
    },
    {
        "product": "ArgoCD",
        "repo": "argoproj/argo-cd",
        "label": "Argo CD Official Repository",
        "trust_level": "CNCF Official",
        "reason": "Official Argo CD repository with RBAC configuration, SSO integration, and security best practices documentation.",
        "focus_paths": ["docs/operator-manual/rbac.md", "docs/operator-manual/security.md", "docs/operator-manual/user-management", "README.md"],
    },
    {
        "product": "ArgoCD",
        "repo": "argoproj/argo-cd",
        "label": "Argo CD RBAC & Policy Configuration",
        "trust_level": "CNCF Official",
        "reason": "RBAC policies, project roles, and JWT token management for Argo CD multi-tenant environments.",
        "focus_paths": ["docs/operator-manual/rbac.md", "docs/operator-manual/project.md"],
    },
    {
        "product": "IDE",
        "repo": "nicedoc/vscode-security",
        "label": "VS Code Security Best Practices",
        "trust_level": "Community",
        "reason": "Community-maintained guidance on Visual Studio Code security settings, extension review, and workspace trust.",
        "focus_paths": ["README.md"],
    },
]

SAAS_BEST_PRACTICES_CACHE_TTL_HOURS = 24


def _github_api_json(url: str, _max_retries: int = 3) -> Any:
    """Fetch JSON from GitHub API with exponential backoff on rate-limit responses."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    last_exc: Exception | None = None
    for attempt in range(_max_retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: dynamic-urllib-use-detected
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code in (403, 429):
                retry_after = exc.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    wait = min(int(retry_after), 60)
                else:
                    wait = min(2 ** attempt, 30)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
            if attempt < _max_retries - 1:
                time.sleep(min(2 ** attempt, 30))
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("_github_api_json: unreachable")


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
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: dynamic-urllib-use-detected — trusted GitHub API URL
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
                with urllib.request.urlopen(sub_req, timeout=15) as sub_resp:  # nosemgrep: dynamic-urllib-use-detected
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


def _fetch_saas_best_practices_from_github():
    """Fetch SaaS best practice files from GitHub repos (Okta, QueryPie, ArgoCD, IDE)."""
    sources = []
    for src in SAAS_BEST_PRACTICES_SOURCES:
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
        if repo_data.get("archived"):
            continue
        sources.append(
            {
                "product": str(src.get("product", "")),
                "label": str(src.get("label", "")),
                "trust_level": str(src.get("trust_level", "Community")),
                "reason": str(src.get("reason", "")),
                "repo": repo_data["repo"],
                "repo_url": repo_data["repo_url"],
                "default_branch": repo_data["default_branch"],
                "updated_at": repo_data["updated_at"],
                "archived": repo_data["archived"],
                "files": repo_data["files"],
                "focus_paths": focus_paths,
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
        "sources": sources,
    }


def _fetch_markdown_preview(raw_url: str, max_chars: int = 1200, max_lines: int = 20) -> str:
    """
    Fetch a small markdown preview for an Audit Points checklist file.
    Returns sanitized HTML with light formatting for headings and bullet items.
    Network failures are silently ignored; caller should handle empty string.
    """
    if not raw_url or _is_env_truthy(CLAUDESEC_DASHBOARD_OFFLINE_ENV):
        return ""
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_FETCH_HOSTS:
        return ""
    try:
        req = urllib.request.Request(
            raw_url,
            headers={"Accept": "application/vnd.github.v3.raw"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: dynamic-urllib-use-detected
            text = resp.read().decode("utf-8", "ignore")
    except Exception:
        return ""
    lines: list[str] = []
    total = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        lines.append(line.rstrip())
        total += len(line)
        if len(lines) >= max_lines or total >= max_chars:
            break
    if not lines:
        return ""
    parts: list[str] = []
    for ln in lines:
        stripped = ln.lstrip()
        if stripped.startswith(("# ", "## ", "### ")):
            parts.append(
                f'<div class="bp-audit-heading">{h(stripped.lstrip("# ").strip())}</div>'
            )
        elif stripped.startswith(("- [ ]", "- [x]", "- [X]")):
            split = stripped.split("]", 1)
            label = split[1].strip() if len(split) > 1 else ""
            parts.append(f'<div class="bp-audit-item">• {h(label)}</div>')
        elif stripped.startswith("- "):
            parts.append(
                f'<div class="bp-audit-item">• {h(stripped[2:].strip())}</div>'
            )
        else:
            parts.append(f'<div class="bp-audit-text">{h(stripped)}</div>')
    return '<div class="bp-audit-preview">' + "".join(parts) + "</div>"


__all__ = [
    "MS_BEST_PRACTICES_REPO_SOURCES",
    "SAAS_BEST_PRACTICES_SOURCES",
    "SAAS_BEST_PRACTICES_CACHE_TTL_HOURS",
    "_github_api_json",
    "_fetch_audit_points_from_github",
    "_fetch_repo_focus_files",
    "_fetch_microsoft_best_practices_from_github",
    "_fetch_saas_best_practices_from_github",
    "_fetch_markdown_preview",
]
