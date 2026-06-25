"""
dashboard_data_analysis.py — Prowler analysis, provider finding filters,
and environment-connection status.

Extracted from dashboard_data_loader.py to keep that module under the
800-line cap (coding-style rule). Re-exported by dashboard_data_loader
for backward compatibility; importers may use either path.
"""

import os
from collections import defaultdict

# ── Prowler Analysis ─────────────────────────────────────────────────────────


_SEV_NORMALIZE = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "informational": "Informational",
}


def _normalize_severity(raw: str) -> str:
    """Normalize severity case variants (CRITICAL/critical/Critical → Critical)."""
    return _SEV_NORMALIZE.get(raw.lower(), raw.title()) if raw else "Unknown"


def analyze_prowler(providers):
    summary = {}
    all_findings = []
    for prov, items in providers.items():
        fails = [i for i in items if i.get("status_code") == "FAIL"]
        passes = [i for i in items if i.get("status_code") == "PASS"]
        by_sev = defaultdict(int)
        for f in fails:
            f["severity"] = _normalize_severity(f.get("severity", ""))
            by_sev[f["severity"]] += 1
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
            res0_data = res0.get("data", {})
            res0_meta = res0_data.get("metadata", {})
            comp = f.get("unmapped", {}).get("compliance", {})
            unmapped = f.get("unmapped", {})
            cloud = f.get("cloud", {})
            remediation_obj = f.get("remediation", {})
            # Resource name: prefer data.metadata.name, fallback to res0.name, then region
            resource_name = (
                res0_meta.get("name")
                or res0.get("name")
                or res0.get("region", "")
            )
            # Prowler native remediation (fallback when CHECK_EN_MAP has no entry)
            native_remediation = (remediation_obj.get("desc") or "").strip()
            native_refs = remediation_obj.get("references", [])
            # Region and account for grouping
            region = res0.get("region") or cloud.get("region", "")
            account_uid = cloud.get("account", {}).get("uid", "")
            account_name = cloud.get("account", {}).get("name", "")
            # Resource type for display
            resource_type = res0.get("type", "")
            # K8s-specific: namespace
            namespace = res0_meta.get("namespace", "")
            # IaC-specific: code location
            start_line = res0_meta.get("StartLine", "")
            # Categories from unmapped
            categories = unmapped.get("categories", [])
            all_findings.append(
                {
                    "provider": prov,
                    "severity": f.get("severity", "Unknown"),
                    "check": f.get("metadata", {}).get("event_code", ""),
                    "title": fi.get("title", ""),
                    "message": f.get("message", ""),
                    "desc": fi.get("desc", ""),
                    "resource": resource_name,
                    "resource_type": resource_type,
                    "region": region,
                    "account": account_name or account_uid,
                    "namespace": namespace,
                    "start_line": str(start_line) if start_line else "",
                    "categories": categories,
                    "native_remediation": native_remediation,
                    "native_refs": native_refs if isinstance(native_refs, list) else [],
                    "related_url": unmapped.get("related_url", ""),
                    "compliance": comp,
                }
            )
    return summary, all_findings


# ── Provider Filter Functions ─────────────────────────────────────────────────


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


def iac_findings(all_findings):
    return [f for f in all_findings if f["provider"] == "iac"]


# ── Environment Status ────────────────────────────────────────────────────────


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
