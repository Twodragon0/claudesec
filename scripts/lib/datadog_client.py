"""Datadog HTTP helpers shared by the dashboard-sync operator scripts.

Extracted from `scripts/build-dashboard.py` and `scripts/sync-cost-xlsx.py`,
which each carried their own copy. `dd_get` and `dd_post` were BYTE-IDENTICAL;
`collect_datadog` differed by exactly one line, the label on the hosts progress
print, which is now a parameter so both scripts keep their existing output.

Credentials are explicit parameters rather than module globals: each script
derives them from its own `env_vars` mapping, and a module-level global here
would make the import order load-bearing.
"""

import json
import urllib.request

DD_API_BASE = "https://api.datadoghq.com"


def dd_get(
    path: str, params: str = "", *, api_key: str, app_key: str
) -> dict[str, object]:
    url = f"{DD_API_BASE}{path}"
    if params:
        url += f"?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(
            req, timeout=30
        ) as r:  # nosemgrep: dynamic-urllib-use-detected — trusted internal API URLs
            payload = json.loads(r.read().decode("utf-8", errors="replace"))
            return payload if isinstance(payload, dict) else {}
    except Exception as e:
        print(f"  DD API 오류 ({path}): {e}")
        return {}


def dd_post(
    path: str, body: object, *, api_key: str, app_key: str
) -> dict[str, object]:
    url = f"{DD_API_BASE}{path}"
    req = urllib.request.Request(
        url,
        json.dumps(body).encode(),
        method="POST",
        headers={
            "DD-API-KEY": api_key,
            "DD-APPLICATION-KEY": app_key,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(
            req, timeout=30
        ) as r:  # nosemgrep: dynamic-urllib-use-detected — trusted internal API URLs
            payload = json.loads(r.read().decode("utf-8", errors="replace"))
            return payload if isinstance(payload, dict) else {}
    except Exception as e:
        print(f"  DD API 오류 ({path}): {e}")
        return {}


def collect_datadog(
    *, api_key: str, app_key: str, hosts_label: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Datadog 호스트 + 보안 시그널 수집.

    `hosts_label` is the ONLY thing the two copies disagreed on
    (`"  Datadog 호스트..."` vs `"\\n[Datadog] 호스트..."`), so it is passed in
    rather than picked for them.
    """
    if not api_key:
        print("  Datadog API Key 없음, 스킵")
        return [], []

    print(hosts_label)
    raw = dd_get("/api/v1/hosts", "count=200", api_key=api_key, app_key=app_key)
    hosts = []
    host_list = raw.get("host_list", [])
    if not isinstance(host_list, list):
        host_list = []
    for h in host_list:
        if not isinstance(h, dict):
            continue
        tags = {}
        tags_by_source = h.get("tags_by_source", {})
        if not isinstance(tags_by_source, dict):
            tags_by_source = {}
        for _src, tlist in tags_by_source.items():
            if not isinstance(tlist, list):
                continue
            for t in tlist:
                if ":" in t:
                    k, v = t.split(":", 1)
                    tags[k] = v
        hosts.append(
            {
                "name": h.get("name", ""),
                "instance_type": tags.get("instance-type", ""),
                "region": tags.get("region", ""),
                "cluster": tags.get(
                    "aws_eks_cluster-name", tags.get("eks_eks-cluster-name", "")
                ),
                "nodepool": tags.get("karpenter.sh/nodepool", ""),
                "env": tags.get("env", ""),
                "aws_alias": tags.get("aws_alias", ""),
                "aws_account": tags.get("aws_account", ""),
                "up": h.get("up", False),
                "agent_version": h.get("meta", {}).get("agent_version", ""),
            }
        )
    print(f"    {len(hosts)}개")

    print("  Datadog 보안 시그널 (14일)...")
    raw = dd_post(
        "/api/v2/security_monitoring/signals/search",
        {
            "filter": {
                "from": "now-14d",
                "to": "now",
                "query": "status:(high OR critical OR medium)",
            },
            "sort": "timestamp",
            "page": {"limit": 100},
        },
        api_key=api_key,
        app_key=app_key,
    )
    signals = []
    signal_data = raw.get("data", [])
    if not isinstance(signal_data, list):
        signal_data = []
    for s in signal_data:
        if not isinstance(s, dict):
            continue
        a = s.get("attributes", {})
        if not isinstance(a, dict):
            a = {}
        signals.append(
            {
                "id": s.get("id", "")[:30],
                "title": a.get("message", "")[:200],
                "severity": a.get("severity", ""),
                "status": a.get("status", ""),
                "timestamp": a.get("timestamp", ""),
                "tags": a.get("tags", [])[:5],
            }
        )
    print(f"    {len(signals)}건")
    return hosts, signals
