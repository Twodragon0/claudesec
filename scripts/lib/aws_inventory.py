"""AWS inventory loading and asset-register cross-verification.

Extracted from `scripts/build-dashboard.py` and `scripts/sync-cost-xlsx.py`.
`cross_verify_ec2` was BYTE-IDENTICAL across both (98 lines each);
`is_karpenter_node` differed only by a redundant function-local `import re`;
`load_aws_live_data` differed only in where it read `AWS_PROFILES` from
(`os.environ` vs the script's own `env_vars`), which is now a parameter so
both keep their existing source.
"""

import json
import re
from pathlib import Path
from typing import Any, Mapping

_KARPENTER_NODE_RE = re.compile(r"ip-10-\d+-\d+-\d+\.")

# Resource kinds probed per profile. `rds-clusters` collapses into `rds` so the
# two RDS shapes land in one bucket.
_AWS_RESOURCE_KINDS = ("ec2", "rds", "rds-clusters", "elasticache", "s3", "eks")


def is_karpenter_node(name: str) -> bool:
    """Karpenter 동적 노드 여부 판별 (ip-10-* 패턴)."""
    if not name:
        return False
    return bool(_KARPENTER_NODE_RE.match(name))


def cross_verify_ec2(
    aws_ec2: list[dict[str, object]], sheet_servers: list[dict[str, object]]
) -> dict[str, Any]:
    """AWS EC2 실시간 vs 자산관리대장 서버 교차 검증 (Karpenter 노드 분리)."""
    # Karpenter 노드와 고정 서버 분리
    aws_static: dict[str, dict[str, object]] = {}
    aws_karpenter: list[dict[str, object]] = []
    for e in aws_ec2:
        iid = e.get("InstanceId", "")
        name = e.get("Name", "")
        if not isinstance(iid, str) or not iid:
            continue
        if not isinstance(name, str):
            name = ""
        if is_karpenter_node(name):
            aws_karpenter.append(
                {
                    "id": iid,
                    "name": name,
                    "type": e.get("Type", ""),
                    "profile": e.get("_profile", ""),
                }
            )
        else:
            aws_static[iid] = e

    # 시트에서도 Karpenter/고정 분리
    sheet_static: dict[str, dict[str, object]] = {}
    sheet_karpenter: list[dict[str, object]] = []
    for s in sheet_servers:
        iid = s.get("instance_id", "")
        name = s.get("name", "")
        if not isinstance(iid, str) or not iid:
            continue
        if not isinstance(name, str):
            name = ""
        if is_karpenter_node(name):
            sheet_karpenter.append(
                {
                    "id": iid,
                    "name": name,
                    "type": s.get("instance_type", ""),
                    "account": s.get("account", ""),
                }
            )
        else:
            sheet_static[iid] = s

    # 고정 서버 교차 검증
    aws_only: list[dict[str, object]] = []
    for iid, e in aws_static.items():
        if iid not in sheet_static:
            aws_only.append(
                {
                    "id": iid,
                    "name": e.get("Name", ""),
                    "type": e.get("Type", ""),
                    "profile": e.get("_profile", ""),
                    "status": "미등록",
                }
            )

    sheet_only: list[dict[str, object]] = []
    for iid, s in sheet_static.items():
        if iid not in aws_static:
            sheet_only.append(
                {
                    "id": iid,
                    "name": s.get("name", ""),
                    "type": s.get("instance_type", ""),
                    "account": s.get("account", ""),
                    "status": "종료/교체",
                }
            )

    matched = len(set(aws_static) & set(sheet_static))

    result = {
        "aws_total": len(aws_ec2),
        "aws_static": len(aws_static),
        "aws_karpenter": len(aws_karpenter),
        "sheet_total": len(sheet_servers),
        "sheet_static": len(sheet_static),
        "sheet_karpenter": len(sheet_karpenter),
        "matched": matched,
        "aws_only": aws_only,
        "sheet_only": sheet_only,
        "aws_only_count": len(aws_only),
        "sheet_only_count": len(sheet_only),
        "karpenter_nodes": aws_karpenter,
        "karpenter_count": len(aws_karpenter),
    }
    print(
        f"  교차검증: 고정 서버 AWS {len(aws_static)} vs 시트 {len(sheet_static)}, "
        f"일치 {matched}, 미등록 {len(aws_only)}, 종료 {len(sheet_only)}"
    )
    print(f"  Karpenter: AWS {len(aws_karpenter)}개 동적 노드 (교차검증 제외)")
    return result


def load_aws_live_data(
    assets_dir: Path, env: Mapping[str, str]
) -> dict[str, list[dict[str, object]]]:
    """Load AWS describe results from `<assets_dir>/aws-*.json`.

    `env` is the profile source. The two copies read `AWS_PROFILES` from
    different places — `os.environ` in build-dashboard, the script's own
    `env_vars` in sync-cost-xlsx — so the caller supplies the mapping.
    """
    result: dict[str, list[dict[str, object]]] = {
        "ec2": [],
        "rds": [],
        "elasticache": [],
        "s3": [],
        "eks": [],
    }
    aws_profiles = [
        p.strip() for p in env.get("AWS_PROFILES", "").split(",") if p.strip()
    ]
    if not aws_profiles:
        # No explicit profile list — infer it from the files already on disk.
        for f in sorted(assets_dir.glob("aws-ec2-*.json")):
            p = f.stem.replace("aws-ec2-", "")
            if p not in aws_profiles:
                aws_profiles.append(p)
    for profile in aws_profiles:
        for rtype in _AWS_RESOURCE_KINDS:
            fpath = assets_dir / f"aws-{rtype}-{profile}.json"
            if not fpath.exists():
                continue
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        item["_profile"] = profile
                    key = rtype.replace("-clusters", "")
                    if key not in result:
                        result[key] = []
                    result[key].extend(data)
                elif isinstance(data, dict) and "clusters" in data:
                    for c in data["clusters"]:
                        result["eks"].append({"name": c, "_profile": profile})
            except Exception:
                pass
    for k, v in result.items():
        if v:
            print(f"    AWS {k}: {len(v)}개")
    return result
