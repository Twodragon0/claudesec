#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — 멀티소스 자산 수집기
#
# Datadog API, AWS, Prowler 결과를 수집하여
# .claudesec-assets/ 에 통합 JSON 생성
#
# 사용법:
#   ./scripts/collect-assets.sh                    # 전체 수집
#   ./scripts/collect-assets.sh --datadog-only     # Datadog만
#   ./scripts/collect-assets.sh --aws-only         # AWS만
#   ./scripts/collect-assets.sh --prowler-only     # Prowler만
#
# 환경변수:
#   DD_API_KEY       — Datadog API Key
#   DD_APP_KEY       — Datadog Application Key
#   DD_SITE          — Datadog 사이트 (기본: datadoghq.com)
#   AWS_PROFILE      — AWS 프로파일 (기본: dive-prod)
# ============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS_DIR="$ROOT_DIR/.claudesec-assets"
mkdir -p "$ASSETS_DIR"

DD_SITE="${DD_SITE:-datadoghq.com}"
DD_API_KEY="${DD_API_KEY:-}"
DD_APP_KEY="${DD_APP_KEY:-}"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

COLLECT_DD=1
COLLECT_AWS=1
COLLECT_PROWLER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datadog-only) COLLECT_AWS=0; COLLECT_PROWLER=0; shift ;;
    --aws-only) COLLECT_DD=0; COLLECT_PROWLER=0; shift ;;
    --prowler-only) COLLECT_DD=0; COLLECT_AWS=0; shift ;;
    -h|--help)
      echo "Usage: $0 [--datadog-only|--aws-only|--prowler-only]"
      exit 0 ;;
    *) shift ;;
  esac
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ClaudeSec 자산 수집기"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Datadog 자산 수집 ──────────────────────────────────────────────────────

collect_datadog() {
  if [[ -z "$DD_API_KEY" || -z "$DD_APP_KEY" ]]; then
    echo "  ⚠ Datadog API Key 미설정 (DD_API_KEY, DD_APP_KEY 필요)"
    return 0
  fi

  echo ""
  echo "▶ Datadog 자산 수집 중..."

  # 1. 호스트 목록 (인프라 자산)
  echo "  - 호스트 목록 수집..."
  curl -s -X GET "https://api.${DD_SITE}/api/v1/hosts" \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    -H "Content-Type: application/json" \
    | jq '{
      collected_at: "'"$NOW"'",
      source: "datadog-hosts",
      total_hosts: .total_matching,
      hosts: [.host_list[]? | {
        name: .name,
        id: .id,
        platform: .meta.platform,
        os: (.meta.gohai // {} | fromjson? // {} | .platform // {}).os // "unknown",
        agent_version: .meta.agent_version,
        is_muted: .is_muted,
        apps: .apps,
        sources: .sources,
        tags_by_source: .tags_by_source,
        up: .up,
        last_reported: .last_reported_time
      }]
    }' > "$ASSETS_DIR/datadog-hosts.json" 2>/dev/null || echo '{"error":"API call failed"}' > "$ASSETS_DIR/datadog-hosts.json"

  host_count=$(jq -r '.total_hosts // 0' "$ASSETS_DIR/datadog-hosts.json" 2>/dev/null || echo "0")
  echo "    호스트: ${host_count}개"

  # 2. Security Signals (SIEM 이벤트)
  echo "  - 보안 시그널 수집..."
  curl -s -X POST "https://api.${DD_SITE}/api/v2/security_monitoring/signals/search" \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
      "filter": {
        "from": "now-7d",
        "to": "now",
        "query": "status:(high OR critical)"
      },
      "sort": "timestamp",
      "page": {"limit": 100}
    }' \
    | jq '{
      collected_at: "'"$NOW"'",
      source: "datadog-security-signals",
      signals: [.data[]? | {
        id: .id,
        type: .type,
        title: .attributes.message,
        severity: .attributes.severity,
        status: .attributes.status,
        timestamp: .attributes.timestamp,
        tags: .attributes.tags
      }]
    }' > "$ASSETS_DIR/datadog-security-signals.json" 2>/dev/null || echo '{"signals":[]}' > "$ASSETS_DIR/datadog-security-signals.json"

  signal_count=$(jq -r '.signals | length' "$ASSETS_DIR/datadog-security-signals.json" 2>/dev/null || echo "0")
  echo "    보안 시그널 (최근 7일, high+critical): ${signal_count}건"

  # 3. Usage/Cost 데이터
  echo "  - 사용량/비용 데이터 수집..."
  # 최근 1개월 사용량
  month_start=$(date -u -v-1m +"%Y-%m-01" 2>/dev/null || date -u -d "1 month ago" +"%Y-%m-01" 2>/dev/null || echo "2026-02-01")
  curl -s -X GET "https://api.${DD_SITE}/api/v1/usage/summary?start_month=${month_start}" \
    -H "DD-API-KEY: ${DD_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
    -H "Content-Type: application/json" \
    | jq '{
      collected_at: "'"$NOW"'",
      source: "datadog-usage",
      usage: .usage[]?
    }' > "$ASSETS_DIR/datadog-usage.json" 2>/dev/null || echo '{"usage":{}}' > "$ASSETS_DIR/datadog-usage.json"

  echo "    사용량 데이터 수집 완료"
}

# ── AWS 자산 수집 ──────────────────────────────────────────────────────────

collect_aws() {
  if ! command -v aws &>/dev/null; then
    echo "  ⚠ AWS CLI 미설치"
    return 0
  fi

  echo ""
  echo "▶ AWS 자산 수집 중..."

  # 4개 프로파일 순회
  IFS=',' read -ra profiles <<< "${AWS_PROFILES:-}"
  [[ ${#profiles[@]} -eq 0 ]] && { echo "  AWS_PROFILES 미설정"; return 0; }

  local all_ec2=()
  local all_rds=()
  local all_eks=()

  for profile in "${profiles[@]}"; do
    echo "  - 프로파일: $profile"

    # EC2 인스턴스
    aws ec2 describe-instances --profile "$profile" --region ap-northeast-2 \
      --query 'Reservations[].Instances[].{
        InstanceId: InstanceId,
        Type: InstanceType,
        State: State.Name,
        Platform: PlatformDetails,
        LaunchTime: LaunchTime,
        Tags: Tags
      }' --output json 2>/dev/null | jq --arg p "$profile" \
      '[.[]? | . + {profile: $p}]' >> "$ASSETS_DIR/aws-ec2-${profile}.json" 2>/dev/null || true

    # RDS 인스턴스
    aws rds describe-db-instances --profile "$profile" --region ap-northeast-2 \
      --query 'DBInstances[].{
        DBInstanceIdentifier: DBInstanceIdentifier,
        Engine: Engine,
        EngineVersion: EngineVersion,
        DBInstanceClass: DBInstanceClass,
        Status: DBInstanceStatus,
        MultiAZ: MultiAZ,
        StorageEncrypted: StorageEncrypted,
        AutoMinorVersionUpgrade: AutoMinorVersionUpgrade
      }' --output json 2>/dev/null | jq --arg p "$profile" \
      '[.[]? | . + {profile: $p}]' >> "$ASSETS_DIR/aws-rds-${profile}.json" 2>/dev/null || true

    # EKS 클러스터
    aws eks list-clusters --profile "$profile" --region ap-northeast-2 \
      --query 'clusters' --output json 2>/dev/null | jq --arg p "$profile" \
      '{profile: $p, clusters: .}' >> "$ASSETS_DIR/aws-eks-${profile}.json" 2>/dev/null || true

    # S3 버킷
    aws s3api list-buckets --profile "$profile" \
      --query 'Buckets[].{Name: Name, Created: CreationDate}' \
      --output json 2>/dev/null | jq --arg p "$profile" \
      '[.[]? | . + {profile: $p}]' >> "$ASSETS_DIR/aws-s3-${profile}.json" 2>/dev/null || true

    echo "    $profile 수집 완료"
  done

  # 통합 파일 생성
  echo "  - 통합 자산 파일 생성 중..."
  jq -s 'flatten' "$ASSETS_DIR"/aws-ec2-*.json > "$ASSETS_DIR/aws-ec2-all.json" 2>/dev/null || echo '[]' > "$ASSETS_DIR/aws-ec2-all.json"
  jq -s 'flatten' "$ASSETS_DIR"/aws-rds-*.json > "$ASSETS_DIR/aws-rds-all.json" 2>/dev/null || echo '[]' > "$ASSETS_DIR/aws-rds-all.json"

  ec2_count=$(jq 'length' "$ASSETS_DIR/aws-ec2-all.json" 2>/dev/null || echo "0")
  rds_count=$(jq 'length' "$ASSETS_DIR/aws-rds-all.json" 2>/dev/null || echo "0")
  echo "    EC2: ${ec2_count}개, RDS: ${rds_count}개"
}

# ── Prowler 결과 수집 ──────────────────────────────────────────────────────

collect_prowler() {
  echo ""
  echo "▶ Prowler 결과 수집 중..."

  local prowler_dir="$ROOT_DIR/.claudesec-prowler"
  if [[ ! -d "$prowler_dir" ]]; then
    echo "  ⚠ Prowler 결과 없음 ($prowler_dir)"
    return 0
  fi

  # Prowler 결과 요약 생성
  python3 -c "
import json, glob, os
from collections import Counter

prowler_dir = '$prowler_dir'
all_findings = []

for f in glob.glob(os.path.join(prowler_dir, '*.ocsf.json')):
    try:
        with open(f) as fh:
            data = json.load(fh)
            if isinstance(data, list):
                all_findings.extend(data)
            else:
                all_findings.append(data)
    except (json.JSONDecodeError, IOError):
        pass

# 통계
severity_counter = Counter(f.get('severity', 'unknown') for f in all_findings)
status_counter = Counter(f.get('status_code', 'unknown') for f in all_findings)
provider_counter = Counter(
    f.get('unmapped', {}).get('provider', 'unknown')
    for f in all_findings if isinstance(f.get('unmapped'), dict)
)

# FAIL만 필터
failures = [f for f in all_findings if f.get('status_code') == 'FAIL']
fail_severity = Counter(f.get('severity', 'unknown') for f in failures)

summary = {
    'collected_at': '$NOW',
    'source': 'prowler-summary',
    'total_findings': len(all_findings),
    'by_severity': dict(severity_counter),
    'by_status': dict(status_counter),
    'by_provider': dict(provider_counter),
    'failures': {
        'total': len(failures),
        'by_severity': dict(fail_severity),
    },
    'files_processed': len(glob.glob(os.path.join(prowler_dir, '*.ocsf.json'))),
}

with open('$ASSETS_DIR/prowler-summary.json', 'w') as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print(f'    총 {len(all_findings)}건 (FAIL: {len(failures)}건)')
print(f'    심각도: {dict(fail_severity)}')
" 2>/dev/null || echo "  ⚠ Prowler 요약 생성 실패"
}

# ── 실행 ──────────────────────────────────────────────────────────────────

[[ "$COLLECT_DD" == "1" ]] && collect_datadog
[[ "$COLLECT_AWS" == "1" ]] && collect_aws
[[ "$COLLECT_PROWLER" == "1" ]] && collect_prowler

# 최종 통합 리포트 생성
echo ""
echo "▶ 통합 자산 리포트 생성 중..."

python3 -c "
import json, glob, os
from datetime import datetime

assets_dir = '$ASSETS_DIR'
report = {
    'generated_at': '$NOW',
    'version': '1.0',
    'sources': {},
}

# 모든 JSON 파일 읽기
for f in sorted(glob.glob(os.path.join(assets_dir, '*.json'))):
    name = os.path.basename(f).replace('.json', '')
    if name == 'asset-inventory':
        continue
    try:
        with open(f) as fh:
            data = json.load(fh)
            if isinstance(data, list):
                report['sources'][name] = {'count': len(data), 'type': 'list'}
            elif isinstance(data, dict):
                report['sources'][name] = {'type': 'object', 'keys': list(data.keys())[:10]}
    except (json.JSONDecodeError, IOError):
        pass

# 인벤토리 요약
report['inventory_summary'] = {
    'total_sources': len(report['sources']),
    'source_names': list(report['sources'].keys()),
}

with open(os.path.join(assets_dir, 'asset-inventory.json'), 'w') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)

print(f'  수집 소스: {len(report[\"sources\"])}개')
for name, info in report['sources'].items():
    print(f'    - {name}: {info}')
" 2>/dev/null || echo "  ⚠ 통합 리포트 생성 실패"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  자산 수집 완료"
echo "  결과: $ASSETS_DIR/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
