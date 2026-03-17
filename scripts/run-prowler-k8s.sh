#!/usr/bin/env bash
# ============================================================================
# Prowler K8s 스캔 — EKS 클러스터 내 Pod로 실행
#
# Okta OIDC 인증 환경에서 Prowler가 exec credential을 처리하지 못하므로,
# K8s Job + ServiceAccount로 클러스터 내에서 직접 스캔합니다.
#
# 사용법:
#   ./scripts/run-prowler-k8s.sh                # dive-prod 스캔
#   ./scripts/run-prowler-k8s.sh dive-dev       # dive-dev 스캔
# ============================================================================
set -euo pipefail

CONTEXT="${1:-dive-dev}"
NS="platform"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/.claudesec-prowler"
CRONJOB_NAME="prowler-k8s-scan"
JOB_NAME="prowler-manual-$(date +%s)"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Prowler K8s 스캔 ($CONTEXT / $NS)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# RBAC 확인
if ! kubectl get sa prowler-scanner -n "$NS" --context "$CONTEXT" &>/dev/null; then
  echo "▶ RBAC 배포..."
  kubectl apply -f "$ROOT_DIR/.claudesec-prowler/prowler-rbac.yaml" --context "$CONTEXT"
fi

# CronJob 확인
if ! kubectl get cronjob "$CRONJOB_NAME" -n "$NS" --context "$CONTEXT" &>/dev/null; then
  echo "▶ CronJob 배포..."
  kubectl apply -f "$ROOT_DIR/.claudesec-prowler/prowler-cronjob.yaml" --context "$CONTEXT"
fi

# 수동 Job 생성 (CronJob 기반)
echo "▶ 수동 스캔 실행..."
kubectl create job "$JOB_NAME" --from=cronjob/"$CRONJOB_NAME" -n "$NS" --context "$CONTEXT"

# 완료 대기
echo "▶ 스캔 대기 중... (최대 10분)"
kubectl wait --for=condition=complete "job/$JOB_NAME" -n "$NS" --context "$CONTEXT" --timeout=600s 2>&1 || {
  echo "  타임아웃 또는 실패:"
  kubectl logs "job/$JOB_NAME" -n "$NS" --context "$CONTEXT" --tail=20 2>&1
  exit 1
}

# 결과 수집 (base64 디코딩)
echo "▶ 결과 수집..."
POD_NAME=$(kubectl get pods -n "$NS" --context "$CONTEXT" \
  -l "job-name=$JOB_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -n "$POD_NAME" ]]; then
  kubectl logs "$POD_NAME" -n "$NS" --context "$CONTEXT" 2>&1 | \
    sed -n '/RESULT_BASE64_START/,/RESULT_BASE64_END/p' | \
    grep -v "RESULT_BASE64" | \
    base64 -D > "$OUTPUT_DIR/prowler-k8s-${CONTEXT}-latest.ocsf.json" && {
    echo "  저장: $OUTPUT_DIR/prowler-k8s-${CONTEXT}-latest.ocsf.json"
    python3 -c "
import json
data=json.load(open('$OUTPUT_DIR/prowler-k8s-${CONTEXT}-latest.ocsf.json'))
if isinstance(data,list):
    total=len(data)
    fail=sum(1 for d in data if d.get('status_code')=='FAIL')
    print(f'  결과: 총 {total}건, FAIL {fail}건, PASS {total-fail}건')
" 2>/dev/null || echo "  결과 파싱 실패"
  } || echo "  결과 추출 실패"
else
  echo "  Pod를 찾을 수 없습니다"
fi

# 수동 Job 정리
echo "▶ 수동 Job 정리..."
kubectl delete job "$JOB_NAME" -n "$NS" --context "$CONTEXT" --ignore-not-found 2>/dev/null || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  완료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
