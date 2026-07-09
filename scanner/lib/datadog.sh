#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Datadog collection helpers (split out of the claudesec entrypoint)
# ============================================================================
# Datadog API base-URL resolution, the retrying/rate-limit-aware API request
# helper, and the dashboard artifact collector. Sourced by the `claudesec`
# entrypoint AFTER output.sh (info) and checks.sh (run_with_timeout), which
# these functions call at runtime. No behavior change vs when these lived
# inline in the entrypoint.

datadog_api_base_url() {
  local site="$1"
  case "$site" in
    datadoghq.com) echo "https://api.datadoghq.com" ;;
    datadoghq.eu) echo "https://api.datadoghq.eu" ;;
    us3.datadoghq.com) echo "https://api.us3.datadoghq.com" ;;
    us5.datadoghq.com) echo "https://api.us5.datadoghq.com" ;;
    ddog-gov.com) echo "https://api.ddog-gov.com" ;;
    *) echo "https://api.${site}" ;;
  esac
}

datadog_logs_intake_base_url() {
  local site="$1"
  case "$site" in
    datadoghq.com|datadoghq.eu|us3.datadoghq.com|us5.datadoghq.com|ddog-gov.com)
      echo "https://http-intake.logs.${site}"
      ;;
    *)
      echo "https://http-intake.logs.${site}"
      ;;
  esac
}

datadog_api_request_with_retry() {
  local method="$1"
  local url="$2"
  local output_file="$3"
  local data_file="${4:-}"
  local content_type="${5:-}"

  local tmp_body tmp_headers http_code attempt reset_sec remaining reset_for_soft wait_sec
  local last_http_code="000"
  local debug_enabled="${CLAUDESEC_DEBUG:-0}"
  local debug_verbose="${CLAUDESEC_DEBUG_VERBOSE:-0}"
  local soft_throttle_threshold="${CLAUDESEC_DD_SOFT_THROTTLE_THRESHOLD:-2}"
  local request_id="ddreq-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
  local dd_site_hint="${DD_SITE:-datadoghq.com}"
  local dd_api_base_hint
  dd_api_base_hint="$(datadog_api_base_url "$dd_site_hint")"
  local api_key_set=0
  local app_key_set=0
  local auth_hint_printed=0
  local soft_throttle_enabled=1

  [[ -n "${DD_API_KEY:-${DATADOG_API_KEY:-}}" ]] && api_key_set=1
  [[ -n "${DD_APP_KEY:-}" ]] && app_key_set=1

  if [[ ! "$soft_throttle_threshold" =~ ^[0-9]+$ ]]; then
    soft_throttle_threshold=2
  fi
  if [[ "$soft_throttle_threshold" -eq 0 ]]; then
    soft_throttle_enabled=0
  fi
  tmp_body=$(mktemp 2>/dev/null || echo "")
  tmp_headers=$(mktemp 2>/dev/null || echo "")
  local tmp_curlcfg
  tmp_curlcfg=$(mktemp 2>/dev/null || echo "")
  [[ -n "$tmp_body" && -n "$tmp_headers" && -n "$tmp_curlcfg" ]] || return 1
  chmod 600 "$tmp_curlcfg"

  # Write sensitive headers to curl config file to avoid process list exposure
  printf 'header = "DD-API-KEY: %s"\n' "${DD_API_KEY:-${DATADOG_API_KEY:-}}" > "$tmp_curlcfg"
  printf 'header = "DD-APPLICATION-KEY: %s"\n' "${DD_APP_KEY:-}" >> "$tmp_curlcfg"

  for attempt in 1 2 3; do
    if [[ -n "$data_file" && -n "$content_type" ]]; then
      http_code=$(run_with_timeout 20 curl -sS -X "$method" "$url" \
        --config "$tmp_curlcfg" \
        -H "X-Request-ID: ${request_id}" \
        -H "Accept: application/json" \
        -H "Content-Type: ${content_type}" \
        -d @"$data_file" \
        -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" || echo "000")
    else
      http_code=$(run_with_timeout 20 curl -sS -X "$method" "$url" \
        --config "$tmp_curlcfg" \
        -H "X-Request-ID: ${request_id}" \
        -H "Accept: application/json" \
        -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" || echo "000")
    fi
    last_http_code="$http_code"
    if [[ "$debug_enabled" == "1" && "$debug_verbose" == "1" ]]; then
      echo "[claudesec][debug] datadog request_id=${request_id} attempt=${attempt}/3 code=${http_code} url=${url}" >&2
    fi
    remaining=$(grep -i '^x-ratelimit-remaining:' "$tmp_headers" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '\r')
    reset_for_soft=$(grep -i '^x-ratelimit-reset:' "$tmp_headers" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '\r')

    if [[ "$http_code" == "200" || "$http_code" == "201" ]]; then
      if [[ "$soft_throttle_enabled" -eq 1 && "$remaining" =~ ^[0-9]+$ && "$remaining" -le "$soft_throttle_threshold" ]]; then
        wait_sec=1
        if [[ "$reset_for_soft" =~ ^[0-9]+$ && "$reset_for_soft" -gt 0 && "$reset_for_soft" -le 10 ]]; then
          wait_sec="$reset_for_soft"
        fi
        [[ "$debug_enabled" == "1" ]] && echo "[claudesec][debug] datadog soft-throttle remaining=${remaining} threshold=${soft_throttle_threshold} wait=${wait_sec}s url=${url}" >&2
        sleep "$wait_sec"
      fi
      if [[ "$debug_enabled" == "1" && "$debug_verbose" == "1" ]]; then
        echo "[claudesec][debug] datadog request_id=${request_id} success code=${http_code} url=${url}" >&2
      fi
      mv "$tmp_body" "$output_file" 2>/dev/null || cp "$tmp_body" "$output_file"
      rm -f "$tmp_headers" "$tmp_body" "$tmp_curlcfg"
      return 0
    fi

    if [[ ( "$http_code" == "401" || "$http_code" == "403" ) && "$auth_hint_printed" -eq 0 ]]; then
      auth_hint_printed=1
      echo "[claudesec][hint] datadog auth code=${http_code} site=${dd_site_hint} base_url=${dd_api_base_hint} api_key_set=${api_key_set} app_key_set=${app_key_set} (check DD_SITE, key validity, and DD_APP_KEY scopes; recommended DD_SITE: datadoghq.com|datadoghq.eu|us3.datadoghq.com|ddog-gov.com)" >&2
    fi

    if [[ "$http_code" == "429" && "$attempt" -lt 3 ]]; then
      reset_sec=$(grep -i '^x-ratelimit-reset:' "$tmp_headers" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '\r')
      if [[ "$reset_sec" =~ ^[0-9]+$ ]]; then
        sleep "$reset_sec"
      else
        sleep $((attempt * 2))
      fi
      continue
    fi

    if [[ "$attempt" -lt 3 ]]; then
      sleep $((attempt * 2))
      continue
    fi
  done

  [[ "$debug_enabled" == "1" ]] && echo "[claudesec][debug] datadog request_id=${request_id} failed code=${last_http_code} url=${url}" >&2
  rm -f "$tmp_headers" "$tmp_body" "$tmp_curlcfg"
  return 1
}

collect_datadog_dashboard_artifacts() {
  local datadog_enabled="${CLAUDESEC_DATADOG_FETCH_CLOUD_SECURITY:-1}"
  [[ "$datadog_enabled" == "0" ]] && return 0

  local dd_api_key="${DD_API_KEY:-${DATADOG_API_KEY:-}}"
  local dd_app_key="${DD_APP_KEY:-}"
  [[ -n "$dd_api_key" && -n "$dd_app_key" ]] || return 0

  local dd_site="${DD_SITE:-datadoghq.com}"
  local dd_api_base
  dd_api_base="$(datadog_api_base_url "$dd_site")"
  local dd_intake_base
  dd_intake_base="$(datadog_logs_intake_base_url "$dd_site")"
  local dd_dir="${CLAUDESEC_DATADOG_DIR:-${SCAN_DIR}/.claudesec-datadog}"

  mkdir -p "$dd_dir"

  local to_ts from_1h_ts from_24h_ts
  to_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  from_1h_ts=$(date -u -v-1H +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '1 hour ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
  from_24h_ts=$(date -u -v-1d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")
  [[ -n "$from_1h_ts" && -n "$from_24h_ts" ]] || return 0

  local run_id
  run_id="local-$(date +%s)"
  local dd_service="${DD_SERVICE:-claudesec}"
  local dd_env="${DD_ENV:-local}"
  local dd_tags="service:${dd_service},env:${dd_env},ci_pipeline_id:${run_id}"
  local dd_query="service:${dd_service} env:${dd_env} ci_pipeline_id:${run_id}"

  cat > "$dd_dir/intake.json" <<JSON
{
  "message": "ClaudeSec local dashboard run",
  "service": "${dd_service}",
  "env": "${dd_env}",
  "ci_pipeline_id": "${run_id}",
  "status": "info",
  "source": "claudesec-local"
}
JSON
  run_with_timeout 15 curl -sS -X POST "${dd_intake_base}/v1/input?ddtags=${dd_tags}" \
    -H "Content-Type: application/json" \
    -H "DD-API-KEY: ${dd_api_key}" \
    -d @"$dd_dir/intake.json" >/dev/null || true

  cat > "$dd_dir/query.json" <<JSON
{
  "filter": {
    "from": "${from_1h_ts}",
    "to": "${to_ts}",
    "query": "${dd_query}"
  },
  "sort": "timestamp",
  "page": { "limit": 200 }
}
JSON
  if ! datadog_api_request_with_retry "POST" "${dd_api_base}/api/v2/logs/events/search" "$dd_dir/datadog-logs.json" "$dd_dir/query.json" "application/json"; then
    printf '{"data":[]}' > "$dd_dir/datadog-logs.json"
  fi

  cat > "$dd_dir/signals-query.json" <<JSON
{
  "filter": {
    "from": "${from_24h_ts}",
    "to": "${to_ts}",
    "query": "security:cloud_security_management (severity:critical OR severity:high)"
  },
  "page": { "limit": 100 },
  "sort": "timestamp"
}
JSON
  if ! datadog_api_request_with_retry "POST" "${dd_api_base}/api/v2/security_monitoring/signals/search" "$dd_dir/datadog-cloud-signals.json" "$dd_dir/signals-query.json" "application/json"; then
    printf '{"data":[]}' > "$dd_dir/datadog-cloud-signals.json"
  fi

  if ! datadog_api_request_with_retry "GET" "${dd_api_base}/api/v2/cases?page[size]=100" "$dd_dir/datadog-cases.json"; then
    printf '{"data":[]}' > "$dd_dir/datadog-cases.json"
  fi

  python3 - "$dd_dir" <<'PY'
import json
import re
import sys
from pathlib import Path

base = Path(sys.argv[1])
paths = {
    base / "datadog-logs.json": base / "datadog-logs-sanitized.json",
    base / "datadog-cloud-signals.json": base / "datadog-cloud-signals-sanitized.json",
    base / "datadog-cases.json": base / "datadog-cases-sanitized.json",
}

def redact_text(text: str) -> str:
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted-email>", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted-ip>", text)
    text = re.sub(r"\b\d{12}\b", "<redacted-account-id>", text)
    return text

def sanitize(obj):
    if isinstance(obj, dict):
        blocked = {
            "email", "user_email", "ip", "ip_address", "host", "hostname",
            "aws_account_id", "account_id", "principal_arn", "access_key_id",
            "secret", "token", "authorization", "api_key",
        }
        out = {}
        for k, v in obj.items():
            if str(k).lower() in blocked:
                out[k] = "<redacted>"
            else:
                out[k] = sanitize(v)
        return out
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj

for src, dst in paths.items():
    try:
        with src.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {"data": []}
    with dst.open("w", encoding="utf-8") as f:
        json.dump(sanitize(data), f, ensure_ascii=False)
PY

  rm -f "$dd_dir/intake.json" "$dd_dir/query.json" "$dd_dir/signals-query.json" \
    "$dd_dir/datadog-logs.json" "$dd_dir/datadog-cloud-signals.json" "$dd_dir/datadog-cases.json"

  if [[ "$FORMAT" == "text" && -z "${QUIET:-}" ]]; then
    info "Datadog artifacts refreshed: ${dd_dir}/datadog-*-sanitized.json"
  fi
}
