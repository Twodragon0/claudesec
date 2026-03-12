#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Network & Security Scan Tools (Open Source Best Practices)
# Runs Trivy (vuln/misconfig), optional nmap/sslscan when configured.
# Results are written to .claudesec-network/ for dashboard integration.
# ============================================================================

NETWORK_OUTPUT_DIR="${SCAN_DIR:-.}/.claudesec-network"
mkdir -p "$NETWORK_OUTPUT_DIR" 2>/dev/null || true

# Normalized report (schema v1) used by diagram generator and dashboards.
NETWORK_REPORT_JSON="$NETWORK_OUTPUT_DIR/network-report.v1.json"

# ── Trivy (filesystem + config) ───────────────────────────────────────────

_trivy_run() {
  local enabled="${CLAUDESEC_TRIVY_ENABLED:-1}"
  if [[ "$enabled" == "0" ]]; then
    skip "TRIVY-001" "Trivy vulnerability scan" "Disabled in config (trivy_enabled: false)"
    return 0
  fi
  if ! has_command trivy; then
    skip "TRIVY-001" "Trivy vulnerability scan" "Trivy not installed (see https://trivy.dev)"
    return 0
  fi

  local scan_path="${SCAN_DIR:-.}"
  local out_fs="$NETWORK_OUTPUT_DIR/trivy-fs.json"
  local out_config="$NETWORK_OUTPUT_DIR/trivy-config.json"
  local timeout_sec="${PROWLER_TIMEOUT:-600}"
  [[ "$timeout_sec" -gt 120 ]] || timeout_sec=120

  # Trivy fs: vulnerabilities + misconfig (one scan)
  if run_with_timeout "$timeout_sec" trivy fs --scanners vuln,misconfig --format json --output "$out_fs" "$scan_path" 2>/dev/null; then
    pass "TRIVY-001" "Trivy filesystem scan completed (see dashboard)"
  else
    # Timeout or error — still write empty/minimal so dashboard doesn't break
    echo '{"Results":[]}' > "$out_fs" 2>/dev/null || true
    warn "TRIVY-001" "Trivy scan failed or timed out" "Check .claudesec-network/trivy-fs.json"
  fi

  # Parse Trivy JSON and push critical/high into findings for Overview
  if [[ -f "$out_fs" ]] && has_command python3; then
    local crit=0 high=0 med=0
    read -r crit high med <<< "$(python3 - "$out_fs" <<'PYTRIVY' 2>/dev/null)" || true
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    c, h, m = 0, 0, 0
    for r in d.get('Results', []):
        for v in r.get('Vulnerabilities', []) or []:
            s = (v.get('Severity') or '').upper()
            if s == 'CRITICAL': c += 1
            elif s == 'HIGH': h += 1
            elif s == 'MEDIUM': m += 1
        for v in r.get('Misconfigurations', []) or []:
            s = (v.get('Severity') or '').upper()
            if s == 'CRITICAL': c += 1
            elif s == 'HIGH': h += 1
            elif s == 'MEDIUM': m += 1
    print(c, h, m)
except Exception:
    print(0, 0, 0)
PYTRIVY
    [[ "$crit" -gt 0 ]] && fail "TRIVY-CRIT" "Trivy: $crit CRITICAL vulnerability(ies)" "critical" \
      "Review .claudesec-network/trivy-fs.json and fix or suppress" "Run 'trivy fs $scan_path' for details"
    [[ "$high" -gt 0 ]] && fail "TRIVY-HIGH" "Trivy: $high HIGH vulnerability(ies)" "high" \
      "Review .claudesec-network/trivy-fs.json" "Run 'trivy fs $scan_path' for details"
    [[ "$med" -gt 0 && "$med" -le 30 ]] && warn "TRIVY-MED" "Trivy: $med MEDIUM finding(s)" "Review .claudesec-network/trivy-fs.json"
  fi

  # Trivy config (separate; quick)
  run_with_timeout 60 trivy config --format json --output "$out_config" "$scan_path" 2>/dev/null || true
  [[ -f "$out_config" ]] || echo '{"Misconfigurations":[]}' > "$out_config" 2>/dev/null || true
}

# ── Nmap (optional, only when targets are set) ──────────────────────────────

_nmap_run() {
  local enabled="${CLAUDESEC_NETWORK_SCAN_ENABLED:-0}"
  local targets="${CLAUDESEC_NETWORK_SCAN_TARGETS:-}"
  if [[ "$enabled" != "1" || -z "$targets" ]]; then
    return 0
  fi
  if ! has_command nmap; then
    skip "NMAP-001" "Network port scan" "nmap not installed; set network_scan_targets only when nmap is available"
    return 0
  fi

  local t
  for t in ${targets//,/ }; do
    t="${t// /}"
    [[ -z "$t" ]] && continue
    local host="$t" port=""
    if [[ "$t" == *:* ]]; then
      host="${t%%:*}"
      port="${t##*:}"
    fi
    local safe_name="${t//[^a-zA-Z0-9._-]/_}"
    local out_xml="$NETWORK_OUTPUT_DIR/nmap-${safe_name}.xml"
    local nmap_args=(-sV -sC --script=ssl-enum-ciphers)
    [[ -n "$port" ]] && nmap_args=(-p "$port" "${nmap_args[@]}")
    run_with_timeout 120 nmap -oX "$out_xml" "${nmap_args[@]}" "$host" 2>/dev/null || true
    if [[ -f "$out_xml" && -s "$out_xml" ]]; then
      # Optional: convert to JSON for dashboard (nmap has -oN, -oX; we can parse XML in Python)
      true
    fi
  done
  # Don't add pass/fail for nmap; dashboard will show results from .claudesec-network
  return 0
}

# ── SSL/TLS scan (optional) ─────────────────────────────────────────────────

_sslscan_run() {
  local enabled="${CLAUDESEC_NETWORK_SCAN_ENABLED:-0}"
  local targets="${CLAUDESEC_NETWORK_SCAN_TARGETS:-}"
  if [[ "$enabled" != "1" || -z "$targets" ]]; then
    return 0
  fi
  local have_sslscan=false
  has_command sslscan && have_sslscan=true
  has_command testssl.sh && have_sslscan=true
  if [[ "$have_sslscan" != "true" ]]; then
    return 0
  fi

  local t
  for t in ${targets//,/ }; do
    t="${t// /}"
    [[ -z "$t" ]] && continue
    # TLS scan is meaningful when a TLS port is provided; default to 443 when only host supplied.
    if [[ "$t" != *:* ]]; then
      t="${t}:443"
    fi
    local safe_name="${t//[^a-zA-Z0-9._-]/_}"
    local out_file="$NETWORK_OUTPUT_DIR/sslscan-${safe_name}.json"
    if has_command sslscan; then
      run_with_timeout 60 sslscan --json="$out_file" "$t" 2>/dev/null || true
    fi
  done
  return 0
}

# ── HTTP headers scan (optional) ─────────────────────────────────────────────

_http_headers_run() {
  local enabled="${CLAUDESEC_NETWORK_SCAN_ENABLED:-0}"
  local targets="${CLAUDESEC_NETWORK_SCAN_TARGETS:-}"
  if [[ "$enabled" != "1" || -z "$targets" ]]; then
    return 0
  fi
  if ! has_command curl; then
    return 0
  fi

  local t
  for t in ${targets//,/ }; do
    t="${t// /}"
    [[ -z "$t" ]] && continue

    # Build URL (default https). If user provided scheme, keep it.
    local url="$t"
    if [[ "$url" != http://* && "$url" != https://* ]]; then
      url="https://${url}"
    fi
    local safe_name="${t//[^a-zA-Z0-9._-]/_}"
    local out_headers="$NETWORK_OUTPUT_DIR/http-headers-${safe_name}.txt"
    local out_meta="$NETWORK_OUTPUT_DIR/http-headers-${safe_name}.json"

    local hdr effective redirects
    redirects=0
    effective=""
    # Capture headers AND effective URL/redirect count.
    hdr="$(curl -sS -L -D - -o /dev/null --connect-timeout 5 -m 12 \
      -w "\n__CLAUDESEC_EFFECTIVE_URL:%{url_effective}\n__CLAUDESEC_REDIRECTS:%{num_redirects}\n" \
      "$url" 2>/dev/null)" || hdr=""
    if [[ -z "$hdr" ]]; then
      echo "" > "$out_headers" 2>/dev/null || true
      echo "{\"ok\":false,\"url\":\"${url}\",\"error\":\"no response\"}" > "$out_meta" 2>/dev/null || true
      continue
    fi
    printf "%s" "$hdr" > "$out_headers" 2>/dev/null || true

    local status
    status="$(printf "%s" "$hdr" | awk '/^HTTP\\//{s=$2} END{print s+0}' 2>/dev/null)" || status=0
    effective="$(printf "%s" "$hdr" | awk -F: '/^__CLAUDESEC_EFFECTIVE_URL:/{print $2}' | tail -1 | sed 's/^ *//;s/\\r$//' 2>/dev/null)" || effective=""
    redirects="$(printf "%s" "$hdr" | awk -F: '/^__CLAUDESEC_REDIRECTS:/{print $2}' | tail -1 | tr -d ' \\r' 2>/dev/null)" || redirects=0
    [[ -n "$redirects" ]] || redirects=0
    echo "{\"ok\":true,\"url\":\"${url}\",\"effective_url\":\"${effective}\",\"redirects\":${redirects},\"status\":${status}}" > "$out_meta" 2>/dev/null || true
  done
  return 0
}


_normalize_network_report() {
  # Build a single normalized JSON for diagram + dashboard usage.
  if ! has_command python3; then
    return 0
  fi

  python3 - "$NETWORK_OUTPUT_DIR" "$NETWORK_REPORT_JSON" <<'PYNET' 2>/dev/null || true
import json
import re
import sys
import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
import socket

out_dir = Path(sys.argv[1])
out_path = Path(sys.argv[2])

def _safe_load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def _parse_headers_txt(p: Path):
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"status": 0, "headers": {}}
    # Remove our curl write-out footer lines if present.
    raw = "\n".join([ln for ln in raw.splitlines() if not ln.startswith("__CLAUDESEC_")])
    blocks = [b.strip("\n\r") for b in re.split(r"\r?\n\r?\n", raw) if b.strip()]
    chosen = ""
    for b in reversed(blocks):
        if b.startswith("HTTP/"):
            chosen = b
            break
    if not chosen and blocks:
        chosen = blocks[-1]
    lines = [ln.strip("\r") for ln in chosen.splitlines() if ln.strip()]
    status = 0
    headers = {}
    for i, ln in enumerate(lines):
        if i == 0 and ln.startswith("HTTP/"):
            parts = ln.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
            continue
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"status": status, "headers": headers}

def _parse_redirect_chain(raw_text: str):
    # Parse all header blocks and capture {status, location} chain in order.
    raw_text = "\n".join([ln for ln in raw_text.splitlines() if not ln.startswith("__CLAUDESEC_")])
    blocks = [b.strip("\n\r") for b in re.split(r"\r?\n\r?\n", raw_text) if b.strip()]
    chain = []
    for b in blocks:
        lines = [ln.strip("\r") for ln in b.splitlines() if ln.strip()]
        if not lines or not lines[0].startswith("HTTP/"):
            continue
        parts = lines[0].split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        location = None
        for ln in lines[1:]:
            if ln.lower().startswith("location:"):
                location = ln.split(":", 1)[1].strip()
                break
        chain.append({"status": status, "location": location})
    return chain

def _dns_resolve(host: str):
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos if i and i[4] and i[4][0]})
        return ips[:10]
    except Exception:
        return []

def _parse_hsts(hdrs: dict):
    v = hdrs.get("strict-transport-security")
    if not v:
        return None
    max_age = None
    include_subdomains = False
    preload = False
    for part in [p.strip() for p in v.split(";") if p.strip()]:
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except Exception:
                max_age = None
        elif part.lower() == "includesubdomains":
            include_subdomains = True
        elif part.lower() == "preload":
            preload = True
    return {"max_age": max_age, "include_subdomains": include_subdomains, "preload": preload}

def _assess_csp(hdrs: dict):
    v = hdrs.get("content-security-policy")
    if not v:
        return {"present": False, "quality": "missing", "issues": ["missing:csp"]}
    # Very lightweight quality heuristics.
    val = v.lower()
    issues = []
    if "'unsafe-inline'" in val:
        issues.append("csp:unsafe-inline")
    if "'unsafe-eval'" in val:
        issues.append("csp:unsafe-eval")
    if "default-src" not in val:
        issues.append("csp:no-default-src")
    quality = "good"
    if any(i.startswith("csp:") for i in issues):
        quality = "needs-review"
    return {"present": True, "quality": quality, "issues": issues}

def _header_issues(hdrs: dict):
    issues = []
    required = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ]
    for k in required:
        if k not in hdrs:
            issues.append({"id": f"missing:{k}", "severity": "medium", "title": f"Missing header: {k}"})
    if "server" in hdrs:
        issues.append({"id": "infoleak:server", "severity": "low", "title": "Server header present"})
    if "x-powered-by" in hdrs:
        issues.append({"id": "infoleak:x-powered-by", "severity": "low", "title": "X-Powered-By header present"})
    return issues

def _tls_grade_from_sslscan(obj):
    if not isinstance(obj, dict):
        return {"grade": "unknown", "issues": [], "protocols": []}
    protos = []
    for k in ("protocols", "Protocols", "acceptedProtocols"):
        v = obj.get(k)
        if isinstance(v, list):
            protos = [str(x).lower() for x in v]
            break
    if not protos:
        for maybe in ("scanResult", "scan_result", "result"):
            sub = obj.get(maybe)
            if isinstance(sub, dict):
                v = sub.get("protocols") or sub.get("Protocols")
                if isinstance(v, list):
                    protos = [str(x).lower() for x in v]
                    break
    issues = []
    deprecated = any(p in ("ssl2.0","ssl3.0","ssl2","ssl3","tls1.0","tls1","tls1.1") for p in protos)
    has_13 = any("1.3" in p for p in protos)
    has_12 = any("1.2" in p for p in protos)
    if deprecated:
        issues.append({"id": "tls:deprecated-protocols", "severity": "high", "title": "Deprecated TLS/SSL protocols supported"})
        grade = "D"
    elif has_13:
        grade = "A"
    elif has_12:
        grade = "B"
    else:
        grade = "unknown"
    return {"grade": grade, "issues": issues, "protocols": protos[:]}

def _parse_nmap_ports(xml_path: Path):
    ports = []
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return ports
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for p in ports_el.findall("port"):
            portid = p.get("portid")
            proto = p.get("protocol") or ""
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else ""
            svc_el = p.find("service")
            svc = svc_el.get("name") if svc_el is not None else ""
            if portid and portid.isdigit():
                ports.append({"port": int(portid), "protocol": proto, "state": state or "", "service": svc or ""})
    # dedupe
    seen = set()
    out = []
    for it in ports:
        key = (it["port"], it["protocol"], it["state"], it["service"])
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return sorted(out, key=lambda x: (x["port"], x["protocol"]))

def _infer_target_from_filename(prefix, p: Path):
    name = p.name[len(prefix):]
    name = re.sub(r"\.(xml|json|txt)$", "", name)
    return name.replace("_", ":")

targets = {}

for p in out_dir.glob("nmap-*.xml"):
    t = _infer_target_from_filename("nmap-", p)
    targets.setdefault(t, {})["nmap"] = {"file": p.name, "ports": _parse_nmap_ports(p)}

for p in out_dir.glob("sslscan-*.json"):
    t = _infer_target_from_filename("sslscan-", p)
    obj = _safe_load_json(p)
    tls = _tls_grade_from_sslscan(obj)
    targets.setdefault(t, {})["tls"] = {"file": p.name, **tls}

for p in out_dir.glob("http-headers-*.txt"):
    t = _infer_target_from_filename("http-headers-", p)
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        raw = ""
    parsed = _parse_headers_txt(p)
    chain = _parse_redirect_chain(raw) if raw else []
    issues = _header_issues(parsed.get("headers", {}) or {})
    # Try to enrich with meta JSON produced by curl write-out.
    meta = _safe_load_json(out_dir / (p.name.replace(".txt", ".json")))
    if not isinstance(meta, dict):
        meta = {}
    hdrs = parsed.get("headers", {}) or {}
    targets.setdefault(t, {})["http"] = {
        "file": p.name,
        "status": parsed.get("status", 0),
        "url": meta.get("url"),
        "effective_url": meta.get("effective_url"),
        "redirects": meta.get("redirects"),
        "redirect_chain": chain,
        "hsts": _parse_hsts(hdrs),
        "csp": _assess_csp(hdrs),
        "issues": issues,
    }

items = []
for t, data in sorted(targets.items(), key=lambda kv: kv[0]):
    host = t
    port = None
    m = re.match(r"^(.*):(\d+)$", host)
    if m:
        host, port = m.group(1), int(m.group(2))
    items.append({
        "target": t,
        "host": host,
        "port": port,
        "dns": {"ips": _dns_resolve(host)},
        "nmap": data.get("nmap"),
        "tls": data.get("tls"),
        "http": data.get("http"),
    })

report = {
    "schema": {"name": "claudesec-network-report", "version": 1},
    "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    "targets": items,
}

out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PYNET
}

# ── Run all (Trivy always when available; nmap/ssl only when enabled) ───────

_trivy_run
_nmap_run
_sslscan_run
_http_headers_run
_normalize_network_report
