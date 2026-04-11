#!/usr/bin/env bash
# ClaudeSec — Network: TLS & Connection Security Checks

# NET-001: HTTPS enforced (no plain HTTP URLs)
# Exclude ephemeral state, vendored deps, and build outputs so heuristic
# checks run only over audited application code.
http_files=$(find "$SCAN_DIR" \( -name "*.ts" -o -name "*.js" -o -name "*.py" -o -name "*.go" -o -name "*.java" \) \
  -not -path "*/node_modules/*" -not -path "*/.git/*" \
  -not -path "*/.venv*/*" -not -path "*/venv/*" \
  -not -path "*/.omc/*" -not -path "*/.claude/*" \
  -not -path "*/.claudesec-*" -not -path "*/dist/*" -not -path "*/build/*" \
  -not -path "*/__pycache__/*" -not -path "*/.cache/*" \
  2>/dev/null | head -100 || true)

if [[ -n "$http_files" ]]; then
  if echo "$http_files" | xargs grep -lE "http://[^l][^o][^c]" 2>/dev/null | head -1 | grep -q . 2>/dev/null; then
    warn "NET-001" "Non-HTTPS URLs found in source code" \
      "Replace http:// with https:// for external connections"
  else
    pass "NET-001" "No plain HTTP URLs found (excluding localhost)"
  fi
else
  skip "NET-001" "HTTPS enforcement" "No application source files found"
fi

# NET-002: TLS configuration (nginx/apache)
if has_file "nginx.conf" || files_contain "*.conf" "server" 2>/dev/null; then
  if files_contain "*.conf" "ssl_protocols\s+TLSv1(\s|;|$)|ssl_protocols\s.*TLSv1\.0|ssl_protocols\s.*TLSv1\.1(\s|;|$)|SSLv3"; then
    fail "NET-002" "Deprecated TLS versions enabled" "high" \
      "TLS 1.0/1.1 and SSLv3 are deprecated and insecure" \
      "Use 'ssl_protocols TLSv1.2 TLSv1.3;'"
  elif files_contain "*.conf" "ssl_protocols\s+TLSv1\.[23]"; then
    pass "NET-002" "TLS 1.2+ configured"
  else
    skip "NET-002" "TLS version check" "No TLS configuration found"
  fi
else
  skip "NET-002" "TLS configuration" "No web server config found"
fi

# NET-003: Security headers
if files_contain "*.conf" "Content-Security-Policy" 2>/dev/null || \
   files_contain "*.ts" "Content-Security-Policy|helmet" 2>/dev/null || \
   files_contain "*.js" "Content-Security-Policy|helmet" 2>/dev/null; then
  pass "NET-003" "Security headers (CSP) configured"
else
  if files_contain "*.ts" "(express|fastify|koa|hono)" 2>/dev/null || \
     files_contain "*.js" "(express|fastify|koa|hono)" 2>/dev/null; then
    warn "NET-003" "No Content-Security-Policy header detected" \
      "Add security headers (CSP, HSTS, X-Frame-Options) or use helmet middleware"
  else
    skip "NET-003" "Security headers" "No web server detected"
  fi
fi

# NET-004: CORS configuration
if files_contain "*.ts" "cors|Access-Control-Allow-Origin" 2>/dev/null || \
   files_contain "*.js" "cors|Access-Control-Allow-Origin" 2>/dev/null || \
   files_contain "*.py" "cors|Access-Control-Allow-Origin" 2>/dev/null; then
  if files_contain "*.ts" "origin:\s*['\"]?\*['\"]?" 2>/dev/null || \
     files_contain "*.js" "origin:\s*['\"]?\*['\"]?" 2>/dev/null || \
     files_contain "*.py" "allow_origins.*\*" 2>/dev/null; then
    warn "NET-004" "CORS allows all origins (*)" \
      "Restrict CORS to specific trusted origins"
  else
    pass "NET-004" "CORS configured with restricted origins"
  fi
else
  skip "NET-004" "CORS configuration" "No CORS patterns found"
fi

# NET-005: Firewall rules (cloud/IaC)
if files_contain "*.tf" "0\.0\.0\.0/0" 2>/dev/null; then
  if files_contain "*.tf" "0\.0\.0\.0/0.*22\|port.*22.*0\.0\.0\.0/0" 2>/dev/null; then
    fail "NET-005" "SSH (port 22) open to 0.0.0.0/0 in IaC" "critical" \
      "SSH should not be open to the internet" \
      "Restrict to specific IP ranges or use a bastion host"
  else
    warn "NET-005" "Ingress rule allows 0.0.0.0/0" \
      "Review if public access is intentional"
  fi
else
  skip "NET-005" "Firewall rules" "No IaC firewall rules found"
fi
