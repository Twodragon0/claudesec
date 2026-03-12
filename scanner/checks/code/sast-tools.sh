#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — SAST Tool Integration
# Integrates with external static analysis tools when available:
#   semgrep, bandit (Python), gosec (Go), eslint-plugin-security (JS/TS),
#   brakeman (Ruby), phpstan (PHP), cargo-audit (Rust), npm/pip audit
# Falls back gracefully when tools are not installed.
# ============================================================================

# Dashboard/non-interactive mode should be fast and side-effect free.
# Skip running external scanners (Semgrep/Bandit/gosec/audit tools) unless user runs `scan` explicitly.
if [[ "${CLAUDESEC_NONINTERACTIVE:-}" == "1" ]]; then
  skip "CODE-SAST-001" "Semgrep SAST scan" "Skipped in dashboard mode (set CLAUDESEC_NONINTERACTIVE=0 to run)"
  skip "CODE-SAST-002" "Bandit Python SAST" "Skipped in dashboard mode"
  skip "CODE-SAST-003" "gosec Go SAST" "Skipped in dashboard mode"
  skip "CODE-SAST-004" "Dependency Audit (npm/pip/cargo)" "Skipped in dashboard mode"
  return 0 2>/dev/null || true
fi

# ── CODE-SAST-001: Semgrep (Multi-language SAST) ────────────────────────────

if has_command semgrep; then
  info "Running Semgrep security scan..."
  _semgrep_output=$(semgrep scan --config auto --severity ERROR --severity WARNING \
    --json --quiet --max-target-bytes 1000000 \
    --exclude='node_modules' --exclude='.git' --exclude='vendor' --exclude='dist' --exclude='scanner' \
    "$SCAN_DIR" 2>/dev/null || true)

  if [[ -n "$_semgrep_output" ]]; then
    _semgrep_errors=$(echo "$_semgrep_output" | grep -c '"severity": "ERROR"' 2>/dev/null || echo 0)
    _semgrep_warns=$(echo "$_semgrep_output" | grep -c '"severity": "WARNING"' 2>/dev/null || echo 0)
    _semgrep_total=$((_semgrep_errors + _semgrep_warns))

    if [[ $_semgrep_total -gt 0 ]]; then
      # Extract top findings
      _semgrep_details="Semgrep: ${_semgrep_errors} error(s), ${_semgrep_warns} warning(s)"
      _semgrep_findings=$(echo "$_semgrep_output" | awk '
        /"check_id":/ { gsub(/.*"check_id": *"/, ""); gsub(/".*/, ""); rule=$0 }
        /"severity":/ { gsub(/.*"severity": *"/, ""); gsub(/".*/, ""); sev=$0 }
        /"message":/ { gsub(/.*"message": *"/, ""); gsub(/".*/, ""); msg=$0 }
        /"path":/ { gsub(/.*"path": *"/, ""); gsub(/".*/, ""); path=$0 }
        /"start":/ { getline; gsub(/.*"line": */, ""); gsub(/,.*/, ""); line=$0;
          if (count < 15 && rule != "") {
            printf "\\n    [%s] %s:%s — %s (%s)", sev, path, line, msg, rule
            count++
          }
          rule=""; sev=""; msg=""; path=""
        }
      ' 2>/dev/null || true)
      _semgrep_details="${_semgrep_details}${_semgrep_findings}"

      local _sev="high"
      [[ $_semgrep_errors -gt 0 ]] && _sev="critical"
      fail "CODE-SAST-001" "Semgrep: ${_semgrep_total} security finding(s)" "$_sev" \
        "$_semgrep_details" \
        "Run: semgrep scan --config auto --severity ERROR for details"
    else
      pass "CODE-SAST-001" "Semgrep: No security issues found"
    fi
  else
    pass "CODE-SAST-001" "Semgrep: No security issues found"
  fi
else
  skip "CODE-SAST-001" "Semgrep SAST scan" "Install: pip install semgrep or brew install semgrep"
fi

# ── CODE-SAST-002: Bandit (Python SAST) ──────────────────────────────────

if [[ "${_has_python:-}" == "true" ]]; then
  if has_command bandit; then
    info "Running Bandit Python security scan..."
    _bandit_output=$(bandit -r "$SCAN_DIR" -f json -ll --exclude '.git,node_modules,venv,scanner,.claudesec-prowler' 2>/dev/null || true)

    if [[ -n "$_bandit_output" ]]; then
      _bandit_high=$(echo "$_bandit_output" | grep -c '"severity": "HIGH"' 2>/dev/null || echo 0)
      _bandit_med=$(echo "$_bandit_output" | grep -c '"severity": "MEDIUM"' 2>/dev/null || echo 0)
      _bandit_total=$((_bandit_high + _bandit_med))

      if [[ $_bandit_total -gt 0 ]]; then
        _bandit_details="Bandit: ${_bandit_high} high, ${_bandit_med} medium"
        _bandit_findings=$(echo "$_bandit_output" | awk '
          /"test_id":/ { gsub(/.*"test_id": *"/, ""); gsub(/".*/, ""); tid=$0 }
          /"severity":/ { gsub(/.*"severity": *"/, ""); gsub(/".*/, ""); sev=$0 }
          /"issue_text":/ { gsub(/.*"issue_text": *"/, ""); gsub(/".*/, ""); msg=$0 }
          /"filename":/ { gsub(/.*"filename": *"/, ""); gsub(/".*/, ""); file=$0 }
          /"line_number":/ { gsub(/.*"line_number": */, ""); gsub(/,.*/, ""); line=$0;
            if (count < 15 && tid != "") {
              printf "\\n    [%s] %s:%s — %s (%s)", sev, file, line, msg, tid
              count++
            }
            tid=""; sev=""; msg=""; file=""
          }
        ' 2>/dev/null || true)
        _bandit_details="${_bandit_details}${_bandit_findings}"

        fail "CODE-SAST-002" "Bandit: ${_bandit_total} Python security issue(s)" "high" \
          "$_bandit_details" \
          "Run: bandit -r . -ll for details"
      else
        pass "CODE-SAST-002" "Bandit: No high/medium Python issues"
      fi
    else
      pass "CODE-SAST-002" "Bandit: No Python security issues found"
    fi
  else
    skip "CODE-SAST-002" "Bandit Python SAST" "Install: pip install bandit"
  fi
else
  skip "CODE-SAST-002" "Bandit Python SAST" "No Python files detected"
fi

# ── CODE-SAST-003: gosec (Go SAST) ──────────────────────────────────────

if [[ "${_has_go:-}" == "true" ]]; then
  if has_command gosec; then
    info "Running gosec Go security scan..."
    _gosec_output=$(cd "$SCAN_DIR" && gosec -fmt json -quiet ./... 2>/dev/null || true)

    if [[ -n "$_gosec_output" ]]; then
      _gosec_count=$(echo "$_gosec_output" | grep -c '"severity": "HIGH"' 2>/dev/null || echo 0)
      _gosec_med=$(echo "$_gosec_output" | grep -c '"severity": "MEDIUM"' 2>/dev/null || echo 0)
      _gosec_total=$((_gosec_count + _gosec_med))

      if [[ $_gosec_total -gt 0 ]]; then
        _gosec_details="gosec: ${_gosec_count} high, ${_gosec_med} medium"
        fail "CODE-SAST-003" "gosec: ${_gosec_total} Go security issue(s)" "high" \
          "$_gosec_details" \
          "Run: gosec ./... for details"
      else
        pass "CODE-SAST-003" "gosec: No high/medium Go issues"
      fi
    else
      pass "CODE-SAST-003" "gosec: No Go security issues found"
    fi
  else
    skip "CODE-SAST-003" "gosec Go SAST" "Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
  fi
else
  skip "CODE-SAST-003" "gosec Go SAST" "No Go files detected"
fi

# ── CODE-SAST-004: Dependency Audit (npm/pip/cargo) ──────────────────────

_dep_total=0
_dep_details=""

# npm audit
if [[ -f "$SCAN_DIR/package-lock.json" || -f "$SCAN_DIR/yarn.lock" ]]; then
  if has_command npm; then
    _npm_audit=$(cd "$SCAN_DIR" && npm audit --json 2>/dev/null || true)
    if [[ -n "$_npm_audit" ]]; then
      _npm_critical=$(echo "$_npm_audit" | grep -oE '"critical":[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
      _npm_high=$(echo "$_npm_audit" | grep -oE '"high":[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
      _npm_total=$((_npm_critical + _npm_high))
      if [[ $_npm_total -gt 0 ]]; then
        _dep_total=$((_dep_total + _npm_total))
        _dep_details="${_dep_details}\\n    npm: ${_npm_critical} critical, ${_npm_high} high"
      fi
    fi
  fi
fi

# pip-audit / safety
if [[ -f "$SCAN_DIR/requirements.txt" || -f "$SCAN_DIR/Pipfile.lock" || -f "$SCAN_DIR/poetry.lock" ]]; then
  if has_command pip-audit; then
    _pip_audit=$(cd "$SCAN_DIR" && pip-audit -r requirements.txt --format json 2>/dev/null || true)
    if [[ -n "$_pip_audit" ]]; then
      _pip_vulns=$(echo "$_pip_audit" | grep -c '"id":' 2>/dev/null || echo 0)
      if [[ $_pip_vulns -gt 0 ]]; then
        _dep_total=$((_dep_total + _pip_vulns))
        _dep_details="${_dep_details}\\n    pip: ${_pip_vulns} known vulnerability(ies)"
      fi
    fi
  elif has_command safety; then
    _safety_out=$(cd "$SCAN_DIR" && safety check --json 2>/dev/null || true)
    if [[ -n "$_safety_out" ]]; then
      _safety_vulns=$(echo "$_safety_out" | grep -c '"vulnerability_id"' 2>/dev/null || echo 0)
      if [[ $_safety_vulns -gt 0 ]]; then
        _dep_total=$((_dep_total + _safety_vulns))
        _dep_details="${_dep_details}\\n    pip (safety): ${_safety_vulns} known vulnerability(ies)"
      fi
    fi
  fi
fi

# cargo audit (Rust)
if [[ -f "$SCAN_DIR/Cargo.lock" ]] && has_command cargo-audit; then
  _cargo_audit=$(cd "$SCAN_DIR" && cargo audit --json 2>/dev/null || true)
  if [[ -n "$_cargo_audit" ]]; then
    _cargo_vulns=$(echo "$_cargo_audit" | grep -c '"id":' 2>/dev/null || echo 0)
    if [[ $_cargo_vulns -gt 0 ]]; then
      _dep_total=$((_dep_total + _cargo_vulns))
      _dep_details="${_dep_details}\\n    cargo: ${_cargo_vulns} known vulnerability(ies)"
    fi
  fi
fi

# Go vulnerability check
if [[ -f "$SCAN_DIR/go.sum" ]] && has_command govulncheck; then
  _go_vuln=$(cd "$SCAN_DIR" && govulncheck ./... 2>/dev/null | grep -c 'Vulnerability' || echo 0)
  if [[ $_go_vuln -gt 0 ]]; then
    _dep_total=$((_dep_total + _go_vuln))
    _dep_details="${_dep_details}\\n    go: ${_go_vuln} known vulnerability(ies)"
  fi
fi

if [[ $_dep_total -gt 0 ]]; then
  fail "CODE-SAST-004" "Dependency Audit: ${_dep_total} known vulnerability(ies)" "high" \
    "Known vulnerabilities in dependencies:${_dep_details}" \
    "Run npm audit fix, pip-audit, or cargo audit fix. Update vulnerable packages."
elif [[ -f "$SCAN_DIR/package-lock.json" || -f "$SCAN_DIR/requirements.txt" || -f "$SCAN_DIR/Cargo.lock" || -f "$SCAN_DIR/go.sum" ]]; then
  pass "CODE-SAST-004" "Dependency audit: No known high/critical vulnerabilities"
else
  skip "CODE-SAST-004" "Dependency audit" "No lockfile found (package-lock.json, requirements.txt, Cargo.lock, go.sum)"
fi

# ── CODE-SAST-005: Brakeman (Ruby on Rails SAST) ────────────────────────

if [[ "${_has_ruby:-}" == "true" && -f "$SCAN_DIR/Gemfile" ]]; then
  if has_command brakeman; then
    info "Running Brakeman Rails security scan..."
    _brake_output=$(brakeman -q --no-pager -f json "$SCAN_DIR" 2>/dev/null || true)
    if [[ -n "$_brake_output" ]]; then
      _brake_high=$(echo "$_brake_output" | grep -c '"confidence": "High"' 2>/dev/null || echo 0)
      _brake_total=$(echo "$_brake_output" | grep -c '"warning_type"' 2>/dev/null || echo 0)
      if [[ $_brake_total -gt 0 ]]; then
        fail "CODE-SAST-005" "Brakeman: ${_brake_total} Rails warning(s) (${_brake_high} high confidence)" "high" \
          "Run brakeman for full report" \
          "Fix high-confidence findings first"
      else
        pass "CODE-SAST-005" "Brakeman: No Rails security warnings"
      fi
    else
      pass "CODE-SAST-005" "Brakeman: No Rails security warnings"
    fi
  else
    skip "CODE-SAST-005" "Brakeman Rails SAST" "Install: gem install brakeman"
  fi
else
  skip "CODE-SAST-005" "Brakeman Rails SAST" "No Ruby on Rails project detected"
fi

# ── CODE-SAST-006: SAST Tool Coverage Summary ───────────────────────────

_sast_available=0
_sast_list=""

has_command semgrep && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} semgrep"; }
has_command bandit && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} bandit"; }
has_command gosec && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} gosec"; }
has_command brakeman && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} brakeman"; }
has_command npm && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} npm-audit"; }
has_command pip-audit && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} pip-audit"; }
has_command safety && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} safety"; }
has_command cargo-audit && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} cargo-audit"; }
has_command govulncheck && { _sast_available=$((_sast_available+1)); _sast_list="${_sast_list} govulncheck"; }

if [[ $_sast_available -ge 2 ]]; then
  pass "CODE-SAST-006" "SAST tool coverage: ${_sast_available} tool(s) available (${_sast_list})"
elif [[ $_sast_available -eq 1 ]]; then
  warn "CODE-SAST-006" "Limited SAST coverage: only${_sast_list} available" \
    "Install semgrep for multi-language coverage. Consider: bandit (Python), gosec (Go), brakeman (Ruby)"
else
  warn "CODE-SAST-006" "No SAST tools installed" \
    "Install semgrep (multi-language), bandit (Python), gosec (Go) for automated vulnerability scanning"
fi
