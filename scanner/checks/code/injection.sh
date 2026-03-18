#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Code Vulnerability Scanner: Injection & Input Handling
# OWASP Top 10 2025: A03 Injection, A01 Broken Access Control
# Severity: P0 (Critical), P1 (High), Medium, Low
# ============================================================================

# Detect languages in use
_has_python=false; _has_js=false; _has_ts=false; _has_go=false; _has_java=false; _has_ruby=false; _has_php=false; _has_rust=false; _has_csharp=false

[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.py' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/venv/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_python=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.js' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/dist/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_js=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.ts' -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/dist/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_ts=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_go=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.java' -not -path '*/.git/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_java=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.rb' -not -path '*/.git/*' -not -path '*/vendor/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_ruby=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.php' -not -path '*/.git/*' -not -path '*/vendor/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_php=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.rs' -not -path '*/.git/*' -not -path '*/target/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_rust=true
[[ -n "$(find "$SCAN_DIR" -maxdepth 4 -name '*.cs' -not -path '*/.git/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _has_csharp=true

_any_code=false
[[ "$_has_python" == "true" || "$_has_js" == "true" || "$_has_ts" == "true" || "$_has_go" == "true" || "$_has_java" == "true" || "$_has_ruby" == "true" || "$_has_php" == "true" || "$_has_rust" == "true" || "$_has_csharp" == "true" ]] && _any_code=true

if [[ "$_any_code" != "true" ]]; then
  skip "CODE-INJ-001" "SQL Injection scan" "No source code files detected"
  skip "CODE-INJ-002" "Command Injection scan" "No source code files detected"
  skip "CODE-INJ-003" "XSS vulnerability scan" "No source code files detected"
  skip "CODE-INJ-004" "Path Traversal scan" "No source code files detected"
  skip "CODE-INJ-005" "SSRF vulnerability scan" "No source code files detected"
  skip "CODE-INJ-006" "Template Injection scan" "No source code files detected"
  skip "CODE-INJ-007" "LDAP/NoSQL Injection scan" "No source code files detected"
  skip "CODE-INJ-008" "XML/XXE vulnerability scan" "No source code files detected"
  return 0 2>/dev/null || exit 0
fi

# Shared exclude paths for find
_FIND_EXCLUDE='-not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" -not -path "*/dist/*" -not -path "*/venv/*" -not -path "*/__pycache__/*" -not -path "*/target/*" -not -path "*/scanner/*" -not -path "*/.claudesec-*" -not -path "*test*" -not -path "*spec*" -not -path "*mock*"'

# Helper: search code files for pattern, return file:line matches
_code_grep() {
  local pattern="$1" extensions="$2" max_hits="${3:-20}"
  local results=""

  IFS=',' read -ra exts <<< "$extensions"
  for ext in "${exts[@]}"; do
    local hits
    hits=$(find "$SCAN_DIR" -maxdepth 5 -name "$ext" \
      -not -path "*/.git/*" -not -path "*/node_modules/*" -not -path "*/vendor/*" \
      -not -path "*/dist/*" -not -path "*/venv/*" -not -path "*/.venv*/*" -not -path "*/__pycache__/*" \
      -not -path "*/target/*" -not -path "*/scanner/*" -not -path "*/.claudesec-*" \
      -exec grep -nE "$pattern" {} /dev/null \; 2>/dev/null | head -"$max_hits" || true)
    [[ -n "$hits" ]] && results="${results}${results:+$'\n'}${hits}"
  done

  echo "$results" | head -"$max_hits"
}

# Format findings for details field (uses literal \n for pipe-delimited storage)
_format_hits() {
  local hits="$1" max="${2:-10}"
  local output="" count=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ $count -ge $max ]] && break
    # Shorten path relative to SCAN_DIR
    line="${line#$SCAN_DIR/}"
    output="${output}\\n    ${line}"
    count=$((count + 1))
  done <<< "$hits"
  local total
  total=$(echo "$hits" | grep -c . 2>/dev/null || echo 0)
  [[ $total -gt $max ]] && output="${output}\\n    ... and $((total - max)) more"
  echo "$output"
}

# ── CODE-INJ-001: SQL Injection (P0/Critical) — OWASP A03 ─────────────────

_sqli_hits=""

# Python: string formatting in SQL queries
[[ "$_has_python" == "true" ]] && {
  _sqli_hits=$(_code_grep '(execute|cursor\.execute|raw|RawSQL)\s*\(\s*(f"|f'"'"'|%s|".*%|".*\.format|".*\+)' "*.py")
}

# JavaScript/TypeScript: string concatenation in queries
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_sqli=$(_code_grep '(query|execute|raw)\s*\(\s*(`[^`]*\$\{|"[^"]*"\s*\+|'"'"'[^'"'"']*'"'"'\s*\+)' "*.js,*.ts,*.tsx")
  [[ -n "$_js_sqli" ]] && _sqli_hits="${_sqli_hits}${_sqli_hits:+$'\n'}${_js_sqli}"
}

# Go: string formatting in SQL
[[ "$_has_go" == "true" ]] && {
  _go_sqli=$(_code_grep '(Query|Exec|Prepare)\s*\(\s*(fmt\.Sprintf|"[^"]*"\s*\+)' "*.go")
  [[ -n "$_go_sqli" ]] && _sqli_hits="${_sqli_hits}${_sqli_hits:+$'\n'}${_go_sqli}"
}

# Java: string concatenation in SQL
[[ "$_has_java" == "true" ]] && {
  _java_sqli=$(_code_grep '(createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\(\s*"[^"]*"\s*\+' "*.java")
  [[ -n "$_java_sqli" ]] && _sqli_hits="${_sqli_hits}${_sqli_hits:+$'\n'}${_java_sqli}"
}

# PHP: SQL with variables
[[ "$_has_php" == "true" ]] && {
  _php_sqli=$(_code_grep '(mysql_query|mysqli_query|pg_query|->query)\s*\(\s*"[^"]*\$' "*.php")
  [[ -n "$_php_sqli" ]] && _sqli_hits="${_sqli_hits}${_sqli_hits:+$'\n'}${_php_sqli}"
}

# Ruby: string interpolation in SQL
[[ "$_has_ruby" == "true" ]] && {
  _rb_sqli=$(_code_grep '(where|find_by_sql|execute)\s*\(\s*"[^"]*#\{' "*.rb")
  [[ -n "$_rb_sqli" ]] && _sqli_hits="${_sqli_hits}${_sqli_hits:+$'\n'}${_rb_sqli}"
}

if [[ -n "$_sqli_hits" ]]; then
  _sqli_count=$(echo "$_sqli_hits" | grep -c . 2>/dev/null || echo 0)
  _sqli_details="P0: SQL Injection — ${_sqli_count} potential injection point(s) found$(_format_hits "$_sqli_hits")"
  fail "CODE-INJ-001" "SQL Injection: ${_sqli_count} unsafe query pattern(s)" "critical" \
    "$_sqli_details" \
    "Use parameterized queries/prepared statements. Never concatenate user input into SQL (OWASP A03)"
else
  pass "CODE-INJ-001" "No SQL injection patterns detected"
fi

# ── CODE-INJ-002: Command Injection (P0/Critical) — OWASP A03 ────────────

_cmdi_hits=""

# Python: os.system, subprocess with shell=True, os.popen
[[ "$_has_python" == "true" ]] && {
  _cmdi_hits=$(_code_grep '(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*(\+|f"|f'"'"'|%s|\.format)' "*.py")
  _py_shell=$(_code_grep 'shell\s*=\s*True' "*.py")
  [[ -n "$_py_shell" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_py_shell}"
}

# JavaScript: child_process.exec with string concat
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_cmdi=$(_code_grep '(exec|execSync|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{|"[^"]*"\s*\+|'"'"'[^'"'"']*'"'"'\s*\+)' "*.js,*.ts")
  [[ -n "$_js_cmdi" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_js_cmdi}"
}

# Go: exec.Command with user input
[[ "$_has_go" == "true" ]] && {
  _go_cmdi=$(_code_grep 'exec\.Command\s*\(.*(\+|fmt\.Sprintf)' "*.go")
  [[ -n "$_go_cmdi" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_go_cmdi}"
}

# Java: Runtime.exec with concat
[[ "$_has_java" == "true" ]] && {
  _java_cmdi=$(_code_grep '(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(.*\+' "*.java")
  [[ -n "$_java_cmdi" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_java_cmdi}"
}

# PHP: system, exec, passthru, shell_exec with variables
[[ "$_has_php" == "true" ]] && {
  _php_cmdi=$(_code_grep '(system|exec|passthru|shell_exec|popen|proc_open)\s*\(.*\$' "*.php")
  [[ -n "$_php_cmdi" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_php_cmdi}"
}

# Ruby: system, backticks with interpolation
[[ "$_has_ruby" == "true" ]] && {
  _rb_cmdi=$(_code_grep '(system|%x|exec)\s*\(?\s*"[^"]*#\{' "*.rb")
  [[ -n "$_rb_cmdi" ]] && _cmdi_hits="${_cmdi_hits}${_cmdi_hits:+$'\n'}${_rb_cmdi}"
}

if [[ -n "$_cmdi_hits" ]]; then
  _cmdi_count=$(echo "$_cmdi_hits" | grep -c . 2>/dev/null || echo 0)
  _cmdi_details="P0: Command Injection — ${_cmdi_count} unsafe command execution(s)$(_format_hits "$_cmdi_hits")"
  fail "CODE-INJ-002" "Command Injection: ${_cmdi_count} unsafe exec pattern(s)" "critical" \
    "$_cmdi_details" \
    "Use parameterized APIs (subprocess.run with list args). Never pass user input to shell commands (OWASP A03)"
else
  pass "CODE-INJ-002" "No command injection patterns detected"
fi

# ── CODE-INJ-003: XSS — Cross-Site Scripting (P1/High) — OWASP A03 ──────

_xss_hits=""

# JavaScript/TypeScript: innerHTML, document.write, dangerouslySetInnerHTML
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _xss_hits=$(_code_grep '(innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\.html\s*\()' "*.js,*.ts,*.jsx,*.tsx")
}

# Python: mark_safe, |safe in templates, Markup() with user input
[[ "$_has_python" == "true" ]] && {
  _py_xss=$(_code_grep '(mark_safe|Markup)\s*\(|__html__|autoescape\s+off|\|safe' "*.py,*.html")
  [[ -n "$_py_xss" ]] && _xss_hits="${_xss_hits}${_xss_hits:+$'\n'}${_py_xss}"
}

# PHP: echo without htmlspecialchars
[[ "$_has_php" == "true" ]] && {
  _php_xss=$(_code_grep 'echo\s+\$_(GET|POST|REQUEST|COOKIE)' "*.php")
  [[ -n "$_php_xss" ]] && _xss_hits="${_xss_hits}${_xss_hits:+$'\n'}${_php_xss}"
}

# Ruby: raw, html_safe
[[ "$_has_ruby" == "true" ]] && {
  _rb_xss=$(_code_grep '\.html_safe|raw\s+' "*.rb,*.erb")
  [[ -n "$_rb_xss" ]] && _xss_hits="${_xss_hits}${_xss_hits:+$'\n'}${_rb_xss}"
}

if [[ -n "$_xss_hits" ]]; then
  _xss_count=$(echo "$_xss_hits" | grep -c . 2>/dev/null || echo 0)
  _xss_details="P1: Cross-Site Scripting — ${_xss_count} potential XSS vector(s)$(_format_hits "$_xss_hits")"
  fail "CODE-INJ-003" "XSS: ${_xss_count} unescaped output pattern(s)" "high" \
    "$_xss_details" \
    "Use framework auto-escaping. Sanitize with DOMPurify or equivalent. CSP headers recommended (OWASP A03)"
else
  pass "CODE-INJ-003" "No XSS patterns detected"
fi

# ── CODE-INJ-004: Path Traversal (P1/High) — OWASP A01 ──────────────────

_path_hits=""

# Python: open() with user-controlled path
[[ "$_has_python" == "true" ]] && {
  _path_hits=$(_code_grep 'open\s*\(.*request\.|os\.path\.join\s*\(.*request\.' "*.py")
}

# JavaScript/TypeScript: fs operations with user input
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_path=$(_code_grep '(readFile|readFileSync|createReadStream|writeFile)\s*\(.*req\.' "*.js,*.ts")
  [[ -n "$_js_path" ]] && _path_hits="${_path_hits}${_path_hits:+$'\n'}${_js_path}"
}

# Go: os.Open with request param
[[ "$_has_go" == "true" ]] && {
  _go_path=$(_code_grep '(os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\(.*r\.' "*.go")
  [[ -n "$_go_path" ]] && _path_hits="${_path_hits}${_path_hits:+$'\n'}${_go_path}"
}

# Java: File operations with request
[[ "$_has_java" == "true" ]] && {
  _java_path=$(_code_grep 'new File\s*\(.*request\.getParameter' "*.java")
  [[ -n "$_java_path" ]] && _path_hits="${_path_hits}${_path_hits:+$'\n'}${_java_path}"
}

# PHP: file operations with user input
[[ "$_has_php" == "true" ]] && {
  _php_path=$(_code_grep '(include|require|fopen|file_get_contents)\s*\(.*\$_(GET|POST|REQUEST)' "*.php")
  [[ -n "$_php_path" ]] && _path_hits="${_path_hits}${_path_hits:+$'\n'}${_php_path}"
}

if [[ -n "$_path_hits" ]]; then
  _path_count=$(echo "$_path_hits" | grep -c . 2>/dev/null || echo 0)
  _path_details="P1: Path Traversal — ${_path_count} unsafe file access pattern(s)$(_format_hits "$_path_hits")"
  fail "CODE-INJ-004" "Path Traversal: ${_path_count} unvalidated file path(s)" "high" \
    "$_path_details" \
    "Validate and canonicalize file paths. Use allowlists for permitted directories (OWASP A01)"
else
  pass "CODE-INJ-004" "No path traversal patterns detected"
fi

# ── CODE-INJ-005: SSRF — Server-Side Request Forgery (P1/High) — OWASP A10 ──

_ssrf_hits=""

# Python: requests/urllib with user-controlled URL
[[ "$_has_python" == "true" ]] && {
  _ssrf_hits=$(_code_grep '(requests\.(get|post|put|delete|head|patch)|urllib\.request\.urlopen|httpx\.(get|post))\s*\(.*request\.' "*.py")
}

# JavaScript: fetch/axios with user URL
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_ssrf=$(_code_grep '(fetch|axios\.(get|post)|http\.request|https\.request)\s*\(.*req\.' "*.js,*.ts")
  [[ -n "$_js_ssrf" ]] && _ssrf_hits="${_ssrf_hits}${_ssrf_hits:+$'\n'}${_js_ssrf}"
}

# Go: http.Get with user input
[[ "$_has_go" == "true" ]] && {
  _go_ssrf=$(_code_grep 'http\.(Get|Post|Do)\s*\(.*r\.(URL|Form|Query)' "*.go")
  [[ -n "$_go_ssrf" ]] && _ssrf_hits="${_ssrf_hits}${_ssrf_hits:+$'\n'}${_go_ssrf}"
}

# Java: URL with request param
[[ "$_has_java" == "true" ]] && {
  _java_ssrf=$(_code_grep 'new URL\s*\(.*request\.getParameter' "*.java")
  [[ -n "$_java_ssrf" ]] && _ssrf_hits="${_ssrf_hits}${_ssrf_hits:+$'\n'}${_java_ssrf}"
}

if [[ -n "$_ssrf_hits" ]]; then
  _ssrf_count=$(echo "$_ssrf_hits" | grep -c . 2>/dev/null || echo 0)
  _ssrf_details="P1: SSRF — ${_ssrf_count} user-controlled URL request(s)$(_format_hits "$_ssrf_hits")"
  fail "CODE-INJ-005" "SSRF: ${_ssrf_count} user-controlled URL pattern(s)" "high" \
    "$_ssrf_details" \
    "Validate URLs against allowlist. Block internal/private IP ranges. Use URL parsers (OWASP A10)"
else
  pass "CODE-INJ-005" "No SSRF patterns detected"
fi

# ── CODE-INJ-006: Template Injection (P0/Critical) — OWASP A03 ──────────

_ssti_hits=""

# Python: Jinja2/Mako render_template_string with user input
[[ "$_has_python" == "true" ]] && {
  _ssti_hits=$(_code_grep '(render_template_string|Template)\s*\(.*request\.|Environment\s*\(.*autoescape\s*=\s*False' "*.py")
}

# JavaScript: template engines with user input
[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_ssti=$(_code_grep '(ejs\.render|pug\.render|nunjucks\.renderString)\s*\(.*req\.' "*.js,*.ts")
  [[ -n "$_js_ssti" ]] && _ssti_hits="${_ssti_hits}${_ssti_hits:+$'\n'}${_js_ssti}"
}

# Java: Freemarker/Velocity with user input
[[ "$_has_java" == "true" ]] && {
  _java_ssti=$(_code_grep '(Template|VelocityEngine).*request\.getParameter' "*.java")
  [[ -n "$_java_ssti" ]] && _ssti_hits="${_ssti_hits}${_ssti_hits:+$'\n'}${_java_ssti}"
}

if [[ -n "$_ssti_hits" ]]; then
  _ssti_count=$(echo "$_ssti_hits" | grep -c . 2>/dev/null || echo 0)
  _ssti_details="P0: Template Injection — ${_ssti_count} unsafe template rendering(s)$(_format_hits "$_ssti_hits")"
  fail "CODE-INJ-006" "SSTI: ${_ssti_count} user input in template rendering" "critical" \
    "$_ssti_details" \
    "Never render user input as templates. Use data-binding instead of string templating (OWASP A03)"
else
  pass "CODE-INJ-006" "No template injection patterns detected"
fi

# ── CODE-INJ-007: LDAP/NoSQL Injection (P1/High) — OWASP A03 ────────────

_nosql_hits=""

# Python/JS: MongoDB queries with user input
[[ "$_has_python" == "true" ]] && {
  _nosql_hits=$(_code_grep '(find|find_one|aggregate|update_one|delete_one)\s*\(.*request\.' "*.py")
}

[[ "$_has_js" == "true" || "$_has_ts" == "true" ]] && {
  _js_nosql=$(_code_grep '(find|findOne|aggregate|updateOne|deleteOne)\s*\(.*req\.(body|query|params)' "*.js,*.ts")
  [[ -n "$_js_nosql" ]] && _nosql_hits="${_nosql_hits}${_nosql_hits:+$'\n'}${_js_nosql}"
}

# LDAP injection
_ldap_hits=""
_ldap_hits=$(_code_grep '(ldap_search|search_s|ldap\.search)\s*\(.*(\+|f"|%s|\.format|req\.)' "*.py,*.js,*.ts,*.java,*.php")

_all_nosql="${_nosql_hits}${_nosql_hits:+$'\n'}${_ldap_hits}"
_all_nosql=$(echo "$_all_nosql" | grep -v '^$' || true)

if [[ -n "$_all_nosql" ]]; then
  _nosql_count=$(echo "$_all_nosql" | grep -c . 2>/dev/null || echo 0)
  _nosql_details="P1: LDAP/NoSQL Injection — ${_nosql_count} unsanitized query input(s)$(_format_hits "$_all_nosql")"
  fail "CODE-INJ-007" "LDAP/NoSQL Injection: ${_nosql_count} unsafe query pattern(s)" "high" \
    "$_nosql_details" \
    "Sanitize and validate query inputs. Use ODM/ORM query builders. Never pass raw user input to queries (OWASP A03)"
else
  pass "CODE-INJ-007" "No LDAP/NoSQL injection patterns detected"
fi

# ── CODE-INJ-008: XML/XXE Vulnerabilities (P0/Critical) — OWASP A05 ─────

_xxe_hits=""

# Python: xml.etree without defused, lxml with resolve_entities
[[ "$_has_python" == "true" ]] && {
  _xxe_hits=$(_code_grep 'xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|lxml\.etree\.parse' "*.py")
}

# Java: DocumentBuilderFactory without secure features
[[ "$_has_java" == "true" ]] && {
  _java_xxe=$(_code_grep 'DocumentBuilderFactory|SAXParser|XMLReader|TransformerFactory' "*.java")
  [[ -n "$_java_xxe" ]] && _xxe_hits="${_xxe_hits}${_xxe_hits:+$'\n'}${_java_xxe}"
}

# PHP: simplexml_load_string, DOMDocument
[[ "$_has_php" == "true" ]] && {
  _php_xxe=$(_code_grep '(simplexml_load_string|DOMDocument|xml_parse)\s*\(' "*.php")
  [[ -n "$_php_xxe" ]] && _xxe_hits="${_xxe_hits}${_xxe_hits:+$'\n'}${_php_xxe}"
}

# C#: XmlDocument, XmlReader
[[ "$_has_csharp" == "true" ]] && {
  _cs_xxe=$(_code_grep '(XmlDocument|XmlTextReader|XmlReader)' "*.cs")
  [[ -n "$_cs_xxe" ]] && _xxe_hits="${_xxe_hits}${_xxe_hits:+$'\n'}${_cs_xxe}"
}

if [[ -n "$_xxe_hits" ]]; then
  _xxe_count=$(echo "$_xxe_hits" | grep -c . 2>/dev/null || echo 0)
  _xxe_details="P0: XML/XXE — ${_xxe_count} XML parser(s) without secure configuration$(_format_hits "$_xxe_hits")"
  fail "CODE-INJ-008" "XXE: ${_xxe_count} XML parser(s) may be vulnerable" "critical" \
    "$_xxe_details" \
    "Use defusedxml (Python), disable external entities (Java: setFeature). Never parse untrusted XML without hardening (OWASP A05)"
else
  pass "CODE-INJ-008" "No XXE-vulnerable XML parser patterns detected"
fi
