#!/usr/bin/env bash
# shellcheck disable=SC2016,SC2317
# ============================================================================
# ClaudeSec — Code Vulnerability Scanner: Security Design Flaws
# OWASP Top 10 2025: A02 Crypto, A04 Insecure Design, A07 Auth, A08 Integrity
# Severity: P0 (Critical), P1 (High), Medium, Low
# ============================================================================

# Re-use language detection from injection.sh (sourced before this file)
# If vars not set, re-detect
if [[ -z "${_any_code:-}" ]]; then
  _any_code=false
  [[ -n "$(find "$SCAN_DIR" -maxdepth 4 \( -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.go' -o -name '*.java' -o -name '*.rb' -o -name '*.php' \) -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/scanner/*' 2>/dev/null | head -1)" ]] && _any_code=true
fi

if [[ "$_any_code" != "true" ]]; then
  skip "CODE-SEC-001" "Insecure crypto scan" "No source code files detected"
  skip "CODE-SEC-002" "Unsafe deserialization scan" "No source code files detected"
  skip "CODE-SEC-003" "Hardcoded credentials scan" "No source code files detected"
  skip "CODE-SEC-004" "Insecure random scan" "No source code files detected"
  skip "CODE-SEC-005" "Debug/dev mode scan" "No source code files detected"
  skip "CODE-SEC-006" "Error information leak scan" "No source code files detected"
  skip "CODE-SEC-007" "Insecure file upload scan" "No source code files detected"
  skip "CODE-SEC-008" "Race condition scan" "No source code files detected"
  skip "CODE-SEC-009" "Prototype pollution scan" "No source code files detected"
  skip "CODE-SEC-010" "Insecure redirect scan" "No source code files detected"
  if ! return 0 2>/dev/null; then
    exit 0
  fi
fi

# ── CODE-SEC-001: Insecure Cryptography (P1/High) — OWASP A02 ────────────

_crypto_hits=""

# Weak hash algorithms: MD5, SHA1
_crypto_hits=$(_code_grep '(md5|MD5|sha1|SHA1)\s*\(|hashlib\.(md5|sha1)|MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"' "*.py,*.js,*.ts,*.go,*.java,*.rb,*.php")

# Weak encryption: DES, RC4, ECB mode
_weak_enc=$(_code_grep '\b(DES|RC4|RC2|Blowfish|ECB)\b|DES\.new|AES\.new\s*\([^)]*MODE_ECB|Cipher\.getInstance\s*\(\s*"DES' "*.py,*.js,*.ts,*.java")
[[ -n "$_weak_enc" ]] && _crypto_hits="${_crypto_hits}${_crypto_hits:+$'\n'}${_weak_enc}"

# Hardcoded IV/nonce
_hardcoded_iv=$(_code_grep '(iv|IV|nonce)\s*=\s*(b"[^"]+"|"[0-9a-f]{16,}"|\[0x)' "*.py,*.js,*.ts,*.go,*.java")
[[ -n "$_hardcoded_iv" ]] && _crypto_hits="${_crypto_hits}${_crypto_hits:+$'\n'}${_hardcoded_iv}"

_crypto_hits=$(echo "$_crypto_hits" | grep -v '^$' || true)

if [[ -n "$_crypto_hits" ]]; then
  _crypto_count=$(echo "$_crypto_hits" | grep -c . 2>/dev/null || true)
  _crypto_details="P1: Insecure Cryptography — ${_crypto_count} weak algorithm(s) / config(s)$(_format_hits "$_crypto_hits")"
  fail "CODE-SEC-001" "Insecure Crypto: ${_crypto_count} weak algorithm/config" "high" \
    "$_crypto_details" \
    "Use SHA-256+ for hashing, AES-GCM/ChaCha20 for encryption. Never use MD5/SHA1/DES/ECB (OWASP A02)"
else
  pass "CODE-SEC-001" "No insecure cryptography patterns detected"
fi

# ── CODE-SEC-002: Unsafe Deserialization (P0/Critical) — OWASP A08 ───────

_deser_hits=""

# Python: pickle, yaml.load (unsafe), marshal
[[ "${_has_python:-}" == "true" ]] && {
  _deser_hits=$(_code_grep '(pickle\.(loads?|Unpickler)|yaml\.load\s*\([^)]*(?!Loader)|yaml\.unsafe_load|marshal\.loads?|shelve\.open)\s*\(' "*.py")
  # yaml.load without SafeLoader
  _yaml_unsafe=$(_code_grep 'yaml\.load\s*\(' "*.py")
  _yaml_safe=$(_code_grep 'yaml\.load\s*\(.*Loader\s*=' "*.py")
  if [[ -n "$_yaml_unsafe" && -z "$_yaml_safe" ]]; then
    _deser_hits="${_deser_hits}${_deser_hits:+$'\n'}${_yaml_unsafe}"
  fi
}

# Java: ObjectInputStream, XMLDecoder
[[ "${_has_java:-}" == "true" ]] && {
  _java_deser=$(_code_grep '(ObjectInputStream|XMLDecoder|readObject\s*\(|readUnshared\s*\()' "*.java")
  [[ -n "$_java_deser" ]] && _deser_hits="${_deser_hits}${_deser_hits:+$'\n'}${_java_deser}"
}

# PHP: unserialize
[[ "${_has_php:-}" == "true" ]] && {
  _php_deser=$(_code_grep 'unserialize\s*\(' "*.php")
  [[ -n "$_php_deser" ]] && _deser_hits="${_deser_hits}${_deser_hits:+$'\n'}${_php_deser}"
}

# Ruby: Marshal.load, YAML.load
[[ "${_has_ruby:-}" == "true" ]] && {
  _rb_deser=$(_code_grep '(Marshal\.load|YAML\.load)\s*\(' "*.rb")
  [[ -n "$_rb_deser" ]] && _deser_hits="${_deser_hits}${_deser_hits:+$'\n'}${_rb_deser}"
}

# JavaScript: node-serialize, js-yaml (untrusted)
[[ "${_has_js:-}" == "true" || "${_has_ts:-}" == "true" ]] && {
  _js_deser=$(_code_grep '(serialize|node-serialize|js-yaml).*\.(unserialize|load)\s*\(' "*.js,*.ts")
  [[ -n "$_js_deser" ]] && _deser_hits="${_deser_hits}${_deser_hits:+$'\n'}${_js_deser}"
}

_deser_hits=$(echo "$_deser_hits" | grep -v '^$' || true)

if [[ -n "$_deser_hits" ]]; then
  _deser_count=$(echo "$_deser_hits" | grep -c . 2>/dev/null || true)
  _deser_details="P0: Unsafe Deserialization — ${_deser_count} dangerous deserializer(s)$(_format_hits "$_deser_hits")"
  fail "CODE-SEC-002" "Unsafe Deserialization: ${_deser_count} dangerous pattern(s)" "critical" \
    "$_deser_details" \
    "Never deserialize untrusted data. Use JSON/safe formats. Python: yaml.safe_load, avoid pickle on user data (OWASP A08)"
else
  pass "CODE-SEC-002" "No unsafe deserialization patterns detected"
fi

# ── CODE-SEC-003: Hardcoded Credentials in Code (P0/Critical) — OWASP A07 ──

_hc_hits=""
_hc_hits=$(_code_grep '(password|passwd|pwd|secret|token|api_key|apikey)\s*=\s*["\x27][^"\x27]{8,}["\x27]' "*.py,*.js,*.ts,*.go,*.java,*.rb,*.php,*.rs,*.cs" 20)

# Filter out obvious non-secrets (env lookups, empty, placeholder)
_hc_filtered=""
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  # Skip env lookups, os.getenv, process.env, os.Getenv, etc.
  echo "$line" | grep -qiE '(os\.getenv|os\.environ|process\.env|os\.Getenv|System\.getenv|ENV\[|getenv)' && continue
  # Skip config file reads, var assignments from function calls
  echo "$line" | grep -qiE '(config\.|settings\.|\.get\(|=\s*(None|null|undefined|""|'"''"'))' && continue
  # Skip test/mock files
  echo "$line" | grep -qiE '(test|spec|mock|fixture|example|sample)' && continue
  _hc_filtered="${_hc_filtered}${_hc_filtered:+$'\n'}${line}"
done <<< "$_hc_hits"

if [[ -n "$_hc_filtered" ]]; then
  _hc_count=$(echo "$_hc_filtered" | grep -c . 2>/dev/null || true)
  _hc_details="P0: Hardcoded Credentials — ${_hc_count} embedded secret(s)$(_format_hits "$_hc_filtered")"
  fail "CODE-SEC-003" "Hardcoded Credentials: ${_hc_count} embedded secret(s)" "critical" \
    "$_hc_details" \
    "Use environment variables or secrets managers. Never commit credentials to source code (OWASP A07)"
else
  pass "CODE-SEC-003" "No hardcoded credentials detected in code logic"
fi

# ── CODE-SEC-004: Insecure Random Number Generation (P1/High) — OWASP A02 ──

_rand_hits=""

# Python: random module for security-sensitive operations
[[ "${_has_python:-}" == "true" ]] && {
  _rand_hits=$(_code_grep 'random\.(randint|random|choice|randrange|sample)\s*\(' "*.py")
}

# JavaScript: Math.random for tokens/passwords
[[ "${_has_js:-}" == "true" || "${_has_ts:-}" == "true" ]] && {
  _js_rand=$(_code_grep 'Math\.random\s*\(\s*\)' "*.js,*.ts")
  [[ -n "$_js_rand" ]] && _rand_hits="${_rand_hits}${_rand_hits:+$'\n'}${_js_rand}"
}

# Go: math/rand without crypto/rand
[[ "${_has_go:-}" == "true" ]] && {
  _go_rand=$(_code_grep 'math/rand|rand\.Intn|rand\.Int\(' "*.go")
  [[ -n "$_go_rand" ]] && _rand_hits="${_rand_hits}${_rand_hits:+$'\n'}${_go_rand}"
}

# Java: java.util.Random (not SecureRandom)
[[ "${_has_java:-}" == "true" ]] && {
  _java_rand=$(_code_grep 'new Random\s*\(|java\.util\.Random' "*.java")
  [[ -n "$_java_rand" ]] && _rand_hits="${_rand_hits}${_rand_hits:+$'\n'}${_java_rand}"
}

_rand_hits=$(echo "$_rand_hits" | grep -v '^$' || true)

if [[ -n "$_rand_hits" ]]; then
  _rand_count=$(echo "$_rand_hits" | grep -c . 2>/dev/null || true)
  _rand_details="P1: Insecure Random — ${_rand_count} weak PRNG usage(s)$(_format_hits "$_rand_hits")"
  fail "CODE-SEC-004" "Insecure Random: ${_rand_count} non-CSPRNG usage(s)" "high" \
    "$_rand_details" \
    "Use secrets module (Python), crypto.getRandomValues (JS), crypto/rand (Go), SecureRandom (Java) for security (OWASP A02)"
else
  pass "CODE-SEC-004" "No insecure random number generation detected"
fi

# ── CODE-SEC-005: Debug/Development Mode in Production (P1/High) ─────────

_debug_hits=""

# Python: DEBUG=True, Flask debug
_debug_hits=$(_code_grep '(DEBUG\s*=\s*True|app\.debug\s*=\s*True|app\.run\(.*debug\s*=\s*True)' "*.py")

# JavaScript: NODE_ENV != production checks missing
_js_debug=$(_code_grep 'console\.(log|debug|trace)\s*\(.*password|console\.(log|debug)\s*\(.*secret|console\.(log|debug)\s*\(.*token' "*.js,*.ts")
[[ -n "$_js_debug" ]] && _debug_hits="${_debug_hits}${_debug_hits:+$'\n'}${_js_debug}"

# Java: verbose error output
_java_debug=$(_code_grep 'printStackTrace\s*\(\s*\)|e\.getMessage\s*\(\s*\).*response' "*.java")
[[ -n "$_java_debug" ]] && _debug_hits="${_debug_hits}${_debug_hits:+$'\n'}${_java_debug}"

# PHP: display_errors, error_reporting
[[ "${_has_php:-}" == "true" ]] && {
  _php_debug=$(_code_grep '(display_errors|error_reporting)\s*\(' "*.php")
  [[ -n "$_php_debug" ]] && _debug_hits="${_debug_hits}${_debug_hits:+$'\n'}${_php_debug}"
}

_debug_hits=$(echo "$_debug_hits" | grep -v '^$' || true)

if [[ -n "$_debug_hits" ]]; then
  _debug_count=$(echo "$_debug_hits" | grep -c . 2>/dev/null || true)
  _debug_details="P1: Debug/Dev Mode — ${_debug_count} debug configuration(s) found$(_format_hits "$_debug_hits")"
  fail "CODE-SEC-005" "Debug Mode: ${_debug_count} debug/verbose config(s)" "high" \
    "$_debug_details" \
    "Disable debug mode in production. Use environment-specific configuration (OWASP A05)"
else
  pass "CODE-SEC-005" "No debug mode configurations detected"
fi

# ── CODE-SEC-006: Error Information Leakage (Medium) — OWASP A04 ────────

_err_hits=""

# Stack traces, detailed error messages to client
_err_hits=$(_code_grep '(traceback\.format_exc|traceback\.print_exc)\s*\(' "*.py")

_js_err=$(_code_grep 'res\.(send|json)\s*\(.*err(or)?\.(message|stack)' "*.js,*.ts")
[[ -n "$_js_err" ]] && _err_hits="${_err_hits}${_err_hits:+$'\n'}${_js_err}"

# Go: returning raw error to client
_go_err=$(_code_grep '(http\.Error|w\.Write|json\.NewEncoder).*err\.(Error\(\)|String\(\))' "*.go")
[[ -n "$_go_err" ]] && _err_hits="${_err_hits}${_err_hits:+$'\n'}${_go_err}"

_err_hits=$(echo "$_err_hits" | grep -v '^$' || true)

if [[ -n "$_err_hits" ]]; then
  _err_count=$(echo "$_err_hits" | grep -c . 2>/dev/null || true)
  _err_details="Medium: Information Leakage — ${_err_count} verbose error response(s)$(_format_hits "$_err_hits")"
  warn "CODE-SEC-006" "Info Leak: ${_err_count} detailed error exposed to client" \
    "$_err_details"
else
  pass "CODE-SEC-006" "No error information leakage patterns detected"
fi

# ── CODE-SEC-007: Insecure File Upload (P1/High) — OWASP A04 ────────────

_upload_hits=""

# File upload without type/size validation
[[ "${_has_python:-}" == "true" ]] && {
  _upload_hits=$(_code_grep '(request\.files|FileUpload|UploadFile|save\()' "*.py")
}

[[ "${_has_js:-}" == "true" || "${_has_ts:-}" == "true" ]] && {
  _js_upload=$(_code_grep '(multer|formidable|busboy|req\.file)' "*.js,*.ts")
  [[ -n "$_js_upload" ]] && _upload_hits="${_upload_hits}${_upload_hits:+$'\n'}${_js_upload}"
}

[[ "${_has_php:-}" == "true" ]] && {
  _php_upload=$(_code_grep 'move_uploaded_file|tmp_name|\$_FILES' "*.php")
  [[ -n "$_php_upload" ]] && _upload_hits="${_upload_hits}${_upload_hits:+$'\n'}${_php_upload}"
}

_upload_hits=$(echo "$_upload_hits" | grep -v '^$' || true)

if [[ -n "$_upload_hits" ]]; then
  # Check if validation exists nearby
  _has_validation=$(_code_grep '(allowed_extensions|ALLOWED_EXTENSIONS|mime_type|content_type|fileFilter|file_size|maxFileSize)' "*.py,*.js,*.ts,*.php" 5)
  if [[ -z "$_has_validation" ]]; then
    _upload_count=$(echo "$_upload_hits" | grep -c . 2>/dev/null || true)
    _upload_details="P1: Insecure Upload — ${_upload_count} file upload handler(s) without visible validation$(_format_hits "$_upload_hits")"
    fail "CODE-SEC-007" "Insecure Upload: ${_upload_count} handler(s) without validation" "high" \
      "$_upload_details" \
      "Validate file type (magic bytes), size, and extension. Store outside webroot. Scan for malware (OWASP A04)"
  else
    pass "CODE-SEC-007" "File upload handlers found with validation present"
  fi
else
  skip "CODE-SEC-007" "File upload security" "No file upload patterns found"
fi

# ── CODE-SEC-008: Race Conditions (Medium) — CWE-362 ────────────────────

_race_hits=""

# Python: shared state without locks in threading context
[[ "${_has_python:-}" == "true" ]] && {
  _race_hits=$(_code_grep '(threading\.(Thread|Lock)|global\s+|multiprocessing)' "*.py")
}

# Go: goroutines with shared state (no mutex)
[[ "${_has_go:-}" == "true" ]] && {
  _go_race=$(_code_grep 'go func|go\s+[a-zA-Z]+\s*\(' "*.go")
  [[ -n "$_go_race" ]] && _race_hits="${_race_hits}${_race_hits:+$'\n'}${_go_race}"
}

# Java: shared mutable state
[[ "${_has_java:-}" == "true" ]] && {
  _java_race=$(_code_grep '(synchronized|AtomicInteger|volatile|ConcurrentHashMap|ThreadLocal)' "*.java")
  # If synchronization primitives present, it's likely handled
  if [[ -z "$_java_race" ]]; then
    _java_threads=$(_code_grep '(new Thread|ExecutorService|CompletableFuture|@Async)' "*.java")
    [[ -n "$_java_threads" ]] && _race_hits="${_race_hits}${_race_hits:+$'\n'}${_java_threads}"
  fi
}

_race_hits=$(echo "$_race_hits" | grep -v '^$' || true)

if [[ -n "$_race_hits" ]]; then
  _race_count=$(echo "$_race_hits" | grep -c . 2>/dev/null || true)
  _race_details="Medium: Concurrency — ${_race_count} concurrent code pattern(s). Verify thread safety.$(_format_hits "$_race_hits" 5)"
  warn "CODE-SEC-008" "Concurrency: ${_race_count} pattern(s) — verify thread safety" \
    "$_race_details"
else
  pass "CODE-SEC-008" "No obvious race condition patterns detected"
fi

# ── CODE-SEC-009: Prototype Pollution (P1/High) — JavaScript specific ────

if [[ "${_has_js:-}" == "true" || "${_has_ts:-}" == "true" ]]; then
  _proto_hits=""
  _proto_hits=$(_code_grep '(__proto__|constructor\[|Object\.assign\s*\(\s*\{\}|\.merge\s*\(|lodash\.merge|deepmerge|Object\.defineProperty)' "*.js,*.ts")

  if [[ -n "$_proto_hits" ]]; then
    _proto_count=$(echo "$_proto_hits" | grep -c . 2>/dev/null || true)
    _proto_details="P1: Prototype Pollution — ${_proto_count} risky pattern(s)$(_format_hits "$_proto_hits")"
    fail "CODE-SEC-009" "Prototype Pollution: ${_proto_count} risky merge/assign pattern(s)" "high" \
      "$_proto_details" \
      "Validate keys before merging. Use Object.create(null) or Map. Freeze prototypes (CWE-1321)"
  else
    pass "CODE-SEC-009" "No prototype pollution patterns detected"
  fi
else
  skip "CODE-SEC-009" "Prototype pollution" "No JavaScript/TypeScript code"
fi

# ── CODE-SEC-010: Open Redirect (P1/High) — OWASP A01 ───────────────────

_redir_hits=""

# Python: redirect with user input
[[ "${_has_python:-}" == "true" ]] && {
  _redir_hits=$(_code_grep '(redirect|HttpResponseRedirect)\s*\(.*request\.(GET|POST|args|form)' "*.py")
}

# JavaScript: res.redirect with user input
[[ "${_has_js:-}" == "true" || "${_has_ts:-}" == "true" ]] && {
  _js_redir=$(_code_grep 'res\.redirect\s*\(.*req\.(query|body|params)' "*.js,*.ts")
  [[ -n "$_js_redir" ]] && _redir_hits="${_redir_hits}${_redir_hits:+$'\n'}${_js_redir}"
}

# PHP: header Location with user input
[[ "${_has_php:-}" == "true" ]] && {
  _php_redir=$(_code_grep 'header\s*\(\s*"Location:.*\$_(GET|POST|REQUEST)' "*.php")
  [[ -n "$_php_redir" ]] && _redir_hits="${_redir_hits}${_redir_hits:+$'\n'}${_php_redir}"
}

# Java: sendRedirect with request param
[[ "${_has_java:-}" == "true" ]] && {
  _java_redir=$(_code_grep 'sendRedirect\s*\(.*request\.getParameter' "*.java")
  [[ -n "$_java_redir" ]] && _redir_hits="${_redir_hits}${_redir_hits:+$'\n'}${_java_redir}"
}

_redir_hits=$(echo "$_redir_hits" | grep -v '^$' || true)

if [[ -n "$_redir_hits" ]]; then
  _redir_count=$(echo "$_redir_hits" | grep -c . 2>/dev/null || true)
  _redir_details="P1: Open Redirect — ${_redir_count} unvalidated redirect(s)$(_format_hits "$_redir_hits")"
  fail "CODE-SEC-010" "Open Redirect: ${_redir_count} unvalidated redirect(s)" "high" \
    "$_redir_details" \
    "Validate redirect URLs against allowlist. Use relative paths or domain validation (OWASP A01)"
else
  pass "CODE-SEC-010" "No open redirect patterns detected"
fi
