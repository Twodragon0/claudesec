#!/usr/bin/env bash
# ClaudeSec — Access Control: IAM & Authentication Checks

# IAM-001: Environment files not in repository
if is_git_repo; then
  tracked_env=$(git -C "$SCAN_DIR" ls-files '*.env' '.env*' 2>/dev/null | grep -v ".env.example" | head -5 || true)
  if [[ -n "$tracked_env" ]]; then
    fail "IAM-001" ".env file tracked in git" "critical" \
      "Files: $tracked_env" \
      "Add .env to .gitignore and remove from tracking with 'git rm --cached'"
  else
    pass "IAM-001" "No .env files tracked in git"
  fi
else
  skip "IAM-001" "Env file tracking" "Not a git repository"
fi

# IAM-002: .gitignore includes sensitive patterns
if has_file ".gitignore"; then
  missing_patterns=""
  required_patterns=(".env" "*.pem" "*.key" "credentials" "*.secret")
  required_regexes=("\\.env" "\\*\\.pem" "\\*\\.key" "credentials" "\\*\\.secret")
  for idx in "${!required_patterns[@]}"; do
    pattern="${required_patterns[$idx]}"
    regex="${required_regexes[$idx]}"
    if ! file_contains ".gitignore" "$regex"; then
      missing_patterns="$missing_patterns $pattern"
    fi
  done
  if [[ -z "$missing_patterns" ]]; then
    pass "IAM-002" ".gitignore covers sensitive file patterns"
  else
    warn "IAM-002" ".gitignore missing patterns:$missing_patterns" \
      "Add these patterns to prevent accidental commits"
  fi
else
  fail "IAM-002" "No .gitignore file" "medium" \
    "Without .gitignore, sensitive files may be committed" \
    "Create .gitignore with entries for .env, *.pem, *.key, credentials"
fi

# IAM-003: Password hashing uses strong algorithm
if files_contain "*.ts" "(bcrypt|argon2|scrypt)" 2>/dev/null || \
   files_contain "*.js" "(bcrypt|argon2|scrypt)" 2>/dev/null || \
   files_contain "*.py" "(bcrypt|argon2|scrypt|pbkdf2)" 2>/dev/null; then
  pass "IAM-003" "Strong password hashing algorithm detected"
elif files_contain "*.ts" "md5|sha1|sha256" 2>/dev/null || \
     files_contain "*.js" "md5|sha1|sha256" 2>/dev/null || \
     files_contain "*.py" "(hashlib\.md5|hashlib\.sha1)" 2>/dev/null; then
  fail "IAM-003" "Weak hashing algorithm used for passwords" "high" \
    "MD5/SHA1/SHA256 are not suitable for password hashing" \
    "Use bcrypt, argon2id, or scrypt for password hashing"
else
  skip "IAM-003" "Password hashing" "No password hashing patterns found"
fi

# IAM-004: JWT secret strength
if files_contain "*.ts" "jwt|jsonwebtoken|jose" 2>/dev/null || \
   files_contain "*.js" "jwt|jsonwebtoken|jose" 2>/dev/null || \
   files_contain "*.py" "jwt|pyjwt|python-jose" 2>/dev/null; then
  if files_contain "*.ts" "secret.*=.*['\"][^'\"]{1,16}['\"]" 2>/dev/null || \
     files_contain "*.js" "secret.*=.*['\"][^'\"]{1,16}['\"]" 2>/dev/null; then
    warn "IAM-004" "JWT secret may be too short or hardcoded" \
      "Use 256+ bit keys from environment variables"
  else
    pass "IAM-004" "JWT configuration appears reasonable"
  fi
else
  skip "IAM-004" "JWT security" "No JWT usage detected"
fi

# IAM-005: Session security
if files_contain "*.ts" "session|cookie" 2>/dev/null || \
   files_contain "*.js" "session|cookie" 2>/dev/null; then
  if files_contain "*.ts" "httpOnly.*true|secure.*true" 2>/dev/null || \
     files_contain "*.js" "httpOnly.*true|secure.*true" 2>/dev/null; then
    pass "IAM-005" "Secure cookie flags detected"
  else
    warn "IAM-005" "Cookie security flags may not be set" \
      "Set httpOnly: true, secure: true, sameSite: 'strict' on session cookies"
  fi
else
  skip "IAM-005" "Session security" "No session/cookie patterns found"
fi

# IAM-006: SECURITY.md exists
if has_file "SECURITY.md" || has_file ".github/SECURITY.md"; then
  pass "IAM-006" "Security policy (SECURITY.md) exists"
else
  fail "IAM-006" "No SECURITY.md found" "medium" \
    "Projects should have a security vulnerability disclosure policy" \
    "Create SECURITY.md — see templates/SECURITY.md"
fi
