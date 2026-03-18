---
description: Review current code changes for security issues before commit
---
Review the current git changes for security issues:

1. Run `git diff --cached` (staged) and `git diff` (unstaged) to see all changes

2. Check each changed file for:
   - Hardcoded secrets, API keys, tokens
   - SQL injection, XSS, command injection
   - Insecure crypto (MD5, SHA1, DES)
   - Missing input validation
   - Unsafe deserialization
   - OWASP Top 10 vulnerabilities

3. Run ClaudeSec scan on changed files only:
   `./scanner/claudesec scan -d . -c code -s high`

4. Provide a summary:
   - Files reviewed
   - Issues found (with severity)
   - Recommended fixes
   - Whether it's safe to commit

5. If no issues found, confirm "✅ Security review passed — safe to commit"
