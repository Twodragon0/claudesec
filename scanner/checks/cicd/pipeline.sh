#!/usr/bin/env bash
# ClaudeSec — CI/CD: Pipeline Security Checks

# CICD-001: GitHub Actions — permissions restricted
if has_dir ".github/workflows"; then
  if workflows_contain "permissions:"; then
    pass "CICD-001" "GitHub Actions workflows define permissions"
  else
    fail "CICD-001" "GitHub Actions workflows missing permissions block" "high" \
      "Without explicit permissions, workflows get broad default access" \
      "Add 'permissions: { contents: read }' to each workflow"
  fi

  # CICD-002: Actions pinned to SHA
  if workflows_contain "uses:.*@[a-f0-9]{40}"; then
    pass "CICD-002" "Some GitHub Actions pinned to SHA"
  elif workflows_contain "uses:.*@v[0-9]"; then
    warn "CICD-002" "GitHub Actions pinned to version tags, not SHA" \
      "Pin to full SHA for supply chain security (e.g., actions/checkout@b4ffde65...)"
  else
    skip "CICD-002" "Actions pinning" "No action references found"
  fi

  # CICD-003: No secrets in workflow logs
  if workflows_contain 'echo.*\$\{\{ secrets\.'; then
    fail "CICD-003" "Possible secret exposure in workflow logs" "critical" \
      "Echoing secrets can expose them in build logs" \
      "Never echo or print secrets. Use them only as env vars."
  else
    pass "CICD-003" "No obvious secret logging in workflows"
  fi

  # CICD-004: Dependency review action
  if workflows_contain "dependency-review-action"; then
    pass "CICD-004" "Dependency review action configured"
  else
    warn "CICD-004" "No dependency review action in CI" \
      "Add actions/dependency-review-action to block vulnerable dependencies"
  fi

  # CICD-005: SAST/Security scanning in CI
  if workflows_contain "(codeql|semgrep|sonar|snyk|trivy|gitleaks|pip-audit|npm.audit|shellcheck)"; then
    pass "CICD-005" "Security scanning (SAST/SCA) configured in CI"
  else
    fail "CICD-005" "No security scanning in CI pipeline" "high" \
      "No SAST or SCA tools detected in GitHub Actions" \
      "Add CodeQL, Semgrep, or Trivy to your CI pipeline"
  fi

  # CICD-006: Script injection prevention
  #
  # SINGLE QUOTES ARE LOAD-BEARING. Written in double quotes, bash consumes the
  # backslash before `$` and hands grep a bare `$` — an end-of-line anchor — so
  # a pattern needing characters after it matches NOTHING, ever. That made the
  # `fail` branch below unreachable code and this check report PASS on the very
  # construct it exists to find. CICD-003 above has always used single quotes.
  if workflows_contain '\$\{\{ github\.event\.(issue|pull_request|comment)'; then
    if workflows_contain 'run:.*\$\{\{ github\.event'; then
      fail "CICD-006" "Potential script injection in GitHub Actions" "high" \
        "User-controlled event data used directly in run: steps" \
        "Use environment variables instead of direct interpolation"
    else
      pass "CICD-006" "Event data handled safely in workflows"
    fi
  else
    pass "CICD-006" "No user-controlled event data in workflows"
  fi
else
  skip "CICD-001" "GHA permissions" "No GitHub Actions workflows found"
  skip "CICD-002" "GHA SHA pinning" "No GitHub Actions workflows found"
  skip "CICD-003" "GHA secret logging" "No GitHub Actions workflows found"
  skip "CICD-004" "Dependency review" "No GitHub Actions workflows found"
  skip "CICD-005" "Security scanning" "No GitHub Actions workflows found"
  skip "CICD-006" "Script injection" "No GitHub Actions workflows found"
fi

# CICD-007: Lockfile exists
if has_file "package-lock.json" || has_file "yarn.lock" || has_file "pnpm-lock.yaml" || \
   has_file "poetry.lock" || has_file "Pipfile.lock" || has_file "go.sum" || \
   has_file "Cargo.lock" || has_file "Gemfile.lock"; then
  pass "CICD-007" "Dependency lock file exists"
elif has_file "package.json" || has_file "pyproject.toml" || has_file "go.mod" || \
     has_file "Cargo.toml" || has_file "Gemfile"; then
  fail "CICD-007" "Missing dependency lock file" "high" \
    "Without a lock file, builds are not reproducible" \
    "Generate a lock file (npm install, poetry lock, etc.)"
else
  skip "CICD-007" "Lock file" "No package manager detected"
fi

# CICD-008: Branch protection (GitHub)
if is_git_repo; then
  remote_url=$(git_remote_url)
  if [[ "$remote_url" == *"github.com"* ]]; then
    if has_file ".github/CODEOWNERS"; then
      pass "CICD-008" "CODEOWNERS file exists"
    else
      warn "CICD-008" "No CODEOWNERS file" \
        "Add .github/CODEOWNERS to require reviews from domain experts"
    fi
  else
    skip "CICD-008" "CODEOWNERS" "Not a GitHub repository"
  fi
else
  skip "CICD-008" "CODEOWNERS" "Not a git repository"
fi
