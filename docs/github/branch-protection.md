---
title: Branch Protection & CODEOWNERS
description: Access control best practices for GitHub repositories
tags: [github, branch-protection, codeowners, access-control]
---

# Branch Protection & CODEOWNERS

## Branch Protection Rules

### Recommended Settings for `main`

**Settings → Branches → Add rule → Branch name pattern: `main`**

| Setting | Recommended | Why |
|---------|-------------|-----|
| Require PR before merging | Yes | No direct pushes to main |
| Required approvals | 2 (1 minimum) | Peer review enforcement |
| Dismiss stale reviews | Yes | Re-review after changes |
| Require review from CODEOWNERS | Yes | Domain experts must approve |
| Require status checks | Yes | CI must pass |
| Require branches be up to date | Yes | No merge conflicts |
| Require signed commits | Optional | Verify commit authorship |
| Require linear history | Recommended | Clean git history |
| Restrict force pushes | Yes | Prevent history rewriting |
| Restrict deletions | Yes | Prevent branch deletion |

### Rulesets (Recommended over branch protection)

GitHub Rulesets provide more granular control:

```json
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "rules": [
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true
      }
    },
    { "type": "required_status_checks",
      "parameters": {
        "required_status_checks": [
          { "context": "ci/tests" },
          { "context": "security/codeql" },
          { "context": "security/secrets" }
        ],
        "strict_required_status_checks_policy": true
      }
    },
    { "type": "non_fast_forward" }
  ]
}
```

## CODEOWNERS

### Setup

Create `.github/CODEOWNERS`:

```
# Default owners for everything
* @org/engineering-leads

# Security-sensitive files
SECURITY.md              @org/security-team
.github/workflows/       @org/devops @org/security-team
.github/CODEOWNERS       @org/engineering-leads

# Authentication and authorization
src/auth/                @org/security-team @org/backend
src/middleware/auth*      @org/security-team

# Infrastructure
terraform/               @org/devops @org/security-team
Dockerfile               @org/devops
docker-compose*.yml      @org/devops

# API definitions
openapi/                 @org/api-team
src/routes/              @org/backend @org/api-team

# Frontend
src/components/          @org/frontend
src/pages/               @org/frontend

# Database migrations
migrations/              @org/backend @org/dba
prisma/                  @org/backend @org/dba
```

### Best Practices

1. **Keep ownership granular** — avoid `* @everyone`
2. **Security files need security team** — auth, crypto, config
3. **Infrastructure needs DevOps** — Dockerfiles, CI, IaC
4. **Review CODEOWNERS quarterly** — remove departed members
5. **Use teams, not individuals** — resilient to personnel changes

## Environment Protection

For deployment environments:

**Settings → Environments → New environment**

| Environment | Reviewers | Wait timer | Branch policy |
|-------------|-----------|------------|---------------|
| staging | Auto-deploy | None | Any branch |
| production | @org/leads | 15 min | `main` only |

## References

- [GitHub Branch Protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [GitHub CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
