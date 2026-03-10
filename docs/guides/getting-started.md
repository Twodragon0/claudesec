---
title: Getting Started with ClaudeSec
description: Quick start guide for integrating ClaudeSec into your project
tags: [getting-started, setup, quickstart]
---

# Getting Started with ClaudeSec

## Prerequisites

- Git
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI installed
- A project repository to secure

## Step 1: Clone ClaudeSec

```bash
git clone https://github.com/your-username/claudesec.git
cd claudesec
```

## Step 2: Install Security Hooks

Copy the Claude Code hooks to your project:

```bash
# From your project directory
cp /path/to/claudesec/hooks/security-lint.sh .claude/hooks/
cp /path/to/claudesec/hooks/secret-check.sh .claude/hooks/

# Add hook configuration to your .claude/settings.json
cat <<'EOF' >> .claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "bash .claude/hooks/security-lint.sh"
      }
    ]
  }
}
EOF
```

## Step 3: Add GitHub Workflows

```bash
cp /path/to/claudesec/templates/codeql.yml .github/workflows/
cp /path/to/claudesec/templates/dependency-review.yml .github/workflows/
```

## Step 4: Add Security Policy

```bash
cp /path/to/claudesec/templates/SECURITY.md .github/
```

## Step 5: Configure Dependabot

```bash
cp /path/to/claudesec/templates/dependabot.yml .github/
```

## What's Next?

1. Read the [DevSecOps Pipeline Guide](../devsecops/pipeline.md) for full CI/CD security
2. Set up [Branch Protection](../github/branch-protection.md) for your repository
3. Review the [LLM Security Checklist](../ai/llm-security-checklist.md) if using AI features
4. Start a [Threat Modeling](../devsecops/threat-modeling.md) session for your application

## Common Use Cases

| I want to... | Guide |
|---------------|-------|
| Secure my CI/CD pipeline | [Pipeline Guide](../devsecops/pipeline.md) |
| Set up code scanning | [GitHub Security Features](../github/security-features.md) |
| Review code for security | [AI Code Review](../ai/code-review.md) |
| Protect against prompt injection | [Prompt Injection Defense](../ai/prompt-injection.md) |
| Build a security culture | [Security Champions](../devsecops/security-champions.md) |
