# Contributing to ClaudeSec

Thank you for your interest in contributing to ClaudeSec! This project aims to make security accessible and integrated into AI-assisted development workflows.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/Twodragon0/claudesec/issues) to report bugs or suggest features
- Check existing issues before creating a new one
- Use the provided issue templates
- New contributors: look for issues labeled **`good first issue`** for smaller, guided tasks (see [.github/LABELS.md](.github/LABELS.md) for recommended labels and setup)

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feat/your-feature`
3. **Make changes** following our conventions below
4. **Test** your changes locally
   - Docs change checklist (required):
     - `markdownlint "**/*.md"`
     - `lychee "**/*.md"`
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature or guide
   - `fix:` correction to existing content
   - `docs:` documentation improvements
   - `chore:` maintenance tasks
6. **Push** and open a **Pull Request**

### Do not commit (개인정보·회사정보·민감정보 금지)

- **Company or internal paths**: Real folder paths (e.g. `~/Desktop/...`, internal drive paths) must not appear in the repo. Use placeholders like `~/.kube/config`, `/path/to/kubeconfig`, or `</path/to/your/config>` in examples and templates.
- **Personal or identifying data (개인정보)**: No real names, emails, internal hostnames, **IP addresses**, **account IDs**, or org/company names in examples or configs.
- **Local config with secrets/paths**: `.claudesec.yml` is gitignored; do not add it to the repo. Users copy from `templates/*.example.yml` and fill in paths locally only.
- **Secrets and credentials**: No API keys, passwords, tokens, or kubeconfig contents. Use env vars or local-only files listed in `.gitignore`.

### Conventions

### GitHub Actions and Dependabot Operations

- Keep CodeQL in **default setup mode only**. Do not add additional repo-level CodeQL workflow files unless migration is explicitly planned.
- If an action fails to download with `401 (Unauthorized)`, rerun the failed workflow up to **2 times** before manual triage.
- If Dependabot action update PRs conflict with current `main`, apply the required action-version update directly to `main`, then close duplicate/conflicting Dependabot PRs with an explanation comment.

#### File Naming

- Use kebab-case: `threat-modeling.md`, not `ThreatModeling.md`
- Group related files in appropriate directories

#### Markdown Style

- Use ATX headers (`#`, `##`, `###`)
- Include a YAML frontmatter block with `title`, `description`, and `tags`
- Add a table of contents for documents longer than 3 sections
- Use fenced code blocks with language identifiers

#### Content Guidelines

- Be actionable: provide commands, configs, and examples
- Reference official sources (OWASP, NIST, CIS)
- Include "Why" context before "How" instructions
- Keep guides self-contained when possible

### What We're Looking For

| Priority | Area | Description |
|----------|------|-------------|
| High | Security guides | OWASP, SAST/DAST, supply chain |
| High | Claude Code hooks | Pre/post tool-use security checks |
| Medium | CI/CD templates | GitHub Actions, GitLab CI |
| Medium | Language guides | Language-specific security |
| Low | Translations | i18n support |

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/); see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the full text and enforcement.

## Questions?

Open a [Discussion](https://github.com/Twodragon0/claudesec/discussions) or reach out via Issues.
