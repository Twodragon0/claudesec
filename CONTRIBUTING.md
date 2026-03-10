# Contributing to ClaudeSec

Thank you for your interest in contributing to ClaudeSec! This project aims to make security accessible and integrated into AI-assisted development workflows.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/Twodragon0/claudesec/issues) to report bugs or suggest features
- Check existing issues before creating a new one
- Use the provided issue templates

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feat/your-feature`
3. **Make changes** following our conventions below
4. **Test** your changes locally
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature or guide
   - `fix:` correction to existing content
   - `docs:` documentation improvements
   - `chore:` maintenance tasks
6. **Push** and open a **Pull Request**

### Conventions

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

Be respectful, constructive, and inclusive. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## Questions?

Open a [Discussion](https://github.com/Twodragon0/claudesec/discussions) or reach out via Issues.
