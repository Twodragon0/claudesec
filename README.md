# ClaudeSec

> AI Security Best Practices toolkit for secure development with Claude Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard-green.svg)](https://scorecard.dev/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-orange.svg)](https://owasp.org/Top10/)

ClaudeSec integrates security best practices directly into your AI-powered development workflow. It provides security-focused prompts, hooks, templates, and guides designed for use with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and CI/CD pipelines.

## Why ClaudeSec?

AI coding assistants accelerate development — but speed without security creates risk. ClaudeSec bridges this gap:

- **Shift-left security**: Catch vulnerabilities before they reach production
- **AI-native guardrails**: Security hooks and prompts designed for Claude Code workflows
- **AI Security automation**: GitHub Actions, pre-commit hooks, and CI/CD templates
- **SaaS security scanning**: Datadog, Cloudflare, Vercel, ArgoCD, Sentry, Okta, SendGrid, and more
- **Supply chain integrity**: SLSA, SBOM, and artifact signing workflows
- **Compliance mapping**: SOC 2, ISO 27001, NIST, PCI-DSS, KISA ISMS-P, KISA 주요정보통신기반시설
- **Living documentation**: Actionable guides for OWASP Top 10, MITRE ATLAS, and more

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Twodragon0/claudesec.git
cd claudesec

# One-command setup into your project
bash scripts/setup.sh /path/to/your/project
```

Or manually:

```bash
# Install Claude Code security hooks
cp hooks/*.sh /path/to/your/project/.claude/hooks/

# Copy CI/CD templates
cp templates/*.yml /path/to/your/project/.github/workflows/
```

## Scanner CLI

ClaudeSec includes a zero-dependency bash scanner that checks your project for security best practices across 6 categories (~50 checks).

```bash
# Run all checks
./scanner/claudesec scan

# Scan specific categories
./scanner/claudesec scan --category cloud
./scanner/claudesec scan --category ai,cicd

# Filter by severity
./scanner/claudesec scan --severity high,critical

# Output formats
./scanner/claudesec scan --format json
./scanner/claudesec scan --format markdown

# With compliance mapping
./scanner/claudesec scan --compliance iso27001
./scanner/claudesec scan --compliance isms-p
```

### Scanner Categories

| Category | Checks | Covers |
|----------|--------|--------|
| `infra` | 16 | Docker, Kubernetes, IaC (Terraform/Helm) |
| `ai` | 9 | LLM API keys, prompt injection, RAG, agent tools |
| `network` | 5 | TLS, security headers, CORS, firewall rules |
| `cloud` | 13 | AWS, GCP, Azure (IAM, logging, storage, network) |
| `access-control` | 6 | .env files, password hashing, JWT, sessions |
| `cicd` | 8 | GHA permissions, SHA pinning, SAST, lockfiles |
| `macos` | 20 | FileVault, SIP, Gatekeeper, CIS Benchmark v4.0 |
| `windows` | 20 | KISA W-series, UAC, Firewall, Defender, SMBv1 |

## Project Structure

```
claudesec/
├── scanner/             # Security scanner CLI (bash, zero dependencies)
│   ├── claudesec        # Main CLI entry point
│   ├── lib/             # Output formatting, helper functions
│   └── checks/          # Check modules (infra, ai, network, cloud, cicd, access-control)
├── docs/
│   ├── devsecops/       # DevSecOps practices, OWASP, supply chain, cloud, K8s
│   ├── github/          # GitHub security features and workflows
│   ├── ai/              # AI/LLM security, MITRE ATLAS, prompt injection
│   ├── compliance/      # NIST CSF 2.0, ISO 27001/42001, KISA ISMS-P
│   └── guides/          # Getting started, compliance mapping
├── templates/           # GitHub Actions workflow templates
├── scripts/             # Security automation scripts
├── hooks/               # Claude Code security hooks
├── examples/            # Example configurations
└── .github/             # Issue templates, CI workflows
```

## Documentation

### DevSecOps

| Guide | Description |
|-------|-------------|
| [OWASP Top 10 2025](docs/devsecops/owasp-top10-2025.md) | All 10 categories with controls and code examples |
| [Supply Chain Security](docs/devsecops/supply-chain-security.md) | SLSA, SBOM, Sigstore, OpenSSF Scorecard |
| [Cloud Security Posture](docs/devsecops/cloud-security-posture.md) | CSPM with Prowler, multi-cloud checklist |
| [Kubernetes Security](docs/devsecops/kubernetes-security.md) | Pod security, RBAC, NetworkPolicy, runtime |
| [DevSecOps Pipeline](docs/devsecops/pipeline.md) | End-to-end secure CI/CD pipeline |
| [Audit Checklist](docs/devsecops/audit-checklist.md) | 80+ audit points for CI/CD, DB, server, K8s |
| [Security Maturity (SAMM)](docs/devsecops/security-maturity.md) | OWASP SAMM assessment and roadmap |
| [Threat Modeling](docs/devsecops/threat-modeling.md) | AI-assisted STRIDE threat modeling |
| [Security Champions](docs/devsecops/security-champions.md) | Building security culture at scale |
| [macOS CIS Security](docs/devsecops/macos-cis-security.md) | CIS Benchmark v4.0 hardening guide |

### AI Security

| Guide | Description |
|-------|-------------|
| [OWASP LLM Top 10 2025](docs/ai/llm-top10-2025.md) | LLM-specific risks including agentic AI |
| [MITRE ATLAS](docs/ai/mitre-atlas.md) | AI threat framework with 66 techniques |
| [Prompt Injection Defense](docs/ai/prompt-injection.md) | Multi-layer defense strategies |
| [AI Code Review](docs/ai/code-review.md) | OWASP-aligned AI-assisted security review |
| [LLM Security Checklist](docs/ai/llm-security-checklist.md) | Pre-deployment security checklist |

### GitHub Security

| Guide | Description |
|-------|-------------|
| [GitHub Security Features](docs/github/security-features.md) | Dependabot, CodeQL, secret scanning |
| [Branch Protection](docs/github/branch-protection.md) | Rulesets, CODEOWNERS, environment protection |
| [Actions Security](docs/github/actions-security.md) | Supply chain hardening for CI/CD |

### Compliance

| Guide | Description |
|-------|-------------|
| [NIST CSF 2.0](docs/compliance/nist-csf-2.md) | 6 functions including new Govern, SP 800-53 control families |
| [ISO 27001:2022](docs/compliance/iso27001-2022.md) | 93 controls in 4 themes, 11 new controls |
| [ISO 42001:2023](docs/compliance/iso42001-ai.md) | AI Management System (AIMS) with Annex A controls |
| [KISA ISMS-P](docs/compliance/isms-p.md) | 102 certification items for Korean compliance |
| KISA 주요정보통신기반시설 | Windows W-01~W-84, Unix U-01~U-72, PC-01~PC-19 (175 items) |

### Guides

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/guides/getting-started.md) | Quick setup guide |
| [Compliance Mapping](docs/guides/compliance-mapping.md) | SOC 2, ISO 27001, NIST, PCI-DSS, KISA ISMS-P |

## Templates

Ready-to-use GitHub Actions workflows:

| Template | Purpose |
|----------|---------|
| [codeql.yml](templates/codeql.yml) | CodeQL static analysis |
| [dependency-review.yml](templates/dependency-review.yml) | Block PRs with vulnerable deps |
| [prowler.yml](templates/prowler.yml) | Cloud security posture scan |
| [sbom.yml](templates/sbom.yml) | SBOM generation + vulnerability scan + signing |
| [scorecard.yml](templates/scorecard.yml) | OpenSSF Scorecard health check |
| [SECURITY.md](templates/SECURITY.md) | Security policy template |
| [dependabot.yml](templates/dependabot.yml) | Dependabot configuration |

## Hooks

Claude Code security hooks for real-time protection:

| Hook | Trigger | Purpose |
|------|---------|---------|
| [security-lint.sh](hooks/security-lint.sh) | PreToolUse (Write/Edit) | Blocks hardcoded secrets, injection patterns |
| [secret-check.sh](hooks/secret-check.sh) | Pre-commit | Prevents committing secrets |

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "command": "bash hooks/security-lint.sh"
      }
    ]
  }
}
```

See [hooks/README.md](hooks/README.md) for details.

## Security Coverage Map

```
                    ClaudeSec Coverage
┌──────────────────────────────────────────────────┐
│  PLAN          BUILD          TEST         DEPLOY │
│  ┌──────┐     ┌──────┐     ┌──────┐     ┌──────┐│
│  │Threat│     │Secret│     │SAST  │     │CSPM  ││
│  │Model │     │Scan  │     │DAST  │     │IaC   ││
│  │Design│     │SCA   │     │Pentest│    │K8s   ││
│  │Review│     │SBOM  │     │Fuzz  │     │Cloud ││
│  └──────┘     └──────┘     └──────┘     └──────┘│
│                                                   │
│  MONITOR       COMPLY        AI SAFETY            │
│  ┌──────┐     ┌──────┐     ┌──────┐              │
│  │Audit │     │SOC2  │     │LLM   │              │
│  │Alert │     │ISO   │     │ATLAS │              │
│  │SIEM  │     │NIST  │     │Agent │              │
│  │IR    │     │PCI   │     │RAG   │              │
│  └──────┘     └──────┘     └──────┘              │
└──────────────────────────────────────────────────┘
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas We Need Help

- Language-specific security guides (Python, Go, Rust, Java)
- Additional CI/CD integrations (GitLab CI, Azure DevOps)
- Real-world case studies and incident post-mortems
- Translations (i18n) — especially Korean, Japanese, Chinese
- Custom CodeQL queries and Semgrep rules
- Kubernetes admission policies (Kyverno/OPA)

## Acknowledgments

- Cloud security patterns from [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
- Audit framework informed by [querypie/audit-points](https://github.com/querypie/audit-points)
- Web security based on [OWASP Top 10 2025](https://github.com/OWASP/Top10/tree/master/2025)
- AI security guidance from [MITRE ATLAS](https://atlas.mitre.org/) and [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- Built for the [Claude Code](https://docs.anthropic.com/en/docs/claude-code) ecosystem

## License

MIT License — see [LICENSE](LICENSE) for details.
