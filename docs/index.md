---
layout: default
title: ClaudeSec — DevSecOps 통합 보안 대시보드
description: AI 보조 보안 개발 도구킷. 보안 스캐너 · ISMS-P PDCA 대시보드 · 자산 관리 · 컴플라이언스 자동화. KakaoTalk·Slack·SNS 링크 공유 미리보기 지원.
tags: [claudesec, devsecops, security, isms-p, pdca, dashboard, documentation]
image:
  path: /assets/claudesec-logo.png
  height: 768
  width: 1376
  alt: ClaudeSec DevSecOps 통합 보안 대시보드 로고
---

# ClaudeSec Documentation

DevSecOps toolkit for AI-assisted secure development.

## Quick Start

```bash
npx claudesec scan            # Scan current directory
npx claudesec dashboard       # Full scan + dashboard
```

## Sections

| Section | Description |
|---------|-------------|
| [Getting Started](guides/getting-started.md) | Installation, first scan, dashboard setup |
| [DevSecOps](devsecops/pipeline.md) | CI/CD pipeline, supply chain, threat modeling |
| [AI Security](ai/llm-security-checklist.md) | LLM Top 10, MITRE ATLAS, prompt injection |
| [Compliance](compliance/isms-p.md) | ISMS-P, ISO 27001, NIST CSF, ISO 42001 |
| [Architecture](architecture/) | System diagrams, scan flow, security domains |
| [GitHub Security](github/security-features.md) | Actions security, branch protection, CodeQL |

## Features

- 40+ security checks across code, CI/CD, IAM, infrastructure, cloud, AI/LLM, SaaS
- Prowler CSPM: AWS, Kubernetes, GitHub, IaC
- ISMS asset management dashboard (9 tabs)
- Claude Code slash commands: `/scan`, `/dashboard`, `/audit`
- Docker one-command setup
- npm package with SLSA provenance

## Links

- [npm package](https://www.npmjs.com/package/claudesec)
- [GitHub Repository](https://github.com/Twodragon0/claudesec)
- [Security Policy](https://github.com/Twodragon0/claudesec/security/policy)
- [Issues](https://github.com/Twodragon0/claudesec/issues)
