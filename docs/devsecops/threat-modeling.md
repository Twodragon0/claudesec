---
title: AI-Assisted Threat Modeling
description: Using AI tools to accelerate and improve threat modeling
tags: [threat-modeling, stride, ai, security-design]
---

# AI-Assisted Threat Modeling

## Why Threat Model?

Threat modeling identifies security risks early in the design phase — when fixes are cheapest. AI assistants can accelerate this process by generating threat scenarios, analyzing data flows, and suggesting mitigations.

## STRIDE Framework

| Category | Question | Example Threat |
|----------|----------|----------------|
| **S**poofing | Can an attacker impersonate a user/system? | Forged JWT tokens |
| **T**ampering | Can data be modified in transit/at rest? | Man-in-the-middle on API calls |
| **R**epudiation | Can actions be denied? | Missing audit logs |
| **I**nformation Disclosure | Can sensitive data leak? | Verbose error messages |
| **D**enial of Service | Can the system be overwhelmed? | Unrate-limited API endpoints |
| **E**levation of Privilege | Can a user gain unauthorized access? | IDOR vulnerabilities |

## AI-Assisted Workflow

### Step 1: System Description

Provide your AI assistant with a system description:

```
System: E-commerce API
Components:
- React frontend (CDN-hosted)
- Node.js API server
- PostgreSQL database
- Redis cache
- Stripe payment integration
- S3 file storage

Data flows:
- User → Frontend → API → Database
- API → Stripe (payment processing)
- API → S3 (file uploads)
```

### Step 2: Generate Threat Scenarios

Prompt your AI assistant:

```
Analyze this system using STRIDE. For each component and data flow,
identify potential threats, their severity (Critical/High/Medium/Low),
and recommended mitigations.
```

### Step 3: Data Flow Diagram (DFD)

```
┌──────────┐     HTTPS      ┌──────────┐      TLS       ┌──────────┐
│  Browser  │───────────────→│ API      │───────────────→│ Database │
│  (React)  │←───────────────│ Server   │←───────────────│ (PG)     │
└──────────┘                 └──────────┘                 └──────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    ↓             ↓              ↓
              ┌──────────┐ ┌──────────┐  ┌──────────┐
              │  Redis   │ │  Stripe  │  │   S3     │
              │  Cache   │ │  API     │  │  Storage │
              └──────────┘ └──────────┘  └──────────┘

Trust Boundaries:
─── Public Internet ─── │ ─── Internal Network ─── │ ─── Cloud Services ───
```

### Step 4: Prioritize and Track

Create a threat register:

```markdown
| ID | Threat | STRIDE | Severity | Component | Mitigation | Status |
|----|--------|--------|----------|-----------|------------|--------|
| T1 | SQL injection via search | Tampering | Critical | API → DB | Parameterized queries | Mitigated |
| T2 | Missing rate limiting | DoS | High | API Server | Rate limiter middleware | Open |
| T3 | SSRF via file upload URL | Spoofing | High | API → S3 | URL allowlist validation | Open |
```

## Claude Code Integration

Add a threat modeling hook to your project:

```bash
#!/bin/bash
# hooks/threat-model-check.sh
# Runs when new API endpoints or data models are created

FILE="$1"
if grep -qE "(app\.(get|post|put|delete|patch)|router\.|@(Get|Post|Put|Delete))" "$FILE"; then
  echo "⚠️  New API endpoint detected. Consider updating the threat model."
  echo "   Run: claude 'Analyze this endpoint for STRIDE threats'"
fi
```

## Tools

| Tool | Type | Use Case |
|------|------|----------|
| Microsoft Threat Modeling Tool | GUI | Visual DFD + STRIDE analysis |
| OWASP Threat Dragon | Web/Desktop | Open-source threat modeling |
| Threagile | CLI | Threat modeling as code (YAML) |
| IriusRisk | Platform | Automated threat modeling |

## References

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
