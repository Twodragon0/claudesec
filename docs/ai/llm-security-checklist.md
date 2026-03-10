---
title: LLM Security Checklist
description: Security considerations for applications using Large Language Models
tags: [llm, security, checklist, owasp]
---

# LLM Security Checklist

Based on the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## Pre-Deployment Checklist

### LLM01: Prompt Injection

- [ ] System prompts separated from user input with clear delimiters
- [ ] Input sanitization for known injection patterns
- [ ] Output validation before acting on LLM responses
- [ ] Canary tokens in system prompts to detect leaks
- [ ] Tool/function permissions follow least privilege
- [ ] Rate limiting on LLM API calls

### LLM02: Insecure Output Handling

- [ ] LLM output treated as untrusted (never `eval()` or raw SQL)
- [ ] HTML output sanitized before rendering (XSS prevention)
- [ ] Structured output validated against schema
- [ ] Error messages from LLM don't expose internals
- [ ] Output length limits enforced

### LLM03: Training Data Poisoning

- [ ] Training data sources vetted and documented
- [ ] Fine-tuning data reviewed for malicious content
- [ ] Model provenance tracked (who trained, when, on what)
- [ ] Regular evaluation against adversarial test sets

### LLM04: Model Denial of Service

- [ ] Request rate limiting per user/IP
- [ ] Token limits on input and output
- [ ] Timeout on LLM API calls
- [ ] Queue management for concurrent requests
- [ ] Cost monitoring and alerts

### LLM05: Supply Chain Vulnerabilities

- [ ] Models downloaded from trusted sources only
- [ ] Model checksums verified
- [ ] Dependencies pinned and audited
- [ ] No untrusted plugins or extensions
- [ ] SBOM generated for AI components

### LLM06: Sensitive Information Disclosure

- [ ] PII filtering on LLM inputs and outputs
- [ ] System prompts don't contain secrets
- [ ] Training data scrubbed of sensitive information
- [ ] Data retention policies for LLM interactions
- [ ] Logging excludes sensitive content

### LLM07: Insecure Plugin Design

- [ ] Plugins require authentication
- [ ] Plugin inputs validated and sanitized
- [ ] Plugin permissions are minimal (least privilege)
- [ ] Plugin actions are logged and auditable
- [ ] Sensitive operations require user confirmation

### LLM08: Excessive Agency

- [ ] LLM actions bounded by clear permissions
- [ ] High-impact actions require human approval
- [ ] Action audit trail maintained
- [ ] Rollback capability for LLM-initiated changes
- [ ] Session isolation between users

### LLM09: Overreliance

- [ ] Users informed they're interacting with AI
- [ ] AI-generated content marked/labeled
- [ ] Critical decisions require human verification
- [ ] Confidence scores displayed when available
- [ ] Fallback to human support available

### LLM10: Model Theft

- [ ] API keys rotated regularly
- [ ] Access controls on model endpoints
- [ ] Query rate monitoring for extraction attempts
- [ ] Watermarking on model outputs (if applicable)
- [ ] Usage analytics for anomaly detection

## Architecture Security

```
┌─────────────────────────────────────────────────┐
│                 Application Layer                │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Input    │  │  Output  │  │   Action     │  │
│  │  Guard    │→ │  Guard   │→ │   Guard      │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│       ↓              ↓              ↓           │
│  Sanitize      Validate       Approve/Deny     │
│  Rate-limit    Filter PII     Audit log        │
│  Schema-check  Schema-check   Human-in-loop    │
├─────────────────────────────────────────────────┤
│                    LLM Layer                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  System   │  │  Model   │  │   Tool       │  │
│  │  Prompt   │  │  Config  │  │   Registry   │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
├─────────────────────────────────────────────────┤
│                 Infrastructure                   │
│  Encryption │ Auth │ Logging │ Monitoring       │
└─────────────────────────────────────────────────┘
```

## Monitoring

| Signal | Tool | Alert Threshold |
|--------|------|-----------------|
| API cost spike | Cloud billing | >2x daily average |
| Error rate | APM | >5% of requests |
| Latency | APM | >10s p99 |
| Token usage | LLM dashboard | >90% of budget |
| Prompt injection attempts | WAF/custom | Any detection |
| PII in outputs | DLP | Any detection |

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI 600-1 — AI Risk Management](https://csrc.nist.gov/pubs/ai/600/1/final)
- [MITRE ATLAS — AI Threat Framework](https://atlas.mitre.org/)
