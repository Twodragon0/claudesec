---
title: Security Maturity Model (OWASP SAMM)
description: Measuring and improving software security maturity with OWASP SAMM
tags: [samm, maturity, governance, security-program, assessment]
---

# Security Maturity Model — OWASP SAMM

[OWASP SAMM v2.0](https://owaspsamm.org/) is the leading framework for assessing and improving an organization's software security posture. Technology-agnostic, it works with Agile, DevOps, and traditional methodologies.

## Model Structure

```
5 Business Functions
└── 15 Security Practices (3 per function)
    └── 30 Activity Streams (2 per practice)
        └── 3 Maturity Levels per stream (0–3)
```

---

## Business Functions & Security Practices

### 1. Governance

| Practice | Stream A | Stream B |
|----------|----------|----------|
| **Strategy & Metrics** | Create and promote | Measure and improve |
| **Policy & Compliance** | Policy management | Compliance management |
| **Education & Guidance** | Training | Organization guidance |

**Level 1 Example**: Security policy exists but not consistently enforced.
**Level 3 Example**: Metrics-driven security program with automated compliance checks.

### 2. Design

| Practice | Stream A | Stream B |
|----------|----------|----------|
| **Threat Assessment** | Application risk profile | Threat modeling |
| **Security Requirements** | Software requirements | Supplier security |
| **Security Architecture** | Architecture design | Technology management |

**Level 1 Example**: Ad-hoc threat modeling for some features.
**Level 3 Example**: Systematic threat modeling for all features, tracked in issue system.

### 3. Implementation

| Practice | Stream A | Stream B |
|----------|----------|----------|
| **Secure Build** | Build process | Software dependencies |
| **Secure Deployment** | Deployment process | Secret management |
| **Defect Management** | Defect tracking | Metrics and feedback |

**Level 1 Example**: Manual dependency checks, basic CI.
**Level 3 Example**: Automated SBOM, signed artifacts, SLSA Level 3.

### 4. Verification

| Practice | Stream A | Stream B |
|----------|----------|----------|
| **Architecture Assessment** | Architecture validation | Architecture mitigation |
| **Requirements Testing** | Control verification | Misuse/abuse testing |
| **Security Testing** | Scalable baseline | Deep understanding |

**Level 1 Example**: Automated SAST in CI pipeline.
**Level 3 Example**: SAST + DAST + IAST + manual pentest + fuzzing with coverage targets.

### 5. Operations

| Practice | Stream A | Stream B |
|----------|----------|----------|
| **Incident Management** | Detection | Response |
| **Environment Management** | Configuration hardening | Patching/updating |
| **Operational Management** | Data protection | System decomissioning |

**Level 1 Example**: Incident response plan exists but not tested.
**Level 3 Example**: Regular tabletop exercises, automated response playbooks, SLA on MTTR.

---

## Maturity Levels

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| **0** | Not practiced | No security activities |
| **1** | Initial | Ad hoc, basic awareness |
| **2** | Defined | Repeatable, documented processes |
| **3** | Optimized | Measured, automated, continuously improving |

---

## Self-Assessment Scorecard

Rate your organization (0–3) for each practice:

```
GOVERNANCE                          Score
├── Strategy & Metrics              [ /3]
├── Policy & Compliance             [ /3]
└── Education & Guidance            [ /3]

DESIGN
├── Threat Assessment               [ /3]
├── Security Requirements           [ /3]
└── Security Architecture           [ /3]

IMPLEMENTATION
├── Secure Build                    [ /3]
├── Secure Deployment               [ /3]
└── Defect Management               [ /3]

VERIFICATION
├── Architecture Assessment         [ /3]
├── Requirements Testing            [ /3]
└── Security Testing                [ /3]

OPERATIONS
├── Incident Management             [ /3]
├── Environment Management          [ /3]
└── Operational Management          [ /3]

OVERALL AVERAGE                     [ /3]
```

---

## Roadmap by Maturity Level

### Level 0 → 1 (Foundations)

| Priority | Activity | Tools |
|----------|----------|-------|
| 1 | Create security policy | OWASP Security Policy template |
| 2 | Enable automated dependency scanning | Dependabot, `npm audit` |
| 3 | Add SAST to CI pipeline | Semgrep (free tier) |
| 4 | Document incident response process | PagerDuty + runbook |
| 5 | Security awareness training (annual) | OWASP materials |

### Level 1 → 2 (Process)

| Priority | Activity | Tools |
|----------|----------|-------|
| 1 | Threat modeling for major features | STRIDE, Threat Dragon |
| 2 | SBOM generation and tracking | Syft, Dependency-Track |
| 3 | DAST in staging pipeline | OWASP ZAP |
| 4 | Security requirements in user stories | Jira templates |
| 5 | Security champions program | [Security Champions Guide](security-champions.md) |
| 6 | Incident response tabletop exercises | Quarterly cadence |
| 7 | Cloud security posture monitoring | Prowler, Checkov |

### Level 2 → 3 (Optimization)

| Priority | Activity | Tools |
|----------|----------|-------|
| 1 | Security metrics dashboard | Grafana, custom KPIs |
| 2 | Artifact signing and SLSA compliance | Cosign, SLSA generator |
| 3 | Automated compliance reporting | Prowler compliance reports |
| 4 | Red team exercises (annual) | External or internal team |
| 5 | Bug bounty program | HackerOne, Bugcrowd |
| 6 | Adversarial ML testing (if AI used) | MITRE ATLAS techniques |

---

## Key Metrics

| Metric | Level 1 Target | Level 2 Target | Level 3 Target |
|--------|---------------|---------------|---------------|
| MTTD (Mean Time to Detect) | < 7 days | < 24 hours | < 1 hour |
| MTTR (Mean Time to Remediate) | < 30 days | < 14 days | < 7 days |
| Critical vuln SLA | 30 days | 14 days | 7 days |
| Code coverage (security tests) | > 40% | > 70% | > 85% |
| Security training completion | > 50% | > 80% | > 95% |
| Threat models per quarter | 1+ | All major features | All features |
| Dependency scan frequency | Monthly | Weekly | Daily/per-PR |

---

## SAMM + Compliance Framework Mapping

| SAMM Practice | NIST SSDF | ISO 27001 | SOC 2 |
|---------------|-----------|-----------|-------|
| Strategy & Metrics | PO.1 | A.5 | CC1.1 |
| Policy & Compliance | PO.2 | A.5, A.18 | CC1.2 |
| Threat Assessment | PW.1 | A.14.1 | CC3.2 |
| Security Requirements | PW.1 | A.14.1 | CC6.1 |
| Secure Build | PW.4 | A.14.2 | CC8.1 |
| Secure Deployment | PW.9 | A.12.5 | CC7.1 |
| Security Testing | PW.6, PW.8 | A.14.2.8 | CC4.1 |
| Incident Management | RV.1, RV.3 | A.16 | CC7.3 |

## References

- [OWASP SAMM — owaspsamm.org](https://owaspsamm.org/)
- [OWASP SAMM Model](https://owaspsamm.org/model/)
- [NIST SSDF — SP 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [OWASP SAMM Assessment Tool](https://owaspsamm.org/assessment/)
- [NIST Paper on OWASP SAMM](https://www.nist.gov/document/cybersecurity-labeling-position-paper-owasp-samm)
