---
title: NIST Cybersecurity Framework 2.0
description: Complete guide to NIST CSF 2.0 with the new Govern function
tags: [nist, csf, compliance, governance, risk-management]
---

# NIST Cybersecurity Framework 2.0

Released February 2024, NIST CSF 2.0 is the first major update since 2014. The biggest change: a new **Govern** function that makes cybersecurity governance a first-class requirement.

## CSF 2.0 vs CSF 1.1

| Change | CSF 1.1 (2018) | CSF 2.0 (2024) |
|--------|---------------|----------------|
| Functions | 5 (ID, PR, DE, RS, RC) | 6 (+**Govern**) |
| Scope | Critical infrastructure | **All organizations** |
| Supply chain | Limited mention | Full supply chain risk category |
| Profiles | Current/Target | Enhanced community profiles |
| Tiers | Implementation tiers | Refined with governance context |
| AI/Cloud | Not addressed | Included in guidance |

## The 6 Functions

```
        ┌──────────────────────────┐
        │        GOVERN (GV)       │
        │  Policy, Risk Strategy,  │
        │  Roles, Supply Chain     │
        └────────────┬─────────────┘
                     │
    ┌────────┬───────┴───────┬────────┐
    ▼        ▼               ▼        ▼
┌────────┐ ┌────────┐ ┌──────────┐ ┌────────┐
│IDENTIFY│ │PROTECT │ │ DETECT   │ │RESPOND │
│  (ID)  │ │  (PR)  │ │   (DE)   │ │  (RS)  │
└────────┘ └────────┘ └──────────┘ └────────┘
                                       │
                                   ┌───┴────┐
                                   │RECOVER │
                                   │  (RC)  │
                                   └────────┘
```

### GV — Govern (NEW)

Establishes cybersecurity as an enterprise-level risk alongside financial, reputation, and operational risks.

| Category | ID | Description |
|----------|-----|-------------|
| Organizational Context | GV.OC | Understand mission, stakeholder expectations, legal requirements |
| Risk Management Strategy | GV.RM | Define risk appetite, tolerance, and strategy |
| Roles & Responsibilities | GV.RR | Establish accountability for cybersecurity |
| Policy | GV.PO | Create, communicate, and enforce cybersecurity policies |
| Oversight | GV.OV | Board/executive oversight of cybersecurity risk |
| Supply Chain Risk Mgmt | GV.SC | Manage supply chain cybersecurity risk |

### ID — Identify

| Category | ID | Description |
|----------|-----|-------------|
| Asset Management | ID.AM | Inventory all hardware, software, data, systems |
| Risk Assessment | ID.RA | Identify threats, vulnerabilities, likelihood, impact |
| Improvement | ID.IM | Use assessments to improve cybersecurity posture |

### PR — Protect

| Category | ID | Description |
|----------|-----|-------------|
| Identity Mgmt & Access Control | PR.AA | Manage identities, credentials, access |
| Awareness & Training | PR.AT | Security training for all personnel |
| Data Security | PR.DS | Data protected in transit and at rest |
| Platform Security | PR.PS | Hardware, software, services managed securely |
| Technology Infrastructure Resilience | PR.IR | Resilience through redundancy, segmentation |

### DE — Detect

| Category | ID | Description |
|----------|-----|-------------|
| Continuous Monitoring | DE.CM | Monitor for cybersecurity events |
| Adverse Event Analysis | DE.AE | Analyze events for potential incidents |

### RS — Respond

| Category | ID | Description |
|----------|-----|-------------|
| Incident Management | RS.MA | Manage incident response process |
| Incident Analysis | RS.AN | Investigate and understand incidents |
| Incident Response Reporting | RS.CO | Coordinate response with stakeholders |
| Incident Mitigation | RS.MI | Contain and mitigate incidents |

### RC — Recover

| Category | ID | Description |
|----------|-----|-------------|
| Incident Recovery Plan Execution | RC.RP | Execute recovery plans |
| Incident Recovery Communication | RC.CO | Coordinate recovery communications |

---

## NIST SP 800-53 Rev 5 — Key Control Families

For organizations needing prescriptive controls (vs. CSF's outcome-based approach):

| Family | Code | Controls | Key Examples |
|--------|------|----------|-------------|
| Access Control | AC | 25 | AC-2 (Account Mgmt), AC-6 (Least Privilege) |
| Audit & Accountability | AU | 16 | AU-2 (Event Logging), AU-6 (Audit Review) |
| Configuration Mgmt | CM | 14 | CM-2 (Baseline Config), CM-7 (Least Functionality) |
| Identification & Auth | IA | 12 | IA-2 (User ID & Auth), IA-5 (Authenticator Mgmt) |
| Incident Response | IR | 10 | IR-4 (Incident Handling), IR-6 (Incident Reporting) |
| Risk Assessment | RA | 7 | RA-3 (Risk Assessment), RA-5 (Vuln Scanning) |
| System & Comms Protection | SC | 44 | SC-7 (Boundary Protection), SC-8 (Transmission Confidentiality) |
| System & Info Integrity | SI | 20 | SI-2 (Flaw Remediation), SI-4 (System Monitoring) |
| Supply Chain Risk Mgmt | SR | 12 | SR-3 (Supply Chain Controls), SR-4 (Provenance) |

---

## Implementation with ClaudeSec

| CSF Function | ClaudeSec Tools |
|-------------|-----------------|
| **Govern** | [Compliance Mapping](../guides/compliance-mapping.md), [Security Maturity](../devsecops/security-maturity.md) |
| **Identify** | `claudesec scan --all` (asset discovery) |
| **Protect** | [Hooks](../../hooks/), [Access Control Checks](../../scanner/checks/access-control/) |
| **Detect** | [Cloud Security Posture](../devsecops/cloud-security-posture.md), Prowler |
| **Respond** | [Audit Checklist](../devsecops/audit-checklist.md) (LOG section) |
| **Recover** | Incident playbook templates |

## References

- [NIST CSF 2.0 Official](https://www.nist.gov/cyberframework)
- [NIST CSF 2.0 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [NIST AI RMF](https://www.nist.gov/artificial-intelligence)
