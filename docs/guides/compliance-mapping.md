---
title: Compliance Framework Mapping
description: Mapping ClaudeSec controls to SOC 2, ISO 27001, NIST, PCI-DSS, and KISA ISMS-P
tags: [compliance, soc2, iso27001, nist, pci-dss, kisa, isms-p]
---

# Compliance Framework Mapping

This guide maps ClaudeSec security controls to major compliance frameworks, helping you understand which controls satisfy which requirements.

## Framework Overview

| Framework | Scope | Mandatory? | Key Industries |
|-----------|-------|------------|---------------|
| **SOC 2** | Service organizations | Voluntary (client-driven) | SaaS, Cloud |
| **ISO 27001** | Information security management | Voluntary (certification) | Global enterprise |
| **NIST 800-53** | Federal information systems | Mandatory (US Gov) | Government, Defense |
| **NIST CSF** | Cybersecurity framework | Voluntary | All industries |
| **PCI-DSS** | Payment card data | Mandatory (if processing cards) | E-commerce, Finance |
| **GDPR** | EU personal data | Mandatory (EU) | Any org handling EU data |
| **HIPAA** | Health information | Mandatory (US healthcare) | Healthcare, Healthtech |
| **KISA ISMS-P** | Information security (Korea) | Mandatory (Korea, conditions) | Korean organizations |
| **CMMC 2.0 Level 2** | Controlled unclassified information (CUI) | Mandatory (US DoD contracts handling CUI) | Defense industrial base |

---

## Control-to-Framework Matrix

### Access Control

| ClaudeSec Control | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | KISA ISMS-P |
|-------------------|-------|-----------|-------------|---------|-------------|
| MFA enforcement | CC6.1 | A.9.4.2 | IA-2(1) | 8.3 | 2.5.3 |
| Least privilege RBAC | CC6.3 | A.9.2.3 | AC-6 | 7.1 | 2.5.1 |
| Access review (quarterly) | CC6.2 | A.9.2.5 | AC-2(3) | 7.1.2 | 2.5.4 |
| Session management | CC6.1 | A.9.4.2 | AC-12 | 8.1.8 | 2.5.5 |
| Privileged access management | CC6.1 | A.9.2.3 | AC-6(5) | 7.2 | 2.5.2 |

### Secure Development

| ClaudeSec Control | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | KISA ISMS-P |
|-------------------|-------|-----------|-------------|---------|-------------|
| SAST in CI/CD | CC8.1 | A.14.2.8 | SA-11 | 6.3.2 | 2.9.1 |
| DAST (staging) | CC8.1 | A.14.2.8 | SA-11(8) | 6.5 | 2.9.1 |
| Dependency scanning | CC8.1 | A.14.2.4 | SA-11 | 6.3 | 2.9.2 |
| Code review | CC8.1 | A.14.2.1 | SA-11 | 6.3.2 | 2.9.1 |
| Secret scanning | CC6.1 | A.14.2.5 | SA-11 | 6.5.3 | 2.9.3 |
| Threat modeling | CC3.2 | A.14.1.1 | RA-3 | 6.1 | 2.9.1 |

### Supply Chain

| ClaudeSec Control | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | KISA ISMS-P |
|-------------------|-------|-----------|-------------|---------|-------------|
| SBOM generation | CC3.2 | A.14.2.4 | SR-4 | 6.3.2 | 2.9.2 |
| Artifact signing | CC6.6 | A.14.2.5 | SA-12 | 6.3.2 | 2.9.3 |
| Dependency pinning | CC8.1 | A.14.2.4 | CM-2 | 6.3 | 2.9.2 |
| License compliance | CC1.1 | A.18.1 | — | — | 2.3.3 |

### Infrastructure

| ClaudeSec Control | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | KISA ISMS-P |
|-------------------|-------|-----------|-------------|---------|-------------|
| Cloud posture (CSPM) | CC7.1 | A.12.6 | CM-6 | 2.2 | 2.10.1 |
| Encryption at rest | CC6.1 | A.10.1 | SC-28 | 3.4 | 2.7.1 |
| Encryption in transit | CC6.1 | A.10.1 | SC-8 | 4.1 | 2.7.1 |
| Network segmentation | CC6.6 | A.13.1 | SC-7 | 1.3 | 2.6.2 |
| Container security | CC6.6 | A.12.6 | CM-7 | 2.2 | 2.10.2 |

### Monitoring & Incident Response

| ClaudeSec Control | SOC 2 | ISO 27001 | NIST 800-53 | PCI-DSS | KISA ISMS-P |
|-------------------|-------|-----------|-------------|---------|-------------|
| Security logging | CC7.2 | A.12.4 | AU-2, AU-3 | 10.1 | 2.11.1 |
| Log integrity | CC7.2 | A.12.4.3 | AU-10 | 10.5 | 2.11.2 |
| Real-time alerting | CC7.2 | A.12.4.1 | SI-4 | 10.6 | 2.11.3 |
| Incident response plan | CC7.3 | A.16.1 | IR-1, IR-4 | 12.10 | 2.12.1 |
| Log retention (90+ days) | CC7.2 | A.12.4.1 | AU-11 | 10.7 | 2.11.2 |

---

## What the Scanner Actually Renders for SOC 2

The tables above are the full control-design reference. The scanner's dashboard
renders a coarser, series-level view — the nine Common Criteria of the
[AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
(2017, revised 2022) — defined in `scanner/lib/compliance-map.py`.

| Series | Status source | Keyword signals |
|--------|---------------|-----------------|
| CC1 Control environment | **N/A** (governance) | — |
| CC2 Communication and information | **N/A** (governance) | — |
| CC3 Risk assessment | PASS/FAIL | vulnerability, dependency, dependabot, scan |
| CC4 Monitoring activities | PASS/FAIL | audit, monitoring, scan |
| CC5 Control activities | PASS/FAIL | configuration, misconfigur, hardening, default |
| CC6 Logical and physical access controls | PASS/FAIL | mfa, two_factor, sso, authentication, rbac, branch_protection, encrypt, secret |
| CC7 System operations | PASS/FAIL | logging, incident, detection, alert, anomaly |
| CC8 Change management | PASS/FAIL | code_scanning, codeql, sast, require_approval, branch_protection |
| CC9 Risk mitigation | **N/A** (vendor/BCP program) | — |

**Why CC1, CC2, and CC9 render N/A.** These are the COSO-derived governance
criteria: control environment, communication of security responsibilities, and
vendor/business-continuity risk mitigation. They are assessed from board
minutes, training records, contracts, and DPAs — evidence no scanner can
produce. Reporting them PASS merely because no finding matched would be false
assurance, so `map_compliance()` reports them `N/A` and excludes them from the
pass/fail totals. The same rule already governs ISO 27001 A.5.1 and the KISA
ISMS-P 3.x privacy controls.

**SOC 2 is keyword-driven, not Prowler-native.** Prowler tags almost every AWS
check with a SOC 2 requirement, and ClaudeSec's native-compliance match is
framework-level rather than control-level — one native hit would mark all nine
series FAIL. The framework is therefore registered as `SOC 2 (TSC)`, which does
not substring-match Prowler's bare `SOC2` key, keeping per-criterion signal
intact. Renaming it would silently change that behavior; a regression test pins
it.

---

## CMMC 2.0 Level 2 domain coverage

CMMC 2.0 Level 2's 110 practices are NIST SP 800-171 Rev. 2's requirements
verbatim ([NIST SP 800-171 Rev. 2][sp800-171], incorporated by the CMMC program
rule at 32 CFR Part 170), so ClaudeSec maps the framework from
Prowler's `nist_800_171_revision_2_aws.json` rather than a CMMC-specific file.
Controls are rendered per **domain** (800-171 requirement family), not per
practice: Prowler's file carries 50 of the 110 requirements, so a
practice-level table would be 60 rows of "no data".

Measured against the pinned Prowler 5.30.1 file — 50 requirements, 49 with
checks, 87 distinct checks:

| Domain | 800-171 family | Mapped checks |
|--------|----------------|---------------|
| SC — System and Communications Protection | 3.13 | 50 |
| AC — Access Control | 3.1 | 43 |
| AU — Audit and Accountability | 3.3 | 21 |
| CM — Configuration Management | 3.4 | 21 |
| IA — Identification and Authentication | 3.5 | 21 |
| IR — Incident Response | 3.6 | 14 |
| SI — System and Information Integrity | 3.14 | 13 |
| CA — Security Assessment | 3.12 | 9 |
| RA — Risk Assessment | 3.11 | 3 |
| AT, MA, MP, PE, PS | 3.2, 3.7, 3.8, 3.9, 3.10 | **none** |

**These controls carry no keywords, deliberately.** Every other framework in
`COMPLIANCE_CONTROL_MAP` falls back to substring matching when Prowler ships no
mapping. CMMC does not: a prototype keyword set built from the vocabulary of the
target checks themselves measured 34.2% coverage (CM 1/22, SI 1/13), so keywords
here would manufacture wrong answers rather than approximate right ones. The
controls are tagged `native_only`, and a `native_only` control with no Prowler
mapping reports **N/A** (`match_source: "unmapped"`) instead of taking the
`count == 0 → PASS` default — a domain that was never evaluated must not read as
compliant. That is why AT/MA/MP/PE/PS are always N/A today.

**Coverage limit: AWS only.** Prowler ships 800-171 for AWS and no other
provider, and the mapping is read from the installed Prowler package rather
than from the scan — so on a Kubernetes-only run it stays fully populated with
AWS check ids, matches nothing, and would otherwise score all nine mapped
domains PASS on zero evidence. The framework is therefore scoped to the `aws`
provider: a run that did not scan AWS reports **every** domain N/A, and the
dashboard states the limit under the framework heading.

The same false-PASS exists today for **NIST 800-53 Rev5**, which is also
AWS-only in Prowler. It is left unscoped for now because changing it is a
separate, separately-measured behaviour change.

[sp800-171]: https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final

---

## AI-Specific Compliance

### NIST AI RMF + EU AI Act

| AI Security Control | NIST AI RMF Function | EU AI Act Article |
|---------------------|---------------------|-------------------|
| AI risk assessment | MAP 1.1 | Art. 9 |
| Training data governance | MAP 2.1 | Art. 10 |
| Model testing & evaluation | MEASURE 2.1 | Art. 9(7) |
| AI transparency/explainability | MANAGE 3.1 | Art. 13 |
| Human oversight | GOVERN 1.1 | Art. 14 |
| AI incident reporting | MANAGE 4.1 | Art. 62 |

---

## Implementation Priority by Framework

### SOC 2 Fast Track (3 months)

```
Month 1: Access control + logging (CC6, CC7)
├── MFA enforcement
├── RBAC implementation
├── Security logging
└── Incident response plan

Month 2: Development security (CC8)
├── SAST/DAST in CI
├── Dependency scanning
├── Code review process
└── Secret scanning

Month 3: Monitoring + evidence (CC7, CC3)
├── Real-time alerting
├── Vulnerability management
├── Risk assessment
└── Evidence collection automation
```

### ISO 27001 Roadmap (6 months)

```
Phase 1 (Month 1-2): ISMS Foundation
├── Security policy (A.5)
├── Risk assessment methodology (A.6)
├── Asset inventory (A.8)

Phase 2 (Month 3-4): Technical Controls
├── Access control (A.9)
├── Cryptography (A.10)
├── Network security (A.13)
├── Secure development (A.14)

Phase 3 (Month 5-6): Operations
├── Incident management (A.16)
├── Business continuity (A.17)
├── Compliance audit (A.18)
├── Internal audit preparation
```

---

## Tools for Compliance Automation

| Tool | Compliance Coverage | Type |
|------|-------------------|------|
| **Prowler** | CIS, SOC 2, ISO 27001, PCI-DSS, HIPAA, KISA ISMS-P | Open source |
| **Drata** | SOC 2, ISO 27001, HIPAA, GDPR, PCI-DSS | Commercial |
| **Vanta** | SOC 2, ISO 27001, HIPAA | Commercial |
| **OpenSSF Scorecard** | Supply chain best practices | Open source |
| **Checkov** | CIS benchmarks for IaC | Open source |

## References

- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [ISO 27001:2022 Controls](https://www.iso.org/standard/27001)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/document_library/)
- [KISA ISMS-P](https://isms.kisa.or.kr/)
- [NIST AI RMF](https://www.nist.gov/artificial-intelligence)
- [EU AI Act](https://artificialintelligenceact.eu/)
