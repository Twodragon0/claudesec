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

Since [#451] SOC 2 reads Prowler's own `soc2_{aws,azure,gcp}.json`
requirement→check data, so a series with a reachable native mapping is decided
by **exact check-id membership**, not by its keyword list. CC1, CC2 and CC9 are
decided by neither — they are tagged `assessable: False` and report N/A
whatever the source says (see below).

Native check counts are measured at the pinned Prowler 5.30.1. Keyword lists
are copied from `COMPLIANCE_CONTROL_MAP` and pinned against it by
`scanner/tests/test_ci_compliance_doc_table.py`, because this table has rotted
twice: it published `sso` and `vulnerability` after #447/#452 narrowed them to
`_sso`/`vulnerab`, and `default` on CC5 after CI started rejecting it outright.

| Series | Status source | Native checks | Keyword fallback |
|--------|---------------|---------------|------------------|
| CC1 Control environment | **N/A** (governance) | 30 | `security_policy`, `governance` |
| CC2 Communication and information | **N/A** (governance) | 23 | `awareness`, `training` |
| CC3 Risk assessment | PASS/FAIL | 55 | `vulnerab`, `dependency`, `dependabot`, `scan`, `cve` |
| CC4 Monitoring activities | PASS/FAIL | 28 | `audit`, `monitoring`, `scan`, `guardduty`, `securityhub`, `config_recorder` |
| CC5 Control activities | PASS/FAIL | 29 | `configuration`, `misconfigur`, `hardening`, `benchmark` |
| CC6 Logical and physical access controls | PASS/FAIL | 136 | `mfa`, `two_factor`, `_sso`, `authentication`, `rbac`, `encrypt`, `secret`, `public_access`, `publicly`, `0.0.0.0`, `security_group`, `securitygroup`, `ingress`, `unrestricted` |
| CC7 System operations | PASS/FAIL | 113 | `logging`, `incident`, `detection`, `alert`, `anomaly`, `cloudtrail`, `flow_log`, `log_file_validation` |
| CC8 Change management | PASS/FAIL | 15 | `branch_protection`, `_approval`, `codeowners`, `status_checks`, `force_push`, `signed_commits`, `code_scanning` |
| CC9 Risk mitigation | **N/A** (vendor/BCP program) | 1 (gcp only) | `governance`, `third_party` |

The keyword column is not dead: a series falls back to it whenever no check in
its native list belongs to a provider the run actually scanned (see
[Native provider scope](#native-provider-scope)). An AWS-only scan measures
`8 exact / 1 keyword` — the one is CC9, whose single native check
(`gemini_api_disabled`) exists only in `soc2_gcp.json`. The dashboard's
**Evidence source** line reports that split per framework.

[#451]: https://github.com/Twodragon0/claudesec/pull/451

**Why CC1, CC2, and CC9 render N/A.** These are the COSO-derived governance
criteria: control environment, communication of security responsibilities, and
vendor/business-continuity risk mitigation. An auditor assesses them from board
minutes, training records, contracts, and DPAs. They are tagged
`assessable: False`, so `map_compliance()` reports them `N/A` whatever the
evidence says and excludes them from the pass/fail totals. The same rule governs
ISO 27001 A.5.1 and the KISA ISMS-P 3.x privacy controls.

Note what that now suppresses. Before #451 these criteria had no native mapping,
so the case being avoided was a **vacuous PASS** — a control reported compliant
merely because no keyword happened to match. That is no longer the case: Prowler
maps 30 checks to CC1 and 23 to CC2, and they match real findings. Measured on
an AWS run with two genuine FAIL findings:

```text
CC1  N/A  prowler  count=1     # entra_non_privileged_user_has_mfa
CC2  N/A  prowler  count=1     # cloudtrail_multi_region_enabled
```

So an exact-mapped **FAIL** is what the tag now drops from the totals, not an
unevidenced pass. The count is still recorded and the findings still render, so
the signal is visible rather than lost — but "no automated test method exists"
is a weaker claim for CC1/CC2 than it is for, say, KISA's PII controls, and
Prowler evidently disagrees with it. Revisiting that classification is a policy
question this guide does not settle.

**Why the framework is named `SOC 2 (TSC)` and not `SOC2`.** Two different
mechanisms read Prowler data, and only one of them is the requirement→check
mapping above:

- `prowler_native_map.load_framework()` reads the **compliance file** Prowler
  ships and matches a control by exact check id. This is per control, and it is
  what decides SOC 2 today.
- `_match_prowler_compliance()` reads the **compliance tags on the finding
  itself** (`unmapped.compliance`, whose key is literally `SOC2`) and is
  **framework-level**: one hit marks every control it is consulted for. Prowler
  tags 160 of its 605 AWS checks with a SOC 2 requirement (26%), so a framework
  named `SOC2` would substring-match that tag and pin every affected series to
  FAIL on a single finding.

The spaced, parenthesised name does not substring-match `SOC2`, which keeps the
per-criterion signal intact. That still matters even though SOC 2 is natively
mapped, because `_match_prowler_compliance()` runs only on the **keyword** path
— so the load-bearing case is a run that reaches **none** of aws/azure/gcp and
sends every series there. Measured on a Kubernetes-only run with one
SOC2-tagged finding:

| Framework key | CC3 | CC4 | CC5 | CC6 | CC7 | CC8 |
|---------------|-----|-----|-----|-----|-----|-----|
| `SOC 2 (TSC)` | PASS | FAIL | PASS | PASS | PASS | PASS |
| `SOC2` | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |

Five of the six assessable series flip on one finding. (CC9 is *not* the
example to use: it is `assessable: False`, so it reads N/A either way — only
its `match_source` label changes.) Renaming the framework would silently flip
this; `test_compliance_map.py::TestMatchProwlerCompliance` pins it.

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
provider, so a run that did not scan AWS reports **every** CMMC domain N/A and
the dashboard states the limit under the framework heading. This is one case of
the general rule in [Native provider scope](#native-provider-scope) below.

[sp800-171]: https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final

---

## Native provider scope

The native mapping is read from the **installed Prowler package**, not from the
scan. Prowler ships each framework for some providers and not others, so a
mapping is populated whenever Prowler is installed — including on a run that
scanned none of those providers. Every natively-mapped control then matches
zero findings and takes the `count == 0 → PASS` default.

Provider coverage at the pinned Prowler 5.30.1:

| Framework | Providers Prowler ships it for |
|-----------|-------------------------------|
| ISO 27001:2022 | aws, azure, gcp, kubernetes, m365, nhn |
| PCI-DSS v4.0.1 | aws, azure, gcp, kubernetes |
| SOC 2 (TSC) | aws, azure, gcp |
| KISA ISMS-P | aws |
| NIST 800-53 Rev5 | aws |
| CMMC 2.0 Level 2 (800-171) | aws |

Measured on a Kubernetes-only scan, with 62 real Kubernetes check ids from
Prowler's own `pci_4.0_kubernetes.json` and `iso27001_2022_kubernetes.json`
supplied as FAIL findings:

| Framework | Before scoping | After scoping |
|-----------|----------------|---------------|
| NIST 800-53 Rev5 | **10 pass / 0 fail** (all `prowler`) | 5 pass / 5 fail (all `keyword`) |
| SOC 2 (TSC) | **6 pass / 0 fail** (all `prowler`) | 3 pass / 3 fail (all `keyword`) |
| KISA ISMS-P | 20 pass / 7 fail (16 controls on `prowler`) | 9 pass / 18 fail |
| PCI-DSS v4.0.1 | 0 pass / 7 fail | totals unchanged — Prowler ships a k8s file |
| ISO 27001:2022 | 3 pass / 3 fail | totals unchanged, but one more control moves to `keyword` (see below) |

NIST 800-53 and SOC 2 were reporting a perfect score on an estate whose
evidence they could never read. Five NIST failures, three SOC 2 failures, and
eleven KISA failures were hidden.

**The gate is per control, not per framework.** The loader *merges* every
provider file into one check set per control, so "ISO ships for kubernetes" can
be true while an individual control's checks are all AWS. A framework-level
scope would leave that case wide open, and it is not hypothetical — it reaches
the flagship provider. Measured at 5.30.1, of the repo's seven ISO controls:

| ISO control | Evidenced by |
|-------------|--------------|
| A.8.2 | aws, azure, gcp, kubernetes, m365, nhn |
| A.5.1 | aws, azure, gcp, kubernetes, m365 |
| A.8.5 | aws, azure, kubernetes, m365 |
| A.8.24 | aws, azure, gcp, kubernetes |
| A.8.9 | aws, azure, gcp, nhn |
| **A.8.8** | **m365 only** |
| A.8.28 | *(no native mapping — keywords)* |

So on an **AWS** run, `A.8.8` used to report `PASS` from Prowler's exact
mapping while every check backing it belongs to m365. It now reports `keyword`.
On a Kubernetes run, `A.8.9` is gated the same way.

**The scope is derived, not declared.** It is built in the same pass, from the
same parsed content, as the mapping it scopes: a provider is recorded for a
control only once one of its requirements survived the merge. Deriving it from
filenames instead would let a file that exists but contributes nothing widen
the scope past the evidence. A hand-written list — the shape #455 used for CMMC
alone — would have to be revised on every Prowler release, and the table above
shows it would have been incomplete from the day it was written.

**Gating never invents an N/A.** A gated control falls back to its existing
behaviour: keyword-bearing controls return to keywords, and `native_only`
controls (CMMC's) report N/A. A GitHub-only run is out of scope for every
framework — the only file under Prowler's `compliance/github/` is
`cis_1.0_github.json`, and CIS is deliberately not registered as a native
source — so it keeps the keyword path, which is the case that path exists for.

**The dashboard says which path a framework took.** Each framework renders an
*Evidence source* line counting its controls by provenance — `exact` (Prowler's
requirement→check mapping), `keyword` (approximation, no reachable native
mapping for this run), `not assessed` (N/A). Gating that nothing displays is
gating an operator cannot audit, and the keyword path reproduces only 41.5% of
Prowler's own mapping where both have an opinion.

**Known limitation, not addressed by the scope.** On a *mixed* run (e.g. AWS +
GitHub), a control whose native providers include AWS keeps its native mapping,
and GitHub findings can never match an AWS check id — so they stay invisible to
that control. Restoring them means matching per finding rather than gating per
control, which is a separate change.

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
