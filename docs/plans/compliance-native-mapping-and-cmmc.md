---
title: Compliance mapping — adopt Prowler's native requirement→check data, and add CMMC 2.0 on top of it
description: Measurement showing the hand-written keyword map reproduces 41.5% of Prowler's own KISA mapping, and the plan to add CMMC 2.0 Level 2 without repeating it
tags: [compliance, cmmc, nist-800-171, prowler, planning]
---

# Compliance mapping: stop guessing, read the mapping we already ship

## The finding that changes the plan

The task was "add CMMC 2.0 Level 2 as an 8th framework, designing keywords against
the Prowler corpus from the start". Measuring the corpus first produced a different
conclusion: **Prowler ships a native, authoritative requirement→check mapping for
every framework `COMPLIANCE_CONTROL_MAP` hand-writes**, and the hand-written
keyword heuristics reproduce it poorly.

Measured 2026-08-14 against Prowler 5.38 (1550 checks with metadata):

| what Prowler ships | file |
|---|---|
| SOC 2 | `compliance/{aws,azure,gcp}/soc2_*.json` |
| ISO 27001:2013 / :2022 | `iso27001_2013_aws.json`, `iso27001_2022_{aws,azure}.json` |
| PCI-DSS 3.2.1 / 4.0 | `pci_{3.2.1,4.0}_*.json` |
| NIST 800-53 rev4 / rev5 | `nist_800_53_revision_{4,5}_aws.json` |
| CIS (per provider, per version) | `cis_*_{aws,azure,gcp,kubernetes,...}.json` |
| **KISA ISMS-P 2023** | **`kisa_isms_p_2023_aws.json`** (+ a Korean-language variant) |
| **NIST 800-171 rev2** | **`nist_800_171_revision_2_aws.json`** |

### How far off the hand-written map is

`kisa_isms_p_2023_aws.json` carries **101 requirements mapped to 562 checks**. The
repo hand-maps 42 KISA ISMS-P controls, of which only **16 share a control id** with
Prowler's. On those 16, the repo's keywords reproduce **237 of 571 mappings —
41.5%**.

| control | repo keywords | reproduced |
|---|---|---|
| 2.9.4 백업·복구 | `backup, recovery, snapshot, restore` | **0 / 58** |
| 2.10.8 악성코드 | `malware, antivirus, sentinelone` | **0 / 14** |
| 2.6.3 세션·토큰 | `token, session, application, oauth` | **0 / 2** |
| 2.6.2 인증 | `mfa, authentication, _sso, two_factor` | 4 / 64 (6%) |
| 2.10.1 네트워크 | `firewall, security_group, antivirus` | 9 / 89 (10%) |
| 2.9.3 로깅 | `logging, audit, log_maxage, cloudtrail` | 9 / 24 (38%) |

2.9.4 scoring 0/58 is the clearest case: the keywords are the *right words*
(`backup`, `snapshot`, `restore`) and Prowler's 58 backup checks are the *right
checks* — they simply do not share literal substrings, because Prowler maps by
intent and the map matches by text.

### Why keywords structurally cannot close this

One check belongs to many requirements. `apigateway_restapi_logging_enabled` is
mapped by Prowler to 800-171 §3.1 (Access Control), §3.3 (Audit), §3.6 (Incident
Response) **and** §3.14 (System Integrity) simultaneously. A substring rule assigns
a check to whichever controls happen to share vocabulary with it — a different
function entirely.

This is the same root cause behind every miss rate measured in this cycle:
SOC 2 CC3 78%, CC4 75%, CC5 72%; KISA vulnerability-management 68.5%, logging 42.6%.
And behind the false-positive classes: `sso` inside "associated", `sast` inside
"disaster", `change` at 97.5% wrong, `edr` at 100% wrong. Every one is a symptom of
approximating a semantic mapping with text matching.

## Plan

### Phase 1 — load Prowler's mapping as a data source (prerequisite for CMMC)

Add a loader that reads `compliance/<provider>/<framework>.json` from the Prowler
installation already present in the scanner image, and resolves
`requirement id → [check ids]`. A finding then belongs to a control when its
`event_code` is in that control's check list — exact, not substring.

Keep the keyword map as the **fallback** for two cases it is genuinely needed for:
GitHub-provider findings (Prowler ships no `soc2_github.json` — this is why SOC 2
CC8 measures 100% miss against the SOC 2 corpus while matching 8/10 real GitHub
checks) and any framework Prowler does not ship.

Success criterion, measured the same way as above: reproduce ≥95% of Prowler's own
mapping for KISA ISMS-P and SOC 2, versus 41.5% today.

### Phase 2 — CMMC 2.0 Level 2 on that foundation

**Status: landed.** `CMMC 2.0 Level 2` is registered in `FRAMEWORK_SOURCES` and
renders 14 domain controls, all `native_only` with empty keyword lists. Two
corrections to what is written below, both from re-measuring against the pinned
Prowler **5.30.1** rather than the 5.38 used for the original survey:

- Prowler writes 800-171 requirement ids with **underscores** (`3_13_5`), not
  the dotted form the standard prints. The normalizer accepts both.
- 5.30.1 carries 50 requirements / 49 with checks / **87** distinct checks, and
  the per-family counts differ slightly: SC 50 (not 52), IA 21 (not 25), CM 21
  (not 22), AU 21, AC 43, IR 14, SI 13, CA 9, RA 3. The nine-domain shape and
  the five empty domains (AT/MA/MP/PE/PS) are unchanged.

The "do not hand-write keywords" instruction was followed literally: a
`native_only` control skips the keyword branch entirely and reports N/A
(`match_source: "unmapped"`) when Prowler ships no mapping, rather than falling
through to the `count == 0 → PASS` default. The AWS-only caveat is rendered in
the dashboard under the framework heading.

CMMC 2.0 Level 2's 110 practices are drawn directly from NIST SP 800-171, so
`nist_800_171_revision_2_aws.json` is the mapping basis. It carries 50 requirements
over 94 distinct checks, grouped by 800-171 family:

| 800-171 | CMMC domain | checks |
|---|---|---|
| 3.1 | AC — Access Control | 43 |
| 3.13 | SC — System & Communications Protection | 52 |
| 3.5 | IA — Identification & Authentication | 25 |
| 3.4 | CM — Configuration Management | 22 |
| 3.3 | AU — Audit & Accountability | 21 |
| 3.6 | IR — Incident Response | 14 |
| 3.14 | SI — System & Information Integrity | 13 |
| 3.12 | CA — Security Assessment | 9 |
| 3.11 | RA — Risk Assessment | 3 |

**Do not hand-write keywords for these.** A prototype keyword set built from
vocabulary actually present in each family was measured at **34.2% coverage**
(3.4 Configuration Management: 1/22; 3.14 System Integrity: 1/13). That is the
ceiling this approach reaches even when the vocabulary is drawn from the target
checks themselves.

Coverage caveat to state in the docs: Prowler ships 800-171 for **AWS only**. Azure
and GCP estates get no CMMC coverage from this source, and the dashboard must say
so rather than render an empty domain as passing — the same rule already applied to
non-assessable controls.

### Phase 3 — retire what measurement made unnecessary

Once Phase 1 lands, most of `COMPLIANCE_CONTROL_MAP`'s keyword lists become dead
weight, and with them the guard machinery built to police them
(`test_ci_compliance_keyword_guard.py`'s `BENIGN_WORDS` curation, the
`NEVER_EMITTED_TOKENS` set, the over-broad-whole-word pins). Retire them
deliberately and with measurement, not by deletion.

## What this plan does not claim

- The 41.5%, 34.2% and per-family numbers are measured. The ≥95% Phase 1 success
  criterion is a target, not a measurement.
- Prowler's own mapping is treated as ground truth here. It is authoritative for
  "which check evidences which requirement", but it is still one vendor's
  judgement, and it double-maps freely (one check to four families). Adopting it
  means adopting that judgement.
- No estimate of implementation effort is given, because the loader's shape depends
  on how the scanner image exposes the Prowler package, which has not been checked.
