---
title: "ADR-001: CI Guard Hardening Discipline & Periodic Adversarial Audit"
description: Two-pass adversarial review for substring/parse CI guards, shared comment-stripping primitives, and a periodic comprehensive audit cadence
tags: [adr, ci-cd, supply-chain, devsecops, testing]
---

# ADR-001: CI Guard Hardening Discipline & Periodic Adversarial Audit

- **Status:** Accepted
- **Date:** 2026-06-24
- **Context owners:** ClaudeSec maintainers

## Context

ClaudeSec protects its CI security/quality gates with stdlib-only `pytest`
"config regression guards" under `scanner/tests/test_ci_*.py` (catalogued in
[CI Config Regression Guards](./ci-config-regression-guards.md)). These guards
read workflow YAML / shell / Dockerfiles as **text** (no PyYAML in the CI test
job) and assert each invariant — coverage floors, action SHA pinning, the
`Security Scan Gate` severity block, branch-protection desired-state, the
Dependabot fork guard, npm provenance — still holds.

Because they are text/substring/regex matchers, they share a recurring
**false-negative class**: a protected token can survive only in a `#` comment
(or in a YAML form the parser does not recognise) while the real control is
removed, leaving the guard **green**. This is the supply-chain flow-control risk
class **OWASP CICD-SEC-1 (Insufficient Flow Control)** and the integrity
expectations of **NIST SSDF (SP 800-218) PO.3 / PW.4**. A guard that silently
fails to fire gives the reviewer false assurance — worse than no guard.

Two independent lines of evidence over recent work showed this is not
hypothetical:

1. **The injection-surface guard (`test_ci_injection_surface.py`, #270).** A
   first adversarial review found a CRITICAL evasion (`run: |2-` block-scalar
   header parsed as an inline command, body unscanned); a **second** review then
   found *another* CRITICAL (`run: | # comment` trailing-comment header). Both
   were in the same block-scalar-header parsing — fixed structurally by a
   grammar-complete rule (a `run:` value starting with `|`/`>` *is* a block
   scalar) rather than enumerating header forms.

2. **A full adversarial audit of all 22 guards (#271).** It found a CRITICAL
   comment-evasion in the `Security Scan Gate` severity block (a `# exit 1`
   satisfied the merge-block check) plus three HIGH and several MEDIUM/LOW
   instances in guards that **predated** the shared comment-stripping helpers.
   Remediation landed across #271 / #275 / #277, clearing the backlog (F-1..F-9).

The common root cause: guards authored before a hardening primitive existed never
adopted it, and substring/parse guards are bypassable in non-obvious ways that a
single author pass misses.

## Decision

1. **Route every presence/regex check through the shared comment-stripping
   primitives** in `scanner/tests/_ci_guard_util.py`
   (`strip_comment_lines` for whole-line comments, `strip_inline_comment` for
   trailing comments, plus `extract_on_block` / `top_level_jobs` for structural
   scoping). A token surviving only in a comment must never satisfy an invariant.

2. **Two-pass adversarial review for any substring/parse guard before merge.**
   New or materially-changed guards of this class get an independent adversarial
   review whose explicit goal is to find a bypass (false negative) or a false
   positive — and, given the evidence above, a **second** pass when the first
   finds a CRITICAL, because the first fix has repeatedly left a residual hole.

3. **Every detector ships a non-vacuous mutation self-test.** The test must fail
   on the targeted regression (prove it by mutation) and stay green on the real
   on-disk files. State the regression direction (floor `>=`, pin `==`,
   presence) in the docstring.

4. **Prefer a grammar-complete rule over enumerating forms.** When a matcher
   keeps missing cases of a structured input (YAML block-scalar headers, `on:`
   trigger styles), invert to a rule that is complete by the grammar instead of
   patching the enumeration a third time.

5. **Run a periodic comprehensive adversarial audit** of the whole guard suite —
   not just newly-touched guards — to catch older guards that predate a
   hardening primitive. Record the review date and any backlog in the catalog's
   "Unguarded invariants backlog" section.

## Consequences

- **Positive:** silent weakening of a CI gate fails loudly and reviewably; the
  hardening stays uniform across guards via the shared helpers; regressions are
  pinned by mutation tests; periodic audits surface drift in older guards.
- **Cost:** new guards take longer (two review passes + mutation tests); the
  shared helpers are a small coupling point (changes there must keep all
  consumers green — covered by `scanner/tests/test__ci_guard_util.py`).
- **Constraints preserved:** guards stay stdlib-only (no PyYAML), do not import
  `scanner/lib` (so they never move the 99% coverage floor), and pass under both
  `pytest` and `python3 -m unittest`.

## References

- [CI Config Regression Guards catalog](./ci-config-regression-guards.md)
- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control):
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- OWASP Top 10 CI/CD — CICD-SEC-4 (Poisoned Pipeline Execution):
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (SSDF) — PO.3 / PW.4:
  <https://csrc.nist.gov/pubs/sp/800/218/final>
- GitHub Actions — Security hardening (script injection):
  <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
