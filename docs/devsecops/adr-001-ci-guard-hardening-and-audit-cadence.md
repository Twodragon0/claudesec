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

3. **The #297 quarterly audit (2026-07/08, 9 PRs).** Beyond more comment-evasion,
   it surfaced a strictly worse class: **inert guards** whose haystack was the
   *raw whole file*, so commenting the control out — or deleting it outright —
   left the guard green with no evasion needed. Two were found by hand; codifying
   that triage as an AST meta-guard found **seven more** in guards that had
   already passed review, including both required merge contexts and a
   `pull_request_target` fork guard. The same audit found that the two REQUIRED
   workflows never *ran* on stacked PRs, so a correct guard can still be worth
   zero. Retrospective:
   [ADR-001 Q3 audit](../reports/adr-001-q3-audit-retrospective.md).

The common root cause: guards authored before a hardening primitive existed never
adopted it, and substring/parse guards are bypassable in non-obvious ways that a
single author pass misses.

## Decision

1. **Route every presence/regex check through the shared comment-stripping
   primitives** in `scanner/tests/_ci_guard_util.py`: `strip_comment_lines` for
   whole-line comments; `strip_inline_comment` for trailing comments in
   **YAML/Dockerfile** lines, where `;#` is literal scalar content;
   `strip_inline_comment_sh` for **shell** lines, where bash starts a comment
   after a metacharacter (`;`/`&`/`|`/`(`/`)`/`<`/`>`/backtick) with no space;
   `strip_html_comments` for **Markdown**, whose only comment form is
   `<!-- ... -->`; plus `extract_on_block` / `top_level_jobs` for structural
   scoping. Pick the stripper by the language of the scanned line, not the file
   extension — a `run:` body in a `.yml` file is shell. A token surviving only in
   a comment must never satisfy an invariant.

2. **Scope the haystack before choosing a matcher.** A presence assertion aimed
   at the raw whole file is **inert**: it survives commenting the control out and
   misses a plain deletion, while reading green. No amount of stripping fixes
   `assertIn("exit 1", lint_yml)` when the file holds a dozen unrelated
   `exit 1` lines — bound the haystack to the owning block (balanced `if`/`fi`
   depth, the `- name:` step, the `case` arm) first, then match. A line-anchored
   regex (`(?m)^\s*token`) is an acceptable inline scoping. Negative
   (FORBIDDEN-token) assertions are exempt: over a raw file they only
   over-report, which is a false alarm, never a silent bypass. Enforced by
   `test_ci_guard_assertion_scoping.py`.

3. **Two-pass adversarial review for any substring/parse guard before merge.**
   New or materially-changed guards of this class get an independent adversarial
   review whose explicit goal is to find a bypass (false negative) or a false
   positive — and, given the evidence above, a **second** pass when the first
   finds a CRITICAL, because the first fix has repeatedly left a residual hole.

4. **Every detector ships a non-vacuous mutation self-test.** The test must fail
   on the targeted regression (prove it by mutation) and stay green on the real
   on-disk files. State the regression direction (floor `>=`, pin `==`,
   presence) in the docstring. **Prove the verification harness can produce a
   RED before trusting a green**: the #297 audit's first inertness measurement
   reported green across the board because `unittest` re-ran `setUpClass` and
   reloaded the real file over the injected mutant. The measurement was wrong,
   not the finding.

5. **Prefer a grammar-complete rule over enumerating forms.** When a matcher
   keeps missing cases of a structured input (YAML block-scalar headers, `on:`
   trigger styles), invert to a rule that is complete by the grammar instead of
   patching the enumeration a third time.

6. **Run a periodic comprehensive adversarial audit** of the whole guard suite —
   not just newly-touched guards — to catch older guards that predate a
   hardening primitive. Record the review date and any backlog in the catalog's
   "Unguarded invariants backlog" section.

7. **The meta-guards are in audit scope, and are audited FIRST.** Five guards now
   guard the guard suite itself. An inert meta-guard is the worst case in this
   design — every invariant it is supposed to protect silently loses its
   backstop — so each audit pass starts here, and each of the five must carry its
   own mutation self-test:

   | Meta-guard | Protects |
   |---|---|
   | `test_ci_guard_assertion_scoping.py` | no guard makes a positive presence assertion against raw whole-file text (Decision 2), pinned by set equality against an **empty** baseline |
   | `test_ci_strip_before_match.py` | a guard comment-strips BEFORE it matches — including when the match is a block BOUNDARY, and inside its own helpers (Decision 1 applied one layer down); empty baseline. It does **not** detect over-stripping in general: "a stripper must never remove a line containing the asserted token" is false by design, since removing a commented copy or another block's token is precisely what scoping does. Over-stripping stays a Decision-3 review obligation |
   | `test_ci_pr_trigger_scope.py` | the two REQUIRED workflows keep an unscoped `pull_request:` trigger — no `branches:` (hides the check from stacked PRs) and no `paths:`/`paths-ignore:` (the #186 permanent merge-block) |
   | `test_ci_catalog_completeness.py` | every guard file has a catalog row (HTML-comment-stripped, so a row hidden in `<!-- -->` does not count) |
   | `test_ci_catalog_no_ghost_rows.py` | every catalog-cited guard path exists on disk |

   Both catalog meta-guards shipped with **no** mutation self-test and ran only
   against the real catalog — a parser regression would have made them pass
   vacuously. That is now fixed and is the standing bar for any future
   meta-guard.

8. **Audit whether each guard RUNS, not only whether its logic is right.** A
   guard that is never triggered is worth zero regardless of correctness. Each
   audit pass verifies the workflows behind the REQUIRED contexts still fire for
   the PR shapes in use — the #297 audit found its own entire follow-on chain
   unverified in CI because `on.pull_request.branches: [main]` skipped stacked
   PRs. Distinguish the two directions before proposing a trigger change:
   widening a `branches:` filter is strictly additive, whereas a workflow-level
   `paths-ignore:` on a required check blocks merges permanently (#186).

9. **Route every BLOCK COLLECTOR through the shared block primitives**
   (`block_ends_at`, `key_column`), and match the collector to the grammar it
   reads. Decision 2 says bound the haystack; this decides where the bound *is*,
   and getting it wrong makes a perfectly-spelled matcher scan a block that stops
   short — nothing found, which reads exactly like compliant.

   A comment line ends **no** YAML mapping — verified against PyYAML, `a:` then
   `x: 1`, a `# c` line, then `y: 2` resolves to both keys — so a terminator of the
   form "first non-blank line at or left of the threshold column" hides every key
   after a comment. Three live bypasses on 2026-08-11 (#419), one comment line each,
   all measured against PyYAML on the real files: a workflow-level `packages: write`
   with the owning guard at `12 passed`, and a step-level and a job-level
   `continue-on-error:` on the required `Security Scan Gate` at `61 passed` — the
   last two defeating the guards written FOR that key (Decisions 4 and 6 in action,
   both green). Any `min(indent)` column derivation must skip blank and comment
   lines for the same reason; five copies existed and every one was wrong the moment
   comments could live inside a block.

   The rule is grammar-specific, not universal. In a block/folded scalar a `#` is
   content and a less-indented one is a `ParserError`, so a collector over a
   `run: |` body is **right** to stop there — "fixing" it for consistency
   over-captures shell out of a workflow file, which is how a guard comes to execute
   text it never meant to read. Follow the parser, not the appearance of
   consistency.

   Two corollaries, both earned in the same cycle:
   - **Placement decides a probe's verdict.** The same comment at the START of a
     block truncates unrelated keys away, trips other assertions, and reads as
     "caught" — a false negative in the probe, not in the guard.
   - **"No observable effect" is not a verdict** (#420). It describes a measurement
     and explains nothing, which is how a stale "known fine" gets written. Find the
     reason: the immunity may live in the guard's CALLER — one `strip_comment_lines`
     call in `setUpClass`, which nothing asserted — and that is what needs pinning.

### On citing this ADR

Cite decisions by **title**, not only by number, and **never renumber** this list:
62 references to `ADR-001 §N` exist across `scanner/`, `docs/` and `.claude/`, so an
inserted item silently re-points all of them. This decision is appended as §9 for
that reason rather than filed next to Decision 2 where it belongs topically.

A drift was found and fixed on 2026-08-11: 26 `ADR-001 §4` citations existed and
**23 of them meant §5** (Prefer a grammar-complete rule) — they quoted *"prefer a
rule complete by construction over an incomplete reassembler"*, *"a third patch to
an enumeration is a redesign signal"*, or *"model the grammar, not a proxy"*, none
of which is §4. §4 is the mutation-self-test decision, and exactly **two**
citations meant it correctly (`test_ci_security_gate_behaviour`'s and
`test_ci_required_graph_not_disabled`'s "a control with no mutation self-test is an
untested control"). Every citation was classified by its quoted text before being
touched; a blanket rewrite would have broken those two.

`test_ci_adr_decision_numbering.py` now pins each decision number to its title, so
inserting or renumbering fails the build with a message pointing here. Appending is
a one-line guard update — deliberately, so it is a review moment rather than a
silent re-pointing of 60-odd citations.

## Consequences

- **Positive:** silent weakening of a CI gate fails loudly and reviewably; the
  hardening stays uniform across guards via the shared helpers; regressions are
  pinned by mutation tests; periodic audits surface drift in older guards. Two of
  the recurring manual triage steps — "is this haystack raw?" and "is a catalog
  row real?" — are now machine-checked on every PR rather than once a quarter.
- **Cost of the meta layer:** four guards exist only to guard other guards, and
  Decision 2's scoping rule makes an ordinary presence check slightly more work
  to author. Accepted: the #297 audit's meta-guard found 7 inert sites in guards
  that had already passed a two-pass review, so the human passes demonstrably do
  not catch this class on their own.
- **Cost:** new guards take longer (two review passes + mutation tests); the
  shared helpers are a small coupling point (changes there must keep all
  consumers green — covered by `scanner/tests/test__ci_guard_util.py`, which is
  the SINGLE direct-unit-test file for the shared module; a second one had grown
  up beside it and was folded back in on 2026-08-10, since two test files for one
  module means "is this primitive tested?" has two answers and neither is
  authoritative).
- **Constraints preserved:** guards stay stdlib-only (no PyYAML), do not import
  `scanner/lib` (so they never move the 99% coverage floor), and pass under both
  `pytest` and `python3 -m unittest`.

## References

- [CI Config Regression Guards catalog](./ci-config-regression-guards.md)
- [ADR-001 Q3 audit retrospective (#297)](../reports/adr-001-q3-audit-retrospective.md)
- [Runner-key audit retrospective (#404 → #408)](../reports/runner-key-audit-retrospective.md)
  — what execution-based proof closes, and the boundary it cannot cross
- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control):
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- OWASP Top 10 CI/CD — CICD-SEC-4 (Poisoned Pipeline Execution):
  <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (SSDF) — PO.3 / PW.4:
  <https://csrc.nist.gov/pubs/sp/800/218/final>
- GitHub Actions — Security hardening (script injection):
  <https://docs.github.com/en/actions/reference/security/secure-use>
