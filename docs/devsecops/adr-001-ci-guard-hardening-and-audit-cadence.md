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
**81** load-bearing references to these decisions exist across `scanner/`, `docs/`
and `.claude/` (30 files), so an inserted item silently re-points all of them. This
decision is appended as §9 for that reason rather than filed next to Decision 2
where it belongs topically.

**81, not 67.** The familiar 67 counts one spelling. Measured on `d55c506`, the tree
the vintage sweep below audited; the citations are written five ways, and only the
first is what `test_ci_adr_decision_numbering.py` and the #423 / #426 / #430 sweeps
ever matched.

To reproduce 81, exclude **every** drift note that quotes a number as *data* about
the drift rather than as a pointer to a rule — this section, the numbering guard's
docstring, that guard's row in the catalog, and the 2026-08 cycle retrospective's
falsification table. The rule is the number's *role* in the sentence, not its file.
On `d55c506` that is 11 exclusions out of 92 `§`-shaped hits.

| Spelling | Count | Seen by the guard? |
|---|---|---|
| `ADR-001 §N` | 64 | yes |
| bare `Decision N` (this file's own cross-references) | 6 | no |
| `ADR §N` (no `-001`) | 5 | no |
| `ADR-001 Decision N` (the authoring skill) | 4 | no |
| the tail of a `§N/§M` chain | 2 | no |

The 17 invisible ones are where the surviving errors were — with one distinction
worth keeping straight. **Four** of the five citations still carrying a
pre-`9a530d6` number were cleanly invisible: no `ADR-001 §N` anywhere on the line.
The fifth, `ci-config-regression-guards.md:324`, was an **invisible token on a
visible line** — `ADR-001 §1/§3` is match #8 of 69 in a plain `_CITE_RE` scan, so
the sweeps read the line, resolved its `§1` (correctly), and never saw the `/§3`.
It then sat in the untriaged §1 bucket looking done.

Write new citations as `ADR-001 §N` for that reason, and when you cite two decisions
**repeat the prefix** (`ADR-001 §1 and ADR-001 §4`) rather than chaining (`§1/§4`) —
a chain hides its tail from the only scanner that reads these. Correcting this
paragraph's own first version, measured against `_CITE_RE` while
`test_ci_adr_citation_spelling.py` was being written: writing the pair out as
`§1 and §4` does **not** fix it either. That regex requires the `ADR-001` anchor
before every `§N`, so it returns `['1']` for the chained form and for
`ADR-001 §1 and §4` alike, and `['1', '4']` only when the prefix is repeated.
Un-chaining improves readability; it does not restore visibility. The three-row
transcript is in the catalog's backlog.

That distinction is not mechanizable in the other direction, which is why the
spelling guard flags the chain and permits the un-repeated pair: on 2026-08-12 all
three live instances of "a canonical citation with a bare `§M` later on the same
line" were drift notes quoting a number as *data* (*"26 `ADR-001 §4` citations of
which 23 meant §5"*), not second citations. A rule broad enough to catch the pair
would over-report on exactly the prose that documents this class.

A count taken on a later commit will not be 81: this PR's own fixes add three
`ADR-001 §N` matches (69 → 72 by that regex), two from normalising `ADR §N` in
`adr-001-q3-audit-retrospective.md` and one from naming §2 alongside §1 in
`test_ci_drift_watch_not_silent.py`. The new tables in *this* section add none —
they write `§N` without the `ADR-001` prefix, so `_CITE_RE` does not see them.

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

The `§2`/`§3` follow-up is now done too (22 sites: **17 corrected — 13 by quoted
text, 4 by provenance — and 5 already right**). The 13 classified by their text:

| Was | Now | Why |
|---|---|---|
| §2 ×9 | **§3** | "5th-pass finding", "the mandated adversarial pass", "the mandated review chain", "반복 적대 검증" — all the ITERATED review, and one quotes §3's "second pass when the first finds a CRITICAL" verbatim |
| ~~§2 ×2~~ | ~~**§1**~~ | **Both reverted by the vintage sweep below — this row was wrong.** Two *different* misreads, not one: at `ci-config-regression-guards.md`:356 the evidence quoted is the sentence BEFORE the one the parenthetical sits in, while the clause it annotates is "A **5th-pass** review" (→ §3). At `test_ci_drift_watch_not_silent.py`:40 there is no preceding sentence — the pre-#426 text is a *single* sentence holding both clauses, and the evidence quoted its first clause while the parenthetical annotates its second, "the inert-guard class" (→ §2) |
| §3 ×1 | **§2** | "the inert-assertion class" is §2's, not §3's — read the text, do not infer from the topic |
| §3 ×1 | **§4** | "mutation self-tests for the …" is §4 |

Five `§2` citations were already correct (the inert-guard class, an unhardened
service certified by a mis-cut block, "stripped BEFORE the job block is cut out")
and stay.

**The four held sites are now resolved — by provenance, not by re-reading the text.**
All four were written the same day in `b1fb276` (squashed into `d9c79a2`, PR #379,
merged 2026-08-05 14:10 KST), whose own body opens *"ADR-001 §2 adversarial pass
on #379 found two guards still bypassable"*. On 2026-07-30, §2 **was**
**Two-pass adversarial review for any substring/parse guard before merge** — so all
four were correct when written. `9a530d6` (PR #390, 2026-08-05 18:47 KST, **4h37m
after #379 merged**) inserted the new §2 (Scope the haystack) and shifted old §2→§3,
§3→§4, §4→§5, §5→§6 while touching **no** citation. Both apparent ambiguities
dissolve on that timeline: today's §6 was §5 then and today's §5 was §4 then, so
neither is reachable from a "§2" written before the insertion. All four → **§3**.

| Site | Now | Evidence |
|---|---|---|
| `no_ere_pipe_regression:102` "audit bypass" | **§3** Two-pass adversarial review … before merge | `b1fb276` added the `\begrep\b` alternative; the *same hunk* relabelled the #297-sourced finding on the next line to "an **earlier** audit bypass", separating the two passes by hand |
| `no_ere_pipe_regression:385` "Audit finding" | **§3** (same) | same commit; `test_detects_egrep_backslash_pipe` is new in the second pass. The §6-sourced finding in this guard (`--extended-regexp`, `87c50e2`, PR #379's first commit) carries no `§N` at all |
| `cross_os_non_required:48` "the capitalized form evaded" | **§3** (same) | `b1fb276`: *"false NEGATIVE: case-sensitive, so GitHub's own `macOS-14` … evaded"*. The grammar-complete rule was §**4** that day and was available to cite — it was not cited |
| `cross_os_non_required:59` "false-positive finding" | **§3** (same) | same commit: *"false POSITIVE: … false-tripped a REQUIRED check"*. §3 is also the only decision whose text has a pass look for "a bypass (false negative) **or a false positive**"; §2 calls a raw-file over-report "a false alarm" and exempts it |

Corroborated independently by the Q3 retrospective, whose #379 row files all three
findings — case-insensitivity, the charset false positive, and `egrep` — under
**"잔여 우회 (2차 패스에서 발견)"**: residual bypasses found in the *second* pass.

The generalisable rule: when two decisions both fit the quoted text, the
**introducing commit** decides, because a citation is only ever as stable as the
numbering in force the day it was written.

#### The vintage sweep (2026-08-12) — the population is now audited, not sampled

Both earlier sweeps (#423, and #426/#430) classified citations by **quoted text**,
which found real errors but left the rest *unverified* rather than *verified*: nobody
had checked how many citations were written before `9a530d6`. So all 81 were dated —
`git log`-walked to the first revision whose text carries the citation's anchor
**and** a number, which unlike `git blame` is not fooled by a later reflow. Two
dates per site: when the annotated claim was written, and when its current `§N` was.

`9a530d6` (2026-08-05 18:47:58 +0900) is confirmed the **only** renumbering in the
ADR's ten-commit history — every revision's Decision list was extracted and
diffed. Before it: 1 strippers / 2 two-pass review / 3 mutation self-test /
4 grammar-complete / 5 periodic audit. So a pre-`9a530d6` citation shifts
§2→§3, §3→§4, §4→§5, §5→§6, and §1 is immune.

**36 of the 81 predate it.** By the number as originally written:

| Original | Count | Should now be | Status |
|---|---|---|---|
| §1 | 14 | §1 (immune) | all 14 correct, untouched |
| §2 | 12 | §3 | 10 already fixed; **1 fixed here**; **1 was sent to §1 by #426 — reverted here** |
| §3 | 3 | §4 | 1 already fixed; **2 fixed here** |
| §4 | 7 | §5 | 5 already fixed; **2 fixed here** |

**Zero** pre-`9a530d6` citations name a §6 or higher, so the "cited a decision that
did not exist yet" class — a different error, not a shiftable one — is empty. And
every prior correction agrees with vintage: all 16 sites #423/#426/#430 moved landed
exactly where the shift predicts. Vintage corroborates them rather than reopening
them.

Seven sites were wrong. Five had never been triaged (their spelling was invisible to
all three sweeps), and two were prior corrections that went the wrong way:

| Site | Was | Now | Why |
|---|---|---|---|
| `ci-config-guard-claudesec` skill:71 | Decision 2 | **3** Two-pass adversarial review … before merge | written `5a35454` (pre-shift); "do the adversarial pass … before merge. This is not optional for that class" is §3 verbatim |
| `ci-config-guard-claudesec` skill:306 | Decision 4 | **5** Prefer a grammar-complete rule over enumerating forms | same commit; "**Model the grammar, not a proxy** … a third patch to an enumeration is a redesign signal" is §5's own text |
| `ci-config-regression-guards.md`:324 | §1/§3 | §1 and **§4** Every detector ships a non-vacuous mutation self-test | written `b82394af` (pre-shift); every bullet under the heading pairs a stripper fix with "+ mutation test" |
| `adr-001-q3-audit-retrospective.md`:139 | ADR §4 | **§5** Prefer a grammar-complete rule over enumerating forms | written `9b1d3fe` (pre-shift); the heading *is* "프록시가 아니라 문법을 모델링하라" — model the grammar, not a proxy |
| `adr-001-q3-audit-retrospective.md`:191 | ADR §3 | **§4** Every detector ships a non-vacuous mutation self-test | same commit; the subject is a **vacuous** self-test. The maxim it quotes is from the Context, not from any decision — now attributed there |
| `ci-config-regression-guards.md`:356 | §1 (by #426) | **§3** Two-pass adversarial review … before merge | the parenthetical annotates "A **5th-pass** review"; #426's recorded evidence is the *preceding* sentence, about `strip_inline_comment`. #426 sent the four *other* "5th-pass" citations to §3. Pre-shift original was §2 = the two-pass review, so vintage says §3 as well |
| `test_ci_drift_watch_not_silent.py`:40 | §1 (by #426) | **§1 and §2** | authored `8bee564c` (2026-08-06 19:36:48 +0900, **post**-shift) as §2 — correct as written, since §2 was already "Scope the haystack" and "the inert-guard class" is its vocabulary (#383 is the inert-assertion meta-guard). Decisive: #426 left the *identical* phrase at §2 in `test_ci_security_gate.py`:295 (`inert-guard class, ADR-001 §2`) and its own summary counts "the inert-guard class" among the five §2 citations that were **already correct** — then moved this one to §1. Both decisions are now named so the sentence stops inviting another re-decision |

`b82394af` settles its own two sites internally: the same commit wrote `§2 review
chain` and `§4 grammar-complete extractor`, both correct pre-shift, so its `§1/§3`
was written in the same old numbering and its `§3` is today's §4.

Three of the §2→§3 corrections are **not** in the 36 and the shift does not explain
them: `ci-config-regression-guards.md`:490 (`99e8c2e`) and
`guard-yaml-shape-sweep-retrospective.md`:43 and :180 (both `55b30ada`) were written
on 2026-08-06, the day *after* the renumbering, as §2. All three are
text-unambiguous §3 ("적대 리뷰", "의무화한 리뷰 패스"), so #426 moved them correctly —
they are named here because a table that presents the shift as the explanation while
silently omitting them invites the next reader to re-derive the arithmetic.

**A correction to the account above: the §4→§5 drift was mostly not mechanical.**
Of those 23 citations, only **5** predate `9a530d6`; the other **18** were written
*after* the renumbering, over six days, with the guard green. Those dates are
measured. The *mechanism* — a stale number copied from a pre-shift sibling — is
**inference** from the pattern, not evidence: no commit says so. What the dates alone
establish is that the insertion cannot account for 18 of the 23, so something
downstream of it did. Cite by number *and title* regardless, because a title is what
makes a wrong number fail to typecheck under review.

The guard's limit stands, and vintage sharpens it. Two things it does **not** do:

- It does not make renumbering impossible. Renumber the ADR **and** reorder
  `DECISIONS` in the same commit and all 10 tests pass while 81 citations silently
  re-point — measured by in-memory mutation, with the one-sided control (ADR
  renumbered, `DECISIONS` untouched) correctly failing
  `test_numbers_map_to_the_same_decisions`, so the harness demonstrably reaches the
  assertion. What the guard delivers is that a renumber must be a **lockstep,
  reviewable diff** instead of an invisible one-line edit. An *append* without its
  `DECISIONS` line does genuinely fail (`test_no_extra_or_missing_decisions` is a set
  equality), so "appending costs one line here, by design" is exact.
- It cannot detect a citation pointing at a real decision it does not mean. That is
  what reading the quoted text — and, when the text ties, the commit that wrote it —
  is for.

What the vintage sweep adds is knowing *which* citations were exposed to the shift,
and that the answer is now none.

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
