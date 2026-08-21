---
title: Compliance status model — per-finding evidence routing, and what `assessable: False` should mean
description: Measurement showing a clean AWS scan erases 25 of 28 GitHub-evidenced compliance failures, and the plan to route evidence per finding without waking 44 untuned keyword lists
tags: [compliance, prowler, planning, false-negative]
---

# Compliance status model: the rule discards evidence it already has

Two defects were left open by [#456] and [#457]. They look unrelated — one is
about `assessable: False`, the other about mixed-provider scans — but they are
the same shape: **a control's status is decided by a rule that throws away
evidence the run produced.** They also edit the same fifteen lines of
`map_compliance()`, so they are designed together here even though they ship
apart.

All numbers below were measured against the pinned **Prowler 5.30.1** files,
using real check ids from Prowler's own `pci_4.0_kubernetes.json` (32) ∪
`iso27001_2022_kubernetes.json` (54) = 62 Kubernetes ids, and
`cis_1.0_github.json` (22 GitHub ids), supplied as FAIL findings. Where a
figure is a target rather than a measurement, it says so.

**Denominators.** 8 frameworks are declared in `COMPLIANCE_CONTROL_MAP`. 6 have
a native source registered in `FRAMEWORK_SOURCES`; CIS Benchmarks (9 controls)
and KISA ISMS Simple (20) do not and are keyword-only throughout. "Total FAILs
across 5 frameworks" below means the 6 registered minus CMMC, whose 14 controls
are `native_only` and report N/A on every run these corpora exercise.

[#456]: https://github.com/Twodragon0/claudesec/pull/456
[#457]: https://github.com/Twodragon0/claudesec/pull/457

## The state space

118 controls across 8 frameworks. Three axes decide a status: whether the
control is declared `assessable`, whether Prowler ships a native mapping for
it, and whether that mapping is reachable by the providers scanned.

| assessable | has native mapping | `native_only` | controls |
|---|---|---|---|
| yes | yes | no | 44 |
| yes | no | no | 34 |
| **no** | **no** | no | 22 |
| yes | yes | yes (CMMC) | 9 |
| yes | no | yes (CMMC) | 5 |
| **no** | **yes** | no | **4** |

The last row is defect A's entire population. The 44-row is defect B's.

## Defect B — a clean AWS scan erases GitHub evidence

`map_compliance()` picks ONE source per control and applies it to ALL findings.
A control on the native path matches by exact check id, and a finding from a
provider Prowler ships no file for can never have a matching id — so it is not
merely unmatched, it is never evaluated at all. It does not fall back to
keywords; nothing looks at it.

Measured, 22 real GitHub check ids as FAIL findings:

| Run | Total FAILs across 5 frameworks |
|---|---|
| `github` only | **28** |
| `github` + one AWS finding (`ec2_ebs_snapshots_encrypted`) | 9 |
| `github` + a **completely clean** AWS scan | **3** |

The middle row depends on which AWS finding: it ranges 7–11 over the corpus.
`ec2_ebs_snapshots_encrypted` is named because it reproduces both this table
and the Kubernetes one below; five other ids do the same. The first and third
rows take no AWS input and are therefore the load-bearing ones.

The third row is the important one and it is worse than the second. The gate
added in #456 keys on `scanned_providers`, which `dashboard-gen.py` derives
from the Prowler **artifact files present**, not from findings. So an AWS scan
that produced zero failures still un-gates every AWS-mapped control, which then
matches nothing and reports PASS.

> **Merely configuring an AWS credential — with AWS perfectly clean — turns 25
> of 28 GitHub-evidenced failures green.**

The same mechanism hits Kubernetes on the three frameworks Prowler ships no k8s
file for. Measured with 62 real k8s check ids, adding one AWS finding:

| Framework | k8s only | + AWS |
|---|---|---|
| SOC 2 (TSC) | 3 | 1 |
| NIST 800-53 Rev5 | 5 | 0 |
| KISA ISMS-P | 18 | 8 |

ISO and PCI are unaffected — Prowler ships a Kubernetes file for both.

### The safety property that bounds the whole fix

No GitHub check id appears in any registered framework's native mapping
(verified across all six). Off-provider findings therefore contribute **exactly
zero** matches today. Any routing change that lets them reach a keyword list can
only ADD matches:

> **The routing change is monotone. It can turn PASS into FAIL and never FAIL
> into PASS, so it cannot create a false PASS — the failure class
> [#455]/[#456] exist to close.**

Swept across five scenarios (k8s+aws, gh+aws, gh+k8s+aws, aws-only, k8s-only):
**0** FAIL→PASS transitions. So every possible regression from the routing
change is a keyword **false FAIL** — one class, not four.

**This property is scoped to the routing change only.** Choice 3 below
(dropping `_match_prowler_compliance` from the fallback path) removes matches
and is therefore *not* monotone; it is justified separately, on the ground that
the matcher is unreachable against Prowler's real output.

[#455]: https://github.com/Twodragon0/claudesec/pull/455

### The risk, measured: 44 keyword lists have been dead since #451

The keyword lists on natively-mapped controls have not decided anything since
PR #451 registered the native sources. They were never measured against a
corpus because on any reachable run they saw none. B wakes all 44 at once.

Three of them still carry `default` — a token this repo **removed from SOC 2
CC5 and banned by CI** after measuring it at 158 corpus hits and 0 relevant
(`test_ci_compliance_keyword_guard.py::test_cc5_does_not_carry_default`). The
ban is per control, which was defensible while the others were dead:

| Control | keyword list |
|---|---|
| NIST CM-6 | `configuration`, `benchmark`, `hardening`, **`default`**, `baseline` |
| ISO A.8.9 | `configuration`, `misconfigur`, **`default`** |
| PCI Req 2 | `configuration`, **`default`**, `hardening`, `benchmark` |

Measured against the GitHub corpus: `default` matches 12 of 22 checks, and
**11 of those 12 are `repository_default_branch_*`** — a git ref, not a
configuration default. About 92% wrong, on exactly the controls B would newly
feed. `NIST AC-2` (`account`, `user`, `admin`, `permission`, `iam`) and SOC 2
CC3/CC4 (both carrying `scan`) are unmeasured and generic enough to be
suspect.

This is why the plan sequences a measurement pass **before** B. Shipping B
first means the first dashboard cannot distinguish "B restored real evidence"
from "`default` started matching branch names".

## Defect A — `assessable: False` outranks exact native evidence

Four controls are both declared non-assessable and natively mapped:

| Control | Native checks | Composition |
|---|---|---|
| ISO A.5.1 | 37 | 27 Kubernetes (12 `apiserver`, 6 `kubelet`, 5 `rbac`, 4 `etcd`) + 10 Azure/AWS (4 `entra`, 2 `defender`, …) |
| SOC 2 CC1 | 30 | 15 `entra` + 15 `iam` |
| SOC 2 CC2 | 23 | 10 `monitor`, 9 `logging`, 3 `cloudtrail`, 1 `config` |
| SOC 2 CC9 | 1 | `gemini_api_disabled` |

On a scan where those checks fail, the control reports N/A and is excluded from
the pass/fail totals that flow into `scan-report.json` history.

**What is NOT lost:** `count` and `findings` are recorded regardless, and the
dashboard renders the finding rows. Verified — a CC1 with one matching FAIL
renders `N/A`, count `1`, and the finding row. Only the verdict and the roll-up
drop it.

**Recommendation: do not change the status policy.** Two independent reasons:

1. The information is not lost, only the roll-up is — see above. The gap
   between "N/A" and a visible FAIL row is a *display* contradiction.
2. Reclassifying trades a false N/A for a false PASS. With zero matches, an
   assessable A.5.1 would assert that an approved, published information
   security policy exists on the strength of an empty check list. This repo
   ranks false-PASS as the worse error, which is the whole content of
   [#454]/[#455]/[#456].

Prowler's files must map something to every requirement, and over-attachment is
the predictable result — `gemini_api_disabled` as evidence for "vendor and
business-partner risk mitigation" is that in its plainest form. A failing Entra
admin-count check does not refute COSO board oversight either.

Two arguments this plan deliberately does **not** rest on. The CIS refusal in
`prowler_native_map.py` is about **id misalignment** (`CIS-6.1` here is CIS
Controls v8's Safeguard 8.1) — a mechanical problem that does not arise for ISO
(`_identity`) or SOC 2 (`_soc2_series`), where Prowler's attachments land on the
correct control ids. And the existing pin in `test_prowler_native_map.py`
("CC1 is governance; a native mapping must not resurrect it as PASS/FAIL")
records that a decision was made, not that it was right; citing it as a reason
not to revisit would be circular.

What is genuinely wrong is the **row**: it shows `N/A` beside a non-zero count
and visible FAIL rows, with nothing explaining the contradiction. On a
Kubernetes + clean-AWS run, five N/A controls carry non-zero counts — A.5.1 at
27. That is a rendering fix.

ISO A.5.1 is the one case that could survive a per-control review: 27
Kubernetes hardening checks genuinely refute "topic-specific policies are
technically enforced", even though they can never establish "defined, approved
by management, published". If anyone reopens A, start there, one control at a
time, against the criterion text — not as a blanket rule.

[#454]: https://github.com/Twodragon0/claudesec/pull/454

## Plan

### Phase 0 — measure the 44 dormant keyword lists (prerequisite for B)

Reuse the methodology already documented in
`test_ci_compliance_keyword_guard.py`: score each list against Prowler's own
mapping as ground truth, count recovered-vs-newly-lit. Prune what fails and pin
the removals in `REMOVED_TOKENS`. Start with `default` on CM-6 / A.8.9 / Req 2,
which already has a measured verdict on a sibling control.

Independently valuable: it makes the lists honest whether or not B ships.

**Success criterion, stated operationally.** The CC5 verdict is not a precision
figure and cannot be used as a threshold: it records that `default` *"recovers
0 of its 21 missed checks and newly lights 158 corpus-wide"* — 169 hits total,
none of them CC5's. So the gate has the same shape, not the same number:

> Prune a token from a control when it recovers **zero** of that control's
> Prowler-mapped checks while lighting more than a stated number of unrelated
> corpus checks. Record both counts in `REMOVED_TOKENS`, as CC5's entry does.

Two caveats a reader needs. The CC5 measurement was taken against Prowler
**5.38**'s catalog, while every other figure in this plan is 5.30.1 — re-measure
rather than compare across versions. And
`test_ci_compliance_keyword_guard.py::test_edited_controls_keep_at_least_two_checks`
imposes a floor of 2: ISO A.8.9 has exactly 3 keywords, so dropping `default`
leaves it **at** the floor and a second pruning there fails CI. That control may
need a replacement token rather than a removal.

**If Phase 0 is inconclusive** — say the measurement cannot separate signal from
noise for a given list — do not let it block B indefinitely. Ship B with the
kill switch below and the unresolved lists documented, rather than leaving a
control that flips green on an empty AWS artifact.

### Phase 1 — route evidence per finding (defect B)

Match on the **check id first**, provider second:

```python
# `eff` is the control's native check set, or None once the #456 gate fires.
# `covered` is None when the control has no native mapping AND when a
# version-skewed sibling failed to supply the scope table — see choice 2.
if eff and str(f.get("check", "")) in eff:
    exact.append(f)                      # check id first; ids are globally unique
elif ctrl["checks"] and (
    not eff or (covered is not None and f.get("provider") not in covered)
):
    text = f"{f['check']} {f['title']} {f['message']}".lower()
    if any(kw in text for kw in ctrl["checks"]):
        keyword.append(f)
# else: a covered-provider finding whose id is not mapped — no match (this is #451)
matching = exact + keyword               # exact ranked first, so findings[:5] shows it
```

Five choices, each with a reason:

1. **Check id first, not provider first.** Makes the branches mutually
   exclusive by construction (no double-counted `count`), removes any
   dependence on scanner-slug ↔ Prowler-directory parity, and makes
   `provider`-less findings a non-issue — three hazards closed by one ordering.
   Safe within a framework by construction: ids and providers are co-recorded
   in the same loop, so every id in a control's set came from a file of a
   provider in its own `covered`. 547 of 890 ids appear in more than one
   framework, which is harmless — frameworks are scored independently.
2. **The fallback predicate has two arms, and both are load-bearing.** Three
   candidate spellings, measured on `github` + clean AWS, on a version-skewed
   sibling (`_NATIVE_PROVIDER_SCOPE == {}`, so `covered is None` everywhere),
   and on the two keyword-only frameworks:

   | Predicate | gh+aws | version-skew | CIS + ISMS-Simple |
   |---|---|---|---|
   | `covered is None or provider not in covered` | 28 | **28** (keyword flood) | 8 |
   | `covered is not None and provider not in covered` | 25 | 0 | **0 (both frameworks silenced)** |
   | `not eff or (covered is not None and provider not in covered)` | **28** | **3** | **8** |

   Only the third is right. The first floods on version skew — 0 → 27 new FAILs
   from a single finding — and would flip the currently-green pin
   `test_native_provider_scope.py::test_the_same_run_used_to_report_prowler_and_pass`.
   The second destroys the keyword path for all 29 controls that have no native
   mapping at all, because they also have `covered is None`. The third
   reproduces today's version-skew behaviour exactly (3 = today's gh+clean-aws)
   and leaves CIS Benchmarks and KISA ISMS Simple untouched.
3. **Keyword-only on the fallback path — stop *calling*
   `_match_prowler_compliance` from it. Do not delete the function**: it is
   re-exported by `dashboard_compliance.py` and `dashboard_mapping.py`,
   imported by `dashboard-gen.py`, and asserted by ~14 tests across 3 files.
   The justification is not that it is "dormant because natively-mapped
   controls never take the keyword path" — they take it on every gated run.
   It is that the matcher is **unreachable against Prowler's real output**:
   Prowler's tag keys are `iso27001_2022` / `soc2` / `nist_800_53_revision_5`
   shaped, and the matcher needs a substring relation with the *display* name
   (`ISO 27001:2022`). Measured across seven real key shapes and all eight
   display names: **zero matches**. Removing the call is therefore a no-op
   against real data, while leaving it in would give a framework-level
   indiscriminate matcher 44 new controls on every mixed run the day a key
   shape changes.
4. **Keep the #456 gate.** It looks redundant after B — if no scanned provider
   is covered, no finding is exact-eligible anyway — but it is the only thing
   producing `unmapped`/N/A for `native_only` controls. Measured: with the gate,
   CMMC on a k8s-only run is 14 N/A; without it, **9 PASS / 5 N/A**. The gate
   answers "can this control be assessed at all", routing answers "which
   findings can the mapping speak for". Add a comment saying so.
5. **`native_only` controls take no fallback.** Their `checks` are `[]`, so the
   `elif` is already inert. The invariant that makes this safe
   (`has_keywords ≡ not native_only`) is **already pinned** for all 118 controls
   by `test_compliance_map.py::test_each_control_has_required_fields` and again
   through `map_compliance` by `test_prowler_native_map.py`. No new guard is
   needed; the existing pin simply becomes load-bearing for a second reason.

Prototyped and measured. `github` + clean AWS goes **3 → 28**; an AWS-only run
is byte-identical; #451's exactness survives (a covered-provider finding whose
text is saturated with a control's keywords but whose id is unmapped still does
not match); CMMC stays 14 N/A on a k8s-only run.

**`match_source` keeps its current meaning; add a sibling.** It is a
control-level *capability* label ("was the native mapping reachable"), defined
even at zero findings. 25 exact-equality assertions across five test files read
it, and about four of those call `map_compliance([])` and so require a value
that exists with no findings at all. A joined `"prowler+keyword"` string breaks
them and lands in the renderer's unknown-source bucket. Instead add
`evidence: {"prowler": n, "keyword": m}` and render it in the control row next
to `count` — `12 (3 exact · 9 keyword)` — where an operator decides whether to
trust the FAIL. The framework rollup keeps counting controls by capability.
`_MATCH_SOURCE_LABELS` needs rewording: `exact` overclaims for a
`prowler`-labelled control that scored most of its findings by keyword —
propose **"native mapping available"**. `evidence` is a render-time field; it is
**not** persisted to `scan-report.json`, which carries only the rollup.

### Tests Phase 1 must account for

- **Changes meaning, must be updated:** the rationale in
  `test_compliance_map.py::TestMatchProwlerCompliance` (its "runs ONLY on the
  keyword path" reasoning survives, but the call site it describes moves).
- **Must stay green unchanged, and is the regression canary for choice 2:**
  `test_native_provider_scope.py::test_the_same_run_used_to_report_prowler_and_pass`
  — it stubs the scope to `None` and pins `prowler`/`PASS`. Predicate 1 flips it;
  predicate 3 does not.
- **Must stay green unchanged:** the four zero-finding `match_source`
  assertions, `TestGatingIsPerControlNotPerFramework`, `TestEveryFrameworkIsScoped`,
  and all CMMC N/A assertions.
- **New:** per-finding routing cases (covered/uncovered/mixed), the `evidence`
  counts, exact-ranked-first ordering, and a rendering test for the new row.

### Rollback and history

- **Kill switch.** Gate the routing on an env var (`CLAUDESEC_COMPLIANCE_ROUTING`,
  default on) so one scan can be re-run under both models and diffed. Remove it
  once Phase 0's pruning has been through a real scan.
- **The trend series spans two policies.** `dashboard-gen.py` appends the
  rollup to `.claudesec-history/scan-*.json`; existing entries carry no policy
  marker and cannot be backfilled, because the findings that produced them are
  not retained. Stamp a `compliance_policy` version into new entries and have
  the trend render the boundary rather than smooth over it — [#446] solved the
  analogous problem by *displaying* the discontinuity, not hiding it.

[#446]: https://github.com/Twodragon0/claudesec/pull/446

### Phase 2 — disclose, do not reclassify (defect A)

Render-only. On a control that is `assessable: False` with a non-zero count,
state the contradiction the row currently leaves unexplained: *"N native-mapped
findings matched; this criterion has no automated test method, so no verdict is
issued."* No change to `map_compliance`'s status expression, to
`compliance_summary`, or to `scan-report.json` — therefore no discontinuity in
the history series.

## Sequencing

Phase 0 → Phase 1 → Phase 2. **Do not invert 0 and 1.**

A and B are independent at the status level: `assessable: False → N/A` is
applied *after* matching, so B changes `count` and `findings` on those four
controls but can never change their `status`. Phase 2 can ship at any time.

## Options considered and rejected

| Option | Why not |
|---|---|
| **A(b)** reclassify A.5.1/CC1/CC2 as assessable | Trades a false N/A for a false PASS: with zero matches, A.5.1 would assert an approved published policy exists from an empty check list. This repo ranks false-PASS as the worse error. |
| **A(c)** a fourth status | `compliance_summary` counts exactly three states with `total = pass + fail`; a fourth vanishes from all four counters and breaks `total == len(controls) - na`. The renderer's `else` branch is FAIL, so it would render red. High blast radius for 4 controls. |
| **A(d)** "never PASS, FAIL on exact evidence" | Right *shape* — evidence that refutes but cannot establish — and it fits ISO A.5.1. It does not generalise: a failing Entra check does not refute COSO board oversight, and CC9's single `gemini_api_disabled` is a bad attachment on its face. Revisit per control, not as a rule. |
| **B′** route off-provider findings to a new "unevaluated" state instead of keywords | Strictly honest and produces no keyword false-FAILs, but **cannot restore the GitHub evidence that motivates B** — Prowler ships no GitHub file for any registered framework, so those findings would never be evaluated by anything. Also needs the fourth status rejected above. |
| Delete the #456 gate as redundant after B | Measured: CMMC goes to 9 PASS / 5 N/A on a k8s-only run. |

## What this plan does not claim

- The 28 restored failures are **keyword-grade**, not exact. B restores
  *recall*, at the precision of lists Phase 0 has not yet measured. Calling it
  "restoring exact evidence" would be wrong.
- **The monotonicity guarantee covers the routing change only.** Choice 3
  removes matches and is not monotone; it rests on a separate measurement
  (zero reachable tag-key shapes), not on the safety property.
- Phase 0's success criterion is a shape, not a threshold, and its reference
  measurement was taken on a different Prowler version. Every other number here
  is measured at 5.30.1.
- The `+ one AWS finding` column depends on an unstated-until-now input; the
  two input-free rows carry the argument.
- The measurements use Prowler's own check ids as synthetic FAIL findings. A
  real estate fails a different subset; the direction and the mechanism hold,
  the absolute counts are corpus-specific.
- Prowler's requirement→check attachments are treated as ground truth for
  *which check evidences which requirement*. Defect A is precisely a case where
  that judgement is disputed.
- **B introduces its own mild over-attachment, unmeasured.** `covered` is per
  control, so a finding Prowler explicitly maps to control X is still offered to
  control Y's keyword list whenever Y's providers exclude that finding's
  provider. "Only for findings the mapping cannot speak for" is true per
  control and false per framework. No status change from this was reproducible
  on the available corpora (ISO: 0 controls affected on k8s+AWS), so it is a
  latent property, not a measured defect — but it is the same class this plan
  criticises in defect A.
- No estimate of implementation effort. Phase 0's size depends on how many of
  the 44 lists survive measurement, which is the thing being measured.
