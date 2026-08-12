---
name: ci-config-guard-claudesec
description: ClaudeSec-specific CI config regression guard authoring — exact conventions (scanner/tests, stdlib-only/no-PyYAML, 99% pytest + 90% kcov floors, scanner/lib) and the existing test_ci_*.py catalog. Use in THIS repo. For the repo-agnostic pattern, use the global ci-config-guard skill.
user-invocable: true
---

# CI Config Regression Guard — Authoring Playbook

CI gates are the controls between a regression and a green build, and they are
easy to weaken **silently** (lower a floor, drop a job from an aggregator's
`needs:`, re-introduce a tag pin, delete an `exit 1`). This skill produces a
guard test that makes any such weakening fail loudly and reviewably. Maps to
OWASP CICD-SEC-1 (Insufficient Flow Control) / CICD-SEC-7 (Insecure System
Configuration) and NIST SSDF PO.3/PW.4.

Catalog of existing guards: `docs/devsecops/ci-config-regression-guards.md`.
Implementations: `scanner/tests/test_ci_*.py`.

## When to add a guard

Add one only when **silent weakening of a specific invariant would disable
enforcement** AND you can name a concrete past or plausible incident. No incident
→ likely not worth it (avoid guard sprawl). Good candidates: required-check
aggregator `needs` completeness, action SHA-pinning, coverage `--cov-fail-under`,
a severity `exit 1`, a load-bearing version pin.

## Conventions (ClaudeSec)

- **Location**: `scanner/tests/test_ci_<thing>.py`, run by the `scanner-unit-tests`
  job (`python3 -m pytest scanner/tests/`).
- **stdlib-only**: regex / line scanning. **No PyYAML** — it's not in
  `requirements-ci.txt`, so `import yaml` fails in CI.
- **No `scanner/lib` import** → does not affect the 99% coverage gate.
- **Direction-explicit**: floors `>=` (ratchet-up stays green), pins `==`
  (any change trips), triggers/flags = presence. State it in the docstring.
- **Non-vacuous**: prove it fails on the regression before shipping (see below).
- **Dual-runner**: pass under `pytest` and `python3 -m unittest`.
- **Route every presence/regex check through the shared primitives** in
  `scanner/tests/_ci_guard_util.py` (ADR-001 Decision 1) — never hand-roll
  comment stripping. A token surviving only in a `#` comment must never satisfy
  an invariant. Read that module for the current set, and mind the
  shell-vs-YAML split under **Picking a stripper** below. A new primitive goes
  there **and** gets a test in `test__ci_guard_util.py` — coverage is not
  automatic (`join_continuations` and `on_key_inline` have no direct tests
  today, 94% module coverage).

## Authoring steps

1. Pin the file and the invariant. Resolve the repo root robustly:
   `REPO_ROOT = Path(__file__).resolve().parents[2]`.
2. Extract the relevant slice with line/regex scanning (a job block, an `on:`
   region, a `needs:` list, a `[ "$X" -gt 0 ]` body). Keep a `*_exists` canary
   test so a moved/renamed file fails clearly rather than vacuously.
3. Assert the invariant with the right direction (`>=` / `==` / presence) and a
   message that tells the next engineer how to fix it (or how to update the
   guard if the change is intentional).
4. Verify (mandatory):
   - Positive: passes on the real file.
   - **Non-vacuous**: mutate a temp copy (lower the floor, swap a SHA for `@vN`,
     drop a `needs` item, delete `exit 1`) and confirm the assertion FAILS.
     Monkeypatch the module's path constant at a temp file — never mutate the
     real workflow.
   - **Non-vacuous also applies to self-tests of the parser itself.** A
     scoping test that never exercises the scoping is worthless: in #378 a
     nested-`case` self-test used an inline `*) s ;;` arm that the bare-arm
     regex never matched, so the scoping branch under test (then indent-based,
     now `case`/`esac` depth) was never entered. Assert the test enters the
     branch you think it does — instrument the counter if you are not sure.
5. If the guard parses text (substring / regex / mini-parser), do the
   adversarial pass in **Parse/substring guards** below before merge. This is
   not optional for that class — ADR-001 Decision 3, "Two-pass adversarial review
   for any substring/parse guard before merge".

## Template

```python
import re, unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET = REPO_ROOT / ".github" / "workflows" / "lint.yml"

class TestSomeInvariant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""

    def test_target_exists(self):
        self.assertTrue(TARGET.is_file(), f"{TARGET} not found")

    def test_invariant_holds(self):
        m = re.findall(r"--cov-fail-under=(\d+)", self.text)
        self.assertTrue(m, "gate removed")
        self.assertGreaterEqual(min(int(x) for x in m), 99,
            "coverage floor lowered; if intentional, update this guard.")

if __name__ == "__main__":
    unittest.main()
```

## Non-vacuous verification harness (no real files touched)

Note `apply_mutation` rather than `orig.replace(...)`: a bare `str.replace` whose
anchor has gone stale returns the input unchanged and the harness then reports
"NOT non-vacuous" about a guard that is fine. See the probe checklist below.

```python
import importlib.util, sys, tempfile
from pathlib import Path
sys.path.insert(0, "scanner/tests")
from _ci_guard_util import apply_mutation

def load(p):
    s = importlib.util.spec_from_file_location("m", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

m = load("scanner/tests/test_ci_coverage_thresholds.py")
orig = m.LINT_YML.read_text()
tmp = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
tmp.write(apply_mutation(orig, "--cov-fail-under=99", "--cov-fail-under=80")); tmp.close()
m.LINT_YML = Path(tmp.name); m.TestCiCoverageThresholds.setUpClass()
try:
    m.TestCiCoverageThresholds().test_python_cov_fail_under_present_and_not_lowered()
    print("NOT non-vacuous (bad)")
except AssertionError as e:
    print("OK: guard fails on mutation ->", str(e).splitlines()[0])
```

```console
$ python3 /tmp/harness.py
OK: guard fails on mutation -> 80 not greater than or equal to 99 : Python
coverage gate lowered to 80% (min allowed 99%). If intentional, update
MIN_PYTHON_COV_FAIL_UNDER in this test and justify in the PR.
```

## Probe checklist — run this before you believe a "GAP"

A **probe** is the throwaway mutation you apply to argue a guard is bypassable.
Across #411 / #415 / #419 / #420 / #424 the probe was wrong **nine** times and
the guard was right every one of them; each near-miss was about to file a false
finding in the catalog or "fix" a correct guard. Probes are not scratch work —
they are the evidence, and they get audited like the guard does.

Work the items in order. Every one names the incident that earned it and how you
would learn the **probe**, not the guard, is what is broken.

1. **Reconcile the contradiction first — it is the signal in every one of these.**
   A probe verdict of "bypass" that coexists with the guard suite reporting
   `16 passed` is not a finding; it is two measurements that cannot both be true,
   and one of them is yours. Stop and resolve which before writing anything down.
   In #420 a probe handed **raw** text straight to the collector, got `None`, and
   called it a bypass — while the same probe's own suite said `16 passed`. The
   suite was right (the immunity was in `setUpClass`; item 5).
   *Probe is wrong if:* you ran the collector but not the guard. Re-run the
   guard's own tests against the same mutant; a green suite outranks a
   hand-called helper, because the guard is what CI executes.

2. **Attack the harness before the code.** Before concluding "gap", state the
   runtime consequence of your mutant: which command now exits 0, which key the
   runner now ignores, which arm is now unreachable. #411's provider-labels probe
   moved a `case` arm to just **before** the `*)` catch-all, where it is still
   perfectly reachable — nothing was disabled, so the guard's green was correct.
   #415 produced five in one audit (arm-before-`*)`; a section **header** edited
   instead of the entry beneath it; a `job_block` case written only for
   end-of-file when the discriminating shape is a following top-level key;
   `if: always()` deleted from a gate whose **comments** quote it verbatim, so
   the repo's own comment-evasion class bit the fixture; text injected onto a
   TestCase attribute that `setUpClass` overwrote from disk).
   *Probe is wrong if:* you cannot name that consequence in one sentence, or the
   sentence is "the guard stopped matching" — that describes the guard, not the
   control.

3. **A mutation the grammar rejects proves nothing.** An invalid document is not
   a bypass: it never runs, so no control was removed. #424 planted a comment at
   the key column inside a folded scalar and filed "3 false positives"; that
   shape is a `ParserError`, and the verdict was void. Measure with PyYAML —
   local ground truth only, never an `import yaml` in a guard (not in
   `requirements-ci.txt`):

   ```python
   import yaml                                        # pyyaml 6.0.3, local only
   yaml.safe_load("a:\n  x: 1\n# c\n  y: 2\n")        # {'a': {'x': 1, 'y': 2}}
   yaml.safe_load("args: >-\n  --one\n  # c\n  --two\n")  # {'args': '--one # c --two'}
   yaml.safe_load("steps:\n  - run: |\n      echo one\n# c\n      echo two\n")  # ParserError
   ```

   A comment ends **nothing** in a mapping (so it can hide keys from a collector
   — a real class), it is **content** in a folded scalar (so pre-stripping
   deletes a live CLI token), and a less-indented one in a block scalar is a
   parse error (so it proves nothing).
   *Probe is wrong if:* `yaml.safe_load(mutant)` raises. Discard the mutant and
   find a valid one; do not file the finding.

4. **Placement inside the block decides the verdict.** Put the mutation where an
   author regrouping keys would — at the **END** of the block it terminates. The
   same comment at the **start** of a job block truncates `steps:` away too,
   trips assertions that have nothing to do with your invariant, and reads as
   "caught" (#419).
   *Probe is wrong if:* the failing assertion names something other than the
   invariant you targeted. That is collateral damage read as detection — the
   guard "caught" a broken document, not your bypass.

5. **"No observable effect" is a measurement, not a conclusion — and the
   immunity is often in the CALLER.** Never file it as a verdict: it explains
   nothing, so the next audit re-investigates from zero and it is how a stale
   "known fine" gets written. #420's collector *was* comment-blind; the guard was
   immune because `setUpClass` builds `cls.text` with
   `strip_comment_lines(cls.raw)` — one line, in the caller, that nothing
   asserted. Check `setUpClass` and every wrapper between your entry point and
   the assertion, then pin the reason where it lives.
   *Probe is wrong if:* you cannot point at the line that provides the immunity.
   Until you can, the verdict is unfinished, not clean.

6. **Prove the harness can produce a RED before trusting a green**
   (ADR-001 Decision 4). Run it against a case you *know* is broken first. The
   #297 audit's first inertness measurement came back green across the board
   because `unittest` re-ran `setUpClass`, which reloaded the real file over the
   injected mutant — the measurement was wrong, not the finding (#415's shape 5
   is the same bug in a fixture).
   *Probe is wrong if:* your known-broken control also reports green. Then the
   harness never reached the code, and every "clean" result it produced is void.

7. **Never hand-roll the substitution — use the helpers, which raise at the
   mistake site.** `str.replace` and `re.sub` both no-op silently on a stale
   anchor (#415 for the literal form, #416 for the regex form). Verified
   signatures in `scanner/tests/_ci_guard_util.py`:

   ```python
   apply_mutation(text, old, new, *, count=1) -> str
   apply_regex_mutation(text, pattern, repl, *, count=1, flags=0) -> str
   assert_disables(detector, clean_text, mutant_text, label="")  # -> mutant findings
   ```

   ```text
   apply_mutation("a b c", "zzz", "q")
     AssertionError: mutation fixture is stale: 'zzz' not found in the target
     text — the file changed under the test, so this case proves nothing
   apply_mutation("exit 1", "exit 1", "exit 1")
     AssertionError: mutation 'exit 1' -> 'exit 1' left the text unchanged
   apply_regex_mutation(two_occurrences, r"-gt 0 \]; then", "-gt 99 ]; then")
     AssertionError: pattern '-gt 0 \\]; then' matched 2 times but count=1 —
     refusing to guess which occurrence the fixture meant. Narrow the pattern,
     or pass the count you intend (0 for all).
   ```

   `apply_regex_mutation` adds the check a literal cannot need — **more matches
   than `count` is an error**, because you can eyeball where a substring occurs
   and cannot eyeball a pattern (`-gt 0 ]; then` occurs twice in the gate;
   a countless `str.replace` changed both while the test name claimed one).
   `assert_disables` pins both directions at once, and its failure message states
   the priority this checklist is built on:

   ```console
   AssertionError: detector did NOT fire on the mutant [probe] — either the guard
   has a gap, or the mutation does not actually disable the control. Check the
   SECOND possibility first (see apply_mutation).
   ```

   Two limits to state in the test rather than assume away: the helpers close
   only the **mechanical** shapes (anchor missing, bytes unchanged) — item 2's
   arm-before-`*)`, end-of-file-only and comment-quoting shapes are **semantic**
   and no helper decides them. And a fixture that **appends** text after
   substituting (`\nfi\n`) differs from the original even when the substitution
   missed, so the differ check is structurally blind to it; #416's stale anchor
   surfaced three steps later as `bash: syntax error near unexpected token 'fi'`.
   Assert the anchor separately in that case.

## Parse/substring guards — the false-negative class

Text matchers share one failure mode: the real control is gone but a protected
token survives in a form the parser mis-reads, so the guard stays **green** and
gives false assurance. ADR-001
(`docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md`) mandates a
two-pass adversarial review here. Two sub-classes, from the #297 audits:

- **Class-1 — comment / quote state.** The token hides in a comment, or the
  quote tracker loses sync. Highest risk: it can disable a check that branch
  protection actually requires (today: `Lint`, `Security Scan Gate`). Two shipped
  instances, same guard, same required gate, different adjacency: #271 F-1
  (`# exit 1`), and `;#exit 1` — still live on main until #376 lands, because
  `conditional_body_from` strips with the whitespace-only regex, so it finds the
  commented-out `exit 1` and stays green while bash exits 0.
- **Class-2 — matcher completeness.** The parser enumerates a few shapes instead
  of modelling the rule, so a plausible edit slips past. Examples: a top-level
  `*)` indented deeper than the first arm (#378); `macOS-14` missed because the
  runner regex was case-sensitive (#379). Both were residuals in the audit's own
  *first fixes*, found by the second pass — not holes in long-shipped guards.

### Picking a stripper

`strip_inline_comment` is whitespace-boundary only (`\s+#`). That is correct for
YAML and Dockerfile lines and **bypassable on shell lines**: bash treats
`echo x;#exit 1` as a comment, the regex leaves it intact. For shell text use
the bash-aware variant (`strip_inline_comment_sh`, landing with #376), whose
boundary set is space, tab, `;` `&` `|` `(` `)` `<` `>` and a backtick.

Adjacency is boundary-specific, so write PoCs from the real grammar, not by
analogy: `x;#c` and `` x`#c` `` are comments, but `$'\''#c` is **not** — after a
closing quote the `#` is literal word text. Verify each form against bash before
you claim it.

### Rules that came out of the audit

- **Model the grammar, not a proxy.** Indentation is not what decides `case` arm
  ownership — `case`/`esac` depth is. A block scalar *is* any `run:` value
  starting with `|`/`>`. A third patch to an enumeration is a redesign signal
  (ADR-001 Decision 5, "Prefer a grammar-complete rule over enumerating forms").
- **A regex can be wrong in both directions at once.** #379's runner regex was
  too narrow (case-sensitive → missed `macOS-latest`) *and* too broad (a genuine
  `windows-1252` charset or `macos-universal` arch token in `run:`/`name:` text
  would trip it — prospective, none in today's `lint.yml`). Fixing one direction
  can worsen the other: bare `re.IGNORECASE` widens the false positives, because
  `windows-1252` and `windows-2022` are shape-identical. When token shape can't
  disambiguate, **scope by context** (`runs-on:` / matrix `os:`) instead.
- **Check word-boundary assumptions.** `\bgrep\b` does not match `egrep`.
- **Classify every residual limit by DIRECTION, and say which.** Over-strip /
  false alarm is documentable — annoying, not dangerous. Under-strip / false
  negative is a **bypass**: fix it. Prove the direction by execution before you
  write it down, because filing an under-strip under an over-strip heading is
  precisely what hid #376's CRITICAL — its docstring listed the unmodelled
  ANSI-C `$'...'` case under "over-strip direction … never a silent security
  bypass" when it was in fact an under-strip.
- **Shipping a known false negative needs an explicit cost argument, not a
  heading.** The bar is high but not infinite, and never for an invariant behind
  a required check. `no_ere_pipe_regression` accepts
  its cross-line variable-indirection gap (`PATTERN="foo\|bar"` on one line,
  `grep -E "$PATTERN"` on another) and documents *why*: the only line-scanner
  rule that would catch it — flag every `\|` in any string assignment — was
  judged worse than the gap, every real occurrence has the `\|` on the same line
  as the ERE consumer, and it records a revisit trigger ("only if an indirection
  instance actually lands") (#379). That is the shape of a defensible exception.
  "It's only over-strip" is not.
- **A fix to this class can create the class.** #376's CRITICAL was introduced
  *by the hardening*: modelling quote state opened a new under-strip **case** —
  ANSI-C — in a matcher that had just closed the naive regex's own under-strips
  (`;#`, `&#`, `` `# ``, all real bash comments it leaves intact). Each version
  gets a different set wrong: the naive one strips the ANSI-C case correctly, the
  modelled one strips `;#` correctly, and even the fixed one over-strips
  `x=$(cmd)#c` where the naive one is right. Neither dominates — re-attack the
  new version on its own terms, not just the old one's known gaps.

### The block collector — the extractor is the matcher's haystack

A matcher can be spelling-perfect and still see nothing, because what it scans is
whatever the block collector returned. Attack the collector first.

**Use the primitives; do not hand-roll.**

- `block_ends_at(line, col)` — whether a line ENDS a mapping/sequence block.
- `key_column(block)` — a block's own key column, ignoring blank AND comment lines.

Both landed 2026-08-11 (#419) after the same bug appeared in five collectors and
five separate `min(indent)` derivations. Three were live bypasses, each one comment
line, each measured against PyYAML on the real file:

```text
npm-publish.yml  column-0 comment under `permissions:`
  PyYAML {'contents': 'read', 'packages': 'write'}    guard 12 passed
security-scan.yml  comment at the gate STEP's dash column
  PyYAML step keys ['continue-on-error', 'name', 'run']  guards 61 passed
security-scan.yml  comment at the `scan` JOB's key column
  PyYAML jobs.scan.continue-on-error = True             guards 61 passed
```

The last two defeated the guards written *for that key*. The first defeated a
whole-block anchor its own comment called "a structural catch-all for any added key
the write-grant scan does not classify" — a catch-all only within what the
extractor RETURNED, and the truncated block really was exactly `contents: read`.

**Match the collector to the grammar it reads.** Measured both ways:

```text
mapping        a:\n  x: 1\n# c\n  y: 2        -> {'a': {'x': 1, 'y': 2}}
block scalar   a:\n  run: |\n    e\n# c\n  e  -> ParserError
```

So a comment ends nothing in a mapping and does not keep a scalar alive either.
`extract_run_block` breaking on such a line is **correct**; "fixing" it for
consistency over-captures shell out of a workflow file — the execution-safety
hazard that guard exists to avoid. Two rules that look inconsistent and are not:
they follow the parser.

**Placement decides a probe's verdict.** The same comment at the START of a job
truncates `steps:` away too, trips unrelated assertions and reads as "caught" — a
false negative in the probe, not the guard. Put it where an author regrouping keys
would: at the END of the block it terminates. (Probe checklist item 4.)

**Re-run the existing mutation tests after fixing a shared primitive, before
reviewing the diff.** Once comments live inside a block, every column derivation
inherits them. #419's second-order defect (a column-2 divider comment dragging
`job_col` to 2, so `_declares(block, 2, key)` looked a level out) surfaced as
`28 passed` → `1 failed`. Static review would not have found it.

**Never file "no observable effect" as a verdict.** It describes a measurement and
explains nothing, which is how a stale "known fine" is written. `dashboard_control_
smoke` was recorded that way and turned out IMMUNE — because `setUpClass` builds
`cls.text` with `strip_comment_lines(cls.raw)`. The immunity was in the **caller**,
one line, unasserted; the collector alone still truncates
(`harness_step_block(RAW, …) -> None` vs `(STRIPPED, …) -> the step`). Find the
reason, then pin it where it lives (#420). (Probe checklist item 5.)

### The inert guard — check the HAYSTACK before the matcher

A subtler failure than a beatable matcher: a guard whose **haystack is the raw
whole file**. Comment the control out and the token is still there, so a
presence assertion stays green — no evasion needed, and it misses a *plain
deletion* too. This is worse than no guard: a reviewer reads the green check as
proof the control is intact.

Two were found by hand in #383 (`npm audit signatures` satisfied by the
workflow's own comments and `echo "::error::…"` strings; `exit 1` satisfied by
any of a dozen unrelated lines). Codifying that triage as an AST meta-guard
(`test_ci_guard_assertion_scoping.py`) then found **seven more** in guards that
had passed review — including both required merge contexts and a
`pull_request_target` fork guard.

- **Never assert presence against the raw text.** Aim at the comment-stripped
  scan the guard already builds, or scope the haystack to the step/block that
  owns the control. A line-anchored regex (`(?m)^\s*token`) also counts as
  scoped — a `#`-commented copy cannot match it.
- **Scope before you match.** `assertIn("exit 1", lint_yml)` is unfixable by any
  amount of stripping — `lint.yml` has a dozen unrelated `exit 1` lines. Bound
  it to the owning block first (balanced `if`/`fi` depth, the `- name:` step),
  then match.
- **Negative assertions are exempt.** Scanning raw text for a FORBIDDEN token
  only over-reports — a false alarm, never a silent bypass.
- **Watch for weak duplicates.** Several guards had a strict aggregate validator
  *and* narrower per-invariant tests that re-checked the raw text for better
  error messages. The narrow ones were inert. Same file, two strictness levels.
- **When you keep finding a shape by hand, ask whether the triage can be a
  guard.** Two hand-found instances became seven automated ones, and the check
  now runs on every new guard.

### Does the guard actually RUN?

Audit the trigger, not just the logic. During #297 the entire follow-on chain
sat on stacked PRs, and `on.pull_request.branches: [main]` meant the two
REQUIRED workflows never fired for a PR whose base was a feature branch —
3 checks instead of 28, with `Lint` and `Security Scan Gate` **absent**. Every
guard was correct and none of them ran.

Note the asymmetry with the #186 lesson before proposing a fix: `paths-ignore`
on a required check blocks merges *permanently* (it never reports for a PR that
does target `main`); removing a `branches:` filter is **strictly additive** and
cannot recreate that. Both are now pinned by `test_ci_pr_trigger_scope.py`.

### Distrust your own verification harness

The first attempt to prove those seven sites inert reported **green across the
board** — the harness injected mutated text into the class attribute, but
`unittest` re-ran `setUpClass`, which reloaded the real file. The measurement
was wrong, not the finding. Before believing a "no problem here" result, prove
the harness can produce a RED: run it against a case you *know* is broken.
(Probe checklist item 6.)

### Adversarial pass — how to run it

Dispatch two `sec-reviewer` passes in parallel (`/team 2:sec-reviewer`, with
`model=opus` — this pass has to reason about bash quote state), each briefed
with a **different lens**, then a second round if the first finds a CRITICAL.
The first fix has repeatedly left a residual hole: #376 took five passes — an
earlier one closed a live gate evasion (`;#exit 1`), the fifth found the ANSI-C
CRITICAL. Neither was the pass that "finished" the guard.

- **False-negative lens**: build a *runnable* PoC where the control is genuinely
  removed yet the guard returns green.
- **False-positive / claim lens**: legit edits that would now trip, self-tests
  that don't exercise the logic, parser crashes, docstring assertions.

Every finding must carry execution evidence on both sides — the real tool's
behaviour (e.g. bash actually treating it as a comment) **and** the consumer
guard function returning "invariant holds". Reasoning alone is not a finding.
**A pass that finds nothing must record the attack set it executed**; a bare
"CLEAN" is not a completed pass.

**When the reviewers disagree, do not take a vote or defer to the more confident
one** — reproduce it yourself and let the execution decide. In #376 a reviewer
that had trusted the docstring for `$'...'` was overruled by running bash plus
the real consumer (`conditional_body_from`). The no-self-approval rule applies
to the *approval* pass; independently reproducing a disputed fact is required,
not a conflict of interest.

## Porting to another repo

The PATTERN is portable; the INVARIANTS are repo-specific. Before porting,
**assess the target repo** (do not assume ClaudeSec's posture):

- **SHA-pin guard** fits only if the repo SHA-pins all `uses:`. Many repos
  tag-pin (`@v6`) — there the guard would fail; SHA-pinning is a prior decision,
  not something the guard can assume. (Observed 2026-06: `sns-monitor` tag-pins.)
- **Aggregator-completeness guard** fits only if the repo has a `lint-gate`-style
  required-check aggregator and branch protection that requires it.
- Match the target repo's **test stack/runner and conventions** (its `CLAUDE.md`
  takes precedence); rewrite the template accordingly — don't copy verbatim.
- Do repo-local work **from that repo's own session**, branch + PR there, and
  verify in **its** CI separately.

Worked example of the adversarial pass above, with the full #376/#378/#379
findings and evidence: `docs/reports/adr-001-q3-audit-retrospective.md`
(landing in #380 — not on disk before that merges).

See also [[reference: docs/devsecops/ci-config-regression-guards.md]] and the
`verify-consumer-end-to-end-path` discipline: prove the guard fails on the real
regression, in the target repo's CI, not just locally.
