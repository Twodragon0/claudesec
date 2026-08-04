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
   not optional for that class — ADR-001 Decision 2.

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

```python
import importlib.util, tempfile
from pathlib import Path
def load(p): 
    s = importlib.util.spec_from_file_location("m", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
m = load("scanner/tests/test_ci_coverage_thresholds.py")
orig = m.LINT_YML.read_text()
tmp = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
tmp.write(orig.replace("--cov-fail-under=99", "--cov-fail-under=80")); tmp.close()
m.LINT_YML = Path(tmp.name); m.TestCiCoverageThresholds.setUpClass()
try:
    m.TestCiCoverageThresholds().test_python_cov_fail_under_present_and_not_lowered()
    print("NOT non-vacuous (bad)")
except AssertionError:
    print("OK: guard fails on mutation")
```

## Parse/substring guards — the false-negative class

Text matchers share one failure mode: the real control is gone but a protected
token survives in a form the parser mis-reads, so the guard stays **green** and
gives false assurance. ADR-001
(`docs/devsecops/adr-001-ci-guard-hardening-and-audit-cadence.md`) mandates a
two-pass adversarial review here. Two sub-classes, from the #297 audits:

- **Class-1 — comment / quote state.** The token hides in a comment, or the
  quote tracker loses sync. Highest risk: it can disable a check that branch
  protection actually requires (today: `Lint`, `Security Scan Gate`). The shipped
  instance was #271 F-1 — a `# exit 1` satisfying the Security Scan Gate's
  merge-block check.
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
  (ADR-001 Decision 4).
- **A regex can be wrong in both directions at once.** #379's runner regex was
  too narrow (case-sensitive → missed `macOS-latest`) *and* too broad (a genuine
  `windows-1252` charset or `macos-universal` arch token in `run:`/`name:` text
  would trip it — prospective, none in today's `lint.yml`). Fixing one direction
  can worsen the other: bare `re.IGNORECASE` widens the false positives, because
  `windows-1252` and `windows-2022` are shape-identical. When token shape can't
  disambiguate, **scope by context** (`runs-on:` / matrix `os:`) instead.
- **Check word-boundary assumptions.** `\bgrep\b` does not match `egrep`.
- **Classify every residual limit by DIRECTION, and say which.** Over-strip
  (false alarm) is a documented known limitation — fine to ship, like the
  cross-line variable indirection in `no_ere_pipe_regression` (documented there
  by #379), where a catching rule would cost more false positives than the gap
  it closes. Under-strip is a **bypass**
  and must be fixed. Documenting a limit is right; documenting it in the wrong
  direction is what hid #376's CRITICAL, whose docstring filed an unmodelled
  ANSI-C `$'...'` case under "over-strip direction … never a silent security
  bypass" when it was in fact an under-strip. Prove the direction by execution
  before you write it down.
- **A fix to this class can create the class.** #376's CRITICAL was introduced
  *by the hardening*: modelling quote state opened an under-strip direction the
  naive whitespace regex never had (the naive one strips that case correctly; it
  misses `;#` instead). Neither matcher dominates — so re-attack the new version
  on its own terms, not just the old one's known gaps.

### Adversarial pass — how to run it

Dispatch two `sec-reviewer` passes in parallel (`/team 2:sec-reviewer`, with
`model=opus` — this pass has to reason about bash quote state), each briefed
with a **different lens**, then a second round if the first finds a CRITICAL.
The first fix has repeatedly left a residual hole: #376 needed five passes, and
the fifth found the CRITICAL.

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
