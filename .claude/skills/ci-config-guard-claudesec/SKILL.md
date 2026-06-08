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
- Avoid regexes that also match **commentary** in the workflow YAML.

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

See also [[reference: docs/devsecops/ci-config-regression-guards.md]] and the
`verify-consumer-end-to-end-path` discipline: prove the guard fails on the real
regression, in the target repo's CI, not just locally.
