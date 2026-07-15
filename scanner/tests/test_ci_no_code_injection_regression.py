"""
Regression guard: no CWE-94 (OWASP A03:2021 – Injection) code-injection sites
where a bash variable is interpolated DIRECTLY into a `python3 -c "..."` /
`python -c "..."` program body.

THE RISK
--------
`python3 -c "... $VAR ... "` splices the shell variable's *text* into the
Python source before it is parsed. If that value can ever contain a quote,
backslash, or other Python-meaningful character (attacker-controlled input,
a path with unexpected characters, a stray `'` in upstream data), the
interpolation breaks out of its intended literal and executes as arbitrary
Python — a classic CWE-94 code-injection bug, catalogued under OWASP
A03:2021 (Injection): https://owasp.org/Top10/A03_2021-Injection/. The fix
(landed in #346 for `output_prowler.sh` / `prowler_compliance_summary.py`,
and in the PR pairing with this guard for `scripts/run-prowler-k8s.sh`,
`scripts/check-prowler-python-ceiling.sh`, and
`scripts/sync-scan-to-dashboard.sh`) is to pass the value through the process
ENVIRONMENT — `VAR="$value" python3 -c "..."` and `os.environ['VAR']` inside
the program — so the `-c` argument text is a constant with no `$` in it and
the value can never be re-parsed as Python source.

WHAT THIS GUARD CHECKS
-----------------------
For every production shell file under `scanner/claudesec`, `scanner/lib/**/*.sh`,
`scanner/checks/**/*.sh`, `scripts/**/*.sh`, and `hooks/**/*.sh` (whichever
exist), it locates every `python3 -c "..."` / `python -c "..."` invocation
whose `-c` argument is DOUBLE-quoted, captures the program text up to the
matching (unescaped) closing double quote — programs commonly span multiple
lines, so the file is scanned as one joined text, not line-by-line — and
flags the site if that captured body contains ANY unescaped `$`. Whole-line
`#` comments are stripped first (via the shared `strip_comment_lines` helper)
so a `$VAR` surviving only in a comment cannot trip the guard.

Detection rule: "any unescaped `$`" (hardened; see below)
-----------------------------------------------------------
Inside a bash double-quoted string, an unescaped `$` ALWAYS begins an
expansion — there is no double-quoted context where a bare `$` is inert. That
covers not just the named/braced/command-substitution forms (`$NAME`,
`${...}`, `$(...)`) but every positional and special parameter too: `$1`..`$9`,
`$0`, `$@`, `$*`, `$#`, `$?`, `$$`, `$!`, `$-`. An earlier version of this
guard enumerated only the named/braced/substitution shapes and MISSED the
positional/special-parameter forms — demonstrated live via
`set -- alpha; python3 -c "print('$1')"`, which leaks `alpha` into the Python
program exactly like `$NAME` would. The single "any unescaped `$`" rule
(`has_unescaped_dollar`) subsumes all of these in one check and cannot repeat
that miss. A `\\$` (backslash-escaped literal dollar) is correctly excluded.

Regression-pin semantics
-------------------------
The computed violation set (`"relpath:construct"`, one entry per offending
site, `construct` being the sorted, comma-joined distinct `$`-expansions found
in that body) must EQUAL the baseline `KNOWN_INJECTION_SITES`. After the
paired fix PR, that baseline is the empty `set()` — i.e. this guard asserts NO
interpolated `python3 -c` double-quoted program remains in the repo. A NEW
site fails the guard immediately (not silently mergeable); shrinking the
baseline without fixing the site would also fail (keeps the allowlist honest).
Adding an entry back to `KNOWN_INJECTION_SITES` must be accompanied by a
one-line justification comment — this guard exists specifically so that does
not happen silently.

Detection is conservative / what's OUT OF SCOPE
------------------------------------------------
This guard intentionally only covers ONE construct family and is NOT a full
injection scanner:
  * `python3 -c '...'` (SINGLE-quoted `-c` argument) is SAFE and NOT flagged —
    bash does not expand `$` inside single quotes, so nothing is interpolated.
  * Values passed as `argv` (`python3 -c "..." "$value"`, read via
    `sys.argv[1]`), via `stdin` (`echo "$x" | python3 -c "..."`, read via
    `sys.stdin`), or via the environment (`VAR="$x" python3 -c "..."`, read
    via `os.environ`) are the SAFE patterns this guard's fix moves callers
    toward, and are never flagged — the `-c` body itself contains no `$`.
  * `awk -v var=... '...'`, quoted heredocs (`<<'EOF'`), and any other
    interpreter invocation are OUT OF SCOPE — this guard looks only at
    `python3 -c "` / `python -c "` sites.
  * An UNquoted heredoc that feeds a script into `python3` (`python3 <<EOF`
    without quoting `EOF`) is a structurally identical CWE-94 risk (bash
    expands `$` inside it too) but is NOT detected here — this guard's regex
    is anchored on the `-c "..."` invocation form only. Treat that as a known
    gap, not a covered case, when auditing new code.
  * A `-c` argument built from adjacent CONCATENATED bash segments — quoted
    and unquoted back to back with no space, e.g. `"..."unquoted"$VAR..."`
    (bash treats adjacent quoted/unquoted/quoted runs with no separating
    whitespace as ONE argument) — is only scanned up to the FIRST unescaped
    closing `"` of the opening segment. Interpolation living in a later
    concatenated segment is not detected: this guard's capture is a single
    quoted-string match, not a full shell-word tokenizer. This construct is
    non-idiomatic and not present anywhere in the current repo, but it is a
    real blind spot — do not treat this guard as full coverage against it.

stdlib-only (no PyYAML). No `scanner/lib` import (does not touch the 99%
coverage gate). No network, no subprocess. Runs under pytest (the CI runner)
and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]

# Shared guard primitive (whole-line comment stripping). Import as a top-level
# module so it resolves under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

# Matches a `python3 -c "..."` / `python -c "..."` invocation whose `-c`
# argument is DOUBLE-quoted, capturing the program text up to the matching
# unescaped closing `"`. re.DOTALL so the body can span multiple lines (the
# common case for these blocks). The alternation `\\.|[^"\\]` is the standard
# "escaped-quoted-string" idiom: an escaped char, or any char that is neither
# a backslash nor an unescaped closing quote.
_PYC_RE = re.compile(r'python3?\s+-c\s+"((?:\\.|[^"\\])*)"', re.DOTALL)

# The ACTUAL violation condition: any `$` in the captured body that is NOT
# immediately preceded by a backslash. Inside a bash double-quoted string this
# is exactly the set of characters that begin an expansion — there is no
# unescaped `$` that stays inert. Strictly more robust than enumerating shapes
# (the pre-hardening detector matched only `$NAME`/`${...}`/`$(...)`), because
# it also catches positional (`$1`) and special (`$@`, `$*`, `$#`, `$?`, `$$`,
# `$!`, `$-`) parameters that a named/braced/substitution-only regex misses.
_UNESCAPED_DOLLAR_RE = re.compile(r"(?<!\\)\$")

# Recognizable expansion TOKEN shapes, used only to render a readable
# `relpath:construct` string in the violation report — NOT the detection
# condition (that is `_UNESCAPED_DOLLAR_RE`/`has_unescaped_dollar`, above).
# Covers named vars, `${...}`, `$(...)`, and every positional/special
# parameter. `${[^}]*}` and `$([^)]*)` are deliberately non-nested (sufficient
# for the flat interpolations this guard targets; a nested `${a:-$(b)}` would
# still match on its outer/inner boundary and still flag the site).
_DOLLAR_TOKEN_RE = re.compile(
    r"(?<!\\)\$(?:\{[^}]*\}|\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])"
)

# Regression baseline. MUST be empty after the paired fix PR — a non-empty
# entry here means a real CWE-94 site was found and deliberately deferred
# (each entry must carry a justification comment; none currently do because
# none should exist).
KNOWN_INJECTION_SITES = set()


def find_double_quoted_c_bodies(text: str) -> list:
    """The captured program-body text of every double-quoted `python3 -c "..."`
    / `python -c "..."` site in `text`, in document order."""
    return _PYC_RE.findall(text)


def has_unescaped_dollar(body: str) -> bool:
    """True if `body` contains ANY unescaped `$` — the actual violation
    condition (see module docstring / `_UNESCAPED_DOLLAR_RE`). This is the
    function `compute_violations` uses to decide whether a site is flagged;
    it subsumes named vars, `${...}`, `$(...)`, and every positional/special
    parameter in one rule, so it cannot repeat the enumerated-shape miss that
    let `$1`/`$@` slip through the pre-hardening detector."""
    return bool(_UNESCAPED_DOLLAR_RE.search(body))


def violating_constructs(body: str) -> list:
    """The recognizable `$`-expansion TOKENS found in one captured `-c`
    program body (empty list if none match a known shape) — used only to
    render a human-readable `relpath:construct` report string. Does NOT
    decide whether the site is a violation; `has_unescaped_dollar` does. An
    unescaped `$` in a shape none of the known tokens match (rare) would still
    be flagged by `has_unescaped_dollar` even if this returns an empty list —
    `compute_violations` falls back to a placeholder construct in that case."""
    return _DOLLAR_TOKEN_RE.findall(body)


def _production_files() -> list:
    """Every production shell file this guard scans (whichever dirs exist)."""
    files = []
    entry = REPO_ROOT / "scanner" / "claudesec"
    if entry.is_file():
        files.append(entry)
    for sub in ("scanner/lib", "scanner/checks", "scripts", "hooks"):
        d = REPO_ROOT / sub
        if d.is_dir():
            files += sorted(d.rglob("*.sh"))
    return files


def compute_violations(files) -> tuple:
    """Returns (violations, total_sites) — `violations` is the
    `"relpath:construct"` set, `total_sites` is the count of ALL double-quoted
    `python3 -c` sites scanned (violating or not), for the non-vacuity check."""
    violations = set()
    total_sites = 0
    for f in files:
        text = strip_comment_lines(Path(f).read_text(encoding="utf-8"))
        for body in find_double_quoted_c_bodies(text):
            total_sites += 1
            if has_unescaped_dollar(body):
                rel = str(Path(f).resolve().relative_to(REPO_ROOT))
                tokens = violating_constructs(body)
                construct = ",".join(sorted(set(tokens))) if tokens else "$<unrecognized-shape>"
                violations.add(f"{rel}:{construct}")
    return violations, total_sites


class TestNoCodeInjectionRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = _production_files()

    def test_scan_set_nonempty(self):
        # If no production files were found, the path assumptions broke —
        # fail loudly rather than vacuously passing the injection scan below.
        self.assertTrue(
            self.files,
            "No production shell files found to scan — check the "
            "scanner/claudesec, scanner/lib, scanner/checks, scripts, hooks "
            "path assumptions in _production_files().",
        )

    def test_parsed_non_trivial_number_of_sites(self):
        # Canary: if the `-c "..."` regex/paths broke, this would silently
        # find zero sites and the assertion below would vacuously pass.
        _, total_sites = compute_violations(self.files)
        self.assertGreater(
            total_sites, 10,
            "Parsed suspiciously few `python3 -c \"...\"` sites across the "
            "repo — the detection regex or file paths likely broke.",
        )

    def test_no_new_injection_site(self):
        violations, _ = compute_violations(self.files)
        new_violations = violations - KNOWN_INJECTION_SITES
        self.assertEqual(
            new_violations, set(),
            "NEW CWE-94 code-injection site(s) — a bash variable is "
            "interpolated directly into a `python3 -c \"...\"` program body "
            f"(OWASP A03:2021): {sorted(new_violations)}. Fix by passing the "
            "value through the environment (`VAR=\"$val\" python3 -c \"...\"` "
            "+ `os.environ['VAR']` inside the program) instead of splicing "
            "`$VAR`/`${...}`/`$(...)` into the program text.",
        )

    def test_no_stale_allowlist_entry(self):
        violations, _ = compute_violations(self.files)
        stale = KNOWN_INJECTION_SITES - violations
        self.assertEqual(
            stale, set(),
            f"KNOWN_INJECTION_SITES lists site(s) that are no longer "
            f"violations: {sorted(stale)} (fixed, or file removed/changed). "
            "Drop them from KNOWN_INJECTION_SITES so the baseline stays "
            "honest.",
        )


class TestInjectionDetectorMutation(unittest.TestCase):
    """Non-vacuity: the detector must FIRE on the unsafe interpolated form and
    stay QUIET on the safe single-quoted / argv / stdin / env-var forms."""

    def test_fires_on_dollar_var(self):
        body = "\n".join(["import json, os", "print(open('$OUTPUT_DIR/f.json'))"])
        self.assertTrue(
            has_unescaped_dollar(body),
            "Mutation FAILED: a bare `$VAR` interpolation was not detected.",
        )

    def test_fires_on_braced_var(self):
        body = "print('${CONTEXT}')"
        self.assertTrue(
            has_unescaped_dollar(body),
            "Mutation FAILED: a `${VAR}` interpolation was not detected.",
        )

    def test_fires_on_command_substitution(self):
        body = "print('$(date)')"
        self.assertTrue(
            has_unescaped_dollar(body),
            "Mutation FAILED: a `$(...)` command substitution was not "
            "detected.",
        )

    def test_fires_on_positional_param(self):
        # Gap 1 (HIGH, coordinator-found): `$1` was missed by the
        # pre-hardening enumerated-shape regex. Verified live:
        # `set -- alpha; python3 -c "print('$1')"` leaks `alpha`.
        body = "print('$1')"
        self.assertTrue(
            has_unescaped_dollar(body),
            "Mutation FAILED: positional parameter `$1` was not detected — "
            "this is the exact false-negative found in adversarial review.",
        )

    def test_fires_on_special_param_at(self):
        # Gap 1 (HIGH): `$@` (and `$*`, `$#`, `$?`, `$$`, `$!`, `$-`) are
        # special parameters bash also expands inside double quotes; the
        # enumerated-shape regex missed these too.
        body = "print('$@')"
        self.assertTrue(
            has_unescaped_dollar(body),
            "Mutation FAILED: special parameter `$@` was not detected — "
            "this is the exact false-negative found in adversarial review.",
        )

    def test_quiet_on_escaped_dollar(self):
        # A backslash-escaped `\$` is a LITERAL dollar sign — bash does not
        # expand it inside the double-quoted -c argument, so it must not be
        # flagged.
        body = "print('\\$5.00')"
        self.assertFalse(
            has_unescaped_dollar(body),
            "False positive: an escaped `\\$` (literal dollar) was flagged "
            "as an expansion.",
        )

    def test_quiet_on_env_var_read(self):
        # The documented-safe fix: no `$` in the body at all.
        body = "\n".join(["import json, os", "print(open(os.environ['OCSF_FILE']))"])
        self.assertFalse(
            has_unescaped_dollar(body),
            "False positive: a body reading os.environ (the safe fix) was "
            "flagged.",
        )

    def test_quiet_on_single_quoted_c_argument(self):
        # A single-quoted -c argument must not even be captured as a site —
        # bash never expands $ inside single quotes.
        text = "python3 -c 'import os; print(os.environ[\"X\"])' 2>/dev/null"
        self.assertEqual(
            find_double_quoted_c_bodies(text), [],
            "False positive: a single-quoted `-c` argument was captured as "
            "a double-quoted site.",
        )

    def test_multiline_double_quoted_body_captured(self):
        # Programs typically span multiple lines between the opening
        # `-c "` and the closing `"` — the DOTALL capture must span them.
        text = 'python3 -c "\nimport os\nprint(os.environ[\'X\'])\n" 2>/dev/null'
        bodies = find_double_quoted_c_bodies(text)
        self.assertEqual(len(bodies), 1)
        self.assertIn("import os", bodies[0])

    def test_comment_only_reference_does_not_flag(self):
        # A `$VAR` mentioned only in a whole-line `#` comment (stripped before
        # scanning) must not be captured as part of a program body at all —
        # simulated here by confirming strip_comment_lines removes it.
        text = "\n".join(
            [
                '# see $OUTPUT_DIR for context, not interpolated below',
                'python3 -c "import os; print(os.environ[\'OCSF_FILE\'])"',
            ]
        )
        stripped = strip_comment_lines(text)
        bodies = find_double_quoted_c_bodies(stripped)
        self.assertEqual(len(bodies), 1)
        self.assertFalse(has_unescaped_dollar(bodies[0]))

    def test_real_repo_baseline_matches(self):
        # Full end-to-end check against the real production corpus, isolated
        # from the class-level test above so a fixture regression here can be
        # diagnosed independently.
        violations, _ = compute_violations(_production_files())
        self.assertEqual(
            violations, KNOWN_INJECTION_SITES,
            f"Live scan violations {sorted(violations)} do not match "
            f"KNOWN_INJECTION_SITES {sorted(KNOWN_INJECTION_SITES)}.",
        )


if __name__ == "__main__":
    unittest.main()
