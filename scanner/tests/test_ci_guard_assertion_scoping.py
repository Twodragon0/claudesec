"""
Meta-guard: no `test_ci_*.py` guard may make a PRESENCE assertion against the
RAW, whole-file text of the artifact it protects.

Why this exists
---------------
A CI config guard has one job: fail when the control it protects is weakened.
The natural regression path is not a clever rewrite — it is **commenting the
control out** ("temporarily disabling" it). A presence assertion aimed at the
raw file text survives that edit, because the token is still in the file:

    cls.text = WORKFLOW.read_text(...)          # raw, never comment-stripped
    ...
    self.assertIn("exit 1", self.text)          # green after the gate is gutted

The guard then reports green while the control is dead. That is worse than
having no guard: a reviewer reads the green check as evidence the control is
intact. The #297 quarterly audit sweep found this shape twice by hand —
`test_ci_provenance_verify.py` (`npm audit signatures` satisfied by four of the
workflow's own comments and two `echo "::error::…"` strings, so a plain deletion
of the real invocation went undetected) and `test_ci_docker_image_size_gate.py`
(`assertIn("exit 1", text)` satisfied by any of `lint.yml`'s dozen unrelated
`exit 1` lines) — both fixed in #383. Hand triage does not scale to 39 guards
and does not run on new ones. This guard makes the shape fail in CI.

What counts as a violation
--------------------------
A **positive presence assertion** — `assertIn(needle, hay)`, `assertRegex(hay,
pat)`, or `assertTrue(needle in hay)` — whose haystack resolves to a name bound
DIRECTLY to a `Path.read_text()` result (i.e. the raw whole file), with no
comment-stripping or block-scoping applied.

Two things are deliberately NOT violations:

1. **Negative** assertions (`assertNotIn` / `assertNotRegex` / `not in`).
   Scanning raw text for a FORBIDDEN token is the strict direction: a token
   living only in a comment produces a false ALARM, never a silent bypass. The
   author is free to strip there, but failing to is not an inert guard.
2. **Line-anchored regexes** — a pattern that begins with `^` (under
   `re.MULTILINE`, explicit `(?m)` or the `assertRegex` default of a `(?m)`
   prefix) followed only by `\\s*`. Such a pattern requires that nothing but
   whitespace precede the token on its line, so a `#`-commented copy cannot
   satisfy it. That IS a scoping mechanism, just an inline one, and several
   guards use it correctly (`(?m)^\\s*schedule:\\s*$`).

Direction / semantics
---------------------
Regression-pin over a KNOWN baseline, the same shape as
`test_ci_scanner_lib_reachability.py` and `test_ci_no_code_injection_regression.py`:
the detected set must EQUAL `KNOWN_RAW_PRESENCE_ASSERTIONS`. A new offender
fails, AND a stale baseline entry fails once the site is fixed — so the
allowlist cannot quietly outlive its justification. The baseline is currently
EMPTY: every site the detector found was fixed in the PR that added this guard.

Detection is AST-based (`ast`, stdlib), not textual, so a reformatted assertion
or a renamed variable does not evade it and a mention inside a docstring does
not false-trip it.

Known limitations (all UNDER-report — the guard can miss a violation, it does
not invent one, so it never false-blocks a PR):
- Only names bound directly to `read_text()` are treated as raw. A raw string
  passed through an identity-like wrapper, or read via `open().read()`, is not
  tracked.
- Block-scoping helpers are recognized only by "the haystack is not a raw name";
  a helper that returns the whole file unchanged would be trusted.
- Cross-module haystacks (a raw text imported from another test module) are not
  followed.

stdlib-only (no PyYAML, no third-party). Does not import `scanner/lib`, so it
never moves the 99% coverage gate. No network, no subprocess. Runs under pytest
(the CI runner) and `python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SP 800-218 (SSDF) PO.3, PW.4.
"""

import ast
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scanner" / "tests"

# Positive presence assertions -> index of the HAYSTACK argument.
PRESENCE_ASSERTIONS = {"assertIn": 1, "assertRegex": 0}

# Sites accepted as-is, `"<file>:<line>:<assertion>"`. EMPTY by design: every
# site found when this guard landed was fixed in the same PR. Adding an entry
# requires a rationale in the catalog row — and the set-equality check below
# fails once the entry is fixed, so a stale exemption cannot linger.
KNOWN_RAW_PRESENCE_ASSERTIONS = frozenset()


def _raw_text_names(tree: ast.AST) -> set:
    """Names bound directly to a `Path.read_text()` result — i.e. raw whole-file
    text with no comment-stripping or scoping applied.

    Recognizes both the bare call and the `read_text(...) if ....is_file() else ""`
    guarded form every guard in this suite uses. A binding whose OUTER expression
    is any other call (`active_text(...)`, `strip_comment_lines(...)`,
    `breach_block(...)`, ...) is treated as processed, not raw.
    """

    def _is_read_text(node) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "read_text"
        )

    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if isinstance(value, ast.IfExp):  # `X.read_text(...) if X.is_file() else ""`
            value = value.body
        if not _is_read_text(value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                names.add(target.attr)  # cls.text / self.text
            elif isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _haystack_name(node: ast.AST):
    """The identifier a haystack expression refers to, or None if it is an
    expression (a call, a slice, a join — i.e. something was applied to it)."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        if node.value.id in ("self", "cls"):
            return node.attr
        return None
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_line_anchored(pattern_node: ast.AST) -> bool:
    """True if the regex literal is anchored to the start of a line with only
    `\\s*` allowed before the token, so a `#`-commented copy cannot match it."""
    if not (isinstance(pattern_node, ast.Constant) and isinstance(pattern_node.value, str)):
        return False
    pat = pattern_node.value
    if pat.startswith("(?m)"):
        pat = pat[4:]
    if not pat.startswith("^"):
        return False
    rest = pat[1:]
    # Only whitespace-matching atoms may sit between `^` and the real token.
    for atom in (r"\s*", r"\s+", r"[ \t]*", r"[ \t]+", " *", " +"):
        if rest.startswith(atom):
            return True
    # A bare `^token` is anchored at column 0 — a comment `#` would precede it.
    return bool(rest) and rest[0] not in ".(["


def raw_presence_assertions(source: str, filename: str) -> list:
    """Every positive presence assertion in `source` aimed at raw whole-file
    text. Returns `"<filename>:<line>:<assertion>"` strings, sorted."""
    tree = ast.parse(source)
    raw_names = _raw_text_names(tree)
    if not raw_names:
        return []

    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        name = node.func.attr

        if name in PRESENCE_ASSERTIONS:
            idx = PRESENCE_ASSERTIONS[name]
            if len(node.args) <= idx:
                continue
            if _haystack_name(node.args[idx]) not in raw_names:
                continue
            # `assertRegex(hay, pat)` with a line-anchored pattern is scoped.
            if name == "assertRegex" and _is_line_anchored(node.args[1]):
                continue
            hits.append(f"{filename}:{node.lineno}:{name}")

        elif name == "assertTrue" and node.args:
            # `assertTrue(needle in hay)` is the same assertion, spelled out.
            cmp_node = node.args[0]
            if (
                isinstance(cmp_node, ast.Compare)
                and len(cmp_node.ops) == 1
                and isinstance(cmp_node.ops[0], ast.In)
                and _haystack_name(cmp_node.comparators[0]) in raw_names
            ):
                hits.append(f"{filename}:{node.lineno}:assertTrue-in")

    return sorted(hits)


def scan_guard_suite() -> list:
    """Every raw-text presence assertion across `scanner/tests/test_ci_*.py`."""
    hits = []
    for path in sorted(TESTS_DIR.glob("test_ci_*.py")):
        hits.extend(raw_presence_assertions(path.read_text(encoding="utf-8"), path.name))
    return sorted(hits)


class TestGuardAssertionScoping(unittest.TestCase):
    def test_guard_files_found(self):
        # Canary: an empty glob would make the pin below pass vacuously.
        self.assertTrue(
            sorted(TESTS_DIR.glob("test_ci_*.py")),
            f"no test_ci_*.py guards found under {TESTS_DIR} — glob/path broke",
        )

    def test_no_new_raw_text_presence_assertion(self):
        found = set(scan_guard_suite())
        new = sorted(found - KNOWN_RAW_PRESENCE_ASSERTIONS)
        self.assertEqual(
            new,
            [],
            "Inert guard assertion(s): a positive presence check aimed at the RAW "
            "whole-file text of the protected artifact.\n  "
            + "\n  ".join(new)
            + "\n\nCommenting the control out leaves the token in the file, so the "
            "assertion stays green while the control is dead — the reviewer reads "
            "the green check as proof the control is intact.\n"
            "Fix: assert against the comment-stripped scan the guard already "
            "builds (`strip_comment_lines` + `strip_inline_comment_sh` for shell, "
            "`strip_inline_comment` for YAML/Dockerfile), or scope the haystack to "
            "the specific step/block that owns the control. A line-anchored regex "
            r"(`(?m)^\s*token`) also counts as scoped.",
        )

    def test_baseline_has_no_stale_entries(self):
        found = set(scan_guard_suite())
        stale = sorted(KNOWN_RAW_PRESENCE_ASSERTIONS - found)
        self.assertEqual(
            stale,
            [],
            "Stale KNOWN_RAW_PRESENCE_ASSERTIONS entries (site fixed or moved):\n  "
            + "\n  ".join(stale)
            + "\n\nRemove them so the allowlist keeps meaning what it says.",
        )


class TestDetectorMutation(unittest.TestCase):
    """Mutation self-tests: the detector must fire on the real shapes the #297
    sweep found by hand, and stay quiet on the correctly-scoped ones."""

    _HEADER = (
        "class T(unittest.TestCase):\n"
        "    @classmethod\n"
        "    def setUpClass(cls):\n"
        "        cls.text = WORKFLOW.read_text(encoding='utf-8')\n"
    )

    def _scan(self, body: str) -> list:
        return raw_presence_assertions(self._HEADER + body, "synthetic.py")

    def test_docker_size_gate_shape_is_detected(self):
        # The real #383 finding: `exit 1` satisfied by any unrelated line.
        hits = self._scan(
            "    def test_gate(self):\n"
            "        self.assertIn('exit 1', self.text)\n"
        )
        self.assertTrue(hits, "unscoped assertIn over raw file text NOT detected")

    def test_provenance_shape_is_detected(self):
        # The other #383 finding: a bare regex satisfied by the workflow's own
        # comments and `echo` strings.
        hits = self._scan(
            "    def test_audit(self):\n"
            "        self.assertRegex(self.text, r'npm audit signatures')\n"
        )
        self.assertTrue(hits, "unanchored assertRegex over raw file text NOT detected")

    def test_assert_true_in_form_is_detected(self):
        hits = self._scan(
            "    def test_gate(self):\n"
            "        self.assertTrue('exit 1' in self.text)\n"
        )
        self.assertTrue(hits, "`assertTrue(x in raw)` NOT detected")

    def test_local_raw_variable_is_detected(self):
        hits = raw_presence_assertions(
            "class T(unittest.TestCase):\n"
            "    def test_gate(self):\n"
            "        body = WORKFLOW.read_text(encoding='utf-8')\n"
            "        self.assertIn('exit 1', body)\n",
            "synthetic.py",
        )
        self.assertTrue(hits, "raw text bound to a LOCAL variable NOT detected")

    def test_stripped_haystack_is_not_flagged(self):
        hits = raw_presence_assertions(
            self._HEADER
            + "        cls.scan = active_text(cls.text)\n"
            "    def test_gate(self):\n"
            "        self.assertIn('exit 1', self.scan)\n",
            "synthetic.py",
        )
        self.assertEqual(hits, [], "a comment-stripped haystack must not be flagged")

    def test_scoped_block_haystack_is_not_flagged(self):
        hits = self._scan(
            "    def test_gate(self):\n"
            "        self.assertRegex(breach_block(self.text), r'exit 1')\n"
        )
        self.assertEqual(hits, [], "a block-scoped haystack must not be flagged")

    def test_line_anchored_regex_is_not_flagged(self):
        # `(?m)^\s*schedule:` cannot match a `# schedule:` line, so it is scoped.
        hits = self._scan(
            "    def test_sched(self):\n"
            "        self.assertRegex(self.text, r'(?m)^\\s*schedule:\\s*$')\n"
        )
        self.assertEqual(hits, [], "a line-anchored regex must not be flagged")

    def test_negative_assertion_is_not_flagged(self):
        # FORBIDDEN-token direction: raw scanning only over-reports.
        hits = self._scan(
            "    def test_no_admin(self):\n"
            "        self.assertNotIn('--admin', self.text)\n"
        )
        self.assertEqual(hits, [], "a negative assertion must not be flagged")

    def test_mention_in_a_docstring_is_not_flagged(self):
        hits = self._scan(
            "    def test_doc(self):\n"
            "        '''Do not write self.assertIn(\"exit 1\", self.text) here.'''\n"
            "        self.assertIn('exit 1', active_text(self.text))\n"
        )
        self.assertEqual(hits, [], "AST parsing must ignore prose in a docstring")

    def test_file_without_read_text_yields_nothing(self):
        hits = raw_presence_assertions(
            "class T(unittest.TestCase):\n"
            "    def test_x(self):\n"
            "        self.assertIn('a', 'abc')\n",
            "synthetic.py",
        )
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
