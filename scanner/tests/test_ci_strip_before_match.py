"""
Meta-guard: a guard must COMMENT-STRIP before it MATCHES — including when the
match is a block boundary, and including inside the guard's own helper functions.

Why this exists
---------------
`test_ci_guard_assertion_scoping.py` covers the *inert* shape: an assertion aimed
at raw whole-file text. This guard covers the shape one level down, in the
helpers that build the haystack. Both defects it detects were found by hand in
the 2026-08-07 stripper/haystack audit, each with a runnable PoC on the real tool
AND on the consumer guard:

- **A — matched on the raw input.** `test_ci_security_gate.conditional_body_from`
  comment-stripped the BODY it returned but searched for the block ANCHOR in the
  raw text. One comment line —
  `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi` — therefore anchored the scan
  inside itself and handed back ` exit 1; ` as the block body. Bash exited 0 on a
  CRITICAL finding (merge allowed) while the guard behind the REQUIRED
  `Security Scan Gate` reported the merge block intact.

- **B — extracted before stripping.** `test_ci_compose_dashboard_hardening`
  called `_strip_comments(_dashboard_block(text))`. The service terminator has to
  match a bare `  redis:` line, so a sibling written `  redis:  # cache sidecar`
  never terminated the dashboard block, and the sibling's hardening directives
  satisfied the dashboard's. Reproduced on the real `docker-compose.yml`: with
  every directive deleted from the dashboard service, `missing_directives`
  returned `[]`.

A comment can move a BLOCK BOUNDARY exactly as it can satisfy a token check, and
a boundary that moves silently enlarges or shrinks the haystack. That is ADR-001
§2 ("scope the haystack, strip then match") applied to the helper layer.

What this guard does NOT claim
------------------------------
It does not detect OVER-STRIPPING in general. There is no static notion of "the
control", so the property "a stripper must never remove a line containing the
token the guard later asserts on" is not just unenforceable, it is FALSE by
design: removing exactly those lines — a `#`-commented copy, an `exit 1` from
another job — is what scoping is for. What is mechanizable is the ORDERING
PRECONDITION, and that is what this checks. Everything else in that class stays
a review obligation (ADR-001 §3).

Direction / semantics
---------------------
Regression-pin over a KNOWN baseline, the shape of
`test_ci_guard_assertion_scoping.py`: the detected set must EQUAL
`KNOWN_STRIP_ORDER_EXCEPTIONS`. A new offender fails, and a stale exemption fails
once the site is fixed. The baseline is EMPTY: every site found when this guard
landed was fixed in the same PR.

Known limitations (all UNDER-report — it can miss a violation, never invent one):
- A parameter reassigned to a stripped value anywhere in the function is treated
  as sanitized for the whole function, so a match placed BEFORE that assignment
  is not flagged.
- Stripper aliases are resolved within one module only; a wrapper imported from
  another test module is not followed.
- Only `re` matchers (`search`/`match`/`findall`/`finditer`/`fullmatch`) count as
  matching. A hand-rolled `str.find`/`startswith` boundary scan is not tracked.
- An extractor that also READS its own text (`read_text`/`open`/`glob`) is
  excluded from detector B, because that is how a file *reader* is written and
  flagging those produced the only two false positives this detector has ever
  had. An extractor that both reads and narrows would therefore be missed.

stdlib-only (`ast`); no PyYAML, no `scanner/lib` import, no network, no
subprocess. Runs under pytest (the CI runner) and `python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SP 800-218 (SSDF) PO.3, PW.4.
"""

import ast
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "scanner" / "tests"
SHARED_UTIL = TESTS_DIR / "_ci_guard_util.py"

# The canonical comment-stripping primitives. Module-local wrappers around them
# (`active_text`, `_strip_comments`, ...) are resolved automatically, so a
# renamed helper does not fall out of scope.
CANONICAL_STRIPPERS = frozenset(
    {
        "strip_comment_lines",
        "strip_inline_comment",
        "strip_inline_comment_sh",
        "strip_html_comments",
        "non_comment_lines",
    }
)

RE_MATCHERS = frozenset({"search", "match", "findall", "finditer", "fullmatch"})

# Calls that SOURCE text or files rather than narrow it. A function using one is
# a reader, not an extractor, so `strip_x(read_y(...))` is the correct order, not
# a defect. Without this the detector fired on `_upgrade_lines(self._text(name))`
# and `compute_violations(_production_files())` — both harmless, and both found
# by running it against the real suite.
TEXT_SOURCE_CALLS = frozenset({"read_text", "open", "glob", "rglob", "iterdir", "walk"})

# Accepted sites, `"<file>:<line>:<detector>"`. EMPTY by design. An entry needs a
# rationale in the catalog row, and the set-equality check below fails once the
# entry is fixed, so a stale exemption cannot linger. A legitimate exception
# exists: an extractor whose boundaries ARE comments (a `# NET-005` banner)
# genuinely must run before stripping.
#
# CLEARED 2026-08-08. The single entry this ever held —
# `test_ci_security_gate.py:53:match-on-raw-param`, `conditional_body_from`
# searching the block ANCHOR in raw text while comment-stripping only the body it
# returned — is gone because the FUNCTION is gone, not because it was patched.
# Three successive line-scanner fixes were each defeated (1 shape, then 4, then
# 6), so the invariant moved to a behavioural check that executes the gate
# (`test_ci_security_gate_behaviour.py`), and the text version was deleted rather
# than kept as a second, weaker proof. Deleting the defective consumer is a valid
# way to clear an entry here — arguably the only one that scales.
KNOWN_STRIP_ORDER_EXCEPTIONS = frozenset()


def _call_name(node) -> str:
    """The callee name of a Call (`f(...)` -> 'f', `a.b(...)` -> 'b'), else ''."""
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _module_strippers(tree: ast.AST) -> set:
    """Every name that yields comment-stripped text in this module: the canonical
    primitives plus local functions that (transitively) call one, to a fixed
    point. A guard's `active_text = "\\n".join(strip_inline_comment_sh(...))`
    counts as a stripper for its callers."""
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    strippers = set(CANONICAL_STRIPPERS)
    changed = True
    while changed:
        changed = False
        for name, node in funcs.items():
            if name in strippers:
                continue
            if any(_call_name(c) in strippers for c in ast.walk(node) if isinstance(c, ast.Call)):
                strippers.add(name)
                changed = True
    return strippers


def _sanitized_params(fn: ast.FunctionDef, strippers: set) -> set:
    """Parameters reassigned to a stripped value (`text = active_text(text)`)."""
    out = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        if not any(_call_name(c) in strippers for c in ast.walk(node.value) if isinstance(c, ast.Call)):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                out.add(target.id)
    return out


def _match_haystack(call: ast.Call):
    """The haystack argument of an `re` matcher call, or None if not one.

    `re.search(pat, hay)` puts the haystack second; a precompiled
    `RX.search(hay)` puts it first."""
    if _call_name(call) not in RE_MATCHERS or not isinstance(call.func, ast.Attribute):
        return None
    base = call.func.value
    idx = 1 if isinstance(base, ast.Name) and base.id == "re" else 0
    return call.args[idx] if len(call.args) > idx else None


def strip_order_violations(source: str, filename: str) -> list:
    """Every strip-after-match ordering defect in `source`, as sorted
    `"<filename>:<line>:<detector>"` strings."""
    tree = ast.parse(source)
    strippers = _module_strippers(tree)
    local_funcs = {
        n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
    }
    extractors = {
        name
        for name, node in local_funcs.items()
        if (node.args.args or node.args.kwonlyargs)
        and not any(
            _call_name(c) in TEXT_SOURCE_CALLS
            for c in ast.walk(node)
            if isinstance(c, ast.Call)
        )
    }
    hits = []

    # A — a stripping function that matches on its own RAW parameter.
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        params = {a.arg for a in fn.args.args + fn.args.kwonlyargs} - {"self", "cls"}
        params -= _sanitized_params(fn, strippers)
        if not params:
            continue
        calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)]
        if not any(_call_name(c) in strippers for c in calls):
            continue  # the function never strips: its caller owns that decision
        for call in calls:
            hay = _match_haystack(call)
            if isinstance(hay, ast.Name) and hay.id in params:
                hits.append(f"{filename}:{call.lineno}:match-on-raw-param")

    # B — a stripper wrapped AROUND a local extractor, i.e. the extractor drew
    # its boundaries on un-stripped text.
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        if _call_name(call) not in strippers:
            continue
        for arg in call.args:
            inner = _call_name(arg)
            if inner in extractors and inner not in strippers:
                hits.append(f"{filename}:{call.lineno}:strip-after-extract")

    return sorted(hits)


def scanned_files() -> list:
    """The guard suite plus the shared primitives module."""
    return sorted(TESTS_DIR.glob("test_ci_*.py")) + (
        [SHARED_UTIL] if SHARED_UTIL.is_file() else []
    )


def scan_guard_suite() -> list:
    hits = []
    for path in scanned_files():
        hits.extend(strip_order_violations(path.read_text(encoding="utf-8"), path.name))
    return sorted(hits)


class TestStripBeforeMatch(unittest.TestCase):
    def test_scanned_files_found(self):
        # Canary: an empty scan would make the pin below pass vacuously.
        names = [p.name for p in scanned_files()]
        self.assertTrue(names, f"no guard files found under {TESTS_DIR}")
        self.assertIn(
            "_ci_guard_util.py",
            names,
            "the shared primitives module dropped out of scope — it is the "
            "highest-value file here (every guard imports it)",
        )

    def test_no_new_strip_order_violation(self):
        found = set(scan_guard_suite())
        new = sorted(found - KNOWN_STRIP_ORDER_EXCEPTIONS)
        self.assertEqual(
            new,
            [],
            "Strip-after-match ordering defect(s):\n  "
            + "\n  ".join(new)
            + "\n\nA `#` comment must not be able to satisfy a token check OR move "
            "a block boundary. Apply the comment stripper to the WHOLE input "
            "before searching for an anchor, and strip BEFORE an extractor cuts "
            "the block out — not after.\n"
            "  match-on-raw-param : `m = re.search(anchor, text)` then stripping "
            "only the slice -> strip `text` first, then search.\n"
            "  strip-after-extract: `strip_x(extract_y(text))` -> "
            "`extract_y(strip_x(text))`.\n"
            "If the extractor's boundaries are themselves comments (a `# NET-005` "
            "banner), add the site to KNOWN_STRIP_ORDER_EXCEPTIONS with a "
            "rationale in the catalog row.",
        )

    def test_baseline_has_no_stale_entries(self):
        found = set(scan_guard_suite())
        stale = sorted(KNOWN_STRIP_ORDER_EXCEPTIONS - found)
        self.assertEqual(
            stale,
            [],
            "Stale KNOWN_STRIP_ORDER_EXCEPTIONS entries (site fixed or moved):\n  "
            + "\n  ".join(stale)
            + "\n\nRemove them so the allowlist keeps meaning what it says.",
        )


class TestDetectorMutation(unittest.TestCase):
    """Non-vacuity: the detector must fire on the two real 2026-08-07 shapes and
    stay quiet on the fixed forms. Both baselines are empty, so without these the
    guard could pass because it detects nothing at all."""

    _HEADER = (
        "import re\n"
        "def strip_comment_lines(t):\n    return t\n"
        "def strip_inline_comment_sh(t):\n    return t\n"
    )

    def _scan(self, body: str) -> list:
        return strip_order_violations(self._HEADER + body, "synthetic.py")

    def test_security_gate_shape_is_detected(self):
        # The real H1: anchor searched in the raw text, only the slice stripped.
        hits = self._scan(
            "def conditional_body_from(text, var):\n"
            "    m = re.search(r'anchor', text)\n"
            "    rest = '\\n'.join(strip_inline_comment_sh(l) "
            "for l in text[m.end():].splitlines())\n"
            "    return rest\n"
        )
        self.assertTrue(
            [h for h in hits if h.endswith("match-on-raw-param")],
            "a match on the RAW parameter of a stripping function was NOT detected",
        )

    def test_compose_shape_is_detected(self):
        # The real B: `strip(extract(text))`.
        hits = self._scan(
            "def _dashboard_block(text):\n    return text\n"
            "def missing_directives(text):\n"
            "    block = strip_comment_lines(_dashboard_block(text))\n"
            "    return block\n"
        )
        self.assertTrue(
            [h for h in hits if h.endswith("strip-after-extract")],
            "`strip_x(extract_y(text))` was NOT detected",
        )

    def test_precompiled_regex_match_is_detected(self):
        hits = self._scan(
            "RX = re.compile('x')\n"
            "def f(text):\n"
            "    strip_comment_lines('')\n"
            "    return RX.search(text)\n"
        )
        self.assertTrue(hits, "a precompiled `RX.search(raw_param)` was NOT detected")

    def test_local_stripper_alias_is_resolved(self):
        # `active_text` is not canonical; it must still count as a stripper, both
        # as the thing that makes a function "stripping" and as the outer call.
        hits = strip_order_violations(
            self._HEADER
            + "def active_text(t):\n    return strip_comment_lines(t)\n"
            "def _block(t):\n    return t\n"
            "def f(text):\n"
            "    return active_text(_block(text))\n",
            "synthetic.py",
        )
        self.assertTrue(
            [h for h in hits if h.endswith("strip-after-extract")],
            "a module-local stripper alias was not resolved",
        )

    def test_fixed_order_is_not_flagged(self):
        hits = self._scan(
            "def _dashboard_block(text):\n    return text\n"
            "def missing_directives(text):\n"
            "    return _dashboard_block(strip_comment_lines(text))\n"
        )
        self.assertEqual(hits, [], "the CORRECT order must not be flagged")

    def test_match_on_a_stripped_local_is_not_flagged(self):
        hits = self._scan(
            "def f(text):\n"
            "    active = strip_comment_lines(text)\n"
            "    return re.search('x', active)\n"
        )
        self.assertEqual(hits, [], "a match on a stripped local must not be flagged")

    def test_reassigned_parameter_is_treated_as_sanitized(self):
        hits = self._scan(
            "def f(text):\n"
            "    text = strip_comment_lines(text)\n"
            "    return re.search('x', text)\n"
        )
        self.assertEqual(hits, [], "a parameter reassigned to a stripped value is safe")

    def test_file_reader_inner_call_is_not_flagged(self):
        # The detector's only two false positives, both from the real suite:
        # `_upgrade_lines(self._text(name))` and
        # `compute_violations(_production_files())`. A reader SOURCES the text —
        # stripping its result is the correct order, not a defect.
        hits = self._scan(
            "def _text(name):\n    return Path(name).read_text()\n"
            "def f(name):\n"
            "    return strip_comment_lines(_text(name))\n"
        )
        self.assertEqual(hits, [], "a file reader must not be treated as an extractor")

    def test_zero_arg_helper_is_not_flagged(self):
        hits = self._scan(
            "def _files():\n    return []\n"
            "def f():\n    return strip_comment_lines(_files())\n"
        )
        self.assertEqual(hits, [], "a no-argument helper narrows nothing")

    def test_non_stripping_function_is_not_flagged(self):
        # A pure extractor whose CALLER owns the stripping decision.
        hits = self._scan("def _block(text):\n    return re.search('x', text)\n")
        self.assertEqual(
            hits, [], "a function that never strips must not be flagged by detector A"
        )

    def test_re_sub_is_not_a_match(self):
        hits = self._scan(
            "def f(text):\n"
            "    strip_comment_lines('')\n"
            "    return re.sub('x', '', text)\n"
        )
        self.assertEqual(hits, [], "`re.sub` rewrites, it does not scope a haystack")

    def test_docstring_mention_is_not_flagged(self):
        hits = self._scan(
            "def f(text):\n"
            "    '''Never write strip_comment_lines(_block(text)) here.'''\n"
            "    return _ok(text)\n"
            "def _ok(t):\n    return t\n"
        )
        self.assertEqual(hits, [], "AST parsing must ignore prose in a docstring")


if __name__ == "__main__":
    unittest.main()
