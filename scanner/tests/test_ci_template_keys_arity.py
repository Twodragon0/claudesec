"""
Regression guard: `_TEMPLATE_KEYS`, its production caller's argument count, and
the template's placeholders must stay in sync.

WHAT GOES WRONG, AND WHY NOTHING NOTICES
----------------------------------------
`dashboard_html_helpers._build_replacements(*values)` maps positional values onto
`_TEMPLATE_KEYS` by `zip`, and `zip` TRUNCATES to the shorter side. Truncation is
that helper's tested contract on purpose (`test_fewer_values_truncates_result`
pins partial application), so `strict=True` is not available as a fix — the
coupling has to be checked from outside.

Nothing checked it. `_TEMPLATE_KEYS` has 73 entries and exactly one production
caller, `scanner/lib/dashboard-gen.py`, which passes 73 positional values. Add a
74th key without updating the caller and the 74th placeholder is left unreplaced
in the rendered dashboard: no exception, no failing test, no visible diff except
a literal `{{SOMETHING}}` on the page. The reverse — a 74th argument with no key
— silently discards the value instead.

BOTH DIRECTIONS, because the guard is only half a guard otherwise:

1. **Arity.** `len(_TEMPLATE_KEYS)` == the caller's positional argument count.
2. **Placeholder reachability.** A key with no `{{KEY}}` anywhere in the template
   is a DEAD replacement — computed, passed, stored, never substituted. Four
   already exist (`ACTIVE`, `POLICY_022_TOP`, `N_INFO`, `TOTAL_ALL`, measured
   2026-09-01), which is exactly why direction 1 alone would not have helped: the
   common drift is adding a key plus an argument and forgetting the template.

The dead set is asserted EQUAL to a baseline rather than merely non-growing, the
same discipline `test_ci_scanner_lib_reachability.py` uses for dead functions: a
NEW dead key fails because it is not in the baseline, and wiring one up ALSO
fails until it is dropped from the baseline. That keeps the allowlist honest
instead of letting it accumulate.

WHY AST, NOT A LINE SCAN
------------------------
The call spans 73 lines. Counting `,` characters or matching a regex over the
call text breaks on a nested call, a trailing comma, or a comment, and this
repo's history is a list of guards defeated by exactly that
(`feedback-enumerate-with-ast`). `ast.walk` reads the argument list the
interpreter reads, and a `*args` splat is REFUSED rather than guessed, because an
unpackable argument makes the count unknowable statically — fail closed.

stdlib-only (`ast`, `re`, `pathlib` — no PyYAML). No network, no subprocess.
Imports `dashboard_html_helpers` for `_TEMPLATE_KEYS`; that module is already
inside the measured `scanner/lib` coverage set, and this file adds no statements
to it.

OWASP CICD-SEC-1 (Insufficient Flow Control); the "dead renderer" class recorded
in this repo twice before.
"""

import ast
import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
LIB = REPO_ROOT / "scanner" / "lib"
CALLER = LIB / "dashboard-gen.py"
TEMPLATE = LIB / "dashboard-template.html"
HELPER_NAME = "_build_replacements"

sys.path.insert(0, str(LIB))
from dashboard_html_helpers import _TEMPLATE_KEYS  # noqa: E402

# Keys with no `{{KEY}}` in the template: computed, passed, stored, never
# substituted. Baseline measured 2026-09-01 — asserted EQUAL, not as a ceiling.
#
# Left in place rather than deleted: removing a key means removing its positional
# argument from a 73-argument call, which is an off-by-one waiting to happen and a
# behaviour change, not a guard. Recorded here so the next person sees the list
# instead of rediscovering it.
KNOWN_DEAD_KEYS = {
    "ACTIVE",           # caller arg `active`,          index 10
    "POLICY_022_TOP",   # caller arg `policy_022_top`,  index 17
    "N_INFO",           # caller arg `n_info`,          index 18
    "TOTAL_ALL",        # caller arg `total_all`,       index 22
}

# `{{CSP_NONCE}}` is substituted by nginx `sub_filter` per request, not by
# `_build_replacements`, so it is a placeholder with no key BY DESIGN. Listed
# because "placeholder without a key" is otherwise indistinguishable from drift.
KNOWN_EXTERNAL_PLACEHOLDERS = {"CSP_NONCE"}

_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def _caller_calls():
    """Every `_build_replacements(...)` Call node in the production caller."""
    tree = ast.parse(CALLER.read_text(encoding="utf-8"))
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == HELPER_NAME
    ]


def _template_placeholders():
    return set(_PLACEHOLDER_RE.findall(TEMPLATE.read_text(encoding="utf-8")))


class TestInputsAreLocatable(unittest.TestCase):
    """Vacuity canaries. Every assertion below is vacuous on an empty input."""

    def test_files_exist(self):
        for path in (CALLER, TEMPLATE):
            self.assertTrue(path.is_file(), f"{path} not found — a path broke")

    def test_keys_are_populated(self):
        self.assertGreater(
            len(_TEMPLATE_KEYS),
            50,
            "`_TEMPLATE_KEYS` came back nearly empty — the import or the name "
            f"changed. Got {len(_TEMPLATE_KEYS)}.",
        )

    def test_the_call_is_found(self):
        calls = _caller_calls()
        self.assertEqual(
            len(calls),
            1,
            f"expected exactly one `{HELPER_NAME}(...)` call in {CALLER.name}, "
            f"found {len(calls)}. Two callers means two arities to keep in sync "
            "and this guard checks neither; one means the extractor broke.",
        )

    def test_placeholders_are_found(self):
        self.assertGreater(
            len(_template_placeholders()),
            50,
            "almost no `{{KEY}}` placeholders parsed out of the template — the "
            "substitution syntax changed and the reachability check below would "
            "report every key as dead.",
        )


class TestArityIsCoupled(unittest.TestCase):
    def test_caller_passes_one_value_per_key(self):
        call = _caller_calls()[0]
        self.assertEqual(
            len(call.args),
            len(_TEMPLATE_KEYS),
            f"`{HELPER_NAME}` is called with {len(call.args)} positional values "
            f"but `_TEMPLATE_KEYS` has {len(_TEMPLATE_KEYS)} keys. `zip` truncates "
            "to the shorter side, so the surplus is DISCARDED SILENTLY: too few "
            "values leaves trailing `{{KEY}}` placeholders unreplaced in the "
            "rendered dashboard, too many drops the extra value. Neither raises.",
        )

    def test_a_splat_argument_is_refused(self):
        # Fail closed. `_build_replacements(*values)` makes the count unknowable
        # statically, so the guard must reject it rather than skip the check and
        # report green.
        call = _caller_calls()[0]
        starred = [a for a in call.args if isinstance(a, ast.Starred)]
        self.assertEqual(
            starred,
            [],
            f"`{HELPER_NAME}` is called with a `*` splat, so its argument count "
            "cannot be verified statically and the arity coupling is unchecked. "
            "Pass the values positionally, or replace this guard with a runtime "
            "assertion in the same PR.",
        )

    def test_no_keyword_arguments(self):
        # `_build_replacements(*values)` takes no named parameters, so a keyword
        # argument would be a TypeError at runtime — but it would also make
        # `len(call.args)` an undercount, i.e. this guard would report a mismatch
        # with a misleading message. Name the real problem.
        call = _caller_calls()[0]
        self.assertEqual(
            [kw.arg for kw in call.keywords],
            [],
            f"`{HELPER_NAME}` accepts only positional values; a keyword argument "
            "is a TypeError at runtime.",
        )


class TestEveryKeyReachesTheTemplate(unittest.TestCase):
    def test_dead_keys_equal_the_baseline(self):
        dead = {k for k in _TEMPLATE_KEYS if k not in _template_placeholders()}
        new = sorted(dead - KNOWN_DEAD_KEYS)
        fixed = sorted(KNOWN_DEAD_KEYS - dead)
        self.assertEqual(
            (new, fixed),
            ([], []),
            "the set of `_TEMPLATE_KEYS` entries with no `{{KEY}}` in the "
            "template no longer equals the baseline.\n"
            f"  NEWLY DEAD (add a placeholder, or drop the key AND its caller "
            f"argument): {new}\n"
            f"  NOW WIRED UP (delete it from KNOWN_DEAD_KEYS): {fixed}\n"
            "A dead key is a value computed, passed through a 73-argument call "
            "and stored, that nothing ever substitutes.",
        )

    def test_placeholders_without_a_key_equal_the_baseline(self):
        # The other direction: a `{{KEY}}` the replacement map never supplies
        # renders literally on the page. `CSP_NONCE` is supplied by nginx.
        orphans = _template_placeholders() - set(_TEMPLATE_KEYS)
        self.assertEqual(
            orphans,
            KNOWN_EXTERNAL_PLACEHOLDERS,
            "template placeholders with no `_TEMPLATE_KEYS` entry changed.\n"
            f"  got:      {sorted(orphans)}\n"
            f"  expected: {sorted(KNOWN_EXTERNAL_PLACEHOLDERS)}\n"
            "A placeholder nothing supplies renders as literal `{{KEY}}` text in "
            "the dashboard. If a new one is filled in from outside "
            "`_build_replacements`, add it to KNOWN_EXTERNAL_PLACEHOLDERS with a "
            "note saying what supplies it.",
        )


class TestDetectorMutations(unittest.TestCase):
    """The detectors must actually distinguish the shapes they claim to.

    Written against synthetic source so a green result on the real files cannot
    be mistaken for a working extractor — the surrogate trap from #504.
    """

    @staticmethod
    def _calls(src):
        tree = ast.parse(src)
        return [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == HELPER_NAME
        ]

    def test_counts_args_across_line_breaks_and_trailing_comma(self):
        src = "x = _build_replacements(\n    a,\n    b,\n    # a comment\n    c,\n)\n"
        self.assertEqual(len(self._calls(src)[0].args), 3)

    def test_a_nested_call_is_one_argument_not_several(self):
        # The shape a `,`-counting or regex extractor gets wrong.
        src = "x = _build_replacements(a, fmt(b, c, d), e)\n"
        self.assertEqual(
            len(self._calls(src)[0].args),
            3,
            "a nested call's own arguments were counted as the outer call's — "
            "the defect a text scan has and an AST walk does not.",
        )

    def test_a_splat_is_visible_to_the_refusal_check(self):
        src = "x = _build_replacements(*values)\n"
        args = self._calls(src)[0].args
        self.assertTrue(any(isinstance(a, ast.Starred) for a in args))

    def test_an_unrelated_call_is_not_matched(self):
        src = "x = build_replacements(a, b)\ny = other._build_replacements(c)\n"
        self.assertEqual(
            self._calls(src),
            [],
            "a differently-named function, or an attribute call on another "
            "object, was matched as the production caller.",
        )

    def test_placeholder_regex_reads_the_real_syntax(self):
        found = _PLACEHOLDER_RE.findall(
            "<p>{{ALPHA}}</p> {{BETA_2}} {{lowercase}} {{ WITH_SPACES }} {NOT_DOUBLE}"
        )
        self.assertEqual(
            found,
            ["ALPHA", "BETA_2"],
            "the placeholder pattern drifted from the template's actual "
            "`{{UPPER_SNAKE}}` syntax; a pattern that matches nothing reports "
            "every key as dead, and one that matches too much hides real drift.",
        )


if __name__ == "__main__":
    unittest.main()
