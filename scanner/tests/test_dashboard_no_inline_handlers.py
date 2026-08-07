"""
Regression guard: the dashboard must contain NO inline event-handler attributes
(`onclick=`, `onchange=`, `onkeyup=`, ...).

The dashboard ships a strict meta-CSP (`script-src 'nonce-…' 'strict-dynamic'`,
no `'unsafe-inline'`), so any inline `on*=` handler is silently DEAD in the
browser — the click/change/input never fires. All interactivity is instead wired
through the document-level event-delegation dispatchers in
`dashboard-template.html`, keyed on `data-action` / `data-change` / `data-input`.
This guard fails loudly if an inline handler is reintroduced, in either:

  1. the builder SOURCE (`scanner/lib/dashboard*.{py,html}`), or
  2. the rendered markup of the builders that previously carried handlers
     (audit-points / MS+SaaS sources / OWASP expanders).

stdlib-only. No network. Passes under pytest and `python3 -m unittest`.

OWASP A03 (Injection) / A05 (Security Misconfiguration): keeping the CSP strict
and the handlers delegated preserves the XSS mitigation the CSP provides.
"""

import io
import os
import re
import sys
import tokenize
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_DIR = REPO_ROOT / "scanner" / "lib"
sys.path.insert(0, str(LIB_DIR))

# Matches an inline HTML event-handler attribute: whitespace, then `on<name>`,
# then `=`, then an opening quote. `content=`, `font=`, `data-*` etc. never begin
# with the literal `on`, so they never match; `addEventListener('click'...)` has
# no `=` after the handler name so it never matches either.
INLINE_HANDLER_RE = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.IGNORECASE)

# Every builder source that emits dashboard markup.
_SOURCE_FILES = [
    "dashboard-template.html",
    "dashboard-gen.py",
    "dashboard_html_overview.py",
    "dashboard_html_arch.py",
    "dashboard_html_owasp.py",
    "dashboard_html_compliance.py",
    "dashboard_html_builders.py",
    "dashboard_html_sections.py",
    "dashboard_html_audit_points.py",
    "dashboard_html_audit_sources.py",
]


def _strip_scripts_styles(text: str) -> str:
    """Remove <script>/<style> blocks so JS/CSS bodies aren't scanned as attrs.

    The end tag is matched as `</script\\b[^>]*>`, not `</script>`. HTML lets a
    closing tag carry whitespace, a solidus, or attributes (`</script >`,
    `</script/>`, `</script foo="a">` — browsers accept all three), and with
    `.*?` under DOTALL a `</script>`-only pattern does not stop at any of them:
    it runs on to the NEXT `</script>` in the document and deletes everything in
    between. That is an over-strip, i.e. a false NEGATIVE in a guard whose whole
    job is to fail on an inline handler — markup that should have been scanned
    silently leaves the haystack. CodeQL flags the same shape as
    py/bad-tag-filter. No scanned source carries such an end tag today, so this
    closed a latent gap rather than a live miss.

    Residual limit, direction FALSE POSITIVE (safe): a literal `<script` inside
    an attribute value or an HTML comment still opens a strip region here where a
    real parser would not. That can only remove MORE text than intended, and only
    in a file that also has a later end tag; every scanned source has at most one
    script block today. Closing it properly needs a tokenizer — do that rather
    than add a fourth alternation if a real case appears."""
    text = re.sub(r"(?is)<script\b.*?</script\b[^>]*>", "", text)
    text = re.sub(r"(?is)<style\b.*?</style\b[^>]*>", "", text)
    return text


def _strip_py_comments(text: str) -> str:
    """Drop `#` line comments so prose like 'inline onclick' isn't flagged.

    Tokenizer-based, deliberately NOT `line.split("#", 1)[0]`. That split cuts at
    the first `#` ANYWHERE on the line — including one inside a string literal —
    and `scanner/lib/dashboard-gen.py:397` really does emit `<a href="#" ...>`.
    Nine lines across five builders start their markup before such a `#`, so
    everything after it (exactly where an `onclick=` gets appended) was invisible
    to the scan, and a live inline handler on any of them passed this guard
    green. Pre-existing; found by adversarial review of the `</script >` fix.

    On unparseable input the text is returned unchanged, which can only
    over-report (prose in a comment raising a false alarm), never hide a handler.
    """
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text
    cut_at = {}
    for tok in tokens:
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            cut_at[row] = min(cut_at.get(row, col), col)
    lines = text.splitlines()
    for row, col in cut_at.items():
        if 0 < row <= len(lines):
            # rstrip the gap the comment left; trailing whitespace cannot hide an
            # `on*=` attribute, so this only tidies the haystack.
            lines[row - 1] = lines[row - 1][:col].rstrip()
    return "\n".join(lines)


def _scannable(name: str, text: str) -> str:
    """The haystack for one builder source.

    Python comments are stripped BEFORE the script/style strip so `tokenize`
    always sees valid source — the reverse order can cut a `<script>` span out of
    a string literal and leave the file unparseable, which would silently fall
    back to un-stripped text."""
    if name.endswith(".py"):
        text = _strip_py_comments(text)
    return _strip_scripts_styles(text)


def _render_builder_markup() -> str:
    """Render the builders that previously carried inline handlers, on fixture
    data, and return the concatenated HTML. Deterministic and offline: calls the
    pure builder functions directly (no GitHub, no file IO)."""
    from dashboard_html_audit_points import build_audit_points_querypie_html
    from dashboard_html_audit_sources import (
        build_ms_sources_html,
        build_saas_sources_html,
    )
    from dashboard_html_owasp import _build_owasp_html

    audit_points = {
        "fetched_at": "2026-01-01T00:00:00Z",
        "products": [
            {
                "name": "Jenkins",
                "tree_url": "https://github.com/querypie/audit-points/tree/main/Jenkins",
                "files": [
                    {"name": "hardening.md", "url": "https://example.test/1"},
                    {"name": "rbac.md", "url": "https://example.test/2"},
                ],
            }
        ],
    }
    audit_points_detected = {"detected_products": ["Jenkins"], "items": []}

    ms_data = {
        "fetched_at": "2026-01-01T00:00:00Z",
        "source_filter": "all",
        "scubagear_enabled": False,
        "sources": [
            {
                "product": "Windows",
                "label": "Windows Security Baseline",
                "repo": "microsoft/SecurityBaselines",
                "repo_url": "https://github.com/microsoft/SecurityBaselines",
                "trust_level": "Microsoft Official",
                "reason": "Official baseline",
                "updated_at": "2026-01-01T00:00:00Z",
                "files": [{"path": "win/baseline.md", "url": "https://example.test/w1"}],
            }
        ],
    }

    parts = [
        build_audit_points_querypie_html(audit_points, audit_points_detected),
        build_ms_sources_html(ms_data),
        # Empty dict -> falls back to the default SAAS sources (still exercises
        # the ms-source card-title / checkbox delegation branch).
        build_saas_sources_html({}),
        # Empty map -> still renders every static OWASP item header (toggleOwasp).
        _build_owasp_html({}),
    ]
    return "".join(parts)


class TestStripScriptsStyles(unittest.TestCase):
    """Self-tests for the stripper. It decides what the inline-handler scan can
    see, so an over-strip here silently shrinks the haystack and turns this whole
    file into a guard that cannot fail."""

    def test_script_block_is_removed(self):
        self.assertEqual(_strip_scripts_styles("a<script>x=1</script>b"), "ab")

    def test_style_block_is_removed(self):
        self.assertEqual(_strip_scripts_styles("a<style>p{}</style>b"), "ab")

    def test_markup_outside_blocks_survives(self):
        # Canary against a stripper that eats everything.
        html = '<button data-action="go">go</button>'
        self.assertEqual(_strip_scripts_styles(html), html)

    def test_spaced_end_tag_does_not_swallow_following_markup(self):
        # `</script >` is valid HTML. With a `</script>`-only pattern the lazy
        # `.*?` runs on to the SECOND block's end tag and deletes the button in
        # between — the inline handler would never reach INLINE_HANDLER_RE.
        html = (
            "<script>x=1</script >"
            '<button onclick="boom()">b</button>'
            "<script>y=2</script>"
        )
        stripped = _strip_scripts_styles(html)
        self.assertIn("onclick=", stripped)
        self.assertIsNotNone(
            INLINE_HANDLER_RE.search(stripped),
            "an inline handler between a spaced and an unspaced end tag was "
            "stripped away — the guard would report green on a real regression",
        )

    def test_spaced_end_tag_still_strips_its_own_body(self):
        self.assertEqual(_strip_scripts_styles("a<script>x=1</script\n>b"), "ab")

    def test_end_tag_variants_do_not_swallow_following_markup(self):
        # `</script/>` and `</script foo="a">` are both accepted by browsers as
        # end tags. Each was still over-stripping after the first `\s*` fix.
        for end in ("</script/>", '</script foo="a">', "</script\t>"):
            html = (
                f"<script>x=1{end}"
                '<button onclick="boom()">b</button>'
                "<script>y=2</script>"
            )
            stripped = _strip_scripts_styles(html)
            self.assertIsNotNone(
                INLINE_HANDLER_RE.search(stripped),
                f"end-tag form {end!r} swallowed a live inline handler",
            )

    def test_similar_tag_name_is_not_an_end_tag(self):
        # `\b` must keep `</scriptx>` from closing a `<script>` block.
        html = "<script>x=1</scriptx><button onclick='b()'>b</button></script>tail"
        self.assertEqual(_strip_scripts_styles(html), "tail")


class TestStripPyComments(unittest.TestCase):
    """Self-tests for the Python comment stripper — the other half of the
    haystack, and the one that was silently hiding nine real source lines."""

    def test_line_comment_is_dropped(self):
        self.assertEqual(_strip_py_comments("x = 1  # note\ny = 2\n"), "x = 1\ny = 2")

    def test_prose_in_a_comment_is_not_scannable(self):
        scan = _strip_py_comments('# do not use inline onclick="x" here\nx = 1\n')
        self.assertIsNone(INLINE_HANDLER_RE.search(scan))

    def test_hash_inside_a_string_does_not_truncate_the_line(self):
        # The real shape: scanner/lib/dashboard-gen.py:397 emits `<a href="#" …>`.
        # `line.split("#", 1)[0]` cut here, hiding everything after it.
        src = 'h += \'<a href="#" class="l" onclick="boom()">t</a>\'\n'
        scan = _strip_py_comments(src)
        self.assertIn("onclick=", scan)
        self.assertIsNotNone(
            INLINE_HANDLER_RE.search(scan),
            "an inline handler after a `#` inside a string literal was stripped "
            "away — the guard would report green on a real regression",
        )

    def test_comment_after_a_string_containing_a_hash_is_still_dropped(self):
        src = 'h = \'<a href="#">t</a>\'  # anchor\n'
        self.assertEqual(_strip_py_comments(src), 'h = \'<a href="#">t</a>\'')

    def test_unparseable_source_falls_back_to_the_raw_text(self):
        # Over-report direction: nothing is hidden when tokenize fails.
        broken = 'def f(:\n  onclick="x"\n'
        self.assertEqual(_strip_py_comments(broken), broken)

    def test_real_builder_sources_keep_their_markup_visible(self):
        # Regression pin on the nine affected lines: the `href="#"` markup must
        # survive stripping in every builder that emits it.
        seen = 0
        for name in _SOURCE_FILES:
            if not name.endswith(".py"):
                continue
            scan = _scannable(name, (LIB_DIR / name).read_text(encoding="utf-8"))
            seen += scan.count('href="#"')
        self.assertGreater(
            seen,
            0,
            "no `href=\"#\"` markup survived stripping in any builder — the "
            "comment stripper is truncating string literals again",
        )


class TestNoInlineHandlersInSource(unittest.TestCase):
    def test_no_inline_handlers_in_builder_sources(self):
        offenders = []
        for name in _SOURCE_FILES:
            path = LIB_DIR / name
            self.assertTrue(path.is_file(), f"builder source missing: {path}")
            scan = _scannable(name, path.read_text(encoding="utf-8"))
            for m in INLINE_HANDLER_RE.finditer(scan):
                offenders.append(f"{name}: ...{scan[max(0, m.start() - 20):m.end() + 5]!r}")
        self.assertEqual(
            offenders,
            [],
            "Inline event-handler attribute(s) found in dashboard builder "
            "sources — these are DEAD under the strict CSP. Wire the control "
            "through the data-action / data-change / data-input delegation in "
            "dashboard-template.html instead:\n  " + "\n  ".join(offenders),
        )


class TestNoInlineHandlersInRenderedMarkup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.markup = _render_builder_markup()
        cls.body = _strip_scripts_styles(cls.markup)

    def test_rendered_markup_has_no_inline_handlers(self):
        offenders = [
            self.body[max(0, m.start() - 30):m.end() + 10]
            for m in INLINE_HANDLER_RE.finditer(self.body)
        ]
        self.assertEqual(
            offenders,
            [],
            "Inline event-handler attribute(s) in RENDERED builder markup — "
            "dead under the CSP:\n  " + "\n  ".join(repr(o) for o in offenders),
        )

    def test_rendered_markup_uses_delegation(self):
        # Sanity: the render actually produced delegated controls (guards
        # against a vacuous pass if a fixture stopped emitting markup). These
        # are the exact handlers the CSP-dead-control migration recovered.
        for token in (
            'data-action="toggleApProduct"',
            'data-input="apFilterProducts"',
            'data-change="apToggleCheck"',
            'data-action="toggleMsSrc"',
            'data-action="applyMsSourcePresetFilter"',
            'data-change="apToggleCheckMs"',
            'data-action="stop"',
            'data-action="toggleOwasp"',
        ):
            self.assertIn(
                token,
                self.markup,
                f"expected delegated control {token} missing from render",
            )


# Bare test_* functions so pytest function-collection also runs the core checks.
def test_source_has_no_inline_handlers():
    for name in _SOURCE_FILES:
        scan = _scannable(name, (LIB_DIR / name).read_text(encoding="utf-8"))
        assert not INLINE_HANDLER_RE.search(scan), f"inline handler in {name}"


def test_rendered_markup_has_no_inline_handlers_fn():
    body = _strip_scripts_styles(_render_builder_markup())
    assert not INLINE_HANDLER_RE.search(body), "inline handler in rendered markup"


if __name__ == "__main__":
    unittest.main()
