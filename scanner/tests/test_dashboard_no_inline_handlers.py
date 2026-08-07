"""
Regression guard: the dashboard must contain NO inline event-handler attributes
(`onclick=`, `onchange=`, `onkeyup=`, ...).

The dashboard ships a strict meta-CSP (`script-src 'nonce-…' 'strict-dynamic'`,
no `'unsafe-inline'`), so any inline `on*=` handler is silently DEAD in the
browser — the click/change/input never fires. All interactivity is instead wired
through the document-level event-delegation dispatchers in
`dashboard-template.html`, keyed on `data-action` / `data-change` / `data-input`.
This guard fails loudly if an inline handler is reintroduced, in either:

  1. the builder SOURCE (`scanner/lib/dashboard*.{py,html}` plus the repo-root
     `claudesec-asset-dashboard.html`), or
  2. the rendered markup of the builders that previously carried handlers
     (audit-points / MS+SaaS sources / OWASP expanders).

`claudesec-asset-dashboard.html` is the ISMS asset dashboard: a checked-in
TEMPLATE that `scripts/build-dashboard.py` reads and injects data into (it is not
generated output). It ships the SAME strict meta-CSP and the same `data-action`
delegation model, so an inline handler in it is just as dead — but it lives at the
repo ROOT, not under `scanner/lib/`, and was outside this scan entirely. Sources
are therefore carried as repo-relative paths rather than bare `scanner/lib/` names.

SCOPE BOUNDARY, stated so nobody over-trusts this file: `_strip_scripts_styles`
removes `<script>` bodies, so for the two `.html` sources this guard only sees
STATIC markup. The asset dashboard builds nearly all of its markup as JS strings
INSIDE its one script block, which this scan therefore cannot see. Regexing a JS
body for `on…="` needs a comment/string-aware tokenizer to avoid false positives
(its own source comment mentions `<img onerror>` in prose), so that half is
covered empirically instead: `scanner/tests/asset-dashboard-assertions.js` walks
the fully-rendered DOM in headless Chrome and fails on ANY element carrying an
`on*` attribute — which catches runtime-generated handlers this scan cannot.

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

# Every source that emits dashboard markup, as a REPO-RELATIVE path. Repo-relative
# (not bare names resolved under LIB_DIR) so the repo-root asset dashboard can be
# scanned by the same rule instead of needing a `../..` escape hatch.
_SOURCE_FILES = [
    "scanner/lib/dashboard-template.html",
    "scanner/lib/dashboard-gen.py",
    "scanner/lib/dashboard_html_overview.py",
    "scanner/lib/dashboard_html_arch.py",
    "scanner/lib/dashboard_html_owasp.py",
    "scanner/lib/dashboard_html_compliance.py",
    "scanner/lib/dashboard_html_builders.py",
    "scanner/lib/dashboard_html_sections.py",
    "scanner/lib/dashboard_html_audit_points.py",
    "scanner/lib/dashboard_html_audit_sources.py",
    # ISMS asset dashboard: repo-root template, same CSP, same delegation model.
    "claudesec-asset-dashboard.html",
]


# The two elements whose bodies leave the haystack. These are the ONLY spans
# `_strip_scripts_styles` deletes, which is what bounds its blast radius.
_STRIPPED_ELEMENTS = ("script", "style")

# Elements whose content HTML does NOT parse as markup (RCDATA / raw text), so a
# literal `<script` inside one is text, not a tag. Listed only to SKIP — never to
# delete — because the two directions are asymmetric: omitting an element risks
# opening a strip region a browser would not (over-strip -> a silent miss), while
# including one at worst leaves a real script body in the haystack (over-report ->
# a false alarm). Obsolete `<plaintext>` is not modelled: it has no end tag, and
# no scanned source has one.
_TEXT_ONLY_ELEMENTS = (
    "title",
    "textarea",
    "iframe",
    "xmp",
    "noembed",
    "noframes",
    "noscript",
)

# Elements whose content is scanned for an end tag rather than for markup.
_TEXT_MODE_ELEMENTS = _STRIPPED_ELEMENTS + _TEXT_ONLY_ELEMENTS

# HTML's whitespace set, plus the two other characters that terminate a tag name.
_HTML_SPACE = " \t\n\r\f"
_TAG_NAME_RE = re.compile(r"[a-zA-Z][^ \t\n\r\f/>]*")
# The "appropriate end tag" rule from the HTML tokenizer's raw-text/RCDATA end
# tag name state: the name must be followed by whitespace, `/`, or `>`.
_END_TAG_RE = {
    name: re.compile(r"</" + name + r"(?=[ \t\n\r\f/>])", re.IGNORECASE)
    for name in _TEXT_MODE_ELEMENTS
}


class _Unparseable(Exception):
    """Markup this tokenizer will not guess at (EOF inside a tag, an
    unterminated attribute value). Stripping stops at that point and everything
    from there on is kept verbatim — the over-report direction."""


def _scan_markup_decl(text: str, i: int) -> int:
    """Index just past the `<!`/`<?` construct at `i` (comment, doctype, bogus
    comment). An unterminated construct runs to EOF, exactly as a browser reads
    it. Nothing here is ever deleted, only skipped."""
    n = len(text)
    if text.startswith("<!--", i):
        j = i + 4
        if text.startswith(">", j):  # `<!-->` — abrupt-closing comment
            return j + 1
        if text.startswith("->", j):  # `<!--->`
            return j + 2
        k = text.find("-->", j)
        return n if k < 0 else k + 3
    k = text.find(">", i)
    return n if k < 0 else k + 1


def _scan_tag(text: str, i: int):
    """Tokenize the tag starting at `text[i] == '<'`.

    Returns `(end, name, is_end_tag)` with `end` just past the tag's `>`, or
    None when `i` does not start a tag at all (a bare `<`, as in `if a < b`).
    Raises `_Unparseable` for a tag that starts but never validly closes.

    Attribute values are consumed with their quoting, which is the whole point:
    a literal `<script` inside `title="<script>"` is a value, not a tag."""
    n = len(text)
    j = i + 1
    is_end = text.startswith("/", j)
    if is_end:
        j += 1
    m = _TAG_NAME_RE.match(text, j)
    if not m:
        return None
    name, j = m.group(0).lower(), m.end()
    while j < n:
        c = text[j]
        if c == ">":
            return j + 1, name, is_end
        if c in _HTML_SPACE or c == "/":
            j += 1
            continue
        while j < n and text[j] not in _HTML_SPACE + "/>=":  # attribute name
            j += 1
        while j < n and text[j] in _HTML_SPACE:
            j += 1
        if j < n and text[j] == "=":
            j += 1
            while j < n and text[j] in _HTML_SPACE:
                j += 1
            if j < n and text[j] in "\"'":
                quote, j = text[j], j + 1
                k = text.find(quote, j)
                if k < 0:
                    raise _Unparseable(f"unterminated attribute value at {i}")
                j = k + 1
            else:
                while j < n and text[j] not in _HTML_SPACE + ">":
                    j += 1
    raise _Unparseable(f"unterminated tag at {i}")


def _element_end(text: str, start: int, name: str):
    """Index just past the end tag of the raw-text/RCDATA element `name` whose
    content begins at `start`, or None when it has no end tag at all.

    None means "strip nothing": an unterminated `<script>` leaves its body in the
    haystack (over-report) rather than swallowing the rest of the file, which is
    what a browser does but is the miss direction for this guard."""
    m = _END_TAG_RE[name].search(text, start)
    if m is None:
        return None
    return _scan_tag(text, m.start())[0]


def _strip_scripts_styles(text: str) -> str:
    """Remove <script>/<style> ELEMENTS so JS/CSS bodies aren't scanned as attrs.

    Tokenizer-based, deliberately NOT a regex. Two over-strip bugs came out of
    the regex form, and both are silent false NEGATIVES in a guard whose whole
    job is to fail on an inline handler — markup that should have been scanned
    just leaves the haystack:

      1. `<script\\b.*?</script>` under DOTALL does not stop at `</script >`,
         `</script/>` or `</script foo="a">` (browsers accept all three as end
         tags), so it ran on to the NEXT end tag and deleted everything between.
         Fixed by regex in the same pass; CodeQL calls the shape py/bad-tag-filter.
      2. A literal `<script` inside an ATTRIBUTE VALUE (`title="<script>"`) or an
         HTML COMMENT (`<!-- <script> -->`) opened a strip region where no real
         parser would, again deleting everything up to the next end tag. The
         previous docstring filed this under "direction FALSE POSITIVE (safe)"
         while describing it as removing MORE text than intended — those are
         opposite directions, and the second one is the bypass. Only a tokenizer
         closes it, so this is a tokenizer.

    Deletion is bounded by construction: the ONLY spans removed are `<script>` /
    `<style>` elements entered from a genuine start tag. Comments, doctypes,
    other tags and RCDATA elements are skipped, never deleted, so a
    mis-classification there can only leave text IN the haystack.

    Failure direction is over-report everywhere:
    - unparseable markup (EOF inside a tag, an unterminated attribute value) ->
      stop stripping, keep the remainder verbatim;
    - a `<script>` with no end tag -> strip nothing;
    - script-data double-escaping (`<script>var s = "<!--<script>"; </script>`)
      ends the span at the first `</script`, earlier than a browser would.
    Each removes LESS than intended, which can only raise a false alarm."""
    out, keep, i, n = [], 0, 0, len(text)
    while i < n:
        if text[i] != "<":
            i += 1
            continue
        if text.startswith("<!", i) or text.startswith("<?", i):
            i = _scan_markup_decl(text, i)
            continue
        try:
            tag = _scan_tag(text, i)
        except _Unparseable:
            break
        if tag is None:  # a bare `<`, e.g. `if a < b`
            i += 1
            continue
        end, name, is_end = tag
        if is_end or name not in _TEXT_MODE_ELEMENTS:
            i = end
            continue
        try:
            elem_end = _element_end(text, end, name)
        except _Unparseable:
            break
        if elem_end is None:
            # Unterminated: the rest of the document is this element's content,
            # so there is nothing left to tokenize. Stop and keep it verbatim.
            break
        if name in _STRIPPED_ELEMENTS:
            out.append(text[keep:i])
            keep = elem_end
        i = elem_end
    out.append(text[keep:])
    return "".join(out)


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
        # `</scriptx>` must not close a `<script>` block.
        html = "<script>x=1</scriptx><button onclick='b()'>b</button></script>tail"
        self.assertEqual(_strip_scripts_styles(html), "tail")


class TestStripScriptsStylesFalseStripRegions(unittest.TestCase):
    """A `<script`/`<style` that is NOT a start tag must not open a strip region.

    These are the shapes the regex form got wrong. Each deleted a live inline
    handler from the haystack, so the guard reported green on a real regression —
    an over-strip, i.e. a false NEGATIVE, not the "false positive" the old
    docstring claimed. Verified against a real HTML tokenizer
    (`html.parser.HTMLParser`), which reports the `<button>` as a start tag
    carrying an `onclick` attribute in every case below.
    """

    def _assert_handler_survives(self, html, msg):
        stripped = _strip_scripts_styles(html)
        self.assertIsNotNone(INLINE_HANDLER_RE.search(stripped), f"{msg}: {stripped!r}")

    def test_script_inside_an_attribute_value_is_not_a_tag(self):
        self._assert_handler_survives(
            '<div title="<script>">'
            '<button onclick="boom()">b</button>'
            "<script>y=2</script>",
            "a `<script` inside a double-quoted attribute value opened a strip region",
        )

    def test_style_inside_an_attribute_value_is_not_a_tag(self):
        self._assert_handler_survives(
            "<div data-x='<style>'>"
            "<button onclick='boom()'>b</button>"
            "<style>p{}</style>",
            "a `<style` inside a single-quoted attribute value opened a strip region",
        )

    def test_script_inside_an_html_comment_is_not_a_tag(self):
        self._assert_handler_survives(
            "<!-- <script> -->"
            '<button onclick="boom()">b</button>'
            "<script>y=2</script>",
            "a `<script` inside an HTML comment opened a strip region",
        )

    def test_script_inside_rcdata_content_is_not_a_tag(self):
        # `<title>`/`<textarea>` content is text, not markup, so the `<script`
        # here never starts an element. Modelling the RCDATA elements is the safe
        # side: omitting one risks a strip region, including one at worst leaves a
        # real script body in the haystack.
        self._assert_handler_survives(
            "<title><script></title>"
            '<button onclick="boom()">b</button>'
            "<script>y=2</script>",
            "a `<script` inside RCDATA content opened a strip region",
        )

    def test_attribute_value_containing_gt_does_not_end_the_tag(self):
        # `>` inside a quoted value is data; the `<script>` after it is still the
        # only thing removed.
        html = '<div title="a>b"><script>x=1</script>tail'
        self.assertEqual(_strip_scripts_styles(html), '<div title="a>b">tail')


class TestStripScriptsStylesFailureDirection(unittest.TestCase):
    """Re-attack on the tokenizer's OWN terms (ADR-001: a fix to this class can
    create the class). Every residual must remove LESS than intended — an
    over-report, i.e. a false alarm — never more."""

    def test_bare_less_than_is_data_not_a_tag(self):
        # Python sources are scanned too, and `if a < b:` is not markup.
        html = 'if a < b:<button onclick="boom()">b</button><script>y=2</script>'
        self.assertEqual(
            _strip_scripts_styles(html),
            'if a < b:<button onclick="boom()">b</button>',
        )

    def test_unterminated_script_strips_nothing(self):
        # A browser would read the rest of the file as script body; doing that
        # here would DELETE it, so the stripper stops instead.
        html = '<script>x=1<button onclick="boom()">b</button>'
        self.assertEqual(_strip_scripts_styles(html), html)

    def test_unterminated_attribute_value_stops_stripping(self):
        # Unparseable markup -> keep the remainder verbatim.
        html = '<div title="oops><script>x=1</script><button onclick="b()">x</button>'
        self.assertEqual(_strip_scripts_styles(html), html)

    def test_abrupt_closing_comment_ends_at_the_first_gt(self):
        # `<!-->` is a complete comment; the markup after it stays scannable.
        html = '<!--><button onclick="boom()">b</button><script>y=2</script>'
        self.assertEqual(_strip_scripts_styles(html), '<!--><button onclick="boom()">b</button>')

    def test_cdata_marker_does_not_swallow_following_markup(self):
        # `<![CDATA[..]]>` is a bogus comment in HTML: it ends at the first `>`.
        html = '<![CDATA[x]]><button onclick="boom()">b</button><script>y=2</script>'
        stripped = _strip_scripts_styles(html)
        self.assertIsNotNone(INLINE_HANDLER_RE.search(stripped), stripped)

    def test_script_data_double_escape_ends_the_span_early(self):
        # Documented residual: after `<!--<script`, a browser does NOT end the
        # element at the next `</script>`. Ending early removes LESS text, so the
        # trailing markup stays scannable — an over-report, never a miss.
        html = '<script>var s="<!--<script>";</script><button onclick="boom()">b</button>'
        stripped = _strip_scripts_styles(html)
        self.assertIsNotNone(INLINE_HANDLER_RE.search(stripped), stripped)

    def test_uppercase_tags_are_stripped(self):
        self.assertEqual(_strip_scripts_styles("a<SCRIPT>x=1</SCRIPT>b"), "ab")

    def test_solidus_start_tag_still_opens_a_script_element(self):
        # `<script/>` is NOT self-closing in HTML: the `/` is ignored and the
        # element still takes raw text.
        self.assertEqual(_strip_scripts_styles("a<script/>x=1</script>b"), "ab")

    def test_real_template_script_and_style_bodies_are_removed(self):
        # Non-vacuity canary on the REAL file. Every failure path above falls back
        # to "strip less"; without this, a stripper that silently stopped working
        # on dashboard-template.html would still leave this guard green.
        text = (LIB_DIR / "dashboard-template.html").read_text(encoding="utf-8")
        self.assertIn("addEventListener", text)  # lives only inside <script>
        self.assertIn("font-family", text)  # lives only inside <style>
        stripped = _strip_scripts_styles(text)
        self.assertNotIn(
            "addEventListener",
            stripped,
            "the <script> body survived stripping — the tokenizer bailed out on "
            "the real template and the haystack is no longer what this guard thinks",
        )
        self.assertNotIn("font-family", stripped, "the <style> body survived stripping")
        self.assertIn("<title>", stripped, "non-script markup must survive")


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
            scan = _scannable(name, (REPO_ROOT / name).read_text(encoding="utf-8"))
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
            path = REPO_ROOT / name
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
        scan = _scannable(name, (REPO_ROOT / name).read_text(encoding="utf-8"))
        assert not INLINE_HANDLER_RE.search(scan), f"inline handler in {name}"


def test_rendered_markup_has_no_inline_handlers_fn():
    body = _strip_scripts_styles(_render_builder_markup())
    assert not INLINE_HANDLER_RE.search(body), "inline handler in rendered markup"


if __name__ == "__main__":
    unittest.main()
