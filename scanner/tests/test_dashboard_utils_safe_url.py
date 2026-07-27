"""
Unit tests for dashboard_utils.safe_url() — the href URL-scheme gate.

safe_url neutralizes `javascript:` / `data:` / `vbscript:` (and any other
non-http(s)/mailto scheme) reference URLs that survive h() (which only
HTML-escapes) and would execute on click in an <a href> context. Externally
sourced reference URLs (GitHub findings, Prowler OCSF remediation.references)
flow to the ref-link render sites in dashboard-gen.py, so this gate is applied
as h(safe_url(u)) there.

Authored for both pytest and `python3 -m unittest` discovery. stdlib-only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_utils import safe_url  # noqa: E402


ALLOWED = [
    "https://github.com/owner/repo",
    "http://example.test/a",
    "mailto:security@example.test",
    "#frag",
    "/relative/path",
    "./sibling.html",
    "../parent.html",
    "docs/guide.html",   # scheme-less relative path
    "//cdn.example.test/x",  # protocol-relative (http/https-equivalent)
]

BLOCKED = [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",   # case-insensitive
    "  javascript:alert(1)",  # leading whitespace
    "java\tscript:alert(1)",  # embedded control char in scheme
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
]


class TestSafeUrl(unittest.TestCase):
    def test_allowed_urls_pass_through_unchanged(self):
        for u in ALLOWED:
            self.assertEqual(safe_url(u), u, f"should allow: {u!r}")

    def test_blocked_schemes_collapse_to_hash(self):
        for u in BLOCKED:
            self.assertEqual(safe_url(u), "#", f"should block: {u!r}")

    def test_non_string_input_is_coerced(self):
        # str(12345) has no scheme -> treated as a scheme-less relative value.
        self.assertEqual(safe_url(12345), "12345")

    def test_javascript_scheme_never_survives_with_h(self):
        # The real render pattern is h(safe_url(u)); a javascript: URL must not
        # reach the href as an executable scheme.
        from dashboard_utils import h
        self.assertEqual(h(safe_url("javascript:alert(document.cookie)")), "#")


class TestDashboardGenHardeningPins(unittest.TestCase):
    """Source-level regression pins for the dashboard-gen.py XSS hardening:
    the scanner-category scope links must NOT reintroduce an inline
    onclick JS-string that interpolates the (raw) finding category, and the
    externally-sourced reference links must keep their safe_url() scheme gate."""

    @property
    def _src(self):
        path = os.path.join(os.path.dirname(__file__), "..", "lib", "dashboard-gen.py")
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_no_inline_onclick_switchtab_with_category(self):
        # The Finding-3 vector: onclick="switchTab('overview','scanner-cat-{h(cat)}')"
        # — an h()-escaped quote decodes back to a live delimiter in inline JS.
        self.assertNotIn("onclick=\"switchTab('overview','scanner-cat-", self._src)

    def test_scope_cat_links_use_data_action_delegation(self):
        self.assertIn('data-action="switchTab" data-arg="overview" data-scroll="scanner-cat-', self._src)

    def test_reference_links_go_through_safe_url(self):
        # Finding-4: href must gate the scheme via safe_url(), never raw h(rl).
        self.assertIn("href=\"{h(safe_url(rl))}\"", self._src)
        self.assertNotIn("href=\"{h(rl)}\"", self._src)


# Bare test_* functions so pytest (function collection) also runs them.
def test_safe_url_allows_https():
    assert safe_url("https://x.test/y") == "https://x.test/y"


def test_safe_url_blocks_javascript():
    assert safe_url("javascript:alert(1)") == "#"


def test_safe_url_allows_fragment_and_relative():
    assert safe_url("#top") == "#top"
    assert safe_url("docs/x.html") == "docs/x.html"


if __name__ == "__main__":
    unittest.main()
