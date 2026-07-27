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


def _read_lib_source(filename):
    """Read a scanner/lib/*.py file, dropping full-line ``#`` comments so a
    commented-out example cannot satisfy a positive source-pin assertion."""
    path = os.path.join(os.path.dirname(__file__), "..", "lib", filename)
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    return "\n".join(ln for ln in lines if not ln.lstrip().startswith("#"))


class TestDashboardGenHardeningPins(unittest.TestCase):
    """Source-level regression pins for the dashboard-gen.py XSS hardening:
    the scanner-category scope links must NOT reintroduce an inline
    onclick JS-string that interpolates the (raw) finding category, and the
    externally-sourced reference links must keep their safe_url() scheme gate."""

    @property
    def _src(self):
        return _read_lib_source("dashboard-gen.py")

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

    def test_policies_card_url_goes_through_safe_url(self):
        # Policies card (.claudesec-assets/policies.json, Google-Drive-derived):
        # the 원문↗ href value must gate the scheme via safe_url() before h().
        self.assertIn('h(safe_url(_pol.get("url", "")))', self._src)
        self.assertNotIn('_url = h(_pol.get("url", ""))', self._src)

    def test_policies_article_num_is_html_escaped(self):
        # The article number is interpolated into HTML text and must pass h().
        self.assertIn('{h(_a.get("num", ""))}', self._src)
        self.assertNotIn('">{_a.get("num", "")}. ', self._src)


class TestAuditSourceHrefHardeningPins(unittest.TestCase):
    """Source-level regression pins for the audit-points / MS / SaaS source
    href sinks (GitHub-API-derived URLs). Every externally-sourced href must
    keep its safe_url() scheme gate: h(safe_url(url)), never raw h(url).
    Mirrors the #366 hardening applied to the reference links."""

    def _assert_all_hrefs_gated(self, filename, var_names):
        src = _read_lib_source(filename)
        for var in var_names:
            # The safe_url()-gated form must be present ...
            self.assertIn(
                'href="{h(safe_url(%s))}"' % var,
                src,
                f"{filename}: href for {var!r} must go through safe_url()",
            )
            # ... and the un-gated form must NOT reappear.
            self.assertNotIn(
                'href="{h(%s)}"' % var,
                src,
                f"{filename}: raw h({var}) href would reintroduce a scheme-injection sink",
            )

    def test_audit_points_hrefs_gated(self):
        self._assert_all_hrefs_gated(
            "dashboard_html_audit_points.py", ("tree_url", "url", "repo_url")
        )

    def test_audit_sources_hrefs_gated(self):
        self._assert_all_hrefs_gated(
            "dashboard_html_audit_sources.py", ("repo_url", "url")
        )


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
