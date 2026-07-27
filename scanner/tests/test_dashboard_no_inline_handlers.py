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

import os
import re
import sys
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
    """Remove <script>/<style> blocks so JS/CSS bodies aren't scanned as attrs."""
    text = re.sub(r"(?is)<script\b.*?</script>", "", text)
    text = re.sub(r"(?is)<style\b.*?</style>", "", text)
    return text


def _strip_py_comments(text: str) -> str:
    """Drop `#` line comments so prose like 'inline onclick' isn't flagged."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


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


class TestNoInlineHandlersInSource(unittest.TestCase):
    def test_no_inline_handlers_in_builder_sources(self):
        offenders = []
        for name in _SOURCE_FILES:
            path = LIB_DIR / name
            self.assertTrue(path.is_file(), f"builder source missing: {path}")
            scan = _strip_scripts_styles(path.read_text(encoding="utf-8"))
            if name.endswith(".py"):
                scan = _strip_py_comments(scan)
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
        scan = _strip_scripts_styles((LIB_DIR / name).read_text(encoding="utf-8"))
        if name.endswith(".py"):
            scan = _strip_py_comments(scan)
        assert not INLINE_HANDLER_RE.search(scan), f"inline handler in {name}"


def test_rendered_markup_has_no_inline_handlers_fn():
    body = _strip_scripts_styles(_render_builder_markup())
    assert not INLINE_HANDLER_RE.search(body), "inline handler in rendered markup"


if __name__ == "__main__":
    unittest.main()
