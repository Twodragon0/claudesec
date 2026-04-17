"""
Unit tests for the two HTML builder functions in
scanner/lib/dashboard_html_audit_sources.py.

Each test covers exactly one behaviour.  No network access, no CLI invocation,
no filesystem fixtures beyond the module import itself.
"""

import os
import sys

# Make the lib directory importable exactly as the other test files do.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_audit_sources import build_ms_sources_html, build_saas_sources_html


# ---------------------------------------------------------------------------
# Helpers – minimal source dicts
# ---------------------------------------------------------------------------

def _ms_source(
    product="Windows",
    label="Test Source",
    trust_level="Microsoft Official",
    reason="A reason",
    repo_url="https://github.com/microsoft/test",
    files=None,
    archived=False,
):
    src = {
        "product": product,
        "label": label,
        "trust_level": trust_level,
        "reason": reason,
        "repo_url": repo_url,
        "files": files if files is not None else [],
    }
    if archived:
        src["archived"] = True
    return src


def _saas_source(
    product="Okta",
    label="Test SaaS Source",
    trust_level="Vendor Official",
    reason="A saas reason",
    repo="okta/test",
    files=None,
    focus_paths=None,
):
    src = {
        "product": product,
        "label": label,
        "trust_level": trust_level,
        "reason": reason,
        "repo": repo,
        "files": files if files is not None else [],
    }
    if focus_paths is not None:
        src["focus_paths"] = focus_paths
    return src


# ===========================================================================
# build_ms_sources_html
# ===========================================================================

def test_ms_empty_sources_shows_no_cached_fallback():
    """Empty sources list → 'No Microsoft best-practice source metadata cached yet' fallback."""
    html = build_ms_sources_html({"sources": [], "source_filter": "all"})
    assert "No Microsoft best-practice source metadata cached yet" in html


def test_ms_source_filter_none_shows_hidden_message():
    """source_filter='none' with no sources → 'Microsoft source area is hidden' message."""
    html = build_ms_sources_html({"sources": [], "source_filter": "none"})
    assert "Microsoft source area is hidden" in html


def test_ms_source_filter_none_via_env(monkeypatch):
    """When env var sets filter to 'none' and sources empty → hidden message appears."""
    monkeypatch.setenv("CLAUDESEC_MS_SOURCE_FILTER", "none")
    html = build_ms_sources_html({"sources": []})
    assert "Microsoft source area is hidden" in html


def test_ms_microsoft_official_source_gets_trust_ms_chip():
    """Source with trust_level='Microsoft Official' renders with trust-ms chip and label."""
    data = {
        "sources": [_ms_source(trust_level="Microsoft Official")],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert "trust-ms" in html
    assert "Microsoft Official" in html


def test_ms_government_source_gets_trust_gov_chip():
    """Source with trust_level='Government' renders with trust-gov chip."""
    data = {
        "sources": [_ms_source(trust_level="Government")],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert "trust-gov" in html


def test_ms_community_source_gets_trust_community_chip():
    """Source with trust_level='Community' renders with trust-community chip."""
    data = {
        "sources": [_ms_source(trust_level="Community")],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert "trust-community" in html


def test_ms_product_grouping_order_windows_before_intune():
    """Windows product group appears before Intune in the rendered HTML."""
    data = {
        "sources": [
            _ms_source(product="Intune", label="Intune Src"),
            _ms_source(product="Windows", label="Windows Src"),
        ],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert html.index(">Windows<") < html.index(">Intune<")


def test_ms_product_grouping_order_intune_before_office365():
    """Intune product group appears before Office 365 in the rendered HTML."""
    data = {
        "sources": [
            _ms_source(product="Office 365", label="O365 Src"),
            _ms_source(product="Intune", label="Intune Src"),
        ],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert html.index(">Intune<") < html.index(">Office 365<")


def test_ms_scubagear_enabled_shows_enabled_copy(monkeypatch):
    """When CLAUDESEC_MS_INCLUDE_SCUBAGEAR is truthy → 'ScubaGear is enabled' copy appears."""
    monkeypatch.setenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", "1")
    data = {"sources": [_ms_source()], "source_filter": "all"}
    html = build_ms_sources_html(data)
    assert "ScubaGear" in html
    assert "is enabled" in html


def test_ms_scubagear_disabled_shows_optional_copy(monkeypatch):
    """When CLAUDESEC_MS_INCLUDE_SCUBAGEAR is absent → 'Optional source available' copy appears."""
    monkeypatch.delenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", raising=False)
    data = {"sources": [_ms_source()], "source_filter": "all"}
    html = build_ms_sources_html(data)
    assert "Optional source available" in html


def test_ms_html_escaping_in_source_label():
    """Source label containing '<script>' is HTML-escaped in output."""
    data = {
        "sources": [_ms_source(label="<script>alert(1)</script>")],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_ms_archived_source_shows_archived_tag():
    """Source with archived=True renders '(archived)' tag in output."""
    data = {
        "sources": [_ms_source(archived=True)],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    assert "(archived)" in html


def test_ms_fetched_at_renders_cache_updated_copy():
    """When fetched_at is present, 'Microsoft source cache updated:' copy appears."""
    data = {
        "sources": [_ms_source()],
        "source_filter": "all",
        "fetched_at": "2026-04-17T10:00:00Z",
    }
    html = build_ms_sources_html(data)
    assert "Microsoft source cache updated:" in html
    # Only the first 19 chars of fetched_at are rendered
    assert "2026-04-17T10:00:00" in html


def test_ms_filter_banner_appears_when_filter_is_not_all():
    """When source_filter != 'all' and sources present → 'Active source filter:' banner appears."""
    data = {
        "sources": [_ms_source(trust_level="Government")],
        "source_filter": "official,gov",
    }
    html = build_ms_sources_html(data)
    assert "Active source filter:" in html
    assert "official,gov" in html


def test_ms_filter_banner_absent_when_filter_is_all():
    """When source_filter == 'all' → 'Active source filter:' banner does NOT appear in source body."""
    data = {
        "sources": [_ms_source()],
        "source_filter": "all",
    }
    html = build_ms_sources_html(data)
    # The banner paragraph for non-all filters must not appear
    assert "Active source filter:" not in html


def test_ms_empty_sources_with_non_all_non_none_filter_shows_matched_filter_message():
    """Empty sources with source_filter not 'all' and not 'none' → 'No Microsoft best-practice sources matched filter' message."""
    data = {"sources": [], "source_filter": "official,gov"}
    html = build_ms_sources_html(data)
    assert "No Microsoft best-practice sources matched filter" in html
    assert "official,gov" in html


# ===========================================================================
# build_saas_sources_html
# ===========================================================================

def test_saas_truly_empty_shows_no_sources_configured():
    """Empty sources with module-level constant also patched → 'No SaaS/DevOps best-practice sources configured'."""
    import dashboard_html_audit_sources as _mod
    import dashboard_api_client as _dac

    original_dac = _dac.SAAS_BEST_PRACTICES_SOURCES
    original_mod = _mod.SAAS_BEST_PRACTICES_SOURCES
    _dac.SAAS_BEST_PRACTICES_SOURCES = []
    _mod.SAAS_BEST_PRACTICES_SOURCES = []
    try:
        html = build_saas_sources_html({"sources": []})
    finally:
        _dac.SAAS_BEST_PRACTICES_SOURCES = original_dac
        _mod.SAAS_BEST_PRACTICES_SOURCES = original_mod

    assert "No SaaS/DevOps best-practice sources configured" in html


def test_saas_vendor_official_source_gets_trust_ms_chip():
    """Source with trust_level='Vendor Official' renders with trust-ms chip and label."""
    data = {"sources": [_saas_source(trust_level="Vendor Official")]}
    html = build_saas_sources_html(data)
    assert "trust-ms" in html
    assert "Vendor Official" in html


def test_saas_cncf_official_source_gets_trust_ms_chip():
    """Source with trust_level='CNCF Official' renders with trust-ms chip (per color map)."""
    data = {"sources": [_saas_source(product="ArgoCD", trust_level="CNCF Official", label="ArgoCD CNCF")]}
    html = build_saas_sources_html(data)
    assert "trust-ms" in html
    assert "CNCF Official" in html


def test_saas_government_source_gets_trust_gov_chip():
    """Source with trust_level='Government' renders with trust-gov chip."""
    data = {"sources": [_saas_source(trust_level="Government")]}
    html = build_saas_sources_html(data)
    assert "trust-gov" in html


def test_saas_community_source_gets_trust_community_chip():
    """Source with trust_level='Community' renders with trust-community chip."""
    data = {"sources": [_saas_source(trust_level="Community")]}
    html = build_saas_sources_html(data)
    assert "trust-community" in html


def test_saas_product_grouping_order_okta_before_querypie():
    """Okta product group appears before QueryPie in the rendered HTML."""
    data = {
        "sources": [
            _saas_source(product="QueryPie", label="QueryPie Src"),
            _saas_source(product="Okta", label="Okta Src"),
        ]
    }
    html = build_saas_sources_html(data)
    assert html.index(">Okta<") < html.index(">QueryPie<")


def test_saas_product_grouping_order_querypie_before_argocd():
    """QueryPie product group appears before ArgoCD in the rendered HTML."""
    data = {
        "sources": [
            _saas_source(product="ArgoCD", label="ArgoCD Src"),
            _saas_source(product="QueryPie", label="QueryPie Src"),
        ]
    }
    html = build_saas_sources_html(data)
    assert html.index(">QueryPie<") < html.index(">ArgoCD<")


def test_saas_focus_paths_rendered_when_populated():
    """Source with focus_paths populated renders 'Focus paths:' copy with comma-joined codes."""
    data = {
        "sources": [
            _saas_source(focus_paths=["policies/", "factors/"])
        ]
    }
    html = build_saas_sources_html(data)
    assert "Focus paths:" in html
    assert "policies/" in html
    assert "factors/" in html


def test_saas_focus_paths_absent_when_empty():
    """Source without focus_paths does NOT render 'Focus paths:' copy."""
    data = {"sources": [_saas_source(focus_paths=[])]}
    html = build_saas_sources_html(data)
    assert "Focus paths:" not in html


def test_saas_html_escaping_in_source_label():
    """Source label containing '<' is HTML-escaped in output."""
    data = {"sources": [_saas_source(label="<evil>label</evil>")]}
    html = build_saas_sources_html(data)
    assert "<evil>" not in html
    assert "&lt;evil&gt;" in html


def test_saas_empty_product_slot_is_skipped():
    """Only Okta has entries — ArgoCD/IDE/QueryPie h4 headers are not rendered."""
    data = {"sources": [_saas_source(product="Okta", label="Okta Only")]}
    html = build_saas_sources_html(data)
    assert ">Okta<" in html
    assert ">QueryPie<" not in html
    assert ">ArgoCD<" not in html
    assert ">IDE<" not in html
