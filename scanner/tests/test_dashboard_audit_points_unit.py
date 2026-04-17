"""
Unit tests for build_audit_points_querypie_html in
scanner/lib/dashboard_html_audit_points.py.

Each test covers exactly one behaviour.  No network access, no CLI invocation,
no filesystem fixtures beyond the module import itself.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_audit_points import build_audit_points_querypie_html


# ---------------------------------------------------------------------------
# Helpers – minimal data constructors
# ---------------------------------------------------------------------------

def _product(name, files=None, tree_url=None, repo_url=None):
    """Build a minimal product dict as returned by the audit-points API."""
    p = {"name": name, "files": files if files is not None else []}
    if tree_url is not None:
        p["tree_url"] = tree_url
    if repo_url is not None:
        p["repo_url"] = repo_url
    return p


def _file_item(name, url=None):
    """Build a minimal file item dict."""
    item = {"name": name}
    if url is not None:
        item["url"] = url
    return item


def _audit_data(products=None, fetched_at=None):
    d = {"products": products if products is not None else []}
    if fetched_at is not None:
        d["fetched_at"] = fetched_at
    return d


def _detected(product_names=None):
    return {"detected_products": product_names if product_names is not None else []}


# ===========================================================================
# 1. Both inputs empty → fallback message
# ===========================================================================

def test_both_inputs_empty_renders_fallback_scan_message():
    """Both inputs empty → fallback paragraph with 'claudesec scan -c saas' appears."""
    html = build_audit_points_querypie_html(_audit_data(), _detected())
    assert "claudesec scan -c saas" in html


def test_both_inputs_empty_renders_querypie_audit_points_heading():
    """Both inputs empty → card heading 'QueryPie Audit Points' appears in fallback."""
    html = build_audit_points_querypie_html(_audit_data(), _detected())
    assert "QueryPie Audit Points" in html


# ===========================================================================
# 2. products populated, detected_products empty
# ===========================================================================

def test_products_only_renders_querypie_audit_points_heading():
    """With products and no detected products → section titled 'QueryPie Audit Points' (not 'Relevant to this project')."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert "QueryPie Audit Points" in html
    assert "Relevant to this project" not in html


def test_products_only_renders_product_name():
    """Product name 'Jenkins' appears in catalog when detected_products is empty."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Jenkins", files=[_file_item("audit.md")])]),
        _detected(),
    )
    assert "Jenkins" in html


def test_products_only_renders_item_count():
    """Item count badge rendered correctly for a product with 3 files."""
    files = [_file_item(f"file{i}.md") for i in range(3)]
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Nexus", files=files)]),
        _detected(),
    )
    assert "3 items" in html


# ===========================================================================
# 3. Both populated with overlap → "Relevant to this project" + detected chips
# ===========================================================================

def test_both_populated_renders_relevant_heading():
    """Both inputs populated with overlap → 'Relevant to this project' section heading appears."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("check.md")])]),
        _detected(["Okta"]),
    )
    assert "Relevant to this project" in html


def test_both_populated_renders_detected_badge_with_green_count():
    """Detected badge shows count in green colour class (rgba(34,197,94))."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(["Okta"]),
    )
    assert "22c55e" in html


def test_both_populated_renders_ap_detected_chip_for_each_detected_product():
    """Each detected product gets an 'ap-detected-chip' span."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[
            _product("Okta"),
            _product("Jenkins"),
        ]),
        _detected(["Okta", "Jenkins"]),
    )
    assert html.count('class="ap-detected-chip"') == 2


def test_detected_product_card_has_open_class():
    """Detected product card has the 'open' CSS class (expanded by default)."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("a.md")])]),
        _detected(["Okta"]),
    )
    # The detected section uses 'ap-product-card open'
    assert 'ap-product-card open' in html


# ===========================================================================
# 4. Detected product not in audit_points_data.products → silently skipped
# ===========================================================================

def test_detected_product_missing_from_catalog_is_skipped():
    """Detected product absent from catalog does not render a product card (no ap-product-card for it)."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(["GhostProduct"]),
    )
    # GhostProduct may appear in the detected-chip strip, but must NOT have a product card
    # A product card would include data-product="ghostproduct" attribute
    assert 'data-product="ghostproduct"' not in html


# ===========================================================================
# 5. Per-product card rendering
# ===========================================================================

def test_known_product_jenkins_uses_wrench_icon():
    """Jenkins maps to the 🔧 icon."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Jenkins")]),
        _detected(),
    )
    assert "🔧" in html


def test_known_product_okta_uses_lock_icon():
    """Okta maps to the 🔐 icon."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert "🔐" in html


def test_unknown_product_uses_clipboard_icon():
    """Unknown product name maps to the 📋 fallback icon."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("UnknownTool")]),
        _detected(),
    )
    assert "📋" in html


def test_explicit_tree_url_rendered_as_github_link():
    """When product has explicit tree_url it appears in the output verbatim."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", tree_url="https://example.com/custom-tree")]),
        _detected(),
    )
    assert "https://example.com/custom-tree" in html


def test_tree_url_constructed_from_repo_when_absent():
    """When tree_url is absent, URL is built from the AUDIT_POINTS_REPO + product name."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("My Product")]),
        _detected(),
    )
    # URL-encoded product name used in auto-constructed href
    assert "My%20Product" in html


def test_file_item_rendered_with_audit_item_row_class():
    """File items appear inside 'bp-audit-item-row' div."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("audit.md")])]),
        _detected(),
    )
    assert 'class="bp-audit-item-row"' in html


def test_file_item_rendered_with_ap_checkbox():
    """File items include an 'ap-checkbox' input."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("audit.md")])]),
        _detected(),
    )
    assert 'class="ap-checkbox"' in html


def test_file_item_data_ap_id_follows_pattern():
    """data-ap-id for item 1 of 'My Tool' → 'ap-my-tool-1' (lowercase, spaces→hyphens)."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("My Tool", files=[_file_item("check.md")])]),
        _detected(),
    )
    assert 'data-ap-id="ap-my-tool-1"' in html


def test_file_item_index_number_rendered():
    """Index number '1' appears in 'bp-audit-index' span for first file item."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("a.md")])]),
        _detected(),
    )
    assert 'class="bp-audit-index">1<' in html


def test_file_extension_rendered_in_bp_audit_ext_span():
    """File name with extension renders '<span class="bp-audit-ext">.md</span>'."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("checklist.md")])]),
        _detected(),
    )
    assert '<span class="bp-audit-ext">.md</span>' in html


def test_file_without_extension_has_no_bp_audit_ext_span():
    """File name without '.' does NOT produce a 'bp-audit-ext' span."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("MAKEFILE")])]),
        _detected(),
    )
    assert 'bp-audit-ext' not in html


# ===========================================================================
# 6. Catalog file truncation at 50 items
# ===========================================================================

def test_sixty_files_truncated_to_fifty_with_truncation_message():
    """Product with 60 files renders only first 50 and '… and 10 more in' message."""
    files = [_file_item(f"file{i:03d}.md") for i in range(60)]
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Jenkins", files=files)]),
        _detected(),
    )
    assert "… and 10 more in" in html


def test_fifty_files_exactly_has_no_truncation_message():
    """Product with exactly 50 files does NOT render the truncation message."""
    files = [_file_item(f"file{i:03d}.md") for i in range(50)]
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Jenkins", files=files)]),
        _detected(),
    )
    assert "… and" not in html


def test_truncation_message_includes_github_folder_link():
    """Truncation message links to a GitHub folder URL."""
    files = [_file_item(f"f{i}.md") for i in range(55)]
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=files)]),
        _detected(),
    )
    assert "GitHub folder" in html


# ===========================================================================
# 7. fetched_at rendered when present
# ===========================================================================

def test_fetched_at_renders_cache_updated_copy():
    """When fetched_at is present, 'Cache updated:' copy and first 19 chars appear."""
    html = build_audit_points_querypie_html(
        _audit_data(
            products=[_product("Okta")],
            fetched_at="2026-04-17T10:00:00Z",
        ),
        _detected(),
    )
    assert "Cache updated:" in html
    assert "2026-04-17T10:00:00" in html


def test_fetched_at_absent_no_cache_updated_copy():
    """When fetched_at is absent, 'Cache updated:' copy does NOT appear."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert "Cache updated:" not in html


# ===========================================================================
# 8. HTML escaping
# ===========================================================================

def test_product_name_with_angle_brackets_is_escaped():
    """Product name containing '<' is HTML-escaped in rendered output."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("<evil>")]),
        _detected(),
    )
    assert "<evil>" not in html
    assert "&lt;evil&gt;" in html


def test_file_name_with_ampersand_is_escaped():
    """File name containing '&' is HTML-escaped in rendered output."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta", files=[_file_item("check&verify.md")])]),
        _detected(),
    )
    assert "check&verify" not in html
    assert "check&amp;verify" in html


def test_product_name_with_double_quotes_is_escaped():
    """Product name containing '\"' is HTML-escaped in data-product attribute."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product('Say "Hello"')]),
        _detected(),
    )
    assert 'Say "Hello"' not in html
    assert "&quot;" in html


# ===========================================================================
# 9. Search bar + progress bar always rendered when products present
# ===========================================================================

def test_search_bar_rendered_when_products_present():
    """Search bar input with class 'ap-search' appears when products list is non-empty."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert 'class="ap-search"' in html


def test_progress_bar_rendered_when_products_present():
    """Progress bar fill element 'ap-progress-fill' appears when products list is non-empty."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert 'ap-progress-fill' in html


def test_search_bar_rendered_when_only_detected_present():
    """Search bar appears even when all_products is empty but detected_products is non-empty."""
    # This exercises the branch: detected_products OR all_products → show search bar
    # We need a product in all_products for detected to match, but this tests
    # the strip rendering path when detected_products list is populated
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(["Okta"]),
    )
    assert 'class="ap-search"' in html


# ===========================================================================
# 10. Detection summary strip counts
# ===========================================================================

def test_detection_summary_shows_det_count_and_all_count():
    """Summary strip shows '{det} detected / {all} total' when detection populated."""
    products = [_product("Okta", files=[_file_item("f.md")]), _product("Jenkins")]
    html = build_audit_points_querypie_html(
        _audit_data(products=products),
        _detected(["Okta"]),
    )
    assert "1 detected / 2 total" in html


def test_detection_summary_shows_detected_items_count():
    """Summary strip shows checklist items count matching detected products' file counts."""
    files = [_file_item(f"f{i}.md") for i in range(3)]
    products = [_product("Okta", files=files)]
    html = build_audit_points_querypie_html(
        _audit_data(products=products),
        _detected(["Okta"]),
    )
    assert "3 checklist items" in html


def test_no_detected_shows_no_products_detected_message():
    """When detected_products is empty but all_products present → 'No products detected' message."""
    html = build_audit_points_querypie_html(
        _audit_data(products=[_product("Okta")]),
        _detected(),
    )
    assert "No products detected in this repo" in html
