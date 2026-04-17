"""
Unit tests for build_network_config_section and build_tooling_readiness_section
in scanner/lib/dashboard_html_network.py.

Each test covers exactly one behaviour. No network access, no filesystem
fixtures beyond the module import itself.
"""

import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_network import (
    build_network_config_section,
    build_tooling_readiness_section,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(**overrides):
    """Return an env-patcher context manager that clears the three env vars
    and applies the given overrides."""
    base = {
        "CLAUDESEC_NETWORK_SCAN_ENABLED": "0",
        "CLAUDESEC_NETWORK_SCAN_TARGETS": "",
        "CLAUDESEC_TRIVY_ENABLED": "1",
    }
    base.update(overrides)
    return mock.patch.dict(os.environ, base, clear=False)


# ===========================================================================
# 1. build_network_config_section() return shape and defaults
# ===========================================================================

def test_config_section_returns_four_tuple():
    """build_network_config_section returns a 4-tuple (html, enabled, targets, trivy)."""
    with _env():
        result = build_network_config_section()
    assert isinstance(result, tuple)
    assert len(result) == 4


def test_config_section_renders_card_title():
    """Configuration card renders the 'Network &amp; Security — Configuration' title."""
    with _env():
        html, *_ = build_network_config_section()
    assert "Network &amp; Security — Configuration" in html


def test_config_section_renders_three_ssb_items():
    """Configuration grid contains exactly three 'ssb-item' blocks."""
    with _env():
        html, *_ = build_network_config_section()
    assert html.count('class="ssb-item"') == 3


def test_config_section_default_net_enabled_is_zero():
    """When env var is unset, net_enabled defaults to '0'."""
    with _env():
        _, net_enabled, _, _ = build_network_config_section()
    assert net_enabled == "0"


def test_config_section_default_trivy_enabled_is_one():
    """When env var is unset, trivy_enabled defaults to '1'."""
    with _env():
        _, _, _, trivy_enabled = build_network_config_section()
    assert trivy_enabled == "1"


def test_config_section_empty_targets_renders_placeholder():
    """Empty net_targets renders '(empty)' placeholder in the targets cell."""
    with _env(CLAUDESEC_NETWORK_SCAN_TARGETS=""):
        html, *_ = build_network_config_section()
    assert "(empty)" in html


def test_config_section_populated_targets_rendered():
    """Populated CLAUDESEC_NETWORK_SCAN_TARGETS is rendered in output."""
    with _env(CLAUDESEC_NETWORK_SCAN_TARGETS="example.com:443"):
        html, _, net_targets, _ = build_network_config_section()
    assert "example.com:443" in html
    assert net_targets == "example.com:443"


def test_config_section_targets_with_html_are_escaped():
    """Raw HTML in targets env var is HTML-escaped in output."""
    with _env(CLAUDESEC_NETWORK_SCAN_TARGETS="<script>alert(1)</script>"):
        html, *_ = build_network_config_section()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_config_section_renders_enable_instructions_code_block():
    """Config section includes the CLAUDESEC_NETWORK_SCAN_ENABLED=1 export line."""
    with _env():
        html, *_ = build_network_config_section()
    assert "export CLAUDESEC_NETWORK_SCAN_ENABLED=1" in html


# ===========================================================================
# 2. build_tooling_readiness_section — readiness card skeleton
# ===========================================================================

def test_readiness_renders_card_title():
    """Tooling card renders the 'Tooling readiness (auto-detected)' title."""
    html = build_tooling_readiness_section({}, "0", "", "1")
    assert "Tooling readiness (auto-detected)" in html


def test_readiness_renders_env_grid():
    """Tooling card always renders an 'env-grid' container."""
    html = build_tooling_readiness_section({}, "0", "", "1")
    assert 'class="env-grid"' in html


def test_readiness_renders_recommended_install_commands():
    """Tooling card always renders the recommended install commands block."""
    html = build_tooling_readiness_section({}, "0", "", "1")
    assert "Recommended install commands" in html
    assert "brew install curl nmap sslscan" in html


# ===========================================================================
# 3. Next-steps guidance — driven by enable flags and tooling presence
# ===========================================================================

def test_readiness_disabled_shows_enable_next_step():
    """net_enabled=0 surfaces the 'Enable network scanning' next-step note."""
    html = build_tooling_readiness_section({}, "0", "", "1")
    assert "Next steps" in html
    assert "CLAUDESEC_NETWORK_SCAN_ENABLED=1" in html


def test_readiness_enabled_no_targets_shows_targets_next_step():
    """net_enabled=1 without targets surfaces the 'No targets configured' note."""
    html = build_tooling_readiness_section({}, "1", "", "0")
    assert "No targets configured" in html


def test_readiness_enabled_with_targets_no_targets_note():
    """net_enabled=1 with targets does NOT surface the 'No targets configured' note."""
    with mock.patch("dashboard_html_network._has_cmd", return_value=True):
        html = build_tooling_readiness_section(
            {"network_report": {"targets": [{"http": {}, "tls": {}}]}},
            "1",
            "example.com",
            "0",
        )
    assert "No targets configured" not in html


def test_readiness_trivy_enabled_missing_trivy_surfaces_install_hint():
    """trivy_enabled=1 but `trivy` absent surfaces the install hint."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c != "trivy",
    ):
        html = build_tooling_readiness_section({}, "0", "", "1")
    assert "`trivy` not found" in html


def test_readiness_trivy_disabled_suppresses_install_hint():
    """trivy_enabled=0 suppresses the trivy install hint even when trivy absent."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c != "trivy",
    ):
        html = build_tooling_readiness_section({}, "0", "", "0")
    assert "`trivy` not found" not in html


def test_readiness_trivy_enabled_present_no_install_hint():
    """trivy_enabled=1 with trivy present does NOT surface install hint."""
    with mock.patch("dashboard_html_network._has_cmd", return_value=True):
        html = build_tooling_readiness_section({}, "0", "", "1")
    assert "`trivy` not found" not in html


# ===========================================================================
# 4. Enable-flag value handling (truthy / falsy strings)
# ===========================================================================

def test_readiness_enabled_accepts_true_string():
    """net_enabled='true' is treated as enabled."""
    html = build_tooling_readiness_section({}, "true", "", "0")
    assert "No targets configured" in html


def test_readiness_enabled_accepts_yes_string():
    """net_enabled='yes' is treated as enabled."""
    html = build_tooling_readiness_section({}, "yes", "", "0")
    assert "No targets configured" in html


def test_readiness_trivy_enabled_falsy_off_value():
    """trivy_enabled='off' is treated as disabled (no install hint even if missing)."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c != "trivy",
    ):
        html = build_tooling_readiness_section({}, "0", "", "off")
    assert "`trivy` not found" not in html


# ===========================================================================
# 5. net_data artifact hints
# ===========================================================================

def test_readiness_enabled_with_curl_no_http_artifacts_hint():
    """net_enabled + targets + curl present + no http artifacts → HTTP artifact hint."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c == "curl",
    ):
        html = build_tooling_readiness_section({}, "1", "example.com", "0")
    assert "HTTP header artifacts not found yet" in html


def test_readiness_enabled_with_sslscan_no_tls_artifacts_hint():
    """net_enabled + targets + sslscan present + no tls artifacts → TLS artifact hint."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c == "sslscan",
    ):
        html = build_tooling_readiness_section({}, "1", "example.com", "0")
    assert "TLS artifacts not found yet" in html


def test_readiness_net_data_with_http_artifact_suppresses_hint():
    """net_data with http artifact suppresses the 'HTTP header artifacts' hint."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c == "curl",
    ):
        html = build_tooling_readiness_section(
            {"network_report": {"targets": [{"http": {"status": 200}}]}},
            "1",
            "example.com",
            "0",
        )
    assert "HTTP header artifacts not found yet" not in html


def test_readiness_net_data_with_tls_artifact_suppresses_hint():
    """net_data with tls artifact suppresses the 'TLS artifacts' hint."""
    with mock.patch(
        "dashboard_html_network._has_cmd",
        side_effect=lambda c: c == "sslscan",
    ):
        html = build_tooling_readiness_section(
            {"network_report": {"targets": [{"tls": {"grade": "A"}}]}},
            "1",
            "example.com",
            "0",
        )
    assert "TLS artifacts not found yet" not in html


def test_readiness_malformed_net_data_does_not_raise():
    """Malformed net_data (non-dict network_report) is handled gracefully."""
    html = build_tooling_readiness_section(
        {"network_report": "not-a-dict"},
        "0",
        "",
        "0",
    )
    assert "Tooling readiness" in html
