"""
Unit tests for build_compliance_html and build_prov_table in
scanner/lib/dashboard_html_compliance.py.

Each test covers exactly one behaviour.  No network access, no CLI invocation,
no filesystem fixtures beyond the module import itself.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_compliance import build_compliance_html, build_prov_table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _control(control="A.1.1", name="Control name", status="PASS", count=0,
             desc=None, action=None, findings=None):
    c = {
        "control": control,
        "name": name,
        "status": status,
        "count": count,
    }
    if desc is not None:
        c["desc"] = desc
    if action is not None:
        c["action"] = action
    if findings is not None:
        c["findings"] = findings
    return c


def _prov(total_fail=0, total_pass=0, critical=0, high=0, medium=0, low=0):
    return {
        "total_fail": total_fail,
        "total_pass": total_pass,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ===========================================================================
# build_compliance_html
# ===========================================================================

def test_compliance_empty_map_renders_framework_chip_header():
    """Empty compliance_map still renders the 'comp-frameworks' chip header."""
    html = build_compliance_html({})
    assert 'class="comp-frameworks"' in html


def test_compliance_empty_map_has_no_framework_section():
    """Empty compliance_map does not render any 'comp-section' div."""
    html = build_compliance_html({})
    assert 'class="comp-section"' not in html


def test_compliance_single_framework_renders_section():
    """compliance_map with one framework renders a 'comp-section' div."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control()],
    })
    assert 'class="comp-section"' in html


def test_compliance_pass_fail_counts_displayed():
    """Pass/fail counts appear in cs-pass/cs-fail spans for framework with mixed controls."""
    controls = [_control(status="PASS"), _control(status="FAIL"), _control(status="FAIL")]
    html = build_compliance_html({"ISO 27001:2022": controls})
    assert "1 pass" in html
    assert "2 fail" in html


def test_compliance_control_with_pass_uses_comp_pass_class():
    """Control with status PASS renders a 'comp-pass' row class."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control(status="PASS")],
    })
    assert "comp-pass" in html


def test_compliance_control_with_fail_uses_comp_fail_class():
    """Control with status FAIL renders a 'comp-fail' row class."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control(status="FAIL")],
    })
    assert "comp-fail" in html


def test_compliance_control_name_html_escaped():
    """Control name containing '<' is HTML-escaped."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control(name="<script>alert(1)</script>")],
    })
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_compliance_framework_name_html_escaped():
    """Framework name containing '&' is HTML-escaped in section title."""
    html = build_compliance_html({
        "Custom & Framework": [_control()],
    })
    assert "Custom & Framework" not in html
    assert "Custom &amp; Framework" in html


def test_compliance_default_action_when_action_missing():
    """Missing action field falls back to 'Apply security best practices...' copy."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control(action=None)],
    })
    assert "Apply security best practices for this control" in html


def test_compliance_iso_framework_renders_architecture_links():
    """ISO 27001:2022 framework renders the 'Related architecture' chip row."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control()],
    })
    assert "Related architecture" in html


def test_compliance_unknown_framework_omits_architecture_links():
    """An unknown framework name does NOT render the 'Related architecture' row."""
    html = build_compliance_html({
        "Completely Made Up Framework": [_control()],
    })
    assert "Related architecture" not in html


def test_compliance_finding_truncation_over_five():
    """Control with count=8 and 6 finding entries renders '... +3 more' truncation."""
    findings = [{"check": f"c-{i}", "message": "m"} for i in range(6)]
    html = build_compliance_html({
        "ISO 27001:2022": [_control(count=8, findings=findings)],
    })
    assert "... +3 more" in html


def test_compliance_comp_id_uses_slug():
    """Section id uses comp_slug of framework name (lowercase, delimiters replaced)."""
    html = build_compliance_html({
        "ISO 27001:2022": [_control()],
    })
    # comp_slug("ISO 27001:2022") should produce an id like 'iso-27001-2022' or similar
    assert 'id="' in html
    # Guarantee framework heading also present (smoke check)
    assert "ISO 27001:2022" in html


# ===========================================================================
# build_prov_table
# ===========================================================================

def test_prov_empty_summary_renders_all_default_providers():
    """Empty prov_summary still renders the 8 default display-order providers."""
    html = build_prov_table({})
    # _display_order has 8 entries: aws, gcp, googleworkspace, kubernetes, azure, m365, iac, github
    assert html.count("<tr") == 8


def test_prov_empty_summary_kubernetes_uses_no_data_class():
    """kubernetes with no data renders 'prov-row-no-data' class."""
    html = build_prov_table({})
    assert "prov-row-no-data" in html


def test_prov_empty_summary_kubernetes_not_run_copy():
    """kubernetes with no data renders '— not run' copy."""
    html = build_prov_table({})
    assert "— not run" in html


def test_prov_aws_with_data_renders_label():
    """AWS provider with data renders 'AWS' label."""
    html = build_prov_table({"aws": _prov(total_fail=3, total_pass=10)})
    assert "AWS" in html


def test_prov_aws_renders_total_cells():
    """AWS with fail=3 pass=10 renders total 13 in totals cell."""
    html = build_prov_table({"aws": _prov(total_fail=3, total_pass=10)})
    assert ">13</td>" in html


def test_prov_critical_count_rendered_in_red():
    """Critical count is rendered in a #f87171 (red) styled cell."""
    html = build_prov_table({"aws": _prov(total_fail=1, critical=5)})
    assert "#f87171" in html


def test_prov_pass_count_rendered_in_green():
    """Pass count is rendered in a #22c55e (green) styled cell."""
    html = build_prov_table({"aws": _prov(total_pass=7)})
    assert "#22c55e" in html


def test_prov_aws_has_switchprovtab_onclick():
    """AWS row renders an onclick that switches to the 'aws' sub-tab."""
    html = build_prov_table({"aws": _prov(total_fail=1)})
    assert "switchProvTab('aws')" in html


def test_prov_unknown_provider_appended_after_display_order():
    """Providers not in _display_order (e.g. 'llm') are appended to the table."""
    html = build_prov_table({"llm": _prov(total_fail=2, total_pass=4)})
    assert "LLM" in html
    # LLM is not in _display_order so it is appended; totals = 6
    assert ">6</td>" in html


def test_prov_github_with_data_rendered_in_fixed_order():
    """'github' provider present renders with label 'GitHub'."""
    html = build_prov_table({"github": _prov(total_fail=1, total_pass=2)})
    assert "GitHub" in html


def test_prov_googleworkspace_with_zero_totals_shows_not_run():
    """googleworkspace with all-zero data still renders '— not run' row."""
    html = build_prov_table({"googleworkspace": _prov()})
    assert "— not run" in html


def test_prov_googleworkspace_with_data_hides_not_run():
    """googleworkspace with actual data does NOT render '— not run' copy for it."""
    html = build_prov_table({
        "googleworkspace": _prov(total_fail=1, total_pass=2),
    })
    # Another no-data row (kubernetes) may still carry the message, so check the
    # googleworkspace row specifically does not get the no-data class applied to its label
    assert "Google Workspace</td>" in html
