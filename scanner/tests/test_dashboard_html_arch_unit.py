"""
Unit tests for build_arch_html and build_owasp_html in
scanner/lib/dashboard_html_arch.py.

Each test covers exactly one behaviour.  No network access, no CLI invocation,
no filesystem fixtures beyond the module import itself.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_arch import build_arch_html, build_owasp_html


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain(name="Domain", icon="🧩", fail_count=0, findings=None, links=None,
            summary=None, action=None):
    """Build a minimal arch-domain dict as consumed by build_arch_html."""
    d = {
        "name": name,
        "icon": icon,
        "fail_count": fail_count,
        "findings": findings if findings is not None else [],
    }
    if links is not None:
        d["links"] = links
    if summary is not None:
        d["summary"] = summary
    if action is not None:
        d["action"] = action
    return d


def _finding(severity="High", check="c-1", message="msg", provider="", resource=""):
    return {
        "severity": severity,
        "check": check,
        "message": message,
        "provider": provider,
        "resource": resource,
    }


# ===========================================================================
# build_arch_html
# ===========================================================================

def test_arch_empty_list_returns_empty_string():
    """Empty arch_domains list → empty string, no wrapper HTML."""
    assert build_arch_html([]) == ""


def test_arch_single_domain_renders_arch_domain_wrapper():
    """Single domain renders a div with class 'arch-domain'."""
    html = build_arch_html([_domain(name="Access")])
    assert 'class="arch-domain' in html


def test_arch_domain_with_zero_fail_uses_pass_class():
    """Domain with fail_count=0 renders status class 'pass'."""
    html = build_arch_html([_domain(fail_count=0)])
    assert "arch-domain pass" in html


def test_arch_domain_with_positive_fail_uses_fail_class():
    """Domain with fail_count>0 renders status class 'fail'."""
    html = build_arch_html([_domain(fail_count=3)])
    assert "arch-domain fail" in html


def test_arch_domain_id_uses_index():
    """Domain id attribute uses the enumerate index."""
    html = build_arch_html([_domain(name="A"), _domain(name="B")])
    assert 'id="arch-dom-0"' in html
    assert 'id="arch-dom-1"' in html


def test_arch_domain_name_is_html_escaped():
    """Domain name containing '<' is HTML-escaped in output."""
    html = build_arch_html([_domain(name="<attack>")])
    assert "<attack>" not in html
    assert "&lt;attack&gt;" in html


def test_arch_domain_icon_rendered():
    """Domain icon character appears verbatim in output."""
    html = build_arch_html([_domain(icon="🔐")])
    assert "🔐" in html


def test_arch_fail_count_rendered_in_stat():
    """Fail count renders in the arch-stat block as '{n} failed'."""
    html = build_arch_html([_domain(fail_count=7)])
    assert "7 failed" in html


def test_arch_no_findings_renders_pass_checkmark_copy():
    """Domain with no findings renders the '✓ No findings in this domain.' copy."""
    html = build_arch_html([_domain(findings=[])])
    assert "No findings in this domain" in html


def test_arch_findings_rendered_as_af_row():
    """Findings list renders each entry with 'af-row' div."""
    html = build_arch_html([_domain(fail_count=1, findings=[_finding()])])
    assert 'class="af-row"' in html


def test_arch_findings_truncated_at_eight_with_more_message():
    """Domain with 10 findings renders 8 af-rows + '... and 2 more' truncation."""
    findings = [_finding(check=f"c-{i}") for i in range(10)]
    html = build_arch_html([_domain(fail_count=10, findings=findings)])
    assert html.count('class="af-row"') == 8
    assert "... and 2 more" in html


def test_arch_scanner_coverage_dots_rendered_when_scanner_link_present():
    """Domain with scanner link renders cov-dot spans."""
    html = build_arch_html([
        _domain(links={"scanner": ["network"]}),
    ])
    assert "cov-dot" in html


def test_arch_owasp_link_chip_rendered():
    """Domain with owasp link renders 'arch-owasp' chip with the owasp id."""
    html = build_arch_html([
        _domain(links={"owasp": ["A01"]}),
    ])
    assert "arch-owasp" in html
    assert "A01" in html


def test_arch_compliance_link_chip_rendered():
    """Domain with compliance link renders 'arch-comp' chip with the control id."""
    html = build_arch_html([
        _domain(links={"compliance": [("ISO 27001:2022", "A.5.15")]}),
    ])
    assert "arch-comp" in html
    assert "A.5.15" in html


def test_arch_no_links_omits_arch_links_container():
    """Domain with no owasp/compliance/scanner links does NOT render 'arch-links' container."""
    html = build_arch_html([_domain(links={})])
    assert 'class="arch-links"' not in html


def test_arch_default_summary_when_summary_missing():
    """Missing summary falls back to the domain name."""
    html = build_arch_html([_domain(name="MyDomain")])
    # The summary line uses the domain name when summary absent
    assert "MyDomain" in html


def test_arch_default_action_when_action_missing():
    """Missing action falls back to the 'Apply security best practices...' copy."""
    html = build_arch_html([_domain()])
    assert "Apply security best practices" in html


# ===========================================================================
# build_owasp_html
# ===========================================================================

def test_owasp_empty_map_renders_web_heading():
    """Empty owasp_map still renders the Web application security heading."""
    html = build_owasp_html({})
    assert "OWASP Top 10:2025" in html


def test_owasp_empty_map_renders_llm_heading():
    """Empty owasp_map still renders the LLM Applications 2025 heading."""
    html = build_owasp_html({})
    assert "OWASP Top 10 for LLM Applications 2025" in html


def test_owasp_no_findings_uses_pass_class():
    """An OWASP category with no findings renders with status class 'pass'."""
    html = build_owasp_html({})
    assert "owasp-item pass" in html


def test_owasp_with_findings_uses_fail_class():
    """An OWASP category populated with findings renders with status class 'fail'."""
    findings = [_finding()]
    html = build_owasp_html({"A01:2025": findings})
    assert "owasp-item fail" in html


def test_owasp_finding_message_escaped():
    """Finding message containing '<' is HTML-escaped."""
    findings = [_finding(message="<evil>payload")]
    html = build_owasp_html({"A01:2025": findings})
    assert "<evil>payload" not in html
    assert "&lt;evil&gt;" in html


def test_owasp_findings_truncated_at_ten():
    """More than 10 findings in a single category → '... and N more' truncation."""
    findings = [_finding(check=f"c-{i}") for i in range(15)]
    html = build_owasp_html({"A01:2025": findings})
    assert "... and 5 more" in html


def test_owasp_count_badge_reflects_findings_length():
    """Count badge shows the number of findings for that OWASP id."""
    findings = [_finding(check=f"c-{i}") for i in range(3)]
    html = build_owasp_html({"A01:2025": findings})
    # Look for the owasp-count span with value 3
    assert '<span class="owasp-count">3</span>' in html
