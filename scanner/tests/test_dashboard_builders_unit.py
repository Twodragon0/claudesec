"""
Unit tests for the four HTML builder functions extracted into
scanner/lib/dashboard_html_sections.py.

Each test covers exactly one behaviour.  No network access, no CLI invocation,
no filesystem fixtures beyond the module import itself.
"""

import sys
import os

# Make the lib directory importable exactly as the other test files do.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_sections import (
    _build_compliance_html,
    _build_audit_points_html,
    _build_arch_html,
    _build_prov_table,
)


# ---------------------------------------------------------------------------
# _build_compliance_html
# ---------------------------------------------------------------------------

def test_compliance_empty_map_returns_framework_chip_header():
    """Empty compliance_map produces the framework-chip header and no framework sections."""
    html = _build_compliance_html({})
    assert 'class="comp-frameworks"' in html
    # No comp-section div should exist (no frameworks iterated)
    assert 'class="comp-section"' not in html


def test_compliance_pass_control_has_comp_pass_class():
    """A PASS control row gets the comp-pass CSS class."""
    compliance_map = {
        "TestFramework": [
            {"status": "PASS", "control": "T-1", "name": "Test Control",
             "desc": "Desc", "action": "Action", "count": 0},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert 'class="comp-pass"' in html


def test_compliance_fail_control_has_comp_fail_class():
    """A FAIL control row gets the comp-fail CSS class."""
    compliance_map = {
        "TestFramework": [
            {"status": "FAIL", "control": "T-2", "name": "Fail Control",
             "desc": "Desc", "action": "Action", "count": 1},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert 'class="comp-fail"' in html


def test_compliance_pass_fail_counts_in_cs_spans():
    """Pass and fail counts are rendered in .cs-pass and .cs-fail spans."""
    compliance_map = {
        "MixedFramework": [
            {"status": "PASS", "control": "M-1", "name": "Pass", "desc": "", "action": "", "count": 0},
            {"status": "PASS", "control": "M-2", "name": "Pass2", "desc": "", "action": "", "count": 0},
            {"status": "FAIL", "control": "M-3", "name": "Fail", "desc": "", "action": "", "count": 1},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert 'class="cs-pass"' in html
    assert '2 pass' in html
    assert 'class="cs-fail"' in html
    assert '1 fail' in html


def test_compliance_control_with_findings_renders_findings_div():
    """A control whose 'findings' list is populated produces a comp-findings div."""
    compliance_map = {
        "FindingFW": [
            {
                "status": "FAIL",
                "control": "F-1",
                "name": "Ctrl",
                "desc": "Desc",
                "action": "Act",
                "count": 1,
                "findings": [
                    {"severity": "High", "check": "chk-001", "message": "Bad thing",
                     "provider": "aws", "resource": "arn:aws:s3:::my-bucket"},
                ],
            }
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert 'class="comp-findings"' in html
    assert "chk-001" in html


def test_compliance_iso27001_framework_has_arch_links():
    """ISO 27001:2022 is in COMP_FW_TO_ARCH so its section contains arch link chips."""
    compliance_map = {
        "ISO 27001:2022": [
            {"status": "PASS", "control": "A.5.1", "name": "Policies",
             "desc": "Desc", "action": "Act", "count": 0},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert "comp-arch-links" in html


def test_compliance_unknown_framework_has_no_arch_links():
    """A framework not in COMP_FW_TO_ARCH produces no architecture-links row."""
    compliance_map = {
        "MyCustomFramework": [
            {"status": "PASS", "control": "C-1", "name": "Custom",
             "desc": "Desc", "action": "Act", "count": 0},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert "comp-arch-links" not in html


def test_compliance_html_escapes_control_name():
    """Control name containing HTML special characters is escaped in output."""
    compliance_map = {
        "EscFW": [
            {"status": "PASS", "control": "E-1", "name": "<script>alert(1)</script>",
             "desc": "Desc", "action": "Act", "count": 0},
        ]
    }
    html = _build_compliance_html(compliance_map)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_compliance_multiple_frameworks_all_rendered():
    """Multiple frameworks each produce their own comp-section block."""
    compliance_map = {
        "FW Alpha": [
            {"status": "PASS", "control": "A-1", "name": "Alpha ctrl",
             "desc": "", "action": "", "count": 0},
        ],
        "FW Beta": [
            {"status": "FAIL", "control": "B-1", "name": "Beta ctrl",
             "desc": "", "action": "", "count": 2},
        ],
    }
    html = _build_compliance_html(compliance_map)
    assert "FW Alpha" in html
    assert "FW Beta" in html
    assert html.count('class="comp-section"') == 2


# ---------------------------------------------------------------------------
# _build_audit_points_html
# ---------------------------------------------------------------------------

def _empty_audit_inputs():
    return (
        {"products": [], "fetched_at": ""},  # audit_points_data
        {"detected_products": [], "items": []},  # audit_points_detected
        {"sources": [], "fetched_at": ""},  # ms_best_practices_data
        {"sources": []},  # saas_bp_data
    )


def test_audit_points_all_empty_shows_fallback_message():
    """All four inputs empty → fallback message about running claudesec scan."""
    html = _build_audit_points_html(*_empty_audit_inputs())
    assert "claudesec scan -c saas" in html


def test_audit_points_detected_products_shows_relevant_section():
    """Populated detected_products produces 'Relevant to this project' heading."""
    ap_data = {
        "products": [
            {"name": "Okta", "files": [{"name": "okta-checklist.md", "url": "https://example.com/okta.md"}]},
        ],
        "fetched_at": "",
    }
    ap_detected = {"detected_products": ["Okta"], "items": []}
    ms_data = {"sources": [], "fetched_at": ""}
    saas_data = {"sources": []}
    html = _build_audit_points_html(ap_data, ap_detected, ms_data, saas_data)
    assert "Relevant to this project" in html
    assert "ap-detected-chip" in html


def test_audit_points_all_products_without_detection_shows_querypie_heading():
    """all_products without detected_products produces 'QueryPie Audit Points' heading."""
    ap_data = {
        "products": [
            {"name": "Jenkins", "files": []},
        ],
        "fetched_at": "",
    }
    ap_detected = {"detected_products": [], "items": []}
    ms_data = {"sources": [], "fetched_at": ""}
    saas_data = {"sources": []}
    html = _build_audit_points_html(ap_data, ap_detected, ms_data, saas_data)
    assert "QueryPie Audit Points" in html


def test_audit_points_ms_sources_populated_renders_trust_chips():
    """ms_best_practices_data.sources populated → trust-badge chips appear."""
    ap_data = {"products": [], "fetched_at": ""}
    ap_detected = {"detected_products": [], "items": []}
    ms_data = {
        "sources": [
            {
                "product": "Office 365",
                "label": "Microsoft Security Baseline",
                "trust_level": "Microsoft Official",
                "reason": "official baseline",
                "repo": "microsoft/example",
                "repo_url": "https://github.com/microsoft/example",
                "files": [],
            }
        ],
        "source_filter": "all",
        "fetched_at": "",
    }
    saas_data = {"sources": []}
    html = _build_audit_points_html(ap_data, ap_detected, ms_data, saas_data)
    assert "trust-ms" in html
    assert "Microsoft Official" in html


def test_audit_points_saas_sources_empty_shows_no_sources_configured():
    """saas_bp_data.sources empty → fallback text when no SaaS sources configured.

    The function falls back to SAAS_BEST_PRACTICES_SOURCES when saas_bp_data.sources
    is empty.  We pass a non-empty saas_bp_data dict with sources=[] to force the
    empty-sources branch, which triggers the 'No SaaS/DevOps best-practice sources
    configured' message regardless of the module-level constant.
    """
    ap_data = {"products": [], "fetched_at": ""}
    ap_detected = {"detected_products": [], "items": []}
    ms_data = {"sources": [], "fetched_at": ""}
    # saas_bp_data.sources is explicitly [] — the function uses this value directly
    # and only falls back to SAAS_BEST_PRACTICES_SOURCES when .get("sources") is falsy.
    # To force the empty branch we need to patch the fallback constant in the sections module.
    import dashboard_html_sections as _sections_mod
    import dashboard_api_client as _dac
    original_const = _dac.SAAS_BEST_PRACTICES_SOURCES
    _dac.SAAS_BEST_PRACTICES_SOURCES = []
    # The function reads the name via `from dashboard_api_client import ...` at module load,
    # so we also patch it in the sections module's own namespace.
    original_sections = getattr(_sections_mod, "SAAS_BEST_PRACTICES_SOURCES", original_const)
    _sections_mod.SAAS_BEST_PRACTICES_SOURCES = []
    try:
        html = _build_audit_points_html(ap_data, ap_detected, ms_data, {"sources": []})
    finally:
        _dac.SAAS_BEST_PRACTICES_SOURCES = original_const
        _sections_mod.SAAS_BEST_PRACTICES_SOURCES = original_sections

    assert "No SaaS/DevOps best-practice sources configured" in html


def test_audit_points_html_escapes_product_name():
    """Product name containing '<' is escaped so raw HTML tags don't appear."""
    ap_data = {
        "products": [
            {"name": "<Evil>Product</Evil>", "files": []},
        ],
        "fetched_at": "",
    }
    ap_detected = {"detected_products": [], "items": []}
    ms_data = {"sources": [], "fetched_at": ""}
    saas_data = {"sources": []}
    html = _build_audit_points_html(ap_data, ap_detected, ms_data, saas_data)
    assert "<Evil>" not in html
    assert "&lt;Evil&gt;" in html


# ---------------------------------------------------------------------------
# _build_arch_html
# ---------------------------------------------------------------------------

def test_arch_empty_domains_returns_empty_string():
    """Empty arch_domains list returns an empty string."""
    result = _build_arch_html([])
    assert result == ""


def test_arch_domain_with_no_findings_gets_pass_class():
    """Domain with fail_count=0 gets 'arch-domain pass' class and 'No findings' text."""
    domains = [
        {
            "name": "Network & TLS",
            "icon": "🌐",
            "fail_count": 0,
            "summary": "Good network posture",
            "action": "Keep it up",
            "findings": [],
            "links": {"owasp": [], "compliance": [], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert 'arch-domain pass' in html
    assert "No findings in this domain" in html


def test_arch_domain_with_findings_gets_fail_class():
    """Domain with fail_count > 0 gets 'arch-domain fail' class."""
    domains = [
        {
            "name": "Identity & Access",
            "icon": "🔐",
            "fail_count": 3,
            "summary": "IAM issues found",
            "action": "Fix IAM",
            "findings": [
                {"severity": "High", "check": "iam-001", "message": "Overprivileged role",
                 "provider": "aws", "resource": "arn:aws:iam::123:role/admin"},
            ],
            "links": {"owasp": [], "compliance": [], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert 'arch-domain fail' in html


def test_arch_domain_findings_rendered_up_to_8():
    """Up to 8 findings are rendered; no overflow note when count <= 8."""
    findings = [
        {"severity": "Medium", "check": f"chk-{i:03d}", "message": f"Issue {i}",
         "provider": "gcp", "resource": ""}
        for i in range(8)
    ]
    domains = [
        {
            "name": "Data & Storage",
            "icon": "💾",
            "fail_count": 8,
            "summary": "Storage findings",
            "action": "Fix storage",
            "findings": findings,
            "links": {"owasp": [], "compliance": [], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert "chk-000" in html
    assert "chk-007" in html
    assert "and" not in html.split("of-more")[1] if "of-more" in html else True


def test_arch_domain_overflow_note_when_fail_count_exceeds_8():
    """fail_count > 8 produces '... and N more' overflow note."""
    findings = [
        {"severity": "Low", "check": f"chk-{i:03d}", "message": f"Issue {i}",
         "provider": "aws", "resource": ""}
        for i in range(8)
    ]
    domains = [
        {
            "name": "CI/CD",
            "icon": "🔄",
            "fail_count": 15,
            "summary": "Pipeline risks",
            "action": "Harden pipeline",
            "findings": findings,
            "links": {"owasp": [], "compliance": [], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert "of-more" in html
    assert "7 more" in html  # 15 - 8 = 7


def test_arch_domain_owasp_link_chip_rendered():
    """Domain with links.owasp populated produces arch-owasp chip."""
    domains = [
        {
            "name": "Application",
            "icon": "🖥",
            "fail_count": 0,
            "summary": "",
            "action": "",
            "findings": [],
            "links": {"owasp": ["A01-2025"], "compliance": [], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert "arch-owasp" in html
    assert "A01-2025" in html


def test_arch_domain_compliance_link_chip_rendered():
    """Domain with links.compliance populated produces arch-comp chip with comp_slug id."""
    domains = [
        {
            "name": "Compliance Domain",
            "icon": "📋",
            "fail_count": 0,
            "summary": "",
            "action": "",
            "findings": [],
            "links": {"owasp": [], "compliance": [("ISO 27001:2022", "A.5.1")], "scanner": []},
        }
    ]
    html = _build_arch_html(domains)
    assert "arch-comp" in html
    assert "A.5.1" in html


def test_arch_domain_scanner_chip_rendered_with_label():
    """Domain with links.scanner=['code'] produces a 'Code' scanner chip."""
    domains = [
        {
            "name": "Code Security",
            "icon": "💻",
            "fail_count": 0,
            "summary": "",
            "action": "",
            "findings": [],
            "links": {"owasp": [], "compliance": [], "scanner": ["code"]},
        }
    ]
    html = _build_arch_html(domains)
    assert "arch-scanner" in html
    assert "Code" in html


# ---------------------------------------------------------------------------
# _build_prov_table
# ---------------------------------------------------------------------------

def test_prov_table_empty_summary_produces_8_fixed_rows():
    """Empty prov_summary still renders the 8 fixed display-order rows."""
    html = _build_prov_table({})
    # Fixed order: aws, gcp, googleworkspace, kubernetes, azure, m365, iac, github
    assert "AWS" in html
    assert "GCP" in html
    assert "Google Workspace" in html
    assert "K8s" in html
    assert "Azure" in html
    assert "Microsoft 365" in html
    assert "IaC" in html
    assert "GitHub" in html


def test_prov_table_kubernetes_zero_totals_shows_not_run():
    """kubernetes with zero totals produces prov-row-no-data class and 'not run' marker."""
    html = _build_prov_table({"kubernetes": {"total_fail": 0, "total_pass": 0,
                                              "critical": 0, "high": 0, "medium": 0, "low": 0}})
    assert "prov-row-no-data" in html
    assert "not run" in html


def test_prov_table_kubernetes_nonzero_totals_no_not_run():
    """kubernetes with non-zero totals renders a normal row without 'not run' marker."""
    html = _build_prov_table({"kubernetes": {"total_fail": 2, "total_pass": 5,
                                              "critical": 1, "high": 1, "medium": 0, "low": 0}})
    # The K8s row label is "K8s"; split on it to isolate text AFTER the K8s row starts.
    # googleworkspace (which precedes kubernetes in display order) may still show
    # prov-row-no-data, but the K8s row itself must not contain "not run".
    parts = html.split(">K8s<", 1)
    assert len(parts) == 2, "K8s row not found in output"
    k8s_row_and_after = parts[1]
    # The "not run" span appears only inside prov-row-no-data rows.
    # The next <tr> boundary is a safe delimiter for the K8s row fragment.
    k8s_row_fragment = k8s_row_and_after.split("</tr>", 1)[0]
    assert "not run" not in k8s_row_fragment


def test_prov_table_extra_provider_appears_after_fixed_rows():
    """A provider not in the display order (e.g. cloudflare) still appears in the table."""
    html = _build_prov_table({
        "cloudflare": {"total_fail": 3, "total_pass": 10,
                       "critical": 1, "high": 2, "medium": 0, "low": 0}
    })
    assert "Cloudflare" in html


def test_prov_table_critical_color_present():
    """Critical severity count cell uses the #f87171 color."""
    html = _build_prov_table({
        "aws": {"total_fail": 1, "total_pass": 0,
                "critical": 1, "high": 0, "medium": 0, "low": 0}
    })
    assert "#f87171" in html


def test_prov_table_high_color_present():
    """High severity count cell uses the #fca5a5 color."""
    html = _build_prov_table({
        "aws": {"total_fail": 1, "total_pass": 0,
                "critical": 0, "high": 1, "medium": 0, "low": 0}
    })
    assert "#fca5a5" in html


def test_prov_table_medium_color_present():
    """Medium severity count cell uses the #fde68a color."""
    html = _build_prov_table({
        "aws": {"total_fail": 1, "total_pass": 0,
                "critical": 0, "high": 0, "medium": 1, "low": 0}
    })
    assert "#fde68a" in html


def test_prov_table_googleworkspace_zero_shows_not_run():
    """googleworkspace with zero totals also produces prov-row-no-data (same guard as k8s)."""
    html = _build_prov_table({"googleworkspace": {"total_fail": 0, "total_pass": 0,
                                                   "critical": 0, "high": 0, "medium": 0, "low": 0}})
    assert "prov-row-no-data" in html
