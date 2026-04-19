"""
Pure-input unit tests for scanner/lib/dashboard_html_builders.py.

Each test exercises a single behaviour of the private HTML-builder helpers:
  * _build_scanner_section
  * _build_provider_cards
  * _build_artifact_links_section
  * _build_target_posture_table
  * _build_trivy_section
  * _build_datadog_logs_section
  * _build_datadog_signals_section
  * _build_datadog_cases_section

Tests are authored as both bare `def test_*()` functions (for pytest) AND
as a `unittest.TestCase` wrapper (for `python3 -m xmlrunner discover` in CI,
which loads unittest.TestLoader and therefore only picks up TestCase
subclasses).  Uses stdlib + unittest.mock only — no `import pytest`, so CI
(which does not install pytest) will still import the module successfully.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_html_builders as builders  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _trivy_summary(critical=0, high=0, medium=0, low=0):
    return {"critical": critical, "high": high, "medium": medium, "low": low}


def _net_data(**overrides):
    base = {
        "trivy_fs": None,
        "trivy_config": None,
        "trivy_summary": _trivy_summary(),
        "trivy_vulns": [],
        "nmap_scans": [],
        "sslscan_results": [],
        "network_report": None,
    }
    base.update(overrides)
    return base


def _dd_data(**overrides):
    base = {
        "logs": [],
        "summary": {"error": 0, "warning": 0, "info": 0, "unknown": 0, "total": 0},
        "signals": [],
        "signal_summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "unknown": 0, "total": 0,
        },
        "cases": [],
        "case_summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "unknown": 0, "total": 0,
        },
    }
    base.update(overrides)
    return base


# ===========================================================================
# _build_scanner_section
# ===========================================================================


def test_scanner_section_returns_three_tuple():
    """Returns a 3-tuple (rows, cat_summary, insights_html)."""
    result = builders._build_scanner_section([])
    assert isinstance(result, tuple)
    assert len(result) == 3


def test_scanner_section_empty_list_shows_empty_row():
    """No findings produces the 'No failed or warning findings' placeholder."""
    rows, cat_summary, insights = builders._build_scanner_section([])
    assert "No failed or warning findings from the local scanner" in rows
    assert cat_summary == ""
    assert "No active failed/warning findings" in insights


def test_scanner_section_empty_list_insights_action_plan_default():
    """Empty findings list renders the default action-plan message."""
    _, _, insights = builders._build_scanner_section([])
    assert "Continue running regular scans" in insights


def test_scanner_section_high_finding_uses_sev_high_class():
    """A single high-severity finding produces the sev-high row class."""
    findings = [{
        "id": "TLS-001",
        "title": "Weak TLS cipher",
        "details": "Upgrade to TLS 1.2+",
        "severity": "high",
        "category": "network",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "sev-high" in rows
    assert "Weak TLS cipher" in rows
    assert "Upgrade to TLS 1.2+" in rows


def test_scanner_section_critical_shows_fail_status_icon():
    """Critical severity renders the fail status icon and label."""
    findings = [{
        "id": "IAM-010",
        "title": "Root account active",
        "details": "Disable root usage",
        "severity": "critical",
        "category": "access-control",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "scan-status-critical" in rows
    assert "Fail" in rows


def test_scanner_section_low_shows_warning_status_label():
    """Low severity renders the Warning status label."""
    findings = [{
        "id": "NET-002",
        "title": "Minor issue",
        "details": "Informational",
        "severity": "low",
        "category": "network",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "Warning" in rows


def test_scanner_section_html_escapes_finding_title():
    """A title containing raw HTML is escaped in output."""
    findings = [{
        "id": "CODE-001",
        "title": "<script>alert(1)</script>",
        "details": "",
        "severity": "medium",
        "category": "code",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "<script>alert(1)</script>" not in rows
    assert "&lt;script&gt;" in rows


def test_scanner_section_location_adds_expandable_row():
    """A finding with a location produces an expandable detail row."""
    findings = [{
        "id": "INFRA-001",
        "title": "Exposed port",
        "details": "Close port",
        "severity": "high",
        "category": "infra",
        "location": "/etc/services",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "expandable" in rows
    assert 'data-action="toggleRow"' in rows
    assert "row-detail" in rows


def test_scanner_section_no_details_no_location_no_expandable():
    """A finding without details/location does NOT render row-detail."""
    findings = [{
        "id": "MAC-001",
        "title": "Title only",
        "details": "",
        "severity": "medium",
        "category": "macos",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "row-detail" not in rows


def test_scanner_section_cat_summary_contains_scat_chip():
    """cat_summary contains a scat-chip per non-empty category."""
    findings = [{
        "id": "NET-001",
        "title": "x",
        "details": "",
        "severity": "medium",
        "category": "network",
    }]
    _, cat_summary, _ = builders._build_scanner_section(findings)
    assert "scat-chip" in cat_summary
    assert "Network security" in cat_summary


def test_scanner_section_groups_by_category_header():
    """Each category with findings produces a cat-header row."""
    findings = [
        {"id": "NET-001", "title": "n", "details": "", "severity": "medium", "category": "network"},
        {"id": "CODE-001", "title": "c", "details": "", "severity": "medium", "category": "code"},
    ]
    rows, _, _ = builders._build_scanner_section(findings)
    assert rows.count("cat-header") == 2


def test_scanner_section_arch_links_for_network_category():
    """Network category produces at least one arch-link-chip via SCANNER_TO_ARCH."""
    findings = [{
        "id": "NET-001",
        "title": "t",
        "details": "",
        "severity": "medium",
        "category": "network",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "arch-link-chip" in rows
    assert "Related architecture" in rows


def test_scanner_section_other_category_has_no_arch_links():
    """'other' category yields no architecture link chips (SCANNER_TO_ARCH is [])."""
    findings = [{
        "id": "OTHER-001",
        "title": "t",
        "details": "",
        "severity": "medium",
        "category": "other",
    }]
    rows, _, _ = builders._build_scanner_section(findings)
    assert "Related architecture" not in rows


def test_scanner_section_infers_category_from_id_when_missing():
    """Missing category is inferred from the id prefix (IAM → access-control)."""
    findings = [{
        "id": "IAM-042",
        "title": "x",
        "details": "",
        "severity": "medium",
    }]
    rows, cat_summary, _ = builders._build_scanner_section(findings)
    # Category label contains '&' which is HTML-escaped to '&amp;' in rows,
    # but the cat_summary chip uses the raw label text.
    assert "Access control &amp; IAM" in rows
    assert "Access control & IAM" in cat_summary


def test_scanner_section_severity_count_summary_line():
    """Insights summary line contains severity counts."""
    findings = [
        {"id": "A-1", "title": "a", "details": "", "severity": "critical", "category": "code"},
        {"id": "A-2", "title": "b", "details": "", "severity": "high", "category": "code"},
    ]
    _, _, insights = builders._build_scanner_section(findings)
    assert "1 critical" in insights
    assert "1 high" in insights


def test_scanner_section_top_findings_deduplicated_actions():
    """Repeated 'details' strings are deduplicated in the action plan."""
    findings = [
        {"id": "F-1", "title": "t1", "details": "Do the thing", "severity": "high", "category": "code"},
        {"id": "F-2", "title": "t2", "details": "Do the thing", "severity": "medium", "category": "code"},
    ]
    _, _, insights = builders._build_scanner_section(findings)
    # "Do the thing" should appear once in the <ol> action-plan list.
    action_block = insights.split("Action plan")[1]
    assert action_block.count("Do the thing") == 1


def test_scanner_section_top_findings_limited_to_6_in_detail_list():
    """Detail list shows at most 6 <li> entries (top_findings cap)."""
    findings = [
        {"id": f"F-{i:03d}", "title": f"t{i}", "details": "",
         "severity": "medium", "category": "code"}
        for i in range(20)
    ]
    _, _, insights = builders._build_scanner_section(findings)
    detail_block = insights.split("Detail (Top findings)")[1].split("Action plan")[0]
    assert detail_block.count("<li") == 6


def test_scanner_section_action_list_limited_to_5():
    """Action list shows at most 5 items (cap after dedup)."""
    findings = [
        {"id": f"F-{i}", "title": "t", "details": f"Action #{i}",
         "severity": "high", "category": "code"}
        for i in range(10)
    ]
    _, _, insights = builders._build_scanner_section(findings)
    action_block = insights.split("Action plan")[1]
    assert action_block.count("<li>") == 5


def test_scanner_section_warning_severity_counted_in_summary():
    """Warning-severity findings appear in the summary count."""
    findings = [{
        "id": "X-1", "title": "t", "details": "",
        "severity": "warning", "category": "other",
    }]
    _, _, insights = builders._build_scanner_section(findings)
    assert "1 warning" in insights


def test_scanner_section_top_categories_limited_to_three():
    """Hotspots line shows at most 3 category entries."""
    findings = [
        {"id": "A-1", "title": "t", "details": "", "severity": "medium", "category": "code"},
        {"id": "B-1", "title": "t", "details": "", "severity": "medium", "category": "network"},
        {"id": "C-1", "title": "t", "details": "", "severity": "medium", "category": "infra"},
        {"id": "D-1", "title": "t", "details": "", "severity": "medium", "category": "cloud"},
    ]
    _, _, insights = builders._build_scanner_section(findings)
    hotspots = insights.split("Hotspots:")[1].split("</p>")[0]
    assert hotspots.count(" · ") == 2  # 3 entries joined by 2 separators


# ===========================================================================
# _build_provider_cards
# ===========================================================================


def test_provider_cards_empty_returns_empty_string():
    """Empty provider summary returns an empty string."""
    assert builders._build_provider_cards({}) == ""


def test_provider_cards_aws_entry_rendered():
    """Known provider 'aws' renders its label and icon."""
    html = builders._build_provider_cards({
        "aws": {"total_fail": 2, "total_pass": 3, "critical": 1, "high": 1, "medium": 0, "low": 0},
    })
    assert "AWS" in html
    assert "prov-card" in html
    assert "☁" in html


def test_provider_cards_critical_badge_rendered():
    """Provider with critical>0 renders the pcs-crit badge."""
    html = builders._build_provider_cards({
        "aws": {"total_fail": 1, "total_pass": 0, "critical": 1, "high": 0, "medium": 0, "low": 0},
    })
    assert "pcs-crit" in html
    assert "1C" in html


def test_provider_cards_high_badge_rendered():
    """Provider with high>0 renders the pcs-high badge."""
    html = builders._build_provider_cards({
        "gcp": {"total_fail": 1, "total_pass": 0, "critical": 0, "high": 2, "medium": 0, "low": 0},
    })
    assert "pcs-high" in html
    assert "2H" in html


def test_provider_cards_medium_badge_rendered():
    """Provider with medium>0 renders the pcs-med badge."""
    html = builders._build_provider_cards({
        "azure": {"total_fail": 1, "total_pass": 0, "critical": 0, "high": 0, "medium": 3, "low": 0},
    })
    assert "pcs-med" in html
    assert "3M" in html


def test_provider_cards_no_severity_badges_when_all_zero():
    """Zero crit/high/med counts suppress their badges."""
    html = builders._build_provider_cards({
        "aws": {"total_fail": 0, "total_pass": 1, "critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    assert "pcs-crit" not in html
    assert "pcs-high" not in html
    assert "pcs-med" not in html


def test_provider_cards_unknown_provider_falls_back_to_default():
    """Unknown provider name uses default cloud icon and provider name as label."""
    html = builders._build_provider_cards({
        "mysterycloud": {"total_fail": 0, "total_pass": 1, "critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    assert "mysterycloud" in html
    assert "☁" in html


def test_provider_cards_totals_displayed():
    """Fail count and total (fail+pass) are both displayed."""
    html = builders._build_provider_cards({
        "github": {"total_fail": 4, "total_pass": 6, "critical": 0, "high": 0, "medium": 0, "low": 0},
    })
    # e.g. 4<span class="prov-card-total">/10</span>
    assert ">4<" in html
    assert "/10" in html


# ===========================================================================
# _build_artifact_links_section
# ===========================================================================


def test_artifact_links_returns_empty_when_no_files():
    """With no artifact files present on disk, returns empty string."""
    with mock.patch("os.path.isfile", return_value=False):
        assert builders._build_artifact_links_section() == ""


def test_artifact_links_renders_card_when_file_exists():
    """When at least one artifact exists, renders the quick-links card."""
    with mock.patch(
        "os.path.isfile",
        side_effect=lambda p: p == ".claudesec-network/network-report.v1.json",
    ):
        html = builders._build_artifact_links_section()
    assert "Artifacts (quick links)" in html
    assert "network-report.v1.json" in html


def test_artifact_links_swallows_isfile_exception():
    """An OSError from os.path.isfile does NOT propagate."""
    with mock.patch("os.path.isfile", side_effect=OSError("boom")):
        html = builders._build_artifact_links_section()
    assert html == ""


# ===========================================================================
# _build_target_posture_table
# ===========================================================================


def test_target_posture_empty_net_data_returns_empty():
    """net_data with no network_report returns empty string."""
    assert builders._build_target_posture_table({"network_report": None}) == ""


def test_target_posture_no_targets_returns_empty():
    """network_report with empty targets list returns empty string."""
    assert builders._build_target_posture_table({"network_report": {"targets": []}}) == ""


def test_target_posture_renders_card_title():
    """Populated targets list produces the card-title heading."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{"target": "example.com", "dns": {"ips": ["1.2.3.4"]},
                                        "tls": {"grade": "A"}, "http": {"status": 200}}]}
    })
    assert "Target posture" in html


def test_target_posture_redacts_target_by_default():
    """Default env keeps identifiers redacted ('target-<hash>')."""
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", None)
        html = builders._build_target_posture_table({
            "network_report": {"targets": [{"target": "example.com",
                                            "dns": {"ips": []}, "tls": {"grade": "A"},
                                            "http": {"status": 200}}]}
        })
    assert "target-" in html
    assert "example.com" not in html


def test_target_posture_shows_identifier_when_env_set():
    """CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS=1 surfaces the raw target."""
    with mock.patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS": "1"}):
        html = builders._build_target_posture_table({
            "network_report": {"targets": [{"target": "example.com",
                                            "dns": {"ips": []}, "tls": {"grade": "A"},
                                            "http": {"status": 200}}]}
        })
    assert "example.com" in html


def test_target_posture_renders_dns_count():
    """DNS IP count is rendered as an integer cell."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{"target": "x",
                                        "dns": {"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]},
                                        "tls": {}, "http": {}}]}
    })
    # Cell containing DNS count `>3<` should appear
    assert ">3<" in html


def test_target_posture_row_detail_when_issues():
    """Header issues populate a row-detail panel."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{
            "target": "x", "dns": {"ips": []}, "tls": {},
            "http": {"issues": [{"severity": "high", "id": "H-1", "title": "Bad header"}]},
        }]}
    })
    assert "row-detail" in html
    assert "H-1" in html
    assert "Bad header" in html


def test_target_posture_row_detail_when_redirect_chain():
    """Redirect chain populates a row-detail panel with 'Redirect chain' label."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{
            "target": "x", "dns": {"ips": []}, "tls": {},
            "http": {"redirect_chain": [{"status": 301, "location": "https://final"}]},
        }]}
    })
    assert "Redirect chain" in html
    assert "https://final" in html


def test_target_posture_overflow_note_when_more_than_20_issues():
    """More than 20 header issues produces an '… and N more' note."""
    issues = [{"severity": "low", "id": f"I-{i}", "title": f"issue {i}"} for i in range(25)]
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{
            "target": "x", "dns": {"ips": []}, "tls": {},
            "http": {"issues": issues},
        }]}
    })
    assert "and 5 more" in html


def test_target_posture_handles_non_dict_target():
    """Non-dict entries in targets list are skipped without raising."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": ["not-a-dict", {"target": "x",
                                                     "dns": {"ips": []}, "tls": {}, "http": {}}]},
    })
    assert "Target posture" in html


def test_target_posture_handles_non_dict_http_tls_dns():
    """Non-dict http/tls/dns fields default to empty without raising."""
    html = builders._build_target_posture_table({
        "network_report": {"targets": [{"target": "x",
                                        "dns": "broken", "tls": None, "http": 42}]},
    })
    assert "Target posture" in html


# ===========================================================================
# _build_trivy_section
# ===========================================================================


def test_trivy_section_empty_returns_empty_string():
    """With no trivy/nmap/sslscan data, returns empty string."""
    assert builders._build_trivy_section(_net_data(), _trivy_summary()) == ""


def test_trivy_section_with_trivy_fs_renders_card():
    """Populated trivy_fs triggers the Trivy severity card."""
    html = builders._build_trivy_section(
        _net_data(trivy_fs={"foo": "bar"}),
        _trivy_summary(critical=2, high=1),
    )
    assert "Trivy (vulnerabilities" in html
    # severity counts rendered
    assert ">2<" in html
    assert ">1<" in html


def test_trivy_section_with_vulns_renders_top_50_card():
    """Populated trivy_vulns renders the 'Trivy findings (top 50)' card."""
    vulns = [{"severity": "HIGH", "id": "CVE-0001", "target": "pkg-a",
              "pkg": "libx", "title": "Overflow"}]
    html = builders._build_trivy_section(_net_data(trivy_fs={}, trivy_vulns=vulns),
                                         _trivy_summary(high=1))
    assert "Trivy findings (top 50)" in html
    assert "CVE-0001" in html
    assert "Overflow" in html


def test_trivy_section_unknown_severity_maps_to_low():
    """Unknown vulnerability severity is rendered with the low badge class."""
    vulns = [{"severity": "BOGUS", "id": "CVE-X", "target": "", "pkg": "", "title": ""}]
    html = builders._build_trivy_section(_net_data(trivy_fs={}, trivy_vulns=vulns),
                                         _trivy_summary())
    assert 'class="badge low"' in html


def test_trivy_section_nmap_scan_rendered():
    """Nmap scan list renders per-host entries with ports."""
    nmap = [{"name": "scan1", "hosts": [{"addr": "1.2.3.4", "ports": ["22/tcp", "80/tcp"]}]}]
    html = builders._build_trivy_section(_net_data(nmap_scans=nmap), _trivy_summary())
    assert "Nmap scan summary" in html
    assert "scan1" in html
    assert "1.2.3.4" in html
    assert "22/tcp" in html


def test_trivy_section_nmap_empty_ports_shows_none_marker():
    """Nmap host with empty ports renders '(none)' marker."""
    nmap = [{"name": "s", "hosts": [{"addr": "h", "ports": []}]}]
    html = builders._build_trivy_section(_net_data(nmap_scans=nmap), _trivy_summary())
    assert "(none)" in html


def test_trivy_section_sslscan_rendered():
    """sslscan_results list renders the SSL/TLS card with scan names."""
    ssl = [{"name": "ssl1", "data": {}}]
    html = builders._build_trivy_section(_net_data(sslscan_results=ssl), _trivy_summary())
    assert "SSL/TLS scan" in html
    assert "ssl1" in html


# ===========================================================================
# _build_datadog_logs_section
# ===========================================================================


def test_datadog_logs_empty_summary_returns_empty():
    """Summary with total=0 returns empty string."""
    assert builders._build_datadog_logs_section(_dd_data()) == ""


def test_datadog_logs_missing_summary_returns_empty():
    """Missing summary key returns empty string."""
    assert builders._build_datadog_logs_section({"logs": []}) == ""


def test_datadog_logs_renders_summary_card():
    """Non-zero summary total renders the Datadog CI log summary card."""
    html = builders._build_datadog_logs_section(_dd_data(
        summary={"error": 2, "warning": 1, "info": 3, "unknown": 0, "total": 6},
    ))
    assert "Datadog CI log summary" in html
    assert "Datadog CI logs (latest 100)" in html


def test_datadog_logs_renders_log_row_with_escaped_message():
    """A log row renders its message with HTML escaping."""
    html = builders._build_datadog_logs_section(_dd_data(
        summary={"error": 1, "warning": 0, "info": 0, "unknown": 0, "total": 1},
        logs=[{"severity": "error", "message": "<b>boom</b>",
               "source": "svc-a", "timestamp": "2026-01-01T00:00:00Z"}],
    ))
    assert "svc-a" in html
    assert "<b>boom</b>" not in html
    assert "&lt;b&gt;boom&lt;/b&gt;" in html


def test_datadog_logs_warning_sev_uses_warning_badge():
    """Warning-severity log rows use the 'warning' badge class."""
    html = builders._build_datadog_logs_section(_dd_data(
        summary={"error": 0, "warning": 1, "info": 0, "unknown": 0, "total": 1},
        logs=[{"severity": "warning", "message": "m", "source": "s", "timestamp": "t"}],
    ))
    assert 'class="badge warning"' in html


def test_datadog_logs_unknown_sev_uses_low_badge():
    """Unknown severity log rows fall back to the 'low' badge class."""
    html = builders._build_datadog_logs_section(_dd_data(
        summary={"error": 0, "warning": 0, "info": 0, "unknown": 1, "total": 1},
        logs=[{"severity": "unknown", "message": "m", "source": "s", "timestamp": "t"}],
    ))
    assert 'class="badge low"' in html


# ===========================================================================
# _build_datadog_signals_section
# ===========================================================================


def test_datadog_signals_empty_returns_empty():
    """signal_summary total=0 returns empty string."""
    assert builders._build_datadog_signals_section(_dd_data()) == ""


def test_datadog_signals_renders_summary_card():
    """Non-zero signal total renders the signals summary card."""
    html = builders._build_datadog_signals_section(_dd_data(
        signal_summary={"critical": 1, "high": 2, "medium": 0, "low": 0,
                        "info": 0, "unknown": 0, "total": 3},
    ))
    assert "Datadog Cloud Security signals summary" in html
    assert "Datadog Cloud Security signals (critical/high first)" in html


def test_datadog_signals_critical_badge_used():
    """Critical-severity signal uses the critical badge class."""
    html = builders._build_datadog_signals_section(_dd_data(
        signal_summary={"critical": 1, "high": 0, "medium": 0, "low": 0,
                        "info": 0, "unknown": 0, "total": 1},
        signals=[{"severity": "critical", "timestamp": "t", "status": "open",
                  "rule": "R-1", "title": "Bad signal"}],
    ))
    assert 'class="badge critical"' in html
    assert "R-1" in html
    assert "Bad signal" in html


def test_datadog_signals_unknown_severity_falls_back_to_low():
    """Unknown severity maps to the 'low' badge class."""
    html = builders._build_datadog_signals_section(_dd_data(
        signal_summary={"critical": 0, "high": 0, "medium": 0, "low": 1,
                        "info": 0, "unknown": 0, "total": 1},
        signals=[{"severity": "weird", "timestamp": "t", "status": "s",
                  "rule": "r", "title": "t"}],
    ))
    assert 'class="badge low"' in html


# ===========================================================================
# _build_datadog_cases_section
# ===========================================================================


def test_datadog_cases_empty_returns_empty():
    """case_summary total=0 returns empty string."""
    assert builders._build_datadog_cases_section(_dd_data()) == ""


def test_datadog_cases_renders_both_cards():
    """Non-zero case_summary total renders summary + list cards."""
    html = builders._build_datadog_cases_section(_dd_data(
        case_summary={"critical": 1, "high": 0, "medium": 0, "low": 0,
                      "info": 0, "unknown": 0, "total": 1},
        cases=[{"severity": "critical", "timestamp": "t", "status": "open",
                "rule": "incident-type", "title": "Case A"}],
    ))
    assert "Datadog case management summary" in html
    assert "Datadog cases (critical/high first)" in html
    assert "Case A" in html


def test_datadog_cases_high_sev_uses_high_badge():
    """High-severity case uses the 'high' badge class."""
    html = builders._build_datadog_cases_section(_dd_data(
        case_summary={"critical": 0, "high": 1, "medium": 0, "low": 0,
                      "info": 0, "unknown": 0, "total": 1},
        cases=[{"severity": "high", "timestamp": "t", "status": "s",
                "rule": "r", "title": "t"}],
    ))
    assert 'class="badge high"' in html


def test_datadog_cases_html_escapes_title():
    """Case title containing HTML is escaped in output."""
    html = builders._build_datadog_cases_section(_dd_data(
        case_summary={"critical": 0, "high": 0, "medium": 1, "low": 0,
                      "info": 0, "unknown": 0, "total": 1},
        cases=[{"severity": "medium", "timestamp": "t", "status": "s",
                "rule": "r", "title": "<img src=x>"}],
    ))
    assert "<img src=x>" not in html
    assert "&lt;img" in html


# ---------------------------------------------------------------------------
# unittest.TestCase wrapper so the same assertions run under `python -m
# unittest discover` / `xmlrunner discover` (CI), which only picks up
# TestCase subclasses — not bare `def test_*` functions.
# ---------------------------------------------------------------------------


# Enumerate every module-level test_* function above so unittest can discover
# each as an independent TestCase method.  Using a closure avoids copy-paste.
_MODULE = sys.modules[__name__]
_TEST_FUNCS = sorted(
    name for name in dir(_MODULE)
    if name.startswith("test_") and callable(getattr(_MODULE, name))
)


def _make_method(fn):
    def method(self):  # noqa: ANN001
        fn()
    method.__doc__ = fn.__doc__
    return method


class TestDashboardHtmlBuildersPure(unittest.TestCase):
    """Auto-generated TestCase wrapping every module-level test_* function."""


for _name in _TEST_FUNCS:
    setattr(
        TestDashboardHtmlBuildersPure,
        _name,
        _make_method(getattr(_MODULE, _name)),
    )


if __name__ == "__main__":
    unittest.main()
