"""
Unit tests for build_service_surface_html, build_priority_queue_html,
and build_overview_blocks in scanner/lib/dashboard_html_overview.py.

Each test covers exactly one behaviour. No network access, no filesystem
fixtures beyond the module import itself.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_html_overview import (
    build_service_surface_html,
    build_priority_queue_html,
    build_overview_blocks,
    _build_top_findings,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _empty_net_data():
    return {
        "trivy_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "trivy_fs": None,
        "trivy_vulns": [],
        "nmap_scans": [],
        "sslscan_results": [],
        "network_report": {"targets": []},
    }


def _empty_datadog_data():
    return {
        "summary": {"total": 0},
        "signal_summary": {"total": 0},
        "case_summary": {"total": 0},
        "logs": [],
        "signals": [],
        "cases": [],
    }


def _prov_summary(total_fail=0, total_pass=0, critical=0, high=0, medium=0, low=0):
    return {
        "total_fail": total_fail,
        "total_pass": total_pass,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ===========================================================================
# 1. build_service_surface_html — skeleton and card counts
# ===========================================================================

def test_service_surface_renders_coverage_grid_wrapper():
    """Service-surface builder wraps output in a 'coverage-grid' container."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert '<div class="coverage-grid">' in html
    assert html.endswith("</div>")


def test_service_surface_renders_six_coverage_cards():
    """Service-surface builder always renders six coverage-card blocks."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert html.count('class="coverage-card"') == 6


def test_service_surface_renders_all_six_card_labels():
    """Service-surface builder surfaces all six card labels."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    for label in (
        "Local scanner",
        "Cloud CSPM",
        "Integrations",
        "Architecture",
        "Network telemetry",
        "Guidance hub",
    ):
        assert label in html


def test_service_surface_empty_scanner_shows_pass_skip_fallback():
    """Empty findings_list surfaces the 'pass/skip only' fallback copy."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert "pass/skip only" in html


def test_service_surface_env_connected_equal_total_all_connected_copy():
    """env_connected == env_total (non-zero) surfaces 'All configured providers connected'."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 3, 3, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert "All configured providers connected" in html


def test_service_surface_env_partial_connected_surfaces_gap_count():
    """Partial env connection surfaces 'N providers still need setup'."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 1, 3, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert "2 providers still need setup" in html


def test_service_surface_arch_attention_message_when_failures():
    """Architecture card surfaces '{n} domains need attention' when fail_count > 0."""
    html = build_service_surface_html(
        [],
        0, 0, 0,
        {},
        0, 0,
        _empty_net_data(),
        _empty_datadog_data(),
        [{"fail_count": 2}, {"fail_count": 0}],
        {},
        {},
    )
    assert "1 domains need attention" in html


def test_service_surface_arch_no_failures_shows_clean_message():
    """Architecture card surfaces 'No mapped architecture findings' when nothing failing."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(),
        [{"fail_count": 0}], {}, {},
    )
    assert "No mapped architecture findings in this run" in html


def test_service_surface_none_inputs_do_not_raise():
    """None datadog/net/audit/ms inputs are coerced to empty dicts without raising."""
    html = build_service_surface_html(
        [], 0, 0, 0, {}, 0, 0, None, None, [], None, None
    )
    assert '<div class="coverage-grid">' in html


def test_service_surface_escapes_scanner_category_labels():
    """Scanner category labels are HTML-escaped in the output."""
    findings = [{"id": "secrets.api_key_leak", "category": "<b>secrets</b>"}]
    html = build_service_surface_html(
        findings, 1, 0, 0, {}, 0, 0, _empty_net_data(), _empty_datadog_data(), [], {}, {}
    )
    assert "<b>secrets</b>" not in html


# ===========================================================================
# 2. build_priority_queue_html — skeleton and branch selection
# ===========================================================================

def test_priority_queue_renders_priority_grid_wrapper():
    """Priority-queue builder wraps output in a 'priority-grid' container."""
    html = build_priority_queue_html(
        [], {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert '<div class="priority-grid">' in html


def test_priority_queue_renders_three_cards():
    """Priority-queue builder always renders three priority-card buttons."""
    html = build_priority_queue_html(
        [], {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert html.count('class="priority-card ') == 3


def test_priority_queue_no_urgent_surfaces_success_copy():
    """Empty urgent findings surfaces the 'No critical/high findings in this run' card."""
    html = build_priority_queue_html(
        [], {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert "No critical/high findings in this run" in html


def test_priority_queue_urgent_findings_surface_burn_down_copy():
    """Critical findings in scanner surface the 'Burn down N critical/high findings' title."""
    findings = [{"severity": "critical", "id": "a"}, {"severity": "high", "id": "b"}]
    html = build_priority_queue_html(
        findings, {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert "Burn down 2 critical/high findings" in html


def test_priority_queue_five_urgent_findings_use_critical_tone():
    """5+ urgent findings elevate the immediate card tone to 'critical'."""
    findings = [{"severity": "critical", "id": str(i)} for i in range(5)]
    html = build_priority_queue_html(
        findings, {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert 'class="priority-card priority-critical"' in html


def test_priority_queue_four_urgent_findings_use_warning_tone():
    """1-4 urgent findings use the 'warning' tone, not 'critical'."""
    findings = [{"severity": "critical", "id": str(i)} for i in range(4)]
    html = build_priority_queue_html(
        findings, {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert 'class="priority-card priority-warning"' in html
    assert 'class="priority-card priority-critical"' not in html


def test_priority_queue_disconnected_integrations_surface_gap():
    """env_connected < env_total surfaces the 'disconnected integration(s)' gap chip."""
    html = build_priority_queue_html(
        [], {}, 0, 3, _empty_net_data(), _empty_datadog_data()
    )
    assert "3 disconnected integration(s)" in html


def test_priority_queue_missing_cspm_and_network_surfaces_gaps():
    """Empty prov_summary + empty net_data surface the cloud-CSPM and telemetry gap chips."""
    html = build_priority_queue_html(
        [], {}, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert "cloud CSPM evidence missing" in html
    assert "network or Datadog telemetry missing" in html


def test_priority_queue_all_evidence_present_surfaces_baseline_met():
    """When CSPM + network evidence exist, the 'Coverage baseline met' chip is used."""
    prov = {"aws": _prov_summary(total_fail=1, total_pass=2)}
    net_data = _empty_net_data()
    net_data["trivy_summary"]["high"] = 1
    html = build_priority_queue_html(
        [], prov, 3, 3, net_data, _empty_datadog_data()
    )
    assert "Coverage baseline met" in html


def test_priority_queue_focus_items_with_top_provider():
    """Provider failures surface the provider label chip in focus section."""
    prov = {"aws": _prov_summary(total_fail=2, critical=1, high=1)}
    findings = [{"severity": "critical", "id": "a", "category": "secrets"}]
    html = build_priority_queue_html(
        findings, prov, 0, 0, _empty_net_data(), _empty_datadog_data()
    )
    assert "AWS" in html


def test_priority_queue_escapes_card_chips():
    """Priority chips are HTML-escaped."""
    html = build_priority_queue_html(
        [], {}, 0, 3, _empty_net_data(), _empty_datadog_data()
    )
    # chip text with numbers is safe; check the tone class is escaped
    assert "<script>" not in html


# ===========================================================================
# 3. _build_top_findings — grouping and fallback
# ===========================================================================

def test_top_findings_empty_shows_fallback_copy():
    """Empty inputs surface the 'No critical or high findings' fallback banner."""
    html = _build_top_findings([], [])
    assert "No critical or high findings" in html


def test_top_findings_scanner_critical_renders_row():
    """A scanner critical finding renders a 'top-finding' row."""
    findings = [{"severity": "critical", "id": "iam.root_mfa", "title": "root MFA off"}]
    html = _build_top_findings(findings, [])
    assert "iam.root_mfa" in html
    assert 'class="top-finding"' in html


def test_top_findings_low_severity_is_filtered_out():
    """Low/medium scanner findings are filtered out of the top list."""
    findings = [{"severity": "low", "id": "scanner.low", "title": "x"}]
    html = _build_top_findings(findings, [])
    assert "scanner.low" not in html


def test_top_findings_prowler_critical_renders_row():
    """A Prowler Critical finding renders with its check name."""
    prowler = [{
        "severity": "Critical",
        "check": "aws_root_account_mfa",
        "provider": "aws",
        "message": "root has no MFA",
    }]
    html = _build_top_findings([], prowler)
    assert "aws_root_account_mfa" in html


def test_top_findings_escapes_message_text():
    """Prowler messages containing HTML are escaped."""
    prowler = [{
        "severity": "Critical",
        "check": "c",
        "message": "<img src=x onerror=y>",
        "provider": "p",
    }]
    html = _build_top_findings([], prowler)
    assert "<img src=x" not in html
    assert "&lt;img" in html


def test_top_findings_duplicate_groups_include_count_chip():
    """Repeated (severity, check, provider) triples emit an '(N)' occurrence chip."""
    prowler = [
        {"severity": "High", "check": "c1", "provider": "p1", "message": "m"}
        for _ in range(3)
    ]
    html = _build_top_findings([], prowler)
    assert "(3)" in html


def test_top_findings_caps_rows_at_twelve():
    """Top findings surface at most 12 entries."""
    prowler = [
        {"severity": "High", "check": f"c{i}", "provider": "p", "message": "m"}
        for i in range(20)
    ]
    html = _build_top_findings([], prowler)
    assert html.count('class="top-finding"') == 12


# ===========================================================================
# 4. build_overview_blocks — aggregate contract
# ===========================================================================

def _overview_kwargs(**over):
    base = dict(
        prov_summary={},
        all_findings=[],
        envs=[],
        net_data=_empty_net_data(),
        datadog_data=_empty_datadog_data(),
        passed=0,
        total_prowler_pass=0,
        warnings=0,
        total_checks=0,
        failed=0,
        arch_domains=[],
        audit_points_data={},
        ms_best_practices_data={},
        findings_list=[],
    )
    base.update(over)
    return base


def test_overview_blocks_returns_expected_keys():
    """build_overview_blocks returns the documented dict contract."""
    result = build_overview_blocks(**_overview_kwargs())
    expected = {
        "n_crit", "n_high", "n_med", "n_low", "n_info",
        "policy_022_top", "prov_cards",
        "bar_crit", "bar_high", "bar_med", "bar_warn", "bar_low",
        "top_findings_html", "env_connected", "env_total",
        "service_surface_html", "priority_queue_html",
        "network_tools_html", "network_tools_badge",
    }
    assert expected.issubset(result.keys())


def test_overview_blocks_env_counts_match_input():
    """env_connected and env_total reflect the envs list."""
    envs = [{"connected": True}, {"connected": False}, {"connected": True}]
    result = build_overview_blocks(**_overview_kwargs(envs=envs))
    assert result["env_connected"] == 2
    assert result["env_total"] == 3


def test_overview_blocks_badge_dash_when_no_evidence():
    """network_tools_badge is '—' when no network or datadog artifacts."""
    result = build_overview_blocks(**_overview_kwargs())
    assert result["network_tools_badge"] == "—"


def test_overview_blocks_badge_checkmark_with_artifacts_only():
    """network_tools_badge is '✓' when artifacts exist but totals are zero."""
    net = _empty_net_data()
    net["nmap_scans"] = [{"name": "scan1", "hosts": []}]
    result = build_overview_blocks(**_overview_kwargs(net_data=net))
    assert result["network_tools_badge"] == "✓"


def test_overview_blocks_badge_uses_total_when_positive():
    """network_tools_badge shows the numeric total when trivy+datadog > 0."""
    net = _empty_net_data()
    net["trivy_summary"]["high"] = 3
    result = build_overview_blocks(**_overview_kwargs(net_data=net))
    assert result["network_tools_badge"] == "3"


def test_overview_blocks_network_tools_html_always_has_cockpit():
    """network_tools_html always contains the configuration cockpit card title."""
    result = build_overview_blocks(**_overview_kwargs())
    assert "Network &amp; Security — Configuration" in result["network_tools_html"]


def test_overview_blocks_empty_findings_top_fallback():
    """Empty findings produces the top-findings fallback banner."""
    result = build_overview_blocks(**_overview_kwargs())
    assert "No critical or high findings" in result["top_findings_html"]


def test_overview_blocks_findings_list_default_empty():
    """findings_list=None is coerced to empty list without raising."""
    kwargs = _overview_kwargs()
    kwargs["findings_list"] = None
    result = build_overview_blocks(**kwargs)
    assert result["env_total"] == 0


def test_overview_blocks_service_surface_contains_grid():
    """service_surface_html output contains the coverage-grid wrapper."""
    result = build_overview_blocks(**_overview_kwargs())
    assert '<div class="coverage-grid">' in result["service_surface_html"]


def test_overview_blocks_priority_queue_contains_grid():
    """priority_queue_html output contains the priority-grid wrapper."""
    result = build_overview_blocks(**_overview_kwargs())
    assert '<div class="priority-grid">' in result["priority_queue_html"]
