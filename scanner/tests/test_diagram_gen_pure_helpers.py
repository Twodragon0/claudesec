"""
Unit tests for pure helpers in scanner/lib/diagram-gen.py.

Each test exercises exactly one behaviour.  No subprocess calls, no network,
no real Draw.io fixtures.  tmp_path is used purely to write/read deterministic
outputs the helpers produce as part of their normal contract.

Import strategy: diagram-gen.py contains hyphens, so we use
importlib.util.spec_from_file_location to load it by path.

Environment note: defusedxml.ElementTree does NOT expose Element / SubElement
in this environment, but the module uses them internally.  We monkey-patch
defusedxml.ElementTree with stdlib xml.etree.ElementTree equivalents at
module-load time.  This is the minimum shim needed to exercise the string /
XML helpers — no business logic is altered.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module loader (patched so ET.Element / SubElement are available)
# ---------------------------------------------------------------------------

def _load_diagram_gen():
    import defusedxml.ElementTree as _dET
    import xml.etree.ElementTree as _stdET
    # Shim: defusedxml.ElementTree in this env lacks Element/SubElement.
    # The module calls ET.SubElement and ET.Element in nearly every builder.
    if not hasattr(_dET, "Element"):
        _dET.Element = _stdET.Element
    if not hasattr(_dET, "SubElement"):
        _dET.SubElement = _stdET.SubElement

    path = Path(__file__).resolve().parents[1] / "lib" / "diagram-gen.py"
    spec = importlib.util.spec_from_file_location("diagram_gen_pure", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_diagram_gen()


# Minimal aggregate fixture builder — keeps each test's intent clear.
def _agg(**overrides):
    base = {
        "scan": {
            "score": 0,
            "grade": "F",
            "total": 0,
            "failed": 0,
            "warnings": 0,
            "findings": [],
        },
        "prowler_providers": [],
        "prowler_summary": {},
        "history_count": 0,
    }
    base.update(overrides)
    return base


# ===========================================================================
# 1. Module-level constants
# ===========================================================================

def test_version_is_string():
    assert isinstance(MOD.VERSION, str)


def test_version_is_nonempty():
    assert len(MOD.VERSION) > 0


def test_categories_length_is_eleven():
    assert len(MOD.CATEGORIES) == 11


def test_categories_contains_prowler():
    assert "prowler" in MOD.CATEGORIES


def test_categories_contains_macos():
    assert "macos" in MOD.CATEGORIES


def test_arch_domains_length_is_six():
    assert len(MOD.ARCH_DOMAINS) == 6


def test_arch_domains_each_has_name_and_icon():
    for d in MOD.ARCH_DOMAINS:
        assert "name" in d
        assert "icon" in d


# ===========================================================================
# 2. mx_escape — pure HTML escape
# ===========================================================================

def test_mx_escape_none_returns_empty_string():
    assert MOD.mx_escape(None) == ""


def test_mx_escape_int_is_stringified():
    assert MOD.mx_escape(42) == "42"


def test_mx_escape_ampersand_goes_first():
    # "&" must be escaped before "<" / ">" to avoid double-escaping.
    assert MOD.mx_escape("&<>") == "&amp;&lt;&gt;"


def test_mx_escape_double_quote():
    assert MOD.mx_escape('say "hi"') == "say &quot;hi&quot;"


def test_mx_escape_plain_ascii_unchanged():
    assert MOD.mx_escape("hello-world_123") == "hello-world_123"


# ===========================================================================
# 3. _svg_escape — pure HTML escape for SVG
# ===========================================================================

def test_svg_escape_none_returns_empty_string():
    assert MOD._svg_escape(None) == ""


def test_svg_escape_encodes_lt_gt():
    assert "&lt;" in MOD._svg_escape("<tag>")
    assert "&gt;" in MOD._svg_escape("<tag>")


def test_svg_escape_encodes_ampersand():
    assert MOD._svg_escape("a&b") == "a&amp;b"


def test_svg_escape_encodes_double_quote():
    assert "&quot;" in MOD._svg_escape('he said "hi"')


def test_svg_escape_int_stringified():
    assert MOD._svg_escape(7) == "7"


# ===========================================================================
# 4. _parse_ocsf_json — pure string → list of dicts
# ===========================================================================

def test_parse_ocsf_empty_string_returns_empty_list():
    assert MOD._parse_ocsf_json("") == []


def test_parse_ocsf_whitespace_returns_empty_list():
    assert MOD._parse_ocsf_json("   \n\t  ") == []


def test_parse_ocsf_single_object():
    items = MOD._parse_ocsf_json('{"a": 1}')
    assert items == [{"a": 1}]


def test_parse_ocsf_array_of_dicts():
    items = MOD._parse_ocsf_json('[{"a": 1}, {"b": 2}]')
    assert items == [{"a": 1}, {"b": 2}]


def test_parse_ocsf_array_filters_non_dicts():
    items = MOD._parse_ocsf_json('[{"a": 1}, 42, "str", [1,2]]')
    assert items == [{"a": 1}]


def test_parse_ocsf_concatenated_objects_newline_separated():
    raw = '{"a": 1}\n{"b": 2}'
    items = MOD._parse_ocsf_json(raw)
    assert items == [{"a": 1}, {"b": 2}]


def test_parse_ocsf_invalid_json_returns_empty():
    # Non-JSON chars advance idx by one until EOF — returns [].
    assert MOD._parse_ocsf_json("not json at all {{{") == []


def test_parse_ocsf_ignores_leading_garbage_and_parses_object():
    # First char is invalid, but the parser advances idx by 1 until
    # valid JSON is found.
    items = MOD._parse_ocsf_json('x{"a": 1}')
    assert items == [{"a": 1}]


# ===========================================================================
# 5. load_scan_results — file I/O via tmp_path
# ===========================================================================

def test_load_scan_results_missing_path_returns_zeroed_dict():
    r = MOD.load_scan_results("/definitely/not/a/file.json")
    assert r["total"] == 0
    assert r["grade"] == "F"
    assert r["findings"] == []


def test_load_scan_results_none_path_returns_zeroed_dict():
    r = MOD.load_scan_results(None)
    assert r["total"] == 0
    assert r["score"] == 0


def test_load_scan_results_empty_path_returns_zeroed_dict():
    r = MOD.load_scan_results("")
    assert r["grade"] == "F"


def test_load_scan_results_reads_valid_json(tmp_path):
    data = {"total": 7, "score": 85, "grade": "A", "findings": []}
    f = tmp_path / "scan.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    r = MOD.load_scan_results(str(f))
    assert r["total"] == 7
    assert r["grade"] == "A"


# ===========================================================================
# 6. load_prowler_files — dir scan + JSON parse
# ===========================================================================

def test_load_prowler_files_missing_dir_returns_empty_dict():
    assert MOD.load_prowler_files("/no/such/dir") == {}


def test_load_prowler_files_empty_dir_returns_empty_dict(tmp_path):
    assert MOD.load_prowler_files(str(tmp_path)) == {}


def test_load_prowler_files_reads_ocsf_json(tmp_path):
    (tmp_path / "prowler-aws.ocsf.json").write_text(
        '[{"status_code": "FAIL"}, {"status_code": "PASS"}]',
        encoding="utf-8",
    )
    providers = MOD.load_prowler_files(str(tmp_path))
    assert "aws" in providers
    assert len(providers["aws"]) == 2


def test_load_prowler_files_provider_name_strips_prefix_and_suffix(tmp_path):
    (tmp_path / "prowler-gcp.ocsf.json").write_text('[]', encoding="utf-8")
    providers = MOD.load_prowler_files(str(tmp_path))
    assert list(providers.keys()) == ["gcp"]


def test_load_prowler_files_unreadable_file_becomes_empty(tmp_path):
    # Write invalid content — _parse_ocsf_json returns [] and the
    # provider entry should become [].
    (tmp_path / "prowler-bad.ocsf.json").write_text(
        "xxx not json xxx", encoding="utf-8"
    )
    providers = MOD.load_prowler_files(str(tmp_path))
    assert providers.get("bad") == []


# ===========================================================================
# 7. load_scan_history — dir scan + JSON parse
# ===========================================================================

def test_load_scan_history_missing_dir_returns_empty_list():
    assert MOD.load_scan_history("/no/such/history/dir") == []


def test_load_scan_history_empty_dir_returns_empty_list(tmp_path):
    assert MOD.load_scan_history(str(tmp_path)) == []


def test_load_scan_history_reads_scan_files(tmp_path):
    (tmp_path / "scan-2026-01-01.json").write_text('{"total": 1}', encoding="utf-8")
    (tmp_path / "scan-2026-01-02.json").write_text('{"total": 2}', encoding="utf-8")
    entries = MOD.load_scan_history(str(tmp_path))
    assert len(entries) == 2


def test_load_scan_history_ignores_malformed_json_files(tmp_path):
    (tmp_path / "scan-good.json").write_text('{"total": 1}', encoding="utf-8")
    (tmp_path / "scan-bad.json").write_text("not json", encoding="utf-8")
    entries = MOD.load_scan_history(str(tmp_path))
    assert len(entries) == 1


def test_load_scan_history_only_matches_scan_prefix(tmp_path):
    (tmp_path / "scan-ok.json").write_text('{"ok": 1}', encoding="utf-8")
    (tmp_path / "other.json").write_text('{"no": 1}', encoding="utf-8")
    entries = MOD.load_scan_history(str(tmp_path))
    assert len(entries) == 1


# ===========================================================================
# 8. aggregate_scan_data — combines all loaders
# ===========================================================================

def test_aggregate_scan_data_missing_dir_returns_zeroed_keys(tmp_path, monkeypatch):
    # Clear env vars so the fallback path does not inject anything.
    for k in [
        "CLAUDESEC_SCAN_JSON", "CLAUDESEC_PASSED", "CLAUDESEC_FAILED",
        "CLAUDESEC_WARNINGS", "CLAUDESEC_SKIPPED", "CLAUDESEC_TOTAL",
        "CLAUDESEC_SCORE", "CLAUDESEC_GRADE", "CLAUDESEC_DURATION",
        "CLAUDESEC_FINDINGS_JSON",
    ]:
        monkeypatch.delenv(k, raising=False)
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["total"] == 0
    assert out["prowler_providers"] == []
    assert out["history_count"] == 0


def test_aggregate_scan_data_reads_scan_report(tmp_path, monkeypatch):
    for k in ["CLAUDESEC_SCAN_JSON", "CLAUDESEC_PASSED", "CLAUDESEC_TOTAL"]:
        monkeypatch.delenv(k, raising=False)
    (tmp_path / "scan-report.json").write_text(
        json.dumps({"total": 9, "score": 77, "grade": "C", "findings": []}),
        encoding="utf-8",
    )
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["total"] == 9
    assert out["scan"]["grade"] == "C"


def test_aggregate_scan_data_env_fallback_when_no_report(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDESEC_SCAN_JSON", raising=False)
    monkeypatch.setenv("CLAUDESEC_TOTAL", "12")
    monkeypatch.setenv("CLAUDESEC_PASSED", "10")
    monkeypatch.setenv("CLAUDESEC_FAILED", "2")
    monkeypatch.setenv("CLAUDESEC_SCORE", "83")
    monkeypatch.setenv("CLAUDESEC_GRADE", "B")
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["total"] == 12
    assert out["scan"]["grade"] == "B"


def test_aggregate_scan_data_env_fallback_handles_bad_numbers(tmp_path, monkeypatch):
    # Non-numeric env values → except branch keeps scan dict as default.
    monkeypatch.delenv("CLAUDESEC_SCAN_JSON", raising=False)
    monkeypatch.setenv("CLAUDESEC_TOTAL", "not-a-number")
    out = MOD.aggregate_scan_data(str(tmp_path))
    # Exception handler leaves scan_data as zeroed dict from load_scan_results.
    assert out["scan"]["total"] == 0


def test_aggregate_scan_data_env_findings_parsed(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDESEC_SCAN_JSON", raising=False)
    monkeypatch.setenv("CLAUDESEC_TOTAL", "1")
    monkeypatch.setenv("CLAUDESEC_FINDINGS_JSON", '[{"id": "X1"}]')
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["findings"] == [{"id": "X1"}]


def test_aggregate_scan_data_env_findings_non_list_becomes_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDESEC_SCAN_JSON", raising=False)
    monkeypatch.setenv("CLAUDESEC_TOTAL", "1")
    # Non-array JSON string — does not start with "[" — ignored.
    monkeypatch.setenv("CLAUDESEC_FINDINGS_JSON", '{"not": "array"}')
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["findings"] == []


def test_aggregate_scan_data_scan_json_env_override(tmp_path, monkeypatch):
    # Primary scan-report.json missing, env override points to a valid file.
    alt = tmp_path / "alt.json"
    alt.write_text(
        json.dumps({"total": 5, "grade": "D", "score": 50, "findings": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDESEC_SCAN_JSON", str(alt))
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["scan"]["total"] == 5
    assert out["scan"]["grade"] == "D"


def test_aggregate_scan_data_counts_prowler_fails(tmp_path, monkeypatch):
    for k in ["CLAUDESEC_TOTAL", "CLAUDESEC_SCAN_JSON"]:
        monkeypatch.delenv(k, raising=False)
    (tmp_path / "scan-report.json").write_text(
        json.dumps({"total": 1, "grade": "B", "score": 80, "findings": []}),
        encoding="utf-8",
    )
    prowler_dir = tmp_path / ".claudesec-prowler"
    prowler_dir.mkdir()
    (prowler_dir / "prowler-aws.ocsf.json").write_text(
        '[{"status_code": "FAIL"}, {"status_code": "FAIL"}, {"status_code": "PASS"}]',
        encoding="utf-8",
    )
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["prowler_summary"]["aws"]["fail"] == 2
    assert out["prowler_summary"]["aws"]["total"] == 3


def test_aggregate_scan_data_counts_history_entries(tmp_path, monkeypatch):
    for k in ["CLAUDESEC_TOTAL", "CLAUDESEC_SCAN_JSON"]:
        monkeypatch.delenv(k, raising=False)
    hist = tmp_path / ".claudesec-history"
    hist.mkdir()
    (hist / "scan-1.json").write_text('{"a": 1}', encoding="utf-8")
    (hist / "scan-2.json").write_text('{"a": 2}', encoding="utf-8")
    out = MOD.aggregate_scan_data(str(tmp_path))
    assert out["history_count"] == 2


# ===========================================================================
# 9. generate_architecture_svg — pure string builder (no ET needed)
# ===========================================================================

def test_generate_architecture_svg_writes_xml_declaration(tmp_path):
    out = tmp_path / "arch.svg"
    MOD.generate_architecture_svg(_agg(), str(out))
    assert out.read_text(encoding="utf-8").startswith("<?xml")


def test_generate_architecture_svg_contains_svg_element(tmp_path):
    out = tmp_path / "arch.svg"
    MOD.generate_architecture_svg(_agg(), str(out))
    assert "<svg" in out.read_text(encoding="utf-8")


def test_generate_architecture_svg_renders_scanner_box(tmp_path):
    out = tmp_path / "arch.svg"
    MOD.generate_architecture_svg(_agg(), str(out))
    assert "ClaudeSec Scanner" in out.read_text(encoding="utf-8")


def test_generate_architecture_svg_renders_score_and_grade(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(scan={"score": 82, "grade": "B", "total": 10, "failed": 2, "warnings": 1, "findings": []})
    MOD.generate_architecture_svg(agg, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Score:82%" in content
    assert "Grade:B" in content


def test_generate_architecture_svg_counts_severity_from_findings(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(scan={
        "score": 50, "grade": "D", "total": 3, "failed": 2, "warnings": 0,
        "findings": [
            {"severity": "critical", "category": "cloud"},
            {"severity": "high", "category": "network"},
            {"severity": "high", "category": "cloud"},
        ],
    })
    MOD.generate_architecture_svg(agg, str(out))
    content = out.read_text(encoding="utf-8")
    assert "Crit:1" in content
    assert "High:2" in content


def test_generate_architecture_svg_renders_top_categories(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(scan={
        "score": 0, "grade": "F", "total": 4, "failed": 4, "warnings": 0,
        "findings": [
            {"severity": "high", "category": "cloud"},
            {"severity": "high", "category": "cloud"},
            {"severity": "low", "category": "network"},
            {"severity": "low", "category": "network"},
        ],
    })
    MOD.generate_architecture_svg(agg, str(out))
    content = out.read_text(encoding="utf-8")
    assert "cloud:2" in content
    assert "network:2" in content


def test_generate_architecture_svg_skips_findings_that_are_not_dicts(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(scan={
        "score": 0, "grade": "F", "total": 0, "failed": 0, "warnings": 0,
        "findings": ["not-a-dict", 42, {"severity": "medium", "category": "infra"}],
    })
    MOD.generate_architecture_svg(agg, str(out))
    content = out.read_text(encoding="utf-8")
    # Only the dict contributes — infra:1 should appear in top categories.
    assert "infra:1" in content


def test_generate_architecture_svg_prowler_providers_truncated_after_five(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(prowler_providers=["a", "b", "c", "d", "e", "f", "g"])
    MOD.generate_architecture_svg(agg, str(out))
    content = out.read_text(encoding="utf-8")
    # Truncation suffix appears.
    assert "..." in content


def test_generate_architecture_svg_history_count_rendered(tmp_path):
    out = tmp_path / "arch.svg"
    agg = _agg(history_count=7)
    MOD.generate_architecture_svg(agg, str(out))
    assert "(7 entries)" in out.read_text(encoding="utf-8")


def test_generate_architecture_svg_no_findings_shows_top_categories_none(tmp_path):
    out = tmp_path / "arch.svg"
    MOD.generate_architecture_svg(_agg(), str(out))
    assert "Top categories: none" in out.read_text(encoding="utf-8")


def test_generate_architecture_svg_prowler_no_data_label(tmp_path):
    out = tmp_path / "arch.svg"
    MOD.generate_architecture_svg(_agg(), str(out))
    assert "no data" in out.read_text(encoding="utf-8")


# ===========================================================================
# 10. generate_overview_svg — pure SVG string builder
# ===========================================================================

def test_generate_overview_svg_writes_svg_file(tmp_path):
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    assert content.startswith("<?xml")
    assert "<svg" in content


def test_generate_overview_svg_header_text(tmp_path):
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(), str(tmp_path), str(out))
    assert "ClaudeSec Overview Architecture" in out.read_text(encoding="utf-8")


def test_generate_overview_svg_renders_score_grade(tmp_path):
    out = tmp_path / "overview.svg"
    agg = _agg(scan={
        "score": 91, "grade": "A", "total": 22, "failed": 1, "warnings": 0,
        "findings": [],
    })
    MOD.generate_overview_svg(agg, str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    assert "Score 91%" in content
    assert "Grade A" in content


def test_generate_overview_svg_renders_total_prowler_fail(tmp_path):
    out = tmp_path / "overview.svg"
    agg = _agg(prowler_summary={"aws": {"fail": 4, "total": 5}, "gcp": {"fail": 2, "total": 3}})
    MOD.generate_overview_svg(agg, str(tmp_path), str(out))
    assert "Prowler fail 6" in out.read_text(encoding="utf-8")


def test_generate_overview_svg_uses_network_report_when_present(tmp_path):
    net_dir = tmp_path / ".claudesec-network"
    net_dir.mkdir()
    (net_dir / "network-report.v1.json").write_text(
        json.dumps({
            "targets": [
                {"http": {"issues": ["missing-hsts", "weak-csp"]}},
                {"http": {"issues": ["x-frame"]}},
            ]
        }),
        encoding="utf-8",
    )
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    assert "Network targets 2" in content
    assert "header issues 3" in content


def test_generate_overview_svg_handles_bad_network_json(tmp_path):
    net_dir = tmp_path / ".claudesec-network"
    net_dir.mkdir()
    (net_dir / "network-report.v1.json").write_text(
        "garbage not json", encoding="utf-8"
    )
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(), str(tmp_path), str(out))
    assert "Network targets 0" in out.read_text(encoding="utf-8")


def test_generate_overview_svg_no_network_dir_defaults_zero(tmp_path):
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(), str(tmp_path), str(out))
    assert "Network targets 0" in out.read_text(encoding="utf-8")


def test_generate_overview_svg_renders_history_entries(tmp_path):
    out = tmp_path / "overview.svg"
    MOD.generate_overview_svg(_agg(history_count=42), str(tmp_path), str(out))
    assert "42 entries" in out.read_text(encoding="utf-8")


# ===========================================================================
# 11. Drawio generators — exercised via monkey-patched ET
#     (Validates the helpers produce well-formed <mxfile> output.)
# ===========================================================================

def test_create_drawio_root_returns_tuple_with_mxfile(tmp_path):
    root, gr = MOD.create_drawio_root()
    assert root.tag == "mxfile"


def test_create_drawio_root_graph_root_has_two_cells():
    _root, gr = MOD.create_drawio_root()
    cells = list(gr.findall("mxCell"))
    assert len(cells) == 2


def test_create_multipage_drawio_root_has_no_children():
    root = MOD.create_multipage_drawio_root()
    assert root.tag == "mxfile"
    assert len(list(root)) == 0


def test_add_drawio_page_creates_named_diagram():
    root = MOD.create_multipage_drawio_root()
    MOD.add_drawio_page(root, "Topology", "page-topo")
    diagram = root.find("diagram")
    assert diagram is not None
    assert diagram.get("name") == "Topology"
    assert diagram.get("id") == "page-topo"


def test_generate_architecture_diagram_writes_mxfile(tmp_path):
    out = tmp_path / "arch.drawio"
    MOD.generate_architecture_diagram(_agg(), str(out))
    content = out.read_text(encoding="utf-8")
    assert "mxfile" in content
    assert "ClaudeSec Scanner" in content


def test_generate_scan_flow_diagram_writes_mxfile(tmp_path):
    out = tmp_path / "flow.drawio"
    MOD.generate_scan_flow_diagram(_agg(), str(out))
    content = out.read_text(encoding="utf-8")
    assert "mxfile" in content
    assert "claudesec scan" in content


def test_generate_security_domains_diagram_writes_mxfile(tmp_path):
    out = tmp_path / "dom.drawio"
    MOD.generate_security_domains_diagram(_agg(), str(out))
    content = out.read_text(encoding="utf-8")
    assert "mxfile" in content
    # Domain icons / labels appear.
    assert "Identity" in content or "Network" in content


def test_generate_overview_drawio_writes_multipage_file(tmp_path):
    out = tmp_path / "ov.drawio"
    MOD.generate_overview_drawio(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    assert "mxfile" in content
    # Three diagrams (pages) expected.
    assert content.count("<diagram ") == 3


def test_write_drawio_file_emits_xml_to_path(tmp_path):
    root, _gr = MOD.create_drawio_root()
    out = tmp_path / "w.drawio"
    MOD.write_drawio_file(root, str(out))
    assert "mxfile" in out.read_text(encoding="utf-8")


# ===========================================================================
# 12. Network topology page — exercises _overview_network_topology_page via
#     generate_overview_drawio, including redaction branch.
# ===========================================================================

def test_overview_drawio_network_report_targets_rendered(tmp_path):
    net_dir = tmp_path / ".claudesec-network"
    net_dir.mkdir()
    (net_dir / "network-report.v1.json").write_text(
        json.dumps({
            "targets": [
                {
                    "host": "example.com",
                    "port": 443,
                    "dns": {"ips": ["1.2.3.4", "5.6.7.8"]},
                    "tls": {"grade": "A"},
                    "http": {
                        "status": 200,
                        "issues": ["weak-csp"],
                        "hsts": {"max_age": 31536000},
                        "csp": {"quality": "strict"},
                        "redirects": 1,
                    },
                },
            ],
        }),
        encoding="utf-8",
    )
    out = tmp_path / "ov.drawio"
    MOD.generate_overview_drawio(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    # With default CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS, host is redacted
    # (pseudonym 'target-<hash>'). Port must still appear.
    assert "target-" in content
    assert "443" in content


def test_overview_drawio_show_identifiers_env_unredacts(tmp_path, monkeypatch):
    net_dir = tmp_path / ".claudesec-network"
    net_dir.mkdir()
    (net_dir / "network-report.v1.json").write_text(
        json.dumps({
            "targets": [
                {
                    "host": "visible.example",
                    "port": 443,
                    "dns": {"ips": []},
                    "tls": {"grade": "A"},
                    "http": {"status": 200, "issues": []},
                },
            ],
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDESEC_DASHBOARD_SHOW_IDENTIFIERS", "1")
    out = tmp_path / "ov.drawio"
    MOD.generate_overview_drawio(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    assert "visible.example" in content


def test_overview_drawio_missing_network_report_shows_placeholder(tmp_path):
    # No .claudesec-network dir — network page renders with zero targets.
    out = tmp_path / "ov.drawio"
    MOD.generate_overview_drawio(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    # Summary label reports missing report.
    assert "missing" in content


def test_overview_drawio_invalid_network_json_handled(tmp_path):
    net_dir = tmp_path / ".claudesec-network"
    net_dir.mkdir()
    (net_dir / "network-report.v1.json").write_text("xx not json xx", encoding="utf-8")
    out = tmp_path / "ov.drawio"
    MOD.generate_overview_drawio(_agg(), str(tmp_path), str(out))
    content = out.read_text(encoding="utf-8")
    # Report parse failure → report=None → summary says 'missing'.
    assert "missing" in content
