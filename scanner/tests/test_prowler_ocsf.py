"""Tests for Prowler OCSF data parsing functions in dashboard-gen.py."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
SPEC = importlib.util.spec_from_file_location("dashboard_gen", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Failed to load module spec for {MODULE_PATH}")
dashboard_gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_gen)


def _make_finding(provider, status="FAIL", severity="High", check="chk-001", title="Test"):
    """Build a minimal OCSF finding dict."""
    return {
        "status_code": status,
        "severity": severity,
        "metadata": {"event_code": check},
        "finding_info": {"title": title, "desc": "desc"},
        "resources": [{"data": {"metadata": {"name": "res-1"}}, "region": "us-east-1"}],
        "message": "msg",
        "unmapped": {"related_url": "", "compliance": {}},
    }


class TestParseOcsfJson(unittest.TestCase):
    """Tests for _parse_ocsf_json()."""

    def test_single_array(self):
        data = json.dumps([{"a": 1}, {"b": 2}])
        result = dashboard_gen._parse_ocsf_json(data)
        self.assertEqual(len(result), 2)

    def test_ndjson(self):
        data = '{"x":1}\n{"y":2}\n'
        result = dashboard_gen._parse_ocsf_json(data)
        self.assertEqual(len(result), 2)

    def test_concatenated_arrays(self):
        data = '[{"a":1}][{"b":2}]'
        result = dashboard_gen._parse_ocsf_json(data)
        self.assertEqual(len(result), 2)

    def test_empty_string(self):
        self.assertEqual(dashboard_gen._parse_ocsf_json(""), [])

    def test_whitespace_only(self):
        self.assertEqual(dashboard_gen._parse_ocsf_json("   \n\t  "), [])

    def test_non_dict_items_filtered(self):
        data = json.dumps([{"a": 1}, "string", 42, {"b": 2}])
        result = dashboard_gen._parse_ocsf_json(data)
        self.assertEqual(len(result), 2)

    def test_invalid_json_skipped(self):
        data = '{"a":1}GARBAGE{"b":2}'
        result = dashboard_gen._parse_ocsf_json(data)
        self.assertEqual(len(result), 2)


class TestLoadProwlerFiles(unittest.TestCase):
    """Tests for load_prowler_files()."""

    def test_nonexistent_dir_returns_empty(self):
        result = dashboard_gen.load_prowler_files("/nonexistent/path")
        self.assertEqual(result, {})

    def test_loads_k8s_provider(self):
        with tempfile.TemporaryDirectory() as td:
            findings = [_make_finding("kubernetes")]
            Path(td, "prowler-kubernetes.ocsf.json").write_text(json.dumps(findings))
            result = dashboard_gen.load_prowler_files(td)
            self.assertIn("kubernetes", result)
            self.assertEqual(len(result["kubernetes"]), 1)

    def test_loads_multiple_providers(self):
        with tempfile.TemporaryDirectory() as td:
            for prov in ("aws", "kubernetes", "gcp"):
                Path(td, f"prowler-{prov}.ocsf.json").write_text(
                    json.dumps([_make_finding(prov)])
                )
            result = dashboard_gen.load_prowler_files(td)
            self.assertEqual(set(result.keys()), {"aws", "kubernetes", "gcp"})

    def test_corrupt_file_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "prowler-aws.ocsf.json").write_text("NOT JSON{{{")
            result = dashboard_gen.load_prowler_files(td)
            self.assertIn("aws", result)
            self.assertEqual(result["aws"], [])

    def test_ignores_non_prowler_files(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "other-file.json").write_text('{"x":1}')
            Path(td, "prowler-aws.ocsf.json").write_text(json.dumps([_make_finding("aws")]))
            result = dashboard_gen.load_prowler_files(td)
            self.assertEqual(list(result.keys()), ["aws"])


class TestAnalyzeProwler(unittest.TestCase):
    """Tests for analyze_prowler()."""

    def test_empty_providers(self):
        summary, findings = dashboard_gen.analyze_prowler({})
        self.assertEqual(summary, {})
        self.assertEqual(findings, [])

    def test_counts_pass_fail(self):
        providers = {
            "kubernetes": [
                _make_finding("kubernetes", status="FAIL", severity="High"),
                _make_finding("kubernetes", status="FAIL", severity="Critical"),
                _make_finding("kubernetes", status="PASS"),
            ]
        }
        summary, findings = dashboard_gen.analyze_prowler(providers)
        self.assertEqual(summary["kubernetes"]["total_fail"], 2)
        self.assertEqual(summary["kubernetes"]["total_pass"], 1)
        self.assertEqual(summary["kubernetes"]["high"], 1)
        self.assertEqual(summary["kubernetes"]["critical"], 1)

    def test_severity_breakdown(self):
        providers = {
            "aws": [
                _make_finding("aws", status="FAIL", severity="Medium"),
                _make_finding("aws", status="FAIL", severity="Low"),
                _make_finding("aws", status="FAIL", severity="Informational"),
            ]
        }
        summary, _ = dashboard_gen.analyze_prowler(providers)
        self.assertEqual(summary["aws"]["medium"], 1)
        self.assertEqual(summary["aws"]["low"], 1)
        self.assertEqual(summary["aws"]["informational"], 1)
        self.assertEqual(summary["aws"]["critical"], 0)

    def test_findings_include_metadata(self):
        providers = {
            "kubernetes": [
                _make_finding("kubernetes", check="apiserver_audit", title="Audit logs"),
            ]
        }
        _, findings = dashboard_gen.analyze_prowler(providers)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["provider"], "kubernetes")
        self.assertEqual(findings[0]["check"], "apiserver_audit")
        self.assertEqual(findings[0]["title"], "Audit logs")
        self.assertEqual(findings[0]["resource"], "res-1")

    def test_multiple_providers_combined(self):
        providers = {
            "aws": [_make_finding("aws", status="FAIL")],
            "kubernetes": [
                _make_finding("kubernetes", status="FAIL"),
                _make_finding("kubernetes", status="FAIL"),
            ],
        }
        summary, findings = dashboard_gen.analyze_prowler(providers)
        self.assertEqual(summary["aws"]["total_fail"], 1)
        self.assertEqual(summary["kubernetes"]["total_fail"], 2)
        self.assertEqual(len(findings), 3)


class TestProviderFilterFunctions(unittest.TestCase):
    """Tests for aws_findings(), k8s_findings(), etc."""

    def setUp(self):
        self.findings = [
            {"provider": "aws", "check": "iam"},
            {"provider": "kubernetes", "check": "apiserver"},
            {"provider": "kubernetes", "check": "kubelet"},
            {"provider": "gcp", "check": "iam"},
            {"provider": "github", "check": "repo"},
            {"provider": "azure", "check": "nsg"},
            {"provider": "googleworkspace", "check": "admin"},
            {"provider": "m365", "check": "teams"},
        ]

    def test_aws_findings(self):
        result = dashboard_gen.aws_findings(self.findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["check"], "iam")

    def test_k8s_findings(self):
        result = dashboard_gen.k8s_findings(self.findings)
        self.assertEqual(len(result), 2)

    def test_gcp_findings(self):
        result = dashboard_gen.gcp_findings(self.findings)
        self.assertEqual(len(result), 1)

    def test_github_findings(self):
        result = dashboard_gen.github_findings(self.findings)
        self.assertEqual(len(result), 1)

    def test_azure_findings(self):
        result = dashboard_gen.azure_findings(self.findings)
        self.assertEqual(len(result), 1)

    def test_gws_findings(self):
        result = dashboard_gen.gws_findings(self.findings)
        self.assertEqual(len(result), 1)

    def test_m365_findings(self):
        result = dashboard_gen.m365_findings(self.findings)
        self.assertEqual(len(result), 1)

    def test_empty_list(self):
        self.assertEqual(dashboard_gen.aws_findings([]), [])
        self.assertEqual(dashboard_gen.k8s_findings([]), [])


if __name__ == "__main__":
    unittest.main()
