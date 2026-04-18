"""
Unit tests for scanner/lib/dashboard_data_loader.py.

Focuses on pure helpers (OCSF parsing, provider normalisation, severity
classification, provider filters, env status) plus tmp-path coverage of
the JSON loaders and caching branches.  Each test exercises one behaviour
and is independent of any other test (no shared mutable state, no network).
Written so both unittest (`xmlrunner discover`) and pytest can execute it.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_data_loader as loader  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


# ===========================================================================
# 1. load_scan_results
# ===========================================================================


class TestLoadScanResults(unittest.TestCase):
    def test_empty_path_returns_default_shape(self):
        result = loader.load_scan_results("")
        self.assertEqual(result["passed"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["grade"], "F")
        self.assertEqual(result["findings"], [])

    def test_missing_file_returns_default_shape(self):
        result = loader.load_scan_results("/no/such/file.json")
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["score"], 0)

    def test_existing_file_is_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "scan.json")
            _write_json(p, {"passed": 5, "failed": 1, "score": 90, "grade": "A"})
            result = loader.load_scan_results(p)
        self.assertEqual(result["passed"], 5)
        self.assertEqual(result["grade"], "A")


# ===========================================================================
# 2. _parse_ocsf_json
# ===========================================================================


class TestParseOcsfJson(unittest.TestCase):
    def test_empty_string_returns_empty(self):
        self.assertEqual(loader._parse_ocsf_json(""), [])

    def test_whitespace_only_returns_empty(self):
        self.assertEqual(loader._parse_ocsf_json("   \n\t  "), [])

    def test_single_array(self):
        content = json.dumps([{"a": 1}, {"b": 2}])
        self.assertEqual(loader._parse_ocsf_json(content), [{"a": 1}, {"b": 2}])

    def test_array_filters_out_non_dict_entries(self):
        content = json.dumps([{"a": 1}, 42, "str", None, {"b": 2}])
        self.assertEqual(loader._parse_ocsf_json(content), [{"a": 1}, {"b": 2}])

    def test_single_dict(self):
        content = json.dumps({"k": "v"})
        self.assertEqual(loader._parse_ocsf_json(content), [{"k": "v"}])

    def test_ndjson_multiple_objects(self):
        content = '{"a": 1}\n{"b": 2}\n{"c": 3}\n'
        self.assertEqual(
            loader._parse_ocsf_json(content),
            [{"a": 1}, {"b": 2}, {"c": 3}],
        )

    def test_concatenated_arrays(self):
        content = json.dumps([{"a": 1}]) + json.dumps([{"b": 2}])
        self.assertEqual(loader._parse_ocsf_json(content), [{"a": 1}, {"b": 2}])

    def test_malformed_content_skipped(self):
        # Garbage before a valid object should be skipped char-by-char.
        content = "garbage###" + json.dumps({"ok": 1})
        self.assertEqual(loader._parse_ocsf_json(content), [{"ok": 1}])

    def test_only_garbage_returns_empty(self):
        self.assertEqual(loader._parse_ocsf_json("@@@###"), [])


# ===========================================================================
# 3. _normalize_provider
# ===========================================================================


class TestNormalizeProvider(unittest.TestCase):
    def test_k8s_prefix(self):
        self.assertEqual(loader._normalize_provider("k8s-cluster"), "kubernetes")

    def test_kubernetes_prefix(self):
        self.assertEqual(loader._normalize_provider("kubernetes-dev"), "kubernetes")

    def test_eks_contains(self):
        self.assertEqual(loader._normalize_provider("prod-eks"), "kubernetes")

    def test_other_unchanged(self):
        self.assertEqual(loader._normalize_provider("aws"), "aws")
        self.assertEqual(loader._normalize_provider("github"), "github")


# ===========================================================================
# 4. _load_single_prowler_file
# ===========================================================================


class TestLoadSingleProwlerFile(unittest.TestCase):
    def test_valid_file_returns_name_and_items(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "prowler-aws.ocsf.json")
            _write_json(p, [{"x": 1}])
            name, items = loader._load_single_prowler_file(p)
        self.assertEqual(name, "aws")
        self.assertEqual(items, [{"x": 1}])

    def test_k8s_file_normalized(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "prowler-k8s-prod.ocsf.json")
            _write_json(p, [])
            name, items = loader._load_single_prowler_file(p)
        self.assertEqual(name, "kubernetes")
        self.assertEqual(items, [])

    def test_missing_file_returns_empty_items(self):
        name, items = loader._load_single_prowler_file("/no/such/prowler-aws.ocsf.json")
        self.assertEqual(name, "aws")
        self.assertEqual(items, [])


# ===========================================================================
# 5. load_prowler_files
# ===========================================================================


class TestLoadProwlerFiles(unittest.TestCase):
    def test_missing_dir_returns_empty(self):
        self.assertEqual(loader.load_prowler_files("/no/such/dir"), {})

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(loader.load_prowler_files(d), {})

    def test_loads_files_and_normalises(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "prowler-aws.ocsf.json"), [{"id": "a"}])
            _write_json(os.path.join(d, "prowler-k8s.ocsf.json"), [{"id": "b"}])
            result = loader.load_prowler_files(d)
        self.assertIn("aws", result)
        self.assertIn("kubernetes", result)


# ===========================================================================
# 6. load_scan_history
# ===========================================================================


class TestLoadScanHistory(unittest.TestCase):
    def test_missing_dir_returns_empty(self):
        self.assertEqual(loader.load_scan_history("/no/such/dir"), [])

    def test_reads_scan_star_json_files(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "scan-1.json"), {"score": 70})
            _write_json(os.path.join(d, "scan-2.json"), {"score": 80})
            # non-matching file ignored
            _write_json(os.path.join(d, "other.json"), {"score": 0})
            result = loader.load_scan_history(d)
        self.assertEqual(len(result), 2)

    def test_invalid_json_entries_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "scan-1.json"), {"score": 70})
            with open(os.path.join(d, "scan-2.json"), "w", encoding="utf-8") as f:
                f.write("not json!!!")
            result = loader.load_scan_history(d)
        self.assertEqual(len(result), 1)


# ===========================================================================
# 7. load_audit_points_detected
# ===========================================================================


class TestLoadAuditPointsDetected(unittest.TestCase):
    def test_missing_file_returns_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(loader.load_audit_points_detected(d), {})

    def test_valid_file_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-audit-points"))
            _write_json(
                os.path.join(d, ".claudesec-audit-points", "detected.json"),
                {"detected_products": ["Okta"], "items": []},
            )
            result = loader.load_audit_points_detected(d)
        self.assertEqual(result["detected_products"], ["Okta"])

    def test_invalid_json_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-audit-points"))
            with open(
                os.path.join(d, ".claudesec-audit-points", "detected.json"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("garbage")
            result = loader.load_audit_points_detected(d)
        self.assertEqual(result, {})


# ===========================================================================
# 8. load_audit_points (cache + offline paths)
# ===========================================================================


class TestLoadAuditPoints(unittest.TestCase):
    def test_fresh_cache_returned(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-audit-points")
            os.makedirs(cdir)
            # Cache timestamp very close to "now".
            from datetime import datetime, timezone
            fetched = datetime.now(timezone.utc).isoformat()
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"products": [{"name": "X"}], "fetched_at": fetched},
            )
            result = loader.load_audit_points(d)
        self.assertEqual(result["products"], [{"name": "X"}])

    def test_stale_cache_triggers_fetch_and_writes(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-audit-points")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"products": [], "fetched_at": "2000-01-01T00:00:00+00:00"},
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                with patch(
                    "dashboard_data_loader._fetch_audit_points_from_github",
                    return_value={"products": [{"name": "Fresh"}], "fetched_at": "z"},
                ):
                    result = loader.load_audit_points(d)
            self.assertEqual(result["products"], [{"name": "Fresh"}])
            # Cache file now exists on disk with fresh contents.
            with open(os.path.join(cdir, "cache.json"), encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["products"], [{"name": "Fresh"}])

    def test_offline_env_returns_empty_without_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
                with patch(
                    "dashboard_data_loader._fetch_audit_points_from_github"
                ) as fetch_mock:
                    result = loader.load_audit_points(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})
        fetch_mock.assert_not_called()

    def test_invalid_cache_fetched_at_triggers_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-audit-points")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"products": [], "fetched_at": "not-a-date"},
            )
            with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
                result = loader.load_audit_points(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})

    def test_fetch_returning_none_falls_through(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                with patch(
                    "dashboard_data_loader._fetch_audit_points_from_github",
                    return_value=None,
                ):
                    result = loader.load_audit_points(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})


# ===========================================================================
# 9. load_microsoft_best_practices
# ===========================================================================


class TestLoadMicrosoftBestPractices(unittest.TestCase):
    def test_none_filter_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(
                os.environ, {"CLAUDESEC_MS_SOURCE_FILTER": "none"}, clear=False
            ):
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
                with patch(
                    "dashboard_data_loader._fetch_microsoft_best_practices_from_github"
                ) as fetch_mock:
                    result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [])
        self.assertEqual(result["source_filter"], "none")
        fetch_mock.assert_not_called()

    def test_offline_env_returns_empty_shape(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}, clear=False):
                os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
                os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
                with patch(
                    "dashboard_data_loader._fetch_microsoft_best_practices_from_github"
                ) as fetch_mock:
                    result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [])
        fetch_mock.assert_not_called()

    def test_fresh_cache_returned_when_filter_matches(self):
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-ms-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "source_filter": "all",
                    "scubagear_enabled": False,
                    "sources": [{"product": "X"}],
                },
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
                os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [{"product": "X"}])

    def test_cache_filter_mismatch_triggers_fetch(self):
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-ms-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "source_filter": "gov",
                    "scubagear_enabled": False,
                    "sources": [{"product": "Stale"}],
                },
            )
            fresh = {
                "fetched_at": "z",
                "source_filter": "all",
                "scubagear_enabled": False,
                "sources": [{"product": "Fresh"}],
            }
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
                os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                with patch(
                    "dashboard_data_loader._fetch_microsoft_best_practices_from_github",
                    return_value=fresh,
                ):
                    result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [{"product": "Fresh"}])

    def test_bad_cache_fetched_at_triggers_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-ms-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"fetched_at": "bad", "source_filter": "all", "sources": []},
            )
            with patch.dict(
                os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}, clear=False
            ):
                os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
                os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
                result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [])


# ===========================================================================
# 10. load_saas_best_practices
# ===========================================================================


class TestLoadSaasBestPractices(unittest.TestCase):
    def test_offline_env_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
                with patch(
                    "dashboard_data_loader._fetch_saas_best_practices_from_github"
                ) as fetch_mock:
                    result = loader.load_saas_best_practices(d)
        self.assertEqual(result, {"fetched_at": "", "sources": []})
        fetch_mock.assert_not_called()

    def test_fresh_cache_returned(self):
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-saas-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "sources": [{"product": "Cached"}],
                },
            )
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                result = loader.load_saas_best_practices(d)
        self.assertEqual(result["sources"], [{"product": "Cached"}])

    def test_stale_cache_triggers_fetch_and_writes(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-saas-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"fetched_at": "2000-01-01T00:00:00+00:00", "sources": []},
            )
            fresh = {"fetched_at": "z", "sources": [{"product": "New"}]}
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CLAUDESEC_DASHBOARD_OFFLINE", None)
                with patch(
                    "dashboard_data_loader._fetch_saas_best_practices_from_github",
                    return_value=fresh,
                ):
                    result = loader.load_saas_best_practices(d)
        self.assertEqual(result, fresh)

    def test_bad_fetched_at_triggers_fetch(self):
        with tempfile.TemporaryDirectory() as d:
            cdir = os.path.join(d, ".claudesec-saas-best-practices")
            os.makedirs(cdir)
            _write_json(
                os.path.join(cdir, "cache.json"),
                {"fetched_at": "nope", "sources": []},
            )
            with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
                result = loader.load_saas_best_practices(d)
        self.assertEqual(result, {"fetched_at": "", "sources": []})


# ===========================================================================
# 11. load_network_tool_results
# ===========================================================================


class TestLoadNetworkToolResults(unittest.TestCase):
    def test_empty_dir_returns_default(self):
        result = loader.load_network_tool_results("")
        self.assertEqual(result["trivy_summary"]["critical"], 0)
        self.assertEqual(result["trivy_vulns"], [])
        self.assertEqual(result["nmap_scans"], [])

    def test_missing_dir_returns_default(self):
        result = loader.load_network_tool_results("/no/such/dir")
        self.assertIsNone(result["trivy_fs"])
        self.assertEqual(result["sslscan_results"], [])

    def test_trivy_fs_vulns_classified_by_severity(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "trivy-fs.json"),
                {
                    "Results": [
                        {
                            "Target": "t",
                            "Vulnerabilities": [
                                {"Severity": "CRITICAL", "VulnerabilityID": "C-1",
                                 "Title": "c", "PkgName": "p"},
                                {"Severity": "high", "VulnerabilityID": "H-1",
                                 "Title": "h", "PkgName": "p"},
                                {"Severity": "Medium", "VulnerabilityID": "M-1",
                                 "Title": "m", "PkgName": "p"},
                                {"Severity": "low", "VulnerabilityID": "L-1",
                                 "Title": "l", "PkgName": "p"},
                                {"Severity": "", "VulnerabilityID": "U-1",
                                 "Title": "u", "PkgName": "p"},
                            ],
                            "Misconfigurations": [
                                {"Severity": "CRITICAL", "ID": "MC-1", "Title": "x"},
                            ],
                        }
                    ]
                },
            )
            result = loader.load_network_tool_results(d)
        self.assertEqual(result["trivy_summary"]["critical"], 2)
        self.assertEqual(result["trivy_summary"]["high"], 1)
        self.assertEqual(result["trivy_summary"]["medium"], 1)
        self.assertEqual(result["trivy_summary"]["low"], 1)
        # UNKNOWN severity added to list but not counted
        self.assertEqual(len(result["trivy_vulns"]), 6)

    def test_network_report_v1_parsed_when_dict(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "network-report.v1.json"),
                {"generated_at": "2026-01-01"},
            )
            result = loader.load_network_tool_results(d)
        self.assertEqual(result["network_report"], {"generated_at": "2026-01-01"})

    def test_network_report_non_dict_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "network-report.v1.json"), ["list"])
            result = loader.load_network_tool_results(d)
        self.assertIsNone(result["network_report"])

    def test_trivy_config_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "trivy-config.json"), {"scan": 1})
            result = loader.load_network_tool_results(d)
        self.assertEqual(result["trivy_config"], {"scan": 1})

    def test_trivy_fs_invalid_json_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "trivy-fs.json"), "w", encoding="utf-8") as f:
                f.write("not json")
            result = loader.load_network_tool_results(d)
        self.assertIsNone(result["trivy_fs"])

    def test_sslscan_file_parsed_and_invalid_captured(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "sslscan-good.json"), {"ciphers": []})
            with open(os.path.join(d, "sslscan-bad.json"), "w", encoding="utf-8") as f:
                f.write("nope")
            result = loader.load_network_tool_results(d)
        names = {s["name"] for s in result["sslscan_results"]}
        self.assertIn("sslscan-good.json", names)
        self.assertIn("sslscan-bad.json", names)

    def test_nmap_xml_parsed(self):
        # Loader reads the 'port' attribute on each <port> element, so craft
        # the XML with that attribute name (not 'portid').
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.1"/>
    <ports>
      <port protocol="tcp" port="22"><state state="open"/></port>
      <port protocol="tcp" port="80"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>
"""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "nmap-test.xml"), "w", encoding="utf-8") as f:
                f.write(xml)
            result = loader.load_network_tool_results(d)
        self.assertEqual(len(result["nmap_scans"]), 1)
        scan = result["nmap_scans"][0]
        self.assertEqual(scan["name"], "test")
        # Only open TCP port 22 should be recorded.
        self.assertEqual(scan["hosts"][0]["ports"], ["22"])

    def test_nmap_xml_malformed_still_produces_entry(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "nmap-bad.xml"), "w", encoding="utf-8") as f:
                f.write("<<<not xml>>>")
            result = loader.load_network_tool_results(d)
        self.assertEqual(len(result["nmap_scans"]), 1)
        self.assertEqual(result["nmap_scans"][0]["hosts"], [])


# ===========================================================================
# 12. load_datadog_logs
# ===========================================================================


class TestLoadDatadogLogs(unittest.TestCase):
    def test_empty_dir_returns_default_shape(self):
        result = loader.load_datadog_logs("")
        self.assertEqual(result["logs"], [])
        self.assertEqual(result["summary"]["total"], 0)
        self.assertEqual(result["signals"], [])

    def test_missing_dir_returns_default(self):
        result = loader.load_datadog_logs("/no/such/dir")
        self.assertEqual(result["summary"]["total"], 0)

    def test_json_logs_parsed_with_data_envelope(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "datadog-logs.json"),
                {
                    "data": [
                        {
                            "attributes": {
                                "status": "ERROR",
                                "message": "boom",
                                "service": "svc",
                                "timestamp": "2026-01-01",
                            }
                        },
                        {
                            "attributes": {
                                "status": "warning",
                                "message": "warn",
                                "source": "syslog",
                                "timestamp": "2026-01-02",
                            }
                        },
                        {"attributes": {"status": "info", "message": "ok"}},
                        {"attributes": {"status": "weird", "message": "?"}},
                    ]
                },
            )
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["summary"]["error"], 1)
        self.assertEqual(result["summary"]["warning"], 1)
        self.assertEqual(result["summary"]["info"], 1)
        self.assertEqual(result["summary"]["unknown"], 1)
        self.assertEqual(result["summary"]["total"], 4)

    def test_json_logs_list_root(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "datadog-logs.json"),
                [{"attributes": {"status": "info", "message": "m"}}],
            )
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["summary"]["info"], 1)

    def test_jsonl_logs_parsed_with_invalid_lines_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(
                os.path.join(d, "datadog-logs.jsonl"), "w", encoding="utf-8"
            ) as f:
                f.write(json.dumps({"attributes": {"status": "error", "message": "a"}}) + "\n")
                f.write("\n")  # blank line
                f.write("garbage\n")
                f.write(json.dumps({"attributes": {"status": "ok", "message": "b"}}) + "\n")
            result = loader.load_datadog_logs(d)
        # "ok" maps to info per _normalize_severity
        self.assertEqual(result["summary"]["error"], 1)
        self.assertEqual(result["summary"]["info"], 1)
        self.assertEqual(result["summary"]["total"], 2)

    def test_invalid_logs_file_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "datadog-logs.json"), "w", encoding="utf-8") as f:
                f.write("garbage")
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["summary"]["total"], 0)

    def test_signals_parsed_and_sorted_by_severity(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "datadog-signals.json"),
                {
                    "data": [
                        {"id": "s1", "attributes": {"severity": "low", "title": "t1"}},
                        {"id": "s2", "attributes": {"severity": "critical", "title": "t2"}},
                        {"id": "s3", "attributes": {"severity": "sev-2", "title": "t3"}},
                    ]
                },
            )
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["signal_summary"]["critical"], 1)
        self.assertEqual(result["signal_summary"]["high"], 1)
        self.assertEqual(result["signal_summary"]["low"], 1)
        severities = [s["severity"] for s in result["signals"]]
        self.assertEqual(severities, ["critical", "high", "low"])

    def test_signals_invalid_json_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(
                os.path.join(d, "datadog-signals.json"), "w", encoding="utf-8"
            ) as f:
                f.write("garbage")
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["signals"], [])

    def test_cases_parsed_and_severity_fallback_to_priority(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "datadog-cases.json"),
                {
                    "data": [
                        {"id": "c1", "attributes": {"priority": "p1", "title": "a"}},
                        {"id": "c2", "attributes": {"case_priority": "p3", "title": "b"}},
                        {"id": "c3", "attributes": {"severity": "informational", "name": "c"}},
                    ]
                },
            )
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["case_summary"]["critical"], 1)
        self.assertEqual(result["case_summary"]["medium"], 1)
        self.assertEqual(result["case_summary"]["info"], 1)
        self.assertEqual(result["case_summary"]["total"], 3)

    def test_cases_invalid_json_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(
                os.path.join(d, "datadog-cases.json"), "w", encoding="utf-8"
            ) as f:
                f.write("not json")
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["cases"], [])

    def test_signal_attributes_not_dict_defaults_empty(self):
        # When attributes is not a dict, _inc_sev should record as "unknown".
        with tempfile.TemporaryDirectory() as d:
            _write_json(
                os.path.join(d, "datadog-signals.json"),
                {"data": [{"id": "x", "attributes": "weird"}]},
            )
            result = loader.load_datadog_logs(d)
        self.assertEqual(result["signal_summary"]["unknown"], 1)


# ===========================================================================
# 13. _normalize_severity (Prowler helper)
# ===========================================================================


class TestNormalizeSeverityProwler(unittest.TestCase):
    def test_known_lowercase_mapped(self):
        self.assertEqual(loader._normalize_severity("critical"), "Critical")
        self.assertEqual(loader._normalize_severity("high"), "High")
        self.assertEqual(loader._normalize_severity("medium"), "Medium")
        self.assertEqual(loader._normalize_severity("low"), "Low")
        self.assertEqual(loader._normalize_severity("informational"), "Informational")

    def test_uppercase_mapped(self):
        self.assertEqual(loader._normalize_severity("HIGH"), "High")

    def test_unknown_falls_through_to_title(self):
        self.assertEqual(loader._normalize_severity("custom"), "Custom")

    def test_empty_returns_unknown(self):
        self.assertEqual(loader._normalize_severity(""), "Unknown")


# ===========================================================================
# 14. analyze_prowler
# ===========================================================================


class TestAnalyzeProwler(unittest.TestCase):
    def test_empty_input(self):
        summary, findings = loader.analyze_prowler({})
        self.assertEqual(summary, {})
        self.assertEqual(findings, [])

    def test_separates_pass_and_fail_and_counts_severity(self):
        providers = {
            "aws": [
                {"status_code": "FAIL", "severity": "critical",
                 "finding_info": {"title": "T1", "desc": "d"},
                 "resources": [{"region": "us-east-1", "name": "r1",
                                "type": "rt", "data": {"metadata": {}}}],
                 "metadata": {"event_code": "check_1"}},
                {"status_code": "PASS", "severity": "low"},
                {"status_code": "FAIL", "severity": "high",
                 "finding_info": {}, "resources": []},
            ]
        }
        summary, findings = loader.analyze_prowler(providers)
        self.assertEqual(summary["aws"]["total_fail"], 2)
        self.assertEqual(summary["aws"]["total_pass"], 1)
        self.assertEqual(summary["aws"]["critical"], 1)
        self.assertEqual(summary["aws"]["high"], 1)
        self.assertEqual(len(findings), 2)
        first = findings[0]
        self.assertEqual(first["provider"], "aws")
        self.assertEqual(first["check"], "check_1")
        self.assertEqual(first["title"], "T1")
        self.assertEqual(first["resource"], "r1")

    def test_empty_resources_handled(self):
        providers = {"gcp": [{"status_code": "FAIL", "severity": "low"}]}
        summary, findings = loader.analyze_prowler(providers)
        self.assertEqual(summary["gcp"]["total_fail"], 1)
        self.assertEqual(findings[0]["resource"], "")

    def test_native_refs_non_list_becomes_empty(self):
        providers = {
            "aws": [{
                "status_code": "FAIL", "severity": "high",
                "remediation": {"desc": "do x", "references": "not-a-list"},
            }]
        }
        _, findings = loader.analyze_prowler(providers)
        self.assertEqual(findings[0]["native_remediation"], "do x")
        self.assertEqual(findings[0]["native_refs"], [])


# ===========================================================================
# 15. Provider-filter helpers
# ===========================================================================


class TestProviderFilters(unittest.TestCase):
    def setUp(self):
        self.findings = [
            {"provider": "github"},
            {"provider": "aws"},
            {"provider": "gcp"},
            {"provider": "googleworkspace"},
            {"provider": "kubernetes"},
            {"provider": "azure"},
            {"provider": "m365"},
            {"provider": "iac"},
        ]

    def test_github_filter(self):
        result = loader.github_findings(self.findings)
        self.assertEqual([f["provider"] for f in result], ["github"])

    def test_aws_filter(self):
        self.assertEqual(len(loader.aws_findings(self.findings)), 1)

    def test_gcp_filter(self):
        self.assertEqual(len(loader.gcp_findings(self.findings)), 1)

    def test_gws_filter_matches_googleworkspace(self):
        result = loader.gws_findings(self.findings)
        self.assertEqual([f["provider"] for f in result], ["googleworkspace"])

    def test_k8s_filter(self):
        self.assertEqual(len(loader.k8s_findings(self.findings)), 1)

    def test_azure_filter(self):
        self.assertEqual(len(loader.azure_findings(self.findings)), 1)

    def test_m365_filter(self):
        self.assertEqual(len(loader.m365_findings(self.findings)), 1)

    def test_iac_filter(self):
        self.assertEqual(len(loader.iac_findings(self.findings)), 1)

    def test_filters_return_empty_on_empty_input(self):
        for fn in (
            loader.github_findings,
            loader.aws_findings,
            loader.gcp_findings,
            loader.gws_findings,
            loader.k8s_findings,
            loader.azure_findings,
            loader.m365_findings,
            loader.iac_findings,
        ):
            self.assertEqual(fn([]), [])


# ===========================================================================
# 16. get_env_status
# ===========================================================================


class TestGetEnvStatus(unittest.TestCase):
    def test_returns_expected_number_of_entries(self):
        with patch.dict(os.environ, {}, clear=False):
            for var in [
                "CLAUDESEC_ENV_GITHUB_CONNECTED",
                "CLAUDESEC_ENV_K8S_CONNECTED",
                "CLAUDESEC_ENV_AWS_CONNECTED",
                "CLAUDESEC_ENV_GCP_CONNECTED",
                "CLAUDESEC_ENV_AZ_CONNECTED",
                "CLAUDESEC_ENV_M365_CONNECTED",
                "CLAUDESEC_ENV_OKTA_CONNECTED",
                "CLAUDESEC_ENV_GWS_CONNECTED",
                "CLAUDESEC_ENV_CF_CONNECTED",
                "CLAUDESEC_ENV_NHN_CONNECTED",
                "CLAUDESEC_ENV_LLM_CONNECTED",
                "CLAUDESEC_ENV_DATADOG_CONNECTED",
            ]:
                os.environ.pop(var, None)
            envs = loader.get_env_status()
        self.assertEqual(len(envs), 12)
        for e in envs:
            self.assertFalse(e["connected"])

    def test_github_connected_flag_reflects_env(self):
        with patch.dict(
            os.environ, {"CLAUDESEC_ENV_GITHUB_CONNECTED": "true"}, clear=False
        ):
            envs = loader.get_env_status()
        github = next(e for e in envs if e["name"] == "GitHub")
        self.assertTrue(github["connected"])

    def test_non_true_value_treated_as_disconnected(self):
        with patch.dict(
            os.environ, {"CLAUDESEC_ENV_AWS_CONNECTED": "1"}, clear=False
        ):
            envs = loader.get_env_status()
        aws = next(e for e in envs if e["name"] == "AWS")
        self.assertFalse(aws["connected"])

    def test_all_entries_have_required_keys(self):
        envs = loader.get_env_status()
        for e in envs:
            for key in ("icon", "name", "connected", "setup_id", "hint"):
                self.assertIn(key, e)


if __name__ == "__main__":
    unittest.main()
