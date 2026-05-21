"""
Targeted coverage tests for scanner/lib/dashboard_data_loader.py.

Covers the specific missing lines identified by --cov-report=term-missing:
  118        — providers[name].extend(items) in load_prowler_files (duplicate provider)
  180-181    — OSError/JSONDecodeError except in load_audit_points
  222-223    — OSError/JSONDecodeError except in load_microsoft_best_practices
  255-256    — OSError/JSONDecodeError except in load_saas_best_practices
  280-281    — OSError/JSONDecodeError in network-report.v1.json read
  313-318    — Misconfigurations severity branches (CRITICAL/HIGH/MEDIUM/LOW) in trivy-fs
  336-337    — OSError in trivy-config.json read
  342-355    — ImportError fallback XML parser (defusedxml not installed)
  501-503    — _extract_items returns [] for non-dict/non-list input

No network calls. All filesystem I/O via tmp_path (pytest) or
tempfile.TemporaryDirectory (unittest).  Uses unittest.mock.patch only
to trigger error paths or missing-module conditions.
"""

import importlib
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_data_loader as loader  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


# ===========================================================================
# Line 118 — load_prowler_files: duplicate provider name → extend()
# ===========================================================================

class TestLoadProwlerFilesDuplicateProvider(unittest.TestCase):
    """
    When two OCSF files normalise to the same provider name (e.g. both
    'prowler-k8s-a.ocsf.json' and 'prowler-k8s-b.ocsf.json' → 'kubernetes'),
    the second batch of items must be *extended* into the existing list (line 118).
    """

    def test_duplicate_provider_extends_list(self):
        with tempfile.TemporaryDirectory() as d:
            _write_json(os.path.join(d, "prowler-k8s-a.ocsf.json"), [{"id": 1}])
            _write_json(os.path.join(d, "prowler-k8s-b.ocsf.json"), [{"id": 2}])
            result = loader.load_prowler_files(d)
        self.assertIn("kubernetes", result)
        ids = [item["id"] for item in result["kubernetes"]]
        self.assertCountEqual(ids, [1, 2])


# ===========================================================================
# Lines 180-181 — load_audit_points: OSError in cache read
# ===========================================================================

class TestLoadAuditPointsOSErrorInCacheRead(unittest.TestCase):
    """
    When the cache file exists but open() raises OSError, the function
    must catch it (lines 180-181) and return the empty fallback.
    """

    def test_oserror_in_cache_open_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, ".claudesec-audit-points")
            os.makedirs(cache_dir)
            cache_file = os.path.join(cache_dir, "cache.json")
            # Create the file so isfile() passes, then make it unreadable
            with open(cache_file, "w") as f:
                f.write("{bad json")
            # Patch open to raise OSError on the cache file
            real_open = open

            def _raise_on_cache(path, *args, **kwargs):
                if os.path.basename(path) == "cache.json":
                    raise OSError("mocked permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_cache):
                result = loader.load_audit_points(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})


class TestLoadAuditPointsJsonDecodeErrorInCache(unittest.TestCase):
    """
    When the cache file contains invalid JSON, JSONDecodeError is caught
    (lines 180-181) and the empty fallback is returned.
    """

    def test_invalid_json_in_cache_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, ".claudesec-audit-points")
            os.makedirs(cache_dir)
            cache_file = os.path.join(cache_dir, "cache.json")
            with open(cache_file, "w") as f:
                f.write("THIS IS NOT JSON !!!")
            result = loader.load_audit_points(d)
        self.assertEqual(result, {"products": [], "fetched_at": ""})


# ===========================================================================
# Lines 222-223 — load_microsoft_best_practices: OSError except
# ===========================================================================

class TestLoadMicrosoftBestPracticesOSError(unittest.TestCase):
    """
    When writing the fetched data raises OSError, lines 222-223 catch it
    and return the empty-sources fallback dict.
    """

    def test_oserror_on_write_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            # No cache file → offline=False → will try to fetch + write
            fake_fresh = {"fetched_at": "2024-01-01T00:00:00+00:00", "sources": [{"name": "x"}]}
            with patch(
                "dashboard_data_loader._fetch_microsoft_best_practices_from_github",
                return_value=fake_fresh,
            ), patch(
                "builtins.open",
                side_effect=OSError("disk full"),
            ):
                result = loader.load_microsoft_best_practices(d)
        # Fallback must contain empty sources list
        self.assertEqual(result["sources"], [])
        self.assertIn("fetched_at", result)


class TestLoadMicrosoftBestPracticesJsonDecodeErrorInCache(unittest.TestCase):
    """
    When reading an existing cache raises JSONDecodeError, lines 222-223 catch it
    and return the empty-sources fallback dict.
    """

    def test_json_decode_error_in_cache_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, ".claudesec-ms-best-practices")
            os.makedirs(cache_dir)
            cache_file = os.path.join(cache_dir, "cache.json")
            with open(cache_file, "w") as f:
                f.write("NOT JSON")
            result = loader.load_microsoft_best_practices(d)
        self.assertEqual(result["sources"], [])


# ===========================================================================
# Lines 255-256 — load_saas_best_practices: OSError/JSONDecodeError except
# ===========================================================================

class TestLoadSaasBestPracticesOSError(unittest.TestCase):
    """
    When writing the fresh SaaS data raises OSError, lines 255-256 catch it
    and return the empty fallback.
    """

    def test_oserror_on_write_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            fake_fresh = {"fetched_at": "2024-01-01T00:00:00+00:00", "sources": []}
            with patch(
                "dashboard_data_loader._fetch_saas_best_practices_from_github",
                return_value=fake_fresh,
            ), patch(
                "builtins.open",
                side_effect=OSError("disk full"),
            ):
                result = loader.load_saas_best_practices(d)
        self.assertEqual(result, {"fetched_at": "", "sources": []})


class TestLoadSaasBestPracticesJsonDecodeErrorInCache(unittest.TestCase):
    """
    When cache.json is invalid JSON, JSONDecodeError is caught (lines 255-256)
    and the empty fallback is returned.
    """

    def test_json_decode_error_in_cache_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = os.path.join(d, ".claudesec-saas-best-practices")
            os.makedirs(cache_dir)
            with open(os.path.join(cache_dir, "cache.json"), "w") as f:
                f.write("NOT JSON !!!")
            result = loader.load_saas_best_practices(d)
        self.assertEqual(result, {"fetched_at": "", "sources": []})


# ===========================================================================
# Lines 280-281 — load_network_tool_results: OSError on network-report.v1.json
# ===========================================================================

class TestLoadNetworkToolResultsReportOSError(unittest.TestCase):
    """
    When network-report.v1.json exists but reading it raises OSError,
    lines 280-281 must be executed (the except pass branch).
    """

    def test_oserror_on_report_read_is_skipped(self):
        with tempfile.TemporaryDirectory() as net_dir:
            report_path = os.path.join(net_dir, "network-report.v1.json")
            with open(report_path, "w") as f:
                f.write("{}")

            real_open = open

            def _raise_on_report(path, *args, **kwargs):
                if os.path.basename(path) == "network-report.v1.json":
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_report):
                result = loader.load_network_tool_results(net_dir)

        # network_report stays None; no exception propagated
        self.assertIsNone(result["network_report"])


class TestLoadNetworkToolResultsReportBadJson(unittest.TestCase):
    """
    When network-report.v1.json contains invalid JSON, JSONDecodeError is
    caught (lines 280-281) and network_report stays None.
    """

    def test_bad_json_in_report_skipped(self):
        with tempfile.TemporaryDirectory() as net_dir:
            report_path = os.path.join(net_dir, "network-report.v1.json")
            with open(report_path, "w") as f:
                f.write("INVALID JSON !!!")
            result = loader.load_network_tool_results(net_dir)
        self.assertIsNone(result["network_report"])


# ===========================================================================
# Lines 313-318 — trivy-fs Misconfigurations severity branches
# ===========================================================================

class TestLoadNetworkToolResultsMisconfigurationSeverities(unittest.TestCase):
    """
    Misconfigurations in trivy-fs.json follow the same severity counting
    code path as Vulnerabilities. Lines 313-318 cover the CRITICAL/HIGH/
    MEDIUM/LOW branches for Misconfigurations entries.
    """

    def _make_trivy_fs(self, severities):
        """Return a trivy-fs dict with Misconfigurations at the given severities."""
        return {
            "Results": [
                {
                    "Target": ".",
                    "Misconfigurations": [
                        {"Severity": s, "ID": f"ID-{s}", "Title": s, "Message": ""}
                        for s in severities
                    ],
                }
            ]
        }

    def test_critical_misconfiguration_counted(self):
        with tempfile.TemporaryDirectory() as net_dir:
            _write_json(os.path.join(net_dir, "trivy-fs.json"),
                        self._make_trivy_fs(["CRITICAL"]))
            result = loader.load_network_tool_results(net_dir)
        self.assertEqual(result["trivy_summary"]["critical"], 1)
        self.assertEqual(result["trivy_summary"]["high"], 0)

    def test_high_misconfiguration_counted(self):
        with tempfile.TemporaryDirectory() as net_dir:
            _write_json(os.path.join(net_dir, "trivy-fs.json"),
                        self._make_trivy_fs(["HIGH"]))
            result = loader.load_network_tool_results(net_dir)
        self.assertEqual(result["trivy_summary"]["high"], 1)

    def test_medium_misconfiguration_counted(self):
        with tempfile.TemporaryDirectory() as net_dir:
            _write_json(os.path.join(net_dir, "trivy-fs.json"),
                        self._make_trivy_fs(["MEDIUM"]))
            result = loader.load_network_tool_results(net_dir)
        self.assertEqual(result["trivy_summary"]["medium"], 1)

    def test_low_misconfiguration_counted(self):
        with tempfile.TemporaryDirectory() as net_dir:
            _write_json(os.path.join(net_dir, "trivy-fs.json"),
                        self._make_trivy_fs(["LOW"]))
            result = loader.load_network_tool_results(net_dir)
        self.assertEqual(result["trivy_summary"]["low"], 1)

    def test_mixed_severities_all_counted(self):
        with tempfile.TemporaryDirectory() as net_dir:
            _write_json(os.path.join(net_dir, "trivy-fs.json"),
                        self._make_trivy_fs(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
            result = loader.load_network_tool_results(net_dir)
        self.assertEqual(result["trivy_summary"]["critical"], 1)
        self.assertEqual(result["trivy_summary"]["high"], 1)
        self.assertEqual(result["trivy_summary"]["medium"], 1)
        self.assertEqual(result["trivy_summary"]["low"], 1)


# ===========================================================================
# Lines 336-337 — trivy-config.json read OSError
# ===========================================================================

class TestLoadNetworkToolResultsTrivyConfigOSError(unittest.TestCase):
    """
    When trivy-config.json exists but reading it raises OSError,
    lines 336-337 must be executed (the except pass branch) and
    trivy_config stays None.
    """

    def test_oserror_on_trivy_config_skipped(self):
        with tempfile.TemporaryDirectory() as net_dir:
            cfg_path = os.path.join(net_dir, "trivy-config.json")
            with open(cfg_path, "w") as f:
                f.write("{}")

            real_open = open

            def _raise_on_cfg(path, *args, **kwargs):
                if os.path.basename(path) == "trivy-config.json":
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_cfg):
                result = loader.load_network_tool_results(net_dir)

        self.assertIsNone(result["trivy_config"])


class TestLoadNetworkToolResultsTrivyConfigBadJson(unittest.TestCase):
    """
    When trivy-config.json is invalid JSON, JSONDecodeError is caught
    (lines 336-337) and trivy_config stays None.
    """

    def test_bad_json_in_trivy_config_skipped(self):
        with tempfile.TemporaryDirectory() as net_dir:
            cfg_path = os.path.join(net_dir, "trivy-config.json")
            with open(cfg_path, "w") as f:
                f.write("INVALID !!!")
            result = loader.load_network_tool_results(net_dir)
        self.assertIsNone(result["trivy_config"])


# ===========================================================================
# Lines 342-355 — defusedxml ImportError fallback XML parser
# ===========================================================================

class TestLoadNetworkToolResultsDefusedxmlFallback(unittest.TestCase):
    """
    When defusedxml is not installed, lines 342-355 define a fallback
    _parse_xml function using stdlib xml.etree.ElementTree.  We trigger
    this by temporarily removing defusedxml from sys.modules so the
    `import defusedxml.ElementTree as SafeET` inside load_network_tool_results
    raises ImportError, which exercises the fallback code path.
    """

    _NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><address addr="192.0.2.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    def test_fallback_parser_used_when_defusedxml_missing(self):
        import warnings
        # Save and remove defusedxml from sys.modules so the `import` inside
        # load_network_tool_results will raise ImportError.
        saved_modules = {}
        for key in list(sys.modules.keys()):
            if "defusedxml" in key:
                saved_modules[key] = sys.modules.pop(key)

        try:
            with tempfile.TemporaryDirectory() as net_dir:
                nmap_path = os.path.join(net_dir, "nmap-internal.xml")
                with open(nmap_path, "w") as f:
                    f.write(self._NMAP_XML)

                # Also block re-import so the ImportError is triggered
                real_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

                def _block_defusedxml(name, *args, **kwargs):
                    if "defusedxml" in name:
                        raise ImportError(f"No module named '{name}'")
                    return real_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=_block_defusedxml):
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", ImportWarning)
                        result = loader.load_network_tool_results(net_dir)
        finally:
            # Restore defusedxml to sys.modules
            sys.modules.update(saved_modules)

        # The fallback path was triggered: the ImportWarning was emitted
        # and nmap_scans was populated (even if the parse failed gracefully).
        self.assertIsInstance(result["nmap_scans"], list)
        self.assertEqual(len(result["nmap_scans"]), 1)


# ===========================================================================
# Lines 501-503 — _extract_items returns [] for non-dict/non-list input
# ===========================================================================

class TestExtractItemsFallback(unittest.TestCase):
    """
    _extract_items is a closure inside load_datadog_logs called for
    signals and cases data.  Lines 501-503 cover:
      501 — isinstance(data, list) branch
      502 — list comprehension (filter non-dicts)
      503 — return [] when data is neither dict-with-data nor list

    We trigger all three by writing signals/cases files whose content
    is (a) a bare list, (b) a dict with a "data" list, and (c) a scalar.
    """

    def test_signal_as_plain_list_triggers_list_branch(self):
        """Line 501-502: _extract_items called with a plain list (not wrapped in {"data":[]})."""
        with tempfile.TemporaryDirectory() as datadog_dir:
            signals = [
                {"id": "s1", "attributes": {"severity": "high", "title": "Test signal"}},
            ]
            with open(os.path.join(datadog_dir, "datadog-signals.json"), "w") as f:
                json.dump(signals, f)
            result = loader.load_datadog_logs(datadog_dir)
        # The list branch must have been executed; signal parsed
        self.assertEqual(len(result["signals"]), 1)

    def test_signal_as_scalar_triggers_empty_return(self):
        """Line 503: _extract_items called with a scalar → returns []."""
        with tempfile.TemporaryDirectory() as datadog_dir:
            # Write a top-level integer as the signal file content
            with open(os.path.join(datadog_dir, "datadog-signals.json"), "w") as f:
                json.dump(42, f)
            result = loader.load_datadog_logs(datadog_dir)
        self.assertEqual(result["signals"], [])

    def test_cases_as_plain_list_triggers_list_branch(self):
        """Lines 501-502 via the cases code path."""
        with tempfile.TemporaryDirectory() as datadog_dir:
            cases = [
                {"id": "c1", "attributes": {"severity": "critical", "title": "Case 1"}},
            ]
            with open(os.path.join(datadog_dir, "datadog-cases.json"), "w") as f:
                json.dump(cases, f)
            result = loader.load_datadog_logs(datadog_dir)
        self.assertEqual(len(result["cases"]), 1)

    def test_cases_as_scalar_triggers_empty_return(self):
        """Line 503 via the cases code path."""
        with tempfile.TemporaryDirectory() as datadog_dir:
            with open(os.path.join(datadog_dir, "datadog-cases.json"), "w") as f:
                json.dump("not a list", f)
            result = loader.load_datadog_logs(datadog_dir)
        self.assertEqual(result["cases"], [])


if __name__ == "__main__":
    unittest.main()
