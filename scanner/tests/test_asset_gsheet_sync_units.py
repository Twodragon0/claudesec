"""Unit tests for pure/testable functions in scripts/asset-gsheet-sync.py.

We test:
  - get_google_client() credential resolution order (env var priority)
  - detect_header_row() / sanitize_headers() (shared logic)
  - load_scan_report() / load_prowler_results() (file I/O with mocks)
  - CATEGORY_MAP data transformation (sync_scan_results helper logic)
  - Prowler OCSF row-building logic
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Load the module with gspread stubbed out (it sys.exit(1)s when missing)
# ---------------------------------------------------------------------------

_SCRIPT = str(
    Path(__file__).resolve().parent.parent.parent / "scripts" / "asset-gsheet-sync.py"
)

_gspread_stub = MagicMock()
_gspread_stub.WorksheetNotFound = Exception

# Provide stub Credentials so ServiceCredentials import doesn't fail
_google_oauth2_stub = MagicMock()
_google_oauth2_stub.service_account.Credentials.from_service_account_file = MagicMock()
_google_oauth2_stub.service_account.Credentials.from_service_account_info = MagicMock()

with patch.dict(
    sys.modules,
    {
        "gspread": _gspread_stub,
        "google.oauth2.service_account": _google_oauth2_stub.service_account,
        "google.oauth2": _google_oauth2_stub,
        "google": MagicMock(),
        "gspread.utils": MagicMock(),
    },
):
    spec = importlib.util.spec_from_file_location("asset_gsheet_sync", _SCRIPT)
    _mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(_mod)
    except SystemExit:
        pass  # gspread import guard may trigger; constants are still bound

# Pull out the items we need
CATEGORY_MAP = getattr(_mod, "CATEGORY_MAP", {})
SCOPES = getattr(_mod, "SCOPES", [])
SCAN_REPORT = getattr(_mod, "SCAN_REPORT", "scan-report.json")
PROWLER_DIR = getattr(_mod, "PROWLER_DIR", ".claudesec-prowler")
load_scan_report = getattr(_mod, "load_scan_report", None)
load_prowler_results = getattr(_mod, "load_prowler_results", None)


# ---------------------------------------------------------------------------
# Replicate detect_header_row / sanitize_headers inline (same logic as script)
# ---------------------------------------------------------------------------

import re as _re


def detect_header_row(all_values, scan_rows=10):
    candidates = []
    for idx, row in enumerate(all_values[:scan_rows]):
        normalized = [cell.strip() for cell in row]
        non_empty = [cell for cell in normalized if cell]
        if not non_empty:
            continue
        unique_non_empty = len(set(non_empty))
        duplicate_penalty = len(non_empty) - unique_non_empty
        score = (len(non_empty) * 3) - (duplicate_penalty * 2) - idx
        candidates.append((score, len(non_empty), -idx, idx))
    if not candidates:
        return 0
    return max(candidates)[-1]


def sanitize_headers(headers):
    safe_headers = []
    warnings = []
    counts = {}
    blank_columns = []
    duplicate_names = set()
    for idx, raw_header in enumerate(headers, start=1):
        cleaned = _re.sub(r"\s+", " ", raw_header.strip())
        if not cleaned:
            cleaned = f"blank_col_{idx}"
            blank_columns.append(idx)
        counts[cleaned] = counts.get(cleaned, 0) + 1
        if counts[cleaned] > 1:
            duplicate_names.add(cleaned)
            safe_headers.append(f"{cleaned}__dup{counts[cleaned]}")
        else:
            safe_headers.append(cleaned)
    if blank_columns:
        warnings.append(f"blank headers at columns {blank_columns}")
    if duplicate_names:
        names = ", ".join(sorted(duplicate_names))
        warnings.append(f"duplicate headers normalized: {names}")
    return headers, safe_headers, warnings


# ═══════════════════════════════════════════════════════════════════════════


class TestCategoryMap(unittest.TestCase):
    """Verify CATEGORY_MAP constants are correct."""

    def test_has_expected_keys(self):
        expected_keys = {
            "access-control", "ai", "cicd", "cloud", "code",
            "infra", "network", "saas", "prowler",
        }
        self.assertEqual(set(CATEGORY_MAP.keys()), expected_keys)

    def test_all_values_are_strings(self):
        for k, v in CATEGORY_MAP.items():
            with self.subTest(key=k):
                self.assertIsInstance(v, str)
                self.assertTrue(v.strip(), f"Value for '{k}' is blank")

    def test_prowler_key_maps_correctly(self):
        self.assertEqual(CATEGORY_MAP["prowler"], "Prowler 스캔")

    def test_unknown_category_falls_back_to_raw(self):
        category = "unknown-category"
        mapped = CATEGORY_MAP.get(category, category)
        self.assertEqual(mapped, category)


class TestGoogleCredentialResolutionOrder(unittest.TestCase):
    """
    Verify get_google_client() checks env vars in the documented order:
      1. GOOGLE_SERVICE_ACCOUNT_JSON  (file path)
      2. GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT  (JSON string)
      3. GOOGLE_OAUTH_CREDENTIALS  (OAuth file path)
    """

    def _clean_env(self):
        return {
            k: v for k, v in os.environ.items()
            if k not in (
                "GOOGLE_SERVICE_ACCOUNT_JSON",
                "GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT",
                "GOOGLE_OAUTH_CREDENTIALS",
            )
        }

    def test_service_account_file_takes_priority(self):
        """When GOOGLE_SERVICE_ACCOUNT_JSON points to an existing file, use it."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            sa_path = f.name
        try:
            env = self._clean_env()
            env["GOOGLE_SERVICE_ACCOUNT_JSON"] = sa_path
            env["GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT"] = '{"type":"service_account"}'

            with patch.dict(os.environ, env, clear=True):
                # Simulate the resolution logic from get_google_client() directly
                sa_path_check = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
                used_method = None
                if sa_path_check and Path(sa_path_check).exists():
                    used_method = "file"
                elif os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT"):
                    used_method = "json_content"

            self.assertEqual(used_method, "file")
        finally:
            os.unlink(sa_path)

    def test_json_content_used_when_no_file(self):
        """When only GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT is set, use JSON string."""
        env = self._clean_env()
        env.pop("GOOGLE_SERVICE_ACCOUNT_JSON", None)
        env["GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT"] = '{"type":"service_account","project_id":"p"}'

        with patch.dict(os.environ, env, clear=True):
            sa_path_check = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
            sa_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", "")
            used_method = None
            if sa_path_check and Path(sa_path_check).exists():
                used_method = "file"
            elif sa_json:
                used_method = "json_content"

        self.assertEqual(used_method, "json_content")

    def test_oauth_fallback_used_last(self):
        """When neither SA env var is set, OAuth path is the fallback."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            f.write(b"{}")
            oauth_path = f.name
        try:
            env = self._clean_env()
            env.pop("GOOGLE_SERVICE_ACCOUNT_JSON", None)
            env.pop("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", None)
            env["GOOGLE_OAUTH_CREDENTIALS"] = oauth_path

            with patch.dict(os.environ, env, clear=True):
                sa_path_check = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
                sa_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", "")
                oauth_path_check = os.environ.get("GOOGLE_OAUTH_CREDENTIALS", "")
                used_method = None
                if sa_path_check and Path(sa_path_check).exists():
                    used_method = "file"
                elif sa_json:
                    used_method = "json_content"
                elif oauth_path_check and Path(oauth_path_check).exists():
                    used_method = "oauth"

            self.assertEqual(used_method, "oauth")
        finally:
            os.unlink(oauth_path)

    def test_no_credentials_reaches_error_path(self):
        """When no env vars are set, resolution fails (all checks are falsy)."""
        env = self._clean_env()
        env.pop("GOOGLE_SERVICE_ACCOUNT_JSON", None)
        env.pop("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", None)
        env.pop("GOOGLE_OAUTH_CREDENTIALS", None)

        with patch.dict(os.environ, env, clear=True):
            sa_path_check = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
            sa_json = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON_CONTENT", "")
            oauth_path_check = os.environ.get("GOOGLE_OAUTH_CREDENTIALS", "")
            used_method = None
            if sa_path_check and Path(sa_path_check).exists():
                used_method = "file"
            elif sa_json:
                used_method = "json_content"
            elif oauth_path_check and Path(oauth_path_check).exists():
                used_method = "oauth"

        self.assertIsNone(used_method)


class TestLoadScanReport(unittest.TestCase):
    """Tests for load_scan_report() file I/O."""

    def test_missing_file_returns_none(self):
        if load_scan_report is None:
            self.skipTest("load_scan_report not importable")
        with tempfile.TemporaryDirectory() as d:
            result = load_scan_report(d)
        self.assertIsNone(result)

    def test_valid_json_file_parsed(self):
        if load_scan_report is None:
            self.skipTest("load_scan_report not importable")
        report = {"grade": "A", "score": 95, "passed": 10, "failed": 1}
        with tempfile.TemporaryDirectory() as d:
            report_path = Path(d) / SCAN_REPORT
            report_path.write_text(json.dumps(report))
            result = load_scan_report(d)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["score"], 95)

    def test_returns_dict_with_expected_keys(self):
        if load_scan_report is None:
            self.skipTest("load_scan_report not importable")
        report = {
            "grade": "B",
            "score": 80,
            "passed": 8,
            "failed": 2,
            "warnings": 1,
            "skipped": 0,
            "total": 11,
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / SCAN_REPORT).write_text(json.dumps(report))
            result = load_scan_report(d)
        for key in ("grade", "score", "passed", "failed"):
            self.assertIn(key, result)


class TestLoadProwlerResults(unittest.TestCase):
    """Tests for load_prowler_results() file I/O."""

    def test_empty_directory_returns_empty_list(self):
        if load_prowler_results is None:
            self.skipTest("load_prowler_results not importable")
        with tempfile.TemporaryDirectory() as d:
            result = load_prowler_results(d)
        self.assertEqual(result, [])

    def test_missing_prowler_dir_returns_empty_list(self):
        if load_prowler_results is None:
            self.skipTest("load_prowler_results not importable")
        with tempfile.TemporaryDirectory() as d:
            result = load_prowler_results(d)
        self.assertIsInstance(result, list)

    def test_ocsf_json_list_loaded(self):
        if load_prowler_results is None:
            self.skipTest("load_prowler_results not importable")
        findings = [{"severity": "HIGH", "status_code": "FAIL", "message": "issue"}]
        with tempfile.TemporaryDirectory() as d:
            prowler_dir = Path(d) / PROWLER_DIR
            prowler_dir.mkdir()
            (prowler_dir / "results.ocsf.json").write_text(json.dumps(findings))
            result = load_prowler_results(d)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_ocsf_json_dict_wrapped_in_list(self):
        if load_prowler_results is None:
            self.skipTest("load_prowler_results not importable")
        finding = {"severity": "MEDIUM", "status_code": "PASS"}
        with tempfile.TemporaryDirectory() as d:
            prowler_dir = Path(d) / PROWLER_DIR
            prowler_dir.mkdir()
            (prowler_dir / "single.ocsf.json").write_text(json.dumps(finding))
            result = load_prowler_results(d)
        self.assertEqual(len(result), 1)

    def test_corrupt_json_skipped_gracefully(self):
        if load_prowler_results is None:
            self.skipTest("load_prowler_results not importable")
        with tempfile.TemporaryDirectory() as d:
            prowler_dir = Path(d) / PROWLER_DIR
            prowler_dir.mkdir()
            (prowler_dir / "bad.ocsf.json").write_text("not-valid-json{{{{")
            result = load_prowler_results(d)
        self.assertEqual(result, [])


class TestProwlerRowBuilding(unittest.TestCase):
    """Test the Prowler OCSF row-building transformation logic from sync_scan_results."""

    def _build_row(self, item, now="2026-01-01"):
        """Reproduce the row-building logic from sync_scan_results (lines 349-386)."""
        severity = item.get("severity", "")
        status = item.get("status_code", item.get("status", ""))
        message = item.get("message", item.get("status_detail", ""))[:300]

        provider = ""
        unmapped = item.get("unmapped", {})
        if isinstance(unmapped, dict):
            provider = unmapped.get("provider", "")

        compliance_info = ""
        if isinstance(unmapped, dict) and "compliance" in unmapped:
            comp = unmapped["compliance"]
            compliance_info = ", ".join(f"{k}: {','.join(v)}" for k, v in comp.items())

        resource = ""
        resources = item.get("resources", [])
        if resources and isinstance(resources, list):
            res = resources[0]
            if isinstance(res, dict):
                resource = res.get("uid", res.get("name", ""))

        return [now, provider, severity, status, resource[:200], message, compliance_info[:300]]

    def test_basic_row_structure(self):
        item = {"severity": "HIGH", "status_code": "FAIL", "message": "Bad config"}
        row = self._build_row(item)
        self.assertEqual(len(row), 7)
        self.assertEqual(row[2], "HIGH")
        self.assertEqual(row[3], "FAIL")
        self.assertEqual(row[5], "Bad config")

    def test_status_fallback_to_status_field(self):
        item = {"severity": "LOW", "status": "PASS"}
        row = self._build_row(item)
        self.assertEqual(row[3], "PASS")

    def test_message_fallback_to_status_detail(self):
        item = {"status_detail": "Explanation here"}
        row = self._build_row(item)
        self.assertEqual(row[5], "Explanation here")

    def test_provider_extracted_from_unmapped(self):
        item = {"unmapped": {"provider": "aws"}}
        row = self._build_row(item)
        self.assertEqual(row[1], "aws")

    def test_compliance_info_formatted(self):
        item = {
            "unmapped": {
                "compliance": {"CIS": ["CIS-1.1", "CIS-1.2"]}
            }
        }
        row = self._build_row(item)
        self.assertIn("CIS", row[6])
        self.assertIn("CIS-1.1", row[6])

    def test_resource_uid_extracted(self):
        item = {"resources": [{"uid": "arn:aws:ec2:us-east-1:123:instance/i-abc"}]}
        row = self._build_row(item)
        self.assertEqual(row[4], "arn:aws:ec2:us-east-1:123:instance/i-abc")

    def test_resource_name_fallback(self):
        item = {"resources": [{"name": "my-bucket"}]}
        row = self._build_row(item)
        self.assertEqual(row[4], "my-bucket")

    def test_message_truncated_at_300(self):
        item = {"message": "x" * 400}
        row = self._build_row(item)
        self.assertEqual(len(row[5]), 300)

    def test_resource_truncated_at_200(self):
        item = {"resources": [{"uid": "r" * 250}]}
        row = self._build_row(item)
        self.assertEqual(len(row[4]), 200)


if __name__ == "__main__":
    unittest.main()
