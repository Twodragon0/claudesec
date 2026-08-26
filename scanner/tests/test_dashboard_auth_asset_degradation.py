"""
Regression tests: a malformed `.claudesec-assets/dashboard-data.json` must
degrade the SaaS SSO card, never take down the dashboard build.

`_load_saas_sso_stats()` used to end with
`except (FileNotFoundError, json.JSONDecodeError, KeyError)`. That narrowed
tuple missed several realistic inputs, each measured to raise out of the
function (and therefore out of `build_auth_summary_html`, which
`scanner/lib/dashboard-gen.py` calls UNGUARDED during HTML assembly):

  * top-level JSON array        -> AttributeError: 'list' object has no attribute 'get'
  * non-UTF-8 byte in the file  -> UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80
  * "saas" mapped to an object  -> AttributeError: 'str' object has no attribute 'get'
  * "saas" list of strings      -> AttributeError: 'str' object has no attribute 'get'
  * "auth" non-string           -> AttributeError: 'int' object has no attribute 'lower'

`UnicodeDecodeError` and `json.JSONDecodeError` are sibling `ValueError`
subclasses, so catching the latter never caught the former.

The asset file is written by a separate collector, so its shape is not
guaranteed. Degradation must also be observable (RuntimeWarning), because a
dashboard that omits data silently is the failure mode #445/#446/#448 were
about.

Style notes (matches test_dashboard_auth_gaps.py):
  * stdlib + unittest.mock only, no `import pytest`
  * plain `def test_*` plus a `unittest.TestCase` wrapper so both pytest (the
    CI runner) and `python3 -m unittest discover` pick the file up
  * hermetic: tempdirs only, no network, no real paths or PII
"""

import json
import os
import sys
import tempfile
import unittest
import warnings
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_auth import (  # noqa: E402
    _load_saas_sso_stats,
    build_auth_summary_html,
)


def _write_asset(scan_dir, payload, mode="w"):
    """Write raw bytes/text as $SCAN_DIR/.claudesec-assets/dashboard-data.json."""
    asset_dir = os.path.join(scan_dir, ".claudesec-assets")
    os.makedirs(asset_dir, exist_ok=True)
    path = os.path.join(asset_dir, "dashboard-data.json")
    kwargs = {} if "b" in mode else {"encoding": "utf-8"}
    with open(path, mode, **kwargs) as f:
        f.write(payload)
    return path


def _load_with(payload, mode="w"):
    """Return (stats, warning_messages) for a given raw asset-file payload."""
    with tempfile.TemporaryDirectory() as d:
        _write_asset(d, payload, mode)
        with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                stats = _load_saas_sso_stats()
    return stats, [str(w.message) for w in caught]


# ---------------------------------------------------------------------------
# Well-formed input still works (no behaviour change on the happy path)
# ---------------------------------------------------------------------------


def test_well_formed_asset_file_computes_stats_without_warning():
    payload = json.dumps(
        {
            "saas": [
                {"name": "A", "auth": "Okta SSO"},
                {"name": "B", "auth": "SAML via Okta"},
                {"name": "C", "auth": "local password"},
                {"name": "D", "auth": None},
            ]
        }
    )
    stats, msgs = _load_with(payload)
    assert stats == {"sso_count": 2, "total": 4, "pct": 50, "non_sso": 2}
    assert msgs == []


def test_empty_saas_list_returns_none_without_warning():
    """An empty list is "collector ran, nothing found" — not an anomaly."""
    stats, msgs = _load_with(json.dumps({"saas": []}))
    assert stats is None
    assert msgs == []


def test_missing_file_returns_none_without_warning():
    """Asset collection never run is expected, so it must stay quiet."""
    with tempfile.TemporaryDirectory() as d:
        with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                stats = _load_saas_sso_stats()
    assert stats is None
    assert [str(w.message) for w in caught] == []


# ---------------------------------------------------------------------------
# Malformed inputs: degrade to None + emit a RuntimeWarning
# ---------------------------------------------------------------------------


def test_truncated_json_degrades_with_warning():
    stats, msgs = _load_with('{"saas": [{"auth"')
    assert stats is None
    assert len(msgs) == 1
    assert "JSONDecodeError" in msgs[0]


def test_top_level_array_degrades_instead_of_attributeerror():
    stats, msgs = _load_with('[{"auth": "sso"}]')
    assert stats is None
    assert len(msgs) == 1
    assert "top-level JSON is list" in msgs[0]


def test_non_utf8_byte_degrades_instead_of_unicodedecodeerror():
    stats, msgs = _load_with(b'{"saas": [{"auth": "\x80sso"}]}', mode="wb")
    assert stats is None
    assert len(msgs) == 1
    assert "UnicodeDecodeError" in msgs[0]


def test_saas_present_but_not_a_list_degrades_with_warning():
    stats, msgs = _load_with('{"saas": {"okta": 1}}')
    assert stats is None
    assert len(msgs) == 1
    assert "'saas' is dict, expected a list" in msgs[0]


def test_saas_list_of_strings_degrades_with_warning():
    stats, msgs = _load_with('{"saas": ["okta", "other"]}')
    assert stats is None
    assert len(msgs) == 1
    assert "'saas' entry is str, expected an object" in msgs[0]


def test_saas_key_present_but_null_returns_none_without_warning():
    """`{"saas": null}` is falsy, so it is the same "no data" case as [] ."""
    stats, msgs = _load_with('{"saas": null}')
    assert stats is None
    assert msgs == []


def test_non_string_auth_value_is_coerced_not_crashed():
    stats, msgs = _load_with('{"saas": [{"auth": 5}, {"auth": "okta"}]}')
    assert stats == {"sso_count": 1, "total": 2, "pct": 50, "non_sso": 1}
    assert msgs == []


def test_permission_error_on_open_degrades_with_warning():
    """An unreadable asset file (OSError, not FileNotFoundError) degrades."""
    with tempfile.TemporaryDirectory() as d:
        _write_asset(d, '{"saas": [{"auth": "sso"}]}')
        with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
            with patch(
                "builtins.open", side_effect=PermissionError("permission denied")
            ):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    stats = _load_saas_sso_stats()
    msgs = [str(w.message) for w in caught]
    assert stats is None
    assert len(msgs) == 1
    assert "PermissionError" in msgs[0]


# ---------------------------------------------------------------------------
# The caller (dashboard-gen.py calls this UNGUARDED) must still render
# ---------------------------------------------------------------------------


class TestBuildAuthSummaryHtmlSurvivesMalformedAssets(unittest.TestCase):
    MALFORMED = (
        ('[{"auth": "sso"}]', "w"),
        (b'{"saas": [{"auth": "\x80sso"}]}', "wb"),
        ('{"saas": {"okta": 1}}', "w"),
        ('{"saas": ["okta"]}', "w"),
        ('{"saas": [{"auth"', "w"),
    )

    def test_html_renders_na_for_every_malformed_payload(self):
        for payload, mode in self.MALFORMED:
            with self.subTest(payload=repr(payload)[:40]):
                with tempfile.TemporaryDirectory() as d:
                    _write_asset(d, payload, mode)
                    with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore")
                            html = build_auth_summary_html([], [])
                self.assertIn("Authentication &amp; SSO posture", html)
                self.assertIn("N/A", html)
                self.assertIn("Run asset collection", html)


# ---------------------------------------------------------------------------
# unittest.TestCase wrapper for `python3 -m unittest discover`
# ---------------------------------------------------------------------------


class DashboardAuthAssetDegradationTestCase(unittest.TestCase):
    def test_well_formed(self):
        test_well_formed_asset_file_computes_stats_without_warning()

    def test_empty_saas(self):
        test_empty_saas_list_returns_none_without_warning()

    def test_missing_file(self):
        test_missing_file_returns_none_without_warning()

    def test_truncated_json(self):
        test_truncated_json_degrades_with_warning()

    def test_top_level_array(self):
        test_top_level_array_degrades_instead_of_attributeerror()

    def test_non_utf8(self):
        test_non_utf8_byte_degrades_instead_of_unicodedecodeerror()

    def test_saas_not_a_list(self):
        test_saas_present_but_not_a_list_degrades_with_warning()

    def test_saas_list_of_strings(self):
        test_saas_list_of_strings_degrades_with_warning()

    def test_saas_null(self):
        test_saas_key_present_but_null_returns_none_without_warning()

    def test_auth_non_string(self):
        test_non_string_auth_value_is_coerced_not_crashed()

    def test_permission_error(self):
        test_permission_error_on_open_degrades_with_warning()


if __name__ == "__main__":
    unittest.main()
