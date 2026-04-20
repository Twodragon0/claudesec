"""
Gap-closing unit tests for scanner/lib/dashboard_auth.py.

Targets the 25 lines currently uncovered by ``test_dashboard_auth_unit.py``:
  * 18-19 — ``_parse_expiry_datetime`` raw.isdigit exception path
  * 49-50 — ``_jwt_expiry_datetime`` int(exp) exception path
  * 54-77 — ``_collect_token_expiry_items`` (env + jwt + skip branches)
  * 97-101 — ``_duration_label`` day/hour/minute branches
  * 106-130 — ``_load_saas_sso_stats`` (none / empty / valid / json-error)
  * 135-189 — ``build_auth_summary_html`` (with and without stats, with auth findings)

Style matches ``test_dashboard_data_loader_pure.py``:
  * stdlib + unittest.mock only (no pytest imports)
  * plain ``def test_*`` and ``unittest.TestCase`` classes with ``assert*``
  * ``sys.path.insert`` so ``import dashboard_auth`` works under both runners
  * no internal IPs or secrets
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_auth  # noqa: E402
from dashboard_auth import (  # noqa: E402
    _collect_token_expiry_items,
    _duration_label,
    _jwt_expiry_datetime,
    _load_saas_sso_stats,
    _parse_expiry_datetime,
    build_auth_summary_html,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_jwt(payload):
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode())
        .rstrip(b"=")
        .decode()
    )
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.sig"


TOKEN_ENV_VARS = (
    "OKTA_OAUTH_TOKEN_EXPIRES_AT",
    "OKTA_OAUTH_TOKEN",
    "GITHUB_TOKEN_EXPIRES_AT",
    "GH_TOKEN_EXPIRES_AT",
)


def _clear_token_env():
    for var in TOKEN_ENV_VARS:
        os.environ.pop(var, None)


# ===========================================================================
# _parse_expiry_datetime — exception branch (lines 18-19)
# ===========================================================================


def test_parse_expiry_datetime_huge_epoch_overflow_falls_through_to_iso_path():
    """Epoch digits that overflow time_t raise inside the try; except runs and
    ISO parsing is attempted (which also fails → returns None)."""
    huge = "9" * 30
    assert _parse_expiry_datetime(huge) is None


def test_parse_expiry_datetime_extremely_large_digit_string_returns_none():
    """Secondary case exercising the lines 18-19 except → pass → ISO-parse path."""
    # 100 nines — fromtimestamp will always raise OverflowError.
    assert _parse_expiry_datetime("1" + "0" * 50) is None


# ===========================================================================
# _jwt_expiry_datetime — exp int() exception branch (lines 49-50)
# ===========================================================================


def test_jwt_expiry_non_numeric_exp_string_returns_none():
    """JWT with a non-numeric string exp triggers the int() ValueError path."""
    token = _make_jwt({"exp": "not-a-number"})
    assert _jwt_expiry_datetime(token) is None


def test_jwt_expiry_dict_exp_returns_none():
    """JWT with a dict exp triggers TypeError in int() and returns None."""
    token = _make_jwt({"exp": {"nested": 1}})
    assert _jwt_expiry_datetime(token) is None


# ===========================================================================
# _collect_token_expiry_items — lines 54-77
# ===========================================================================


class TestCollectTokenExpiryItems(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in TOKEN_ENV_VARS}
        _clear_token_env()

    def tearDown(self):
        _clear_token_env()
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_no_env_vars_returns_empty_list(self):
        self.assertEqual(_collect_token_expiry_items(), [])

    def test_okta_env_expiry_parsed_with_env_source(self):
        os.environ["OKTA_OAUTH_TOKEN_EXPIRES_AT"] = "2026-04-17T00:00:00Z"
        items = _collect_token_expiry_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["provider"], "Okta OAuth")
        self.assertEqual(items[0]["source"], "env")

    def test_okta_env_empty_but_jwt_token_uses_jwt_source(self):
        os.environ["OKTA_OAUTH_TOKEN_EXPIRES_AT"] = ""
        os.environ["OKTA_OAUTH_TOKEN"] = _make_jwt({"exp": 1745000000})
        items = _collect_token_expiry_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["provider"], "Okta OAuth")
        self.assertEqual(items[0]["source"], "jwt")

    def test_okta_env_empty_and_token_unparseable_skipped(self):
        os.environ["OKTA_OAUTH_TOKEN_EXPIRES_AT"] = ""
        os.environ["OKTA_OAUTH_TOKEN"] = "not.a.jwt.token"
        self.assertEqual(_collect_token_expiry_items(), [])

    def test_github_env_via_gh_fallback(self):
        os.environ["GH_TOKEN_EXPIRES_AT"] = "1745000000"
        items = _collect_token_expiry_items()
        providers = [i["provider"] for i in items]
        self.assertIn("GitHub", providers)

    def test_github_primary_var_preferred_over_gh_fallback(self):
        os.environ["GITHUB_TOKEN_EXPIRES_AT"] = "2026-04-17T00:00:00Z"
        os.environ["GH_TOKEN_EXPIRES_AT"] = "bogus"
        items = _collect_token_expiry_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["provider"], "GitHub")

    def test_both_providers_populated(self):
        os.environ["OKTA_OAUTH_TOKEN_EXPIRES_AT"] = "2026-04-17T00:00:00Z"
        os.environ["GITHUB_TOKEN_EXPIRES_AT"] = "2026-05-01T00:00:00Z"
        items = _collect_token_expiry_items()
        self.assertEqual(len(items), 2)


# ===========================================================================
# _duration_label — lines 97-101
# ===========================================================================


def test_duration_label_exact_days():
    assert _duration_label(86400) == "1d"
    assert _duration_label(3 * 86400) == "3d"


def test_duration_label_exact_hours_when_not_day_multiple():
    assert _duration_label(3600) == "1h"
    assert _duration_label(5 * 3600) == "5h"


def test_duration_label_minutes_when_not_hour_multiple():
    assert _duration_label(60) == "1m"
    assert _duration_label(90 * 60) == "90m"


def test_duration_label_day_takes_priority_over_hour():
    # 172800s is 2d AND 48h — should report days.
    assert _duration_label(172800) == "2d"


# ===========================================================================
# _load_saas_sso_stats — lines 106-130
# ===========================================================================


class TestLoadSaasSsoStats(unittest.TestCase):
    def _write(self, d, obj):
        os.makedirs(os.path.join(d, ".claudesec-assets"), exist_ok=True)
        path = os.path.join(d, ".claudesec-assets", "dashboard-data.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        return path

    def test_missing_data_file_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                self.assertIsNone(_load_saas_sso_stats())

    def test_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-assets"))
            with open(
                os.path.join(d, ".claudesec-assets", "dashboard-data.json"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("not json!")
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                self.assertIsNone(_load_saas_sso_stats())

    def test_empty_saas_list_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"saas": []})
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                self.assertIsNone(_load_saas_sso_stats())

    def test_missing_saas_key_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"other": 1})
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                self.assertIsNone(_load_saas_sso_stats())

    def test_valid_saas_computes_sso_stats(self):
        saas = [
            {"name": "A", "auth": "Okta SSO"},
            {"name": "B", "auth": "SAML via Okta"},
            {"name": "C", "auth": "local password"},
            {"name": "D", "auth": ""},
        ]
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"saas": saas})
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                stats = _load_saas_sso_stats()
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["sso_count"], 2)
        self.assertEqual(stats["non_sso"], 2)
        self.assertEqual(stats["pct"], 50)

    def test_auth_none_value_handled_as_empty_string(self):
        # Guard against the ``(s.get("auth", "") or "")`` branch.
        saas = [{"name": "A", "auth": None}, {"name": "B", "auth": "sso"}]
        with tempfile.TemporaryDirectory() as d:
            self._write(d, {"saas": saas})
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                stats = _load_saas_sso_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["sso_count"], 1)

    def test_defaults_to_current_dir_when_scan_dir_unset(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("SCAN_DIR", None)
                    # No asset file exists → expect None via FileNotFoundError.
                    self.assertIsNone(_load_saas_sso_stats())
            finally:
                os.chdir(cwd)


# ===========================================================================
# build_auth_summary_html — lines 135-189
# ===========================================================================


class TestBuildAuthSummaryHtml(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SCAN_DIR", None)

    def test_no_stats_no_findings_shows_na_and_zero(self):
        # Point SCAN_DIR at an empty tempdir so stats is None → N/A labels.
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], [])
        self.assertIn("Authentication &amp; SSO posture", html)
        self.assertIn("N/A", html)
        self.assertIn("Run asset collection", html)
        # No auth findings → sp-info class for the findings pill, not sp-warn.
        self.assertIn('class="stat-pill sp-info"', html)

    def test_none_findings_list_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], None)
        self.assertIn("N/A", html)

    def test_auth_finding_keywords_counted(self):
        findings = [
            {"id": "AUTH-1", "title": "OAuth misconfig", "details": ""},
            {"id": "X", "title": "JWT replay", "details": ""},
            {"id": "Y", "title": "unrelated", "details": "session timeout"},
            {"id": "Z", "title": "network issue", "details": "nothing"},
        ]
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], findings)
        # 3 auth-keyword matches → rendered in the third stat pill as num.
        self.assertIn('class="sp-num">3<', html)
        # Non-zero auth findings → Auth-related findings pill uses sp-warn.
        self.assertIn('stat-pill sp-warn', html)

    def test_findings_with_non_string_fields_coerced_safely(self):
        # str() is applied to each field; ensure this doesn't blow up.
        findings = [{"id": 1, "title": None, "details": 42}]
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], findings)
        self.assertIn("Authentication &amp; SSO posture", html)

    def test_high_sso_coverage_uses_pass_pill(self):
        # Build dashboard-data.json with 4/4 SSO saas (100%).
        saas = [{"name": n, "auth": "okta sso"} for n in "ABCD"]
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-assets"))
            with open(
                os.path.join(d, ".claudesec-assets", "dashboard-data.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump({"saas": saas}, f)
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], [])
        self.assertIn("sp-pass", html)
        self.assertIn("100%", html)
        self.assertIn("MFA enforced", html)

    def test_mid_sso_coverage_uses_warn_pill(self):
        # 3/5 SSO = 60% → warn tier (50 <= pct < 70).
        saas = (
            [{"name": f"s{i}", "auth": "okta sso"} for i in range(3)]
            + [{"name": "p1", "auth": "password"}, {"name": "p2", "auth": "basic"}]
        )
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-assets"))
            with open(
                os.path.join(d, ".claudesec-assets", "dashboard-data.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump({"saas": saas}, f)
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], [])
        self.assertIn('stat-pill sp-warn"', html)
        self.assertIn("60%", html)

    def test_low_sso_coverage_uses_fail_pill(self):
        # 1/5 SSO = 20% → fail tier.
        saas = [{"name": "s1", "auth": "sso"}] + [
            {"name": f"p{i}", "auth": "password"} for i in range(4)
        ]
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claudesec-assets"))
            with open(
                os.path.join(d, ".claudesec-assets", "dashboard-data.json"),
                "w",
                encoding="utf-8",
            ) as f:
                json.dump({"saas": saas}, f)
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], [])
        self.assertIn("sp-fail", html)
        self.assertIn("20%", html)

    def test_best_practice_references_rendered(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SCAN_DIR": d}, clear=False):
                html = build_auth_summary_html([], [])
        self.assertIn("RFC 9700", html)
        self.assertIn("CIS Controls", html)
        self.assertIn("PKCE", html)


# ===========================================================================
# Module-level sanity
# ===========================================================================


def test_module_exports_public_api():
    expected = {
        "_parse_expiry_datetime",
        "_jwt_expiry_datetime",
        "_collect_token_expiry_items",
        "_parse_duration_seconds",
        "_duration_label",
        "_load_saas_sso_stats",
        "build_auth_summary_html",
    }
    assert expected.issubset(set(dashboard_auth.__all__))


if __name__ == "__main__":
    unittest.main()
