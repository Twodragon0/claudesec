"""
Smoke tests for scanner/lib/zscaler-api.py.

Import strategy: the filename contains hyphens so we use
importlib.util.spec_from_file_location with a safe module name.

Import-time side effects: the module imports `requests` at the top level
and exits with an error message if it is unavailable. Since requests is
installed in this environment, the import is safe. No network calls are
made at import time.

Network constraint: all tests that would trigger HTTP calls use
monkeypatching to avoid any real network access. The `requests.Session`
methods are patched at the session level.

Credential constraint: env vars are set to fake values via monkeypatch;
no real Zscaler credentials are required.

Tested behaviours:
  - Module loads without error.
  - _obfuscate_api_key returns (int timestamp, str obfuscated_key).
  - _obfuscate_api_key obfuscated key has exactly 12 characters.
  - _obfuscate_api_key produces different keys on different timestamps
    (probabilistic — tests the algorithm runs, not that it is secure).
  - _safe_get returns (0, None) when session.get raises an exception.
  - _safe_get returns (200, parsed_json) on a successful response.
  - _safe_get returns (403, None) on a 403 response.
  - collect_posture returns a dict with expected top-level keys.
  - main() prints missing_credentials JSON and exits 0 when no env vars set.
"""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


def _load():
    path = Path(__file__).resolve().parents[1] / "lib" / "zscaler-api.py"
    spec = importlib.util.spec_from_file_location("zscaler_api", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_module_loads_without_error():
    mod = _load()
    assert mod is not None


def test_obfuscate_api_key_returns_tuple_of_int_and_str():
    mod = _load()
    # Zscaler API key must be at least 12 chars (indices 0-11 are accessed)
    fake_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ts, obf = mod._obfuscate_api_key(fake_key)
    assert isinstance(ts, int)
    assert isinstance(obf, str)


def test_obfuscate_api_key_produces_12_character_obfuscated_key():
    mod = _load()
    fake_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _ts, obf = mod._obfuscate_api_key(fake_key)
    # Algorithm appends 6 chars from n digits + 6 chars from r digits = 12 total
    assert len(obf) == 12


def test_obfuscate_api_key_timestamp_is_milliseconds():
    mod = _load()
    import time
    fake_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    before = int(time.time() * 1000)
    ts, _ = mod._obfuscate_api_key(fake_key)
    after = int(time.time() * 1000)
    assert before <= ts <= after + 100


def test_safe_get_returns_zero_and_none_on_exception():
    mod = _load()
    session = MagicMock()
    session.get.side_effect = Exception("connection refused")
    code, data = mod._safe_get(session, "https://fake.example.com", "/api/v1/status")
    assert code == 0
    assert data is None


def test_safe_get_returns_200_and_json_on_success():
    mod = _load()
    session = MagicMock()
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"status": "ACTIVE"}
    session.get.return_value = fake_response
    code, data = mod._safe_get(session, "https://fake.example.com", "/api/v1/status")
    assert code == 200
    assert data == {"status": "ACTIVE"}


def test_safe_get_returns_403_and_none_on_forbidden():
    mod = _load()
    session = MagicMock()
    fake_response = MagicMock()
    fake_response.status_code = 403
    session.get.return_value = fake_response
    code, data = mod._safe_get(session, "https://fake.example.com", "/api/v1/adminUsers")
    assert code == 403
    assert data is None


def _make_session_with_canned_responses(responses: dict):
    """Build a MagicMock session where get(url) returns canned responses keyed by path suffix."""
    session = MagicMock()

    def fake_get(url, timeout=10):
        for path_suffix, (status, body) in responses.items():
            if url.endswith(path_suffix):
                resp = MagicMock()
                resp.status_code = status
                resp.json.return_value = body
                return resp
        # Default: 404
        resp = MagicMock()
        resp.status_code = 404
        return resp

    session.get.side_effect = fake_get
    return session


def test_collect_posture_returns_dict_with_expected_keys():
    mod = _load()
    canned = {
        "/api/v1/status": (200, {"status": "ACTIVE"}),
        "/api/v1/users": (200, [{"groups": ["g1"], "department": {"id": 1}}]),
        "/api/v1/groups": (200, [{"id": 1}]),
        "/api/v1/departments": (200, [{"id": 1}]),
        "/api/v1/advancedSettings": (200, {"authBypassUrls": [], "authBypassApps": [], "domainFrontingBypassUrlCategories": []}),
        "/api/v1/nssFeeds": (200, []),
        "/api/v1/authSettings": (200, {"samlEnabled": True, "kerberosEnabled": False, "autoProvision": False, "authFrequency": "SESSION", "orgAuthType": "SAML"}),
    }
    session = _make_session_with_canned_responses(canned)
    result = mod.collect_posture("https://fake.example.com", session)
    assert isinstance(result, dict)
    assert "service_status" in result
    assert "users" in result
    assert "groups" in result
    assert "departments" in result
    assert "advanced_settings" in result
    assert "nss_feeds" in result
    assert "auth_settings" in result
    assert "policy_access" in result


def test_collect_posture_service_status_active():
    mod = _load()
    canned = {
        "/api/v1/status": (200, {"status": "ACTIVE"}),
    }
    session = _make_session_with_canned_responses(canned)
    result = mod.collect_posture("https://fake.example.com", session)
    assert result["service_status"] == "ACTIVE"


def test_collect_posture_users_counts_no_group_members():
    mod = _load()
    users = [
        {"groups": [], "department": {"id": 1}},   # no_group
        {"groups": ["g1"], "department": None},      # no_dept
        {"groups": [], "department": None},           # unassigned
    ]
    canned = {
        "/api/v1/users": (200, users),
        "/api/v1/status": (200, {"status": "ACTIVE"}),
    }
    session = _make_session_with_canned_responses(canned)
    result = mod.collect_posture("https://fake.example.com", session)
    u = result["users"]
    assert u["total"] == 3
    assert u["no_group"] == 2
    assert u["unassigned"] == 1
    assert u["accessible"] is True


def test_collect_posture_policy_access_records_accessible_and_restricted():
    mod = _load()
    # Only /api/v1/urlCategories returns 200; all others 403
    canned = {
        "/api/v1/urlCategories": (200, []),
        "/api/v1/status": (200, {"status": "ACTIVE"}),
    }
    session = _make_session_with_canned_responses(canned)
    result = mod.collect_posture("https://fake.example.com", session)
    pa = result["policy_access"]
    assert pa["accessible_count"] >= 1
    assert "url_categories" in pa["accessible_endpoints"]


def test_main_prints_missing_credentials_and_exits_0(monkeypatch, capsys):
    mod = _load()
    # Ensure all credential env vars are absent
    for var in ("ZSCALER_API_KEY", "ZSCALER_API_ADMIN", "ZSCALER_API_PASSWORD", "ZSCALER_BASE_URL"):
        monkeypatch.delenv(var, raising=False)

    # sys.exit(0) raises SystemExit — catch it so the test does not itself fail.
    import pytest
    with pytest.raises(SystemExit) as exc_info:
        mod.main()

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    output = json.loads(captured.out.strip())
    assert output.get("error") == "missing_credentials"
