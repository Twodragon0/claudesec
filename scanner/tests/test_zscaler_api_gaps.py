"""
Coverage-gap tests for scanner/lib/zscaler-api.py.

Targets the lines not reached by test_zscaler_api_smoke.py:
  - _auth()             (lines 47-54)
  - main() body         (lines 176-199)

CI-compat notes:
  - No `import pytest` (CI uses `python3 -m xmlrunner discover`).
  - Plain `unittest.TestCase` subclass + `def test_*()` functions.
  - Stdlib + unittest.mock only.
  - No internal / RFC1918 addresses — RFC 5737 example domains only.
  - zscaler-api.py has a hyphen in its filename, so we load it via
    importlib.util.spec_from_file_location (see test_diagram_gen_pure_helpers.py).

Network: every session / requests.Session interaction is mocked. No real
HTTP calls are made.  Credentials are placeholder strings only.
"""

import importlib.util
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch


_MOD_PATH = Path(__file__).resolve().parents[1] / "lib" / "zscaler-api.py"
_FAKE_BASE = "https://example.com"  # RFC 2606 reserved domain


def _load():
    """Load scanner/lib/zscaler-api.py under the name 'zscaler_api_gaps_mod'."""
    spec = importlib.util.spec_from_file_location(
        "zscaler_api_gaps_mod", _MOD_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# _auth()
# ---------------------------------------------------------------------------

def test_auth_returns_true_on_status_200():
    mod = _load()
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    session.post.return_value = resp

    ok = mod._auth(session, _FAKE_BASE, "ABCDEFGHIJKLMNOP", "admin", "pw")

    assert ok is True
    # Confirm the auth endpoint was hit exactly once with a JSON body that
    # contains the obfuscated apiKey and timestamp fields (no raw password leak
    # check beyond shape — this is not a security assertion).
    session.post.assert_called_once()
    args, kwargs = session.post.call_args
    assert args[0].endswith("/api/v1/authenticatedSession")
    body = kwargs.get("json", {})
    assert "apiKey" in body and "timestamp" in body
    assert body["username"] == "admin"
    assert body["password"] == "pw"
    assert kwargs.get("timeout") == 15


def test_auth_returns_false_on_non_200():
    mod = _load()
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 401
    session.post.return_value = resp

    ok = mod._auth(session, _FAKE_BASE, "ABCDEFGHIJKLMNOP", "admin", "pw")
    assert ok is False


def test_auth_returns_false_on_500():
    mod = _load()
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 500
    session.post.return_value = resp

    ok = mod._auth(session, _FAKE_BASE, "ABCDEFGHIJKLMNOP", "admin", "pw")
    assert ok is False


def test_auth_obfuscates_api_key_before_posting():
    """The raw api_key must not appear in the outgoing JSON body."""
    mod = _load()
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    session.post.return_value = resp

    raw_key = "ABCDEFGHIJKLMNOP"
    mod._auth(session, _FAKE_BASE, raw_key, "admin", "pw")

    body = session.post.call_args.kwargs["json"]
    # Obfuscated key is 12 chars built from the raw alphabet — full raw key
    # must not be substring-present.
    assert raw_key not in body["apiKey"]
    assert len(body["apiKey"]) == 12


# ---------------------------------------------------------------------------
# main() — credential branches + full happy path
# ---------------------------------------------------------------------------

def _clear_env(monkeypatch_like):
    for var in (
        "ZSCALER_API_KEY",
        "ZSCALER_API_ADMIN",
        "ZSCALER_API_PASSWORD",
        "ZSCALER_BASE_URL",
    ):
        monkeypatch_like.pop(var, None)


class _EnvGuard:
    """Tiny stdlib-only replacement for pytest's monkeypatch.delenv/setenv."""
    def __init__(self, updates):
        self._updates = updates
        self._saved = {}

    def __enter__(self):
        for k, v in self._updates.items():
            self._saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, prev in self._saved.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def test_main_exits_on_missing_api_key():
    mod = _load()
    env = {
        "ZSCALER_API_KEY": None,
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": _FAKE_BASE,
    }
    with _EnvGuard(env):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                mod.main()
            except SystemExit as e:
                assert e.code == 0
        payload = json.loads(buf.getvalue().strip())
        assert payload == {"error": "missing_credentials"}


def test_main_exits_on_missing_base_url():
    mod = _load()
    env = {
        "ZSCALER_API_KEY": "ABCDEFGHIJKLMNOP",
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": None,
    }
    with _EnvGuard(env):
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                mod.main()
            except SystemExit as e:
                assert e.code == 0
        payload = json.loads(buf.getvalue().strip())
        assert payload == {"error": "missing_credentials"}


def test_main_prints_auth_failed_when_auth_returns_false():
    mod = _load()
    env = {
        "ZSCALER_API_KEY": "ABCDEFGHIJKLMNOP",
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": _FAKE_BASE,
    }
    with _EnvGuard(env):
        fake_session = MagicMock()
        # Force _auth -> False by making the post return non-200.
        fake_post_resp = MagicMock()
        fake_post_resp.status_code = 401
        fake_session.post.return_value = fake_post_resp

        with patch.object(mod, "requests") as rq_mod:
            rq_mod.Session.return_value = fake_session
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    mod.main()
                except SystemExit as e:
                    assert e.code == 0
        payload = json.loads(buf.getvalue().strip())
        assert payload == {"error": "auth_failed"}


def test_main_happy_path_emits_authenticated_true_and_logs_out():
    mod = _load()
    env = {
        "ZSCALER_API_KEY": "ABCDEFGHIJKLMNOP",
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": _FAKE_BASE,
    }
    with _EnvGuard(env):
        fake_session = MagicMock()
        # _auth -> 200
        post_resp = MagicMock()
        post_resp.status_code = 200
        fake_session.post.return_value = post_resp
        # All GETs -> 200 minimal dicts/lists so collect_posture runs cleanly.
        def fake_get(url, timeout=10):
            r = MagicMock()
            r.status_code = 200
            if url.endswith("/api/v1/status"):
                r.json.return_value = {"status": "ACTIVE"}
            elif url.endswith("/api/v1/users"):
                r.json.return_value = []
            elif url.endswith("/api/v1/groups"):
                r.json.return_value = []
            elif url.endswith("/api/v1/departments"):
                r.json.return_value = []
            elif url.endswith("/api/v1/advancedSettings"):
                r.json.return_value = {}
            elif url.endswith("/api/v1/nssFeeds"):
                r.json.return_value = []
            elif url.endswith("/api/v1/authSettings"):
                r.json.return_value = {}
            else:
                r.json.return_value = []
            return r
        fake_session.get.side_effect = fake_get
        # delete (logout) returns a harmless mock
        fake_session.delete.return_value = MagicMock(status_code=204)

        with patch.object(mod, "requests") as rq_mod:
            rq_mod.Session.return_value = fake_session
            buf = io.StringIO()
            with redirect_stdout(buf):
                mod.main()

        payload = json.loads(buf.getvalue().strip())
        assert payload.get("authenticated") is True
        assert payload.get("service_status") == "ACTIVE"
        # Logout must be attempted exactly once.
        fake_session.delete.assert_called_once()
        logout_url = fake_session.delete.call_args.args[0]
        assert logout_url.endswith("/api/v1/authenticatedSession")


def test_main_logout_exception_is_swallowed():
    """If session.delete raises, main() must not propagate the exception."""
    mod = _load()
    env = {
        "ZSCALER_API_KEY": "ABCDEFGHIJKLMNOP",
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": _FAKE_BASE,
    }
    with _EnvGuard(env):
        fake_session = MagicMock()
        post_resp = MagicMock()
        post_resp.status_code = 200
        fake_session.post.return_value = post_resp
        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.json.return_value = {}
        fake_session.get.return_value = get_resp
        fake_session.delete.side_effect = RuntimeError("logout boom")

        with patch.object(mod, "requests") as rq_mod:
            rq_mod.Session.return_value = fake_session
            buf = io.StringIO()
            with redirect_stdout(buf):
                # Should NOT raise — the except block silences logout errors.
                mod.main()
        payload = json.loads(buf.getvalue().strip())
        assert payload.get("authenticated") is True


def test_main_collect_posture_exception_still_attempts_logout():
    """
    If collect_posture raises, the finally-block must still call session.delete.
    This exercises the `finally:` branch on line ~194.
    """
    mod = _load()
    env = {
        "ZSCALER_API_KEY": "ABCDEFGHIJKLMNOP",
        "ZSCALER_API_ADMIN": "admin",
        "ZSCALER_API_PASSWORD": "pw",
        "ZSCALER_BASE_URL": _FAKE_BASE,
    }
    with _EnvGuard(env):
        fake_session = MagicMock()
        post_resp = MagicMock()
        post_resp.status_code = 200
        fake_session.post.return_value = post_resp
        fake_session.delete.return_value = MagicMock(status_code=204)

        with patch.object(mod, "requests") as rq_mod, \
             patch.object(mod, "collect_posture",
                          side_effect=RuntimeError("boom")):
            rq_mod.Session.return_value = fake_session
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    mod.main()
                except RuntimeError:
                    pass  # expected — the try/finally only guards logout.
        fake_session.delete.assert_called_once()


# ---------------------------------------------------------------------------
# unittest.TestCase wrapper so `python3 -m unittest` discovers these as tests
# when the xmlrunner path is used in CI.
# ---------------------------------------------------------------------------

class ZscalerApiGapsTestCase(unittest.TestCase):
    def test_auth_true_on_200(self):
        test_auth_returns_true_on_status_200()

    def test_auth_false_on_401(self):
        test_auth_returns_false_on_non_200()

    def test_auth_false_on_500(self):
        test_auth_returns_false_on_500()

    def test_auth_obfuscation(self):
        test_auth_obfuscates_api_key_before_posting()

    def test_main_missing_key(self):
        test_main_exits_on_missing_api_key()

    def test_main_missing_base(self):
        test_main_exits_on_missing_base_url()

    def test_main_auth_failed(self):
        test_main_prints_auth_failed_when_auth_returns_false()

    def test_main_happy(self):
        test_main_happy_path_emits_authenticated_true_and_logs_out()

    def test_main_logout_swallowed(self):
        test_main_logout_exception_is_swallowed()

    def test_main_collect_raises(self):
        test_main_collect_posture_exception_still_attempts_logout()


if __name__ == "__main__":
    unittest.main()
