"""
Regression tests: a Zscaler ZIA endpoint we never read must NOT render as
`accessible: True`.

`_safe_get()` reports any transport failure (DNS, timeout, TLS, reset) as
status code 0. Six consumers in `collect_posture()` used to compute
`{"accessible": code != 403}`, and `0 != 403`, so a network failure produced
`accessible: True` for users, groups, departments, advanced_settings,
nss_feeds and auth_settings. Measured on the pre-fix code with
`session.get` raising `OSError("dns failure")`:

    {"users": {"accessible": true}, "groups": {"accessible": true}, ...}

`scanner/checks/saas/zscaler.sh` reads exactly that flag (`== "True"` ->
evaluate, else `skip`), so the dashboard asserted the API key reached the ZIA
admin surface when nothing had been read. `auth_settings` also dropped
`saml_enabled` / `kerberos_enabled` while still claiming accessible.

The fix makes them fail CLOSED via `_unreachable()`, matching the
`policy_access` audit's existing `code == 200` pattern, while keeping the
three states distinct in `reason`: a 403 is real information (reached the API,
permission denied) and must stay distinguishable from a transport failure.

Network: every `requests.Session` interaction is mocked; nothing leaves the
process. Credentials are placeholders. Domains are RFC 2606 reserved.
"""

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_MOD_PATH = Path(__file__).resolve().parents[1] / "lib" / "zscaler-api.py"
_FAKE_BASE = "https://example.com"  # RFC 2606 reserved domain

# Every posture key whose `accessible` flag used to be `code != 403`.
_FLAG_KEYS = (
    "users",
    "groups",
    "departments",
    "advanced_settings",
    "nss_feeds",
    "auth_settings",
)


def _load():
    """Load scanner/lib/zscaler-api.py (hyphenated name -> importlib).

    The module does a top-level `import requests` and `sys.exit(1)`s if it is
    missing; CI's scanner-unit-tests job does not install requests, so stub it
    first (same approach as test_zscaler_api_gaps.py).
    """
    if "requests" not in sys.modules:
        sys.modules["requests"] = MagicMock()
    spec = importlib.util.spec_from_file_location("zscaler_api_failclosed_mod", _MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _session_returning(code, payload_for):
    """Mock session whose every GET returns `code` and a per-URL payload."""
    session = MagicMock()

    def _get(url, timeout=10):
        resp = MagicMock()
        resp.status_code = code
        resp.json.return_value = payload_for(url)
        return resp

    session.get.side_effect = _get
    return session


def _healthy_payload(url):
    """Well-shaped payload for each endpoint (the 200 happy path)."""
    if url.endswith("/api/v1/status"):
        return {"status": "ACTIVE"}
    if url.endswith("/api/v1/advancedSettings"):
        return {"authBypassUrls": ["a"], "authBypassApps": [], "domainFrontingBypassUrlCategories": []}
    if url.endswith("/api/v1/authSettings"):
        return {"samlEnabled": True, "kerberosEnabled": False, "autoProvision": True}
    return [{"groups": ["g"], "department": "d"}]


def _status_only_payload(url):
    """/status stays well-shaped; everything else is the wrong JSON type.

    Keeping /status a dict isolates the flag behaviour from the separate
    unfixed `service_status` crash documented at the bottom of this file.
    """
    if url.endswith("/api/v1/status"):
        return {"status": "ACTIVE"}
    return "not-the-expected-shape"


# ---------------------------------------------------------------------------
# _unreachable() — the shared fail-closed descriptor
# ---------------------------------------------------------------------------


def test_unreachable_never_reports_accessible():
    mod = _load()
    for code in (0, 401, 403, 404, 429, 500, 502, 200):
        assert mod._unreachable(code)["accessible"] is False


def test_unreachable_reason_keeps_the_states_distinct():
    mod = _load()
    assert mod._unreachable(0)["reason"] == "transport_error"
    assert mod._unreachable(403)["reason"] == "permission_denied"
    assert mod._unreachable(200)["reason"] == "unexpected_payload"
    assert mod._unreachable(500)["reason"] == "http_error"
    assert mod._unreachable(401)["reason"] == "http_error"


def test_unreachable_preserves_the_status_code():
    mod = _load()
    assert mod._unreachable(0)["status_code"] == 0
    assert mod._unreachable(403)["status_code"] == 403


# ---------------------------------------------------------------------------
# collect_posture() — 200 / 403 / other HTTP / transport failure
# ---------------------------------------------------------------------------


def test_http_200_with_expected_shape_is_accessible():
    mod = _load()
    session = _session_returning(200, _healthy_payload)
    result = mod.collect_posture(_FAKE_BASE, session)
    for key in _FLAG_KEYS:
        assert result[key]["accessible"] is True, key
    assert result["auth_settings"]["saml_enabled"] is True
    assert result["auth_settings"]["kerberos_enabled"] is False
    assert result["service_status"] == "ACTIVE"


def test_http_403_is_not_accessible_and_reads_as_permission_denied():
    mod = _load()
    session = _session_returning(403, lambda url: None)
    result = mod.collect_posture(_FAKE_BASE, session)
    for key in _FLAG_KEYS:
        assert result[key]["accessible"] is False, key
        assert result[key]["reason"] == "permission_denied", key
        assert result[key]["status_code"] == 403, key


def test_other_4xx_is_not_accessible():
    mod = _load()
    session = _session_returning(404, lambda url: None)
    result = mod.collect_posture(_FAKE_BASE, session)
    for key in _FLAG_KEYS:
        assert result[key]["accessible"] is False, key
        assert result[key]["reason"] == "http_error", key


def test_5xx_is_not_accessible():
    mod = _load()
    session = _session_returning(500, lambda url: None)
    result = mod.collect_posture(_FAKE_BASE, session)
    for key in _FLAG_KEYS:
        assert result[key]["accessible"] is False, key
        assert result[key]["reason"] == "http_error", key


def test_http_200_with_unexpected_shape_is_not_accessible():
    mod = _load()
    session = _session_returning(200, _status_only_payload)
    result = mod.collect_posture(_FAKE_BASE, session)
    for key in _FLAG_KEYS:
        assert result[key]["accessible"] is False, key
        assert result[key]["reason"] == "unexpected_payload", key


def test_transport_exception_is_not_accessible():
    """THE defect: DNS/timeout/TLS/reset must never render as accessible."""
    mod = _load()
    for exc in (
        OSError("dns failure: name or service not known"),
        TimeoutError("read timed out"),
        ValueError("tls handshake failure"),
    ):
        session = MagicMock()
        session.get.side_effect = exc
        result = mod.collect_posture(_FAKE_BASE, session)
        for key in _FLAG_KEYS:
            assert result[key]["accessible"] is False, (key, exc)
            assert result[key]["reason"] == "transport_error", (key, exc)
            assert result[key]["status_code"] == 0, (key, exc)


def test_transport_failure_never_claims_sso_flags():
    """auth_settings must not ship saml/kerberos defaults it never read."""
    mod = _load()
    session = MagicMock()
    session.get.side_effect = OSError("connection reset by peer")
    auth = mod.collect_posture(_FAKE_BASE, session)["auth_settings"]
    assert auth["accessible"] is False
    assert "saml_enabled" not in auth
    assert "kerberos_enabled" not in auth


def test_transport_failure_and_403_are_distinguishable():
    """A 403 is real information — it must not collapse into transport_error."""
    mod = _load()
    down = MagicMock()
    down.get.side_effect = OSError("dns failure")
    denied = _session_returning(403, lambda url: None)
    down_users = mod.collect_posture(_FAKE_BASE, down)["users"]
    denied_users = mod.collect_posture(_FAKE_BASE, denied)["users"]
    assert down_users["accessible"] is denied_users["accessible"] is False
    assert down_users["reason"] != denied_users["reason"]


def test_policy_access_stays_fail_closed_on_transport_failure():
    """The one already-correct consumer must keep its `code == 200` semantics."""
    mod = _load()
    session = MagicMock()
    session.get.side_effect = OSError("dns failure")
    policy = mod.collect_posture(_FAKE_BASE, session)["policy_access"]
    assert policy["accessible_count"] == 0
    assert policy["accessible_endpoints"] == []
    assert policy["restricted_count"] == 7


# ---------------------------------------------------------------------------
# `service_status` on a non-dict 200 body. This was pinned as a KNOWN GAP by the
# accessible-flag change ("still calls .get() on whatever /api/v1/status
# returned"), with a self-destructing assertion that failed the moment the crash
# was fixed — which is what brought us back here. The pin worked; these are its
# replacements, asserting the fixed behaviour in both directions.
# ---------------------------------------------------------------------------


def _malformed_status_only(body):
    """Only `/api/v1/status` is malformed; every other endpoint stays healthy.

    Scoped per-URL on purpose. The first draft returned the malformed body for
    EVERY endpoint, which made the list case fail — not because `service_status`
    was still broken, but because a list body then reaches the users handler,
    whose `isinstance(data, list)` guard checks the CONTAINER and not its
    elements, so `1.get("groups")` raises. That is a separate defect, pinned
    below; mixing it in here would have made this test report on the wrong bug.
    """

    def _payload(url):
        return body if url.endswith("/api/v1/status") else _healthy_payload(url)

    return _payload


def test_service_status_survives_a_string_200_payload():
    """The exact input the old pin used. It raised AttributeError before."""
    mod = _load()
    session = _session_returning(200, _malformed_status_only("a string"))
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["service_status"] == "UNEXPECTED_PAYLOAD"


def test_service_status_survives_a_list_200_payload():
    mod = _load()
    session = _session_returning(200, _malformed_status_only([1, 2]))
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["service_status"] == "UNEXPECTED_PAYLOAD"


def test_service_status_survives_a_null_200_body():
    """A 200 whose body is JSON `null`. This used to read as "UNKNOWN" via the
    truthiness test; it is genuinely an unexpected payload, and saying so is the
    point of separating the two values."""
    mod = _load()
    session = _session_returning(200, _malformed_status_only(None))
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["service_status"] == "UNEXPECTED_PAYLOAD"


def test_service_status_reports_the_real_status_for_a_dict_payload():
    """Positive control. The assertions above mean nothing unless the normal path
    still reports the API's own value."""
    mod = _load()
    session = _session_returning(200, _healthy_payload)
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["service_status"] == "ACTIVE"


def test_service_status_is_unknown_when_the_dict_carries_no_status():
    mod = _load()
    session = _session_returning(200, _malformed_status_only({}))
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["service_status"] == "UNKNOWN"


def test_known_gap_list_body_still_crashes_the_users_handler():
    """NEW pin, replacing the one this change consumed.

    `isinstance(data, list)` in the users handler checks the container and not
    its elements, so a 200 whose body is `[1, 2]` reaches `u.get("groups")` and
    raises. Same shape as the `{"saas": ["okta"]}` case fixed in the dashboard
    asset loader. Out of scope here — this change is the `service_status` crash —
    and pinned so it cannot rot: the assertion FAILS the moment it is fixed, which
    is exactly how this defect got picked up.
    """
    mod = _load()
    session = _session_returning(200, lambda url: [1, 2])
    try:
        mod.collect_posture(_FAKE_BASE, session)
    except AttributeError as exc:
        assert "get" in str(exc)
    else:
        raise AssertionError(
            "list-element crash in the users handler appears fixed — update this pin"
        )


def test_service_status_is_unknown_on_a_transport_failure():
    """Documented residual: a transport failure and a status-less 200 both report
    UNKNOWN. Pinned so the conflation stays a recorded decision rather than an
    accident — see the comment at the call site."""
    mod = _load()

    class _Boom:
        def get(self, *_a, **_k):
            raise OSError("dns failure")

        def delete(self, *_a, **_k):
            return None

    posture = mod.collect_posture(_FAKE_BASE, _Boom())
    assert posture["service_status"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# unittest.TestCase wrapper for `python3 -m unittest discover`
# ---------------------------------------------------------------------------


class ZscalerApiFailClosedTestCase(unittest.TestCase):
    def test_unreachable_never_accessible(self):
        test_unreachable_never_reports_accessible()

    def test_unreachable_reasons(self):
        test_unreachable_reason_keeps_the_states_distinct()

    def test_unreachable_status_code(self):
        test_unreachable_preserves_the_status_code()

    def test_200_accessible(self):
        test_http_200_with_expected_shape_is_accessible()

    def test_403_not_accessible(self):
        test_http_403_is_not_accessible_and_reads_as_permission_denied()

    def test_404_not_accessible(self):
        test_other_4xx_is_not_accessible()

    def test_500_not_accessible(self):
        test_5xx_is_not_accessible()

    def test_200_bad_shape_not_accessible(self):
        test_http_200_with_unexpected_shape_is_not_accessible()

    def test_transport_not_accessible(self):
        test_transport_exception_is_not_accessible()

    def test_transport_no_sso_flags(self):
        test_transport_failure_never_claims_sso_flags()

    def test_403_vs_transport(self):
        test_transport_failure_and_403_are_distinguishable()

    def test_policy_access_fail_closed(self):
        test_policy_access_stays_fail_closed_on_transport_failure()

    def test_service_status_string_payload(self):
        test_service_status_survives_a_string_200_payload()

    def test_service_status_list_payload(self):
        test_service_status_survives_a_list_200_payload()

    def test_service_status_null_body(self):
        test_service_status_survives_a_null_200_body()

    def test_service_status_dict_payload(self):
        test_service_status_reports_the_real_status_for_a_dict_payload()

    def test_service_status_no_status_key(self):
        test_service_status_is_unknown_when_the_dict_carries_no_status()

    def test_service_status_transport_failure(self):
        test_service_status_is_unknown_on_a_transport_failure()

    def test_users_handler_list_element_gap(self):
        test_known_gap_list_body_still_crashes_the_users_handler()


if __name__ == "__main__":
    unittest.main()
