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


def test_unreachable_detail_renders_each_reason_distinctly():
    """`reason` was WRITE-ONLY: four states recorded, zero consumers.

    `scanner/checks/saas/zscaler.sh` printed one fixed sentence for all four, and
    for users it was "RBA restricted" — correct for exactly one of them and a
    confident misdiagnosis for the other three. `detail` is the readable form the
    shell check now reads, so the four must stay distinguishable HERE too.
    """
    mod = _load()
    details = {code: mod._unreachable(code)["detail"] for code in (0, 403, 200, 500)}
    assert len(set(details.values())) == 4, details
    assert "never reached the API" in details[0]
    assert "RBA restricted" in details[403]
    assert "RBA" not in details[0], (
        "a transport failure must not be blamed on an RBA restriction — that is "
        "the exact misdiagnosis this field exists to end"
    )
    assert "not the expected shape" in details[200]
    assert details[500] == "HTTP 500"


def test_unreachable_detail_carries_the_status_code_for_other_http_errors():
    mod = _load()
    for code in (401, 404, 429, 502):
        assert mod._unreachable(code)["detail"] == f"HTTP {code}"


def test_unreachable_detail_names_an_unmapped_reason_rather_than_hiding_it():
    """Fail LOUD on a reason with no sentence.

    A generic "not accessible" fallback would reproduce the original defect one
    level down: the state would be recorded and still unreadable. Naming it makes
    an unmapped reason a visible bug instead of a silent one.
    """
    mod = _load()
    assert mod._unreachable_detail("some_new_reason", 418) == "not read (some_new_reason)"


def test_unreachable_detail_is_keyed_on_reason_not_recomputed_from_the_code():
    """The two fields must never disagree about the same response.

    Deriving `detail` from the status code a second time is the two-copies shape
    that drifts. `_unreachable_detail` takes the reason `_unreachable` already
    decided, so a change to the code->reason mapping cannot leave the sentence
    describing the old state.
    """
    mod = _load()
    # A code that maps to `permission_denied` cannot be made to render as a
    # transport failure, and vice versa, because the reason is the only input
    # that selects the sentence.
    assert mod._unreachable_detail("transport_error", 403) == mod._unreachable(0)["detail"]
    assert mod._unreachable_detail("permission_denied", 0) == mod._unreachable(403)["detail"]


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


def test_users_list_with_non_dict_elements_is_unexpected_payload():
    """The pin that stood here asserted this still crashed, and failed the moment
    it was fixed — the second time in this file that a self-destructing pin has
    routed the next change to the right place. `[1, 2]` used to raise
    `AttributeError: 'int' object has no attribute 'get'` out of the users
    handler, because `isinstance(data, list)` checked the container and not its
    elements.
    """
    mod = _load()
    for body in ([1, 2], ["okta"], [None], [{"groups": []}, "mixed"]):
        session = _session_returning(200, lambda url, b=body: b)
        posture = mod.collect_posture(_FAKE_BASE, session)
        assert posture["users"]["accessible"] is False, body
        assert posture["users"]["reason"] == "unexpected_payload", body


def test_users_list_of_dicts_still_counts():
    """Positive control. The assertion above means nothing unless a well-formed
    list is still counted — routing everything to `unexpected_payload` would
    satisfy it and destroy the feature."""
    mod = _load()
    session = _session_returning(200, _healthy_payload)
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["users"]["accessible"] is True
    assert posture["users"]["total"] == 1


def test_users_empty_list_is_a_real_empty_result():
    """`all()` over an empty list is True, which is what we want here: an empty
    user list is a legitimate answer, not a malformed payload."""
    mod = _load()
    session = _session_returning(200, lambda url: [])
    posture = mod.collect_posture(_FAKE_BASE, session)
    assert posture["users"]["accessible"] is True
    assert posture["users"]["total"] == 0


def test_endpoints_that_only_count_are_unaffected():
    """groups/departments/nss_feeds take `len(data)` and never dereference an
    element, so they need no element guard — pinned so a future 'consistency'
    refactor does not add one and change their behaviour by accident."""
    mod = _load()
    session = _session_returning(200, lambda url: [1, 2, 3])
    posture = mod.collect_posture(_FAKE_BASE, session)
    for key in ("groups", "departments", "nss_feeds"):
        assert posture[key]["accessible"] is True, key
        assert posture[key]["total"] == 3, key


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

    def test_unreachable_detail_distinct(self):
        test_unreachable_detail_renders_each_reason_distinctly()

    def test_unreachable_detail_http_codes(self):
        test_unreachable_detail_carries_the_status_code_for_other_http_errors()

    def test_unreachable_detail_unmapped(self):
        test_unreachable_detail_names_an_unmapped_reason_rather_than_hiding_it()

    def test_unreachable_detail_keyed_on_reason(self):
        test_unreachable_detail_is_keyed_on_reason_not_recomputed_from_the_code()

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

    def test_users_non_dict_elements(self):
        test_users_list_with_non_dict_elements_is_unexpected_payload()

    def test_users_list_of_dicts(self):
        test_users_list_of_dicts_still_counts()

    def test_users_empty_list(self):
        test_users_empty_list_is_a_real_empty_result()

    def test_count_only_endpoints_unaffected(self):
        test_endpoints_that_only_count_are_unaffected()


if __name__ == "__main__":
    unittest.main()
