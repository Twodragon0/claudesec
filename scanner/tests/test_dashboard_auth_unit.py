"""
Unit tests for the three pure parsing functions in scanner/lib/dashboard_auth.py.

Each test covers exactly one behaviour.  No network access, no filesystem access,
no environment variable side-effects.  Mocking is unnecessary for these pure functions.

Target: lift dashboard_auth.py coverage from ~39% toward >=70%.
Reference: .omc/research/scanner-lib-coverage-2026-04-17.md
"""

import base64
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from dashboard_auth import (
    _parse_expiry_datetime,
    _jwt_expiry_datetime,
    _parse_duration_seconds,
)


# ---------------------------------------------------------------------------
# Helper — build a syntactically valid JWT without signature verification
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    header = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{body}.signature"


# ===========================================================================
# _parse_expiry_datetime
# ===========================================================================

def test_parse_expiry_datetime_iso8601_utc_z_returns_aware_datetime():
    """ISO-8601 string ending in Z is parsed and returned as UTC-aware datetime."""
    result = _parse_expiry_datetime("2026-04-17T08:30:00Z")
    assert result is not None
    assert result.year == 2026
    assert result.month == 4
    assert result.day == 17
    assert result.tzinfo is not None


def test_parse_expiry_datetime_iso8601_offset_returns_utc_normalised():
    """ISO-8601 string with +09:00 offset is normalised to UTC."""
    result = _parse_expiry_datetime("2026-04-17T08:30:00+09:00")
    assert result is not None
    assert result.tzinfo is not None
    # 08:30 KST == 23:30 UTC previous day
    assert result.utcoffset().total_seconds() == 0


def test_parse_expiry_datetime_iso8601_no_timezone_defaults_to_utc():
    """Naive ISO-8601 string (no tz info) is treated as UTC and returned tz-aware."""
    result = _parse_expiry_datetime("2026-04-17T08:30:00")
    assert result is not None
    assert result.tzinfo is not None
    assert result.tzinfo == timezone.utc


def test_parse_expiry_datetime_datetime_plain_string():
    """'YYYY-MM-DD HH:MM:SS' plain string is parsed correctly."""
    result = _parse_expiry_datetime("2026-04-17 08:30:00")
    assert result is not None
    assert result.year == 2026
    assert result.hour == 8
    assert result.tzinfo is not None


def test_parse_expiry_datetime_date_only_string():
    """'YYYY-MM-DD' date-only string is parsed and returns a tz-aware datetime."""
    result = _parse_expiry_datetime("2026-04-17")
    assert result is not None
    assert result.year == 2026
    assert result.month == 4
    assert result.day == 17
    assert result.tzinfo is not None


def test_parse_expiry_datetime_epoch_int_returns_aware_datetime():
    """Epoch seconds as a Python int returns a UTC-aware datetime."""
    epoch = 1745000000
    result = _parse_expiry_datetime(epoch)
    assert result is not None
    assert result.tzinfo is not None
    assert int(result.timestamp()) == epoch


def test_parse_expiry_datetime_epoch_numeric_string_returns_aware_datetime():
    """Epoch seconds as a numeric string (digits only) returns a UTC-aware datetime."""
    result = _parse_expiry_datetime("1745000000")
    assert result is not None
    assert result.tzinfo is not None
    assert int(result.timestamp()) == 1745000000


def test_parse_expiry_datetime_empty_string_returns_none():
    """Empty string input returns None."""
    assert _parse_expiry_datetime("") is None


def test_parse_expiry_datetime_none_input_returns_none():
    """None input returns None."""
    assert _parse_expiry_datetime(None) is None


def test_parse_expiry_datetime_garbage_string_returns_none():
    """Arbitrary non-date garbage string returns None."""
    assert _parse_expiry_datetime("not-a-date-at-all") is None


def test_parse_expiry_datetime_result_is_always_timezone_aware():
    """All valid parse paths produce a timezone-aware datetime (tzinfo is not None)."""
    for value in ("2026-04-17T00:00:00Z", "2026-04-17", "1745000000"):
        result = _parse_expiry_datetime(value)
        assert result is not None, f"Expected datetime for {value!r}"
        assert result.tzinfo is not None, f"Expected tz-aware for {value!r}"


# ===========================================================================
# _jwt_expiry_datetime
# ===========================================================================

def test_jwt_expiry_valid_exp_returns_matching_datetime():
    """Valid JWT with integer exp claim returns the corresponding UTC datetime."""
    exp_epoch = 1745000000
    token = _make_jwt({"sub": "user", "exp": exp_epoch})
    result = _jwt_expiry_datetime(token)
    assert result is not None
    assert int(result.timestamp()) == exp_epoch


def test_jwt_expiry_valid_exp_result_is_timezone_aware():
    """Returned datetime from a valid JWT is timezone-aware."""
    token = _make_jwt({"exp": 1745000000})
    result = _jwt_expiry_datetime(token)
    assert result is not None
    assert result.tzinfo is not None


def test_jwt_expiry_float_exp_is_handled():
    """JWT with a float exp value is accepted (int() truncates it)."""
    token = _make_jwt({"exp": 1745000000.9})
    result = _jwt_expiry_datetime(token)
    # int(1745000000.9) == 1745000000
    assert result is not None
    assert int(result.timestamp()) == 1745000000


def test_jwt_expiry_missing_exp_returns_none():
    """JWT payload without an 'exp' claim returns None."""
    token = _make_jwt({"sub": "user", "iat": 1700000000})
    assert _jwt_expiry_datetime(token) is None


def test_jwt_expiry_malformed_not_three_parts_returns_none():
    """String that is not dot-separated into at least 2 parts returns None."""
    assert _jwt_expiry_datetime("notajwtatall") is None


def test_jwt_expiry_invalid_base64_payload_returns_none():
    """JWT whose payload segment is not valid base64 returns None."""
    assert _jwt_expiry_datetime("header.!!!invalid-base64!!.sig") is None


def test_jwt_expiry_non_json_payload_returns_none():
    """JWT whose payload decodes to non-JSON text returns None."""
    bad_body = base64.urlsafe_b64encode(b"this is not json").rstrip(b"=").decode()
    token = f"header.{bad_body}.sig"
    assert _jwt_expiry_datetime(token) is None


def test_jwt_expiry_empty_string_returns_none():
    """Empty string input returns None."""
    assert _jwt_expiry_datetime("") is None


def test_jwt_expiry_none_input_returns_none():
    """None input returns None (handled via `token_value or ''`)."""
    assert _jwt_expiry_datetime(None) is None


# ===========================================================================
# _parse_duration_seconds
# NOTE: The function signature is:
#   _parse_duration_seconds(raw_value, default_seconds, default_unit) -> (int, str)
# It returns a (seconds, source) tuple, not a bare int.
# Plain digit strings are scaled by default_unit: "h" -> *3600, else -> *86400.
# ISO-8601 duration strings (e.g. "PT1H30M") are NOT supported; they fall
# through to (default_seconds, "default").
# ===========================================================================

def test_parse_duration_seconds_days_suffix():
    """'90d' returns (90 * 86400, 'env')."""
    seconds, source = _parse_duration_seconds("90d", 86400, "d")
    assert seconds == 90 * 86400
    assert source == "env"


def test_parse_duration_seconds_hours_suffix():
    """'2h' returns (7200, 'env')."""
    seconds, source = _parse_duration_seconds("2h", 3600, "h")
    assert seconds == 7200
    assert source == "env"


def test_parse_duration_seconds_minutes_suffix():
    """'30m' returns (1800, 'env')."""
    seconds, source = _parse_duration_seconds("30m", 3600, "h")
    assert seconds == 1800
    assert source == "env"


def test_parse_duration_seconds_plain_digit_with_hour_default_unit():
    """Plain integer string '1' with default_unit='h' returns (3600, 'env')."""
    seconds, source = _parse_duration_seconds("1", 3600, "h")
    assert seconds == 3600
    assert source == "env"


def test_parse_duration_seconds_plain_digit_with_non_hour_default_unit():
    """Plain integer string '1' with default_unit='d' returns (86400, 'env')."""
    seconds, source = _parse_duration_seconds("1", 86400, "d")
    assert seconds == 86400
    assert source == "env"


def test_parse_duration_seconds_seconds_suffix():
    """'3600s' returns (3600, 'env') using the 's' unit map entry."""
    seconds, source = _parse_duration_seconds("3600s", 86400, "d")
    assert seconds == 3600
    assert source == "env"


def test_parse_duration_seconds_empty_string_returns_default():
    """Empty string returns (default_seconds, 'default')."""
    seconds, source = _parse_duration_seconds("", 86400, "d")
    assert seconds == 86400
    assert source == "default"


def test_parse_duration_seconds_none_input_returns_default():
    """None input returns (default_seconds, 'default')."""
    seconds, source = _parse_duration_seconds(None, 3600, "h")
    assert seconds == 3600
    assert source == "default"


def test_parse_duration_seconds_garbage_string_returns_default():
    """Unrecognised format string returns (default_seconds, 'default')."""
    seconds, source = _parse_duration_seconds("xyz", 86400, "d")
    assert seconds == 86400
    assert source == "default"


def test_parse_duration_seconds_iso8601_duration_not_supported_returns_default():
    """ISO-8601 duration 'PT1H30M' is not supported; falls back to default."""
    seconds, source = _parse_duration_seconds("PT1H30M", 86400, "d")
    assert seconds == 86400
    assert source == "default"


def test_parse_duration_seconds_negative_format_returns_default():
    """'-5h' (non-digit prefix) does not match digit check and returns default."""
    seconds, source = _parse_duration_seconds("-5h", 86400, "d")
    assert seconds == 86400
    assert source == "default"


def test_parse_duration_seconds_zero_digit_returns_default():
    """'0d' (zero value) returns default because int(num) > 0 check fails."""
    seconds, source = _parse_duration_seconds("0d", 86400, "d")
    assert seconds == 86400
    assert source == "default"
