import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "token-expiry-gate.py"

FROZEN_NOW = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

# Timestamps are hand-written literals relative to FROZEN_NOW so the expected
# classification never depends on the arithmetic under test.
WINDOW_BOUNDARIES = {
    "24h": {
        "error_window": "24h",
        "at_window": "2030-01-02T00:00:00Z",
        "below_by_one_second": "2030-01-01T23:59:59Z",
        "below_by_half_second": "2030-01-01T23:59:59.500000Z",
        "above_by_one_microsecond": "2030-01-02T00:00:00.000001Z",
        "above_by_half_second": "2030-01-02T00:00:00.500000Z",
        "above_by_one_second": "2030-01-02T00:00:01Z",
    },
    "7d": {
        "error_window": "168h",
        "at_window": "2030-01-08T00:00:00Z",
        "below_by_one_second": "2030-01-07T23:59:59Z",
        "below_by_half_second": "2030-01-07T23:59:59.500000Z",
        "above_by_one_microsecond": "2030-01-08T00:00:00.000001Z",
        "above_by_half_second": "2030-01-08T00:00:00.500000Z",
        "above_by_one_second": "2030-01-08T00:00:01Z",
    },
}


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN_NOW.astimezone(tz)


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("token_expiry_gate", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "dont_write_bytecode", True):
        spec.loader.exec_module(module)
    return module


class TokenExpiryGateTests(unittest.TestCase):
    def _run_gate(self, args, extra_env=None):
        env = os.environ.copy()
        for key in (
            "GH_TOKEN_EXPIRES_AT",
            "GITHUB_TOKEN_EXPIRES_AT",
            "OKTA_OAUTH_TOKEN_EXPIRES_AT",
            "DATADOG_TOKEN_EXPIRES_AT",
            "DD_TOKEN_EXPIRES_AT",
            "DD_API_KEY_EXPIRES_AT",
            "SLACK_TOKEN_EXPIRES_AT",
            "SLACK_BOT_TOKEN_EXPIRES_AT",
            "CLAUDESEC_TOKEN_EXPIRY_PROVIDERS",
            "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE",
            "CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS",
        ):
            env.pop(key, None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_strict_off_allows_missing_metadata(self):
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h"},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("expiry metadata not set", res.stdout)

    def test_strict_on_fails_missing_metadata(self):
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "true"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h"},
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("expiry metadata is required but missing", res.stdout)

    def test_unknown_provider_is_ignored(self):
        res = self._run_gate(
            ["--providers", "github,unknown-provider", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": "2099-01-01T00:00:00Z",
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Unknown providers ignored", res.stdout)
        self.assertIn("Token expiry gate passed", res.stdout)

    def test_invalid_timestamp_warns_and_skips_when_not_strict(self):
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": "invalid-date-value",
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("format invalid", res.stdout)

    def test_invalid_timestamp_fails_when_strict(self):
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": "invalid-date-value",
            },
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("format is invalid", res.stdout)

    def test_datadog_strict_fails_missing_metadata(self):
        res = self._run_gate(
            ["--providers", "datadog", "--strict-providers", "true"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h"},
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Datadog expiry metadata is required but missing", res.stdout)

    def test_datadog_strict_fails_invalid_timestamp(self):
        res = self._run_gate(
            ["--providers", "datadog", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "DATADOG_TOKEN_EXPIRES_AT": "invalid-date-value",
            },
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Datadog expiry metadata format is invalid", res.stdout)

    def test_datadog_strict_passes_valid_timestamp(self):
        res = self._run_gate(
            ["--providers", "datadog", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "DATADOG_TOKEN_EXPIRES_AT": "2099-01-01T00:00:00Z",
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)

    def test_slack_strict_fails_missing_metadata(self):
        res = self._run_gate(
            ["--providers", "slack", "--strict-providers", "true"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h"},
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Slack expiry metadata is required but missing", res.stdout)

    def test_slack_strict_fails_invalid_timestamp(self):
        res = self._run_gate(
            ["--providers", "slack", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "SLACK_TOKEN_EXPIRES_AT": "invalid-date-value",
            },
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Slack expiry metadata format is invalid", res.stdout)

    def test_slack_strict_passes_valid_timestamp(self):
        res = self._run_gate(
            ["--providers", "slack", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "SLACK_TOKEN_EXPIRES_AT": "2099-01-01T00:00:00Z",
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)


class TokenExpiryGateModeTests(unittest.TestCase):
    """New cases covering previously untested branches."""

    def _run_gate(self, args, extra_env=None):
        env = os.environ.copy()
        for key in (
            "GH_TOKEN_EXPIRES_AT",
            "GITHUB_TOKEN_EXPIRES_AT",
            "OKTA_OAUTH_TOKEN_EXPIRES_AT",
            "DATADOG_TOKEN_EXPIRES_AT",
            "DD_TOKEN_EXPIRES_AT",
            "DD_API_KEY_EXPIRES_AT",
            "SLACK_TOKEN_EXPIRES_AT",
            "SLACK_BOT_TOKEN_EXPIRES_AT",
            "CLAUDESEC_TOKEN_EXPIRY_PROVIDERS",
            "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE",
            "CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS",
        ):
            env.pop(key, None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def _iso(self, dt: datetime) -> str:
        """Format a timezone-aware datetime as ISO 8601 with Z suffix."""
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── (a) MODE=off short-circuits to pass ──────────────────────────────────

    def test_mode_off_exits_zero_without_checking_tokens(self):
        """MODE=off must exit 0 and print 'disabled' even when no token env is set."""
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "true"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "off"},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("disabled", res.stdout)

    def test_mode_none_alias_also_exits_zero(self):
        """'none' is an accepted alias for MODE=off."""
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "true"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "none"},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("disabled", res.stdout)

    def test_mode_false_alias_exits_zero(self):
        """'false' is an accepted alias for MODE=off."""
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "false"},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("disabled", res.stdout)

    # ── (b) MODE=7d window behavior ──────────────────────────────────────────

    def test_mode_7d_fails_token_expiring_within_7_days(self):
        """In 7d mode a token expiring in 100 hours (< 168h) must fail."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=100)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "7d",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("expires within gate window (168h)", res.stdout)

    def test_mode_7d_passes_token_expiring_beyond_7_days(self):
        """In 7d mode a token expiring in 200 hours (> 168h) must pass."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=200)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "7d",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)
        self.assertIn("window=168h", res.stdout)

    def test_mode_24h_passes_token_expiring_in_100h_but_7d_would_fail(self):
        """In default 24h mode a token expiring in 100h must pass (only 7d mode would fail it)."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=100)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)
        self.assertIn("window=24h", res.stdout)

    # ── (c) Valid token expiring far in the future passes ────────────────────

    def test_token_expiring_far_in_future_passes_in_24h_mode(self):
        """A token expiring 30 days from now must pass in 24h mode (non-strict)."""
        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)

    def test_token_expiring_far_in_future_passes_strict_mode(self):
        """A token expiring 30 days from now must pass even in strict mode."""
        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "true"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)

    # ── (d) Missing metadata warns but does not fail when not strict ─────────

    def test_missing_metadata_non_strict_warns_and_passes(self):
        """Missing expiry metadata with strict=false must exit 0 and print a warning."""
        res = self._run_gate(
            ["--providers", "okta", "--strict-providers", "false"],
            {"CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "7d"},
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("expiry metadata not set", res.stdout)
        self.assertIn("Token expiry gate passed", res.stdout)

    def test_token_expiring_just_outside_24h_window_passes(self):
        """Token expiring in 25 hours must pass the 24h gate (just outside the window)."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=25)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Token expiry gate passed", res.stdout)

    def test_token_expiring_just_inside_24h_window_fails(self):
        """Token expiring in 23 hours must fail the 24h gate (inside the window)."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=23)
        res = self._run_gate(
            ["--providers", "github", "--strict-providers", "false"],
            {
                "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": "24h",
                "GH_TOKEN_EXPIRES_AT": self._iso(expiry),
            },
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("expires within gate window (24h)", res.stdout)


class TokenExpiryBoundaryTests(unittest.TestCase):
    """Classify expiries in-process against a frozen clock, in both gate modes."""

    @classmethod
    def setUpClass(cls):
        cls.gate = _load_gate_module()

    def _run_main(self, mode, expires_at):
        env = {
            "CLAUDESEC_TOKEN_EXPIRY_GATE_MODE": mode,
            "GH_TOKEN_EXPIRES_AT": expires_at,
        }
        argv = ["token-expiry-gate.py", "--providers", "github", "--strict-providers", "true"]
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", argv):
                with mock.patch.object(self.gate, "datetime", _FrozenDatetime):
                    with contextlib.redirect_stdout(stdout):
                        code = self.gate.main()
        return code, stdout.getvalue()

    def _assert_within_window(self, mode, expires_at):
        window = WINDOW_BOUNDARIES[mode]["error_window"]
        code, out = self._run_main(mode, expires_at)
        self.assertEqual(code, 1, out)
        self.assertEqual(
            out, f"::error::GitHub token expires within gate window ({window})\n"
        )

    def _assert_expired(self, mode, expires_at):
        code, out = self._run_main(mode, expires_at)
        self.assertEqual(code, 1, out)
        self.assertEqual(out, "::error::GitHub token expired\n")

    def _assert_passed(self, mode, expires_at):
        code, out = self._run_main(mode, expires_at)
        self.assertEqual(code, 0, out)
        self.assertIn("Token expiry gate passed", out)
        self.assertNotIn("::error::", out)

    def test_exactly_at_window_fails_within_window(self):
        for mode, bounds in WINDOW_BOUNDARIES.items():
            with self.subTest(mode=mode):
                self._assert_within_window(mode, bounds["at_window"])

    def test_below_window_fails_within_window(self):
        for mode, bounds in WINDOW_BOUNDARIES.items():
            for case in ("below_by_one_second", "below_by_half_second"):
                with self.subTest(mode=mode, case=case):
                    self._assert_within_window(mode, bounds[case])

    def test_above_window_by_one_second_passes(self):
        for mode, bounds in WINDOW_BOUNDARIES.items():
            with self.subTest(mode=mode):
                self._assert_passed(mode, bounds["above_by_one_second"])

    def test_above_window_by_subsecond_passes(self):
        for mode, bounds in WINDOW_BOUNDARIES.items():
            for case in ("above_by_one_microsecond", "above_by_half_second"):
                with self.subTest(mode=mode, case=case):
                    self._assert_passed(mode, bounds[case])

    def test_past_expiry_fails_as_expired(self):
        for mode in WINDOW_BOUNDARIES:
            for expires_at in ("2029-12-31T23:59:59Z", "2029-12-31T23:59:59.500000Z"):
                with self.subTest(mode=mode, expires_at=expires_at):
                    self._assert_expired(mode, expires_at)

    def test_expiry_exactly_now_fails_as_expired(self):
        for mode in WINDOW_BOUNDARIES:
            with self.subTest(mode=mode):
                self._assert_expired(mode, "2030-01-01T00:00:00Z")

    def test_future_subsecond_fails_within_window_not_expired(self):
        for mode in WINDOW_BOUNDARIES:
            for expires_at in ("2030-01-01T00:00:00.000001Z", "2030-01-01T00:00:00.500000Z"):
                with self.subTest(mode=mode, expires_at=expires_at):
                    self._assert_within_window(mode, expires_at)


if __name__ == "__main__":
    unittest.main()
