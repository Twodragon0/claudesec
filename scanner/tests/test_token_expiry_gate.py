import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from datetime import datetime, timezone
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
