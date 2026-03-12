import os
import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "token-expiry-gate.py"


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


if __name__ == "__main__":
    unittest.main()
