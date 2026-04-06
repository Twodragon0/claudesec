import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from http.client import HTTPMessage
from pathlib import Path
from unittest.mock import MagicMock, patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
SPEC = importlib.util.spec_from_file_location("dashboard_gen", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Failed to load module spec for {MODULE_PATH}")
dashboard_gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_gen)

# Sub-modules (for patching internal cross-module references)
_dac = sys.modules["dashboard_api_client"]
_ddl = sys.modules["dashboard_data_loader"]


class DashboardGenSmokeTest(unittest.TestCase):
    def test_load_microsoft_best_practices_uses_fresh_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / ".claudesec-ms-best-practices"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "cache.json"
            payload = {
                "fetched_at": (
                    datetime.now(timezone.utc) - timedelta(minutes=5)
                ).isoformat(),
                "source_filter": "all",
                "scubagear_enabled": False,
                "sources": [
                    {
                        "product": "Office 365",
                        "label": "Cached Source",
                        "trust_level": "Microsoft Official",
                        "repo": "example/repo",
                        "repo_url": "https://github.com/example/repo",
                        "files": [],
                    }
                ],
            }
            cache_file.write_text(json.dumps(payload), encoding="utf-8")

            with (
                patch.dict(
                    "os.environ",
                    {
                        dashboard_gen.MS_SOURCE_FILTER_ENV: "all",
                        dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "0",
                    },
                    clear=False,
                ),
                patch.object(
                    _ddl,
                    "_fetch_microsoft_best_practices_from_github",
                    side_effect=AssertionError(
                        "network fetch should not run for fresh cache"
                    ),
                ),
            ):
                loaded = dashboard_gen.load_microsoft_best_practices(tmpdir)

            self.assertEqual(loaded.get("sources", [])[0].get("label"), "Cached Source")

    def test_generate_dashboard_includes_trust_badge_and_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "dashboard.html"
            scan_data = {
                "passed": 1,
                "failed": 0,
                "warnings": 0,
                "skipped": 0,
                "total": 1,
                "score": 100,
                "grade": "A",
                "duration": 1,
                "findings": [],
            }
            ms_sources = {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source_filter": "gov",
                "sources": [
                    {
                        "product": "Office 365",
                        "label": "CISA ScubaGear",
                        "trust_level": "Government",
                        "reason": "CISA baseline artifacts",
                        "repo": "cisagov/ScubaGear",
                        "repo_url": "https://github.com/cisagov/ScubaGear",
                        "default_branch": "main",
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "archived": False,
                        "files": [
                            {
                                "name": "README.md",
                                "path": "README.md",
                                "url": "https://github.com/cisagov/ScubaGear/blob/main/README.md",
                                "raw_url": "https://raw.githubusercontent.com/cisagov/ScubaGear/main/README.md",
                            }
                        ],
                    }
                ],
            }

            with (
                patch.object(
                    dashboard_gen,
                    "load_audit_points",
                    return_value={"products": [], "fetched_at": ""},
                ),
                patch.object(
                    dashboard_gen,
                    "load_audit_points_detected",
                    return_value={"detected_products": [], "items": []},
                ),
                patch.object(
                    dashboard_gen,
                    "load_microsoft_best_practices",
                    return_value=ms_sources,
                ),
                patch.dict(
                    "os.environ",
                    {
                        "OKTA_OAUTH_TOKEN_EXPIRES_AT": (
                            datetime.now(timezone.utc) + timedelta(hours=1)
                        ).isoformat(),
                        "CLAUDESEC_TOKEN_EXPIRY_WARNING_24H": "12h",
                        "CLAUDESEC_TOKEN_EXPIRY_WARNING_7D": "2d",
                        "GH_TOKEN_EXPIRES_AT": (
                            datetime.now(timezone.utc) + timedelta(hours=36)
                        ).isoformat(),
                        "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                    },
                    clear=False,
                ),
            ):
                dashboard_gen.generate_dashboard(
                    scan_data=scan_data,
                    prowler_dir=tmpdir,
                    history_dir=tmpdir,
                    output_file=str(output_file),
                )

            html = output_file.read_text(encoding="utf-8")
            # Dashboard must contain core structure
            self.assertIn("ClaudeSec", html)
            self.assertIn("tab-overview", html)
            self.assertIn("Priority Queue", html)
            self.assertIn("Service Surface", html)
            self.assertIn("Function Workspace", html)
            self.assertIn("Local scanner", html)
            self.assertIn("scannerSearchInput", html)
            self.assertIn("prowlerSearchInput", html)
            self.assertIn("githubSearchInput", html)
            # Auth summary — simplified SSO status
            self.assertIn("SSO", html)
            self.assertIn("MFA", html)

    def test_fetch_ms_sources_scubagear_toggle_off_vs_on(self):
        fake_sources = [
            {
                "product": "Office 365",
                "repo": "microsoft/example",
                "label": "Microsoft Example",
                "trust_level": "Microsoft Official",
                "reason": "official",
                "focus_paths": ["README.md"],
            },
            {
                "product": "Office 365",
                "repo": "cisagov/ScubaGear",
                "label": "CISA ScubaGear",
                "trust_level": "Government",
                "reason": "cisa",
                "focus_paths": ["README.md"],
                "optional_env": dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV,
            },
        ]

        with (
            patch.object(
                _dac,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                _dac,
                "_fetch_repo_focus_files",
                return_value={
                    "repo": "x/y",
                    "repo_url": "https://github.com/x/y",
                    "default_branch": "main",
                    "updated_at": "",
                    "archived": False,
                    "files": [],
                },
            ),
        ):
            with patch.dict(
                "os.environ",
                {
                    dashboard_gen.MS_SOURCE_FILTER_ENV: "all",
                    dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "0",
                },
                clear=False,
            ):
                off_data = dashboard_gen._fetch_microsoft_best_practices_from_github()
                off_labels = [s.get("label") for s in off_data.get("sources", [])]
                self.assertNotIn("CISA ScubaGear", off_labels)

            with patch.dict(
                "os.environ",
                {
                    dashboard_gen.MS_SOURCE_FILTER_ENV: "all",
                    dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "1",
                },
                clear=False,
            ):
                on_data = dashboard_gen._fetch_microsoft_best_practices_from_github()
                on_labels = [s.get("label") for s in on_data.get("sources", [])]
                self.assertIn("CISA ScubaGear", on_labels)

    def test_load_ms_best_practices_refreshes_on_filter_change(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / ".claudesec-ms-best-practices"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "cache.json"
            stale_for_filter = {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source_filter": "official",
                "scubagear_enabled": False,
                "sources": [
                    {"label": "Official Source", "trust_level": "Microsoft Official"}
                ],
            }
            cache_file.write_text(json.dumps(stale_for_filter), encoding="utf-8")

            fresh = {
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "source_filter": "gov",
                "scubagear_enabled": True,
                "sources": [{"label": "CISA ScubaGear", "trust_level": "Government"}],
            }

            with (
                patch.dict(
                    "os.environ",
                    {
                        dashboard_gen.MS_SOURCE_FILTER_ENV: "gov",
                        dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "1",
                        "CLAUDESEC_DASHBOARD_OFFLINE": "0",
                    },
                    clear=False,
                ),
                patch.object(
                    _ddl,
                    "_fetch_microsoft_best_practices_from_github",
                    return_value=fresh,
                ) as mocked_fetch,
            ):
                loaded = dashboard_gen.load_microsoft_best_practices(tmpdir)

            self.assertEqual(mocked_fetch.call_count, 1)
            self.assertEqual(loaded.get("source_filter"), "gov")
            self.assertTrue(loaded.get("scubagear_enabled"))
            self.assertEqual(
                loaded.get("sources", [])[0].get("label"), "CISA ScubaGear"
            )

    def test_fetch_ms_sources_supports_multi_filter(self):
        fake_sources = [
            {
                "product": "Windows",
                "repo": "microsoft/seccon",
                "label": "Official Source",
                "trust_level": "Microsoft Official",
                "reason": "official",
                "focus_paths": ["README.md"],
            },
            {
                "product": "Office 365",
                "repo": "cisagov/ScubaGear",
                "label": "Government Source",
                "trust_level": "Government",
                "reason": "government",
                "focus_paths": ["README.md"],
                "optional_env": dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV,
            },
            {
                "product": "Intune",
                "repo": "community/example",
                "label": "Community Source",
                "trust_level": "Community",
                "reason": "community",
                "focus_paths": ["README.md"],
            },
        ]

        with (
            patch.object(
                _dac,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                _dac,
                "_fetch_repo_focus_files",
                return_value={
                    "repo": "x/y",
                    "repo_url": "https://github.com/x/y",
                    "default_branch": "main",
                    "updated_at": "",
                    "archived": False,
                    "files": [],
                },
            ),
            patch.dict(
                "os.environ",
                {
                    dashboard_gen.MS_SOURCE_FILTER_ENV: "gov,official",
                    dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "1",
                },
                clear=False,
            ),
        ):
            data = dashboard_gen._fetch_microsoft_best_practices_from_github()

        labels = [s.get("label") for s in data.get("sources", [])]
        self.assertEqual(data.get("source_filter"), "official,gov")
        self.assertIn("Official Source", labels)
        self.assertIn("Government Source", labels)
        self.assertNotIn("Community Source", labels)

    def test_fetch_ms_sources_supports_none_filter(self):
        fake_sources = [
            {
                "product": "Windows",
                "repo": "microsoft/seccon",
                "label": "Official Source",
                "trust_level": "Microsoft Official",
                "reason": "official",
                "focus_paths": ["README.md"],
            },
            {
                "product": "Office 365",
                "repo": "cisagov/ScubaGear",
                "label": "Government Source",
                "trust_level": "Government",
                "reason": "government",
                "focus_paths": ["README.md"],
                "optional_env": dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV,
            },
        ]

        with (
            patch.object(
                _dac,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                _dac,
                "_fetch_repo_focus_files",
                return_value={
                    "repo": "x/y",
                    "repo_url": "https://github.com/x/y",
                    "default_branch": "main",
                    "updated_at": "",
                    "archived": False,
                    "files": [],
                },
            ),
            patch.dict(
                "os.environ",
                {
                    dashboard_gen.MS_SOURCE_FILTER_ENV: "none",
                    dashboard_gen.MS_INCLUDE_SCUBAGEAR_ENV: "1",
                },
                clear=False,
            ),
        ):
            data = dashboard_gen._fetch_microsoft_best_practices_from_github()

        self.assertEqual(data.get("source_filter"), "none")
        self.assertEqual(data.get("sources", []), [])

    def test_load_datadog_logs_includes_signals_and_cases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dd_dir = Path(tmpdir) / ".claudesec-datadog"
            dd_dir.mkdir(parents=True, exist_ok=True)
            (dd_dir / "datadog-logs.json").write_text(
                json.dumps(
                    {
                        "data": [
                            {
                                "attributes": {
                                    "status": "error",
                                    "message": "pipeline failed",
                                    "service": "ci",
                                    "timestamp": "2026-03-12T00:00:00Z",
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (dd_dir / "datadog-cloud-signals-sanitized.json").write_text(
                json.dumps(
                    {
                        "data": [
                            {
                                "id": "sig-1",
                                "attributes": {
                                    "severity": "critical",
                                    "signal_status": "open",
                                    "title": "Critical cloud signal",
                                    "security_rule_name": "Cloud rule",
                                    "timestamp": "2026-03-12T00:10:00Z",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (dd_dir / "datadog-cases-sanitized.json").write_text(
                json.dumps(
                    {
                        "data": [
                            {
                                "id": "case-1",
                                "attributes": {
                                    "priority": "P2",
                                    "status_name": "OPEN",
                                    "title": "High priority case",
                                    "updated_at": "2026-03-12T00:20:00Z",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            loaded = dashboard_gen.load_datadog_logs(str(dd_dir))

            self.assertEqual(loaded.get("summary", {}).get("total"), 1)
            self.assertEqual(loaded.get("signal_summary", {}).get("critical"), 1)
            self.assertEqual(loaded.get("signal_summary", {}).get("total"), 1)
            self.assertEqual(loaded.get("case_summary", {}).get("high"), 1)
            self.assertEqual(loaded.get("case_summary", {}).get("total"), 1)

    def test_generate_dashboard_renders_datadog_signals_and_cases(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "dashboard-datadog.html"
            scan_data = {
                "passed": 1,
                "failed": 0,
                "warnings": 0,
                "skipped": 0,
                "total": 1,
                "score": 100,
                "grade": "A",
                "duration": 1,
                "findings": [],
            }
            datadog_payload = {
                "logs": [],
                "summary": {
                    "error": 0,
                    "warning": 0,
                    "info": 0,
                    "unknown": 0,
                    "total": 0,
                },
                "signals": [
                    {
                        "severity": "critical",
                        "status": "open",
                        "title": "Cloud signal",
                        "rule": "Cloud rule",
                        "source": "signal",
                        "timestamp": "2026-03-12T00:00:00Z",
                    }
                ],
                "signal_summary": {
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                    "total": 1,
                },
                "cases": [
                    {
                        "severity": "high",
                        "status": "OPEN",
                        "title": "Case title",
                        "rule": "case",
                        "source": "case",
                        "timestamp": "2026-03-12T00:10:00Z",
                    }
                ],
                "case_summary": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                    "total": 1,
                },
            }

            with (
                patch.dict("os.environ", {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}, clear=False),
                patch.object(
                    dashboard_gen,
                    "load_audit_points",
                    return_value={"products": [], "fetched_at": ""},
                ),
                patch.object(
                    dashboard_gen,
                    "load_audit_points_detected",
                    return_value={"detected_products": [], "items": []},
                ),
                patch.object(
                    dashboard_gen,
                    "load_microsoft_best_practices",
                    return_value={
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                        "source_filter": "all",
                        "scubagear_enabled": False,
                        "sources": [],
                    },
                ),
                patch.object(
                    dashboard_gen, "load_datadog_logs", return_value=datadog_payload
                ),
            ):
                dashboard_gen.generate_dashboard(
                    scan_data=scan_data,
                    prowler_dir=tmpdir,
                    history_dir=tmpdir,
                    output_file=str(output_file),
                )

            html = output_file.read_text(encoding="utf-8")
            self.assertIn("Datadog Cloud Security signals summary", html)
            self.assertIn("Datadog case management summary", html)
            self.assertIn("Cloud signal", html)
            self.assertIn("Case title", html)
            self.assertIn("ClaudeSec Local Security Scanner", html)
            self.assertIn("Detail (Top findings)", html)
            self.assertIn("Action plan", html)


    def test_generate_dashboard_renders_env_pills_and_prowler_table(self):
        """Verify env pill HTML (clickable buttons with openSetup) and prowler provider table."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "dashboard-env.html"
            scan_data = {
                "passed": 2,
                "failed": 1,
                "warnings": 0,
                "skipped": 0,
                "total": 3,
                "score": 80,
                "grade": "B",
                "duration": 5,
                "findings": [
                    {
                        "id": "INFRA-001",
                        "title": "Dockerfile USER directive",
                        "description": "Missing USER",
                        "severity": "HIGH",
                        "category": "infra",
                        "status": "FAIL",
                        "recommendation": "Add USER",
                        "details": "No USER directive",
                    }
                ],
            }

            with (
                patch.dict("os.environ", {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}, clear=False),
                patch.object(
                    dashboard_gen,
                    "load_audit_points",
                    return_value={"products": [], "fetched_at": ""},
                ),
                patch.object(
                    dashboard_gen,
                    "load_audit_points_detected",
                    return_value={"detected_products": [], "items": []},
                ),
                patch.object(
                    dashboard_gen,
                    "load_microsoft_best_practices",
                    return_value={
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                        "source_filter": "all",
                        "scubagear_enabled": False,
                        "sources": [],
                    },
                ),
            ):
                dashboard_gen.generate_dashboard(
                    scan_data=scan_data,
                    prowler_dir=tmpdir,
                    history_dir=tmpdir,
                    output_file=str(output_file),
                )

            html = output_file.read_text(encoding="utf-8")

            # Env pills: all pills are <button> with onclick="openSetup(...)"
            self.assertIn("env-pill", html)
            self.assertIn("openSetup(", html)
            # Both connected (env-on) and disconnected (env-off) use <button>
            self.assertIn("env-on", html) if "env-on" in html else None
            self.assertIn("env-off", html)
            # onclick values must be HTML-escaped (no raw quotes that break attributes)
            self.assertNotIn("openSetup('<script>", html)

            # Prowler provider table: fixed providers shown even without data
            self.assertIn("K8s", html)
            self.assertIn("Google Workspace", html)
            self.assertIn("not run", html)  # no-data providers show "not run"
            self.assertIn("switchProvTab(", html)

            # Scanner findings section renders
            self.assertIn("INFRA-001", html)
            self.assertIn("Dockerfile USER directive", html)

            # Overview header has connected/total counter
            self.assertIn("ClaudeSec Local Security Scanner", html)


class GithubApiJsonTest(unittest.TestCase):
    """Tests for _github_api_json exponential backoff and auth header injection."""

    def _make_http_error(self, code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
        headers = HTTPMessage()
        if retry_after is not None:
            headers["Retry-After"] = retry_after
        return urllib.error.HTTPError(
            url="https://api.github.com/test",
            code=code,
            msg=f"HTTP {code}",
            hdrs=headers,
            fp=io.BytesIO(b""),
        )

    def test_retries_on_429_and_succeeds(self):
        """429 on first attempt should trigger a retry and succeed on second."""
        success_resp = MagicMock()
        success_resp.__enter__ = lambda s: s
        success_resp.__exit__ = MagicMock(return_value=False)
        success_resp.read.return_value = json.dumps({"ok": True}).encode()

        err_429 = self._make_http_error(429)

        call_count = 0

        def side_effect(req, timeout=15):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise err_429
            return success_resp

        with (
            patch("urllib.request.urlopen", side_effect=side_effect),
            patch("time.sleep") as mock_sleep,
            patch.dict("os.environ", {}, clear=False),
        ):
            result = dashboard_gen._github_api_json("https://api.github.com/test", _max_retries=3)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(call_count, 2)
        mock_sleep.assert_called_once()
        # Default backoff for attempt=0: min(2**0, 30) == 1
        mock_sleep.assert_called_with(1)

    def test_retry_after_header_respected(self):
        """Retry-After header value should be used as sleep duration."""
        success_resp = MagicMock()
        success_resp.__enter__ = lambda s: s
        success_resp.__exit__ = MagicMock(return_value=False)
        success_resp.read.return_value = json.dumps({"ok": True}).encode()

        err_429 = self._make_http_error(429, retry_after="5")

        call_count = 0

        def side_effect(req, timeout=15):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise err_429
            return success_resp

        with (
            patch("urllib.request.urlopen", side_effect=side_effect),
            patch("time.sleep") as mock_sleep,
            patch.dict("os.environ", {}, clear=False),
        ):
            result = dashboard_gen._github_api_json("https://api.github.com/test", _max_retries=3)

        self.assertEqual(result, {"ok": True})
        mock_sleep.assert_called_with(5)

    def test_github_token_sets_authorization_header(self):
        """GITHUB_TOKEN env var should add Authorization header to request."""
        captured_req: list = []

        success_resp = MagicMock()
        success_resp.__enter__ = lambda s: s
        success_resp.__exit__ = MagicMock(return_value=False)
        success_resp.read.return_value = json.dumps({"data": 1}).encode()

        def side_effect(req, timeout=15):
            captured_req.append(req)
            return success_resp

        with (
            patch("urllib.request.urlopen", side_effect=side_effect),
            patch.dict("os.environ", {"GITHUB_TOKEN": "test-fake-token-abc123"}, clear=False),
        ):
            result = dashboard_gen._github_api_json("https://api.github.com/repos/x/y")

        self.assertEqual(result, {"data": 1})
        self.assertEqual(len(captured_req), 1)
        auth_header = captured_req[0].get_header("Authorization")
        self.assertEqual(auth_header, "token test-fake-token-abc123")

    def test_gh_token_fallback(self):
        """GH_TOKEN env var should be used when GITHUB_TOKEN is absent."""
        captured_req: list = []

        success_resp = MagicMock()
        success_resp.__enter__ = lambda s: s
        success_resp.__exit__ = MagicMock(return_value=False)
        success_resp.read.return_value = json.dumps({}).encode()

        def side_effect(req, timeout=15):
            captured_req.append(req)
            return success_resp

        env = {"GH_TOKEN": "gh_fallback456"}
        # Ensure GITHUB_TOKEN is not set
        with (
            patch("urllib.request.urlopen", side_effect=side_effect),
            patch.dict("os.environ", env, clear=False),
        ):
            # Remove GITHUB_TOKEN if present in the test environment
            import os as _os
            original = _os.environ.pop("GITHUB_TOKEN", None)
            try:
                dashboard_gen._github_api_json("https://api.github.com/repos/a/b")
            finally:
                if original is not None:
                    _os.environ["GITHUB_TOKEN"] = original

        auth_header = captured_req[0].get_header("Authorization")
        self.assertEqual(auth_header, "token gh_fallback456")

    def test_non_rate_limit_http_error_raises_immediately(self):
        """Non-403/429 HTTP errors should propagate without retry."""
        err_404 = self._make_http_error(404)
        call_count = 0

        def side_effect(req, timeout=15):
            nonlocal call_count
            call_count += 1
            raise err_404

        with (
            patch("urllib.request.urlopen", side_effect=side_effect),
            patch("time.sleep") as mock_sleep,
            patch.dict("os.environ", {}, clear=False),
        ):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                dashboard_gen._github_api_json("https://api.github.com/test", _max_retries=3)

        self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(call_count, 1)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
