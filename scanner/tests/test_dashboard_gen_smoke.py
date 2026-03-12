import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
SPEC = importlib.util.spec_from_file_location("dashboard_gen", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Failed to load module spec for {MODULE_PATH}")
dashboard_gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_gen)


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
                    dashboard_gen,
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
            self.assertIn("trust-badge trust-gov", html)
            self.assertIn("CISA ScubaGear", html)
            self.assertIn("Total sources 1", html)
            self.assertIn("source-filter-chip", html)
            self.assertIn("official,gov", html)
            self.assertIn('data-filter="none"', html)
            self.assertIn("claudesec:dashboard:msSourcePreset", html)
            self.assertIn("claudesec.msSourcePreset", html)
            self.assertIn("localStorage.getItem", html)
            self.assertIn("Windows / Intune / Office 365 best-practice sources", html)
            self.assertIn("OAuth &amp; authentication scan readiness", html)
            self.assertIn("RFC 9700", html)
            self.assertIn("OWASP OAuth 2.0 Cheat Sheet", html)
            self.assertIn("Tokens expiring &lt;12h", html)
            self.assertIn("Tokens expiring 12h-2d", html)
            self.assertIn("Active windows: &lt;12h and 12h-2d", html)
            self.assertIn("Threshold source: &lt;12h=env, 2d=env", html)
            self.assertIn("Known token expiries", html)
            self.assertIn("Expiring 12h-2d: 1", html)

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
                dashboard_gen,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                dashboard_gen,
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
                    },
                    clear=False,
                ),
                patch.object(
                    dashboard_gen,
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
                dashboard_gen,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                dashboard_gen,
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
                dashboard_gen,
                "MS_BEST_PRACTICES_REPO_SOURCES",
                fake_sources,
            ),
            patch.object(
                dashboard_gen,
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


if __name__ == "__main__":
    unittest.main()
