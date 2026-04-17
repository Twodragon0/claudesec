"""
Unit tests for scanner/lib/dashboard_api_client.py.

Focuses on pure helpers (module-level source constants, parsing/formatting
behaviour in `_fetch_markdown_preview`, URL construction) plus mocked-I/O
coverage of the GitHub fetchers.  Each test exercises one behaviour and is
independent of any other test (no shared mutable state, no network).
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_api_client as api  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_urlopen(payload, encode=True):
    """Return a context-manager mock that yields payload bytes on read()."""
    resp = MagicMock()
    data = payload.encode("utf-8") if encode else payload
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _json_urlopen(obj):
    return _mock_urlopen(json.dumps(obj))


def _http_error(code, headers=None):
    hdrs = headers or {}
    return urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=code,
        msg="err",
        hdrs=hdrs,
        fp=None,
    )


# ===========================================================================
# 1. Module-level source constants (pure data)
# ===========================================================================


class TestMsBestPracticesRepoSources(unittest.TestCase):
    def test_list_is_non_empty(self):
        self.assertGreater(len(api.MS_BEST_PRACTICES_REPO_SOURCES), 0)

    def test_each_entry_has_required_keys(self):
        required = {"product", "repo", "label", "trust_level", "reason", "focus_paths"}
        for src in api.MS_BEST_PRACTICES_REPO_SOURCES:
            self.assertTrue(required.issubset(src.keys()))

    def test_focus_paths_are_lists_of_strings(self):
        for src in api.MS_BEST_PRACTICES_REPO_SOURCES:
            self.assertIsInstance(src["focus_paths"], list)
            for p in src["focus_paths"]:
                self.assertIsInstance(p, str)

    def test_scubagear_entry_is_marked_optional(self):
        scubagear = [
            s
            for s in api.MS_BEST_PRACTICES_REPO_SOURCES
            if s.get("repo") == "cisagov/ScubaGear"
        ]
        self.assertEqual(len(scubagear), 1)
        self.assertEqual(scubagear[0].get("optional_env"), "CLAUDESEC_MS_INCLUDE_SCUBAGEAR")

    def test_repo_values_use_owner_slash_name(self):
        for src in api.MS_BEST_PRACTICES_REPO_SOURCES:
            self.assertIn("/", src["repo"])

    def test_trust_levels_are_known_values(self):
        known = {"Microsoft Official", "Government", "Community"}
        for src in api.MS_BEST_PRACTICES_REPO_SOURCES:
            self.assertIn(src["trust_level"], known)


class TestSaasBestPracticesSources(unittest.TestCase):
    def test_list_is_non_empty(self):
        self.assertGreater(len(api.SAAS_BEST_PRACTICES_SOURCES), 0)

    def test_each_entry_has_product_and_repo(self):
        for src in api.SAAS_BEST_PRACTICES_SOURCES:
            self.assertIn("product", src)
            self.assertIn("repo", src)

    def test_querypie_product_present(self):
        products = {s["product"] for s in api.SAAS_BEST_PRACTICES_SOURCES}
        self.assertIn("QueryPie", products)

    def test_okta_product_present(self):
        products = {s["product"] for s in api.SAAS_BEST_PRACTICES_SOURCES}
        self.assertIn("Okta", products)

    def test_argocd_uses_cncf_trust_level(self):
        argocd_entries = [
            s for s in api.SAAS_BEST_PRACTICES_SOURCES if s["product"] == "ArgoCD"
        ]
        self.assertTrue(all(s["trust_level"] == "CNCF Official" for s in argocd_entries))


class TestCacheTtlConstant(unittest.TestCase):
    def test_saas_cache_ttl_is_24_hours(self):
        self.assertEqual(api.SAAS_BEST_PRACTICES_CACHE_TTL_HOURS, 24)


# ===========================================================================
# 2. _github_api_json (mocked I/O)
# ===========================================================================


class TestGithubApiJson(unittest.TestCase):
    def test_happy_path_returns_parsed_json(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("GH_TOKEN", None)
            with patch("urllib.request.urlopen", return_value=_json_urlopen({"ok": 1})):
                result = api._github_api_json("https://api.github.com/x")
        self.assertEqual(result, {"ok": 1})

    def test_authorization_header_set_when_github_token_env_present(self):
        captured = {}

        def _capture(req, timeout=0):
            captured["headers"] = dict(req.headers)
            return _json_urlopen([])

        with patch.dict(os.environ, {"GITHUB_TOKEN": "abc123"}, clear=False):
            os.environ.pop("GH_TOKEN", None)
            with patch("urllib.request.urlopen", side_effect=_capture):
                api._github_api_json("https://api.github.com/x")
        # urllib capitalises header keys
        self.assertIn("Authorization", captured["headers"])
        self.assertEqual(captured["headers"]["Authorization"], "token abc123")

    def test_accept_header_always_set(self):
        captured = {}

        def _capture(req, timeout=0):
            captured["headers"] = dict(req.headers)
            return _json_urlopen({})

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("GH_TOKEN", None)
            with patch("urllib.request.urlopen", side_effect=_capture):
                api._github_api_json("https://api.github.com/x")
        self.assertEqual(captured["headers"]["Accept"], "application/vnd.github.v3+json")

    def test_retries_on_403_then_succeeds(self):
        responses = [_http_error(403, {"Retry-After": "0"}), _json_urlopen({"ok": True})]

        def _side_effect(req, timeout=0):
            r = responses.pop(0)
            if isinstance(r, urllib.error.HTTPError):
                raise r
            return r

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            os.environ.pop("GH_TOKEN", None)
            with patch("urllib.request.urlopen", side_effect=_side_effect):
                with patch("time.sleep"):
                    result = api._github_api_json("https://api.github.com/x")
        self.assertEqual(result, {"ok": True})

    def test_retries_on_429_with_retry_after_header(self):
        responses = [_http_error(429, {"Retry-After": "1"}), _json_urlopen([])]

        def _side_effect(req, timeout=0):
            r = responses.pop(0)
            if isinstance(r, urllib.error.HTTPError):
                raise r
            return r

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            with patch("urllib.request.urlopen", side_effect=_side_effect):
                with patch("time.sleep") as slp:
                    api._github_api_json("https://api.github.com/x")
        # ensure we slept (Retry-After honoured)
        slp.assert_called()

    def test_raises_on_non_rate_limit_http_error(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            with patch("urllib.request.urlopen", side_effect=_http_error(500)):
                with self.assertRaises(urllib.error.HTTPError):
                    api._github_api_json("https://api.github.com/x")

    def test_retries_on_urlerror_then_raises(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            with patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.URLError("boom"),
            ):
                with patch("time.sleep"):
                    with self.assertRaises(urllib.error.URLError):
                        api._github_api_json(
                            "https://api.github.com/x", _max_retries=2
                        )

    def test_exhausts_retries_on_repeated_rate_limits(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_TOKEN", None)
            with patch(
                "urllib.request.urlopen",
                side_effect=_http_error(403, {"Retry-After": "0"}),
            ):
                with patch("time.sleep"):
                    with self.assertRaises(urllib.error.HTTPError):
                        api._github_api_json(
                            "https://api.github.com/x", _max_retries=2
                        )


# ===========================================================================
# 3. _fetch_audit_points_from_github (mocked I/O)
# ===========================================================================


class TestFetchAuditPointsFromGithub(unittest.TestCase):
    def test_returns_none_on_network_error(self):
        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            self.assertIsNone(api._fetch_audit_points_from_github())

    def test_returns_none_when_root_not_list(self):
        with patch(
            "urllib.request.urlopen", return_value=_json_urlopen({"not": "a list"})
        ):
            self.assertIsNone(api._fetch_audit_points_from_github())

    def test_skips_non_dir_items(self):
        root = [{"type": "file", "name": "README.md"}]
        with patch("urllib.request.urlopen", return_value=_json_urlopen(root)):
            result = api._fetch_audit_points_from_github()
        self.assertIsNotNone(result)
        self.assertEqual(result["products"], [])

    def test_collects_products_and_files(self):
        root = [
            {"type": "dir", "name": "Okta", "html_url": "https://github.com/x/Okta"},
            {"type": "dir", "name": "Jenkins", "html_url": "https://github.com/x/Jenkins"},
        ]
        children_okta = [
            {
                "type": "file",
                "name": "check.md",
                "html_url": "https://github.com/x/Okta/check.md",
                "download_url": "https://raw/x/Okta/check.md",
            }
        ]
        children_jenkins = [
            {
                "type": "file",
                "name": "build.md",
                "html_url": "https://github.com/x/Jenkins/build.md",
                "download_url": "https://raw/x/Jenkins/build.md",
            },
            # non-markdown file should be skipped
            {"type": "file", "name": "image.png", "html_url": "", "download_url": ""},
        ]
        # Sub-fetches happen in root insertion order (Okta then Jenkins);
        # sorting is applied only to the final products list.
        call_order = [
            _json_urlopen(root),
            _json_urlopen(children_okta),
            _json_urlopen(children_jenkins),
        ]

        def _side_effect(req, timeout=0):
            return call_order.pop(0)

        with patch("urllib.request.urlopen", side_effect=_side_effect):
            result = api._fetch_audit_points_from_github()
        self.assertIsNotNone(result)
        names = [p["name"] for p in result["products"]]
        self.assertEqual(names, ["Jenkins", "Okta"])  # sorted
        jenkins = next(p for p in result["products"] if p["name"] == "Jenkins")
        self.assertEqual(len(jenkins["files"]), 1)  # png filtered out
        self.assertEqual(jenkins["files"][0]["name"], "build.md")

    def test_tolerates_subfolder_fetch_failure(self):
        root = [{"type": "dir", "name": "Okta", "html_url": "https://x/Okta"}]
        calls = [
            _json_urlopen(root),
            # second call raises — should be swallowed, product kept with empty files
            urllib.error.URLError("boom"),
        ]

        def _side_effect(req, timeout=0):
            r = calls.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        with patch("urllib.request.urlopen", side_effect=_side_effect):
            result = api._fetch_audit_points_from_github()
        self.assertIsNotNone(result)
        self.assertEqual(len(result["products"]), 1)
        self.assertEqual(result["products"][0]["files"], [])

    def test_skips_readme_top_level_dir(self):
        # Even if a dir is named "README.md" (rare), it is skipped.
        root = [
            {"type": "dir", "name": "README.md", "html_url": "x"},
            {"type": "dir", "name": "Okta", "html_url": "y"},
        ]

        def _side_effect(req, timeout=0):
            return _json_urlopen([] if "Okta" in req.full_url else root)

        with patch("urllib.request.urlopen", side_effect=_side_effect):
            result = api._fetch_audit_points_from_github()
        self.assertEqual([p["name"] for p in result["products"]], ["Okta"])

    def test_skips_dir_entries_missing_name(self):
        root = [
            {"type": "dir"},  # missing name
            {"type": "dir", "name": "Okta", "html_url": "x"},
        ]

        def _side_effect(req, timeout=0):
            return _json_urlopen([] if "Okta" in req.full_url else root)

        with patch("urllib.request.urlopen", side_effect=_side_effect):
            result = api._fetch_audit_points_from_github()
        self.assertEqual([p["name"] for p in result["products"]], ["Okta"])

    def test_children_non_list_becomes_empty(self):
        root = [{"type": "dir", "name": "Okta", "html_url": "x"}]

        def _side_effect(req, timeout=0):
            if "Okta" in req.full_url:
                return _json_urlopen({"unexpected": "dict"})
            return _json_urlopen(root)

        with patch("urllib.request.urlopen", side_effect=_side_effect):
            result = api._fetch_audit_points_from_github()
        self.assertEqual(result["products"][0]["files"], [])


# ===========================================================================
# 4. _fetch_repo_focus_files (mocked via _github_api_json)
# ===========================================================================


class TestFetchRepoFocusFiles(unittest.TestCase):
    def test_returns_default_shape_on_meta_error(self):
        with patch(
            "dashboard_api_client._github_api_json",
            side_effect=urllib.error.URLError("nope"),
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(result["repo"], "x/y")
        self.assertEqual(result["repo_url"], "https://github.com/x/y")
        self.assertEqual(result["files"], [])
        self.assertFalse(result["archived"])

    def test_meta_non_dict_returns_default(self):
        with patch(
            "dashboard_api_client._github_api_json", return_value=["not a dict"]
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(result["files"], [])

    def test_repo_meta_populates_default_branch_and_pushed_at(self):
        responses = {
            "https://api.github.com/repos/x/y": {
                "default_branch": "main",
                "pushed_at": "2026-01-01T00:00:00Z",
                "archived": False,
            },
            "https://api.github.com/repos/x/y/contents/README.md": {
                "type": "file",
                "name": "README.md",
                "path": "README.md",
                "html_url": "https://github.com/x/y/README.md",
                "download_url": "https://raw/x/y/README.md",
            },
        }

        def _side_effect(url):
            return responses.get(url, {})

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(result["default_branch"], "main")
        self.assertEqual(result["updated_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(len(result["files"]), 1)
        self.assertEqual(result["files"][0]["name"], "README.md")

    def test_falls_back_to_updated_at_when_pushed_at_missing(self):
        responses = {
            "https://api.github.com/repos/x/y": {
                "default_branch": "main",
                "updated_at": "2025-01-01T00:00:00Z",
            },
        }
        with patch(
            "dashboard_api_client._github_api_json",
            side_effect=lambda url: responses.get(url, []),
        ):
            result = api._fetch_repo_focus_files("x/y", [])
        self.assertEqual(result["updated_at"], "2025-01-01T00:00:00Z")

    def test_archived_repo_flag_propagated(self):
        with patch(
            "dashboard_api_client._github_api_json",
            return_value={"default_branch": "main", "archived": True},
        ):
            result = api._fetch_repo_focus_files("x/y", [])
        self.assertTrue(result["archived"])

    def test_focus_path_directory_collects_child_files(self):
        # focus_path='docs' → first fetch returns a listing that contains a
        # sub-directory 'docs/sub'; the recursive fetch of that sub-dir
        # returns markdown files that should be collected.
        meta = {"default_branch": "main"}
        dir_listing = [
            {"type": "dir", "name": "sub", "path": "docs/sub"},
        ]
        children = [
            {
                "type": "file",
                "name": "guide.md",
                "path": "docs/sub/guide.md",
                "html_url": "https://github.com/x/y/docs/sub/guide.md",
                "download_url": "https://raw/x/y/docs/sub/guide.md",
            }
        ]

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            if url.endswith("/contents/docs"):
                return dir_listing
            if url.endswith("/contents/docs/sub"):
                return children
            return {}

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["docs"])
        paths = [f["path"] for f in result["files"]]
        self.assertIn("docs/sub/guide.md", paths)

    def test_focus_path_subdir_fetch_failure_is_swallowed(self):
        meta = {"default_branch": "main"}
        dir_listing = [{"type": "dir", "name": "sub", "path": "docs/sub"}]

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            if url.endswith("/contents/docs"):
                return dir_listing
            raise urllib.error.URLError("child failed")

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["docs"])
        self.assertEqual(result["files"], [])

    def test_single_dict_payload_treated_as_single_entry(self):
        meta = {"default_branch": "main"}
        file_payload = {
            "type": "file",
            "name": "README.md",
            "path": "README.md",
            "html_url": "",
            "download_url": "",
        }

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            return file_payload

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(len(result["files"]), 1)

    def test_non_best_practice_files_filtered_out(self):
        meta = {"default_branch": "main"}
        file_payload = {
            "type": "file",
            "name": "logo.png",
            "path": "logo.png",
        }

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            return file_payload

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["logo.png"])
        self.assertEqual(result["files"], [])

    def test_duplicate_paths_deduplicated(self):
        meta = {"default_branch": "main"}
        entry = {
            "type": "file",
            "name": "README.md",
            "path": "README.md",
            "html_url": "",
            "download_url": "",
        }

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            return [entry, entry]

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(len(result["files"]), 1)

    def test_unexpected_payload_type_yields_no_files(self):
        meta = {"default_branch": "main"}

        def _side_effect(url):
            if url.endswith("/x/y"):
                return meta
            return 42  # not list, not dict

        with patch(
            "dashboard_api_client._github_api_json", side_effect=_side_effect
        ):
            result = api._fetch_repo_focus_files("x/y", ["README.md"])
        self.assertEqual(result["files"], [])


# ===========================================================================
# 5. _fetch_microsoft_best_practices_from_github
# ===========================================================================


class TestFetchMicrosoftBestPracticesFromGithub(unittest.TestCase):
    def _stub_repo_focus(self, **overrides):
        base = {
            "repo": "fake/repo",
            "repo_url": "https://github.com/fake/repo",
            "default_branch": "main",
            "updated_at": "2026-01-01T00:00:00Z",
            "archived": False,
            "files": [],
        }
        base.update(overrides)
        return base

    def test_returns_dict_with_expected_keys(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                return_value=self._stub_repo_focus(),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        self.assertIn("fetched_at", result)
        self.assertIn("source_filter", result)
        self.assertIn("scubagear_enabled", result)
        self.assertIn("sources", result)

    def test_archived_sources_excluded(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                return_value=self._stub_repo_focus(archived=True),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        self.assertEqual(result["sources"], [])

    def test_scubagear_skipped_when_env_not_truthy(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                return_value=self._stub_repo_focus(),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        repos = {s["repo"] for s in result["sources"]}
        self.assertNotIn("cisagov/ScubaGear", repos)
        self.assertFalse(result["scubagear_enabled"])

    def test_scubagear_included_when_env_truthy(self):
        with patch.dict(
            os.environ,
            {"CLAUDESEC_MS_INCLUDE_SCUBAGEAR": "1"},
            clear=False,
        ):
            os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                side_effect=lambda repo, paths: self._stub_repo_focus(
                    repo=repo,
                    repo_url=f"https://github.com/{repo}",
                ),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        repos = {s["repo"] for s in result["sources"]}
        self.assertIn("cisagov/ScubaGear", repos)
        self.assertTrue(result["scubagear_enabled"])

    def test_source_filter_gov_excludes_microsoft_official(self):
        with patch.dict(
            os.environ,
            {"CLAUDESEC_MS_SOURCE_FILTER": "gov"},
            clear=False,
        ):
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                side_effect=lambda repo, paths: self._stub_repo_focus(repo=repo),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        levels = {s["trust_level"] for s in result["sources"]}
        self.assertNotIn("Microsoft Official", levels)

    def test_sources_sorted_by_trust_level_then_product(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDESEC_MS_SOURCE_FILTER", None)
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                side_effect=lambda repo, paths: self._stub_repo_focus(repo=repo),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        # Microsoft Official (order 0) should come before Government (order 1)
        order_values = [
            api.__dict__  # just touch module
            for _ in result["sources"]
        ]
        self.assertGreater(len(result["sources"]), 0)
        trust_ranks = [
            {"Microsoft Official": 0, "Government": 1, "Community": 2}.get(
                s["trust_level"], 9
            )
            for s in result["sources"]
        ]
        self.assertEqual(trust_ranks, sorted(trust_ranks))

    def test_source_filter_normalized_in_output(self):
        with patch.dict(
            os.environ,
            {"CLAUDESEC_MS_SOURCE_FILTER": "official"},
            clear=False,
        ):
            os.environ.pop("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", None)
            with patch(
                "dashboard_api_client._fetch_repo_focus_files",
                side_effect=lambda repo, paths: self._stub_repo_focus(repo=repo),
            ):
                result = api._fetch_microsoft_best_practices_from_github()
        self.assertEqual(result["source_filter"], "official")


# ===========================================================================
# 6. _fetch_saas_best_practices_from_github
# ===========================================================================


class TestFetchSaasBestPracticesFromGithub(unittest.TestCase):
    def _stub(self, **overrides):
        base = {
            "repo": "fake/repo",
            "repo_url": "https://github.com/fake/repo",
            "default_branch": "main",
            "updated_at": "2026-01-01T00:00:00Z",
            "archived": False,
            "files": [],
        }
        base.update(overrides)
        return base

    def test_returns_fetched_at_and_sources_keys(self):
        with patch(
            "dashboard_api_client._fetch_repo_focus_files",
            side_effect=lambda repo, paths: self._stub(
                repo=repo, repo_url=f"https://github.com/{repo}"
            ),
        ):
            result = api._fetch_saas_best_practices_from_github()
        self.assertIn("fetched_at", result)
        self.assertIn("sources", result)

    def test_archived_repos_excluded(self):
        with patch(
            "dashboard_api_client._fetch_repo_focus_files",
            return_value=self._stub(archived=True),
        ):
            result = api._fetch_saas_best_practices_from_github()
        self.assertEqual(result["sources"], [])

    def test_each_source_preserves_focus_paths(self):
        with patch(
            "dashboard_api_client._fetch_repo_focus_files",
            side_effect=lambda repo, paths: self._stub(
                repo=repo, repo_url=f"https://github.com/{repo}"
            ),
        ):
            result = api._fetch_saas_best_practices_from_github()
        for src in result["sources"]:
            self.assertIn("focus_paths", src)
            self.assertIsInstance(src["focus_paths"], list)

    def test_querypie_source_rendered(self):
        with patch(
            "dashboard_api_client._fetch_repo_focus_files",
            side_effect=lambda repo, paths: self._stub(
                repo=repo, repo_url=f"https://github.com/{repo}"
            ),
        ):
            result = api._fetch_saas_best_practices_from_github()
        products = {s["product"] for s in result["sources"]}
        self.assertIn("QueryPie", products)

    def test_sources_sorted_by_trust_level(self):
        with patch(
            "dashboard_api_client._fetch_repo_focus_files",
            side_effect=lambda repo, paths: self._stub(
                repo=repo, repo_url=f"https://github.com/{repo}"
            ),
        ):
            result = api._fetch_saas_best_practices_from_github()
        order = [
            {"Microsoft Official": 0, "Government": 1, "Community": 2}.get(
                s["trust_level"], 9
            )
            for s in result["sources"]
        ]
        self.assertEqual(order, sorted(order))


# ===========================================================================
# 7. _fetch_markdown_preview (pure behaviours + mocked I/O)
# ===========================================================================


class TestFetchMarkdownPreview(unittest.TestCase):
    def setUp(self):
        self._offline_patcher = patch.dict(
            os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}
        )
        self._offline_patcher.start()

    def tearDown(self):
        self._offline_patcher.stop()

    def test_empty_url_returns_empty_string(self):
        self.assertEqual(api._fetch_markdown_preview(""), "")

    def test_offline_env_returns_empty(self):
        with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/file.md"
            )
        self.assertEqual(result, "")

    def test_non_https_scheme_returns_empty(self):
        self.assertEqual(
            api._fetch_markdown_preview("http://raw.githubusercontent.com/x/y/f.md"),
            "",
        )

    def test_disallowed_host_returns_empty(self):
        self.assertEqual(
            api._fetch_markdown_preview("https://evil.example.com/x/y/f.md"),
            "",
        )

    def test_network_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("boom")):
            self.assertEqual(
                api._fetch_markdown_preview(
                    "https://raw.githubusercontent.com/x/y/f.md"
                ),
                "",
            )

    def test_heading_rendered_with_bp_audit_heading_class(self):
        md = "# Title\n"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertIn("bp-audit-heading", result)
        self.assertIn("Title", result)

    def test_checkbox_item_rendered(self):
        md = "- [ ] Enable MFA\n"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertIn("bp-audit-item", result)
        self.assertIn("Enable MFA", result)

    def test_bullet_item_rendered(self):
        md = "- Plain bullet\n"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertIn("Plain bullet", result)
        self.assertIn("bp-audit-item", result)

    def test_plain_text_rendered_with_bp_audit_text_class(self):
        md = "Some plain paragraph\n"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertIn("bp-audit-text", result)

    def test_html_escaped_in_output(self):
        md = "- <script>alert(1)</script>\n"
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_max_lines_truncates_output(self):
        md = "\n".join(f"- Item {i}" for i in range(50))
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(md)):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md", max_lines=5
            )
        self.assertEqual(result.count("bp-audit-item"), 5)

    def test_empty_body_returns_empty_string(self):
        with patch("urllib.request.urlopen", return_value=_mock_urlopen("")):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertEqual(result, "")

    def test_wrapper_div_is_emitted(self):
        with patch(
            "urllib.request.urlopen", return_value=_mock_urlopen("- Item\n")
        ):
            result = api._fetch_markdown_preview(
                "https://raw.githubusercontent.com/x/y/f.md"
            )
        self.assertTrue(result.startswith('<div class="bp-audit-preview">'))
        self.assertTrue(result.endswith("</div>"))


if __name__ == "__main__":
    unittest.main()
