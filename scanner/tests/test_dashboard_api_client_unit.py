"""
Unit tests for scanner/lib/dashboard_api_client.py.

All urllib.request.urlopen calls are mocked — no real network access.
Goal: lift dashboard_api_client.py coverage from 44.5% to ≥70%.

Reference: .omc/research/scanner-lib-coverage-2026-04-17.md
"""

import json
import os
import sys
import urllib.error
import urllib.request
from io import BytesIO
from unittest.mock import MagicMock, patch, call

try:
    import pytest
except ImportError:  # xmlrunner baseline in CI has no pytest; module-level test functions
    pytest = None  # type: ignore[assignment]  # below are pytest-only and skipped by unittest

# ---------------------------------------------------------------------------
# Import setup — match pattern used in test_dashboard_audit_sources_unit.py
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_api_client as dac


# ---------------------------------------------------------------------------
# Fake response helpers
# ---------------------------------------------------------------------------

class _FakeResp:
    """Context-manager-compatible fake urlopen response."""

    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _json_resp(payload, status: int = 200) -> _FakeResp:
    """Return a _FakeResp whose body is the JSON-encoded payload."""
    body = json.dumps(payload).encode("utf-8")
    return _FakeResp(body, status)


def _raw_resp(body: bytes, status: int = 200) -> _FakeResp:
    return _FakeResp(body, status)


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=code,
        msg=f"HTTP {code}",
        hdrs=MagicMock(get=lambda k, d=None: None),  # type: ignore[arg-type]
        fp=None,
    )


def _url_error(msg: str = "connection refused") -> urllib.error.URLError:
    return urllib.error.URLError(msg)


# ===========================================================================
# _github_api_json
# ===========================================================================


def test_github_api_json_happy_path_returns_parsed_json():
    """_github_api_json returns parsed dict when urlopen succeeds."""
    payload = {"default_branch": "main", "archived": False}
    with patch("urllib.request.urlopen", return_value=_json_resp(payload)):
        result = dac._github_api_json("https://api.github.com/repos/test/repo")
    assert result["default_branch"] == "main"
    assert result["archived"] is False


def test_github_api_json_returns_list_payload():
    """_github_api_json handles list-typed JSON responses."""
    payload = [{"type": "file", "name": "README.md"}]
    with patch("urllib.request.urlopen", return_value=_json_resp(payload)):
        result = dac._github_api_json("https://api.github.com/repos/test/repo/contents")
    assert isinstance(result, list)
    assert result[0]["name"] == "README.md"


def test_github_api_json_404_raises_http_error():
    """_github_api_json raises HTTPError for 404 (non-rate-limit error)."""
    with patch("urllib.request.urlopen", side_effect=_http_error(404)):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            dac._github_api_json("https://api.github.com/repos/test/repo")
    assert exc_info.value.code == 404


def test_github_api_json_401_raises_http_error():
    """_github_api_json raises HTTPError for 401."""
    with patch("urllib.request.urlopen", side_effect=_http_error(401)):
        with pytest.raises(urllib.error.HTTPError):
            dac._github_api_json("https://api.github.com/repos/test/repo")


def test_github_api_json_url_error_raises_after_retries():
    """_github_api_json re-raises URLError after exhausting retries."""
    err = _url_error("connection refused")
    # Patch time.sleep to avoid delays in tests
    with patch("urllib.request.urlopen", side_effect=err), \
         patch("time.sleep"):
        with pytest.raises(urllib.error.URLError):
            dac._github_api_json("https://api.github.com/repos/test/repo", _max_retries=2)


def test_github_api_json_sets_accept_header():
    """_github_api_json sets the Accept: application/vnd.github.v3+json header."""
    payload = {}
    captured_req: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        captured_req.append(req)
        return _json_resp(payload)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        dac._github_api_json("https://api.github.com/repos/test/repo")

    assert len(captured_req) == 1
    assert captured_req[0].get_header("Accept") == "application/vnd.github.v3+json"


def test_github_api_json_sets_authorization_header_when_gh_token_set(monkeypatch):
    """_github_api_json sets Authorization header when GH_TOKEN env var is present."""
    monkeypatch.setenv("GH_TOKEN", "fake-token-abc")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    captured_req: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        captured_req.append(req)
        return _json_resp({})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        dac._github_api_json("https://api.github.com/repos/test/repo")

    assert "Authorization" in captured_req[0].headers or \
           captured_req[0].get_header("Authorization") is not None
    auth = captured_req[0].get_header("Authorization")
    assert auth is not None
    assert "fake-token-abc" in auth


def test_github_api_json_no_authorization_header_when_no_token(monkeypatch):
    """_github_api_json omits Authorization header when no token env vars are set."""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    captured_req: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        captured_req.append(req)
        return _json_resp({})

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        dac._github_api_json("https://api.github.com/repos/test/repo")

    auth = captured_req[0].get_header("Authorization")
    assert auth is None


def test_github_api_json_403_retries_then_raises(monkeypatch):
    """_github_api_json retries on 403 and raises after max retries."""
    err = _http_error(403)
    with patch("urllib.request.urlopen", side_effect=err), \
         patch("time.sleep"):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            dac._github_api_json(
                "https://api.github.com/repos/test/repo", _max_retries=2
            )
    assert exc_info.value.code == 403


# ===========================================================================
# _fetch_audit_points_from_github
# ===========================================================================


def test_fetch_audit_points_happy_path_returns_products():
    """_fetch_audit_points_from_github returns products list with expected keys."""
    root_payload = [
        {"type": "dir", "name": "database", "html_url": "https://github.com/q/ap/tree/main/database"},
    ]
    sub_payload = [
        {"type": "file", "name": "access.md", "html_url": "https://github.com/q/ap/blob/main/database/access.md", "download_url": "https://raw.githubusercontent.com/q/ap/main/database/access.md"},
    ]

    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    assert "products" in result
    assert "fetched_at" in result
    assert len(result["products"]) == 1
    assert result["products"][0]["name"] == "database"
    assert len(result["products"][0]["files"]) == 1
    assert result["products"][0]["files"][0]["name"] == "access.md"


def test_fetch_audit_points_skips_non_dir_items():
    """_fetch_audit_points_from_github ignores non-directory items in root listing."""
    root_payload = [
        {"type": "file", "name": "README.md", "html_url": "https://github.com/q/ap/blob/main/README.md"},
        {"type": "dir", "name": "policies", "html_url": "https://github.com/q/ap/tree/main/policies"},
    ]
    sub_payload: list = []

    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    # README.md dir-type skip + "README.md" name skip; only "policies" dir passes
    product_names = [p["name"] for p in result["products"]]
    assert "README.md" not in product_names
    assert "policies" in product_names


def test_fetch_audit_points_returns_none_on_url_error():
    """_fetch_audit_points_from_github returns None when the root request raises URLError."""
    with patch("urllib.request.urlopen", side_effect=_url_error()):
        result = dac._fetch_audit_points_from_github()
    assert result is None


def test_fetch_audit_points_returns_none_on_malformed_json():
    """_fetch_audit_points_from_github returns None when response is not valid JSON."""
    with patch("urllib.request.urlopen", return_value=_raw_resp(b"not json at all")):
        result = dac._fetch_audit_points_from_github()
    assert result is None


def test_fetch_audit_points_returns_none_when_root_is_not_list():
    """_fetch_audit_points_from_github returns None when root response is a dict, not list."""
    with patch("urllib.request.urlopen", return_value=_json_resp({"message": "Not Found"})):
        result = dac._fetch_audit_points_from_github()
    assert result is None


def test_fetch_audit_points_empty_root_list_returns_empty_products():
    """_fetch_audit_points_from_github returns empty products list for empty root."""
    with patch("urllib.request.urlopen", return_value=_json_resp([])):
        result = dac._fetch_audit_points_from_github()
    assert result is not None
    assert result["products"] == []


def test_fetch_audit_points_sub_request_error_gracefully_skipped():
    """_fetch_audit_points_from_github still returns product entry even if sub-request fails."""
    root_payload = [
        {"type": "dir", "name": "policies", "html_url": "https://github.com/q/ap/tree/main/policies"},
    ]
    call_count = [0]

    def fake_urlopen(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _json_resp(root_payload)
        raise urllib.error.URLError("connection refused")

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    # Product should still appear with empty files
    assert len(result["products"]) == 1
    assert result["products"][0]["files"] == []


# ===========================================================================
# _fetch_repo_focus_files
# ===========================================================================


def test_fetch_repo_focus_files_happy_path_returns_files():
    """_fetch_repo_focus_files returns dict with files list and repo metadata."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    contents = [
        {"type": "file", "name": "README.md", "path": "README.md",
         "html_url": "https://github.com/t/r/blob/main/README.md",
         "download_url": "https://raw.githubusercontent.com/t/r/main/README.md"},
    ]
    responses = iter([_json_resp(repo_meta), _json_resp(contents)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert result["repo"] == "test/repo"
    assert result["default_branch"] == "main"
    assert result["archived"] is False
    assert len(result["files"]) == 1
    assert result["files"][0]["name"] == "README.md"


def test_fetch_repo_focus_files_archived_repo_sets_archived_true():
    """_fetch_repo_focus_files sets archived=True when repo metadata says archived."""
    repo_meta = {"default_branch": "main", "pushed_at": "2024-01-01T00:00:00Z", "archived": True}
    # Only one call needed — archived repo still runs focus path fetching
    # but parent callers drop it. Verify the flag is surfaced correctly.
    contents: list = []
    responses = iter([_json_resp(repo_meta), _json_resp(contents)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_repo_focus_files("test/archived-repo", ["README.md"])

    assert result["archived"] is True


def test_fetch_repo_focus_files_returns_empty_on_repo_meta_url_error():
    """_fetch_repo_focus_files returns empty result struct when repo meta fetch raises URLError."""
    with patch("urllib.request.urlopen", side_effect=_url_error()), \
         patch("time.sleep"):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert result["repo"] == "test/repo"
    assert result["files"] == []
    assert result["default_branch"] == ""


def test_fetch_repo_focus_files_returns_empty_on_repo_meta_http_error():
    """_fetch_repo_focus_files returns empty result when repo meta fetch raises HTTPError(404)."""
    with patch("urllib.request.urlopen", side_effect=_http_error(404)):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert result["files"] == []


def test_fetch_repo_focus_files_traverses_directory_entries():
    """_fetch_repo_focus_files recurses into dir-type entries and collects recognised files."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    # Focus path returns a dir entry
    focus_contents = [
        {"type": "dir", "name": "docs", "path": "docs",
         "html_url": "https://github.com/t/r/tree/main/docs"},
    ]
    # Sub-directory contents: .md and .py; only .md is recognised by _is_best_practice_file
    sub_contents = [
        {"type": "file", "name": "security.md", "path": "docs/security.md",
         "html_url": "https://github.com/t/r/blob/main/docs/security.md",
         "download_url": "https://raw.githubusercontent.com/t/r/main/docs/security.md"},
        {"type": "file", "name": "helper.py", "path": "docs/helper.py",
         "html_url": "https://github.com/t/r/blob/main/docs/helper.py",
         "download_url": ""},
    ]
    responses = iter([_json_resp(repo_meta), _json_resp(focus_contents), _json_resp(sub_contents)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    file_names = [f["name"] for f in result["files"]]
    assert "security.md" in file_names
    # .py files are not recognised best-practice files and must be excluded
    assert "helper.py" not in file_names


def test_fetch_repo_focus_files_deduplicates_same_path():
    """_fetch_repo_focus_files does not add the same path twice across focus paths."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    # Same file returned from two focus paths
    file_entry = {"type": "file", "name": "README.md", "path": "README.md",
                  "html_url": "https://github.com/t/r/blob/main/README.md",
                  "download_url": "https://raw.githubusercontent.com/t/r/main/README.md"}

    responses = iter([
        _json_resp(repo_meta),
        _json_resp([file_entry]),  # first focus path response
        _json_resp([file_entry]),  # second focus path response (duplicate)
    ])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md", "README.md"])

    paths = [f["path"] for f in result["files"]]
    assert paths.count("README.md") == 1


def test_fetch_repo_focus_files_caps_results_at_80():
    """_fetch_repo_focus_files returns at most 80 files."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    # Return 100 .md files from the focus path
    many_files = [
        {"type": "file", "name": f"file{i:03d}.md", "path": f"file{i:03d}.md",
         "html_url": f"https://github.com/t/r/blob/main/file{i:03d}.md",
         "download_url": f"https://raw.githubusercontent.com/t/r/main/file{i:03d}.md"}
        for i in range(100)
    ]
    responses = iter([_json_resp(repo_meta), _json_resp(many_files)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_repo_focus_files("test/repo", ["files"])

    assert len(result["files"]) <= 80


# ===========================================================================
# _fetch_markdown_preview
# ===========================================================================


def test_fetch_markdown_preview_happy_path_returns_html():
    """_fetch_markdown_preview returns HTML div when content is valid markdown."""
    md_content = b"# Security Checklist\n- [ ] Enable MFA\n- Use strong passwords\n"

    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}), \
         patch("urllib.request.urlopen", return_value=_raw_resp(md_content)):
        result = dac._fetch_markdown_preview("https://raw.githubusercontent.com/test/repo/main/README.md")

    assert result.startswith('<div class="bp-audit-preview">')
    assert "Security Checklist" in result
    assert "Enable MFA" in result


def test_fetch_markdown_preview_empty_url_returns_empty_string():
    """_fetch_markdown_preview returns empty string for empty URL."""
    result = dac._fetch_markdown_preview("")
    assert result == ""


def test_fetch_markdown_preview_offline_mode_returns_empty_string():
    """_fetch_markdown_preview returns empty string when CLAUDESEC_DASHBOARD_OFFLINE=1."""
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
        result = dac._fetch_markdown_preview("https://raw.githubusercontent.com/test/repo/main/README.md")
    assert result == ""


def test_fetch_markdown_preview_network_error_returns_empty_string():
    """_fetch_markdown_preview returns empty string when urlopen raises any exception."""
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}), \
         patch("urllib.request.urlopen", side_effect=Exception("timeout")):
        result = dac._fetch_markdown_preview("https://raw.githubusercontent.com/test/repo/main/README.md")
    assert result == ""


def test_fetch_markdown_preview_disallowed_host_returns_empty_string():
    """_fetch_markdown_preview returns empty string for URLs not on allowed hosts."""
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}):
        result = dac._fetch_markdown_preview("https://evil.example.com/malicious.md")
    assert result == ""


def test_fetch_markdown_preview_http_scheme_only():
    """_fetch_markdown_preview returns empty string for http:// (non-https) URLs."""
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}):
        result = dac._fetch_markdown_preview("http://raw.githubusercontent.com/test/repo/main/README.md")
    assert result == ""


def test_fetch_markdown_preview_empty_content_returns_empty_string():
    """_fetch_markdown_preview returns empty string when fetched content is blank."""
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}), \
         patch("urllib.request.urlopen", return_value=_raw_resp(b"\n\n\n")):
        result = dac._fetch_markdown_preview("https://raw.githubusercontent.com/test/repo/main/README.md")
    assert result == ""


def test_fetch_markdown_preview_respects_max_lines():
    """_fetch_markdown_preview truncates output to max_lines."""
    # 30 non-empty lines
    many_lines = "\n".join(f"- item {i}" for i in range(30)).encode()
    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}), \
         patch("urllib.request.urlopen", return_value=_raw_resp(many_lines)):
        result = dac._fetch_markdown_preview(
            "https://raw.githubusercontent.com/test/repo/main/README.md",
            max_lines=5
        )
    assert result.count("bp-audit-item") == 5


# ===========================================================================
# Exported constants shape checks
# ===========================================================================


def test_ms_best_practices_repo_sources_is_non_empty_list():
    """MS_BEST_PRACTICES_REPO_SOURCES is a non-empty list."""
    assert isinstance(dac.MS_BEST_PRACTICES_REPO_SOURCES, list)
    assert len(dac.MS_BEST_PRACTICES_REPO_SOURCES) > 0


def test_ms_best_practices_repo_sources_entries_have_required_keys():
    """Each entry in MS_BEST_PRACTICES_REPO_SOURCES has product, repo, label, trust_level."""
    for src in dac.MS_BEST_PRACTICES_REPO_SOURCES:
        assert "product" in src
        assert "repo" in src
        assert "label" in src
        assert "trust_level" in src


def test_saas_best_practices_sources_is_non_empty_list():
    """SAAS_BEST_PRACTICES_SOURCES is a non-empty list."""
    assert isinstance(dac.SAAS_BEST_PRACTICES_SOURCES, list)
    assert len(dac.SAAS_BEST_PRACTICES_SOURCES) > 0


def test_saas_best_practices_sources_entries_have_required_keys():
    """Each entry in SAAS_BEST_PRACTICES_SOURCES has product, repo, label, trust_level."""
    for src in dac.SAAS_BEST_PRACTICES_SOURCES:
        assert "product" in src
        assert "repo" in src
        assert "label" in src
        assert "trust_level" in src


def test_saas_best_practices_cache_ttl_hours_is_positive_int():
    """SAAS_BEST_PRACTICES_CACHE_TTL_HOURS is a positive integer."""
    assert isinstance(dac.SAAS_BEST_PRACTICES_CACHE_TTL_HOURS, int)
    assert dac.SAAS_BEST_PRACTICES_CACHE_TTL_HOURS > 0


# ===========================================================================
# _fetch_microsoft_best_practices_from_github
# ===========================================================================


def test_fetch_microsoft_best_practices_returns_expected_keys(monkeypatch):
    """_fetch_microsoft_best_practices_from_github returns dict with fetched_at, sources."""
    # Mock _fetch_repo_focus_files to avoid any network calls
    fake_repo_data = {
        "repo": "microsoft/SecCon-Framework",
        "repo_url": "https://github.com/microsoft/SecCon-Framework",
        "default_branch": "main",
        "updated_at": "2026-01-01T00:00:00Z",
        "archived": False,
        "files": [],
    }
    monkeypatch.delenv("CLAUDESEC_MS_SOURCE_FILTER", raising=False)
    monkeypatch.delenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", raising=False)

    with patch.object(dac, "_fetch_repo_focus_files", return_value=fake_repo_data):
        result = dac._fetch_microsoft_best_practices_from_github()

    assert "fetched_at" in result
    assert "sources" in result
    assert isinstance(result["sources"], list)


def test_fetch_microsoft_best_practices_drops_archived_sources(monkeypatch):
    """_fetch_microsoft_best_practices_from_github excludes archived repos from sources."""
    archived_repo_data = {
        "repo": "microsoft/SecCon-Framework",
        "repo_url": "https://github.com/microsoft/SecCon-Framework",
        "default_branch": "main",
        "updated_at": "2024-01-01T00:00:00Z",
        "archived": True,
        "files": [],
    }
    monkeypatch.delenv("CLAUDESEC_MS_SOURCE_FILTER", raising=False)
    monkeypatch.delenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", raising=False)

    with patch.object(dac, "_fetch_repo_focus_files", return_value=archived_repo_data):
        result = dac._fetch_microsoft_best_practices_from_github()

    # All archived → should produce no sources (or a subset that had non-archived,
    # but since all return archived=True, sources must be empty)
    for src in result["sources"]:
        assert src["archived"] is False, "Archived repos must be dropped"


# ===========================================================================
# _fetch_saas_best_practices_from_github
# ===========================================================================


def test_fetch_saas_best_practices_returns_expected_keys(monkeypatch):
    """_fetch_saas_best_practices_from_github returns dict with fetched_at and sources."""
    fake_repo_data = {
        "repo": "okta/okta-developer-docs",
        "repo_url": "https://github.com/okta/okta-developer-docs",
        "default_branch": "main",
        "updated_at": "2026-01-01T00:00:00Z",
        "archived": False,
        "files": [],
    }

    with patch.object(dac, "_fetch_repo_focus_files", return_value=fake_repo_data):
        result = dac._fetch_saas_best_practices_from_github()

    assert "fetched_at" in result
    assert "sources" in result
    assert isinstance(result["sources"], list)


def test_fetch_saas_best_practices_drops_archived_sources(monkeypatch):
    """_fetch_saas_best_practices_from_github excludes archived repos."""
    archived_repo_data = {
        "repo": "okta/okta-developer-docs",
        "repo_url": "https://github.com/okta/okta-developer-docs",
        "default_branch": "main",
        "updated_at": "2024-01-01T00:00:00Z",
        "archived": True,
        "files": [],
    }

    with patch.object(dac, "_fetch_repo_focus_files", return_value=archived_repo_data):
        result = dac._fetch_saas_best_practices_from_github()

    for src in result["sources"]:
        assert src["archived"] is False, "Archived repos must be excluded"


# ===========================================================================
# Additional error-fallback branch tests — line 215, 231, 251, 256, 270, 273,
# 324, 354-360, 365-368, 377, 383-389, 391, 394, 396, 414, 421, 468, 553
# ===========================================================================


def test_github_api_json_429_with_numeric_retry_after_uses_header(monkeypatch):
    """_github_api_json uses Retry-After header value when it is a digit string (line 215)."""
    # First call: 429 with Retry-After: 3; second call: success
    fake_headers = MagicMock()
    fake_headers.get = lambda k, d=None: "3" if k == "Retry-After" else d
    err_429 = urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=429,
        msg="Too Many Requests",
        hdrs=fake_headers,
        fp=None,
    )
    payload = {"default_branch": "main"}
    call_count = [0]

    def side_effect(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise err_429
        return _json_resp(payload)

    sleeps = []
    with patch("urllib.request.urlopen", side_effect=side_effect), \
         patch("time.sleep", side_effect=lambda s: sleeps.append(s)):
        result = dac._github_api_json("https://api.github.com/repos/test/repo", _max_retries=2)

    assert result["default_branch"] == "main"
    # Retry-After "3" → wait = min(3, 60) = 3
    assert sleeps[0] == 3


def test_github_api_json_zero_retries_raises_last_exc():
    """_github_api_json with _max_retries=0 raises last_exc sentinel (line 230-231)."""
    # With _max_retries=0, the for loop never runs, last_exc stays None → hits raise RuntimeError.
    # But line 229-230 guard: if last_exc is not None raise last_exc, else RuntimeError.
    # Pass 0 retries to hit RuntimeError on line 231.
    with pytest.raises(RuntimeError, match="unreachable"):
        dac._github_api_json("https://api.github.com/repos/test/repo", _max_retries=0)


def test_fetch_audit_points_skips_non_dict_root_items():
    """_fetch_audit_points_from_github skips non-dict items in root list (line 251)."""
    # Include a non-dict item (a string) alongside a valid dir item
    root_payload = [
        "not-a-dict",
        {"type": "dir", "name": "policies", "html_url": "https://github.com/q/ap/tree/main/policies"},
    ]
    sub_payload: list = []
    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    # Only the valid dict dir item should produce a product
    assert len(result["products"]) == 1
    assert result["products"][0]["name"] == "policies"


def test_fetch_audit_points_skips_readme_md_named_dir():
    """_fetch_audit_points_from_github skips items named 'README.md' (line 256)."""
    # A dir item named "README.md" should be skipped
    root_payload = [
        {"type": "dir", "name": "README.md", "html_url": "https://github.com/q/ap/tree/main/README.md"},
        {"type": "dir", "name": "real-product", "html_url": "https://github.com/q/ap/tree/main/real-product"},
    ]
    sub_payload: list = []
    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    product_names = [p["name"] for p in result["products"]]
    assert "README.md" not in product_names
    assert "real-product" in product_names


def test_fetch_audit_points_sub_response_non_list_becomes_empty_files():
    """_fetch_audit_points_from_github treats non-list sub-response as empty files (line 270)."""
    root_payload = [
        {"type": "dir", "name": "policies", "html_url": "https://github.com/q/ap/tree/main/policies"},
    ]
    # Sub-request returns a dict instead of a list
    sub_payload = {"message": "Not Found"}
    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    assert len(result["products"]) == 1
    assert result["products"][0]["files"] == []


def test_fetch_audit_points_skips_non_dict_children():
    """_fetch_audit_points_from_github skips non-dict items in sub-directory listing (line 273)."""
    root_payload = [
        {"type": "dir", "name": "policies", "html_url": "https://github.com/q/ap/tree/main/policies"},
    ]
    # Sub-listing contains a non-dict (a string) alongside a valid file entry
    sub_payload = [
        "not-a-dict",
        {"type": "file", "name": "checklist.md", "html_url": "https://github.com/q/ap/blob/main/policies/checklist.md", "download_url": "https://raw.githubusercontent.com/q/ap/main/policies/checklist.md"},
    ]
    responses = iter([_json_resp(root_payload), _json_resp(sub_payload)])

    with patch("urllib.request.urlopen", side_effect=lambda *a, **kw: next(responses)):
        result = dac._fetch_audit_points_from_github()

    assert result is not None
    assert len(result["products"]) == 1
    # Only the dict file entry should be collected
    assert len(result["products"][0]["files"]) == 1
    assert result["products"][0]["files"][0]["name"] == "checklist.md"


def test_fetch_repo_focus_files_returns_empty_when_meta_not_dict():
    """_fetch_repo_focus_files returns empty result when repo meta is not a dict (line 324)."""
    # _github_api_json returns a list instead of a dict for repo meta
    with patch.object(dac, "_github_api_json", return_value=["not", "a", "dict"]):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert result["repo"] == "test/repo"
    assert result["files"] == []
    assert result["default_branch"] == ""


def test_fetch_repo_focus_files_focus_path_fetch_error_continues():
    """_fetch_repo_focus_files skips a focus path when its fetch raises (lines 354-360)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    file_entry = {"type": "file", "name": "README.md", "path": "README.md",
                  "html_url": "https://github.com/t/r/blob/main/README.md",
                  "download_url": "https://raw.githubusercontent.com/t/r/main/README.md"}
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        if call_count[0] == 2:
            # First focus path raises
            raise urllib.error.URLError("network error")
        # Second focus path returns valid file
        return [file_entry]

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["broken-path", "README.md"])

    # The broken focus path is skipped; the working one produces a file
    assert len(result["files"]) == 1
    assert result["files"][0]["name"] == "README.md"


def test_fetch_repo_focus_files_payload_is_dict_treated_as_single_entry():
    """_fetch_repo_focus_files handles dict payload (single file) as single-element list (lines 365-366)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    # Contents endpoint returns a single dict for a file (not a list)
    single_file = {"type": "file", "name": "README.md", "path": "README.md",
                   "html_url": "https://github.com/t/r/blob/main/README.md",
                   "download_url": "https://raw.githubusercontent.com/t/r/main/README.md"}
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        return single_file  # dict, not list

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert len(result["files"]) == 1
    assert result["files"][0]["name"] == "README.md"


def test_fetch_repo_focus_files_payload_is_non_list_non_dict_skipped():
    """_fetch_repo_focus_files skips focus path when payload is neither list nor dict (lines 367-368)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        return "a-string-payload"  # neither list nor dict

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["README.md"])

    assert result["files"] == []


def test_fetch_repo_focus_files_dir_entry_with_no_path_skipped():
    """_fetch_repo_focus_files skips dir entries that have no path field (line 377)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    # Dir entry missing "path"
    focus_contents = [
        {"type": "dir", "name": "docs"},  # no "path" key
    ]
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        return focus_contents

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    assert result["files"] == []


def test_fetch_repo_focus_files_sub_dir_fetch_error_continues():
    """_fetch_repo_focus_files skips a sub-directory whose fetch raises (lines 383-389)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    focus_contents = [
        {"type": "dir", "name": "docs", "path": "docs",
         "html_url": "https://github.com/t/r/tree/main/docs"},
    ]
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        if call_count[0] == 2:
            return focus_contents  # focus path: dir entry
        # Sub-dir fetch raises
        raise urllib.error.URLError("network error")

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    assert result["files"] == []


def test_fetch_repo_focus_files_sub_dir_children_not_list_skipped():
    """_fetch_repo_focus_files skips sub-directory when children is not a list (line 391)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    focus_contents = [
        {"type": "dir", "name": "docs", "path": "docs",
         "html_url": "https://github.com/t/r/tree/main/docs"},
    ]
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        if call_count[0] == 2:
            return focus_contents
        return {"message": "not a list"}  # sub-dir returns dict

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    assert result["files"] == []


def test_fetch_repo_focus_files_non_dict_child_skipped():
    """_fetch_repo_focus_files skips non-dict child items in sub-dir listing (line 394)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    focus_contents = [
        {"type": "dir", "name": "docs", "path": "docs",
         "html_url": "https://github.com/t/r/tree/main/docs"},
    ]
    sub_contents = [
        "not-a-dict",  # non-dict child
        {"type": "file", "name": "security.md", "path": "docs/security.md",
         "html_url": "https://github.com/t/r/blob/main/docs/security.md",
         "download_url": ""},
    ]
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        if call_count[0] == 2:
            return focus_contents
        return sub_contents

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    # The string child is skipped; the dict file entry is collected
    assert len(result["files"]) == 1
    assert result["files"][0]["name"] == "security.md"


def test_fetch_repo_focus_files_non_file_child_skipped():
    """_fetch_repo_focus_files skips sub-dir child items that are not type 'file' (line 396)."""
    repo_meta = {"default_branch": "main", "pushed_at": "2026-01-01T00:00:00Z", "archived": False}
    focus_contents = [
        {"type": "dir", "name": "docs", "path": "docs",
         "html_url": "https://github.com/t/r/tree/main/docs"},
    ]
    sub_contents = [
        {"type": "dir", "name": "subdir", "path": "docs/subdir"},  # dir type — skipped
        {"type": "file", "name": "guide.md", "path": "docs/guide.md",
         "html_url": "https://github.com/t/r/blob/main/docs/guide.md",
         "download_url": ""},
    ]
    call_count = [0]

    def fake_github_api_json(url):
        call_count[0] += 1
        if call_count[0] == 1:
            return repo_meta
        if call_count[0] == 2:
            return focus_contents
        return sub_contents

    with patch.object(dac, "_github_api_json", side_effect=fake_github_api_json):
        result = dac._fetch_repo_focus_files("test/repo", ["docs"])

    file_names = [f["name"] for f in result["files"]]
    assert "subdir" not in file_names
    assert "guide.md" in file_names


def test_fetch_microsoft_best_practices_skips_disallowed_trust_level(monkeypatch):
    """_fetch_microsoft_best_practices_from_github skips sources whose trust_level is not allowed (line 414)."""
    # Set source filter to "official" — excludes "Government" and "Community"
    monkeypatch.setenv("CLAUDESEC_MS_SOURCE_FILTER", "official")
    monkeypatch.delenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", raising=False)
    fake_repo_data = {
        "repo": "microsoft/SecCon-Framework",
        "repo_url": "https://github.com/microsoft/SecCon-Framework",
        "default_branch": "main",
        "updated_at": "2026-01-01T00:00:00Z",
        "archived": False,
        "files": [],
    }
    with patch.object(dac, "_fetch_repo_focus_files", return_value=fake_repo_data):
        result = dac._fetch_microsoft_best_practices_from_github()

    # Only "Microsoft Official" sources should be present; "Government" ones are filtered
    for src in result["sources"]:
        assert src["trust_level"] == "Microsoft Official"


def test_fetch_microsoft_best_practices_skips_invalid_repo_entry(monkeypatch):
    """_fetch_microsoft_best_practices_from_github skips sources with non-string repo (line 421)."""
    monkeypatch.delenv("CLAUDESEC_MS_SOURCE_FILTER", raising=False)
    monkeypatch.delenv("CLAUDESEC_MS_INCLUDE_SCUBAGEAR", raising=False)
    # Patch MS_BEST_PRACTICES_REPO_SOURCES with an entry having a bad repo field
    fake_sources = [
        {
            "product": "Test",
            "repo": 12345,  # not a string
            "label": "Bad Source",
            "trust_level": "Microsoft Official",
            "reason": "test",
            "focus_paths": ["README.md"],
        },
    ]
    with patch.object(dac, "MS_BEST_PRACTICES_REPO_SOURCES", fake_sources):
        result = dac._fetch_microsoft_best_practices_from_github()

    assert result["sources"] == []


def test_fetch_saas_best_practices_skips_invalid_repo_entry(monkeypatch):
    """_fetch_saas_best_practices_from_github skips sources with non-string repo (line 468)."""
    fake_sources = [
        {
            "product": "TestSaaS",
            "repo": None,  # not a string
            "label": "Bad SaaS Source",
            "trust_level": "Vendor Official",
            "reason": "test",
            "focus_paths": ["README.md"],
        },
    ]
    with patch.object(dac, "SAAS_BEST_PRACTICES_SOURCES", fake_sources):
        result = dac._fetch_saas_best_practices_from_github()

    assert result["sources"] == []


def test_fetch_markdown_preview_plain_text_line_renders_audit_text():
    """_fetch_markdown_preview wraps plain text lines in bp-audit-text div (line 553)."""
    # A line that is not a heading and not a bullet
    md_content = b"This is a plain text paragraph.\n"

    with patch.dict(os.environ, {"CLAUDESEC_DASHBOARD_OFFLINE": "0"}), \
         patch("urllib.request.urlopen", return_value=_raw_resp(md_content)):
        result = dac._fetch_markdown_preview("https://raw.githubusercontent.com/test/repo/main/README.md")

    assert 'class="bp-audit-text"' in result
    assert "This is a plain text paragraph." in result
