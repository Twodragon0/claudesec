"""
Smoke tests for scanner/lib/audit-points-scan.py.

Import strategy: the filename contains hyphens so it cannot be imported
with a normal `import` statement. We use importlib.util.spec_from_file_location
with a safe module name.

Import-time side effects: the module defines constants and builds the
PRODUCT_DETECTORS list at import time but does NOT execute a scan.
It is safe to load eagerly in _load(); we use a lazy helper so that
each test can reload a clean state if needed.

Tested behaviours (all pure helpers — no network, no real credentials):
  - Module loads without error.
  - detect_products returns [] for an empty directory.
  - detect_products returns [] for a non-existent directory.
  - detect_products finds Jenkins when a Jenkinsfile is present.
  - detect_products finds IDEs when .vscode is present.
  - detect_products finds multiple products simultaneously.
  - _has_nexus_indicator returns False on empty directory.
  - _has_nexus_indicator returns True when pom.xml mentions nexus.
  - _file_contains_any returns False when no matching files exist.
  - _file_contains_any returns True when a matching file contains the keyword.
"""

import importlib.util
from pathlib import Path


def _load():
    path = Path(__file__).resolve().parents[1] / "lib" / "audit-points-scan.py"
    spec = importlib.util.spec_from_file_location("audit_points_scan", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_module_loads_without_error():
    mod = _load()
    assert mod is not None


def test_detect_products_returns_empty_list_for_empty_directory(tmp_path):
    mod = _load()
    result = mod.detect_products(str(tmp_path))
    assert result == []


def test_detect_products_returns_empty_list_for_nonexistent_directory(tmp_path):
    mod = _load()
    nonexistent = str(tmp_path / "does_not_exist")
    result = mod.detect_products(nonexistent)
    assert result == []


def test_detect_products_finds_jenkins_when_jenkinsfile_present(tmp_path):
    mod = _load()
    (tmp_path / "Jenkinsfile").write_text("pipeline {}", encoding="utf-8")
    result = mod.detect_products(str(tmp_path))
    assert "Jenkins" in result


def test_detect_products_finds_ides_when_vscode_directory_present(tmp_path):
    mod = _load()
    (tmp_path / ".vscode").mkdir()
    result = mod.detect_products(str(tmp_path))
    assert "IDEs" in result


def test_detect_products_finds_multiple_products_simultaneously(tmp_path):
    mod = _load()
    (tmp_path / "Jenkinsfile").write_text("pipeline {}", encoding="utf-8")
    (tmp_path / ".vscode").mkdir()
    (tmp_path / "harbor.yml").write_text("harbor: true", encoding="utf-8")
    result = mod.detect_products(str(tmp_path))
    assert "Jenkins" in result
    assert "IDEs" in result
    assert "Harbor" in result


def test_has_nexus_indicator_returns_false_for_empty_directory(tmp_path):
    mod = _load()
    result = mod._has_nexus_indicator(str(tmp_path))
    assert result is False


def test_has_nexus_indicator_returns_true_when_pom_mentions_nexus(tmp_path):
    mod = _load()
    pom = tmp_path / "pom.xml"
    pom.write_text(
        "<project><repositories><repository>"
        "<url>https://nexus.example.com/repo</url>"
        "</repository></repositories></project>",
        encoding="utf-8",
    )
    result = mod._has_nexus_indicator(str(tmp_path))
    assert result is True


def test_file_contains_any_returns_false_when_no_files_match(tmp_path):
    mod = _load()
    result = mod._file_contains_any(str(tmp_path), ["okta"], [".env"])
    assert result is False


def test_file_contains_any_returns_true_when_keyword_found_in_matching_file(tmp_path):
    mod = _load()
    env_file = tmp_path / ".env"
    env_file.write_text("OKTA_CLIENT_ID=abc123\n", encoding="utf-8")
    result = mod._file_contains_any(str(tmp_path), ["okta"], [".env"])
    assert result is True


def test_file_contains_any_returns_false_when_file_matches_suffix_but_not_keyword(tmp_path):
    mod = _load()
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=postgres://localhost/db\n", encoding="utf-8")
    result = mod._file_contains_any(str(tmp_path), ["okta"], [".env"])
    assert result is False


def test_load_cache_returns_dict_for_nonexistent_cache(tmp_path, monkeypatch):
    """load_cache should return a dict (possibly empty) without crashing when no
    cache file and no network is available. We patch _fetch_and_cache to avoid
    any real I/O."""
    mod = _load()
    monkeypatch.setattr(mod, "_fetch_and_cache", lambda d: {"products": [], "fetched_at": ""})
    result = mod.load_cache(str(tmp_path))
    assert isinstance(result, dict)
