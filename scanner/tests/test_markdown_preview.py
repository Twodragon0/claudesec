"""Tests for _fetch_markdown_preview in dashboard-gen.py."""

import importlib.util
import io
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

MODULE_PATH = Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
SPEC = importlib.util.spec_from_file_location("dashboard_gen", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Failed to load module spec for {MODULE_PATH}")
dashboard_gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_gen)


class TestFetchMarkdownPreview(unittest.TestCase):
    """Unit tests for _fetch_markdown_preview()."""

    def _mock_urlopen(self, text: str):
        """Create a mock context manager for urllib.request.urlopen."""
        resp = MagicMock()
        resp.read.return_value = text.encode("utf-8")
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_empty_url_returns_empty(self):
        self.assertEqual(dashboard_gen._fetch_markdown_preview(""), "")

    def test_offline_mode_returns_empty(self):
        with patch.dict("os.environ", {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertEqual(result, "")

    def test_network_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertEqual(result, "")

    def test_heading_rendered(self):
        md = "# Security Checklist\n## Sub heading\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("bp-audit-heading", result)
        self.assertIn("Security Checklist", result)
        self.assertIn("Sub heading", result)

    def test_checkbox_items_rendered(self):
        md = "- [ ] Enable MFA\n- [x] Configure SSO\n- [X] Rotate keys\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("Enable MFA", result)
        self.assertIn("Configure SSO", result)
        self.assertIn("Rotate keys", result)
        self.assertEqual(result.count("bp-audit-item"), 3)

    def test_bullet_items_rendered(self):
        md = "- First item\n- Second item\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("First item", result)
        self.assertIn("Second item", result)

    def test_plain_text_rendered(self):
        md = "Some plain text line\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("bp-audit-text", result)
        self.assertIn("Some plain text line", result)

    def test_html_escaped(self):
        md = "- <script>alert(1)</script>\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_max_lines_limit(self):
        md = "\n".join(f"- Item {i}" for i in range(50))
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview(
                "https://example.com/file.md", max_lines=5
            )
        self.assertEqual(result.count("bp-audit-item"), 5)

    def test_empty_content_returns_empty(self):
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen("")):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertEqual(result, "")

    def test_blank_lines_skipped(self):
        md = "\n\n# Title\n\n- Item\n\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("Title", result)
        self.assertIn("Item", result)

    def test_checkbox_without_label(self):
        md = "- [ ]\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertIn("bp-audit-item", result)

    def test_wrapper_div_present(self):
        md = "- Item\n"
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen(md)):
            result = dashboard_gen._fetch_markdown_preview("https://example.com/file.md")
        self.assertTrue(result.startswith('<div class="bp-audit-preview">'))
        self.assertTrue(result.endswith("</div>"))


class TestHtmlEscape(unittest.TestCase):
    """Tests for the h() HTML escape function."""

    def test_escapes_angle_brackets(self):
        self.assertIn("&lt;", dashboard_gen.h("<b>"))
        self.assertIn("&gt;", dashboard_gen.h("<b>"))

    def test_escapes_ampersand(self):
        self.assertIn("&amp;", dashboard_gen.h("a & b"))

    def test_escapes_quotes(self):
        self.assertIn("&quot;", dashboard_gen.h('"hello"'))


if __name__ == "__main__":
    unittest.main()
