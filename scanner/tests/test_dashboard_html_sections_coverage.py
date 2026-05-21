"""
Coverage tests for scanner/lib/dashboard_html_sections.py.

Missing lines before this file:
  14  — sys.path.insert guard (executed at import time)
  60  — _build_service_surface_html delegation wrapper body
  65  — _build_priority_queue_html delegation wrapper body
  70  — _build_network_config_section delegation wrapper body
  75  — _build_tooling_readiness_section delegation wrapper body

All four wrapper functions delegate to sibling modules and are tested here
by patching the underlying functions so we stay free of network/filesystem I/O.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import dashboard_html_sections as sections  # noqa: E402


class TestSysPathGuard(unittest.TestCase):
    """Line 14: the sys.path.insert guard runs at import time."""

    def test_lib_dir_in_sys_path(self):
        lib_dir = os.path.join(os.path.dirname(__file__), "..", "lib")
        lib_dir = os.path.normpath(lib_dir)
        # At least one entry in sys.path matches the lib directory
        normalized = [os.path.normpath(p) for p in sys.path]
        self.assertIn(lib_dir, normalized)


class TestBuildServiceSurfaceHtmlWrapper(unittest.TestCase):
    """Line 60: _build_service_surface_html calls the delegated implementation."""

    def test_delegates_and_returns_result(self):
        sentinel = "<div>service-surface</div>"
        with patch.object(sections, "build_service_surface_html", return_value=sentinel) as mock_fn:
            result = sections._build_service_surface_html({"key": "val"}, extra="arg")
            mock_fn.assert_called_once_with({"key": "val"}, extra="arg")
            self.assertEqual(result, sentinel)


class TestBuildPriorityQueueHtmlWrapper(unittest.TestCase):
    """Line 65: _build_priority_queue_html calls the delegated implementation."""

    def test_delegates_and_returns_result(self):
        sentinel = "<div>priority-queue</div>"
        with patch.object(sections, "build_priority_queue_html", return_value=sentinel) as mock_fn:
            result = sections._build_priority_queue_html({"findings": []}, limit=10)
            mock_fn.assert_called_once_with({"findings": []}, limit=10)
            self.assertEqual(result, sentinel)


class TestBuildNetworkConfigSectionWrapper(unittest.TestCase):
    """Line 70: _build_network_config_section calls the delegated implementation."""

    def test_delegates_and_returns_result(self):
        sentinel = "<section>network-config</section>"
        with patch.object(sections, "build_network_config_section", return_value=sentinel) as mock_fn:
            result = sections._build_network_config_section()
            mock_fn.assert_called_once_with()
            self.assertEqual(result, sentinel)


class TestBuildToolingReadinessSectionWrapper(unittest.TestCase):
    """Line 75: _build_tooling_readiness_section calls the delegated implementation."""

    def test_delegates_and_returns_result(self):
        sentinel = "<section>tooling-readiness</section>"
        net_data = {"trivy": True}
        with patch.object(sections, "build_tooling_readiness_section", return_value=sentinel) as mock_fn:
            result = sections._build_tooling_readiness_section(net_data, True, ["host1"], True)
            mock_fn.assert_called_once_with(net_data, True, ["host1"], True)
            self.assertEqual(result, sentinel)


if __name__ == "__main__":
    unittest.main()
