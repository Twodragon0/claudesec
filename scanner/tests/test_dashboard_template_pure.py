"""
Unit tests for scanner/lib/dashboard_template.py.

Targets previously-uncovered branches (sys.path insertion, scan_dir and
repo_root exception handlers, open() exception in the SVG read loop, and
the inline-SVG fallback).  Stdlib + unittest.mock only so CI's
`python3 -m xmlrunner discover` can run the suite unchanged.
"""

import base64
import importlib
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

_LIB_DIR = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, _LIB_DIR)

import dashboard_template  # noqa: E402


# ---------------------------------------------------------------------------
# 1. _apply_template_and_write
# ---------------------------------------------------------------------------


class TestApplyTemplateAndWrite(unittest.TestCase):
    def test_replacements_and_nonce_injection(self):
        template = "<script nonce=\"{{CSP_NONCE}}\">{{MSG}}</script>"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.html")
            dashboard_template._apply_template_and_write(
                out, template, {"MSG": "hello"}
            )
            with open(out, encoding="utf-8") as f:
                content = f.read()
        self.assertIn("hello", content)
        # Placeholder replaced with a non-empty nonce.
        self.assertNotIn("{{CSP_NONCE}}", content)
        self.assertIn("<script nonce=\"", content)

    def test_multiple_replacements_applied(self):
        template = "A={{A}} B={{B}} N={{CSP_NONCE}}"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x.html")
            dashboard_template._apply_template_and_write(
                out, template, {"A": "1", "B": "two"}
            )
            text = open(out, encoding="utf-8").read()
        self.assertIn("A=1", text)
        self.assertIn("B=two", text)


# ---------------------------------------------------------------------------
# 2. Module-level sys.path insertion branch (line 16)
# ---------------------------------------------------------------------------


class TestSysPathInsertion(unittest.TestCase):
    def test_module_load_inserts_lib_dir_when_missing(self):
        """Load dashboard_template directly from its file path with its
        lib dir absent from sys.path, proving the top-level `sys.path.insert`
        branch (line 16) runs during module evaluation."""
        src_path = os.path.abspath(dashboard_template.__file__)
        lib_dir = os.path.dirname(src_path)
        saved_path = list(sys.path)
        saved_module = sys.modules.pop("dashboard_template", None)
        try:
            sys.path[:] = [p for p in sys.path if os.path.abspath(p) != lib_dir]
            self.assertNotIn(lib_dir, [os.path.abspath(p) for p in sys.path])
            spec = importlib.util.spec_from_file_location(
                "dashboard_template_reloaded", src_path
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertTrue(hasattr(mod, "_apply_template_and_write"))
            # After execution the module inserted its lib dir into sys.path.
            self.assertIn(lib_dir, [os.path.abspath(p) for p in sys.path])
        finally:
            sys.path[:] = saved_path
            if saved_module is not None:
                sys.modules["dashboard_template"] = saved_module


# ---------------------------------------------------------------------------
# 3. _get_architecture_diagram_html - inline fallback & exception branches
# ---------------------------------------------------------------------------


class TestGetArchitectureDiagramHtml(unittest.TestCase):
    def _call_with_isolated_cwd(self, *, scan_dir="", output_file=""):
        """Run the helper from a temp cwd so no real SVGs are found."""
        with tempfile.TemporaryDirectory() as tmp_cwd:
            # Patch repo_root discovery so the real repo docs/architecture
            # SVG cannot be picked up during the test.
            with patch.object(
                dashboard_template.os.path,
                "dirname",
                wraps=dashboard_template.os.path.dirname,
            ):
                prev = os.getcwd()
                try:
                    os.chdir(tmp_cwd)
                    return dashboard_template._get_architecture_diagram_html(
                        output_file, scan_dir=scan_dir
                    )
                finally:
                    os.chdir(prev)

    def test_returns_inline_svg_when_no_candidates_exist(self):
        # Use fake __file__ path under a temp dir so repo_root branch cannot
        # resolve to the real project directory.
        with tempfile.TemporaryDirectory() as fake_root:
            fake_lib = os.path.join(fake_root, "scanner", "lib")
            os.makedirs(fake_lib)
            fake_file = os.path.join(fake_lib, "dashboard_template.py")
            with open(fake_file, "w") as f:
                f.write("")
            with patch.object(dashboard_template, "__file__", fake_file):
                prev = os.getcwd()
                try:
                    os.chdir(fake_root)
                    html = dashboard_template._get_architecture_diagram_html(
                        "", scan_dir=""
                    )
                finally:
                    os.chdir(prev)
        self.assertIn("arch-diagram-wrap", html)
        self.assertIn("<svg", html)

    def test_svg_file_loaded_and_base64_embedded(self):
        with tempfile.TemporaryDirectory() as d:
            docs = os.path.join(d, "docs", "architecture")
            os.makedirs(docs)
            svg_path = os.path.join(docs, "claudesec-overview.svg")
            svg_content = "<svg>hello</svg>"
            with open(svg_path, "w", encoding="utf-8") as f:
                f.write(svg_content)
            # scan_dir branch picks up the SVG first.
            html = dashboard_template._get_architecture_diagram_html(
                "", scan_dir=d
            )
        b64 = base64.b64encode(svg_content.encode("utf-8")).decode("ascii")
        self.assertIn(b64, html)
        self.assertIn("ClaudeSec Overview Architecture", html)

    def test_architecture_svg_label_when_overview_missing(self):
        with tempfile.TemporaryDirectory() as d:
            docs = os.path.join(d, "docs", "architecture")
            os.makedirs(docs)
            svg_path = os.path.join(docs, "claudesec-architecture.svg")
            with open(svg_path, "w", encoding="utf-8") as f:
                f.write("<svg>arch</svg>")
            html = dashboard_template._get_architecture_diagram_html(
                "", scan_dir=d
            )
        self.assertIn('alt="ClaudeSec Architecture"', html)
        self.assertNotIn("Overview Architecture", html)

    def test_scan_dir_exception_is_swallowed(self):
        # Force os.path.abspath to raise ONLY on the exact scan_dir value so
        # the try/except on lines 80-81 is executed.  Other abspath calls
        # (e.g. for __file__) still work via the wraps delegate.
        real_abspath = os.path.abspath
        sentinel = "__boom_scan_dir__"

        def fake_abspath(p):
            if p == sentinel:
                raise OSError("boom")
            return real_abspath(p)

        with tempfile.TemporaryDirectory() as fake_root:
            fake_lib = os.path.join(fake_root, "scanner", "lib")
            os.makedirs(fake_lib)
            fake_file = os.path.join(fake_lib, "dashboard_template.py")
            with open(fake_file, "w") as f:
                f.write("")
            with patch.object(dashboard_template, "__file__", fake_file):
                with patch.object(
                    dashboard_template.os.path, "abspath", side_effect=fake_abspath
                ):
                    prev = os.getcwd()
                    try:
                        os.chdir(fake_root)
                        html = dashboard_template._get_architecture_diagram_html(
                            "", scan_dir=sentinel
                        )
                    finally:
                        os.chdir(prev)
        # No SVG produced; inline fallback returned.
        self.assertIn("arch-diagram-wrap", html)

    def test_repo_root_exception_is_swallowed(self):
        # Make dashboard_template.__file__ something that os.path.abspath
        # rejects so the try/except on lines 95-96 triggers.
        real_abspath = os.path.abspath

        def fake_abspath(p):
            # The module file lookup happens with the module's __file__.
            if p == dashboard_template.__file__:
                raise RuntimeError("cannot resolve")
            return real_abspath(p)

        with tempfile.TemporaryDirectory() as tmp_cwd:
            prev = os.getcwd()
            try:
                os.chdir(tmp_cwd)
                with patch.object(
                    dashboard_template.os.path, "abspath", side_effect=fake_abspath
                ):
                    html = dashboard_template._get_architecture_diagram_html(
                        "", scan_dir=""
                    )
            finally:
                os.chdir(prev)
        # Fell through to inline SVG fallback.
        self.assertIn("arch-diagram-wrap", html)

    def test_unreadable_svg_triggers_continue_then_fallback(self):
        # Create a valid SVG file path, but make open() raise so the
        # try/except on lines 109-110 runs and the loop continues; with no
        # readable alternative we reach the inline return on line 111.
        with tempfile.TemporaryDirectory() as d:
            docs = os.path.join(d, "docs", "architecture")
            os.makedirs(docs)
            svg_path = os.path.join(docs, "claudesec-overview.svg")
            with open(svg_path, "w", encoding="utf-8") as f:
                f.write("<svg/>")
            real_open = open

            def fake_open(path, *args, **kwargs):
                if str(path).endswith("claudesec-overview.svg") or str(path).endswith(
                    "claudesec-architecture.svg"
                ):
                    raise IOError("no read")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=fake_open):
                html = dashboard_template._get_architecture_diagram_html(
                    "", scan_dir=d
                )
        self.assertIn("arch-diagram-wrap", html)
        self.assertIn("<svg", html)

    def test_output_file_branch_contributes_candidates(self):
        # When output_file is given, its parent's docs/architecture is
        # searched.  Drop an SVG there and confirm it is read.
        with tempfile.TemporaryDirectory() as d:
            docs = os.path.join(d, "docs", "architecture")
            os.makedirs(docs)
            svg = os.path.join(docs, "claudesec-overview.svg")
            with open(svg, "w", encoding="utf-8") as f:
                f.write("<svg>out</svg>")
            out = os.path.join(d, "dashboard.html")
            html = dashboard_template._get_architecture_diagram_html(out)
        self.assertIn("data:image/svg+xml;base64,", html)


# ---------------------------------------------------------------------------
# 4. _load_html_template
# ---------------------------------------------------------------------------


class TestLoadHtmlTemplate(unittest.TestCase):
    def test_loads_repository_template(self):
        html = dashboard_template._load_html_template()
        self.assertIsInstance(html, str)
        self.assertGreater(len(html), 0)


if __name__ == "__main__":
    unittest.main()
