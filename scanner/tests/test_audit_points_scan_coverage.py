"""
Targeted coverage tests for scanner/lib/audit-points-scan.py.

Covers the specific missing lines identified by --cov-report=term-missing:
  28-29   — OSError in _has_nexus_indicator open()
  45-46   — OSError in _file_contains_any open()
  59-60   — OSError in _has_scalr_in_terraform open()
  118-119 — Exception in _fetch_and_cache except block
  138-139 — OSError in load_cache cache-write path
  189     — `if __name__ == "__main__"` guard (subprocess test)

Import: audit-points-scan.py contains hyphens; loaded via importlib following
the same pattern as test_audit_points_scan_pure.py and test_audit_points_scan_smoke.py.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_module():
    path = Path(__file__).resolve().parents[1] / "lib" / "audit-points-scan.py"
    spec = importlib.util.spec_from_file_location("audit_points_scan_cov", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


# ===========================================================================
# Lines 28-29 — _has_nexus_indicator: OSError in open()
# ===========================================================================


class TestHasNexusIndicatorOSError(unittest.TestCase):
    """
    When a pom.xml exists but open() raises OSError, the except on lines
    28-29 must be executed and the function must return False rather than
    propagating the error.
    """

    def test_oserror_on_open_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            pom = os.path.join(d, "pom.xml")
            with open(pom, "w", encoding="utf-8") as f:
                f.write("<project>nexus</project>")

            real_open = open

            def _raise_on_pom(path, *args, **kwargs):
                if os.path.basename(path) == "pom.xml":
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_pom):
                result = MOD._has_nexus_indicator(d)

        self.assertFalse(result)


# ===========================================================================
# Lines 45-46 — _file_contains_any: OSError in open()
# ===========================================================================


class TestFileContainsAnyOSError(unittest.TestCase):
    """
    When a matching file exists but open() raises OSError, the except on
    lines 45-46 must be executed and the function must return False
    rather than propagating the error.
    """

    def test_oserror_on_open_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.yml")
            with open(cfg, "w", encoding="utf-8") as f:
                f.write("okta: true")

            real_open = open

            def _raise_on_cfg(path, *args, **kwargs):
                if path == cfg:
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_cfg):
                result = MOD._file_contains_any(d, ["okta"], [".yml"])

        self.assertFalse(result)


# ===========================================================================
# Lines 59-60 — _has_scalr_in_terraform: OSError in open()
# ===========================================================================


class TestHasScalrInTerraformOSError(unittest.TestCase):
    """
    When a .tf file exists but open() raises OSError, the except on lines
    59-60 must be executed and the function must return False.
    """

    def test_oserror_on_open_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "infra")
            os.makedirs(sub)
            tf = os.path.join(sub, "backend.tf")
            with open(tf, "w", encoding="utf-8") as f:
                f.write('backend "scalr" {}')

            real_open = open

            def _raise_on_tf(path, *args, **kwargs):
                if path == tf:
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_tf):
                result = MOD._has_scalr_in_terraform(d)

        self.assertFalse(result)


# ===========================================================================
# Lines 118-119 — _fetch_and_cache: Exception in exec_module
# ===========================================================================


class TestFetchAndCacheExceptBranch(unittest.TestCase):
    """
    _fetch_and_cache tries to import and call dashboard-gen.py.
    When spec.loader.exec_module raises any exception, lines 118-119
    catch it and return the empty stub.
    """

    def test_exception_in_exec_module_returns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            # Create a fake dashboard-gen.py that will raise at exec time
            dash = os.path.join(d, "dashboard-gen.py")
            with open(dash, "w", encoding="utf-8") as f:
                f.write("raise RuntimeError('simulated failure')\n")

            with patch.object(MOD, "__file__", os.path.join(d, "audit-points-scan.py")):
                result = MOD._fetch_and_cache(d)

        self.assertEqual(result, {"products": [], "fetched_at": ""})


# ===========================================================================
# Lines 138-139 — load_cache: OSError on cache write
# ===========================================================================


class TestLoadCacheWriteOSError(unittest.TestCase):
    """
    When _fetch_and_cache returns products and the subsequent cache write
    raises OSError, lines 138-139 catch it and the function still returns
    the fetched data (no exception propagation).
    """

    def test_oserror_on_cache_write_returns_data(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"products": [{"name": "Jenkins", "files": []}], "fetched_at": "t"}

            with patch.object(MOD, "_fetch_and_cache", return_value=data):
                real_open = open

                def _raise_on_write(path, mode="r", *args, **kwargs):
                    if "w" in mode:
                        raise OSError("disk full")
                    return real_open(path, mode, *args, **kwargs)

                with patch("builtins.open", side_effect=_raise_on_write):
                    result = MOD.load_cache(d)

        self.assertEqual(result, data)


# ===========================================================================
# Line 189 — if __name__ == "__main__" guard
# ===========================================================================


class TestMainEntrypoint(unittest.TestCase):
    """
    Line 189 (`if __name__ == "__main__": sys.exit(main())`) is only
    executed when the module is run directly.  We exercise it via subprocess
    so the module's __name__ is "__main__".
    """

    def test_main_runs_as_subprocess(self):
        script = Path(__file__).resolve().parents[1] / "lib" / "audit-points-scan.py"
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run(
                [sys.executable, str(script), d],
                capture_output=True,
                text=True,
                timeout=15,
            )
        # Must exit 0 and emit a JSON line on stdout
        self.assertEqual(result.returncode, 0)
        output = result.stdout.strip()
        obj = json.loads(output)
        self.assertIn("detected", obj)
        self.assertIn("item_count", obj)


if __name__ == "__main__":
    unittest.main()
