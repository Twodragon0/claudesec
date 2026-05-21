"""
Targeted coverage tests for scanner/lib/diagram-gen.py.

Covers the specific missing lines identified by --cov-report=term-missing:
  73-74    — except Exception: providers[name] = [] in load_prowler_files
  159-182  — drawio_cell called with vertex=False (edge mode), source/target args
  292-293  — prowler_list non-empty branch in generate_scan_flow_diagram
  469      — targets = [] guard when report["targets"] is not a list
  476-477  — except Exception: file_count = 0 in network topology page
  490      — continue when a target entry is not a dict
  908-923  — main() function body
  927      — if __name__ == "__main__": main() (subprocess)

Import: diagram-gen.py contains hyphens; loaded via importlib following the
same pattern as test_diagram_gen_pure_helpers.py.
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
import xml.etree.ElementTree as ET


def _load_diagram_gen():
    path = Path(__file__).resolve().parents[1] / "lib" / "diagram-gen.py"
    spec = importlib.util.spec_from_file_location("diagram_gen_cov", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_diagram_gen()


def _agg(**overrides):
    base = {
        "scan": {
            "score": 0,
            "grade": "F",
            "total": 0,
            "failed": 0,
            "warnings": 0,
            "findings": [],
        },
        "prowler_providers": [],
        "prowler_summary": {},
        "history_count": 0,
    }
    base.update(overrides)
    return base


# ===========================================================================
# Lines 73-74 — load_prowler_files: except Exception → providers[name] = []
# ===========================================================================


class TestLoadProwlerFilesExceptionFallback(unittest.TestCase):
    """
    When a prowler OCSF file exists but open() raises, the except on
    lines 73-74 must execute and set providers[name] to [].
    """

    def test_oserror_on_open_sets_provider_to_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            fpath = os.path.join(d, "prowler-aws.ocsf.json")
            with open(fpath, "w") as f:
                f.write('[{"id": "x"}]')

            real_open = open

            def _raise_on_ocsf(path, *args, **kwargs):
                if path == fpath:
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=_raise_on_ocsf):
                providers = MOD.load_prowler_files(d)

        self.assertIn("aws", providers)
        self.assertEqual(providers["aws"], [])


# ===========================================================================
# Lines 159-182 — drawio_cell: vertex=False (edge) branch + source/target
# ===========================================================================


class TestDrawioCellEdgeMode(unittest.TestCase):
    """
    drawio_cell with vertex=False creates an edge geometry.
    Lines 174-181 (the `else` branch) are only exercised when vertex=False.
    """

    def _make_root(self):
        root, gr = MOD.create_drawio_root()
        return gr

    def test_edge_mode_does_not_set_vertex_attribute(self):
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=10, vertex=False)
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "10"]
        self.assertEqual(len(cells), 1)
        cell = cells[0]
        # vertex=False → "edge" attribute set, not "vertex"
        self.assertEqual(cell.get("edge"), "1")
        self.assertIsNone(cell.get("vertex"))

    def test_edge_geometry_has_relative_attribute(self):
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=11, vertex=False)
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "11"]
        geom = cells[0].find("mxGeometry")
        self.assertIsNotNone(geom)
        self.assertEqual(geom.get("relative"), "1")

    def test_edge_with_source_sets_sourcePoint(self):
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=12, vertex=False, source="src-pt")
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "12"]
        geom = cells[0].find("mxGeometry")
        self.assertEqual(geom.get("sourcePoint"), "src-pt")

    def test_edge_with_target_sets_targetPoint(self):
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=13, vertex=False, target="tgt-pt")
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "13"]
        geom = cells[0].find("mxGeometry")
        self.assertEqual(geom.get("targetPoint"), "tgt-pt")

    def test_edge_without_source_or_target_no_extra_attributes(self):
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=14, vertex=False)
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "14"]
        geom = cells[0].find("mxGeometry")
        self.assertIsNone(geom.get("sourcePoint"))
        self.assertIsNone(geom.get("targetPoint"))

    def test_vertex_mode_does_not_set_edge_attribute(self):
        """Confirm vertex=True (default) uses the vertex branch, not the else."""
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=15, vertex=True)
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "15"]
        cell = cells[0]
        self.assertEqual(cell.get("vertex"), "1")
        self.assertIsNone(cell.get("edge"))

    def test_value_is_set_when_provided(self):
        """Line 162: cell.set('value', ...) executes when value is not None."""
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=20, value="my label")
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "20"]
        self.assertEqual(cells[0].get("value"), "my label")

    def test_style_is_set_when_provided(self):
        """Line 164: cell.set('style', ...) executes when style is truthy."""
        gr = self._make_root()
        MOD.drawio_cell(gr, cell_id=21, style="rounded=1;")
        cells = [c for c in gr.iter("mxCell") if c.get("id") == "21"]
        self.assertEqual(cells[0].get("style"), "rounded=1;")


# ===========================================================================
# Lines 292-293 — _overview_architecture_page: prowler_list non-empty branch
# ===========================================================================


class TestOverviewArchitecturePageProwlerLabel(unittest.TestCase):
    """
    Lines 292-293 are inside _overview_architecture_page (called by
    generate_overview_drawio). They build prowler_label when prowler_list
    is non-empty.
    """

    def test_prowler_providers_appear_in_overview_drawio(self):
        with tempfile.TemporaryDirectory() as scan_dir:
            out = os.path.join(scan_dir, "ov.drawio")
            agg = _agg(
                prowler_providers=["aws", "gcp"],
                prowler_summary={"aws": {"fail": 1, "total": 2}, "gcp": {"fail": 0, "total": 1}},
            )
            MOD.generate_overview_drawio(agg, scan_dir, out)
            content = Path(out).read_text(encoding="utf-8")
        # Both provider names appear in the prowler_label cell value
        self.assertIn("aws", content)
        self.assertIn("gcp", content)

    def test_more_than_five_providers_truncated_in_overview_drawio(self):
        with tempfile.TemporaryDirectory() as scan_dir:
            out = os.path.join(scan_dir, "ov.drawio")
            agg = _agg(
                prowler_providers=["a", "b", "c", "d", "e", "f", "g"],
                prowler_summary={p: {"fail": 0, "total": 0} for p in "abcdefg"},
            )
            MOD.generate_overview_drawio(agg, scan_dir, out)
            content = Path(out).read_text(encoding="utf-8")
        self.assertIn("...", content)


# ===========================================================================
# Lines 469, 476-477, 490 — _overview_network_topology_page edge cases
# ===========================================================================


class TestOverviewNetworkTopologyEdgeCases(unittest.TestCase):
    """
    These lines are inside _overview_network_topology_page, called by
    generate_overview_drawio.

    Line 469: targets = [] when report["targets"] is not a list.
    Lines 476-477: except Exception: file_count = 0 when glob raises.
    Line 490: continue when a target entry in shown is not a dict.
    """

    def test_targets_not_a_list_defaults_to_empty(self):
        """Line 469: report["targets"] is a dict, not list → targets = []."""
        with tempfile.TemporaryDirectory() as scan_dir:
            net_dir = os.path.join(scan_dir, ".claudesec-network")
            os.makedirs(net_dir)
            with open(os.path.join(net_dir, "network-report.v1.json"), "w") as f:
                json.dump({"targets": {"not": "a-list"}}, f)
            out = os.path.join(scan_dir, "ov.drawio")
            MOD.generate_overview_drawio(_agg(), scan_dir, out)
            content = Path(out).read_text(encoding="utf-8")
        # Zero targets → "Targets: 0" in the summary cell
        self.assertIn("Targets: 0", content)

    def test_non_dict_target_is_skipped(self):
        """Line 490: a non-dict entry in targets triggers `continue`."""
        with tempfile.TemporaryDirectory() as scan_dir:
            net_dir = os.path.join(scan_dir, ".claudesec-network")
            os.makedirs(net_dir)
            with open(os.path.join(net_dir, "network-report.v1.json"), "w") as f:
                json.dump({
                    "targets": [
                        "not-a-dict",
                        {"host": "valid.example", "port": 443,
                         "dns": {"ips": []}, "tls": {"grade": "A"},
                         "http": {"status": 200, "issues": []}},
                    ]
                }, f)
            out = os.path.join(scan_dir, "ov.drawio")
            # Must not raise, and output file must be created
            MOD.generate_overview_drawio(_agg(), scan_dir, out)
            self.assertTrue(Path(out).is_file())

    def test_glob_exception_sets_file_count_to_zero(self):
        """Lines 476-477: if net_dir.glob raises, file_count defaults to 0."""
        with tempfile.TemporaryDirectory() as scan_dir:
            net_dir = os.path.join(scan_dir, ".claudesec-network")
            os.makedirs(net_dir)
            with open(os.path.join(net_dir, "network-report.v1.json"), "w") as f:
                json.dump({"targets": []}, f)

            out = os.path.join(scan_dir, "ov.drawio")
            # Patch Path.glob only for the net_dir to simulate a glob failure
            # inside _overview_network_topology_page.
            original_glob = Path.glob

            call_count = [0]

            def _raise_on_first_glob(self_path, pattern, *args, **kwargs):
                if pattern == "**/*" and call_count[0] == 0:
                    call_count[0] += 1
                    raise OSError("glob failed")
                return original_glob(self_path, pattern, *args, **kwargs)

            with patch.object(Path, "glob", _raise_on_first_glob):
                MOD.generate_overview_drawio(_agg(), scan_dir, out)

            # Output file must still be created (exception was caught internally)
            self.assertTrue(Path(out).is_file())


# ===========================================================================
# Lines 908-923 — main() function body
# ===========================================================================


class TestMainFunction(unittest.TestCase):
    """
    Lines 908-923: the main() function constructs out_dir, calls
    aggregate_scan_data and all six generate_* functions.

    We call main() directly with sys.argv patched and a temp scan dir,
    then verify all six output files were created.
    """

    def test_main_generates_all_six_diagrams(self):
        with tempfile.TemporaryDirectory() as scan_dir, \
             tempfile.TemporaryDirectory() as out_dir:
            with patch.dict(os.environ, {"CLAUDESEC_SCAN_DIR": scan_dir}), \
                 patch("sys.argv", ["diagram-gen.py", out_dir]):
                MOD.main()

            files = os.listdir(out_dir)
            self.assertIn("claudesec-overview.drawio", files)
            self.assertIn("claudesec-overview.svg", files)
            self.assertIn("claudesec-architecture.svg", files)
            self.assertIn("claudesec-architecture.drawio", files)
            self.assertIn("claudesec-scan-flow.drawio", files)
            self.assertIn("claudesec-security-domains.drawio", files)

    def test_main_default_out_dir_uses_docs_architecture(self):
        """When sys.argv has no extra arg, out_dir defaults to scan_dir/docs/architecture."""
        with tempfile.TemporaryDirectory() as scan_dir:
            with patch.dict(os.environ, {"CLAUDESEC_SCAN_DIR": scan_dir}), \
                 patch("sys.argv", ["diagram-gen.py"]):
                MOD.main()

            expected_dir = os.path.join(scan_dir, "docs", "architecture")
            self.assertTrue(os.path.isdir(expected_dir))
            self.assertIn("claudesec-overview.drawio", os.listdir(expected_dir))


# ===========================================================================
# Line 927 — if __name__ == "__main__": main() (subprocess)
# ===========================================================================


class TestMainEntrypoint(unittest.TestCase):
    """
    Line 927 (`if __name__ == "__main__": main()`) is only executed when
    the module is run directly as a script.  We verify it via subprocess.
    """

    def test_main_runs_as_subprocess_without_error(self):
        script = Path(__file__).resolve().parents[1] / "lib" / "diagram-gen.py"
        with tempfile.TemporaryDirectory() as scan_dir, \
             tempfile.TemporaryDirectory() as out_dir:
            env = os.environ.copy()
            env["CLAUDESEC_SCAN_DIR"] = scan_dir
            env["CLAUDESEC_DASHBOARD_OFFLINE"] = "1"
            result = subprocess.run(
                [sys.executable, str(script), out_dir],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("Generating diagrams", result.stdout)


if __name__ == "__main__":
    unittest.main()
