"""
Tests for `_augment_scan_report` in scanner/lib/dashboard-gen.py.

Background
----------
`scan-report.json` is written by output.sh BEFORE dashboard-gen.py runs, and it
carried nine keys — none of them compliance. The compliance / OWASP / Prowler
rollups were computed in dashboard-gen and rendered ONLY into the standalone
HTML dashboard, so the ISMS dashboard at `/` (which already fetches
scan-report.json) could not show framework posture without a second page.

`_augment_scan_report` publishes those rollups back into the report. Two
properties matter and are pinned here:

1. **Additive.** The keys output.sh wrote must survive verbatim — diagram-gen.py
   reads them, and a scan that already succeeded must not have its report
   rewritten into something a consumer no longer recognizes.
2. **Best-effort.** A missing, malformed, or non-object report must not raise:
   the scan has already completed by this point, and failing here would turn a
   successful scan into a failed command. This mirrors the diagram generation in
   output.sh, which is likewise guarded.

stdlib-only, no network, tmpdir fixtures only.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, _LIB)

_spec = importlib.util.spec_from_file_location(
    "dashboard_gen_augment", os.path.join(_LIB, "dashboard-gen.py")
)
_dgen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_dgen)


def _write_report(directory, payload):
    path = os.path.join(directory, "scan-report.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
    return path


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestAugmentIsAdditive(unittest.TestCase):
    def test_existing_keys_survive_verbatim(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(
                d,
                '{"passed":3,"failed":1,"warnings":2,"skipped":4,"total":10,'
                '"score":90,"grade":"A","duration":7,"findings":[{"id":"X"}]}',
            )
            self.assertTrue(_dgen._augment_scan_report(d, {}, {}, {}))
            report = json.loads(_read(path))
            for key, value in (
                ("passed", 3), ("failed", 1), ("warnings", 2), ("skipped", 4),
                ("total", 10), ("score", 90), ("grade", "A"), ("duration", 7),
            ):
                self.assertEqual(report[key], value, f"{key} was not preserved")
            self.assertEqual(report["findings"], [{"id": "X"}])

    def test_compliance_summary_is_published_including_na(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, '{"passed":0}')
            summary = {"SOC 2 (TSC)": {"pass": 6, "fail": 0, "na": 3, "total": 6}}
            _dgen._augment_scan_report(d, summary, {}, {})
            published = json.loads(_read(path))["compliance"]["SOC 2 (TSC)"]
            # `na` specifically: a framework with non-assessable controls must
            # not read as all-pass in the ISMS view.
            self.assertEqual(published["na"], 3)
            self.assertEqual(published["total"], 6)

    def test_owasp_counts_track_the_map_and_cover_all_ten(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, '{"passed":0}')
            first, second = _dgen.OWASP_2025[0]["id"], _dgen.OWASP_2025[1]["id"]
            _dgen._augment_scan_report(d, {}, {first: [1, 2, 3]}, {})
            entries = json.loads(_read(path))["owasp"]
            self.assertEqual(len(entries), 10)
            counts = {e["id"]: e["count"] for e in entries}
            self.assertEqual(counts[first], 3)
            # A category with no findings is published as 0 rather than omitted,
            # so the consumer can render a complete Top 10 without inventing rows.
            self.assertEqual(counts[second], 0)

    def test_version_and_timestamp_are_stamped(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, '{"passed":0}')
            _dgen._augment_scan_report(d, {}, {}, {})
            report = json.loads(_read(path))
            self.assertEqual(report["scanner_version"], _dgen.VERSION)
            self.assertTrue(report["generated_at"].endswith("Z"))


class TestAugmentIsBestEffort(unittest.TestCase):
    """The scan has already succeeded by this point — nothing here may raise."""

    def test_missing_report_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(_dgen._augment_scan_report(d, {}, {}, {}))

    def test_malformed_report_is_left_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, "{not json")
            self.assertFalse(_dgen._augment_scan_report(d, {}, {}, {}))
            # Not merely "did not raise": the bad file must not be half-rewritten.
            self.assertEqual(_read(path), "{not json")

    def test_json_array_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, "[1,2,3]")
            self.assertFalse(_dgen._augment_scan_report(d, {}, {}, {}))
            self.assertEqual(_read(path), "[1,2,3]")

    def test_no_temp_file_is_left_behind(self):
        with tempfile.TemporaryDirectory() as d:
            _write_report(d, '{"passed":1}')
            _dgen._augment_scan_report(d, {}, {}, {})
            self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])

    def test_unwritable_directory_returns_false_and_leaves_no_temp(self):
        # The `except OSError` arm: the report exists and parses, but the write
        # fails (read-only dir). A scan that already succeeded must not die here,
        # and the half-written temp file must not survive to confuse the next run.
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, '{"passed":1}')
            os.chmod(d, 0o500)
            try:
                self.assertFalse(_dgen._augment_scan_report(d, {}, {}, {}))
            finally:
                os.chmod(d, 0o700)
            self.assertEqual(_read(path), '{"passed":1}')
            self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])

    def test_result_is_valid_json_not_a_truncated_write(self):
        # os.replace makes the swap atomic; assert the observable consequence
        # rather than the mechanism.
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(d, '{"passed":1}')
            _dgen._augment_scan_report(d, {}, {}, {})
            json.loads(_read(path))


if __name__ == "__main__":
    unittest.main()
