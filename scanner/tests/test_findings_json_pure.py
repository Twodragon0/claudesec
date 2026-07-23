"""
Unit tests for scanner/lib/findings_json.py.

This module was extracted from the inline bash string-concatenation that
used to live in scanner/lib/output.sh's `_emit_finding_json` (see that
file's `generate_html_dashboard`). These tests exercise `build_findings_json`
in-process so coverage.py actually measures it — the bash subprocess
invocation (`python3 findings_json.py` fed via a piped NUL/\x1f record
stream) is invisible to `--cov=scanner/lib`.

Run: python3 -m pytest scanner/tests/test_findings_json_pure.py -q
"""

import io
import json
import os
import runpy
import sys

import pytest

LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, os.path.abspath(LIB_DIR))

import findings_json as fj  # noqa: E402


def _rec(severity_label="high", finding_id="CHK-001", title="Title",
         remediation="", details="", category="code", location=""):
    """Build a 7-field record tuple in build_findings_json()'s fixed order."""
    return (severity_label, finding_id, title, remediation, details, category, location)


class TestBuildFindingsJsonPure:
    def test_empty_records_yields_empty_array(self):
        assert fj.build_findings_json([]) == "[]"

    def test_both_details_and_remediation_present(self):
        rec = _rec(details="actual detail text", remediation="apply this fix")
        result = json.loads(fj.build_findings_json([rec]))
        assert result == [
            {
                "id": "CHK-001",
                "title": "Title",
                "severity": "high",
                "category": "code",
                "details": "actual detail text",
                "remediation": "apply this fix",
            }
        ]

    def test_details_only_omits_remediation_key(self):
        rec = _rec(details="only detail", remediation="")
        result = json.loads(fj.build_findings_json([rec]))
        assert result[0]["details"] == "only detail"
        assert "remediation" not in result[0]

    def test_remediation_only_omits_details_key(self):
        rec = _rec(details="", remediation="only fix")
        result = json.loads(fj.build_findings_json([rec]))
        assert result[0]["remediation"] == "only fix"
        assert "details" not in result[0]

    def test_neither_details_nor_remediation_present(self):
        rec = _rec(details="", remediation="")
        result = json.loads(fj.build_findings_json([rec]))
        assert "details" not in result[0]
        assert "remediation" not in result[0]

    def test_location_omitted_when_empty(self):
        rec = _rec(location="")
        result = json.loads(fj.build_findings_json([rec]))
        assert "location" not in result[0]

    def test_location_present_when_set(self):
        rec = _rec(location="/etc/passwd")
        result = json.loads(fj.build_findings_json([rec]))
        assert result[0]["location"] == "/etc/passwd"

    def test_key_order_matches_pre_refactor_schema(self):
        rec = _rec(details="d", remediation="r", location="/x")
        raw = fj.build_findings_json([rec])
        # json.dumps with dict input preserves insertion order in the
        # emitted text (Python 3.7+ dicts are ordered); assert the exact
        # key sequence id/title/severity/category/details/remediation/location.
        assert raw.startswith(
            '[{"id":"CHK-001","title":"Title","severity":"high",'
            '"category":"code","details":"d","remediation":"r","location":"/x"}]'
        )

    def test_multiple_records_preserve_order(self):
        records = [
            _rec(finding_id="CHK-001", title="First"),
            _rec(finding_id="CHK-002", title="Second"),
        ]
        result = json.loads(fj.build_findings_json(records))
        assert [r["id"] for r in result] == ["CHK-001", "CHK-002"]

    def test_special_characters_newline_backslash_quote(self):
        """The exact bug this refactor fixes: the old bash concat only
        escaped double-quotes, so a backslash produced invalid JSON, and a
        "|"-packed real newline truncated the read."""
        details = 'line1\nline2 with "quote" and back\\slash'
        rec = _rec(details=details)
        raw = fj.build_findings_json([rec])
        # Must be valid JSON (would raise if the backslash broke it).
        result = json.loads(raw)
        assert result[0]["details"] == details

    def test_unicode_passthrough_not_ascii_escaped(self):
        rec = _rec(title="한글 제목 — 유니코드")
        raw = fj.build_findings_json([rec])
        # ensure_ascii=False: Unicode should appear literally, not as \uXXXX.
        assert "한글 제목" in raw
        assert json.loads(raw)[0]["title"] == "한글 제목 — 유니코드"

    def test_embedded_unit_separator_delimiter_in_details_field(self):
        """A details value that happens to already contain the pack
        delimiter (\\x1f) must still round-trip correctly through
        build_findings_json — this function receives pre-split fields, so
        the delimiter, once split upstream, is just ordinary text here."""
        details = "value\x1fwith\x1funit-separators"
        rec = _rec(details=details)
        result = json.loads(fj.build_findings_json([rec]))
        assert result[0]["details"] == details


class TestIterRecords:
    def test_empty_stdin_yields_no_records(self):
        assert list(fj._iter_records("")) == []

    def test_single_record_nul_terminated(self):
        raw = "high\x1fCHK-001\x1fTitle\x1frem\x1fdet\x1fcode\x1floc\0"
        records = list(fj._iter_records(raw))
        assert records == [("high", "CHK-001", "Title", "rem", "det", "code", "loc")]

    def test_multiple_records(self):
        raw = (
            "high\x1fCHK-001\x1fT1\x1f\x1f\x1fcode\x1f\0"
            "low\x1fCHK-002\x1fT2\x1f\x1f\x1finfra\x1f\0"
        )
        records = list(fj._iter_records(raw))
        assert len(records) == 2
        assert records[0][1] == "CHK-001"
        assert records[1][1] == "CHK-002"

    def test_record_with_embedded_real_newline_in_details_field(self):
        raw = "high\x1fCHK-001\x1fTitle\x1frem\x1fline1\nline2\x1fcode\x1floc\0"
        records = list(fj._iter_records(raw))
        assert records == [
            ("high", "CHK-001", "Title", "rem", "line1\nline2", "code", "loc")
        ]

    def test_malformed_record_wrong_field_count_raises(self):
        raw = "high\x1fCHK-001\x1fonly-three-fields\0"
        try:
            list(fj._iter_records(raw))
        except ValueError as exc:
            assert "7" in str(exc)
        else:
            raise AssertionError("expected ValueError for malformed record")


class TestMainCliDriver:
    def test_main_empty_stdin_prints_empty_array(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        rc = fj.main()
        assert rc == 0
        assert capsys.readouterr().out.strip() == "[]"

    def test_main_reads_stdin_and_prints_json(self, monkeypatch, capsys):
        raw = "critical\x1fCHK-099\x1fTitle\x1frem\x1fdet\x1fcode\x1f\0"
        monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
        rc = fj.main()
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out == [
            {
                "id": "CHK-099",
                "title": "Title",
                "severity": "critical",
                "category": "code",
                "details": "det",
                "remediation": "rem",
            }
        ]

    def test_module_main_guard_runs_via_runpy(self, monkeypatch, capsys):
        """Exercise the `if __name__ == "__main__": sys.exit(main())` guard,
        which a normal `import` never executes."""
        module_path = os.path.join(LIB_DIR, "findings_json.py")
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))

        with pytest.raises(SystemExit) as exc_info:
            runpy.run_path(module_path, run_name="__main__")

        assert exc_info.value.code == 0
        assert capsys.readouterr().out.strip() == "[]"
