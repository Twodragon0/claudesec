"""
Unit tests for scanner/lib/prowler_compliance_summary.py.

This module was extracted from the inline `python3 -c "..."` heredoc that
used to live in scanner/lib/output_prowler.sh's
_prowler_compliance_summary_json (see that file's function comment). These
tests exercise every branch in-process so coverage.py actually measures it —
the bash subprocess invocation (`python3 prowler_compliance_summary.py
<dir>`) is invisible to `--cov=scanner/lib`.

Run: python3 -m pytest scanner/tests/test_prowler_compliance_summary.py -q
"""

import importlib.util
import json
import os
import runpy
import sys

import pytest

LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, os.path.abspath(LIB_DIR))

import prowler_compliance_summary as pcs  # noqa: E402


FAIL_ARRAY = """[
  {
    "status_code": "FAIL",
    "message": "S3 bucket public read access detected",
    "metadata": {"event_code": "s3_bucket_public_access"},
    "finding_info": {"title": "S3 Bucket Public Access"},
    "unmapped": {"compliance": {"iso27001_2022": ["A.5.1"]}}
  },
  {
    "status_code": "PASS",
    "message": "MFA enabled for root account",
    "metadata": {"event_code": "iam_root_mfa_enabled"},
    "finding_info": {"title": "Root Account MFA"},
    "unmapped": {"compliance": {"iso27001_2022": ["A.8.2"]}}
  }
]
"""

PASS_ONLY_ARRAY = """[
  {
    "status_code": "PASS",
    "message": "OK",
    "metadata": {"event_code": "everything_fine"},
    "finding_info": {"title": "All good"},
    "unmapped": {"compliance": {}}
  }
]
"""

FAIL_NDJSON = (
    '{"status_code":"FAIL","message":"IAM weak policy",'
    '"metadata":{"event_code":"iam_weak_pwd"},'
    '"finding_info":{"title":"Weak IAM policy"},'
    '"unmapped":{"compliance":{"iso27001_2022":["A.8.5"]}}}\n'
    '{"status_code":"FAIL","message":"Encryption disabled",'
    '"metadata":{"event_code":"rds_encryption_off"},'
    '"finding_info":{"title":"RDS Encryption"},'
    '"unmapped":{"compliance":{"iso27001_2022":["A.8.5"]}}}\n'
)

MALFORMED = "not-json{{{\n"


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_build_summary_json_array_fail_findings(tmp_path):
    _write(tmp_path, "prowler-aws.ocsf.json", FAIL_ARRAY)

    result = pcs.build_summary(str(tmp_path))

    assert result != ""
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert len(parsed) > 0
    assert any(
        isinstance(v, dict) and {"pass", "fail", "na", "total"} <= v.keys()
        for v in parsed.values()
    )


def test_build_summary_ndjson_fail_findings(tmp_path):
    _write(tmp_path, "prowler-ndjson.ocsf.json", FAIL_NDJSON)

    result = pcs.build_summary(str(tmp_path))

    assert result != ""
    parsed = json.loads(result)
    assert len(parsed) > 0


def test_build_summary_pass_only_returns_empty(tmp_path):
    _write(tmp_path, "prowler-pass-only.ocsf.json", PASS_ONLY_ARRAY)

    assert pcs.build_summary(str(tmp_path)) == ""


def test_build_summary_malformed_json_tolerated(tmp_path):
    _write(tmp_path, "prowler-bad.ocsf.json", MALFORMED)

    assert pcs.build_summary(str(tmp_path)) == ""


def test_build_summary_empty_dir_returns_empty(tmp_path):
    assert pcs.build_summary(str(tmp_path)) == ""


def test_build_summary_mixed_malformed_and_valid(tmp_path):
    _write(tmp_path, "prowler-bad.ocsf.json", MALFORMED)
    _write(tmp_path, "prowler-aws.ocsf.json", FAIL_ARRAY)

    result = pcs.build_summary(str(tmp_path))

    assert result != ""
    parsed = json.loads(result)
    assert len(parsed) > 0


def test_load_compliance_map_exposes_public_api():
    module = pcs._load_compliance_map()

    assert hasattr(module, "map_compliance")
    assert hasattr(module, "compliance_summary")


def test_main_with_argv_prints_json_and_returns_zero(tmp_path, capsys):
    _write(tmp_path, "prowler-aws.ocsf.json", FAIL_ARRAY)

    rc = pcs.main([str(tmp_path)])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    json.loads(captured.out.strip())


def test_main_with_pass_only_dir_prints_nothing(tmp_path, capsys):
    _write(tmp_path, "prowler-pass-only.ocsf.json", PASS_ONLY_ARRAY)

    rc = pcs.main([str(tmp_path)])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_main_with_empty_argv_returns_zero_prints_nothing(capsys):
    rc = pcs.main([])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_main_with_none_argv_uses_sys_argv(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["prowler_compliance_summary.py"])

    rc = pcs.main(None)

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_module_main_guard_runs_via_runpy(monkeypatch, capsys):
    """Exercise the `if __name__ == "__main__": sys.exit(main())` guard,
    which normal `import` never executes."""
    module_path = os.path.join(LIB_DIR, "prowler_compliance_summary.py")
    monkeypatch.setattr(sys, "argv", ["prowler_compliance_summary.py"])

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(module_path, run_name="__main__")

    assert exc_info.value.code == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
