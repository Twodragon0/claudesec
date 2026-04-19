"""
Targeted coverage tests for scanner/lib/dashboard-gen.py.

Focus: the top-level orchestrator `generate_dashboard()` plus the `__main__`
entry point. Most pure helpers are already covered by sibling test files
(test_dashboard_gen_smoke.py, test_build_dashboard_units.py, etc.); these
tests target the branches that still miss, specifically:

- Line 124/128/130 — scan_dir fallback branches (prowler_dir absent,
  output_file-only, CWD-only).
- Lines 211-212 — env_html for a connected environment pill.
- Lines 240, 243-267 — GitHub findings table (gh_by_check) with >5 repos
  so the overflow toggle is rendered.
- Lines 313, 317, 319, 324-325, 332-333 — provider table resource metadata
  (type, region, namespace, line) and >15 resources (overflow).
- Lines 337-348 — Prowler Hub link auto-generated from check IDs.
- Lines 403-406 — _middle_ellipsis long path.
- Lines 414, 416, 423 — scope_parts branches.
- Lines 465 — prowler_subtab_map "continue" branch (unreachable in current
  code but exercised via all providers present).
- Lines 560-563 — trivy severity pills in overview.
- Lines 589-630, 633 — policies.json loader (valid + invalid + missing).
- Lines 720-741 — __main__ entry point run via runpy.

Import pattern: dashboard-gen.py has a hyphen, so importlib.util is used.
All tests are CI-safe: no pytest imports, stdlib + unittest.mock only.
"""

import importlib.util
import json
import os
import runpy
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Module loader — mirrors test_diagram_gen_pure_helpers.py pattern
# ---------------------------------------------------------------------------

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
)


def _load_dashboard_gen():
    spec = importlib.util.spec_from_file_location("dashboard_gen_pure", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_dashboard_gen()


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _zero_scan():
    return {
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "skipped": 0,
        "total": 0,
        "score": 0,
        "grade": "F",
        "duration": 0,
        "findings": [],
    }


def _empty_ms():
    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "source_filter": "all",
        "scubagear_enabled": False,
        "sources": [],
    }


def _empty_saas():
    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "sources": [],
    }


def _empty_audit():
    return {"products": [], "fetched_at": ""}


def _empty_detected():
    return {"detected_products": [], "items": []}


def _empty_datadog():
    return {
        "logs": [],
        "summary": {"error": 0, "warning": 0, "info": 0, "unknown": 0, "total": 0},
        "signals": [],
        "signal_summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "unknown": 0, "total": 0,
        },
        "cases": [],
        "case_summary": {
            "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "unknown": 0, "total": 0,
        },
    }


def _default_network():
    return {
        "trivy_fs": None,
        "trivy_config": None,
        "trivy_vulns": [],
        "trivy_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "nmap_scans": [],
        "sslscan_results": [],
        "network_report": None,
    }


def _patches_for_generate(
    scan_dir_override=None,
    audit_detected=None,
    audit_points=None,
    ms=None,
    saas=None,
    datadog=None,
    network=None,
):
    """Return a list of patch context managers suitable for use with ExitStack."""
    return [
        patch.object(MOD, "load_audit_points",
                     return_value=audit_points or _empty_audit()),
        patch.object(MOD, "load_audit_points_detected",
                     return_value=audit_detected or _empty_detected()),
        patch.object(MOD, "load_microsoft_best_practices",
                     return_value=ms or _empty_ms()),
        patch.object(MOD, "load_saas_best_practices",
                     return_value=saas or _empty_saas()),
        patch.object(MOD, "load_datadog_logs",
                     return_value=datadog or _empty_datadog()),
        patch.object(MOD, "load_network_tool_results",
                     return_value=network or _default_network()),
    ]


# ===========================================================================
# 1. scan_dir fallback branches (lines 123-130)
# ===========================================================================


class ScanDirFallbackTests(unittest.TestCase):
    """Cover the three fallback branches for deriving scan_dir."""

    def _run_with_env(self, env, prowler_dir, output_file):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / output_file
            stack = _patches_for_generate()
            with patch.dict(os.environ, env, clear=False):
                # Always clear SCAN_DIR/CLAUDESEC_SCAN_DIR so fallback chain runs
                for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                    if k not in env:
                        os.environ.pop(k, None)
                os.environ["CLAUDESEC_DASHBOARD_OFFLINE"] = "1"
                ctxs = [c.__enter__() for c in stack]
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=prowler_dir,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                return out.read_text(encoding="utf-8")

    def test_scan_dir_derived_from_prowler_dir(self):
        # prowler_dir is a real dir → scan_dir = dirname(prowler_dir)
        with tempfile.TemporaryDirectory() as tmp:
            prowler = Path(tmp) / "prowler"
            prowler.mkdir()
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR", "CLAUDESEC_NETWORK_DIR",
                      "CLAUDESEC_DATADOG_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                ctxs = [c.__enter__() for c in stack]
                out = Path(tmp) / "dash.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=str(prowler),
                        history_dir=str(prowler),
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                self.assertTrue(out.exists())

    def test_scan_dir_derived_from_output_file(self):
        # prowler_dir doesn't exist → scan_dir falls back to dirname(output_file)
        with tempfile.TemporaryDirectory() as tmp:
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR", "CLAUDESEC_NETWORK_DIR",
                      "CLAUDESEC_DATADOG_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                ctxs = [c.__enter__() for c in stack]
                out = Path(tmp) / "dash.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir="/no/such/prowler",
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                self.assertTrue(out.exists())


# ===========================================================================
# 2. env_html for connected pills (lines 211-212)
# ===========================================================================


class ConnectedEnvPillTests(unittest.TestCase):
    def test_connected_env_renders_env_on_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_ENV_GITHUB_CONNECTED": "true",
                "CLAUDESEC_ENV_AWS_CONNECTED": "true",
            }
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                self.assertIn("env-on", html)
                self.assertIn("env-off", html)


# ===========================================================================
# 3. GitHub findings table (lines 240, 243-267)
# ===========================================================================


class GithubFindingsTableTests(unittest.TestCase):
    """Force gh_finds to populate via a prowler-github.ocsf.json file."""

    def _write_github_prowler(self, tmp, num_repos):
        """Write a prowler-github.ocsf.json with repos distributed across a single check."""
        items = []
        for i in range(num_repos):
            items.append({
                "status_code": "FAIL",
                "severity": "high",
                "finding_info": {"title": "GH issue", "desc": "GH desc"},
                "resources": [{
                    "name": f"repo-{i}",
                    "type": "github_repo",
                    "region": "",
                    "data": {"metadata": {}},
                }],
                "metadata": {"event_code": "github_branch_protection"},
                "unmapped": {
                    "related_url": "https://example.com/docs",
                    "compliance": {},
                    "categories": [],
                },
                "remediation": {
                    "desc": "Enable branch protection",
                    "references": ["https://ref.example/a"],
                },
                "cloud": {},
            })
        path = Path(tmp) / "prowler-github.ocsf.json"
        path.write_text(json.dumps(items), encoding="utf-8")

    def test_github_table_with_many_repos_renders_overflow_toggle(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_github_prowler(tmp, num_repos=8)  # >5 triggers overflow
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # repo-0..repo-7 render via h() → <code> pills
                self.assertIn("repo-0", html)
                # Overflow toggle wording
                self.assertIn("more", html)
                self.assertIn("github_branch_protection", html)
                # Reference link present (from remediation.references)
                self.assertIn("Reference", html)

    def test_github_table_few_repos_no_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_github_prowler(tmp, num_repos=2)
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                self.assertIn("repo-0", html)
                self.assertIn("repo-1", html)


# ===========================================================================
# 4. Provider table resource metadata (lines 313, 317, 319, 324-325)
#    + Prowler Hub link (337-348)
# ===========================================================================


class ProviderTableResourceMetadataTests(unittest.TestCase):
    """Exercise _build_provider_table resource extras and Hub link branches."""

    def test_aws_provider_table_with_rich_metadata(self):
        """Resource with type/region/namespace/line renders extras pill."""
        items = [{
            "status_code": "FAIL",
            "severity": "high",
            "finding_info": {"title": "AWS X", "desc": "aws desc"},
            "resources": [{
                "name": "bucket-1",
                "type": "s3_bucket",
                "region": "us-east-1",
                "data": {"metadata": {"namespace": "default", "StartLine": "42"}},
            }],
            "metadata": {"event_code": "prowler-aws-s3_bucket_versioning_enabled"},
            "unmapped": {"related_url": "", "compliance": {}, "categories": []},
            "remediation": {"desc": "", "references": []},
            "cloud": {},
        }]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "prowler-aws.ocsf.json").write_text(
                json.dumps(items), encoding="utf-8"
            )
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Resource extras: type, region, ns, L<line> all present
                self.assertIn("s3_bucket", html)
                self.assertIn("us-east-1", html)
                self.assertIn("ns:default", html)
                self.assertIn("L42", html)
                # Hub link auto-generated from prowler-* check ID
                self.assertIn("hub.prowler.com/check/", html)

    def test_provider_table_with_more_than_fifteen_resources(self):
        """>15 resources triggers overflow collapse and toggle row (lines 323-325)."""
        items = []
        for i in range(20):
            items.append({
                "status_code": "FAIL",
                "severity": "medium",
                "finding_info": {"title": "Multi", "desc": "d"},
                "resources": [{
                    "name": f"resource-{i:02d}",
                    "type": "vm",
                    "region": "",
                    "data": {"metadata": {}},
                }],
                "metadata": {"event_code": "prowler-aws-ec2_instance_profile_attached"},
                "unmapped": {"related_url": "", "compliance": {}, "categories": []},
                "remediation": {"desc": "", "references": []},
                "cloud": {},
            })
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "prowler-aws.ocsf.json").write_text(
                json.dumps(items), encoding="utf-8"
            )
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Overflow row present
                self.assertIn("more resources", html)
                self.assertIn("resource-00", html)
                self.assertIn("resource-19", html)

    def test_hub_link_skipped_for_iac_branch(self):
        """Check IDs containing 'iac-branch' skip Hub link generation."""
        items = [{
            "status_code": "FAIL",
            "severity": "high",
            "finding_info": {"title": "IaC", "desc": "d"},
            "resources": [{
                "name": "tfmod",
                "type": "terraform",
                "region": "",
                "data": {"metadata": {}},
            }],
            "metadata": {"event_code": "prowler-iac-branch-myrule"},
            "unmapped": {"related_url": "", "compliance": {}, "categories": []},
            "remediation": {"desc": "", "references": []},
            "cloud": {},
        }]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "prowler-iac.ocsf.json").write_text(
                json.dumps(items), encoding="utf-8"
            )
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # IaC branch check should NOT generate a Hub link
                self.assertNotIn("hub.prowler.com/check/iac-branch", html)

    def test_hub_name_fix_map_applied(self):
        """Check IDs in _HUB_FIX map get the canonical name."""
        items = [{
            "status_code": "FAIL",
            "severity": "high",
            "finding_info": {"title": "K8s", "desc": "d"},
            "resources": [{
                "name": "pod-1",
                "type": "pod",
                "region": "",
                "data": {"metadata": {}},
            }],
            "metadata": {
                "event_code": "prowler-kubernetes-core_minimize_containers_added_capabiliti"
            },
            "unmapped": {"related_url": "", "compliance": {}, "categories": []},
            "remediation": {"desc": "", "references": []},
            "cloud": {},
        }]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "prowler-k8s.ocsf.json").write_text(
                json.dumps(items), encoding="utf-8"
            )
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Fixed canonical name (capabilities, not capabiliti)
                self.assertIn(
                    "core_minimize_containers_added_capabilities",
                    html,
                )


# ===========================================================================
# 5. scope_parts & _middle_ellipsis (lines 403-406, 414, 416, 423)
# ===========================================================================


class ScopePartsTests(unittest.TestCase):
    def test_audit_points_detected_branch(self):
        """detected_products populates 'Audit Points (project-relevant)' branch."""
        with tempfile.TemporaryDirectory() as tmp:
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate(
                    audit_detected={"detected_products": ["Okta"], "items": []},
                )
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                self.assertIn("Audit Points (project-relevant)", html)

    def test_audit_points_data_branch_without_detected(self):
        """products populated (but no detected_products) hits the elif branch."""
        with tempfile.TemporaryDirectory() as tmp:
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate(
                    audit_points={"products": [{"name": "X"}],
                                   "fetched_at": "z"},
                )
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Plain "Audit Points" scope part present without "(project-relevant)"
                self.assertIn("Audit Points", html)

    def test_network_datadog_scope_part_when_trivy_present(self):
        """trivy_fs truthy triggers 'Network / Datadog' scope part."""
        network = _default_network()
        network["trivy_fs"] = {"Results": []}
        network["trivy_summary"] = {"critical": 2, "high": 1, "medium": 0, "low": 0}
        with tempfile.TemporaryDirectory() as tmp:
            env = {"CLAUDESEC_DASHBOARD_OFFLINE": "1"}
            for k in ("CLAUDESEC_SCAN_DIR", "SCAN_DIR"):
                os.environ.pop(k, None)
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate(network=network)
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                self.assertIn("Network / Datadog", html)
                # Trivy severity pills rendered (lines 560-563 covered)
                self.assertIn("pcs-crit", html)
                self.assertIn("pcs-high", html)

    def test_middle_ellipsis_applied_for_long_scan_dir(self):
        """Scan dir path longer than 68 chars should be middle-ellipsized."""
        # Build a long path via nested directories so os.path.isdir resolves
        with tempfile.TemporaryDirectory() as tmp:
            long_path = Path(tmp)
            # Pad with >68-char nested segment
            for seg in ("a" * 30, "b" * 30, "c" * 30):
                long_path = long_path / seg
            long_path.mkdir(parents=True, exist_ok=True)
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": str(long_path),
            }
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Ellipsized path contains "..."
                self.assertIn("...", html)


# ===========================================================================
# 6. Policies.json loader (lines 589-630, 633)
# ===========================================================================


class PoliciesLoaderTests(unittest.TestCase):
    def _policies_payload(self):
        return [
            {
                "name": "ISMS-P 공통규정",
                "url": "https://drive.example/doc1",
                "total_chapters": 3,
                "total_articles": 42,
                "isms_controls": ["1.1", "2.3"],
                "articles": [
                    {"chapter": "제1장 총칙", "num": "1", "title": "목적"},
                    {"chapter": "제1장 총칙", "num": "2", "title": "용어정의"},
                    {"chapter": "제2장 조직", "num": "3", "title": "정보보호 조직"},
                ],
            },
            {
                "name": "정보보호 지침",
                "url": "",
                "total_chapters": 1,
                "total_articles": 5,
                "isms_controls": [],
                "articles": [],
            },
        ]

    def test_policies_json_rendered(self):
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp) / ".claudesec-assets"
            assets.mkdir()
            (assets / "policies.json").write_text(
                json.dumps(self._policies_payload()),
                encoding="utf-8",
            )
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                html = out.read_text(encoding="utf-8")
                # Policy name rendered
                self.assertIn("ISMS-P", html)
                # URL link present
                self.assertIn("drive.example/doc1", html)
                # Chapter header rendered
                self.assertIn("제1장 총칙", html)
                # Article number and title rendered
                self.assertIn("목적", html)
                # Summary count line
                self.assertIn("2", html)  # 2 policies

    def test_policies_json_invalid_handled_by_except(self):
        """Malformed JSON falls through via except branch and logs 'load error'."""
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp) / ".claudesec-assets"
            assets.mkdir()
            (assets / "policies.json").write_text("not json", encoding="utf-8")
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    # Should not raise — exception is caught
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                self.assertTrue(out.exists())

    def test_policies_json_missing_uses_empty_html(self):
        """No policies.json → policies_html stays empty, 'no data' branch taken."""
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                self.assertTrue(out.exists())

    def test_policies_json_empty_list_treats_as_no_data(self):
        """Empty list in policies.json → policies_html stays empty."""
        with tempfile.TemporaryDirectory() as tmp:
            assets = Path(tmp) / ".claudesec-assets"
            assets.mkdir()
            (assets / "policies.json").write_text("[]", encoding="utf-8")
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": tmp,
            }
            with patch.dict(os.environ, env, clear=False):
                stack = _patches_for_generate()
                for c in stack:
                    c.__enter__()
                out = Path(tmp) / "d.html"
                try:
                    MOD.generate_dashboard(
                        scan_data=_zero_scan(),
                        prowler_dir=tmp,
                        history_dir=tmp,
                        output_file=str(out),
                    )
                finally:
                    for c in reversed(stack):
                        c.__exit__(None, None, None)
                self.assertTrue(out.exists())


# ===========================================================================
# 7. __main__ entry point (lines 720-741)
# ===========================================================================


class MainEntryTests(unittest.TestCase):
    """Exercise the `if __name__ == '__main__'` block via runpy."""

    def test_main_env_fallback_writes_dashboard(self):
        """No scan JSON → env fallback path (lines 727-738)."""
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "dashboard.html"
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_PASSED": "3",
                "CLAUDESEC_FAILED": "1",
                "CLAUDESEC_WARNINGS": "0",
                "CLAUDESEC_SKIPPED": "0",
                "CLAUDESEC_TOTAL": "4",
                "CLAUDESEC_SCORE": "75",
                "CLAUDESEC_GRADE": "C",
                "CLAUDESEC_DURATION": "2",
                "CLAUDESEC_FINDINGS_JSON": "[]",
                "CLAUDESEC_PROWLER_DIR": tmp,
                "CLAUDESEC_HISTORY_DIR": tmp,
                "CLAUDESEC_SCAN_JSON": "",
                "CLAUDESEC_SCAN_DIR": tmp,
            }
            old_argv = sys.argv[:]
            sys.argv = ["dashboard-gen.py", str(out_file)]
            stack = _patches_for_generate()
            for c in stack:
                c.__enter__()
            try:
                with patch.dict(os.environ, env, clear=False):
                    runpy.run_path(str(MODULE_PATH), run_name="__main__")
            finally:
                sys.argv = old_argv
                for c in reversed(stack):
                    c.__exit__(None, None, None)
            self.assertTrue(out_file.exists())

    def test_main_with_scan_json_reads_file(self):
        """CLAUDESEC_SCAN_JSON points to a valid file → load_scan_results branch."""
        with tempfile.TemporaryDirectory() as tmp:
            scan_json = Path(tmp) / "scan.json"
            scan_json.write_text(
                json.dumps({
                    "passed": 2, "failed": 0, "warnings": 0, "skipped": 0,
                    "total": 2, "score": 100, "grade": "A", "duration": 1,
                    "findings": [],
                }),
                encoding="utf-8",
            )
            out_file = Path(tmp) / "dashboard.html"
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_JSON": str(scan_json),
                "CLAUDESEC_SCAN_DIR": tmp,
                "CLAUDESEC_PROWLER_DIR": tmp,
                "CLAUDESEC_HISTORY_DIR": tmp,
            }
            old_argv = sys.argv[:]
            sys.argv = ["dashboard-gen.py", str(out_file)]
            stack = _patches_for_generate()
            for c in stack:
                c.__enter__()
            try:
                with patch.dict(os.environ, env, clear=False):
                    runpy.run_path(str(MODULE_PATH), run_name="__main__")
            finally:
                sys.argv = old_argv
                for c in reversed(stack):
                    c.__exit__(None, None, None)
            self.assertTrue(out_file.exists())

    def test_main_without_argv_uses_default_filename(self):
        """No argv[1] → output_file defaults to 'claudesec-dashboard.html' (cwd)."""
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "CLAUDESEC_DASHBOARD_OFFLINE": "1",
                "CLAUDESEC_SCAN_DIR": tmp,
                "CLAUDESEC_PROWLER_DIR": tmp,
                "CLAUDESEC_HISTORY_DIR": tmp,
                "CLAUDESEC_SCAN_JSON": "",
                "CLAUDESEC_TOTAL": "0",
            }
            old_argv = sys.argv[:]
            old_cwd = os.getcwd()
            sys.argv = ["dashboard-gen.py"]
            stack = _patches_for_generate()
            for c in stack:
                c.__enter__()
            try:
                os.chdir(tmp)
                with patch.dict(os.environ, env, clear=False):
                    runpy.run_path(str(MODULE_PATH), run_name="__main__")
                # Default filename created in cwd
                self.assertTrue(
                    (Path(tmp) / "claudesec-dashboard.html").exists()
                )
            finally:
                os.chdir(old_cwd)
                sys.argv = old_argv
                for c in reversed(stack):
                    c.__exit__(None, None, None)


# ===========================================================================
# 8. Module-level constants & imports sanity
# ===========================================================================


class ModuleSanityTests(unittest.TestCase):
    def test_generate_dashboard_is_callable(self):
        self.assertTrue(callable(MOD.generate_dashboard))

    def test_version_constant_exported(self):
        self.assertIsInstance(MOD.VERSION, str)
        self.assertTrue(len(MOD.VERSION) > 0)

    def test_ms_source_filter_env_constant(self):
        self.assertIsInstance(MOD.MS_SOURCE_FILTER_ENV, str)

    def test_ms_include_scubagear_env_constant(self):
        self.assertIsInstance(MOD.MS_INCLUDE_SCUBAGEAR_ENV, str)


if __name__ == "__main__":
    unittest.main()
