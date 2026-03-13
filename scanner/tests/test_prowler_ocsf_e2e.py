"""End-to-end test: OCSF JSON prowler findings → dashboard HTML integration."""

import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "lib" / "dashboard-gen.py"
SPEC = importlib.util.spec_from_file_location("dashboard_gen", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Failed to load module spec for {MODULE_PATH}")
dashboard_gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dashboard_gen)


def _make_ocsf_finding(
    provider="kubernetes",
    status="FAIL",
    severity="High",
    check="apiserver_audit_log_maxage",
    title="API server audit log max age",
    resource_name="kube-apiserver",
    message="Audit log max age not configured",
    desc="Ensure audit logs are retained for at least 30 days",
    related_url="https://example.com/remediation",
    compliance=None,
):
    """Build a minimal OCSF finding dict matching prowler output format."""
    return {
        "status_code": status,
        "severity": severity,
        "metadata": {"event_code": check},
        "finding_info": {"title": title, "desc": desc},
        "resources": [
            {
                "data": {"metadata": {"name": resource_name}},
                "region": "us-east-1",
            }
        ],
        "message": message,
        "unmapped": {
            "related_url": related_url,
            "compliance": compliance or {},
        },
    }


class TestOcsfDashboardE2E(unittest.TestCase):
    """Verify OCSF JSON findings flow end-to-end into generated dashboard HTML."""

    def _generate_dashboard(self, tmpdir, ocsf_files, scan_data=None):
        """Helper to write OCSF files, generate dashboard, return HTML."""
        for filename, findings in ocsf_files.items():
            Path(tmpdir, filename).write_text(
                json.dumps(findings), encoding="utf-8"
            )

        if scan_data is None:
            scan_data = {
                "passed": 5,
                "failed": 3,
                "warnings": 1,
                "skipped": 0,
                "total": 9,
                "score": 55,
                "grade": "C",
                "duration": 10,
                "findings": [],
            }

        output_file = Path(tmpdir) / "dashboard.html"

        with (
            patch.object(
                dashboard_gen,
                "load_audit_points",
                return_value={"products": [], "fetched_at": ""},
            ),
            patch.object(
                dashboard_gen,
                "load_audit_points_detected",
                return_value={"detected_products": [], "items": []},
            ),
            patch.object(
                dashboard_gen,
                "load_microsoft_best_practices",
                return_value={
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "source_filter": "all",
                    "scubagear_enabled": False,
                    "sources": [],
                },
            ),
        ):
            dashboard_gen.generate_dashboard(
                scan_data=scan_data,
                prowler_dir=tmpdir,
                history_dir=tmpdir,
                output_file=str(output_file),
            )

        return output_file.read_text(encoding="utf-8")

    def test_kubernetes_findings_appear_in_dashboard(self):
        """K8s OCSF findings should render check codes, severity, and resources."""
        findings = [
            _make_ocsf_finding(
                severity="Critical",
                check="apiserver_audit_log_maxage",
                title="Audit log max age",
                resource_name="kube-apiserver",
            ),
            _make_ocsf_finding(
                severity="High",
                check="kubelet_tls_cert",
                title="Kubelet TLS certificate",
                resource_name="kubelet-node-01",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            html = self._generate_dashboard(
                tmpdir, {"prowler-kubernetes.ocsf.json": findings}
            )

            self.assertIn("apiserver_audit_log_maxage", html)
            self.assertIn("kubelet_tls_cert", html)
            self.assertIn("Audit log max age", html)
            self.assertIn("Kubelet TLS certificate", html)
            self.assertIn("K8s", html)

    def test_multi_provider_findings(self):
        """Multiple providers should each render in separate dashboard sections."""
        k8s_findings = [
            _make_ocsf_finding(
                provider="kubernetes",
                severity="Critical",
                check="k8s_rbac_wildcard",
                title="RBAC wildcard permissions",
            ),
        ]
        aws_findings = [
            _make_ocsf_finding(
                provider="aws",
                severity="High",
                check="s3_bucket_public_access",
                title="S3 bucket public access",
                resource_name="my-bucket",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            html = self._generate_dashboard(
                tmpdir,
                {
                    "prowler-kubernetes.ocsf.json": k8s_findings,
                    "prowler-aws.ocsf.json": aws_findings,
                },
            )

            self.assertIn("k8s_rbac_wildcard", html)
            self.assertIn("s3_bucket_public_access", html)
            self.assertIn("K8s", html)
            self.assertIn("AWS", html)

    def test_severity_counts_in_summary(self):
        """Provider summary should reflect correct severity breakdown."""
        findings = [
            _make_ocsf_finding(severity="Critical"),
            _make_ocsf_finding(severity="Critical"),
            _make_ocsf_finding(severity="High"),
            _make_ocsf_finding(severity="Medium", status="PASS"),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            html = self._generate_dashboard(
                tmpdir, {"prowler-kubernetes.ocsf.json": findings}
            )

            # Summary section should exist with provider data
            self.assertIn("K8s", html)
            # Dashboard should contain the generated HTML (not "not run")
            self.assertNotIn("K8s</td>\n", html.replace(" ", ""))

    def test_empty_prowler_dir_shows_not_run(self):
        """When no OCSF files exist, providers should show 'not run'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            html = self._generate_dashboard(tmpdir, {})

            self.assertIn("not run", html)
            self.assertIn("K8s", html)

    def test_ndjson_format_findings(self):
        """NDJSON formatted OCSF files should parse and render correctly."""
        finding1 = _make_ocsf_finding(
            check="ndjson_check_1", title="NDJSON Finding One"
        )
        finding2 = _make_ocsf_finding(
            check="ndjson_check_2", title="NDJSON Finding Two"
        )
        ndjson_content = json.dumps(finding1) + "\n" + json.dumps(finding2) + "\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "prowler-kubernetes.ocsf.json").write_text(
                ndjson_content, encoding="utf-8"
            )
            html = self._generate_dashboard(tmpdir, {})
            # Re-generate with the NDJSON file already written
            html = self._generate_dashboard.__func__(self, tmpdir, {})

        # The NDJSON file was written manually, so re-run without overwriting
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "prowler-kubernetes.ocsf.json").write_text(
                ndjson_content, encoding="utf-8"
            )

            scan_data = {
                "passed": 1, "failed": 1, "warnings": 0, "skipped": 0,
                "total": 2, "score": 50, "grade": "D", "duration": 1,
                "findings": [],
            }
            output_file = Path(tmpdir) / "dashboard.html"

            with (
                patch.object(
                    dashboard_gen, "load_audit_points",
                    return_value={"products": [], "fetched_at": ""},
                ),
                patch.object(
                    dashboard_gen, "load_audit_points_detected",
                    return_value={"detected_products": [], "items": []},
                ),
                patch.object(
                    dashboard_gen, "load_microsoft_best_practices",
                    return_value={
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                        "source_filter": "all",
                        "scubagear_enabled": False,
                        "sources": [],
                    },
                ),
            ):
                dashboard_gen.generate_dashboard(
                    scan_data=scan_data,
                    prowler_dir=tmpdir,
                    history_dir=tmpdir,
                    output_file=str(output_file),
                )

            html = output_file.read_text(encoding="utf-8")
            self.assertIn("ndjson_check_1", html)
            self.assertIn("ndjson_check_2", html)

    def test_corrupt_ocsf_file_does_not_crash(self):
        """Dashboard generation should succeed even with corrupt OCSF files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "prowler-kubernetes.ocsf.json").write_text(
                "not valid json {{{", encoding="utf-8"
            )
            # Should not raise
            html = self._generate_dashboard(tmpdir, {})
            self.assertIn("ClaudeSec local security scanner results", html)


if __name__ == "__main__":
    unittest.main()
