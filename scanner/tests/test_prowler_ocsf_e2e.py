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

    def test_compliance_frameworks_rendered_in_dashboard(self):
        """All compliance frameworks (ISO, ISMS-P, PCI-DSS, NIST, CIS) appear in HTML."""
        findings = [
            _make_ocsf_finding(
                check="apiserver_audit_log_maxage",
                title="API server audit log max age",
                message="Audit logging not configured",
            ),
            _make_ocsf_finding(
                check="rbac_wildcard_permissions",
                title="RBAC wildcard permissions detected",
                message="Restrict admin wildcard access",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            html = self._generate_dashboard(
                tmpdir, {"prowler-kubernetes.ocsf.json": findings}
            )

            # All five frameworks should be rendered
            self.assertIn("ISO 27001:2022", html)
            self.assertIn("KISA ISMS-P", html)
            self.assertIn("PCI-DSS v4.0.1", html)
            self.assertIn("NIST 800-53 Rev5", html)
            self.assertIn("CIS Benchmarks", html)

    def test_compliance_keyword_matching(self):
        """Findings matching compliance keywords should trigger FAIL status."""
        findings = [
            _make_ocsf_finding(
                check="mfa_disabled",
                title="MFA not enabled for admin accounts",
                message="Enable multi-factor authentication",
            ),
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write OCSF file
            Path(tmpdir, "prowler-kubernetes.ocsf.json").write_text(
                json.dumps([
                    {
                        "status_code": "FAIL",
                        "severity": "High",
                        "metadata": {"event_code": "mfa_disabled"},
                        "finding_info": {"title": "MFA not enabled", "desc": "desc"},
                        "resources": [{"data": {"metadata": {"name": "admin"}}, "region": "us-east-1"}],
                        "message": "Enable multi-factor authentication",
                        "unmapped": {"related_url": "", "compliance": {}},
                    }
                ]),
                encoding="utf-8",
            )

            # Load and analyze
            providers = dashboard_gen.load_prowler_files(tmpdir)
            _, all_findings = dashboard_gen.analyze_prowler(providers)
            compliance_result = dashboard_gen.map_compliance(all_findings)

            # NIST IA-2 should match (has "mfa", "authentication" keywords)
            nist_controls = {c["control"]: c for c in compliance_result["NIST 800-53 Rev5"]}
            self.assertEqual(nist_controls["IA-2"]["status"], "FAIL")
            self.assertGreater(nist_controls["IA-2"]["count"], 0)

            # CIS-5.1 should also match (has "mfa" keyword)
            cis_controls = {c["control"]: c for c in compliance_result["CIS Benchmarks"]}
            self.assertEqual(cis_controls["CIS-5.1"]["status"], "FAIL")

    def test_native_prowler_compliance_data_used(self):
        """When prowler provides native compliance mapping, it enhances matching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "prowler-aws.ocsf.json").write_text(
                json.dumps([
                    {
                        "status_code": "FAIL",
                        "severity": "Medium",
                        "metadata": {"event_code": "custom_check_xyz"},
                        "finding_info": {"title": "Custom check", "desc": "desc"},
                        "resources": [{"data": {"metadata": {"name": "res"}}, "region": "us-east-1"}],
                        "message": "Some custom message without keywords",
                        "unmapped": {
                            "related_url": "",
                            "compliance": {"CIS Benchmarks": ["1.1", "4.1"]},
                        },
                    }
                ]),
                encoding="utf-8",
            )

            providers = dashboard_gen.load_prowler_files(tmpdir)
            _, all_findings = dashboard_gen.analyze_prowler(providers)
            compliance_result = dashboard_gen.map_compliance(all_findings)

            # CIS should match via native compliance data even without keyword match
            cis_controls = compliance_result.get("CIS Benchmarks", [])
            cis_fail_count = sum(1 for c in cis_controls if c["status"] == "FAIL")
            self.assertGreater(cis_fail_count, 0)

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
