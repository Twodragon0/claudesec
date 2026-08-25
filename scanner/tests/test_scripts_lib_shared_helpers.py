"""Tests for the helpers extracted into `scripts/lib/`.

These functions lived in duplicate inside `scripts/build-dashboard.py` and
`scripts/sync-cost-xlsx.py`. Neither copy had a test that imported it — the
existing `test_build_dashboard_units.py` deliberately RE-IMPLEMENTS the logic it
checks — so the extraction had no safety net at all. That is what this file is.

Coverage note: `--cov=scanner/lib` does not measure `scripts/`, so these tests
are the only thing standing behind this code. They assert behaviour, not lines.
"""

import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "lib"))

import aws_inventory  # noqa: E402
import datadog_client  # noqa: E402
import scan_history  # noqa: E402


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ===========================================================================
# datadog_client
# ===========================================================================


class TestDdGet(unittest.TestCase):
    def test_url_params_and_credential_headers(self):
        seen = {}

        def _urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = dict(req.headers)
            return _FakeResponse(b'{"host_list": []}')

        with patch("urllib.request.urlopen", side_effect=_urlopen):
            out = datadog_client.dd_get(
                "/api/v1/hosts", "count=200", api_key="k", app_key="a"
            )
        self.assertEqual(out, {"host_list": []})
        self.assertEqual(seen["url"], "https://api.datadoghq.com/api/v1/hosts?count=200")
        # urllib title-cases header names.
        self.assertEqual(seen["headers"]["Dd-api-key"], "k")
        self.assertEqual(seen["headers"]["Dd-application-key"], "a")

    def test_no_params_leaves_the_query_string_off(self):
        seen = {}

        def _urlopen(req, timeout=None):
            seen["url"] = req.full_url
            return _FakeResponse(b"{}")

        with patch("urllib.request.urlopen", side_effect=_urlopen):
            datadog_client.dd_get("/api/v1/hosts", api_key="k", app_key="a")
        self.assertNotIn("?", seen["url"])

    def test_non_dict_payload_becomes_empty_dict(self):
        with patch("urllib.request.urlopen", return_value=_FakeResponse(b"[1, 2]")):
            self.assertEqual(
                datadog_client.dd_get("/x", api_key="k", app_key="a"), {}
            )

    def test_transport_error_degrades_to_empty_dict(self):
        with patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("dns")
        ):
            self.assertEqual(
                datadog_client.dd_get("/x", api_key="k", app_key="a"), {}
            )

    def test_non_utf8_body_does_not_raise(self):
        """`errors="replace"` on the body decode, for the reason in #487: a
        response cut mid multi-byte character raises `UnicodeDecodeError`, which
        is a sibling `ValueError` and would escape the handler."""
        with patch(
            "urllib.request.urlopen", return_value=_FakeResponse(b'{"a": "\x80"}')
        ):
            out = datadog_client.dd_get("/x", api_key="k", app_key="a")
        self.assertEqual(list(out), ["a"])


class TestDdPost(unittest.TestCase):
    def test_method_body_and_headers(self):
        seen = {}

        def _urlopen(req, timeout=None):
            seen["method"] = req.get_method()
            seen["body"] = req.data
            seen["url"] = req.full_url
            return _FakeResponse(b'{"data": []}')

        with patch("urllib.request.urlopen", side_effect=_urlopen):
            out = datadog_client.dd_post(
                "/api/v2/x", {"filter": {"from": "now-14d"}}, api_key="k", app_key="a"
            )
        self.assertEqual(out, {"data": []})
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(json.loads(seen["body"]), {"filter": {"from": "now-14d"}})
        self.assertEqual(seen["url"], "https://api.datadoghq.com/api/v2/x")

    def test_transport_error_degrades_to_empty_dict(self):
        with patch("urllib.request.urlopen", side_effect=OSError("boom")):
            self.assertEqual(
                datadog_client.dd_post("/x", {}, api_key="k", app_key="a"), {}
            )


class TestCollectDatadog(unittest.TestCase):
    _HOSTS = {
        "host_list": [
            {
                "name": "prod-web",
                "up": True,
                "meta": {"agent_version": "7.50.0"},
                "tags_by_source": {
                    "Amazon Web Services": [
                        "instance-type:t3.small",
                        "region:ap-northeast-2",
                        "env:prod",
                        "malformed-no-colon",
                    ],
                    "bad-source": "not-a-list",
                },
            },
            "not-a-dict",
        ]
    }
    _SIGNALS = {
        "data": [
            {
                "id": "x" * 40,
                "attributes": {
                    "message": "m" * 300,
                    "severity": "high",
                    "status": "open",
                    "timestamp": "2026-08-25T00:00:00Z",
                    "tags": list("abcdefg"),
                },
            },
            {"id": "y", "attributes": "not-a-dict"},
            "not-a-dict",
        ]
    }

    def _run(self, hosts_label="  Datadog 호스트..."):
        with patch.object(datadog_client, "dd_get", return_value=self._HOSTS), \
             patch.object(datadog_client, "dd_post", return_value=self._SIGNALS):
            return datadog_client.collect_datadog(
                api_key="k", app_key="a", hosts_label=hosts_label
            )

    def test_missing_api_key_short_circuits(self):
        with patch.object(datadog_client, "dd_get") as g:
            hosts, signals = datadog_client.collect_datadog(
                api_key="", app_key="a", hosts_label="x"
            )
        self.assertEqual((hosts, signals), ([], []))
        g.assert_not_called()

    def test_host_tags_are_flattened_and_non_dicts_skipped(self):
        hosts, _ = self._run()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["instance_type"], "t3.small")
        self.assertEqual(hosts[0]["region"], "ap-northeast-2")
        self.assertEqual(hosts[0]["env"], "prod")
        self.assertEqual(hosts[0]["agent_version"], "7.50.0")
        self.assertEqual(hosts[0]["nodepool"], "")

    def test_signal_fields_are_truncated_and_non_dicts_skipped(self):
        _, signals = self._run()
        self.assertEqual(len(signals), 2)
        self.assertEqual(len(signals[0]["id"]), 30)
        self.assertEqual(len(signals[0]["title"]), 200)
        self.assertEqual(len(signals[0]["tags"]), 5)
        # The entry whose `attributes` was not a dict still yields a row, empty.
        self.assertEqual(signals[1]["severity"], "")

    def test_hosts_label_is_the_callers_choice(self):
        """The ONE line the two script copies disagreed on. Both spellings must
        survive verbatim, or one script's console output silently changes."""
        for label in ("  Datadog 호스트...", "\n[Datadog] 호스트..."):
            with self.subTest(label=label):
                with patch("builtins.print") as p:
                    self._run(hosts_label=label)
                self.assertIn(label, [c.args[0] for c in p.call_args_list])


# ===========================================================================
# aws_inventory
# ===========================================================================


class TestIsKarpenterNode(unittest.TestCase):
    def test_matches_only_the_ip_10_form(self):
        self.assertTrue(aws_inventory.is_karpenter_node("ip-10-1-2-3.ec2.internal"))
        self.assertTrue(aws_inventory.is_karpenter_node("ip-10-0-0-1."))
        self.assertFalse(aws_inventory.is_karpenter_node("prod-web-01"))
        self.assertFalse(aws_inventory.is_karpenter_node(""))
        self.assertFalse(aws_inventory.is_karpenter_node("ip-999.x"))

    def test_is_case_sensitive(self):
        """Pinned because it is surprising, not because it is desirable: the
        original used `re.match` with no flags and this extraction must not
        quietly change it."""
        self.assertFalse(aws_inventory.is_karpenter_node("IP-10-1-2-3."))

    def test_needs_the_trailing_dot(self):
        self.assertFalse(aws_inventory.is_karpenter_node("ip-10-1-2-3"))


class TestCrossVerifyEc2(unittest.TestCase):
    _EC2 = [
        {"InstanceId": "i-1", "Name": "prod-web", "Type": "t3.small", "_profile": "p1"},
        {"InstanceId": "i-2", "Name": "ip-10-1-2-3.ec2.internal", "Type": "c6i.large"},
        {"InstanceId": "i-3", "Name": "orphan", "Type": "t3.nano", "_profile": "p2"},
        {"InstanceId": None, "Name": "bad-id"},
        {"InstanceId": "i-4", "Name": 12345},
    ]
    _SHEET = [
        {"instance_id": "i-1", "name": "prod-web", "instance_type": "t3.small"},
        {"instance_id": "i-9", "name": "gone", "instance_type": "t2.micro"},
        {"instance_id": "i-8", "name": "ip-10-9-9-9.", "instance_type": "x"},
    ]

    def setUp(self):
        patcher = patch("builtins.print")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.r = aws_inventory.cross_verify_ec2(self._EC2, self._SHEET)

    def test_karpenter_nodes_are_split_out_of_the_comparison(self):
        self.assertEqual(self.r["aws_karpenter"], 1)
        self.assertEqual(self.r["sheet_karpenter"], 1)
        self.assertEqual(self.r["karpenter_count"], 1)

    def test_totals_count_every_input_row(self):
        self.assertEqual(self.r["aws_total"], len(self._EC2))
        self.assertEqual(self.r["sheet_total"], len(self._SHEET))

    def test_falsy_instance_id_is_dropped_from_the_static_sets(self):
        # i-1, i-3, i-4 are static; the None-id row is skipped entirely.
        self.assertEqual(self.r["aws_static"], 3)

    def test_non_string_name_does_not_raise_and_counts_as_static(self):
        self.assertIn("i-4", [e["id"] for e in self.r["aws_only"]])

    def test_matched_and_the_two_one_sided_sets(self):
        self.assertEqual(self.r["matched"], 1)
        self.assertEqual(
            sorted(e["id"] for e in self.r["aws_only"]), ["i-3", "i-4"]
        )
        self.assertEqual([e["id"] for e in self.r["sheet_only"]], ["i-9"])
        self.assertEqual(self.r["aws_only_count"], 2)
        self.assertEqual(self.r["sheet_only_count"], 1)

    def test_status_labels(self):
        self.assertEqual({e["status"] for e in self.r["aws_only"]}, {"미등록"})
        self.assertEqual({e["status"] for e in self.r["sheet_only"]}, {"종료/교체"})


class TestLoadAwsLiveData(unittest.TestCase):
    def setUp(self):
        patcher = patch("builtins.print")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fixture(self, tmp):
        (tmp / "aws-ec2-p1.json").write_text(
            json.dumps([{"InstanceId": "i-1"}]), encoding="utf-8"
        )
        (tmp / "aws-rds-clusters-p1.json").write_text(
            json.dumps([{"id": "r1"}]), encoding="utf-8"
        )
        (tmp / "aws-eks-p1.json").write_text(
            json.dumps({"clusters": ["c1"]}), encoding="utf-8"
        )
        (tmp / "aws-s3-p1.json").write_text("{ truncated", encoding="utf-8")

    def test_profile_from_env_and_profile_tagging(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._fixture(tmp)
            out = aws_inventory.load_aws_live_data(tmp, {"AWS_PROFILES": "p1"})
        self.assertEqual(out["ec2"], [{"InstanceId": "i-1", "_profile": "p1"}])
        self.assertEqual(out["eks"], [{"name": "c1", "_profile": "p1"}])

    def test_rds_clusters_collapse_into_rds(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._fixture(tmp)
            out = aws_inventory.load_aws_live_data(tmp, {"AWS_PROFILES": "p1"})
        self.assertEqual(out["rds"], [{"id": "r1", "_profile": "p1"}])

    def test_corrupt_file_is_skipped_not_fatal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._fixture(tmp)
            out = aws_inventory.load_aws_live_data(tmp, {"AWS_PROFILES": "p1"})
        self.assertEqual(out["s3"], [])

    def test_empty_env_infers_profiles_from_the_ec2_files_on_disk(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._fixture(tmp)
            (tmp / "aws-ec2-p2.json").write_text(
                json.dumps([{"InstanceId": "i-2"}]), encoding="utf-8"
            )
            out = aws_inventory.load_aws_live_data(tmp, {})
        self.assertEqual(
            sorted(e["_profile"] for e in out["ec2"]), ["p1", "p2"]
        )

    def test_missing_dir_yields_the_empty_shape(self):
        out = aws_inventory.load_aws_live_data(Path("/no/such/dir"), {})
        self.assertEqual(
            sorted(out), ["ec2", "eks", "elasticache", "rds", "s3"]
        )
        self.assertTrue(all(v == [] for v in out.values()))


# ===========================================================================
# scan_history
# ===========================================================================


class TestCollectScanHistory(unittest.TestCase):
    def test_missing_dir_returns_empty(self):
        self.assertEqual(scan_history.collect_scan_history(Path("/no/such/dir")), [])

    def test_sorted_oldest_first_and_capped_at_thirty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            h = Path(d)
            for i in range(35):
                (h / f"scan-{i:03d}.json").write_text(
                    json.dumps({"timestamp": f"2026-01-{i % 28 + 1:02d}", "i": i}),
                    encoding="utf-8",
                )
            out = scan_history.collect_scan_history(h)
        self.assertEqual(len(out), 30)
        stamps = [e["timestamp"] for e in out]
        self.assertEqual(stamps, sorted(stamps))

    def test_keep_is_overridable(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            h = Path(d)
            for i in range(5):
                (h / f"scan-{i}.json").write_text(
                    json.dumps({"timestamp": str(i)}), encoding="utf-8"
                )
            self.assertEqual(len(scan_history.collect_scan_history(h, keep=2)), 2)

    def test_unreadable_entry_is_skipped_not_fatal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            h = Path(d)
            (h / "scan-ok.json").write_text('{"timestamp": "1"}', encoding="utf-8")
            (h / "scan-bad.json").write_text("nope", encoding="utf-8")
            out = scan_history.collect_scan_history(h)
        self.assertEqual(out, [{"timestamp": "1"}])


# ===========================================================================
# The scripts must still import after the extraction
# ===========================================================================


class TestOperatorScriptsStillLoad(unittest.TestCase):
    """The extraction moved 276 lines across two 1300-line scripts that have no
    end-to-end test. A syntax error or a stale reference would otherwise only
    surface on the next scheduled run.
    """

    def test_no_stale_references_to_the_moved_names(self):
        moved = ("_cross_verify_ec2", "_is_karpenter_node")
        for name in ("build-dashboard.py", "sync-cost-xlsx.py"):
            src = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
            for symbol in moved:
                with self.subTest(script=name, symbol=symbol):
                    self.assertNotIn(symbol, src)

    def test_both_scripts_compile(self):
        import py_compile
        for name in ("build-dashboard.py", "sync-cost-xlsx.py"):
            with self.subTest(script=name):
                py_compile.compile(
                    str(REPO_ROOT / "scripts" / name), doraise=True, cfile=None
                )


if __name__ == "__main__":
    unittest.main()
