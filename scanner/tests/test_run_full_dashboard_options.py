import os
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "run-full-dashboard.sh"


class RunFullDashboardOptionsTests(unittest.TestCase):
    def _run_with_fake_scanner(self, args: Sequence[str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            args_log = tmp / "args.log"
            fake_scanner = tmp / "fake-scanner.sh"
            _ = fake_scanner.write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\nprintf \'%s\\n\' "$@" > "$TEST_ARGS_LOG"\n',
                encoding="utf-8",
            )
            _ = fake_scanner.chmod(fake_scanner.stat().st_mode | stat.S_IXUSR)

            env = os.environ.copy()
            env["CLAUDESEC_SCANNER"] = str(fake_scanner)
            env["CLAUDESEC_SCAN_DIR"] = str(tmp)
            env["TEST_ARGS_LOG"] = str(args_log)

            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), *args],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            return args_log.read_text(encoding="utf-8").splitlines()

    def test_quick_and_no_serve_does_not_serve(self):
        argv = self._run_with_fake_scanner(["--quick", "--no-serve"])
        self.assertEqual(argv[0], "dashboard")
        self.assertEqual(argv[1], "-d")
        self.assertTrue(argv[2])
        self.assertIn("-c", argv)
        self.assertIn("access-control,cicd,code", argv)
        self.assertNotIn("--serve", argv)
        self.assertNotIn("--all", argv)

    def test_no_serve_runs_full_all_mode(self):
        argv = self._run_with_fake_scanner(["--no-serve"])
        self.assertEqual(argv[0], "dashboard")
        self.assertEqual(argv[1], "-d")
        self.assertTrue(argv[2])
        self.assertIn("--all", argv)
        self.assertNotIn("--serve", argv)

    def test_quick_enables_serve_with_default_host_port(self):
        argv = self._run_with_fake_scanner(["--quick"])
        self.assertIn("-c", argv)
        self.assertIn("access-control,cicd,code", argv)
        self.assertIn("--serve", argv)
        self.assertIn("--host", argv)
        self.assertIn("127.0.0.1", argv)
        self.assertIn("--port", argv)
        self.assertIn("11777", argv)


if __name__ == "__main__":
    _ = unittest.main()
