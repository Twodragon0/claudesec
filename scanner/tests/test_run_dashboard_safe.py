import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "run-dashboard-safe.sh"


class RunDashboardSafeTests(unittest.TestCase):
    def test_bind_conflict_uses_fallback_port(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            args_log = tmp / "args.log"
            fake_scanner = tmp / "fake-scanner.sh"
            fake_python = tmp / "python3"
            blocked_port = "43111"

            _ = fake_scanner.write_text(
                '#!/usr/bin/env bash\nset -euo pipefail\nprintf "%s\\n" "$@" > "$TEST_ARGS_LOG"\n',
                encoding="utf-8",
            )
            _ = fake_scanner.chmod(fake_scanner.stat().st_mode | stat.S_IXUSR)

            _ = fake_python.write_text(
                f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "${{1:-}}" == "-" ]]; then
  port="${{3:-}}"
  if [[ "$port" == "{blocked_port}" ]]; then
    exit 1
  fi
  exit 0
fi
exec /usr/bin/env python3 "$@"
""",
                encoding="utf-8",
            )
            _ = fake_python.chmod(fake_python.stat().st_mode | stat.S_IXUSR)

            env = os.environ.copy()
            env["CLAUDESEC_SCANNER"] = str(fake_scanner)
            env["CLAUDESEC_SCAN_DIR"] = str(tmp)
            env["TEST_ARGS_LOG"] = str(args_log)
            env["PATH"] = f"{tmp}:{env['PATH']}"

            res = subprocess.run(
                ["bash", str(SCRIPT_PATH), "--quick", "--port", blocked_port],
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertIn("using fallback port", res.stdout)

            argv = args_log.read_text(encoding="utf-8").splitlines()
            self.assertIn("--serve", argv)
            self.assertIn("--port", argv)
            selected_port = argv[argv.index("--port") + 1]
            self.assertNotEqual(selected_port, blocked_port)


if __name__ == "__main__":
    unittest.main()
