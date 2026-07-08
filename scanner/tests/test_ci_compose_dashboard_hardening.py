"""
Regression guard: the dashboard service in every ClaudeSec compose file keeps
its container hardening (CIS Docker Benchmark).

Background
----------
The dashboard is a network-exposed, long-running nginx service that serves only
static content. It is hardened with a read-only root filesystem (writable paths
tmpfs-backed), all Linux capabilities dropped, no-new-privileges, and memory/PID
caps. As a security *toolkit*, ClaudeSec should not silently regress the posture
of its own shipped container — a dropped `read_only`/`cap_drop`/`no-new-privileges`
would pass review unnoticed. This guard asserts each dashboard service block
keeps the directives.

stdlib-only: block-scoped regex/line scanning, no PyYAML. Runs under pytest and
`python3 -m unittest`. No network, no subprocess.
"""

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ["docker-compose.yml", "docker-compose.quickstart.yml"]

# Required hardening lines inside the dashboard service block. Each is a regex
# matched against the block text (comments stripped).
REQUIRED = {
    "read_only": re.compile(r"^\s*read_only:\s*true\s*$", re.MULTILINE),
    "cap_drop ALL": re.compile(r"^\s*cap_drop:\s*\[?\s*[\"']?ALL[\"']?", re.MULTILINE),
    "no-new-privileges": re.compile(r"no-new-privileges:true"),
    "tmpfs": re.compile(r"^\s*tmpfs:\s*$", re.MULTILINE),
    "mem_limit": re.compile(r"^\s*mem_limit:\s*\S+", re.MULTILINE),
    "pids_limit": re.compile(r"^\s*pids_limit:\s*\d+", re.MULTILINE),
}


def _strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        # Drop whole-line comments; keep inline (compose has no inline # in these keys).
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _dashboard_block(text: str) -> str:
    """Extract the `dashboard:` service block (until the next 2-space top-level
    key at the same indent, or EOF)."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^  dashboard:\s*$", line):
            start = i
            break
    if start is None:
        return ""
    block = [lines[start]]
    for line in lines[start + 1:]:
        # A sibling service starts at exactly 2-space indent + `name:`.
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            break
        block.append(line)
    return "\n".join(block)


def missing_directives(text: str) -> list:
    block = _strip_comments(_dashboard_block(text))
    if not block.strip():
        return ["<no dashboard service block found>"]
    return [name for name, rx in REQUIRED.items() if not rx.search(block)]


class TestComposeDashboardHardening(unittest.TestCase):
    def test_each_compose_dashboard_is_hardened(self):
        for rel in COMPOSE_FILES:
            path = REPO_ROOT / rel
            with self.subTest(compose=rel):
                self.assertTrue(path.is_file(), f"{rel} not found")
                missing = missing_directives(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    missing, [],
                    f"{rel} dashboard service lost hardening directive(s): "
                    + ", ".join(missing),
                )


class TestHardeningGuardSelfTest(unittest.TestCase):
    _GOOD = (
        "services:\n"
        "  dashboard:\n"
        "    image: x\n"
        "    read_only: true\n"
        "    tmpfs:\n"
        "      - /run:mode=1777\n"
        '    cap_drop: ["ALL"]\n'
        '    security_opt: ["no-new-privileges:true"]\n'
        "    mem_limit: 128m\n"
        "    pids_limit: 100\n"
        "  other:\n"
        "    image: y\n"
    )

    def test_good_passes(self):
        self.assertEqual(missing_directives(self._GOOD), [])

    def test_dropped_read_only_detected(self):
        mutant = self._GOOD.replace("    read_only: true\n", "")
        self.assertIn("read_only", missing_directives(mutant))

    def test_block_scoped_not_leaking_from_other_service(self):
        # Hardening on `other:` must NOT satisfy the dashboard block.
        leaky = (
            "services:\n"
            "  dashboard:\n"
            "    image: x\n"
            "  other:\n"
            "    read_only: true\n"
            '    cap_drop: ["ALL"]\n'
            '    security_opt: ["no-new-privileges:true"]\n'
            "    tmpfs:\n"
            "      - /run\n"
            "    mem_limit: 1m\n"
            "    pids_limit: 1\n"
        )
        self.assertNotEqual(missing_directives(leaky), [])


if __name__ == "__main__":
    unittest.main()
    sys.exit(0)
