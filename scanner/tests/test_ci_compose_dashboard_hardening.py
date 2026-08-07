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

# Shared comment-stripping primitive. Import as a top-level module so it resolves
# under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_inline_comment  # noqa: E402

# Required hardening lines inside the dashboard service block. Each is a regex
# matched against the block text (comments stripped).
REQUIRED = {
    "read_only": re.compile(r"^\s*read_only:\s*true\s*$", re.MULTILINE),
    "cap_drop ALL": re.compile(r"^\s*cap_drop:\s*\[?\s*[\"']?ALL[\"']?", re.MULTILINE),
    # Unanchored on purpose: this token legitimately appears MID-line in the
    # inline-array form `security_opt: ["no-new-privileges:true"]` as well as the
    # block-list form `- "no-new-privileges:true"`, so it cannot be `^`-anchored
    # like the others. Comment-evasion is closed by stripping trailing inline
    # comments in `_strip_comments` (ADR-001 §1), not by anchoring.
    "no-new-privileges": re.compile(r"no-new-privileges:true"),
    "tmpfs": re.compile(r"^\s*tmpfs:\s*$", re.MULTILINE),
    "mem_limit": re.compile(r"^\s*mem_limit:\s*\S+", re.MULTILINE),
    "pids_limit": re.compile(r"^\s*pids_limit:\s*\d+", re.MULTILINE),
}


def _strip_comments(text: str) -> str:
    # Drop whole-line `#` comments AND trailing inline `# ...` comments, so a
    # hardening token riding a trailing comment on an unrelated line (e.g.
    # `image: x  # no-new-privileges:true`) cannot satisfy a presence check while
    # the real directive has been deleted (ADR-001 §1).
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(strip_inline_comment(line))
    return "\n".join(out)


# A sibling service key: exactly 2-space indent, bare OR quoted. A quoted key
# (`"redis":`) is the same mapping key to any YAML parser, and one that failed to
# match here would not TERMINATE the dashboard block — the sibling's directives
# would then satisfy the dashboard's requirements.
_SIBLING_SERVICE_RE = re.compile(r"""^  (?:[A-Za-z0-9_.-]+|"[^"]*"|'[^']*'):\s*$""")


def _dashboard_block(text: str) -> str:
    """Extract the `dashboard:` service block (until the next 2-space top-level
    key at the same indent, or EOF).

    Callers MUST pass comment-stripped text (`missing_directives` does). The
    terminator has to match a bare `  redis:` line exactly, so a trailing comment
    on a sibling key — `  redis:  # cache sidecar` — used to slip past it and
    merge the sibling INTO the dashboard block. Verified by mutation on the real
    `docker-compose.yml` (2026-08-07 audit): with every hardening directive
    deleted from the dashboard service and such a sibling added,
    `missing_directives` returned `[]` — the guard certified an unhardened
    service. With the sibling key written plainly it correctly reported all six.
    Stripping first is the fix; ADR-001 §2 (strip, THEN match) applies to a block
    boundary exactly as it does to a token."""
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
        if _SIBLING_SERVICE_RE.match(line):
            break
        block.append(line)
    return "\n".join(block)


def missing_directives(text: str) -> list:
    # Strip BEFORE extracting: a comment must not be able to move the block
    # boundary (see `_dashboard_block`). `_strip_comments` is idempotent, so the
    # block needs no second pass.
    block = _dashboard_block(_strip_comments(text))
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

    def test_dropped_no_new_privileges_via_comment_detected(self):
        # ADR-001 §1: `security_opt` is removed, but the token survives ONLY in a
        # trailing inline comment on the (active) image line. A matcher that
        # keeps trailing comments would stay green here.
        mutant = self._GOOD.replace(
            "    image: x\n",
            "    image: x  # no-new-privileges:true (was here, now default)\n",
        ).replace('    security_opt: ["no-new-privileges:true"]\n', "")
        self.assertIn("no-new-privileges", missing_directives(mutant))

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

    _LEAKY_TEMPLATE = (
        "services:\n"
        "  dashboard:\n"
        "    image: x\n"
        "{sibling}"
        "    read_only: true\n"
        '    cap_drop: ["ALL"]\n'
        '    security_opt: ["no-new-privileges:true"]\n'
        "    tmpfs:\n"
        "      - /run\n"
        "    mem_limit: 1m\n"
        "    pids_limit: 1\n"
    )

    def test_commented_sibling_key_still_terminates_the_block(self):
        # 2026-08-07 audit: the extractor ran BEFORE comment stripping, so a
        # trailing comment on a sibling service key stopped terminating the
        # dashboard block and the sibling's directives satisfied the dashboard's
        # requirements. Reproduced on the real docker-compose.yml.
        for sibling in ("  other:  # cache sidecar\n", '  "other":\n', "  'other':\n"):
            with self.subTest(sibling=sibling.strip()):
                leaky = self._LEAKY_TEMPLATE.format(sibling=sibling)
                self.assertNotEqual(
                    missing_directives(leaky),
                    [],
                    f"sibling key {sibling.strip()!r} failed to terminate the "
                    "dashboard block — another service's hardening satisfied it.",
                )


if __name__ == "__main__":
    unittest.main()
    sys.exit(0)
