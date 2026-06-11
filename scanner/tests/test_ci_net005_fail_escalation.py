"""
Regression guard: NET-005 must ESCALATE SSH-open-to-the-world to FAIL.

`scanner/checks/network/tls.sh` NET-005 flags an IaC ingress rule that exposes
SSH (port 22) to `0.0.0.0/0` as a CRITICAL FAIL. The inner detection pattern is
an ERE alternation passed to `files_contain` (which uses `grep -E`):

    (0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)

It previously used `\\|` for the alternation. Under `grep -E` (ERE) `\\|` is a
LITERAL pipe, not alternation, so the SSH-port-22 case never matched and NET-005
silently downgraded to a mere WARN ("Ingress rule allows 0.0.0.0/0"). Fixed in
PR #224; the behavioral RED/GREEN test lives in test_check_network_tls.sh.

This is the fast STATIC tripwire that complements that behavioral test: it fails
immediately if the alternation regresses to `\\|` or the FAIL escalation is
removed — even if someone also weakened the behavioral test.

stdlib-only, no network/subprocess. Passes under pytest and `python3 -m unittest`.
"""

import re
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TLS_SH = REPO_ROOT / "scanner" / "checks" / "network" / "tls.sh"


class TestNet005FailEscalation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = TLS_SH.read_text(encoding="utf-8") if TLS_SH.is_file() else ""
        # Isolate the NET-005 section (from its banner to the next "# NET-" or EOF)
        # so assertions don't accidentally match other checks.
        lines = cls.text.splitlines()
        start = next(
            (i for i, ln in enumerate(lines) if "NET-005" in ln and ln.lstrip().startswith("#")),
            None,
        )
        if start is None:
            cls.section = ""
        else:
            end = len(lines)
            for j in range(start + 1, len(lines)):
                s = lines[j].lstrip()
                if s.startswith("# NET-") and "NET-005" not in lines[j]:
                    end = j
                    break
            cls.section = "\n".join(lines[start:end])

    def test_tls_check_exists(self):
        self.assertTrue(TLS_SH.is_file(), f"{TLS_SH} not found")

    def test_net005_section_found(self):
        self.assertTrue(
            self.section,
            "NET-005 section not found in tls.sh — parsing assumption broke.",
        )

    def test_net005_escalates_to_critical_fail(self):
        self.assertRegex(
            self.section,
            r'fail\s+"NET-005"[^\n]*"critical"',
            'NET-005 no longer emits a CRITICAL `fail "NET-005" ... "critical"`. '
            "SSH open to 0.0.0.0/0 must escalate to FAIL, not WARN.",
        )

    def test_net005_uses_ere_alternation_not_literal_pipe(self):
        # The port-22 detection must use a real ERE alternation `(a|b)`.
        self.assertRegex(
            self.section,
            r"\(0\\\.0\\\.0\\\.0/0\.\*22\|port\.\*22\.\*0\\\.0\\\.0\\\.0/0\)",
            "NET-005's SSH-port-22 detection pattern changed shape. It must stay an "
            r"ERE alternation `(0\.0\.0\.0/0.*22|port.*22.*0\.0\.0\.0/0)`.",
        )
        # And it must NOT contain a backslash-pipe (the broken literal-pipe form
        # that disabled the match under grep -E).
        self.assertNotRegex(
            self.section,
            r"22\\\|port",
            r"NET-005 reintroduced a literal `\|` in its grep -E detection pattern "
            "(it means a LITERAL pipe in ERE, not alternation, and silently breaks "
            r"detection). Use `(a|b)` alternation instead.",
        )


if __name__ == "__main__":
    unittest.main()
